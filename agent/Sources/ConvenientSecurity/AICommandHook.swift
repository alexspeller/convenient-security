import CryptoKit
import Foundation

public enum AICommandHookClient: String, Codable, Sendable, CaseIterable {
    case claude
    case codex
}

public enum AICommandHookError: Error, LocalizedError {
    case invalidInput
    case unsupportedEvent
    case unsupportedTool
    case invalidCommand
    case invalidExecutablePath

    public var errorDescription: String? {
        switch self {
        case .invalidInput: return "invalid hook JSON"
        case .unsupportedEvent: return "the hook input is not PreToolUse"
        case .unsupportedTool: return "the hook input is not a shell-tool command"
        case .invalidCommand: return "the hook command is empty or outside supported bounds"
        case .invalidExecutablePath: return "the csec executable path is invalid"
        }
    }
}

/// Deterministic adapters for Claude Code and Codex `PreToolUse`. They do no
/// secret work: their job is to replace the proposed shell string with a
/// fail-closed `csec ai` invocation. That covers every tool that runs a shell
/// command (`shellTools`): Bash, and Claude Code's Monitor. For Claude Code the
/// hook also registers the exact program with csecd before printing the
/// rewrite, so a delegated approval can be bound to the one call Claude Code's
/// classifier judged; that registration is best effort and never changes what
/// the hook prints.
///
/// One kind of Claude Code command is left unwrapped: a plain list of `git`
/// commands (`AICommandGitPassthrough`), so Claude Code's worktree guard can
/// see the git it runs. Its output loses csec's masking; git needs no secret
/// from the wrapper. A list whose git reaches a remote (`push`, `fetch`, …)
/// still registers, marked unwrapped, so csecd can delegate the SSH signing
/// it asks for by anchoring on Claude Code's Bash tool shell.
///
/// One kind is refused: in a session Claude Code has isolated in a worktree,
/// a command the hook would wrap whose git could leave that worktree
/// (`AICommandWorktreeEscape`), since the worktree guard cannot see inside the
/// wrapper. A command naming git that such a session's hook does wrap starts
/// with a space (`programToken`), so the guard does not refuse it for starting
/// with git.
public enum AICommandHook {
    public static let maximumCommandBytes = 1024 * 1024
    public static let managedStatusMessage = "Convenient Security: protected output scanning"
    /// Both clients treat a hook that outlives its timeout as cancelled or failed
    /// and then run the *original* command, unwrapped: Claude Code yields
    /// `hook_cancelled` (`utils/hooks.ts`), Codex records `Failed`. The rewrite
    /// itself takes milliseconds, so the bound only matters when the machine is
    /// saturated or a freshly installed binary is being assessed on first launch;
    /// it is sized so those cases still produce a rewrite, while a wedged hook
    /// cannot stall the agent indefinitely.
    public static let hookTimeoutSeconds = 30
    /// Top-level `description` of the generated Codex hooks document.
    public static let codexConfigurationDescription =
        "Route Bash tool output through csec before it reaches an AI model."

    /// The hook's stdout. Empty means "leave the command as it is": exit 0 with
    /// empty stdout is a clean no-op in both clients. Codex gets it when its
    /// own gates would stop the original command and the wrapper would hide it
    /// from them; Claude Code gets it for a plain git command list
    /// (`AICommandGitPassthrough`). `codexPolicy` reads Codex's rules for the
    /// hook's working directory.
    public static func rewrite(
        input: Data,
        client: AICommandHookClient,
        csecExecutablePath: String,
        codexPolicy: (_ workingDirectory: String?) -> CodexCommandGate.Policy = { _ in CodexCommandGate.Policy() },
        worktreeEnvironment: AICommandWorktreeEscape.Environment = .live,
        shellPrefix: String? = nil
    ) throws -> Data {
        try rewriteWithContext(
            input: input,
            client: client,
            csecExecutablePath: csecExecutablePath,
            codexPolicy: codexPolicy,
            worktreeEnvironment: worktreeEnvironment,
            shellPrefix: shellPrefix
        ).output
    }

    /// The hook's complete stdout, after `register` has been handed the
    /// registration (if there is one). Registration is best effort: whether
    /// `register` returns, throws or runs into its own bound, the output is the
    /// rewrite, and nothing is written to stderr — Claude Code shows a hook's
    /// stderr, and a missing registration only means the command is not
    /// delegated. `register` runs before this returns, so a caller that prints
    /// the result afterwards registers before Claude Code can run anything.
    public static func output(
        input: Data,
        client: AICommandHookClient,
        csecExecutablePath: String,
        codexPolicy: (_ workingDirectory: String?) -> CodexCommandGate.Policy = { _ in CodexCommandGate.Policy() },
        worktreeEnvironment: AICommandWorktreeEscape.Environment = .live,
        shellPrefix: String? = nil,
        register: (AgentCommandRegistration) throws -> Void
    ) throws -> Data {
        let rewrite = try rewriteWithContext(
            input: input,
            client: client,
            csecExecutablePath: csecExecutablePath,
            codexPolicy: codexPolicy,
            worktreeEnvironment: worktreeEnvironment,
            shellPrefix: shellPrefix
        )
        if let registration = rewrite.registration {
            try? register(registration)
        }
        return rewrite.output
    }

    /// The rewrite, plus the registration csecd needs to delegate the command.
    /// A registration is built for Claude Code whenever the output is not
    /// empty, and for an unwrapped git list that reaches a remote, whose
    /// registration is marked unwrapped and digests the command exactly as
    /// typed, which is what the Bash tool shell evaluates (a local-only git
    /// list registers nothing). It is built in every permission mode (csecd,
    /// not the hook, declines a mode other than auto, so the panel can say
    /// why), and only when Claude Code's session, tool-use and agent ids,
    /// permission mode and cwd are all within bounds. Codex never registers:
    /// its approvals cannot be attested. A Claude Code command refused in a
    /// worktree-isolated session (`AICommandWorktreeEscape`) is a denial,
    /// which registers nothing.
    public static func rewriteWithContext(
        input: Data,
        client: AICommandHookClient,
        csecExecutablePath: String,
        codexPolicy: (_ workingDirectory: String?) -> CodexCommandGate.Policy = { _ in CodexCommandGate.Policy() },
        worktreeEnvironment: AICommandWorktreeEscape.Environment = .live,
        shellPrefix: String? = nil
    ) throws -> (output: Data, registration: AgentCommandRegistration?) {
        guard input.count <= maximumCommandBytes,
              let object = try JSONSerialization.jsonObject(with: input) as? [String: Any],
              let event = object["hook_event_name"] as? String else {
            throw AICommandHookError.invalidInput
        }
        guard event == "PreToolUse" else { throw AICommandHookError.unsupportedEvent }
        guard let tool = object["tool_name"] as? String, shellTools(for: client).contains(tool) else {
            throw AICommandHookError.unsupportedTool
        }
        // A Monitor that opens a WebSocket (`ws`, no `command`) runs no
        // shell, so there is nothing to wrap: leave it to Claude Code.
        if tool == "Monitor", (object["tool_input"] as? [String: Any])?["command"] == nil {
            return (Data(), nil)
        }
        guard var updatedInput = object["tool_input"] as? [String: Any],
              updatedInput["command"] is String,
              let command = try? JSONDecoder().decode(HookCommand.self, from: input).toolInput.command,
              !command.isEmpty,
              command.utf8.count <= maximumCommandBytes,
              !command.utf8.contains(0) else {
            throw AICommandHookError.invalidCommand
        }
        let executable = URL(fileURLWithPath: csecExecutablePath)
            .standardizedFileURL.resolvingSymlinksInPath().path
        guard executable.hasPrefix("/"),
              !executable.utf8.contains(0),
              executable.utf8.count <= 4_096 else {
            throw AICommandHookError.invalidExecutablePath
        }

        // Codex's dangerous-command check, its execpolicy prompt/forbidden rules
        // and its apply_patch interception all read argv, which the wrapper would
        // replace with `csec ai -- …`. When any of them could stop the original,
        // leave it unwrapped so Codex still judges it; that one command then runs
        // without output scanning.
        if client == .codex,
           CodexCommandGate.requiresCodexGate(command, policy: codexPolicy(object["cwd"] as? String)) {
            return (Data(), nil)
        }

        // Claude Code's worktree guard reads the command it is about to run
        // and cannot see the git inside `csec ai -- '…'`, so a plain list of
        // git commands reaches Claude Code unchanged, for the guard to judge
        // (and its `cd` moves Claude Code's own shell): the hook prints
        // nothing. A local-only list registers nothing (no `csec ai` or `ssh`
        // will ask csecd for anything). One that reaches a remote registers
        // the command as typed, marked unwrapped: its `ssh` has no `csec ai`
        // above it, and csecd binds it through the Bash tool shell that
        // evaluates exactly this text. Codex has no such guard and keeps its
        // wrapper.
        let launcher = (executable as NSString).lastPathComponent
        // Emit the launcher bare (`csec`) for a clean transcript; only a launcher
        // renamed to something with shell metacharacters would need quoting.
        let launcherToken = isSafeBareShellWord(launcher) ? launcher : shellQuote(launcher)

        var worktreeChecked = false
        // `shellPrefix` is the CLAUDE_CODE_SHELL_PREFIX Claude Code gave this
        // hook. When it is csec's own prefix script, Claude Code runs every Bash
        // and Monitor command through `csec ai` after auto mode has reviewed it
        // as typed (`ClaudeCodeShellPrefix`), so there is nothing to rewrite:
        // the hook prints nothing and registers the command as typed, which is
        // exactly what the framing's `eval` runs. Any other value, or none,
        // keeps the rewrite, so a session without the prefix is never left
        // unwrapped. The worktree escape refusal below stands in for Claude
        // Code's own worktree guard only because that guard reads the
        // rewrite; with no rewrite it reads the command itself.
        if client == .claude, let shellPrefix,
           let expected = ClaudeCodeShellPrefix.prefixPath(csecExecutablePath: executable),
           Array(shellPrefix.utf8) == Array(expected.utf8) {
            return (Data(), claudeRegistration(object, programSHA256: programDigest(command), unwrapped: false))
        }
        if client == .claude {
            // A command the agent already wrote in this hook's own form runs
            // under `csec ai` as typed. Rewriting it would nest a second
            // `csec ai` and, worse, change the input after auto mode's server
            // review: Claude Code then has no verdict for the call and blocks
            // it (2.1.314 retired the local classifier that judged it before),
            // so every such call costs a resubmission and three in a row stop
            // the session at a menu (av-e2sa). Printing nothing keeps the
            // server's verdict on exactly the text that runs. The registration
            // and the worktree refusal are the wrapped path's, for the program
            // `csec ai` will receive.
            let typedProgram = alreadyWrappedProgram(command, launcherToken: launcherToken)
            if typedProgram == nil {
                let passthrough = AICommandGitPassthrough.classify(command)
                if passthrough.isUnwrapped {
                    guard passthrough.registersForDelegation else { return (Data(), nil) }
                    return (Data(), claudeRegistration(object, programSHA256: programDigest(command), unwrapped: true))
                }
            }
            // The guard cannot see inside the wrapper it would judge, so in a
            // session isolated in a worktree csec refuses a wrapped command
            // whose git could leave that worktree, as the guard would have.
            let isolation = AICommandWorktreeEscape.isolation(
                workingDirectory: object["cwd"], transcriptPath: object["transcript_path"], agentID: object["agent_id"])
            if let refusal = AICommandWorktreeEscape.refusal(
                for: typedProgram ?? command, isolation: isolation, workingDirectory: object["cwd"] as? String,
                environment: worktreeEnvironment
            ) {
                return (try claudeDenial(reason: refusal.reason), nil)
            }
            if let typedProgram {
                return (Data(), claudeRegistration(object, programSHA256: programDigest(typedProgram), unwrapped: false))
            }
            if case .inWorktree = isolation, AICommandWorktreeEscape.namesGit(command) { worktreeChecked = true }
        }

        // The rewritten command is what the client executes and what shows in the
        // agent's transcript, so keep it short and legible: the bare launcher name
        // (`csec`), resolved from the client shell's PATH, plus the original
        // program single-quoted with `'`→`'"'"'`. The absolute install path is
        // deliberately NOT embedded here — it made every logged line unreadably
        // long, and the security anchor is elsewhere: the hook *wrapper*
        // (`hookConfiguration`) still invokes csec by absolute path with an `-x`
        // check, so a missing/renamed install fails closed before this rewrite is
        // ever produced. This assumes `csec` is on the PATH the client uses to run
        // Bash tool calls (the installer/user places it there).
        //
        // Both supported clients re-execute updatedInput.command through exactly
        // one POSIX shell parse, so the single-quoted program is recovered
        // verbatim. (The base64 blob this form replaced was never a
        // confidentiality boundary — only a quoting dodge; `csec ai` still decodes
        // it for older rewrites.)
        //
        // - Claude runs `zsh -c "… && eval '<cmd>'"` — one parse. Verified from
        //   live `ps`.
        // - Codex runs `<shell> -c <cmd>` / `-lc` with the command as a single
        //   argument (openai/codex `get_command` → `Shell::derive_exec_args`,
        //   pinned by `shell_tests.rs`; the local zsh-fork path builds the same
        //   `[zsh, "-lc"|"-c", cmd]` vector) — one parse, no re-tokenization.
        //   Verified from source and by round-tripping this exact vector.

        // The command reaches csec through the *client's* own shell, which parses
        // the rewritten line before running it. A command that is a plain sequence
        // of shell-safe words (no operator, glob, quote, expansion, redirect, or
        // whitespace beyond spaces) survives that parse unchanged, so it can be
        // emitted bare — `csec ai -- cat foo`, exactly like `sudo ls -l`: the shell
        // word-splits it into argv and `csec ai` rejoins and runs it. Anything else
        // is a shell program (`|`, `&&`, `$VAR`, `>`, `*`, quotes, newlines) and
        // MUST be single-quoted as one argument (`csec ai -- 'cat foo | grep bar'`,
        // like `sh -c '<program>'`); otherwise the client's shell would interpret
        // those metacharacters itself, running part of the command *outside* the
        // scanner — both wrong and an unscanned-egress hole.
        //
        // A command that names git and passed the worktree escape check also
        // starts with a space (`programToken`), so the guard reading the
        // rewrite does not take a command that starts with git for a git
        // launch.
        let commandToken = programToken(forCommand: command, worktreeChecked: worktreeChecked)
        updatedInput["command"] = "\(launcherToken) ai -- \(commandToken)"
        let output = try JSONSerialization.data(
            withJSONObject: ["hookSpecificOutput": hookSpecificOutput(client: client, updatedInput: updatedInput)],
            options: [.sortedKeys]
        )
        guard client == .claude, !output.isEmpty else { return (output, nil) }
        return (output, claudeRegistration(
            object,
            programSHA256: programDigest(launchedProgram(forCommand: command, worktreeChecked: worktreeChecked)),
            unwrapped: false
        ))
    }

    /// The registration for a Claude Code hook input, or nil when any field
    /// is out of bounds. `agent_id` is absent (or null) outside a subagent;
    /// any other non-string value is malformed input: no registration, rather
    /// than a registration that silently drops it.
    private static func claudeRegistration(
        _ object: [String: Any], programSHA256: String, unwrapped: Bool
    ) -> AgentCommandRegistration? {
        if let agentID = object["agent_id"], !(agentID is String), !(agentID is NSNull) {
            return nil
        }
        return AgentCommandRegistration(
            client: .claude,
            sessionID: object["session_id"] as? String ?? "",
            toolUseID: object["tool_use_id"] as? String ?? "",
            agentID: object["agent_id"] as? String,
            permissionMode: object["permission_mode"] as? String ?? "",
            hookCWD: object["cwd"] as? String ?? "",
            programSHA256: programSHA256,
            unwrapped: unwrapped
        )
    }

    /// The program `csec ai` runs for a hook rewrite of `command`. A bare-safe
    /// command reaches `csec ai` as words the client's shell split on spaces,
    /// which `csec ai` rejoins with single spaces, so `"ls  -l"` runs as
    /// `"ls -l"`; a quoted one arrives as one word, unchanged, and one that
    /// passed the worktree escape check with the leading space `programToken`
    /// adds.
    /// The registration digests this, and `csec ai` rebuilds its program with
    /// `launchedProgram(fromWords:)`, so the two cannot drift.
    public static func launchedProgram(forCommand command: String, worktreeChecked: Bool = false) -> String {
        if worktreeChecked { return launchedProgram(fromWords: [worktreeCheckedProgram(command)]) }
        guard isBareShellSafe(command) else { return launchedProgram(fromWords: [command]) }
        return launchedProgram(fromWords: command.split(separator: " ").map(String.init))
    }

    /// The text after `ai --` in the rewrite of `command`: bare when it is
    /// bare-safe, otherwise single-quoted as one word.
    ///
    /// For a command that names git, run in a session Claude Code has
    /// isolated in a worktree and in that worktree (`worktreeChecked`), it is
    /// always one quoted word whose program starts with a space, a no-op for
    /// the shell. Claude Code 2.1.280's worktree guard reads `csec ai -- '…'` as an
    /// unknown launcher and refuses it when the first whitespace-split word of
    /// an operand is git or a shell (`git log | head`, `git fetch && swift
    /// build`), or when a word before the last operand is git (bare `grep -rn
    /// git docs`); after the space that first word is empty. The guard then
    /// judges `' git log | head'` exactly as it already judges `'true && git
    /// log | head'`, which it allows, so nothing runs that could not already
    /// run, and it still refuses an operand with a quote, backquote, `$` or
    /// backslash and a word naming git. Where git runs has been decided before this, by
    /// `AICommandWorktreeEscape`, which judges every such command and has
    /// passed this one. A command that names no git, which that check does
    /// not judge, keeps the ordinary form, and the guard's rules for it (a
    /// shell as the first word among them) are unchanged (csec-m8sl).
    public static func programToken(forCommand command: String, worktreeChecked: Bool) -> String {
        if worktreeChecked { return shellQuote(worktreeCheckedProgram(command)) }
        return isBareShellSafe(command) ? command : shellQuote(command)
    }

    private static func worktreeCheckedProgram(_ command: String) -> String {
        " " + command
    }

    /// The program `csec ai` runs for `command` when it is already this
    /// hook's own form, `<launcherToken> ai -- <tail>`, or nil. The tail is
    /// either bare-safe words, which the client's shell splits on spaces and
    /// `csec ai` rejoins, or exactly `shellQuote(program)`, which that shell
    /// reads as the one word `program`. Nothing else is read: the quoted form
    /// must re-encode to the same bytes, so no text can sit outside the
    /// quotes, and a tail with no words gives `csec ai` nothing to run.
    public static func alreadyWrappedProgram(_ command: String, launcherToken: String) -> String? {
        let prefix = Array("\(launcherToken) ai -- ".utf8)
        let bytes = Array(command.utf8)
        guard bytes.count > prefix.count, bytes.starts(with: prefix) else { return nil }
        let tail = String(decoding: bytes[prefix.count...], as: UTF8.self)
        if isBareShellSafe(tail) {
            let words = tail.split(separator: " ").map(String.init)
            return words.isEmpty ? nil : launchedProgram(fromWords: words)
        }
        let tailBytes = Array(tail.utf8)
        guard tailBytes.count >= 2, tailBytes.first == UInt8(ascii: "'"), tailBytes.last == UInt8(ascii: "'") else {
            return nil
        }
        let program = String(decoding: tailBytes.dropFirst().dropLast(), as: UTF8.self)
            .replacingOccurrences(of: "'\"'\"'", with: "'", options: .literal)
        guard !program.isEmpty, Array(shellQuote(program).utf8) == tailBytes else { return nil }
        return program
    }

    /// The program `csec ai` runs for the words after `--`.
    public static func launchedProgram(fromWords words: [String]) -> String {
        words.joined(separator: " ")
    }

    /// SHA-256 of a program's UTF-8 bytes, 64 lowercase hex: the registration's
    /// `programSHA256`, and what csecd compares with the `csec ai` request's
    /// program. Never logged.
    public static func programDigest(_ program: String) -> String {
        SHA256.hash(data: Data(program.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    /// The tools whose `tool_input.command` the client runs in a shell. Claude
    /// Code's Monitor runs its command through the same Bash tool shell, under
    /// the same permission check and classifier, as Bash (2.1.280), so it is
    /// wrapped and registered exactly as a Bash call is. Codex has only Bash.
    public static func shellTools(for client: AICommandHookClient) -> [String] {
        switch client {
        case .claude: return ["Bash", "Monitor"]
        case .codex: return ["Bash"]
        }
    }

    /// The hook configuration's matcher: every shell tool, as a name list.
    public static func matcher(for client: AICommandHookClient) -> String {
        shellTools(for: client).joined(separator: "|")
    }

    /// `tool_input.command` exactly as the client has it. JSONSerialization drops
    /// a leading U+FEFF from a string value; JSONDecoder keeps it, as Codex's
    /// serde_json and Claude Code's JSON.parse do, so the gate judges, and the
    /// rewrite runs, the command the client would have run.
    private struct HookCommand: Decodable {
        struct ToolInput: Decodable { let command: String }
        let toolInput: ToolInput
        enum CodingKeys: String, CodingKey { case toolInput = "tool_input" }
    }

    /// The rewrite must never carry more authority than the client's own
    /// permission system would grant the original command.
    ///
    /// - Claude Code: `updatedInput` with **no** `permissionDecision` is a
    ///   passthrough rewrite — the rewritten command then goes through Claude's
    ///   normal permission flow (rules, the auto-mode classifier, prompts). An
    ///   `"allow"` here would skip all of that for every Bash call: the classifier
    ///   never runs, content-matching deny rules never match the `csec ai -- …`
    ///   form, and manual mode stops prompting (verified against Claude Code
    ///   2.1.280 and the `toolHooks.ts` hook-decision resolver). Delegated
    ///   approvals rest on this: csecd accepts a registered command as judged
    ///   by the classifier, which an `allow` here would have skipped. Claude
    ///   Code reads an approval from two places (2.1.88 `utils/hooks.ts`
    ///   `processHookJSONOutput`): `hookSpecificOutput.permissionDecision` and
    ///   the legacy top-level `decision: "approve"`; a `PermissionRequest`
    ///   output's `decision.behavior` is a third, for another event. So the
    ///   Claude output is exactly `{"hookSpecificOutput": {"hookEventName":
    ///   "PreToolUse", "updatedInput": …}}` — nothing at the top level beside
    ///   it (bin/ci and the selftest pin both levels).
    /// - Codex: `updatedInput` is honoured only together with
    ///   `permissionDecision: "allow"`, and that `allow` grants nothing — Codex
    ///   has no permission field on its PreToolUse outcome, and its sandbox,
    ///   approval policy and reviewer all still run on the rewritten command
    ///   (`hooks/src/engine/output_parser.rs`, `core/src/hook_runtime.rs`).
    ///   Any other shape is rejected as a failed hook and the original command
    ///   would run unwrapped.
    static func hookSpecificOutput(
        client: AICommandHookClient,
        updatedInput: [String: Any]
    ) -> [String: Any] {
        switch client {
        case .claude:
            return [
                "hookEventName": "PreToolUse",
                "updatedInput": updatedInput,
            ]
        case .codex:
            return [
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "permissionDecisionReason": "Route command output through the csec active-secret scanner",
                "updatedInput": updatedInput,
            ]
        }
    }

    /// The Claude Code output that refuses a command: a `deny`, which Claude
    /// Code shows the agent with its reason and which grants nothing, so it
    /// can never carry more authority than the original command. It is the
    /// only decision the hook ever writes (bin/ci pins it).
    static func claudeDenial(reason: String) throws -> Data {
        try JSONSerialization.data(
            withJSONObject: ["hookSpecificOutput": [
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            ]],
            options: [.sortedKeys]
        )
    }

    public static func hookConfiguration(
        client: AICommandHookClient,
        csecExecutablePath: String
    ) throws -> Data {
        let executable = URL(fileURLWithPath: csecExecutablePath)
            .standardizedFileURL.resolvingSymlinksInPath().path
        guard executable.hasPrefix("/"),
              !executable.utf8.contains(0),
              executable.utf8.count <= 4_096 else {
            throw AICommandHookError.invalidExecutablePath
        }

        let handler: [String: Any]
        switch client {
        case .claude:
            // Always enter through the system shell and translate every launcher
            // failure to status 2. Both supported clients treat that status as a
            // denial; a removed/moved csec binary must not silently let the
            // original unscanned command run.
            handler = [
                "type": "command",
                "command": "/bin/sh",
                "args": [
                    "-c", failClosedHookProgram,
                    "csec-ai-hook", executable, client.rawValue,
                ],
                "timeout": hookTimeoutSeconds,
                "statusMessage": managedStatusMessage,
            ]
        case .codex:
            // Codex command hooks currently use a shell command string.
            handler = [
                "type": "command",
                "command": "/bin/sh -c \(shellQuote(failClosedHookProgram)) "
                    + "csec-ai-hook \(shellQuote(executable)) \(client.rawValue)",
                "timeout": hookTimeoutSeconds,
                "statusMessage": managedStatusMessage,
            ]
        }

        var configuration: [String: Any] = [
            "hooks": [
                "PreToolUse": [[
                    "matcher": matcher(for: client),
                    "hooks": [handler],
                ]],
            ],
        ]
        // Codex documents optional top-level metadata in hooks.json. Claude's
        // settings schema does not need it, so keep its generated fragment to
        // the common `hooks` object only.
        if client == .codex {
            configuration["description"] = codexConfigurationDescription
        }
        return try JSONSerialization.data(
            withJSONObject: configuration,
            options: [.prettyPrinted, .sortedKeys]
        ) + Data("\n".utf8)
    }

    public static func encodeShellCommand(_ command: String) -> String {
        Data(command.utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    public static func decodeShellCommand(_ encoded: String) throws -> String {
        guard !encoded.isEmpty,
              encoded.utf8.count <= maximumCommandBytes * 2,
              encoded.utf8.allSatisfy({
                  ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122)
                      || ($0 >= 48 && $0 <= 57) || $0 == 45 || $0 == 95
              }) else {
            throw AICommandHookError.invalidCommand
        }
        var base64 = encoded
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = base64.utf8.count % 4
        if remainder > 0 { base64 += String(repeating: "=", count: 4 - remainder) }
        guard let data = Data(base64Encoded: base64),
              data.count <= maximumCommandBytes,
              let command = String(data: data, encoding: .utf8),
              !command.isEmpty,
              !command.utf8.contains(0) else {
            throw AICommandHookError.invalidCommand
        }
        return command
    }

    /// `value` single-quoted for a POSIX shell. The replacement is literal:
    /// Foundation otherwise compares composed character sequences, so a `'`
    /// followed by a combining mark (`'\u{301}`) would not match, would stay
    /// unescaped, and would end the quoted word, running the rest of the
    /// command in the client's shell, outside `csec ai`.
    private static func shellQuote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\"'\"'", options: .literal) + "'"
    }

    /// Whether a token can appear unquoted in a shell command line: a non-empty
    /// run of characters no shell treats specially. Used to keep the launcher name
    /// bare (`csec`) in the rewritten command rather than `'csec'`.
    private static func isSafeBareShellWord(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.allSatisfy {
            ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122)
                || ($0 >= 48 && $0 <= 57) || $0 == 45 || $0 == 95 || $0 == 46
        }
    }

    /// Whether a whole command can be emitted unquoted after `ai --`: a non-empty
    /// sequence of shell-safe words separated by spaces, containing no character
    /// the client's shell would interpret (no operator `|&;<>()`, glob `*?[]{}`,
    /// expansion `$` `` ` `` `~`, quote, `=`, `!`, `#`, or whitespace other than a
    /// plain space). Such a command survives the client's shell parse unchanged and
    /// `csec ai` rejoins the argv with single spaces to the same program. The
    /// allowed set is deliberately conservative: only `A-Z a-z 0-9`, space, and
    /// `- . / _ :`, none of which carry shell meaning. `:` acts only beside
    /// characters that stay quoted (`${x:-y}`, `!!:h`, `*(:t)`, `a=~:~`), and
    /// keeping it bare lets an agent's prefix rule on `csec ai -- …` match a
    /// path such as a page cursor (`…/snapshot:4000`).
    private static func isBareShellSafe(_ command: String) -> Bool {
        !command.isEmpty && command.utf8.allSatisfy {
            ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122)   // A-Z a-z
                || ($0 >= 48 && $0 <= 57)                       // 0-9
                || $0 == 32                                     // space
                || $0 == 45 || $0 == 46 || $0 == 47 || $0 == 95 // - . / _
                || $0 == 58                                     // :
        }
    }

    /// The proposed Bash program remains on hook stdin. Positional arguments
    /// carry only the trusted csec path and a fixed client label, avoiding a
    /// second interpretation of either the proposed command or its contents.
    ///
    /// Every failure exits 2 **with a reason on stderr**. Claude Code treats any
    /// status 2 as a block, but Codex blocks only on status 2 with non-empty
    /// stderr; a silent status 2 (e.g. `csec hook` killed by a signal) is a
    /// *failed* hook there, and Codex then runs the original command unwrapped
    /// (`hooks/src/events/pre_tool_use.rs`).
    ///
    /// An install replaces the app bundle by moving the old one out and the
    /// new one in, and the launcher path does not exist in between (about
    /// 25 ms measured on PackageKit's bundle shove). So a launcher that is not
    /// executable, or that the shell could not exec (status 126 or 127: csec
    /// never ran, so stdin is still unread), is tried again every 0.1 s for
    /// 50 tries before the command is denied. That bound is far past the gap
    /// and far inside `hookTimeoutSeconds`, after which a client runs the
    /// command unwrapped. A status csec itself returned is denied at once.
    /// `csec hook` stays a direct child of this shell: csecd's registration
    /// check requires its parent to be the `-c` shell.
    private static let failClosedHookProgram = """
    csec_path=$1
    client=$2
    tries=0
    while :; do
      if [ -x "$csec_path" ]; then
        "$csec_path" hook "$client"
        status=$?
        if [ "$status" -eq 0 ]; then
          exit 0
        fi
        if [ "$status" -ne 126 ] && [ "$status" -ne 127 ]; then
          printf 'csec hook: exited with status %s; command denied\\n' "$status" >&2
          exit 2
        fi
      fi
      tries=$((tries + 1))
      if [ "$tries" -ge 50 ]; then
        printf '%s\\n' 'csec hook: protected output scanner unavailable for 5 s; command denied. This blocks every coding agent on this Mac until Convenient Security is reinstalled.' >&2
        exit 2
      fi
      /bin/sleep 0.1
    done
    """
}
