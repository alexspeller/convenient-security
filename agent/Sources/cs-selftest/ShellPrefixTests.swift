import ConvenientSecurity
import CryptoKit
import Foundation

// csec as Claude Code's CLAUDE_CODE_SHELL_PREFIX (csec-0.83.1, av-e2sa): which
// argument `csec ai --claude-code-shell` wraps and which it runs unwrapped, the
// command a framing's `eval` names, the op guard spliced in after the shell
// snapshot (through a real zsh), the argv csecd reads, the hook that stops
// rewriting only under csec's own prefix, the gates that accept exactly that
// prefix, setup's settings edit, and the script the bundle ships.

private let bundleCsec = "/Applications/ConvenientSecurity.app/Contents/MacOS/csec"
private let bundlePrefix =
    "/Applications/ConvenientSecurity.app/Contents/Resources/claude-code-shell/csec-claude-code-shell"

func shellPrefixTests() {
    print("\n# csec as Claude Code's shell prefix")
    prefixPathTests()
    framingTests()
    guardSpliceTests()
    argumentTests()
    hookUnderPrefixTests()
    gateTests()
    setupPlanTests()
    shippedScriptTests()
}

private func prefixPathTests() {
    check(ClaudeCodeShellPrefix.prefixPath(csecExecutablePath: bundleCsec) == bundlePrefix
          && ClaudeCodeShellPrefix.prefixPath(
              csecExecutablePath: "/Applications/ConvenientSecurity.app/Contents/MacOS/csecd") == bundlePrefix,
          "prefix path: csec and csecd in the bundle name the same prefix script")
    check(["/usr/local/bin/csec", "/repo/agent/.build/debug/csec", "/x/Contents/MacOS/csec",
           "/Applications/ConvenientSecurity.app/Contents/MacOS/other"].allSatisfy {
        ClaudeCodeShellPrefix.prefixPath(csecExecutablePath: $0) == nil
    }, "prefix path: a csec outside an app bundle has no prefix script")
    check(ClaudeCodeShellPrefix.isCsecPrefix(bundlePrefix, accepted: bundlePrefix)
          && !ClaudeCodeShellPrefix.isCsecPrefix(bundlePrefix + " ", accepted: bundlePrefix)
          && !ClaudeCodeShellPrefix.isCsecPrefix(nil, accepted: bundlePrefix)
          && !ClaudeCodeShellPrefix.isCsecPrefix(bundlePrefix, accepted: nil)
          && !ClaudeCodeShellPrefix.isCsecPrefix("/Applications/Conve\u{301}nientSecurity.app", accepted:
              "/Applications/Convénient Security.app"),
          "prefix path: only the exact bytes of csec's prefix are csec's")
}

private func framingTests() {
    let commands = ["ls -la", "printf '%s' \"$TOKEN\" | wc -c", "echo 'it'\"'\"'s'\nwc -l < /etc/hosts",
                    "eval 'echo nested'", "echo '&& pwd -P >| /tmp/x'"]
    for command in commands {
        let framing = claudeFraming(command)
        let parsed = ClaudeCodeShellPrefix.framing(framing)
        check(parsed?.command == command && !ClaudeCodeShellPrefix.runsUnwrapped(framing),
              "framing: Claude Code's framing of \(command.debugDescription) names exactly that command")
        let quotedPath = claudeFraming(command, cwdFile: "'/var/folders/a b/T/claude-1-cwd'")
        check(ClaudeCodeShellPrefix.framing(quotedPath)?.command == command,
              "framing: a single-quoted cwd file still ends the framing (\(command.debugDescription))")
    }
    // A model's command sits inside eval's quotes: it cannot add Claude
    // Code's ending, or remove it.
    let inside = "source x && eval 'ls && pwd -P >| /tmp/x'"
    check(ClaudeCodeShellPrefix.framing(inside) == nil, "framing: an ending inside the eval's quotes is no ending")
    // Hooks and MCP command lines name neither marker: they run unwrapped.
    let unwrapped = ["/Users/x/.claude/hooks/pre-tool.sh", "python3 -m harbor.hooks stop",
                     "'/usr/local/bin/node' '/opt/mcp/server.js' '--stdio'", "jq -r .tool_input.command | evaluate-x"]
    check(unwrapped.allSatisfy(ClaudeCodeShellPrefix.runsUnwrapped),
          "framing: hook and MCP command lines (no eval word, no pwd ending) run unwrapped")
    // Anything framing-like that csec cannot read is wrapped whole, never
    // unwrapped: a future framing, a second eval, a hook mentioning eval.
    let wrapped = [claudeFraming("ls").replacingOccurrences(of: " && eval '", with: " && eval 'true' && eval '"),
                   claudeFraming("ls").replacingOccurrences(of: " && pwd -P >| ", with: " && pwd -L >| "),
                   claudeFraming("ls") + " && true", "do-thing && eval \"$x\"", "pwd -P >| /tmp/y",
                   claudeFraming("ls", cwdFile: "/tmp/a;b"), claudeFraming("ls", cwdFile: "'/tmp/a'b'")]
    check(wrapped.allSatisfy { ClaudeCodeShellPrefix.framing($0) == nil && !ClaudeCodeShellPrefix.runsUnwrapped($0) },
          "framing: a framing csec cannot read, or text naming eval or the ending, is wrapped whole")
    framing319Tests()
}

/// Claude Code 2.1.319's builder adds pieces to some commands' framings
/// (csec-0.98): a bash-version guard first, behind a server flag, for a
/// command its reader cannot prove simple, and on macOS a `git` function
/// for a command that runs `git grep`. Every piece is copied from the
/// official darwin-arm64 build.
private func framing319Tests() {
    let awk = "awk '/^## X$/{f=1;print;next} f&&/^##? /{exit} f' docs/README.md | head -60"
    let heredoc = "gh pr create --title 'Lessons: add @electronics' --body-file - <<'EOF'\n## Summary\n\n"
        + "- Adds `@electronics` (Robotics's group) and it's in the Monday summary: $(not run) \\n\n\nEOF"
    let gitGrep = "git grep -n 'claude-code-shell' -- agent | head -5"
    for command in [awk, heredoc, gitGrep, "ls -la"] {
        for guardLevel in [nil, 4, 5] as [Int?] {
            let framing = claudeFraming319(command, bashGuard: guardLevel)
            check(ClaudeCodeShellPrefix.framing(framing)?.command == command,
                  "framing 2.1.319: \(command.prefix(24).debugDescription) with bash guard \(guardLevel.map(String.init) ?? "none")"
                  + " names exactly that command")
        }
    }
    // Only a quoted eval of literal text is Claude Code's own piece; any other
    // extra command that can run eval still leaves the framing unread.
    let plain = claudeFraming319("ls -la")
    for extra in ["'eval' \"$X\"", "'eval' 'true' \"$X\"", "\\eval 'true'", "builtin 'eval' 'true'",
                  "eval 'true'", "X=1 'eval' 'true'", "'eval'", "\"$E\" 'true'", "'ev'$A'al' 'true'",
                  "'eval' 'a'\\'$X'b'", "'eval' 'a'\\\"'b'", "'eval' 'a''b'"] {
        let framing = plain.replacingOccurrences(of: " && eval '", with: " && { \(extra) 2>/dev/null || 'true'; } && eval '")
        check(framing != plain && ClaudeCodeShellPrefix.framing(framing) == nil,
              "framing 2.1.319: an added \(extra.debugDescription) still leaves the framing unread")
    }
    let literal = plain.replacingOccurrences(of: " && eval '", with: " && { 'eval' 'true' \"x\"y 2>/dev/null || 'true'; } && eval '")
    check(ClaudeCodeShellPrefix.framing(literal)?.command == "ls -la",
          "framing 2.1.319: a quoted eval whose every argument is literal is read past")
}

/// Claude Code 2.1.319's Bash framing around `command` with a snapshot and
/// a shell prefix set, including the pieces it adds for some commands.
func claudeFraming319(_ command: String, bashGuard: Int? = nil,
                      cwdFile: String = "/var/folders/xy/abc/T/claude-1a2b-cwd") -> String {
    func quoted(_ text: String) -> String { "'" + text.replacingOccurrences(of: "'", with: "'\\''") + "'" }
    var pieces: [String] = []
    if let bashGuard {
        pieces.append("{ case \"${BASH_VERSINFO-}\" in \(bashGuard == 4 ? "'2'|'3'" : "'2'|'3'|'4'")) "
            + "\\builtin printf '%s\\n' '__CLAUDE_CODE_DID_NOT_RUN_BASH_TOO_OLD='\"${BASH_VERSION-}\" >&2; "
            + "\\builtin exit 126; \\exit 126;; esac; }")
    }
    pieces.append("source '/synthetic/.claude/shell-snapshots/snapshot-zsh-1.sh' 2>/dev/null || true")
    pieces.append("{ shopt -u extglob || setopt NO_EXTENDED_GLOB NO_BARE_GLOB_QUAL; } >/dev/null 2>&1 || true")
    pieces.append("{ \\builtin unalias -- 'unsetenv'; \\builtin unset -f -- 'unsetenv'; } >/dev/null 2>&1 || true")
    if command.contains("git grep") {
        let function = [
            "function git { 'local' _cc_skip= _cc_word;",
            "for _cc_word in ${1+\"$@\"}; do",
            "if [ -n \"$_cc_skip\" ]; then _cc_skip=; continue; fi;",
            "case \"$_cc_word\" in",
            "-C|-c|--attr-source|--shallow-file|--git-dir|--separate-git-dir|--work-tree|--namespace|--super-prefix"
                + "|--config-env) _cc_skip=1 ;;",
            "-*) ;;",
            "grep) '/usr/bin/env' LC_ALL=C 'git' ${1+\"$@\"}; 'return' ;;",
            "*) break ;;",
            "esac; done;",
            "'command' 'git' ${1+\"$@\"}; }",
        ].joined(separator: " ")
        let install = [
            "if ! 'typeset' -f 'git' >/dev/null 2>&1 && ! 'alias' 'git' >/dev/null 2>&1 &&",
            "( 'eval' \(quoted(function)) ) >/dev/null 2>&1;",
            "then 'eval' \(quoted(function)); fi",
        ].joined(separator: " ")
        pieces.append("{ 'eval' \(quoted(install)) 2>/dev/null || 'true'; }")
    }
    let singleQuoted = "'" + command.replacingOccurrences(of: "'", with: "'\"'\"'") + "'"
    let heredoc = command.contains("<<")
    pieces.append("eval " + singleQuoted + (heredoc ? "" : " < /dev/null"))
    pieces.append("pwd -P >| " + cwdFile)
    return pieces.joined(separator: " && ")
}

/// The op guard must act after the snapshot the framing sources, which can
/// reset PATH and define `op`. Real zsh, no startup files.
private func guardSpliceTests() {
    guard let directory = try? FileManager.default.url(
        for: .itemReplacementDirectory, in: .userDomainMask,
        appropriateFor: URL(fileURLWithPath: NSTemporaryDirectory()), create: true) else {
        check(false, "guard splice: a temporary directory")
        return
    }
    defer { try? FileManager.default.removeItem(at: directory) }
    let snapshot = directory.appendingPathComponent("snapshot.sh").path
    let cwdFile = directory.appendingPathComponent("cwd").path
    try? Data("export PATH=/usr/bin:/bin\nop() { print SNAPSHOT-OP; }\n".utf8).write(to: URL(fileURLWithPath: snapshot))
    guard let credentialGuard = try? AICommandCredentialGuard(executablePath: "/nonexistent/csec") else {
        check(false, "guard splice: a temporary op guard")
        return
    }
    defer { credentialGuard.cleanup() }
    let framing = "source '\(snapshot)' 2>/dev/null || true && eval 'op read x' < /dev/null && pwd -P >| '\(cwdFile)'"
    guard let parsed = ClaudeCodeShellPrefix.framing(framing) else {
        check(false, "guard splice: the test framing parses")
        return
    }
    let guarded = ClaudeCodeShellPrefix.guarded(framing, evalStart: parsed.evalStart, setup: credentialGuard.framingSetup)
    func run(_ script: String) -> (status: Int32, output: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/zsh")
        process.arguments = ["-f", "-c", script]
        process.environment = ["PATH": "/usr/bin:/bin", "HOME": directory.path, "ZDOTDIR": directory.path]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        guard (try? process.run()) != nil else { return (-1, "") }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationStatus, String(decoding: data, as: UTF8.self))
    }
    let spliced = run(guarded)
    check(spliced.status == 126 && spliced.output.contains("csec:") && !spliced.output.contains("SNAPSHOT-OP"),
          "guard splice: after the snapshot reset PATH and defined op, the spliced guard still refuses op "
          + "(\(spliced.status))")
    let prepended = run(credentialGuard.commandLine(forProgram: framing)[2])
    check(prepended.output.contains("SNAPSHOT-OP"),
          "guard splice: the guard put before the framing, as csec ai does for a plain program, would lose to the snapshot")
    let plain = "source '\(snapshot)' 2>/dev/null || true && eval 'print -r -- ran' < /dev/null && pwd -P >| '\(cwdFile)'"
    if let plainParsed = ClaudeCodeShellPrefix.framing(plain) {
        let ran = run(ClaudeCodeShellPrefix.guarded(
            plain, evalStart: plainParsed.evalStart, setup: credentialGuard.framingSetup))
        let cwd = (try? String(contentsOfFile: cwdFile, encoding: .utf8)) ?? ""
        check(ran.status == 0 && ran.output == "ran\n" && !cwd.isEmpty,
              "guard splice: an ordinary command runs and the framing still writes its cwd file")
    } else {
        check(false, "guard splice: the plain framing parses")
    }
}

private func argumentTests() {
    let framing = claudeFraming("ls -la")
    check((try? AICommandExec.program(fromArguments: [ClaudeCodeShellPrefix.option, framing])) == framing,
          "argv: --claude-code-shell runs its one argument as the program")
    for arguments in [[ClaudeCodeShellPrefix.option], [ClaudeCodeShellPrefix.option, ""],
                      [ClaudeCodeShellPrefix.option, framing, "x"], ["--destination", "ai", ClaudeCodeShellPrefix.option, framing],
                      ["--", ClaudeCodeShellPrefix.option, framing]] {
        let program = try? AICommandExec.program(fromArguments: arguments)
        check(arguments.first == "--" ? program != framing : program == nil,
              "argv: \(arguments.map(\.debugDescription).joined(separator: " ").prefix(60)) is not the prefix form")
    }
    check(AICommandExec.registeredProgram(fromProcessArguments: ["csec", "ai", ClaudeCodeShellPrefix.option, framing])
          == "ls -la"
          && AICommandExec.program(fromProcessArguments: ["csec", "ai", ClaudeCodeShellPrefix.option, framing]) == framing,
          "argv: csecd holds the request to the framing and binds the command inside its eval")
    check(AICommandExec.registeredProgram(fromProcessArguments: ["csec", "ai", ClaudeCodeShellPrefix.option, "hook.sh"])
          == nil
          && AICommandExec.registeredProgram(fromProcessArguments: ["csec", "ai", "--", "ls", "-la"]) == "ls -la",
          "argv: an unreadable prefix argument binds nothing; a -- program binds itself")
}

private func hookUnderPrefixTests() {
    func input(_ command: String) -> Data {
        (try? JSONSerialization.data(withJSONObject: [
            "hook_event_name": "PreToolUse", "tool_name": "Bash",
            "tool_input": ["command": command, "description": "synthetic"],
            "transcript_path": "/Users/synthetic/.claude/projects/p/s.jsonl",
            "session_id": "0f3c2a4e-1b2d-4c6e-8f90-a1b2c3d4e5f6", "tool_use_id": "toolu_01ABCdef_ghi-J",
            "permission_mode": "auto", "cwd": "/Users/synthetic/project",
        ])) ?? Data()
    }
    for command in ["ls  -la", "printf '%s' \"$TOKEN\" | wc -c", "git status", "csec ai -- 'ls'"] {
        let under = try? AICommandHook.rewriteWithContext(
            input: input(command), client: .claude, csecExecutablePath: bundleCsec, shellPrefix: bundlePrefix)
        let digest = SHA256.hash(data: Data(command.utf8)).map { String(format: "%02x", $0) }.joined()
        check(under?.output.isEmpty == true && under?.registration?.programSHA256 == digest
              && under?.registration?.unwrapped == false,
              "hook: under csec's prefix \(command.debugDescription) prints nothing and registers the command as typed")
    }
    // Isolated in a worktree, csec's escape refusal stood in for Claude Code's
    // own worktree guard only because that guard read the rewrite; with no
    // rewrite the guard reads the command itself, so csec adds nothing.
    let escape = "env git push"
    let isolated = (try? JSONSerialization.data(withJSONObject: [
        "hook_event_name": "PreToolUse", "tool_name": "Bash",
        "tool_input": ["command": escape, "description": "synthetic"],
        "transcript_path": "/Users/synthetic/.claude/projects/-Users-synthetic-project--claude-worktrees-probe/s.jsonl",
        "session_id": "0f3c2a4e-1b2d-4c6e-8f90-a1b2c3d4e5f6", "tool_use_id": "toolu_01ABCdef_ghi-J",
        "permission_mode": "auto", "cwd": "/Users/synthetic/project/.claude/worktrees/probe",
    ])) ?? Data()
    let rewritten = try? AICommandHook.rewriteWithContext(
        input: isolated, client: .claude, csecExecutablePath: bundleCsec)
    let underIsolated = try? AICommandHook.rewriteWithContext(
        input: isolated, client: .claude, csecExecutablePath: bundleCsec, shellPrefix: bundlePrefix)
    let escapeDigest = SHA256.hash(data: Data(escape.utf8)).map { String(format: "%02x", $0) }.joined()
    check(rewritten.map { String(decoding: $0.output, as: UTF8.self).contains("\"deny\"") } == true
          && underIsolated?.output.isEmpty == true && underIsolated?.registration?.programSHA256 == escapeDigest,
          "hook: in an isolated worktree the escape csec refuses when it rewrites is left, under its prefix, to Claude Code's own guard")
    for prefix in [nil, "/tmp/other", bundlePrefix + "x"] as [String?] {
        let other = try? AICommandHook.rewriteWithContext(
            input: input("ls  -la"), client: .claude, csecExecutablePath: bundleCsec, shellPrefix: prefix)
        check(other?.output.isEmpty == false,
              "hook: with prefix \(prefix.map(\.debugDescription) ?? "unset") the command is still rewritten")
    }
    // Not /usr/local/bin/csec: on a Mac with csec installed that is a symlink
    // into the bundle, and the hook resolves symlinks before it compares.
    let unbundled = try? AICommandHook.rewriteWithContext(
        input: input("ls  -la"), client: .claude, csecExecutablePath: "/nonexistent-csec-selftest/bin/csec",
        shellPrefix: bundlePrefix)
    check(unbundled?.output.isEmpty == false, "hook: a csec with no prefix script of its own keeps rewriting")
    let codex = try? AICommandHook.rewriteWithContext(
        input: input("ls  -la"), client: .codex, csecExecutablePath: bundleCsec, shellPrefix: bundlePrefix)
    check(codex?.output.isEmpty == false, "hook: Codex has no shell prefix and keeps its rewrite")
}

private func gateTests() {
    let name = ClaudeDelegationGateLists.shellPrefixName
    check(ClaudeDelegationGateLists.environmentNames.contains(name)
          && ClaudeDelegationGateLists.settingsEnvironmentEntry(matching: name) == name,
          "gate: the shell prefix stays a listed name, in P's environment and in settings")
    check(ClaudeDelegationGateLists.isAcceptedShellPrefix(name: name, value: bundlePrefix, accepted: bundlePrefix),
          "gate: exactly csec's prefix is accepted")
    for value in ["/tmp/other", bundlePrefix + " ", 1 as Any] as [Any] {
        check(!ClaudeDelegationGateLists.isAcceptedShellPrefix(name: name, value: value, accepted: bundlePrefix),
              "gate: a prefix \(String(describing: value).debugDescription) still declines")
    }
    check(!ClaudeDelegationGateLists.isAcceptedShellPrefix(name: name, value: bundlePrefix, accepted: nil)
          && !ClaudeDelegationGateLists.isAcceptedShellPrefix(name: "ZDOTDIR", value: bundlePrefix, accepted: bundlePrefix),
          "gate: with no installed prefix every value declines, and no other name is accepted")
    check(ClaudeCodeShellPrefix.installedPrefixPath == nil,
          "gate: this selftest runs from no app bundle, so it accepts no prefix at all")
}

private func setupPlanTests() {
    guard let directory = try? FileManager.default.url(
        for: .itemReplacementDirectory, in: .userDomainMask,
        appropriateFor: URL(fileURLWithPath: NSTemporaryDirectory()), create: true) else {
        check(false, "setup: a temporary directory")
        return
    }
    defer { try? FileManager.default.removeItem(at: directory) }
    let path = directory.appendingPathComponent("settings.json").path
    func write(_ object: [String: Any]) {
        let data = (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data()
        FileManager.default.createFile(atPath: path, contents: data, attributes: [.posixPermissions: 0o600])
    }
    func env() -> [String: Any]? {
        guard let data = FileManager.default.contents(atPath: path),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        return object["env"] as? [String: Any]
    }
    let name = ClaudeDelegationGateLists.shellPrefixName
    write(["env": ["FOO": "bar"], "hooks": [:] as [String: Any]])
    do {
        let add = try CodingAgentSetup.planClaudeShellPrefix(
            basedOn: try CodingAgentSetup.planClaudeSettings(path: path), prefixPath: bundlePrefix)
        check(add.added, "setup: the prefix is added")
        try CodingAgentSetup.apply(add.plan)
        check(env()?[name] as? String == bundlePrefix && env()?["FOO"] as? String == "bar",
              "setup: env gains csec's prefix and keeps the rest")
        let again = try CodingAgentSetup.planClaudeShellPrefix(
            basedOn: try CodingAgentSetup.planClaudeSettings(path: path), prefixPath: bundlePrefix)
        check(!again.added, "setup: adding it again changes nothing")
        let remove = try CodingAgentSetup.planClaudeShellPrefixRemoval(
            basedOn: try CodingAgentSetup.planClaudeSettings(path: path), prefixPath: bundlePrefix)
        check(remove.removed, "setup: csec's prefix is removed")
        try CodingAgentSetup.apply(remove.plan)
        check(env()?[name] == nil && env()?["FOO"] as? String == "bar", "setup: removal keeps the rest of env")
    } catch {
        check(false, "setup: add and remove apply (\(error))")
    }
    write(["env": [name: "/tmp/other"]])
    let conflict = try? CodingAgentSetup.planClaudeShellPrefix(
        basedOn: try CodingAgentSetup.planClaudeSettings(path: path), prefixPath: bundlePrefix)
    check(conflict == nil, "setup: another prefix is refused, never replaced")
    let keep = try? CodingAgentSetup.planClaudeShellPrefixRemoval(
        basedOn: try CodingAgentSetup.planClaudeSettings(path: path), prefixPath: bundlePrefix)
    check(keep?.removed == false, "setup: removal leaves a prefix that is not csec's")
    write(["env": "not an object"])
    check((try? CodingAgentSetup.planClaudeShellPrefix(
        basedOn: try CodingAgentSetup.planClaudeSettings(path: path), prefixPath: bundlePrefix)) == nil,
          "setup: an env that is not an object is refused")
}

private func shippedScriptTests() {
    let repository = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    let shipped = repository.appendingPathComponent("packaging/agent/claude-code-shell/csec-claude-code-shell")
    let data = FileManager.default.contents(atPath: shipped.path)
    check(data == Data(ClaudeCodeShellPrefix.scriptText.utf8),
          "shipped script: packaging's prefix script is exactly ClaudeCodeShellPrefix.scriptText")
    let mode = (try? FileManager.default.attributesOfItem(atPath: shipped.path)[.posixPermissions] as? Int) ?? 0
    check(mode & 0o111 != 0 && mode & 0o022 == 0, "shipped script: executable, writable only by its owner")
    // Run it from a fake bundle: it execs that bundle's csec with exactly
    // `ai --claude-code-shell <argument>`, and nothing from PATH.
    guard let directory = try? FileManager.default.url(
        for: .itemReplacementDirectory, in: .userDomainMask,
        appropriateFor: URL(fileURLWithPath: NSTemporaryDirectory()), create: true) else {
        check(false, "shipped script: a temporary directory")
        return
    }
    defer { try? FileManager.default.removeItem(at: directory) }
    let contents = directory.appendingPathComponent("Fake.app/Contents")
    let script = contents.appendingPathComponent("Resources/claude-code-shell/csec-claude-code-shell")
    let csec = contents.appendingPathComponent("MacOS/csec")
    try? FileManager.default.createDirectory(at: script.deletingLastPathComponent(), withIntermediateDirectories: true)
    try? FileManager.default.createDirectory(at: csec.deletingLastPathComponent(), withIntermediateDirectories: true)
    FileManager.default.createFile(atPath: script.path, contents: Data(ClaudeCodeShellPrefix.scriptText.utf8),
                                   attributes: [.posixPermissions: 0o755])
    FileManager.default.createFile(atPath: csec.path, contents: Data("#!/bin/sh\nprintf '%s\\0' \"$@\"\n".utf8),
                                   attributes: [.posixPermissions: 0o755])
    let argument = claudeFraming("echo 'a  b' \"$X\"")
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/zsh")
    process.arguments = ["-f", "-c", "'\(script.path)' \(ReviewDisplay.commandArgument(argument))"]
    process.environment = ["PATH": "/usr/bin:/bin"]
    let pipe = Pipe()
    process.standardOutput = pipe
    try? process.run()
    let output = pipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    let words = output.split(separator: 0, omittingEmptySubsequences: false).dropLast().map {
        String(decoding: $0, as: UTF8.self)
    }
    check(words == ["ai", ClaudeCodeShellPrefix.option, argument],
          "shipped script: run as Claude Code runs a prefix, it hands its bundle's csec exactly ai --claude-code-shell "
          + "<argument> (\(words.count) words)")
}
