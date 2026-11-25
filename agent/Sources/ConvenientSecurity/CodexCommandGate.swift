import Foundation

/// Whether Codex's own gates would stop a shell command, so the Codex hook can
/// leave it unwrapped.
///
/// Codex checks the argv of `[shell, -lc, command]`. That covers its
/// dangerous-command heuristic, its execpolicy `prompt`/`forbidden` prefix
/// rules, and its `apply_patch` interception. After csec rewrites a command to
/// `csec ai -- <command>`, argv starts with `csec`, so none of those can match:
/// a forced `rm`, or a `git push` the user's rules forbid, would run without the
/// prompt or refusal Codex would otherwise raise. For those commands csec gives
/// up output scanning and lets Codex judge the original.
///
/// Codex splits and reads commands with tree-sitter-bash. `CodexShellSyntax`
/// and `CodexDangerousCommand` are line-for-line ports of that code over the
/// same vendored grammar, so the heuristic here is Codex's own.
///
/// The decision is still a superset of Codex's. A miss would hide a gated
/// command behind the wrapper, while an extra flag only costs output scanning
/// for that one command. So:
/// - the heuristic runs whatever the allow rules say. Codex skips it for a
///   command an allow rule matches, and drops allow rules entirely for some
///   models.
/// - a rule matches a program by exact name or by the basename Codex's
///   host-executable lookup would give it, ignoring `host_executable`
///   allowlists.
/// - any rule on a shell leaves every command to Codex, because the hook
///   cannot see which shell Codex will use.
public enum CodexCommandGate {
    public enum Decision: String, Sendable, Equatable {
        case allow
        case prompt
        case forbidden
    }

    /// Which Codex heuristic rule matched (`DangerousCommandMatch` in
    /// is_dangerous_command.rs). `other` only comes from nesting deeper than
    /// Codex follows, where Codex fails closed.
    public enum DangerousCommandMatch: Sendable, Equatable {
        case forcedRm
        case other
    }

    /// One execpolicy `prefix_rule`: each pattern position lists the tokens it
    /// accepts (a single string or a list of alternatives in the rules file).
    public struct PrefixRule: Sendable, Equatable {
        public let pattern: [[String]]
        public let decision: Decision

        public init(pattern: [[String]], decision: Decision) {
            self.pattern = pattern
            self.decision = decision
        }

        /// A prefix match on argv, as `PrefixPattern::matches_prefix`
        /// (execpolicy/src/rule.rs:46-60). The program position also matches by
        /// the basename Codex's host-executable resolution computes
        /// (execpolicy/src/policy.rs:344-371). Codex's `host_executable`
        /// allowlists can only narrow that, so they are ignored here.
        func matches(_ argv: [String]) -> Bool {
            guard let programAlternatives = pattern.first, argv.count >= pattern.count else { return false }
            let program = argv[0]
            let programMatches: Bool
            if programAlternatives.contains(program) {
                programMatches = true
            } else {
                switch CodexCommandGate.hostExecutableName(program) {
                case let .name(name): programMatches = programAlternatives.contains(name)
                case .unknown: programMatches = true
                case .none: programMatches = false
                }
            }
            guard programMatches else { return false }
            for index in 1..<pattern.count where !pattern[index].contains(argv[index]) {
                return false
            }
            return true
        }
    }

    /// True when Codex's dangerous-command heuristic, its `apply_patch`
    /// interception, or a `prompt`/`forbidden` rule could apply to `script`.
    public static func requiresCodexGate(_ script: String, rules: [PrefixRule]) -> Bool {
        // The command Codex builds for the configured shell (zsh on macOS; bash
        // and sh parse identically, and `-c` and `-lc` are treated alike).
        let command = ["/bin/zsh", "-lc", script]
        do {
            // One parse serves every check below: `command` always passes
            // `extract_bash_command`, so each Codex function would parse this
            // same script again.
            let tree = try BashTree(script)

            // core/src/exec_policy.rs:876-904: Codex checks the plain commands of
            // the script, else the whole shell invocation as one argv.
            let plain = CodexShellSyntax.tryParseWordOnlyCommandsSequence(tree) ?? []
            let checked = plain.isEmpty ? [command] : plain

            // (a) Codex's heuristic on each checked argv (its fallback when no
            // rule matches, exec_policy.rs:770-807), here regardless of rules.
            // On the whole invocation, `zsh` is not a command the heuristic
            // unwraps, so the match is its script's literal commands one level
            // down: `dangerous_command_match_with_depth` without the reparse.
            if plain.isEmpty {
                let literal = CodexShellSyntax.literalCommands(in: tree)
                if CodexDangerousCommand.firstMatch(in: literal, wrapperDepth: 1) != nil { return true }
            } else if plain.contains(where: { CodexDangerousCommand.match($0) != nil }) {
                return true
            }

            // (c) Codex runs an `apply_patch <<'EOF' … EOF` heredoc (optionally
            // after `cd <dir> &&`) through its patch engine and patch approval
            // instead of a shell. Wrapped, the heredoc still applies the patch,
            // through Codex's `apply_patch` alias, skipping that approval.
            if invokesPatchTool(tree) { return true }

            // (b) Rules that can gate.
            let gating = rules.filter { $0.decision != .allow }
            if gating.isEmpty { return false }
            // A rule on the shell itself matches every script Codex cannot split
            // into plain commands, and the hook cannot see which shell runs it.
            if gating.contains(where: { rule in
                rule.pattern.first?.contains(where: { CodexShellSyntax.detectShellType($0) != nil }) == true
            }) {
                return true
            }
            return checked.contains { argv in gating.contains { $0.matches(argv) } }
        } catch {
            // The parser could not run: leave the command to Codex.
            return true
        }
    }

    /// Codex's own policy as csec can read it from disk. `opaqueSources` are
    /// files csec could not interpret; while any exists, every command is left
    /// to Codex.
    public struct Policy: Sendable, Equatable {
        public var rules: [PrefixRule]
        public var opaqueSources: [String]

        public init(rules: [PrefixRule] = [], opaqueSources: [String] = []) {
            self.rules = rules
            self.opaqueSources = opaqueSources
        }
    }

    public static func requiresCodexGate(_ script: String, policy: Policy) -> Bool {
        !policy.opaqueSources.isEmpty || requiresCodexGate(script, rules: policy.rules)
    }

    // MARK: - The ported Codex checks, for callers and parity tests

    /// Codex's dangerous-command heuristic on an argv, exactly as
    /// `dangerous_command_match` computes it. A parse that cannot run counts
    /// as `.other`.
    public static func dangerousCommandMatch(_ command: [String]) -> DangerousCommandMatch? {
        CodexDangerousCommand.match(command)
    }

    /// Codex's `parse_shell_lc_plain_commands`: the argv of every command
    /// when `command` is `[zsh|bash|sh, -c|-lc, script]` and the script is
    /// plain words joined by `&&`, `||`, `;` and `|`. Otherwise nil.
    public static func plainCommands(_ command: [String]) -> [[String]]? {
        try? CodexShellSyntax.parseShellLcPlainCommands(command)
    }

    // MARK: - Helpers

    /// Whether any command in `script` runs `apply_patch` or `applypatch`, by
    /// word or by path. This is a superset of the tree-sitter query in
    /// apply-patch/src/invocation.rs:317-386, and it is also checked in trees with
    /// parse errors.
    static func invokesPatchTool(_ tree: BashTree) -> Bool {
        var stack = [tree.root]
        while let node = stack.popLast() {
            if node.kind == "command",
               let name = node.namedChildren.first(where: { $0.kind == "command_name" })?.namedChild(0) {
                let spellings = [tree.text(name), CodexShellSyntax.parseLiteralShellWord(name, tree)]
                if spellings.contains(where: { spelling in
                    guard let spelling, let program = CodexDangerousCommand.executableNameLookupKey(spelling) else {
                        return false
                    }
                    return program == "apply_patch" || program == "applypatch"
                }) {
                    return true
                }
            }
            stack.append(contentsOf: node.namedChildren)
        }
        return false
    }

    /// The program name Codex's host-executable lookup derives from argv[0]:
    /// `AbsolutePathBuf::try_from` expands a leading `~`, absolutizes against
    /// Codex's own working directory, and normalizes lexically, and then the file
    /// name is taken (utils/absolute-path/src/lib.rs:27-62).
    enum HostExecutableName: Equatable {
        case name(String)
        /// Resolves to Codex's working directory or one of its ancestors,
        /// whose name the hook cannot know.
        case unknown
        /// Resolves to `/`, which has no file name.
        case none
    }

    static func hostExecutableName(_ program: String) -> HostExecutableName {
        var path = Array(program.unicodeScalars)
        var absolute = path.first == "/"
        if path.first == "~", path.count == 1 || path[1] == "/" {
            // Relative to the home directory, whose name is not assumed.
            path.removeFirst()
            absolute = false
        }
        var names: [ArraySlice<Unicode.Scalar>] = []
        for part in path.split(separator: "/", omittingEmptySubsequences: true) {
            if part.elementsEqual(["."]) { continue }
            if part.elementsEqual([".", "."]) {
                if !names.isEmpty { names.removeLast() }
                continue
            }
            names.append(part)
        }
        if let last = names.last {
            var name = String.UnicodeScalarView()
            name.append(contentsOf: last)
            return .name(String(name))
        }
        return absolute ? .none : .unknown
    }
}
