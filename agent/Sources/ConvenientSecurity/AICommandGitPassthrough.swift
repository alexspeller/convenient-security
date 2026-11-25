import Foundation

/// Which Claude Code Bash calls csec's hook leaves unwrapped: a plain list of
/// `git` commands, so Claude Code's worktree guard can read them.
///
/// Claude Code 2.1.280 refuses, in a subagent or session isolated in a git
/// worktree, every Bash command whose git operations it cannot show target
/// that worktree. It reads the command it is about to run, which is the hook's
/// rewrite: `csec ai -- '…'` names an unknown launcher with git text among its
/// operands, so it refused every git command such an agent ran, `git status`
/// included. A command this rule accepts reaches Claude Code unchanged, and the
/// guard judges the git it really runs.
///
/// git is the one program left unwrapped because a git command needs nothing
/// `csec ai` gives it: it reads no secret from the environment, so it loses
/// nothing by not having the references resolved, and it signs over SSH
/// through csec's agent, which Claude Code's own `SSH_AUTH_SOCK` names. What
/// it loses is output masking: a value csecd has released that also sits in a
/// tracked file shows in `git diff` unmasked. That is the trade-off this rule
/// makes, and only for git. An HTTPS credential helper gets no injected
/// environment either, so one that needed a csec reference fails visibly.
///
/// Two kinds of subcommand pass. Local ones (`localSubcommands`) register
/// nothing: no `csec ai` runs them, and they ask csecd for nothing. Those that
/// reach a remote (`networkSubcommands`: `push`, `fetch`, `pull`, `clone`,
/// `submodule`) register the command with csecd, marked
/// unwrapped, so the SSH signing they ask csec's agent for can still be
/// delegated: with no `csec ai` above `ssh`, csecd anchors the chain on
/// Claude Code's Bash tool shell (`ClaudeToolShell`,
/// `ClaudeDelegationService.evaluateSSH`) and binds only an unwrapped
/// registration of exactly the command that shell evaluates. A list registers
/// when any of its git commands reaches a remote. Claude Code's auto mode
/// approves read-only local git without its classifier, so a local-only list
/// never registers: nothing it starts may be delegated. `ls-remote` and
/// `remote` keep their wrapper: Claude Code 2.1.280 approves a bare `git
/// ls-remote` (which reaches the remote), `git remote -v` and `git remote show
/// -n` without its classifier, so neither can be told apart from a command the
/// classifier judged.
///
/// The rule is exact and fails closed: anything it cannot read as plain git
/// stays wrapped. A command passes only when every statement is `git` or `cd`
/// with literal words, joined by `&&`, `||`, `;` or newlines:
///
/// - `git` by that bare name, with only the global options csec knows
///   (`-C`, `--git-dir`, `--work-tree`, `--namespace`, `--no-pager`, … from
///   `AICommandSecretFree.gitGlobalOptions`; never `-c`, `--config-env` or
///   `--exec-path`), then a subcommand from `localSubcommands` or
///   `networkSubcommands` (an alias is not one), and never an option that runs
///   a program the command line names (`programOptions`: `rebase --exec`,
///   `grep -O`, `push --receive-pack`, `fetch --upload-pack`, `clone
///   --template`, …, and `submodule foreach`);
/// - `cd` with one literal operand that is not an option;
/// - every word literal in both zsh and bash (`ShellLiteralWords`): plain
///   text, single quotes, double quotes with no `$`, backquote, backslash or
///   `!`. The one exception is the commit-message form Claude Code is told to
///   use, a git argument that is exactly `"$(cat <<'EOF' … EOF)"`: `cat` with
///   no argument reading a heredoc whose delimiter is single-quoted, so its
///   body expands nothing;
/// - output redirections only (`>`, `>>`, `&>`, `&>>`, `>|`, and `>&` onto a
///   descriptor), each with one literal target.
///
/// No assignment, pipe, subshell, group, background job, comment, input
/// redirection or other program passes, so a compound that mixes git with
/// anything else keeps its wrapper (the guard then asks the agent to split
/// it). The parse is the vendored tree-sitter-bash one (`BashTree`), with the
/// bytes the two shells read differently refused first
/// (`AICommandSecretFree.unsafeCharacters`), and `LauncherScript`'s stricter
/// analysis must find exactly the same commands, or the command stays wrapped.
public enum AICommandGitPassthrough {
    /// The git subcommands that work on the local repository only. Left out
    /// on purpose: every one that can reach a remote (those are
    /// `networkSubcommands`, or keep the wrapper: `ls-remote`, `remote`, `archive`,
    /// `request-pull`, `maintenance`, `lfs`, `svn`, the `*-pack` plumbing),
    /// every one whose job is to start another program (`bisect`,
    /// `difftool`, `mergetool`, `filter-branch`, `help`, `instaweb`,
    /// `daemon`, `send-email`), and every alias, whose expansion csec cannot
    /// see.
    public static let localSubcommands: Set<String> = [
        "add", "am", "apply", "blame", "branch", "cat-file", "check-attr", "check-ignore", "check-ref-format",
        "checkout", "cherry", "cherry-pick", "clean", "commit", "commit-tree", "config", "count-objects",
        "describe", "diff", "diff-files", "diff-index", "diff-tree", "for-each-ref", "format-patch", "fsck", "gc",
        "grep", "hash-object", "init", "interpret-trailers", "log", "ls-files", "ls-tree", "merge", "merge-base",
        "merge-file", "mktree", "mv", "name-rev", "notes", "prune", "range-diff", "read-tree", "rebase", "reflog",
        "reset", "restore", "rev-list", "rev-parse", "revert", "rm", "shortlog", "show", "show-branch",
        "show-ref", "sparse-checkout", "stash", "status", "stripspace", "switch", "symbolic-ref", "tag",
        "update-index", "update-ref", "var", "verify-commit", "verify-tag", "version", "whatchanged",
        "worktree", "write-tree",
    ]

    /// The git subcommands that reach a remote and leave the wrapper too. A
    /// command holding one registers with csecd, marked unwrapped, so an SSH
    /// signing it asks for can be delegated. Claude Code 2.1.280's auto mode
    /// sends each of them to its classifier whatever its flags (none is in its
    /// read-only command table), even where it approves read-only git without
    /// one.
    public static let networkSubcommands: Set<String> = [
        "clone", "fetch", "pull", "push", "submodule",
    ]

    /// An option that makes a subcommand run a program the command line
    /// names: its long name (which git accepts abbreviated) and its short
    /// letter, if it has one.
    struct ProgramOption: Sendable {
        let long: String
        let short: Character?
    }

    /// Each ran a planted command on this Mac (Apple git 2.50.1); with a
    /// local-path remote, `--upload-pack` and `--receive-pack` run here, and
    /// `clone --template` and `clone -c core.hooksPath=…` run a hook. `push -u`
    /// is `--set-upstream`, so only `clone`'s `-u` is one. `submodule foreach`
    /// (a shell command in every submodule) is checked on its own.
    static let programOptions: [String: [ProgramOption]] = [
        "rebase": [ProgramOption(long: "--exec", short: "x")],
        "grep": [ProgramOption(long: "--open-files-in-pager", short: "O")],
        "push": [ProgramOption(long: "--receive-pack", short: nil), ProgramOption(long: "--exec", short: nil)],
        "fetch": [ProgramOption(long: "--upload-pack", short: nil)],
        "pull": [ProgramOption(long: "--upload-pack", short: nil)],
        "clone": [
            ProgramOption(long: "--upload-pack", short: "u"), ProgramOption(long: "--template", short: nil),
            ProgramOption(long: "--config", short: "c"),
        ],
    ]

    /// Whether `argument` could be the option `long` or its short form: the
    /// long name, with or without `=value`, or any prefix of it git's
    /// parse-options would expand; or a short cluster holding `short`.
    static func couldBeOption(_ argument: String, long: String, short: Character?) -> Bool {
        if argument.hasPrefix("--") {
            let name = argument.split(separator: "=", maxSplits: 1).first.map(String.init) ?? argument
            return name.count > 2 && long.hasPrefix(name)
        }
        guard let short else { return false }
        return argument.count > 1 && argument.hasPrefix("-") && argument.contains(short)
    }

    /// Output redirections a passthrough command may carry: each only opens a
    /// file for writing or duplicates a descriptor.
    static let outputRedirectOperators: Set<String> = [">", ">>", "&>", "&>>", ">|", ">&"]

    /// Why a command keeps its wrapper. Value-free: node kinds, command
    /// names and git options only.
    public enum Rejection: Error, Sendable, Equatable {
        /// Bytes the bash grammar and zsh read differently.
        case unsafeCharacters(String)
        /// tree-sitter could not parse it, or reported an ERROR or MISSING node.
        case unparsable
        /// A node kind or operator token the rule does not accept.
        case unsupportedSyntax(String)
        case nestingTooDeep
        /// A command other than `git` or `cd` (or a command name that is not
        /// a plain word).
        case otherCommand(String)
        /// A word whose value is not literal in both shells.
        case nonLiteralWord(command: String)
        /// A variable assignment before or as a command.
        case assignment
        /// `cd` without exactly one literal, non-option operand.
        case cdOperand
        /// A git global option csec does not accept here, or no subcommand
        /// ("" when absent).
        case gitGlobalOption(String)
        /// A subcommand in neither `localSubcommands` nor
        /// `networkSubcommands`: one that starts another program, reaches a
        /// remote in a way the rule does not pass (`ls-remote`, `remote`,
        /// `archive`, …), or is an alias.
        case gitSubcommand(String)
        /// An option from `programOptions` (`rebase --exec`, `push
        /// --receive-pack`, `clone --template`, …) or `submodule foreach`,
        /// which run a program the command line names.
        case runsProgram(String)
        /// A redirection other than an output one with one literal target.
        case redirection(String)
        /// No git command at all.
        case noGit
        /// `LauncherScript`'s analysis read different commands, or refused
        /// the text.
        case analysisDisagrees
    }

    public enum Verdict: Sendable, Equatable {
        /// The hook leaves the command unwrapped: no `csec ai` runs it. It
        /// registers the command with csecd, marked unwrapped, only when
        /// `registersForDelegation`: when one of its git commands reaches a
        /// remote (`networkSubcommands`), so csecd may delegate the SSH
        /// signing it asks for.
        case unwrapped(registersForDelegation: Bool)
        /// The hook wraps the command in `csec ai`, as for every other program.
        case wrapped(Rejection)

        public var isUnwrapped: Bool {
            if case .unwrapped = self { return true }
            return false
        }

        /// Unwrapped and registered: csecd may tie an SSH signing to the Bash
        /// tool shell that evaluates it.
        public var registersForDelegation: Bool { self == .unwrapped(registersForDelegation: true) }
    }

    /// Classifies one Claude Code Bash command, exactly as the hook received
    /// it (and as Claude Code's Bash tool shell evaluates it).
    public static func classify(_ command: String) -> Verdict {
        guard !command.isEmpty, command.utf8.count <= AICommandHook.maximumCommandBytes else {
            return .wrapped(.unparsable)
        }
        if let unsafe = AICommandSecretFree.unsafeCharacters(in: command) {
            return .wrapped(.unsafeCharacters(unsafe))
        }
        let walker: PassthroughWalker
        do {
            let tree = try BashTree(command)
            guard !tree.root.hasError else { return .wrapped(.unparsable) }
            var walking = PassthroughWalker(tree: tree)
            try walking.program(tree.root)
            walker = walking
        } catch let rejection as Rejection {
            return .wrapped(rejection)
        } catch {
            return .wrapped(.unparsable)
        }
        guard walker.sawGit else { return .wrapped(.noGit) }
        // `LauncherScript`'s analysis refuses the tree-sitter misreadings it
        // knows of; it must read this text cleanly and find the same
        // commands.
        guard let commands = LauncherScript.simpleCommands(in: command),
              commands.compactMap(\.name).sorted() == walker.names.sorted(),
              commands.allSatisfy({ $0.name != nil }) else {
            return .wrapped(.analysisDisagrees)
        }
        return .unwrapped(registersForDelegation: walker.sawNetwork)
    }
}

// MARK: - The tree walk

private struct PassthroughWalker {
    typealias Rejection = AICommandGitPassthrough.Rejection

    /// Far beyond any real command; it bounds recursion on a hostile one.
    static let maximumDepth = 64

    let tree: BashTree
    /// Every command name, including the `cat` of a commit-message heredoc.
    private(set) var names: [String] = []
    private(set) var sawGit = false
    /// A git command whose subcommand is in `networkSubcommands`.
    private(set) var sawNetwork = false

    init(tree: BashTree) {
        self.tree = tree
    }

    mutating func program(_ root: BashNode) throws {
        guard root.kind == "program" else { throw Rejection.unsupportedSyntax(root.kind) }
        try statements(in: root, tokens: [";"], depth: 0)
    }

    /// The named children of `node` are statements; its anonymous children
    /// must be one of `tokens`. A bare newline separates statements without a
    /// token.
    private mutating func statements(in node: BashNode, tokens: Set<String>, depth: Int) throws {
        for child in node.children {
            if child.isNamed {
                try statement(child, depth: depth + 1)
            } else if !tokens.contains(child.kind) {
                // `&` (background), `|`, keywords.
                throw Rejection.unsupportedSyntax(child.kind)
            }
        }
    }

    private mutating func statement(_ node: BashNode, depth: Int) throws {
        guard depth < Self.maximumDepth else { throw Rejection.nestingTooDeep }
        switch node.kind {
        case "command":
            try command(node)
        case "list":
            try statements(in: node, tokens: ["&&", "||"], depth: depth)
        case "redirected_statement":
            var commands = 0
            for child in node.children {
                switch child.kind {
                case "command":
                    commands += 1
                    try command(child)
                case "file_redirect":
                    try outputRedirect(child)
                default:
                    // A heredoc or here-string feeds the command input; a
                    // redirected list, pipeline or group is not one command.
                    throw Rejection.redirection(child.kind)
                }
            }
            guard commands == 1 else { throw Rejection.unsupportedSyntax("redirected statement") }
        case "variable_assignment", "variable_assignments", "declaration_command", "unset_command":
            throw Rejection.assignment
        default:
            // Pipelines, subshells, groups, comments, negations, tests,
            // functions, loops and anything unknown.
            throw Rejection.unsupportedSyntax(node.kind)
        }
    }

    private mutating func command(_ node: BashNode) throws {
        var name: String?
        var words: [BashNode] = []
        var arguments: [BashNode] = []
        for child in node.children {
            switch child.kind {
            case "command_name":
                guard child.namedChildCount == 1, let word = child.namedChild(0),
                      let literal = ShellLiteralWords.plainLiteral(word, in: tree) else {
                    throw Rejection.otherCommand("a computed name")
                }
                name = literal
                words.append(child)
            case "variable_assignment", "variable_assignments":
                throw Rejection.assignment
            default:
                // Redirections inside the command node, a lone `$`, and
                // anything else unnamed.
                guard child.isNamed, child.kind != "file_redirect", child.kind != "herestring_redirect" else {
                    throw Rejection.unsupportedSyntax(child.kind)
                }
                words.append(child)
                arguments.append(child)
            }
        }
        // Two words the grammar split with nothing between them are one word
        // to zsh.
        for (previous, next) in zip(words, words.dropFirst()) where previous.endByte >= next.startByte {
            throw Rejection.unsupportedSyntax("adjacent words")
        }
        switch name {
        case "git":
            try gitCommand(arguments)
        case "cd":
            guard arguments.count == 1, let operand = ShellLiteralWords.decodedArgument(arguments[0], in: tree),
                  !operand.isEmpty, !operand.hasPrefix("-") else {
                throw Rejection.cdOperand
            }
            names.append("cd")
        case let other?:
            throw Rejection.otherCommand(other)
        case nil:
            throw Rejection.otherCommand("no command name")
        }
    }

    /// `git [global options] <subcommand> …` with literal words, or the
    /// commit-message heredoc in place of one.
    private mutating func gitCommand(_ arguments: [BashNode]) throws {
        names.append("git")
        // The literal value of each argument; nil for the commit-message
        // heredoc, whose value is computed when it runs.
        var values: [String?] = []
        for argument in arguments {
            if let value = ShellLiteralWords.decodedArgument(argument, in: tree) {
                values.append(value)
            } else if try commitMessageHeredoc(argument) {
                values.append(nil)
                names.append("cat")
            } else {
                throw Rejection.nonLiteralWord(command: "git")
            }
        }
        // The global options and the subcommand must all be literal.
        let literalPrefix = Array(values.prefix { $0 != nil }.compactMap { $0 })
        switch AICommandSecretFree.gitGlobalOptions(literalPrefix) {
        case let .failure(rejection):
            switch rejection {
            case let .gitConfigurationOverride(option), let .gitGlobalOption(option):
                throw Rejection.gitGlobalOption(option)
            default:
                throw Rejection.gitGlobalOption("")
            }
        case let .success(index):
            guard index < literalPrefix.count else { throw Rejection.gitGlobalOption("") }
            let subcommand = literalPrefix[index]
            let isNetwork = AICommandGitPassthrough.networkSubcommands.contains(subcommand)
            guard isNetwork || AICommandGitPassthrough.localSubcommands.contains(subcommand) else {
                throw Rejection.gitSubcommand(subcommand)
            }
            // Every argument after the subcommand is checked, values
            // included, so a message that happens to read `-x` keeps the
            // wrapper too.
            let rest = values[(index + 1)...].compactMap { $0 }
            for option in AICommandGitPassthrough.programOptions[subcommand] ?? []
            where rest.contains(where: { AICommandGitPassthrough.couldBeOption($0, long: option.long, short: option.short) }) {
                throw Rejection.runsProgram("\(subcommand) \(option.long)")
            }
            if subcommand == "submodule", rest.contains("foreach") {
                throw Rejection.runsProgram("submodule foreach")
            }
            sawGit = true
            if isNetwork { sawNetwork = true }
        }
    }

    /// Whether `node` is exactly `"$(cat <<'EOF'⏎…⏎EOF⏎)"`: a double-quoted
    /// command substitution holding only `cat`, with no argument, reading a
    /// heredoc whose delimiter is a single-quoted name, so its body is
    /// literal. Anything close to it but not it throws, so the command stays
    /// wrapped with a reason; anything else returns false.
    private func commitMessageHeredoc(_ node: BashNode) throws -> Bool {
        guard node.kind == "string" else { return false }
        let parts = node.children
        guard parts.count == 3, parts[0].kind == "\"", parts[1].kind == "command_substitution",
              parts[2].kind == "\"" else { return false }
        let substitution = parts[1].children
        guard substitution.count == 3, substitution[0].kind == "$(", substitution[2].kind == ")",
              substitution[1].kind == "redirected_statement" else {
            throw Rejection.nonLiteralWord(command: "git")
        }
        let statement = substitution[1].children
        guard statement.count == 2, statement[0].kind == "command", statement[1].kind == "heredoc_redirect" else {
            throw Rejection.nonLiteralWord(command: "git")
        }
        let cat = statement[0].children
        guard cat.count == 1, cat[0].kind == "command_name", cat[0].namedChildCount == 1,
              let word = cat[0].namedChild(0), ShellLiteralWords.plainLiteral(word, in: tree) == "cat" else {
            throw Rejection.nonLiteralWord(command: "git")
        }
        var delimiter: String?
        var ended = false
        for child in statement[1].children {
            switch child.kind {
            case "<<":
                continue
            case "heredoc_start":
                guard delimiter == nil, let text = tree.text(child), let name = Self.quotedDelimiter(text) else {
                    throw Rejection.redirection("heredoc delimiter")
                }
                delimiter = name
            case "heredoc_body":
                // The delimiter is quoted, so the body is literal, whatever
                // the grammar found in it.
                continue
            case "heredoc_end":
                guard let delimiter, tree.text(child) == delimiter else {
                    throw Rejection.redirection("heredoc end")
                }
                ended = true
            default:
                // `<<-`, a descriptor, a second redirection or words after the
                // delimiter.
                throw Rejection.redirection(child.kind)
            }
        }
        guard delimiter != nil, ended else { throw Rejection.redirection("heredoc") }
        // Only the newline that ends the heredoc may sit between its end line
        // and the closing parenthesis.
        let gap = tree.source[Int(statement[1].endByte)..<Int(max(statement[1].endByte, substitution[2].startByte))]
        guard gap.allSatisfy({ $0 == 0x0A }) else { throw Rejection.redirection("text after the heredoc") }
        return true
    }

    /// `NAME` for a heredoc start spelled exactly `'NAME'`, with `NAME` an
    /// identifier.
    static func quotedDelimiter(_ text: String) -> String? {
        let bytes = Array(text.utf8)
        guard bytes.count >= 3, bytes.first == UInt8(ascii: "'"), bytes.last == UInt8(ascii: "'") else { return nil }
        let name = bytes[1..<(bytes.count - 1)]
        guard let first = name.first, ShellBytes.isIdentifierStart(first),
              name.allSatisfy(ShellBytes.isIdentifierByte) else { return nil }
        return String(decoding: name, as: UTF8.self)
    }

    /// `>`, `>>`, `&>`, `&>>` or `>|` onto one literal file, or `>&` onto a
    /// descriptor (`2>&1`, `>&2`, `>&-`).
    private func outputRedirect(_ node: BashNode) throws {
        var operatorKind: String?
        var targets: [BashNode] = []
        for child in node.children {
            if child.kind == "file_descriptor" { continue }
            if child.isNamed {
                targets.append(child)
            } else if AICommandGitPassthrough.outputRedirectOperators.contains(child.kind), operatorKind == nil {
                operatorKind = child.kind
            } else {
                throw Rejection.redirection(child.kind)
            }
        }
        // The grammar hangs words that follow a redirection's target on the
        // redirection, where the shell passes them to the command.
        guard let operatorKind, targets.count == 1,
              let target = ShellLiteralWords.decodedArgument(targets[0], in: tree), !target.isEmpty else {
            throw Rejection.redirection(operatorKind ?? "redirection")
        }
        if operatorKind == ">&" {
            guard target == "-" || target.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }) else {
                throw Rejection.redirection(">& onto a file")
            }
        }
    }
}
