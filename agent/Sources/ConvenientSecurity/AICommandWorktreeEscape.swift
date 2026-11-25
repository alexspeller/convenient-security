import Foundation

/// Which wrapped Claude Code Bash commands csec's hook refuses in a session or
/// subagent Claude Code has isolated in a git worktree, so its git cannot run
/// outside that worktree.
///
/// Claude Code 2.1.280's worktree guard reads the command it is about to run,
/// which is the hook's rewrite. `csec ai -- '…'` is one simple command naming
/// an unknown launcher, and the guard refuses that only when an operand's first
/// word is git or a shell (or it holds a quote, backquote, `$` or backslash and
/// a word naming git or a shell). So wrapped, `cd <shared checkout> && git
/// push`, `true && git push` and `env git push` all ran, the first in the shared checkout (csec-jmjy). A
/// plain list of `git` and `cd` commands is left unwrapped for the guard to
/// judge (`AICommandGitPassthrough`); this rule covers everything else that
/// names git.
///
/// It applies only when the session is isolated (`isolation`), the command
/// would be wrapped, and it names git as Claude Code's guard reads names
/// (`namesGit`). A session whose shell has moved out of its own worktree (the
/// guard lets `git … && cd <dir>` through, since no git follows its `cd`) is
/// refused any such command. Otherwise it passes only when nothing in it can
/// move git out of the worktree:
///
/// - It parses cleanly in both the tree-sitter walk and `LauncherScript`'s
///   stricter analysis, and the two find the same number of commands and of
///   git commands.
/// - Nothing changes the shell's directory, environment, options or command
///   lookup, beyond what stays harmless: a `cd` only to an existing directory
///   whose real path is inside the worktree (`changeDirectory`); an
///   assignment or `export` only of an environment-style name git and the
///   shell do not read (`isAssignableVariable`), with a value that does not
///   name git; no function definition, no builtin or reserved word of zsh or
///   bash beyond a harmless set (`harmlessBuiltins`, `trustedBuiltins`,
///   `read -r` into an ordinary name), no command name that is a directory
///   (zsh's AUTO_CD), no `${…}` that assigns or takes zsh flags, no
///   arithmetic, no `case`, `select` or `>(…)`, and no text naming git where
///   zsh could evaluate it as a subscript (`printf %d 'x[$(…)]'`).
/// - git runs only as a direct command spelled `git`, with no `-C`,
///   `--git-dir`, `--work-tree`, `--bare` or configuration override, and with
///   no program option (`rebase --exec`, `submodule foreach`, …) whose
///   arguments name git.
/// - Any other mention of git is data that reaches only programs that never
///   run what they read (`trustedCommands`): an argument, heredoc or
///   here-string of one, the output of one piped into another or into a
///   command substitution one of them reads, or a file, only when nothing in
///   the command could then run that file (git's program options count). `env
///   git`, `xargs git`, `sh -c '… git …'`, `python3 <<EOF … git … EOF` and
///   `echo … git … | sh` are refused.
///
/// A command naming git that this check passes is wrapped with its program
/// after a space (`AICommandHook.programToken`), so the guard, reading that
/// operand's first word, does not refuse it for starting with git.
///
/// The check is for accidents, as Claude Code's own guard is: a program that
/// runs git itself (a build script, a git alias) or a name spelled to hide it
/// (`$'\x67it'`) is out of its reach, as it is out of the guard's.
public enum AICommandWorktreeEscape {
    /// What the check reads from the machine: whether a path is a directory
    /// (for zsh's AUTO_CD), the `CDPATH` it searches, and a path's real path
    /// (for a `cd` that must stay in the worktree).
    public struct Environment: Sendable {
        public let isDirectory: @Sendable (String) -> Bool
        public let cdpath: [String]
        public let realPath: @Sendable (String) -> String?

        public init(
            isDirectory: @escaping @Sendable (String) -> Bool,
            cdpath: [String],
            realPath: @escaping @Sendable (String) -> String?
        ) {
            self.isDirectory = isDirectory
            self.cdpath = cdpath
            self.realPath = realPath
        }

        public static var live: Environment {
            Environment(
                isDirectory: { path in
                    var isDirectory: ObjCBool = false
                    return FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory)
                        && isDirectory.boolValue
                },
                cdpath: (ProcessInfo.processInfo.environment["CDPATH"] ?? "")
                    .split(separator: ":").map(String.init).filter { !$0.isEmpty },
                realPath: { path in
                    guard let resolved = Darwin.realpath(path, nil) else { return nil }
                    defer { free(resolved) }
                    return String(cString: resolved)
                }
            )
        }
    }

    // MARK: - Isolation

    /// Where the hook's command runs, for Claude Code's worktree guard.
    public enum Isolation: Sendable, Equatable {
        /// Not isolated: the guard is off, and so is this check.
        case none
        /// Isolated, and the command runs in its own worktree, `root`.
        case inWorktree(root: String)
        /// Isolated, but the command would run outside its own worktree (or
        /// the hook input has no `cwd`).
        case outsideWorktree
    }

    /// Whether Claude Code has isolated the hook's session or subagent in a
    /// worktree, so its worktree guard is active, and whether the command runs
    /// in that worktree. Claude Code 2.1.280 puts those worktrees at
    /// `<repo>/.claude/worktrees/<name>` (`claude -w`, `EnterWorktree`, and
    /// `agent-<agent_id>` for a subagent) and recognises its own by that
    /// shape. The hook's `cwd` is inside one for an isolated subagent (reset
    /// there on every call) and at first for an isolated session. A session's
    /// Bash cwd can then move to any directory it is allowed (measured: `cd
    /// /tmp` persists, and the guard lets a plain `git … && cd <dir>` through,
    /// since no git follows its `cd`), but its `transcript_path` stays in the
    /// project directory Claude Code names after the worktree, every UTF-16
    /// unit that is not an ASCII letter or digit made `-` (cut to 200 units
    /// and a hash), so it holds `--claude-worktrees-`. For such a session the
    /// command is in its own worktree only when the `cwd`'s worktree is the one
    /// the transcript names, or the subagent's `agent-<agent_id>`.
    public static func isolation(workingDirectory: Any?, transcriptPath: Any?, agentID: Any?) -> Isolation {
        guard let workingDirectory = workingDirectory as? String, !workingDirectory.isEmpty else {
            return .outsideWorktree
        }
        let project = (transcriptPath as? String).map {
            (($0 as NSString).deletingLastPathComponent as NSString).lastPathComponent
        }
        let sessionInWorktree = project?.contains("--claude-worktrees-") == true
        guard let root = claudeWorktreeRoot(workingDirectory) else {
            return sessionInWorktree ? .outsideWorktree : .none
        }
        if sessionInWorktree, let project {
            let ownSubagentWorktree = (agentID as? String).map { "agent-\($0)" } == (root as NSString).lastPathComponent
            guard projectDirectoryName(root, matches: project) || ownSubagentWorktree else { return .outsideWorktree }
        }
        return .inWorktree(root: root)
    }

    /// `<x>/.claude/worktrees/<name>` for a path inside it, or nil.
    static func claudeWorktreeRoot(_ path: String) -> String? {
        let components = path.split(separator: "/", omittingEmptySubsequences: true)
        guard components.count >= 3 else { return nil }
        for index in 0..<(components.count - 2)
        where components[index] == ".claude" && components[index + 1] == "worktrees" {
            return "/" + components[...(index + 2)].joined(separator: "/")
        }
        return nil
    }

    /// Whether Claude Code names the project directory for `path` `name`.
    static func projectDirectoryName(_ path: String, matches name: String) -> Bool {
        let sanitized = String(decoding: path.utf16.map { unit -> UInt16 in
            let isAlphanumeric = (unit >= 0x30 && unit <= 0x39) || (unit >= 0x41 && unit <= 0x5A)
                || (unit >= 0x61 && unit <= 0x7A)
            return isAlphanumeric ? unit : 0x2D
        }, as: UTF16.self)
        guard sanitized.utf16.count > 200 else { return sanitized == name }
        return name.hasPrefix(String(decoding: Array(sanitized.utf16.prefix(200)), as: UTF16.self) + "-")
    }

    // MARK: - Naming git

    /// Whether `text` names git the way Claude Code 2.1.280's worktree guard
    /// reads it (`n_e`): split on every character that is not a letter, digit,
    /// `_`, `.` or `-`, as written and again with quotes, backslashes and
    /// `$name`/`${…}` expansions removed, a word matching
    /// `^git(\.exe|\.real|-[a-z][\w-]*)?$`, ignoring case.
    public static func namesGit(_ text: String) -> Bool {
        hasGitWord(Array(text.unicodeScalars)) || hasGitWord(withoutQuotesAndExpansions(text))
    }

    static func hasGitWord(_ scalars: [Unicode.Scalar]) -> Bool {
        var word: [Unicode.Scalar] = []
        for scalar in scalars + [" "] {
            if isWordScalar(scalar) {
                word.append(scalar)
            } else {
                if isGitWord(word) { return true }
                word.removeAll(keepingCapacity: true)
            }
        }
        return false
    }

    private static func isWordScalar(_ scalar: Unicode.Scalar) -> Bool {
        isIdentifierScalar(scalar) || scalar == "." || scalar == "-"
    }

    private static func isIdentifierScalar(_ scalar: Unicode.Scalar) -> Bool {
        ("a"..."z").contains(scalar) || ("A"..."Z").contains(scalar) || ("0"..."9").contains(scalar) || scalar == "_"
    }

    private static func isGitWord(_ word: [Unicode.Scalar]) -> Bool {
        let lowered = String(String.UnicodeScalarView(word)).lowercased()
        guard lowered.hasPrefix("git") else { return false }
        let rest = Array(lowered.unicodeScalars.dropFirst(3))
        if rest.isEmpty { return true }
        if rest == Array(".exe".unicodeScalars) || rest == Array(".real".unicodeScalars) { return true }
        guard rest.count >= 2, rest[0] == "-", ("a"..."z").contains(rest[1]) else { return false }
        return rest.dropFirst(2).allSatisfy { isIdentifierScalar($0) || $0 == "-" }
    }

    /// The guard's `/\$\{[^}]*\}|\$\w*|[`'"\\]/g` removed.
    private static func withoutQuotesAndExpansions(_ text: String) -> [Unicode.Scalar] {
        let scalars = Array(text.unicodeScalars)
        var result: [Unicode.Scalar] = []
        var index = 0
        while index < scalars.count {
            let scalar = scalars[index]
            if scalar == "$" {
                if index + 1 < scalars.count, scalars[index + 1] == "{",
                   let close = scalars[(index + 2)...].firstIndex(of: "}") {
                    index = close + 1
                    continue
                }
                index += 1
                while index < scalars.count, isIdentifierScalar(scalars[index]) { index += 1 }
                continue
            }
            if !["`", "'", "\"", "\\"].contains(scalar) { result.append(scalar) }
            index += 1
        }
        return result
    }

    // MARK: - The check

    /// Why a wrapped command that names git is refused in an isolated
    /// session. Value-free: command names, git options and syntax kinds.
    public enum Refusal: Error, Sendable, Equatable {
        /// Bytes zsh and the bash grammar read differently, an ERROR node, or
        /// text `LauncherScript` cannot read cleanly.
        case unparsable
        /// A construct the check does not follow (`[[ ]]`, `case`, a function
        /// definition, arithmetic, `${x:=…}`, `>(…)`, …).
        case unsupportedSyntax(String)
        case nestingTooDeep
        /// A variable assignment, before a command or on its own.
        case assignment
        /// A builtin or reserved word that can change the shell's directory,
        /// environment, options or command lookup, or run a string.
        case shellState(String)
        /// A command name that is not plain literal text.
        case computedCommandName
        /// A command name that is a directory, which zsh's AUTO_CD enters.
        case directoryCommandName
        /// git spelled other than `git` (`/usr/bin/git`, `git-lfs`, …).
        case gitSpelling(String)
        /// A git global option that points git elsewhere or that csec does
        /// not know, or no literal subcommand ("" when absent).
        case gitOption(String)
        /// A git option that runs a program, given a program that names git.
        case gitProgramOption(String)
        /// A command other than git whose arguments name git, and which could
        /// run it.
        case launchesGit(String)
        /// A command option that runs a program or sets a variable, beside a
        /// mention of git.
        case commandOption(String)
        /// A mention of git that reaches something that could run it: a pipe,
        /// a heredoc, a variable or a file.
        case mentionFlows(String)
        /// `LauncherScript` found other commands than the walk.
        case analysisDisagrees
        /// The session is isolated, but its shell is outside its worktree.
        case outsideWorktree

        /// What this command does, for the agent.
        var detail: String {
            switch self {
            case .unparsable:
                return "can't be parsed the same way by zsh and csec's bash grammar"
            case let .unsupportedSyntax(kind):
                return "uses \(kind), which csec doesn't follow"
            case .nestingTooDeep:
                return "nests too deeply to check"
            case .assignment:
                return "assigns a variable, which can point git somewhere else"
            case .shellState("cd"):
                return "runs a cd csec can't show stays in your worktree (cd to an existing directory inside it, "
                    + "by absolute path, or as the first cd, by a path relative to where the command starts)"
            case let .shellState(name):
                return "runs \(name), which can change the directory or environment git runs in"
            case .computedCommandName:
                return "computes a command name, which could be git"
            case .directoryCommandName:
                return "names a directory as a command, which zsh's AUTO_CD would enter"
            case let .gitSpelling(name):
                return "runs git as \(name); spell it git"
            case let .gitOption(option):
                return option.isEmpty
                    ? "runs git without a literal subcommand"
                    : "passes git \(option), which can point it outside the worktree"
            case let .gitProgramOption(option):
                return "passes git \(option) with a program that names git"
            case let .launchesGit(name):
                return "passes git to \(name), which could run it"
            case let .commandOption(option):
                return "uses \(option) beside a mention of git"
            case let .mentionFlows(target):
                return "sends text naming git into \(target), which could run it"
            case .analysisDisagrees:
                return "reads differently to csec's two shell analyses"
            case .outsideWorktree:
                // A `cd` csec wraps runs in `csec ai`'s own shell and moves
                // nothing; a plain `cd … && git …` list runs unwrapped in Claude
                // Code's shell, which keeps its directory.
                return "would run outside your worktree, where this session's shell has moved; "
                    + "move back first with a plain `cd <your worktree> && git status`"
            }
        }

        /// The permission decision reason Claude Code shows the agent.
        public var reason: String {
            "csec: this session is isolated in a Claude Code git worktree, and Claude Code's worktree guard "
                + "can't see inside csec's `csec ai` wrapper, so csec checks that git stays in the worktree. "
                + "This command \(detail). Run git on its own as a plain command or `&&` list "
                + "(git and cd only), which Claude Code's guard checks itself, and the rest as a separate "
                + "command. Text that only mentions git can go to echo, printf, cat, grep, rg, head, tail, "
                + "wc, ls, jq, tee, bd or gh; for anything else, write it to a file in one command and pass "
                + "the file in another."
        }
    }

    /// The refusal for `command`, or nil when it may be wrapped: the session is
    /// not isolated, the command does not name git, or nothing in it can move
    /// git out of the worktree. `workingDirectory` is the hook's `cwd`, where
    /// the command runs.
    public static func refusal(
        for command: String, isolation: Isolation, workingDirectory: String?, environment: Environment
    ) -> Refusal? {
        guard namesGit(command) else { return nil }
        let root: String
        switch isolation {
        case .none:
            return nil
        case .outsideWorktree:
            return .outsideWorktree
        case let .inWorktree(worktree):
            root = worktree
        }
        guard command.utf8.count <= AICommandHook.maximumCommandBytes,
              AICommandSecretFree.unsafeCharacters(in: command) == nil else { return .unparsable }
        let walker: EscapeWalker
        do {
            let tree = try BashTree(command)
            guard !tree.root.hasError else { return .unparsable }
            var walking = EscapeWalker(
                tree: tree, workingDirectory: workingDirectory, worktreeRoot: root, environment: environment)
            try walking.program(tree.root)
            walker = walking
        } catch let refusal as Refusal {
            return refusal
        } catch {
            return .unparsable
        }
        guard let commands = LauncherScript.simpleCommands(in: command) else { return .unparsable }
        guard commands.allSatisfy({ $0.name != nil }),
              commands.count == walker.commandCount,
              commands.filter({ namesGit($0.name ?? "") }).count == walker.gitCount else {
            return .analysisDisagrees
        }
        return nil
    }

    // MARK: - Command classes

    /// Programs that never run what they read, so a mention of git in their
    /// arguments, input or output is only text. Each was checked for an
    /// option that runs a program; those that have one name it in
    /// `programOptions` and are refused with it beside a mention. `gh` passes
    /// only with a subcommand from `ghSubcommands` (an alias or extension can
    /// run a shell command); `tee` writes files.
    static let trustedCommands: Set<String> = [
        "cat", "head", "tail", "wc", "ls", "grep", "egrep", "fgrep", "rg", "jq", "tee", "bd", "gh",
    ]

    /// Builtins that never run a string or change the shell's state, whose
    /// arguments may mention git: they print, test or look a name up.
    static let trustedBuiltins: Set<String> = [
        "echo", "printf", "test", "[", ":", "true", "false", "pwd", "type", "which", "whence", "where",
    ]

    /// Builtins that change nothing git reads, but are no place for a mention
    /// of git. `read` is checked on its own.
    static let harmlessBuiltins: Set<String> = ["wait", "jobs", "kill", "exit", "break", "continue", "read"]

    /// Every builtin and reserved word of zsh 5.9 (`${(k)builtins}`,
    /// `${(k)reswords}`) and bash (`compgen -b`, `compgen -k`) on macOS.
    /// One not in `trustedBuiltins` or `harmlessBuiltins` is refused (`command
    /// -v`/`-V`, a lookup, aside): each can change the directory, the
    /// environment, options or command lookup, or run a string.
    static let shellBuiltinsAndReservedWords: Set<String> = [
        // zsh builtins
        "-", ":", ".", "[", "alias", "autoload", "bg", "bindkey", "break", "builtin", "bye", "cd", "chdir",
        "command", "compadd", "comparguments", "compcall", "compctl", "compdescribe", "compfiles",
        "compgroups", "compquote", "compset", "comptags", "comptry", "compvalues", "continue", "declare",
        "dirs", "disable", "disown", "echo", "echotc", "echoti", "emulate", "enable", "eval", "exec", "exit",
        "export", "false", "fc", "fg", "float", "functions", "getln", "getopts", "hash", "history",
        "integer", "jobs", "kill", "let", "limit", "local", "log", "logout", "noglob", "popd", "print",
        "printf", "private", "pushd", "pushln", "pwd", "r", "read", "readonly", "rehash", "return", "sched",
        "set", "setopt", "shift", "source", "suspend", "test", "times", "trap", "true", "ttyctl", "type",
        "typeset", "ulimit", "umask", "unalias", "unfunction", "unhash", "unlimit", "unset", "unsetopt",
        "vared", "wait", "whence", "where", "which", "zcompile", "zformat", "zle", "zmodload", "zparseopts",
        "zregexparse", "zstyle",
        // zsh reserved words
        "if", "function", "else", "end", "do", "then", "{", "}", "select", "coproc", "case", "[[", "repeat",
        "done", "for", "while", "time", "esac", "until", "nocorrect", "foreach", "elif", "fi", "!", "]]",
        // bash builtins and keywords beyond zsh's
        "bind", "caller", "compgen", "complete", "help", "mapfile", "readarray", "shopt", "in",
    ]

    /// zsh arrays tied to an environment variable or to command or directory
    /// lookup, which a loop or `read` variable must not be.
    static let specialVariableNames: Set<String> = [
        "path", "cdpath", "fpath", "module_path", "manpath", "mailpath", "fignore", "psvar", "watch", "argv",
    ]

    /// `gh` subcommands that run nothing named on the command line.
    static let ghSubcommands: Set<String> = [
        "api", "browse", "cache", "gist", "issue", "label", "org", "pr", "project", "release", "repo",
        "ruleset", "run", "search", "status", "workflow",
    ]

    /// Options of trusted commands that run a program, refused beside a
    /// mention of git. (`printf -v` assigns, and is refused always.)
    static let programOptions: [String: [String]] = [
        "rg": ["--pre", "--pre-glob", "--hostname-bin"],
    ]

    /// Git subcommands with an option or mode that runs a program the command
    /// line names, or that configure one (`config alias.x '!…'`, `core.pager`,
    /// …): `AICommandGitPassthrough.programOptions` plus these.
    static let gitProgramSubcommands: Set<String> = [
        "submodule", "bisect", "difftool", "mergetool", "filter-branch", "config",
    ]

    /// Variables an assignment must not set: what git reads (`GIT_*`, its
    /// configuration's homes), how the shell finds commands and directories,
    /// and what zsh runs for a redirection with no command.
    static let sensitiveVariableNames: Set<String> = [
        "PATH", "CDPATH", "FPATH", "MODULE_PATH", "MANPATH", "HOME", "PWD", "OLDPWD", "IFS", "ZDOTDIR", "ENV",
        "BASH_ENV", "SHELLOPTS", "BASHOPTS", "NULLCMD", "READNULLCMD", "XDG_CONFIG_HOME", "XDG_CONFIG_DIRS",
        "PROMPT_COMMAND",
    ]

    /// A variable an assignment may set: an environment-style name (upper
    /// case: zsh's lower-case specials include `path`, `commands`, `options`
    /// and `aliases`), not `GIT_*`, and not in `sensitiveVariableNames`.
    static func isAssignableVariable(_ name: String) -> Bool {
        let bytes = Array(name.utf8)
        guard let first = bytes.first, (first >= 0x41 && first <= 0x5A) || first == 0x5F else { return false }
        return bytes.allSatisfy { ($0 >= 0x41 && $0 <= 0x5A) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x5F }
            && !name.hasPrefix("GIT_") && !sensitiveVariableNames.contains(name)
    }

    /// An ordinary shell variable name: lower case, and not a zsh special.
    static func isOrdinaryVariable(_ name: String) -> Bool {
        let bytes = Array(name.utf8)
        guard let first = bytes.first, (first >= 0x61 && first <= 0x7A) || first == 0x5F else { return false }
        return bytes.allSatisfy { ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x5F }
            && !specialVariableNames.contains(name)
    }
}

// MARK: - The tree walk

private struct EscapeWalker {
    typealias Refusal = AICommandWorktreeEscape.Refusal
    typealias Escape = AICommandWorktreeEscape

    /// Far beyond any real command; it bounds recursion on a hostile one.
    static let maximumDepth = 64

    let tree: BashTree
    let workingDirectory: String?
    let worktreeRoot: String
    let environment: AICommandWorktreeEscape.Environment
    private(set) var commandCount = 0
    private(set) var gitCount = 0
    /// A file may hold text naming git.
    private var fileMentionsGit = false
    /// A command ran that is neither git nor a trusted command.
    private var ranUntrusted = false
    /// A `cd` came earlier in the text, so a relative one cannot be read.
    private var sawCD = false
    /// Inside a loop body, which can run a `cd` more than once.
    private var loopDepth = 0

    init(
        tree: BashTree, workingDirectory: String?, worktreeRoot: String,
        environment: AICommandWorktreeEscape.Environment
    ) {
        self.tree = tree
        self.workingDirectory = workingDirectory
        self.worktreeRoot = worktreeRoot
        self.environment = environment
    }

    mutating func program(_ root: BashNode) throws {
        guard root.kind == "program" else { throw Refusal.unsupportedSyntax(root.kind) }
        _ = try statements(root.children, input: false, depth: 0)
        // A file written with a mention of git could be run by anything
        // untrusted in the same command (`… > s.sh; sh s.sh`).
        if fileMentionsGit && ranUntrusted { throw Refusal.mentionFlows("a file") }
    }

    // MARK: Statements

    /// Walks the statements among `nodes`; returns whether their output may
    /// name git. `input`: their standard input may name git.
    private mutating func statements(_ nodes: [BashNode], input: Bool, depth: Int) throws -> Bool {
        var output = false
        for node in nodes where node.isNamed {
            if try statement(node, input: input, depth: depth + 1) { output = true }
        }
        return output
    }

    private mutating func statement(_ node: BashNode, input: Bool, depth: Int) throws -> Bool {
        guard depth < Self.maximumDepth else { throw Refusal.nestingTooDeep }
        switch node.kind {
        case "command":
            return try command(node, input: input, depth: depth)
        case "compound_statement" where node.children.first?.kind == "((":
            throw Refusal.unsupportedSyntax("arithmetic")
        case "test_command":
            // `[ … ]` and `[[ … ]]` run nothing themselves; their
            // substitutions run, and are walked.
            _ = try word(node, input: input, depth: depth)
            return false
        case "list", "negated_command", "subshell", "compound_statement", "do_group", "if_statement",
             "elif_clause", "else_clause":
            guard !input || node.kind == "list" || node.kind == "negated_command" else {
                throw Refusal.mentionFlows("a compound command")
            }
            return try statements(node.children, input: input, depth: depth)
        case "while_statement":
            guard !input else { throw Refusal.mentionFlows("a loop") }
            loopDepth += 1
            defer { loopDepth -= 1 }
            return try statements(node.children, input: input, depth: depth)
        case "pipeline":
            var carried = input
            for child in node.children where child.isNamed {
                if try statement(child, input: carried, depth: depth + 1) { carried = true }
            }
            return carried
        case "redirected_statement":
            return try redirectedStatement(node, input: input, depth: depth)
        case "for_statement":
            guard !input else { throw Refusal.mentionFlows("a loop") }
            return try forStatement(node, depth: depth)
        case "comment":
            return false
        case "variable_assignment":
            try assignment(node, depth: depth)
            return false
        case "variable_assignments":
            for child in node.children where child.isNamed {
                guard child.kind == "variable_assignment" else { throw Refusal.assignment }
                try assignment(child, depth: depth)
            }
            return false
        case "declaration_command":
            try declaration(node, depth: depth)
            return false
        case "unset_command":
            throw Refusal.assignment
        case "function_definition":
            throw Refusal.unsupportedSyntax("a function definition")
        case "case_statement":
            throw Refusal.unsupportedSyntax("case")
        case "c_style_for_statement", "arithmetic_expansion", "compound_assignment":
            throw Refusal.unsupportedSyntax("arithmetic")
        default:
            throw Refusal.unsupportedSyntax(node.kind)
        }
    }

    private mutating func redirectedStatement(_ node: BashNode, input: Bool, depth: Int) throws -> Bool {
        var body: BashNode?
        var redirects: [BashNode] = []
        for child in node.children where child.isNamed {
            switch child.kind {
            case "file_redirect", "heredoc_redirect", "herestring_redirect":
                redirects.append(child)
            default:
                guard body == nil else { throw Refusal.unsupportedSyntax("a redirected statement") }
                body = child
            }
        }
        guard let body else { throw Refusal.unsupportedSyntax("a redirected statement") }
        // What the redirections feed the body, and whether a file may then
        // hold a mention of git.
        var fed = false
        for redirect in redirects where try redirection(redirect, input: input, depth: depth) {
            fed = true
        }
        let output: Bool
        if body.kind == "command" {
            output = try command(body, input: input || fed, depth: depth)
        } else {
            output = try statement(body, input: input || fed, depth: depth + 1)
        }
        if output && redirects.contains(where: { $0.kind == "file_redirect" || hasFileRedirect($0) }) {
            fileMentionsGit = true
        }
        return output
    }

    private func hasFileRedirect(_ node: BashNode) -> Bool {
        node.kind == "heredoc_redirect" && node.children.contains { $0.kind == "file_redirect" }
    }

    /// Walks a redirection; returns whether it feeds the command input that
    /// may name git (a heredoc or here-string). A target naming git marks a
    /// file as holding a mention.
    private mutating func redirection(_ node: BashNode, input: Bool, depth: Int) throws -> Bool {
        switch node.kind {
        case "file_redirect":
            for child in node.children where child.isNamed && child.kind != "file_descriptor" {
                let (mention, substituted) = try word(child, input: input, depth: depth)
                if mention || substituted { fileMentionsGit = true }
            }
            return false
        case "herestring_redirect":
            var fed = false
            for child in node.children where child.isNamed {
                let (mention, substituted) = try word(child, input: input, depth: depth)
                if mention || substituted { fed = true }
            }
            return fed
        case "heredoc_redirect":
            return try heredoc(node, input: input, depth: depth)
        default:
            throw Refusal.unsupportedSyntax(node.kind)
        }
    }

    /// A heredoc: its body is the command's input. Under a quoted delimiter
    /// the body is literal; otherwise its substitutions run and are walked.
    /// The grammar hangs what follows the delimiter on the same line (`| sh`,
    /// `&& …`) on the heredoc; only a file redirection may sit there.
    private mutating func heredoc(_ node: BashNode, input: Bool, depth: Int) throws -> Bool {
        var quoted = false
        var fed = false
        for child in node.children {
            switch child.kind {
            case "<<", "<<-", "heredoc_end":
                continue
            case "heredoc_start":
                let text = tree.text(child) ?? ""
                quoted = text.unicodeScalars.contains { $0 == "'" || $0 == "\"" || $0 == "\\" }
            case "heredoc_body":
                if quoted {
                    if Escape.namesGit(tree.text(child) ?? "") { fed = true }
                } else {
                    let (mention, substituted) = try word(child, input: input, depth: depth)
                    if mention || substituted { fed = true }
                }
            case "file_redirect":
                _ = try redirection(child, input: input, depth: depth)
            default:
                throw Refusal.unsupportedSyntax("a command after a heredoc's delimiter")
            }
        }
        return fed
    }

    /// `NAME=value`: a name `isAssignableVariable` accepts, and a value
    /// whose text and substitutions do not name git (a variable can carry
    /// text to `sh -c "$X"`).
    private mutating func assignment(_ node: BashNode, depth: Int) throws {
        var name: String?
        for child in node.children {
            switch child.kind {
            case "variable_name":
                guard name == nil, let text = tree.text(child) else { throw Refusal.assignment }
                name = text
            case "=", "+=":
                continue
            default:
                guard child.isNamed else { throw Refusal.assignment }
                let (mention, substituted) = try word(child, input: false, depth: depth)
                if mention || substituted { throw Refusal.mentionFlows("a variable") }
            }
        }
        guard let name, Escape.isAssignableVariable(name) else { throw Refusal.assignment }
    }

    /// `export NAME[=value] …`, each as `assignment`; no option, and no other
    /// declaration (`typeset`, `declare`, `local`, `readonly`).
    private mutating func declaration(_ node: BashNode, depth: Int) throws {
        guard node.children.first?.kind == "export" else { throw Refusal.assignment }
        for child in node.children.dropFirst() {
            switch child.kind {
            case "variable_assignment":
                try assignment(child, depth: depth)
            case "variable_name":
                guard let name = tree.text(child), Escape.isAssignableVariable(name) else { throw Refusal.assignment }
            default:
                throw Refusal.assignment
            }
        }
    }

    private mutating func forStatement(_ node: BashNode, depth: Int) throws -> Bool {
        var output = false
        var sawIn = false
        for child in node.children {
            switch child.kind {
            case "select":
                throw Refusal.unsupportedSyntax("select")
            case "for", ";", "\n":
                continue
            case "in":
                sawIn = true
            case "variable_name":
                guard !sawIn, let name = tree.text(child), Escape.isOrdinaryVariable(name) else {
                    throw Refusal.assignment
                }
            case "do_group":
                loopDepth += 1
                defer { loopDepth -= 1 }
                if try statement(child, input: false, depth: depth + 1) { output = true }
            default:
                guard child.isNamed, sawIn else { throw Refusal.unsupportedSyntax("a for loop") }
                let (mention, substituted) = try word(child, input: false, depth: depth)
                if mention || substituted { throw Refusal.mentionFlows("a loop variable") }
            }
        }
        return output
    }

    // MARK: Commands

    private enum CommandClass {
        case git
        case trusted
        case untrusted
    }

    /// Walks one simple command; returns whether its output may name git.
    private mutating func command(_ node: BashNode, input: Bool, depth: Int) throws -> Bool {
        commandCount += 1
        var nameNode: BashNode?
        var arguments: [BashNode] = []
        var redirects: [BashNode] = []
        var prefixAssignments: [BashNode] = []
        for child in node.children {
            switch child.kind {
            case "variable_assignment":
                prefixAssignments.append(child)
            case "variable_assignments":
                throw Refusal.assignment
            case "command_name":
                nameNode = child
            case "file_redirect", "herestring_redirect", "heredoc_redirect":
                redirects.append(child)
            default:
                guard child.isNamed else { throw Refusal.unsupportedSyntax(child.kind) }
                arguments.append(child)
            }
        }
        guard let nameNode, nameNode.namedChildCount == 1, let nameWord = nameNode.namedChild(0) else {
            throw Refusal.computedCommandName
        }
        let name: String
        if let literal = ShellLiteralWords.plainLiteral(nameWord, in: tree) {
            name = literal
        } else if nameWord.kind == "word", tree.text(nameWord) == "[" {
            name = "["
        } else {
            throw Refusal.computedCommandName
        }
        let values = arguments.map { ShellLiteralWords.decodedArgument($0, in: tree) }
        let commandClass = try classify(name, values: values)
        // An assignment before a program sets only its environment; one before
        // git or a builtin is refused.
        if !prefixAssignments.isEmpty {
            guard commandClass != .git, !Escape.shellBuiltinsAndReservedWords.contains(name), name != "cd" else {
                throw Refusal.assignment
            }
            for prefix in prefixAssignments { try assignment(prefix, depth: depth) }
        }

        var fed = input
        for redirect in redirects where try redirection(redirect, input: input, depth: depth) {
            fed = true
        }
        if fed && commandClass == .untrusted { throw Refusal.mentionFlows(name) }

        var mentioned = false
        var argumentMentions: [Bool] = []
        for argument in arguments {
            let (mention, substituted) = try word(argument, input: fed, depth: depth)
            argumentMentions.append(mention || substituted)
            if mention || substituted {
                guard commandClass != .untrusted else { throw Refusal.launchesGit(name) }
                mentioned = true
            }
        }
        switch commandClass {
        case .git:
            gitCount += 1
            try gitCommand(values: values, mentions: argumentMentions)
        case .trusted:
            if mentioned || fed {
                for option in Escape.programOptions[name] ?? []
                where values.contains(where: { $0.map { Self.isOption($0, option) } ?? true }) {
                    throw Refusal.commandOption("\(name) \(option)")
                }
                // `tee` writes what it reads to files.
                if name == "tee" { fileMentionsGit = true }
            }
        case .untrusted:
            ranUntrusted = true
        }
        let output = mentioned || fed
        if output && redirects.contains(where: { $0.kind == "file_redirect" || hasFileRedirect($0) }) {
            fileMentionsGit = true
        }
        return output
    }

    /// Whether `value` is `option`, `option=…`, or for a short option a
    /// cluster or attached value holding it.
    private static func isOption(_ value: String, _ option: String) -> Bool {
        if option.hasPrefix("--") {
            return value == option || value.hasPrefix(option + "=")
        }
        return value.hasPrefix("-") && !value.hasPrefix("--") && value.contains(option.dropFirst())
    }

    private mutating func classify(_ name: String, values: [String?]) throws -> CommandClass {
        if name == "git" { return .git }
        if Escape.namesGit(name) { throw Refusal.gitSpelling(name) }
        if name == "printf", values.contains(where: { $0.map { Self.isOption($0, "-v") } ?? true }) {
            throw Refusal.assignment
        }
        if Escape.trustedBuiltins.contains(name) { return .trusted }
        if name == "cd" {
            try changeDirectory(values)
            return .trusted
        }
        if name == "command" {
            guard let first = values.first, first == "-v" || first == "-V" else {
                throw Refusal.shellState(name)
            }
            return .trusted
        }
        if name == "read" {
            for value in values {
                guard let value, value == "-r" || Escape.isOrdinaryVariable(value) else {
                    throw Refusal.shellState("read with that option or variable")
                }
            }
            return .untrusted
        }
        if Escape.harmlessBuiltins.contains(name) { return .untrusted }
        if Escape.shellBuiltinsAndReservedWords.contains(name) { throw Refusal.shellState(name) }
        if name == "gh" {
            guard let first = values.first, let subcommand = first, Escape.ghSubcommands.contains(subcommand) else {
                return .untrusted
            }
            return .trusted
        }
        if Escape.trustedCommands.contains(name) { return .trusted }
        if isDirectoryName(name) { throw Refusal.directoryCommandName }
        return .untrusted
    }

    /// `cd <dir>` that stays in the worktree: one literal operand, not an
    /// option, whose real path (symbolic links followed) is the worktree or
    /// inside it. An absolute one may come anywhere; a relative one only as
    /// the first `cd` in the text and outside a loop, so it is read against
    /// the hook's `cwd`, and only when no `CDPATH` could redirect it.
    private mutating func changeDirectory(_ values: [String?]) throws {
        defer { sawCD = true }
        guard values.count == 1, let target = values[0], !target.isEmpty, !target.hasPrefix("-"),
              !target.hasPrefix("~") else {
            throw Refusal.shellState("cd")
        }
        let path: String
        if target.hasPrefix("/") {
            path = target
        } else {
            guard !sawCD, loopDepth == 0, let workingDirectory, environment.cdpath.isEmpty else {
                throw Refusal.shellState("cd")
            }
            path = (workingDirectory as NSString).appendingPathComponent(target)
        }
        let root = environment.realPath(worktreeRoot) ?? worktreeRoot
        guard let real = environment.realPath(path), real == root || real.hasPrefix(root + "/") else {
            throw Refusal.shellState("cd")
        }
    }

    /// Whether zsh's AUTO_CD could take `name` for a directory to enter: it
    /// is one, read against the command's directory or, without a slash,
    /// against `CDPATH`.
    private func isDirectoryName(_ name: String) -> Bool {
        if name.hasPrefix("/") { return environment.isDirectory(name) }
        var bases: [String] = []
        if let workingDirectory { bases.append(workingDirectory) }
        if !name.contains("/") { bases += environment.cdpath }
        // With no directory to read it against, a relative name could be one.
        if bases.isEmpty { return name.contains("/") || name == ".." }
        return bases.contains { environment.isDirectory(($0 as NSString).appendingPathComponent(name)) }
    }

    /// `git [global options] <subcommand> …`: no option that points git
    /// elsewhere, and no program option beside a program naming git.
    private mutating func gitCommand(values: [String?], mentions: [Bool]) throws {
        let literalPrefix = Array(values.prefix { $0 != nil }.compactMap { $0 })
        let index: Int
        switch AICommandSecretFree.gitGlobalOptions(literalPrefix) {
        case let .failure(rejection):
            switch rejection {
            case let .gitConfigurationOverride(option), let .gitGlobalOption(option):
                throw Refusal.gitOption(option)
            default:
                throw Refusal.gitOption("")
            }
        case let .success(subcommandIndex):
            index = subcommandIndex
        }
        guard index < literalPrefix.count else { throw Refusal.gitOption("") }
        for option in literalPrefix[..<index] {
            let long = option.split(separator: "=", maxSplits: 1).first.map(String.init) ?? option
            if option == "-C" || option == "--bare" || long == "--git-dir" || long == "--work-tree" {
                throw Refusal.gitOption(long)
            }
        }
        let subcommand = literalPrefix[index]
        let rest = values[(index + 1)...]
        let programOption = (AICommandGitPassthrough.programOptions[subcommand] ?? []).first { option in
            rest.contains { value in
                value.map { AICommandGitPassthrough.couldBeOption($0, long: option.long, short: option.short) } ?? true
            }
        }
        // A program git runs could run a file this command wrote.
        if programOption != nil || (Escape.gitProgramSubcommands.contains(subcommand) && subcommand != "config") {
            ranUntrusted = true
        }
        guard mentions[(index + 1)...].contains(true) else { return }
        if Escape.gitProgramSubcommands.contains(subcommand) {
            throw Refusal.gitProgramOption(subcommand)
        }
        if let programOption {
            throw Refusal.gitProgramOption("\(subcommand) \(programOption.long)")
        }
    }

    // MARK: Words

    /// Walks a word: every command or process substitution in it runs, so
    /// is walked as statements. Returns whether its own text (substitutions
    /// left out) names git, and whether a substitution's output may.
    /// `input`: the enclosing command's input may name git, which `$(cat)`
    /// would read.
    private mutating func word(_ node: BashNode, input: Bool, depth: Int) throws -> (mention: Bool, substituted: Bool) {
        var substitutions: [(start: Int, end: Int)] = []
        let substituted = try substitutionsIn(node, input: input, depth: depth, ranges: &substitutions)
        let start = Int(node.startByte)
        var bytes = Array(tree.source[start..<Int(node.endByte)])
        for range in substitutions {
            for index in (range.start - start)..<(range.end - start) { bytes[index] = 0x20 }
        }
        let text = String(decoding: bytes, as: UTF8.self)
        let mention = Escape.namesGit(text)
        // zsh evaluates a subscript as arithmetic wherever it does arithmetic
        // (`printf %d`, `[ -t … ]`, `$x[…]`, `${x[…]}`), and arithmetic runs a
        // `$(…)` or backquote in it, even one the grammar read as quoted text.
        if mention, text.contains("["), text.contains("$(") || text.contains("`") || text.contains("$[") {
            throw Refusal.unsupportedSyntax("text zsh could evaluate in a subscript")
        }
        return (mention, substituted)
    }

    private mutating func substitutionsIn(
        _ node: BashNode, input: Bool, depth: Int, ranges: inout [(start: Int, end: Int)]
    ) throws -> Bool {
        guard depth < Self.maximumDepth else { throw Refusal.nestingTooDeep }
        switch node.kind {
        case "command_substitution":
            ranges.append((Int(node.startByte), Int(node.endByte)))
            return try statements(node.children, input: input, depth: depth)
        case "process_substitution":
            guard node.children.first?.kind == "<(" else { throw Refusal.unsupportedSyntax(">(…)") }
            ranges.append((Int(node.startByte), Int(node.endByte)))
            return try statements(node.children, input: input, depth: depth)
        case "expansion":
            let text = tree.text(node) ?? "="
            if text.contains("=") || text.contains("(") { throw Refusal.unsupportedSyntax("${…} with = or flags") }
        case "arithmetic_expansion":
            throw Refusal.unsupportedSyntax("arithmetic")
        default:
            break
        }
        var substituted = false
        for child in node.children
        where try substitutionsIn(child, input: input, depth: depth + 1, ranges: &ranges) {
            substituted = true
        }
        return substituted
    }
}
