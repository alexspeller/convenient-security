import Foundation

// What the SSH, secret and sudo walks still share now that an SSH signing is
// judged by auto mode's approval alone (csec-0.11): the anchor an SSH request
// is tied to (the `csec ai` running the approved command or, for a git
// command csec's hook left unwrapped, Claude Code's Bash tool shell,
// `ClaudeToolShell`), the environment a program shell starts from, and the
// argv readers sudo's chain rule uses.

/// The environment a `csec ai`'s program shell starts from, read from the
/// `csec ai` itself (whose environment, with each `csec_NAME` reference
/// resolved to `NAME`, is the program shell's). Only the names that point the
/// shell's startup files somewhere else are read (`SSHChainRule
/// .shellEnvironmentNames`).
struct SSHChainAnchorEnvironment: Sendable {
    /// The process whose environment this is.
    let process: ProcessIncarnation
    /// Presence of `ZDOTDIR`, also as the `csec_` reference that `csec ai`
    /// resolves to it. Nil when unreadable.
    let presence: EnvironmentNamePresence?

    /// The names read, plain and as a `csec_` reference.
    static var names: [String] {
        SSHChainRule.shellEnvironmentNames + SSHChainRule.shellEnvironmentNames.map { ExecPlanner.referencePrefix + $0 }
    }

    static func read(from process: ProcessIncarnation, provider: any ClaudeSessionFactProvider) -> SSHChainAnchorEnvironment {
        SSHChainAnchorEnvironment(
            process: process,
            presence: provider.envPresence(of: process, names: names, prefixes: [])
        )
    }

    /// Whether `name` (plain or as a `csec_` reference) occurs.
    func contains(_ name: String) -> Bool {
        guard let presence else { return true }
        return (presence.names[name] ?? 0) > 0 || (presence.names[ExecPlanner.referencePrefix + name] ?? 0) > 0
    }
}

/// The process an SSH chain is anchored on: the one whose program text was
/// approved, and whose parent's parent (or parent) is the Claude Code process.
enum SSHChainAnchor: Sendable, Equatable {
    /// `csec ai`, under the Bash tool shell, with its program shell
    /// (`/bin/zsh -lc`) directly below it.
    case csecAI
    /// Claude Code's Bash tool shell itself (`ClaudeToolShell`), for a git
    /// command the hook left unwrapped: no program shell, and git directly
    /// below it.
    case toolShell
    /// `csec ai` as Claude Code's shell prefix (`ClaudeCodeShellPrefix`): in
    /// the Bash tool shell's place, directly under P, with its program shell
    /// directly below it.
    case csecShellPrefix
}

/// Claude Code's Bash tool shell as the kernel shows it, and the command it
/// evaluates: the anchor of an SSH chain whose git csec's hook left unwrapped
/// (`AICommandGitPassthrough`), where no `csec ai` stands above `ssh`.
///
/// Claude Code 2.1.280 runs every Bash call as a child of its own process
/// with argv `/bin/zsh`, `-c`, and a script that sources the session's shell
/// snapshot, sets a few options and then runs `eval '<command>' < /dev/null
/// && pwd -P >| <cwd file>`, the command single-quoted with each `'` spelled
/// `'"'"'` (measured with `ps`). That framing only ever puts `"` after a
/// closing `'`, so zsh's RC_QUOTES cannot read it another way. The command
/// inside the quotes is the hook's `tool_input.command`, byte for byte, so a
/// registration's digest of it binds here.
///
/// The rule is exact and fails closed: the executable is `/bin/zsh`, argv is
/// exactly `[_, -c, script]`, the script parses with no error, exactly one
/// command in it can run `eval` (by any spelling: `\eval`, `builtin eval`,
/// …), and that one is the plain `eval` with one argument that is literal in
/// both shells (`ShellLiteralWords`). The one exception is a quoted `eval` of
/// literal text only, which Claude Code adds around some commands
/// (`evaluatesQuotedFixedText`). Anything else is not a tool shell, and an
/// `ssh` under it finds no anchor. Only this process's own argv is read;
/// csecd never trusts a process to say what it runs except through the
/// kernel's copy of the argv it was started with, and the registration it
/// binds must have reached csecd before this shell started.
public enum ClaudeToolShell {
    public static let shellPath = "/bin/zsh"
    /// Far above any command the hook accepts (`AICommandHook
    /// .maximumCommandBytes`, quoted) and above the kernel's argument limit.
    static let maximumScriptBytes = 4 * 1024 * 1024
    /// Bounds the walk over a hostile script.
    static let maximumNodes = 1_000_000
    /// Command words that run their next word as a command.
    static let precommands: Set<String> = ["builtin", "command", "exec", "noglob", "nocorrect", "-"]

    /// The command a Bash tool shell evaluates, exactly as `eval` receives it,
    /// or nil when `executablePath` and `argv` are not one.
    public static func program(executablePath: String?, argv: [String]?) -> String? {
        guard executablePath == shellPath, let argv, argv.count == 3,
              ClaudeDelegationService.bytesEqual(argv[1], "-c") else { return nil }
        return evaluated(script: argv[2])?.program
    }

    /// The command Claude Code's framing `script` evaluates, and the byte
    /// offset where that one `eval` command starts, or nil when the script is
    /// not one: the rule `program(executablePath:argv:)` documents, applied to
    /// the script alone.
    static func evaluated(script: String) -> (program: String, evalStart: Int)? {
        guard !script.isEmpty, script.utf8.count <= maximumScriptBytes, !script.utf8.contains(0),
              let tree = try? BashTree(script), !tree.root.hasError else { return nil }
        var evaluating: [BashNode] = []
        var stack = [tree.root]
        var visited = 0
        while let node = stack.popLast() {
            visited += 1
            guard visited <= maximumNodes else { return nil }
            if node.kind == "command", mayRunEval(node, in: tree), !evaluatesQuotedFixedText(node, in: tree) {
                evaluating.append(node)
            }
            stack.append(contentsOf: node.children)
        }
        guard evaluating.count == 1, let eval = evaluating.first else { return nil }
        var name: String?
        var arguments: [BashNode] = []
        for child in eval.children {
            switch child.kind {
            case "command_name":
                guard child.namedChildCount == 1, let word = child.namedChild(0) else { return nil }
                name = ShellLiteralWords.plainLiteral(word, in: tree)
            default:
                // An assignment prefix, a redirection inside the command, or
                // anything unnamed.
                guard child.isNamed, child.kind != "variable_assignment", child.kind != "file_redirect",
                      child.kind != "herestring_redirect" else { return nil }
                arguments.append(child)
            }
        }
        guard name == "eval", arguments.count == 1,
              let program = ShellLiteralWords.decodedArgument(arguments[0], in: tree), !program.isEmpty else {
            return nil
        }
        return (program, Int(eval.startByte))
    }

    /// Whether a command node could run `eval`, over-approximated so that
    /// "exactly one" cannot miss one: its name reads `eval` once quotes and
    /// backslashes are removed, its name is computed (`$…`, a backquote), or
    /// its name is a precommand and any later word reads `eval`.
    static func mayRunEval(_ command: BashNode, in tree: BashTree) -> Bool {
        let children = command.children
        guard let nameIndex = children.firstIndex(where: { $0.kind == "command_name" }),
              let nameText = tree.text(children[nameIndex]) else { return false }
        if nameText.unicodeScalars.contains(where: { $0 == "$" || $0 == "`" }) { return true }
        let name = unquoted(nameText)
        if name == "eval" { return true }
        guard precommands.contains(name) else { return false }
        return children[(nameIndex + 1)...].contains { word in
            word.isNamed && tree.text(word).map(unquoted) == "eval"
        }
    }

    /// Whether a command is a quoted `eval` that evaluates only literal text,
    /// as the pieces Claude Code adds around some commands do: 2.1.319 on
    /// macOS puts `{ 'eval' '<a git function>' 2>/dev/null || 'true'; }`
    /// before the `eval` of any command whose git runs `grep` (csec-0.98).
    /// Its name is a quoted, static spelling of `eval` (never the plain word,
    /// which stays the command's own `eval`), and every argument is literal
    /// in both shells, so it runs fixed text, as if that text were written
    /// into the framing itself, and cannot make the command's `eval`
    /// ambiguous. A computed or backslashed name, a precommand, an assignment
    /// or redirection inside the command, or any argument with an expansion
    /// still counts as a command that may run `eval`.
    static func evaluatesQuotedFixedText(_ command: BashNode, in tree: BashTree) -> Bool {
        var sawName = false
        var arguments = 0
        for child in command.children {
            if child.kind == "command_name" {
                guard !sawName, child.namedChildCount == 1, let word = child.namedChild(0),
                      ShellLiteralWords.plainLiteral(word, in: tree) == nil,
                      ShellLiteralWords.decodedArgument(word, in: tree) == "eval" else { return false }
                sawName = true
                continue
            }
            guard sawName, child.isNamed, child.kind != "variable_assignment", child.kind != "file_redirect",
                  child.kind != "herestring_redirect", isLiteral(child, in: tree) else { return false }
            arguments += 1
        }
        return sawName && arguments > 0
    }

    /// Whether an argument is literal in both shells: `ShellLiteralWords`'
    /// reading, or single-quoted text joined by `\'`, the form Claude Code
    /// quotes its pieces in (`'it'\''s'`). Outside quotes `\'` is a plain
    /// quote in zsh and bash alike.
    private static func isLiteral(_ argument: BashNode, in tree: BashTree) -> Bool {
        if ShellLiteralWords.decodedArgument(argument, in: tree) != nil { return true }
        guard argument.kind == "concatenation" else { return false }
        var previousWasSingleQuoted = false
        for part in argument.children {
            if part.kind == "word", tree.text(part) == "\\'" {
                previousWasSingleQuoted = false
                continue
            }
            // Two adjacent single-quoted parts are one string with a quote in
            // it under zsh's RC_QUOTES, as in `ShellLiteralWords`.
            guard part.kind == "raw_string", !previousWasSingleQuoted,
                  ShellLiteralWords.decodedArgument(part, in: tree) != nil else { return false }
            previousWasSingleQuoted = true
        }
        return true
    }

    private static func unquoted(_ text: String) -> String {
        String(text.unicodeScalars.filter { $0 != "\\" && $0 != "'" && $0 != "\"" })
    }
}

enum SSHChainRule {
    /// Points the program shell's startup files somewhere else: those files
    /// can define a function named like the approved command.
    static let shellEnvironmentNames = ["ZDOTDIR"]

    /// Whether the environment a program shell started from points its
    /// startup files somewhere else, for a secret release and a sudo. An
    /// environment csecd cannot read proves nothing either way.
    static func shellSteering(_ environment: SSHChainAnchorEnvironment) -> DelegationDecline? {
        guard environment.presence != nil else { return .factsUnavailable }
        for name in shellEnvironmentNames where environment.contains(name) {
            return .environmentSteering(process: "the command's shell", name: name)
        }
        return nil
    }


    /// The command GNU `timeout` runs: its argv after its options and the
    /// duration, read as coreutils reads them (src/timeout.c:
    /// `getopt_long(argc, argv, "+fk:ps:v", …)`, stopping at the first operand,
    /// which is the duration). Nil for anything not read exactly here: an
    /// unknown or abbreviated option, `--help`, `--version`, or no command.
    static func timeoutCommand(_ argv: [String]) -> [String]? {
        var index = 1
        while index < argv.count {
            let word = argv[index]
            if word == "--" {
                index += 1
                break
            }
            guard word.hasPrefix("-"), word != "-" else { break }
            if word.hasPrefix("--") {
                let body = word.dropFirst(2)
                if let equals = body.firstIndex(of: "=") {
                    guard ["kill-after", "signal"].contains(String(body[..<equals])) else { return nil }
                    index += 1
                } else if ["foreground", "preserve-status", "verbose"].contains(String(body)) {
                    index += 1
                } else if ["kill-after", "signal"].contains(String(body)) {
                    guard index + 1 < argv.count else { return nil }
                    index += 2
                } else {
                    return nil
                }
                continue
            }
            // A cluster of short options: f, p and v take nothing; k and s take
            // the rest of the word, or the next word when nothing is left.
            let letters = Array(word.dropFirst())
            var next = index + 1
            for (position, letter) in letters.enumerated() {
                if "fpv".contains(letter) { continue }
                guard "ks".contains(letter) else { return nil }
                if position == letters.count - 1 {
                    guard next < argv.count else { return nil }
                    next += 1
                }
                break
            }
            index = next
        }
        // The duration, then the command.
        guard argv.count - index >= 2 else { return nil }
        return Array(argv[(index + 1)...])
    }

    /// The command an argv ends up running when it starts with programs that
    /// exec the rest of it in place, so the process below is that command:
    /// `env [-i] [NAME=value…]`, `nice [-n N | -N]`, `nohup`, `mise exec|x …
    /// --` and `direnv exec DIR`, the argv forms of `ShellPrefixRules`'
    /// executables. Anything else is the command itself.
    static func execedCommand(_ argv: [String]) -> [String] {
        var rest = argv[...]
        while let first = rest.first {
            let name = (first as NSString).lastPathComponent
            var width = 1
            switch name {
            case "nohup":
                break
            case "nice":
                if rest.count > 2, rest[rest.startIndex + 1] == "-n" {
                    width = 3
                } else if rest.count > 1, isNiceAdjustment(rest[rest.startIndex + 1]) {
                    width = 2
                }
            case "env":
                if rest.count > 1, rest[rest.startIndex + 1] == "-i" { width = 2 }
                while rest.startIndex + width < rest.endIndex, isAssignment(rest[rest.startIndex + width]) { width += 1 }
            case "mise":
                guard rest.count > 1, ["exec", "x"].contains(rest[rest.startIndex + 1]),
                      let separator = rest.dropFirst(2).firstIndex(of: "--"),
                      !rest[(rest.startIndex + 2)..<separator].contains(where: ShellPrefixRules.isMiseCommandOption)
                else { return Array(rest) }
                width = separator + 1 - rest.startIndex
            case "direnv":
                guard rest.count > 2, rest[rest.startIndex + 1] == "exec" else { return Array(rest) }
                width = 3
            default:
                return Array(rest)
            }
            guard rest.startIndex + width < rest.endIndex, !rest[rest.startIndex + width].hasPrefix("-") else {
                return Array(rest)
            }
            rest = rest.dropFirst(width)
        }
        return Array(rest)
    }

    private static func isNiceAdjustment(_ text: String) -> Bool {
        let bytes = Array(text.utf8)
        return bytes.count >= 2 && bytes[0] == UInt8(ascii: "-") && bytes.dropFirst().allSatisfy { $0 >= 0x30 && $0 <= 0x39 }
    }

    private static func isAssignment(_ text: String) -> Bool {
        guard let equals = text.firstIndex(of: "="), equals != text.startIndex else { return false }
        let name = text[..<equals]
        return name.first.map { $0 == "_" || $0.isASCII && $0.isLetter } == true
            && name.allSatisfy { $0 == "_" || $0.isASCII && ($0.isLetter || $0.isNumber) }
    }
}
