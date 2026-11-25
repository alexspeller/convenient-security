import Foundation

/// Whether a `csec ai` program can run without any secret, so the broker asks
/// csecd for none of the environment's references and hands the child none of
/// them.
///
/// Every command a coding agent runs inherits the project's direnv environment,
/// so a read-only `ls`, `rg` or `git status` used to ask for the whole secret
/// set, and the first one of a session raised a Touch ID panel. A program is
/// secret-free when it runs only listed tools that need no secret and start no
/// program named on their command line, and expands no reference variable.
/// `git` and `bd` are allowed for a fixed set of subcommands, and so is any
/// command this Mac's administrator lists in `LocalCommands`.
///
/// The classifier reads the program with the vendored tree-sitter-bash parse the
/// Codex gate uses (`BashTree`), but `csec ai` runs it with `/bin/zsh -lc`, and
/// the two do not always split a program the same way. The classifier does not
/// model zsh. It accepts only what both read alike: raw bytes and word shapes on
/// which the two lexers are known to disagree (control characters, a backslash
/// before whitespace, `=(`, ANSI-C `$'…'`, `$#`, `~name`, parentheses or `#`
/// inside a word, a comment that does not follow a blank, an expansion outside
/// double quotes) are refused outright, and the syntax tree is walked with an
/// allowlist of node kinds and operator tokens. Options are checked on the
/// value both shells give a quoted or unquoted literal word. Anything else (functions, `case`, `for`, arithmetic, assignments,
/// unquoted heredocs with expansions, zsh-only syntax) keeps the ordinary path:
/// request every reference, inject, redact. `cs-selftest` runs the whole corpus
/// under the real `/bin/zsh -lc` and checks every secret-free program ran only
/// what this classifier allowed.
///
/// A wrong "secret-free" verdict cannot release anything. It withholds secrets
/// from a command that wanted them, which fails visibly, and it stops that
/// command from activating values for output redaction. Output scanning itself
/// is unchanged: the program still runs under csecd's redaction session, which
/// covers every value already released (the sudo PAM redactor's
/// `tool-exec … -- /bin/cat` depends on that).
public enum AICommandSecretFree {
    /// Tools that neither need a secret nor, with the option checks below, start
    /// another program that might. `git` and `bd` are allowed separately, for
    /// the subcommands in `readOnlyGitSubcommands` and `bdSubcommands`, and so
    /// are the commands in `LocalCommands`.
    public static let listedCommands: Set<String> = [
        "ls", "cat", "head", "tail", "wc", "sort", "uniq", "cut", "tr", "paste", "comm", "nl",
        "fold", "column", "rev", "grep", "egrep", "fgrep", "rg", "find", "fd", "sed", "jq",
        "diff", "cmp", "file", "stat", "du", "df", "tree", "realpath", "readlink", "basename",
        "dirname", "pwd", "cd", "echo", "printf", "true", "false", "test", "[", "which", "type",
        "sleep", "date", "whoami", "id", "uname", "sw_vers", "hostname", "mkdir", "touch", "cp",
        "mv", "rm", "rmdir", "ln", "chmod", "xxd", "od", "hexdump", "strings", "shasum", "md5",
        "cksum", "plutil", "otool", "nm", "lipo", "dwarfdump", "ps", "pgrep", "lsof",
    ]

    /// Commands that run, re-run or source another program. None is listed; they
    /// are named so a verdict says why.
    public static let bannedCommands: Set<String> = [
        "eval", "source", ".", "exec", "env", "xargs", "command", "builtin", "sudo", "nohup",
        "time", "timeout",
    ]

    /// The `bd` (beads issue tracker) subcommands that read or write the issue
    /// database and start no program their command line names (each one's
    /// options, bd 1.3.1). Left out: those that start a program (`edit` and
    /// `create-form`, an editor or a form; `hooks`, `mail`, `preflight`,
    /// `orphans`, `worktree`), reach another service or a remote (`gate`, whose
    /// checks run `gh`; `dolt`, `sync`, `federation`, `vc`, `backup`, and the
    /// `github`, `gitlab`, `jira`, `linear`, `notion` and `ado` integrations),
    /// or set bd up (`init`, `setup`, `config`, `upgrade`, `migrate`, …).
    /// Global options before the subcommand are read by `bdGlobalOptions`.
    public static let bdSubcommands: Set<String> = [
        "show", "list", "search", "ready", "children", "count", "blocked", "stale", "status", "statuses",
        "types", "where", "info", "history", "query", "comments", "memories", "recall", "prime", "version",
        "create", "q", "update", "close", "reopen", "note", "comment", "label", "tag", "dep", "link", "defer",
        "undefer", "assign", "priority", "duplicate", "supersede", "unclaim", "remember", "forget", "kv", "sql",
    ]

    /// Where bd reads a credential from the environment: its database password
    /// and credential command (`BEADS_DOLT_PASSWORD`,
    /// `BEADS_DOLT_CREDENTIAL_COMMAND`, …), a Dolt remote's
    /// (`DOLT_REMOTE_PASSWORD`), and any configuration key as `BD_<KEY>`. While
    /// a reference variable has one of these prefixes, bd may need it, so bd
    /// keeps the ordinary path.
    public static let bdCredentialPrefixes: [String] = ["BD_", "BEADS_", "DOLT_"]

    /// The `git` subcommands that read the repository, reached only without
    /// `-c`, `--config-env` or `--exec-path`.
    public static let readOnlyGitSubcommands: Set<String> = [
        "status", "log", "diff", "show", "branch", "rev-parse", "ls-files", "blame", "grep",
        "merge-base", "cat-file", "describe", "reflog", "shortlog", "for-each-ref",
        "check-ignore", "name-rev",
    ]

    /// Commands whose options are checked. Every argument of one of these must
    /// have a value zsh and bash agree on without expanding anything: plain
    /// unquoted text, single quotes, and double quotes with no `$`, backquote,
    /// backslash or `!` (no escape, expansion, glob, brace or ANSI-C string).
    /// The checks read that decoded value, so `'-exec'` is still `-exec`.
    public static let inspectedCommands: Set<String> = ["find", "fd", "rg", "sort", "jq", "git", "printf"]

    /// Where a listed tool may be named by path. A path anywhere else (a
    /// project's `bin/test`, `./script/diff`) is that project's own program,
    /// which may well need the secrets, whatever its basename.
    public static let systemToolDirectories: Set<String> = [
        "/bin", "/usr/bin", "/sbin", "/usr/sbin", "/usr/local/bin", "/opt/homebrew/bin",
    ]

    /// Why a program is not secret-free. Value-free: command names, options,
    /// node kinds and environment variable names only.
    public enum Rejection: Error, Sendable, Equatable {
        /// Bytes the bash grammar and zsh read differently: a control, format or
        /// non-ASCII whitespace character, a backslash before whitespace, a
        /// control character or the end, or zsh's `=(…)`.
        case unsafeCharacters(String)
        /// tree-sitter could not parse the program, or reported an ERROR or
        /// MISSING node.
        case unparsable
        /// A node kind, operator token or word shape the classifier does not
        /// accept.
        case unsupportedSyntax(String)
        /// Nested deeper than the classifier follows.
        case nestingTooDeep
        /// Assigning or unsetting a variable can retarget a listed tool (`PATH`,
        /// `PAGER`, `GIT_*`); `printf -v` is one too.
        case variableAssignment
        /// A command name that is not a plain literal word.
        case nonLiteralCommandName
        /// An argument of an `inspectedCommands` command whose value zsh could
        /// compute differently from its text (see `inspectedCommands`), so its
        /// options cannot be checked as zsh passes them.
        case nonLiteralArgument(command: String)
        /// A path outside `systemToolDirectories`.
        case commandPathOutsideSystemDirectories(String)
        case bannedCommand(String)
        case unlistedCommand(String)
        /// A reference variable is expanded.
        case expandsReference(String)
        /// `${!name}`-style indirection, which could reach any variable.
        case indirectExpansion
        /// An option, anywhere in the arguments, that makes a listed tool run
        /// another program: find `-exec -execdir -ok -okdir`; fd `-x -X -l`;
        /// rg `--pre -z --hostname-bin`; sort `--compress-program`; git grep
        /// `-O --textconv`, git cat-file `--textconv --filters`, git branch
        /// `--edit-description`, and `--ext-diff --textconv --show-signature`,
        /// `%G…` and `%(signature…)` for the other git subcommands.
        case runsProgram(command: String, option: String)
        /// A `jq` filter that reads the environment (`env`, `$ENV`).
        case readsEnvironment(command: String)
        /// `git -c`, `--config-env` or `--exec-path`.
        case gitConfigurationOverride(String)
        /// A `git` global option that is not accepted.
        case gitGlobalOption(String)
        /// A missing or unlisted `git` subcommand ("" when absent).
        case gitSubcommand(String)
        /// A `bd` global option that is not accepted.
        case bdGlobalOption(String)
        /// A missing or unlisted `bd` subcommand ("" when absent).
        case bdSubcommand(String)
        /// A missing or unlisted subcommand of a `LocalCommands` command (""
        /// when absent; the subcommand alone, or with its second word, for one
        /// allowed only with listed second words).
        case localSubcommand(command: String, subcommand: String)
        /// A reference variable whose name the tool reads its own credential
        /// from (`bdCredentialPrefixes` for bd, a local command's
        /// `credentialVariablePrefixes`).
        case readsCredential(command: String, variable: String)
    }

    public enum Verdict: Sendable, Equatable {
        case secretFree
        case needsSecrets(Rejection)

        public var isSecretFree: Bool { self == .secretFree }
    }

    /// Classify one shell program as `csec ai` runs it (`/bin/zsh -lc program`).
    /// `referenceVariables` are the environment names that hold, or alias,
    /// secret references for this launch (`referenceVariables(of:)`).
    /// `localCommands` are this Mac's additions (`LocalCommands.load()`).
    public static func classify(
        _ program: String,
        referenceVariables: Set<String>,
        localCommands: LocalCommands = .none
    ) -> Verdict {
        if let unsafe = unsafeCharacters(in: program) { return .needsSecrets(.unsafeCharacters(unsafe)) }
        do {
            let tree = try BashTree(program)
            guard !tree.root.hasError else { return .needsSecrets(.unparsable) }
            try Classifier(tree: tree, referenceVariables: referenceVariables, localCommands: localCommands)
                .program(tree.root)
            return .secretFree
        } catch let rejection as Rejection {
            return .needsSecrets(rejection)
        } catch {
            return .needsSecrets(.unparsable)
        }
    }

    /// Whether one command, as zsh actually runs it (its name and every argument
    /// after expansion), is allowed in a secret-free program. `classify` applies
    /// this to the literal words it reads; `cs-selftest` applies it to what the
    /// real zsh ran. `referenceVariables` and `localCommands` are `classify`'s.
    public static func invocationRejection(
        _ argv: [String],
        referenceVariables: Set<String>,
        localCommands: LocalCommands = .none
    ) -> Rejection? {
        guard let name = argv.first, !name.isEmpty else { return .nonLiteralCommandName }
        var program = name
        if let slash = name.lastIndex(of: "/") {
            let directory = String(name[..<slash])
            program = String(name[name.index(after: slash)...])
            guard !program.isEmpty, systemToolDirectories.contains(directory) else {
                return .commandPathOutsideSystemDirectories(name)
            }
        }
        if bannedCommands.contains(program) { return .bannedCommand(program) }
        // Every argument is scanned, wherever it sits: getopt, git's
        // parse-options and ripgrep all take a `--` as an option's value
        // (`sort -o -- --compress-program=x`) and keep reading options after
        // it. Refusing a search for a literal "--pre" is the price.
        let arguments = Array(argv.dropFirst())
        if program == "git" { return gitRejection(arguments) }
        if program == "bd" { return bdRejection(arguments, referenceVariables: referenceVariables) }
        if let local = localCommands.commands[program] {
            return local.rejection(program, arguments, referenceVariables: referenceVariables)
        }
        guard listedCommands.contains(program) else { return .unlistedCommand(program) }
        let option: String?
        switch program {
        case "find":
            // find(1): -exec, -execdir, -ok, -okdir run a utility.
            option = arguments.first { ["-exec", "-execdir", "-ok", "-okdir"].contains($0) }
        case "fd":
            // fd --help: -x/--exec, -X/--exec-batch, and -l/--list-details (an
            // alias for `--exec-batch ls -l`). clap bundles short flags (`-HIx`)
            // and does not accept abbreviated long options.
            option = arguments.first { argument in
                ["--exec", "--exec-batch", "--list-details"].contains(longName(argument))
                    || (isShortCluster(argument) && argument.contains { "xXl".contains($0) })
            }
        case "rg":
            // rg --help: --pre (a preprocessor), -z/--search-zip (decompressors
            // from PATH), --hostname-bin (a hostname command). No abbreviations.
            option = arguments.first { argument in
                ["--pre", "--search-zip", "--hostname-bin"].contains(longName(argument))
                    || (isShortCluster(argument) && argument.contains("z"))
            }
        case "sort":
            // sort(1): --compress-program; getopt_long accepts any unambiguous
            // prefix of a long option.
            option = arguments.first { abbreviates($0, "--compress-program") }
        case "jq":
            // `env` and `$ENV` read the references; `-f` and `-L` read a filter
            // or module the check cannot see.
            if arguments.contains(where: { argument in
                readsEnvironment(argument)
                    || ["--from-file", "--library-path"].contains(longName(argument))
                    || (isShortCluster(argument) && argument.contains { "fL".contains($0) })
            }) {
                return .readsEnvironment(command: program)
            }
            option = nil
        case "printf":
            // `printf -v NAME` assigns a shell parameter, `PATH` included.
            if arguments.contains(where: { $0.hasPrefix("-v") }) { return .variableAssignment }
            option = nil
        default:
            option = nil
        }
        return option.map { .runsProgram(command: program, option: $0) }
    }

    /// Every variable of the launch environment that holds a reference, plus
    /// every `csec_` alias of one. Expanding either means the program wants a
    /// secret.
    public static func referenceVariables(of plan: ExecPlanner.Plan) -> Set<String> {
        Set(plan.assignments.keys).union(plan.referenceNames)
    }

    /// The child environment of a secret-free launch: the ambient environment
    /// without any reference variable or alias, so the child sees neither a
    /// value nor an unresolved reference.
    public static func environmentWithoutReferences(
        _ environment: [String: String],
        plan: ExecPlanner.Plan
    ) -> [String: String] {
        let names = referenceVariables(of: plan)
        return environment.filter { !names.contains($0.key) }
    }

    // MARK: - Raw bytes

    /// A description of the first byte sequence the two lexers read differently,
    /// or nil. tree-sitter-bash treats `\s` (vertical tab, form feed, carriage
    /// return, Unicode spaces) and a backslash before a blank as whitespace
    /// where zsh keeps them in a word; `=(…)` is zsh process substitution.
    static func unsafeCharacters(in program: String) -> String? {
        let scalars = Array(program.unicodeScalars)
        for (index, scalar) in scalars.enumerated() {
            switch scalar {
            case " ", "\t", "\n":
                continue
            case "\\":
                guard index + 1 < scalars.count else { return "a trailing backslash" }
                let next = scalars[index + 1]
                if isInvisible(next) || next == " " || next == "\t" || next == "\n" {
                    return "a backslash before whitespace or a control character"
                }
            case "=":
                if index + 1 < scalars.count, scalars[index + 1] == "(" { return "=(" }
            default:
                if isInvisible(scalar) { return "a control, format or non-ASCII whitespace character" }
            }
        }
        return nil
    }

    private static func isInvisible(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.properties.generalCategory {
        case .control, .format, .lineSeparator, .paragraphSeparator, .spaceSeparator:
            return true
        default:
            return scalar.properties.isWhitespace
        }
    }

    // MARK: - Option checks

    /// git's global options, as git's own `handle_options` (git.c) consumes them:
    /// the index of the subcommand (the argument count when there is none), or
    /// why an option is refused.
    static func gitGlobalOptions(_ arguments: [String]) -> Result<Int, Rejection> {
        let takesValue: Set<String> = ["-C", "--git-dir", "--work-tree", "--namespace"]
        let flags: Set<String> = [
            "-P", "--no-pager", "--no-replace-objects", "--no-lazy-fetch", "--no-optional-locks",
            "--no-advice", "--bare", "--literal-pathspecs", "--no-literal-pathspecs",
            "--glob-pathspecs", "--noglob-pathspecs", "--icase-pathspecs",
        ]
        var index = 0
        while index < arguments.count {
            let argument = arguments[index]
            guard argument.hasPrefix("-") else { break }
            if argument == "-c" || longName(argument) == "--config-env" || argument.hasPrefix("--exec-path") {
                return .failure(.gitConfigurationOverride(argument))
            }
            if takesValue.contains(argument) {
                index += 2
            } else if takesValue.contains(longName(argument)) || flags.contains(argument) {
                index += 1
            } else {
                // `-p` pages through a configurable program; `--help`, `--version`
                // and `--list-cmds` run no subcommand.
                return .failure(.gitGlobalOption(argument))
            }
        }
        return .success(min(index, arguments.count))
    }

    /// `git [global options] <subcommand> …`.
    private static func gitRejection(_ arguments: [String]) -> Rejection? {
        let index: Int
        switch gitGlobalOptions(arguments) {
        case let .failure(rejection): return rejection
        case let .success(subcommandIndex): index = subcommandIndex
        }
        guard index < arguments.count else { return .gitSubcommand("") }
        let subcommand = arguments[index]
        guard readOnlyGitSubcommands.contains(subcommand) else { return .gitSubcommand(subcommand) }
        // Options that start another program, from git help for each allowed
        // subcommand. The revision and diff options (log, show, diff, reflog,
        // shortlog) match exactly; grep, cat-file and branch use parse-options,
        // which also takes an unambiguous prefix and bundled short flags.
        let command = "git \(subcommand)"
        let rest = arguments[(index + 1)...]
        // --ext-diff (external diff driver), --textconv (textconv filters) and
        // --show-signature (gpg.program) ask for a configured program.
        let requestsProgram: (String) -> Bool
        switch subcommand {
        case "grep":
            // -O[<pager>] / --open-files-in-pager[=<pager>] opens the matches in
            // a program named on the command line.
            requestsProgram = {
                abbreviates($0, "--open-files-in-pager") || abbreviates($0, "--textconv")
                    || (isShortCluster($0) && $0.contains("O"))
            }
        case "cat-file":
            // --filters runs the configured smudge filters.
            requestsProgram = { abbreviates($0, "--textconv") || abbreviates($0, "--filters") }
        case "branch":
            // --edit-description starts the configured editor.
            requestsProgram = { abbreviates($0, "--edit-description") }
        default:
            // A pretty format's %G… placeholders and for-each-ref's %(signature)
            // atom verify signatures with gpg.program.
            requestsProgram = {
                ["--ext-diff", "--textconv", "--show-signature"].contains(longName($0))
                    || $0.contains("%G") || $0.contains("%(signature")
            }
        }
        return rest.first(where: requestsProgram).map { .runsProgram(command: command, option: $0) }
    }

    /// bd's global options, as cobra's `stripFlags` (cobra 1.10, which bd 1.3.1
    /// uses) skips them to find the subcommand: an option that takes a value
    /// consumes the next argument unless it has `=value`, a boolean consumes
    /// nothing, and the first other argument is the subcommand. The index of
    /// the subcommand (the argument count when there is none), or why an option
    /// is refused. Only bd's own options pass: cobra would take an unknown
    /// `--name` as consuming the next argument, and `--` hides the subcommand.
    static func bdGlobalOptions(_ arguments: [String]) -> Result<Int, Rejection> {
        let takesValue: Set<String> = ["--actor", "--db", "--database", "-C", "--directory", "--dolt-auto-commit"]
        let flags: Set<String> = [
            "--json", "-q", "--quiet", "-v", "--verbose", "--no-color", "--readonly", "--sandbox", "--global",
            "--ignore-schema-skew",
        ]
        var index = 0
        while index < arguments.count {
            let argument = arguments[index]
            guard argument.hasPrefix("-") else { break }
            if takesValue.contains(argument) {
                index += 2
            } else if flags.contains(argument)
                        || (argument.hasPrefix("--") && argument.contains("=")
                            && takesValue.contains(longName(argument))) {
                index += 1
            } else {
                return .failure(.bdGlobalOption(argument))
            }
        }
        return .success(min(index, arguments.count))
    }

    /// `bd [global options] <subcommand> …`. bd starts other programs only as it
    /// is configured to (its `.beads/hooks`, a credential command, a pager, the
    /// `gh` a gate issue's close checks), which a secret-free program may do
    /// (see `docs/threat-model.md`).
    private static func bdRejection(_ arguments: [String], referenceVariables: Set<String>) -> Rejection? {
        if let name = referenceVariables.sorted().first(where: { name in
            bdCredentialPrefixes.contains { name.hasPrefix($0) }
        }) {
            return .readsCredential(command: "bd", variable: name)
        }
        let index: Int
        switch bdGlobalOptions(arguments) {
        case let .failure(rejection): return rejection
        case let .success(subcommandIndex): index = subcommandIndex
        }
        guard index < arguments.count else { return .bdSubcommand("") }
        let subcommand = arguments[index]
        return bdSubcommands.contains(subcommand) ? nil : .bdSubcommand(subcommand)
    }

    /// `--name` of `--name=value`, else the argument itself.
    private static func longName(_ argument: String) -> String {
        guard argument.hasPrefix("--"), let equals = argument.firstIndex(of: "=") else { return argument }
        return String(argument[..<equals])
    }

    /// `-abc`: one or more bundled short flags.
    private static func isShortCluster(_ argument: String) -> Bool {
        argument.count > 1 && argument.hasPrefix("-") && !argument.hasPrefix("--")
    }

    /// Whether `argument` names `option` or a prefix of it that getopt_long or
    /// git's parse-options would expand to it.
    private static func abbreviates(_ argument: String, _ option: String) -> Bool {
        let name = longName(argument)
        return name.count > 2 && name.hasPrefix("--") && option.hasPrefix(name)
    }

    /// jq's `env` builtin and `$ENV` read the process environment, which is where
    /// the references live.
    private static func readsEnvironment(_ filter: String) -> Bool {
        if filter.contains("$ENV") { return true }
        let scalars = Array(filter.unicodeScalars)
        let target = Array("env".unicodeScalars)
        func isIdentifier(_ scalar: Unicode.Scalar) -> Bool {
            scalar == "_" || ("a"..."z").contains(scalar) || ("A"..."Z").contains(scalar)
                || ("0"..."9").contains(scalar)
        }
        var index = 0
        while index + target.count <= scalars.count {
            if Array(scalars[index..<(index + target.count)]) == target {
                let before = index > 0 ? scalars[index - 1] : nil
                let after = index + target.count < scalars.count ? scalars[index + target.count] : nil
                // `.env` is a field, `$env` a variable, `environment` another name.
                let standsAlone = !(before.map { isIdentifier($0) || $0 == "." || $0 == "$" } ?? false)
                    && !(after.map(isIdentifier) ?? false)
                if standsAlone { return true }
            }
            index += 1
        }
        return false
    }
}

// MARK: - Literal words

/// Words whose value zsh and bash agree on without expanding anything: the
/// shared reading of the secret-free classifier (`AICommandSecretFree`) and
/// the git passthrough rule (`AICommandGitPassthrough`).
enum ShellLiteralWords {
    /// Characters a plain literal word may not contain: every quoting, escape,
    /// expansion, glob, brace, comment and operator character of either shell.
    static let wordSpecials: Set<Unicode.Scalar> = [
        "{", "}", "*", "?", "[", "]", "\\", "~", "^", "#", "$", "`", "(", ")", "!", "<", ">", "|", "&",
        ";", "'", "\"",
    ]

    /// The text of an unquoted word that the shell passes unchanged, or nil.
    static func plainLiteral(_ node: BashNode, in tree: BashTree) -> String? {
        guard node.kind == "word" || node.kind == "number", node.namedChildCount == 0,
              let text = tree.text(node), let first = text.unicodeScalars.first,
              first != "=", !text.unicodeScalars.contains(where: wordSpecials.contains) else {
            return nil
        }
        return text
    }

    /// The exact value zsh and bash both give an argument built only from plain
    /// unquoted text, single-quoted text, and double-quoted text with no `$`,
    /// backquote, backslash or `!`; nil for anything else (an expansion, escape,
    /// brace, glob, ANSI-C string).
    static func decodedArgument(_ node: BashNode, in tree: BashTree) -> String? {
        let parts = node.kind == "concatenation" ? node.children : [node]
        var value = ""
        var previousWasSingleQuoted = false
        for (index, part) in parts.enumerated() {
            switch part.kind {
            case "word", "number":
                guard part.namedChildCount == 0, let text = tree.text(part),
                      isUnquotedLiteral(text, atWordStart: index == 0),
                      !(index == 0 && text == "~" && parts.count > 1) else { return nil }
                value += text
                previousWasSingleQuoted = false
            case "raw_string":
                // Two adjacent single-quoted parts are one string with a quote
                // in it under zsh's RC_QUOTES.
                guard !previousWasSingleQuoted, let text = tree.text(part),
                      let content = CodexShellSyntax.stripDelimiters(text, UInt8(ascii: "'")) else { return nil }
                value += String(decoding: content, as: UTF8.self)
                previousWasSingleQuoted = true
            case "string":
                guard part.children.allSatisfy({ $0.kind == "\"" || $0.kind == "string_content" }),
                      let text = tree.text(part),
                      let content = CodexShellSyntax.stripDelimiters(text, UInt8(ascii: "\"")),
                      !content.contains(where: { [UInt8(ascii: "$"), UInt8(ascii: "`"), UInt8(ascii: "\\"),
                                                  UInt8(ascii: "!")].contains($0) }) else { return nil }
                value += String(decoding: content, as: UTF8.self)
                previousWasSingleQuoted = false
            default:
                return nil
            }
        }
        return value
    }

    /// Whether unquoted `text` passes through zsh unchanged: no quoting, escape,
    /// expansion, glob, brace, comment or operator character, no leading `=`
    /// (zsh's `=cmd`), and no `~` zsh would expand (at the word start other than
    /// `~`/`~/…`, or after `=` or `:`). A `~` inside a word (`HEAD~1`) is not
    /// one: zsh's filename generation only starts on `*`, `(`, `|`, `<`, `[`,
    /// `?`, or `^`/`#` under EXTENDED_GLOB, so `x~y` stays literal even with
    /// EXTENDED_GLOB set (the zsh differential in cs-selftest checks this).
    static func isUnquotedLiteral(_ text: String, atWordStart: Bool) -> Bool {
        let scalars = Array(text.unicodeScalars)
        guard let first = scalars.first, !(atWordStart && first == "=") else { return false }
        for (index, scalar) in scalars.enumerated() {
            if scalar == "~" {
                if index == 0 && atWordStart {
                    guard index + 1 == scalars.count || scalars[index + 1] == "/" else { return false }
                } else if index > 0, scalars[index - 1] == "=" || scalars[index - 1] == ":" {
                    return false
                }
            } else if wordSpecials.contains(scalar) {
                return false
            }
        }
        return true
    }
}

// MARK: - The tree walk

/// One classification. Every method throws the first `Rejection` it finds.
private struct Classifier {
    typealias Rejection = AICommandSecretFree.Rejection

    /// Far beyond any real command; it bounds recursion on a hostile program.
    static let maximumDepth = 128

    /// Operators of `${name…}` that only read `name` and transform its value.
    /// Absent on purpose: `!` (indirection), `:` (an offset, evaluated as
    /// arithmetic, which reads variables by bare name), `=` and `:=` (assign),
    /// `@` (transformations, including prompt re-expansion).
    static let expansionOperators: Set<String> = [
        ":-", "-", ":+", "+", ":?", "?", "#", "##", "%", "%%", "/", "//", "/#", "/%",
        ",", ",,", "^", "^^",
    ]

    /// Redirections that only open, duplicate or close a descriptor. `<<<` is
    /// the here-string.
    static let redirectOperators: Set<String> = [
        "<", ">", ">>", "&>", "&>>", "<&", ">&", ">|", "<&-", ">&-", "<<<",
    ]

    /// Operators inside `[ … ]`. `<` and `>` are left out: the grammar reads them
    /// as comparisons, but the shell treats them as redirections there. So are
    /// `(` and `)`: bash rejects them unescaped, and zsh reads a word such as
    /// `=(…)` as process substitution.
    static let testTokens: Set<String> = ["!", "=", "==", "!=", "-a", "-o"]

    /// Bytes after which a `#` starts a comment for both lexers.
    static let blanks: Set<UInt8> = [0x20, 0x09, 0x0A]

    let tree: BashTree
    let referenceVariables: Set<String>
    let localCommands: AICommandSecretFree.LocalCommands

    func program(_ root: BashNode) throws {
        guard root.kind == "program" else { throw Rejection.unsupportedSyntax(root.kind) }
        try statements(in: root, tokens: [";"], depth: 0)
    }

    /// The named children of `node` are statements; its anonymous children must
    /// be one of `tokens`. A bare newline separates statements without a token.
    private func statements(in node: BashNode, tokens: Set<String>, depth: Int) throws {
        for child in node.children {
            if child.isNamed {
                try statement(child, depth: depth + 1)
            } else if !tokens.contains(child.kind) {
                // `&` (background), `;;`, `|&` outside a pipeline, keywords.
                throw Rejection.unsupportedSyntax(child.kind)
            }
        }
    }

    private func statement(_ node: BashNode, depth: Int) throws {
        guard depth < Self.maximumDepth else { throw Rejection.nestingTooDeep }
        switch node.kind {
        case "command":
            try command(node, depth: depth)
        case "comment":
            try comment(node)
        case "list":
            try statements(in: node, tokens: ["&&", "||"], depth: depth)
        case "pipeline":
            try statements(in: node, tokens: ["|", "|&"], depth: depth)
        case "subshell":
            try statements(in: node, tokens: ["(", ")", ";"], depth: depth)
        case "compound_statement":
            // `{ …; }` groups statements; `(( … ))` is an arithmetic command,
            // which reads variables by bare name.
            guard node.children.first?.kind == "{" else {
                throw Rejection.unsupportedSyntax(node.children.first?.kind ?? node.kind)
            }
            try statements(in: node, tokens: ["{", "}", ";"], depth: depth)
        case "negated_command":
            try statements(in: node, tokens: ["!"], depth: depth)
        case "if_statement":
            try statements(in: node, tokens: ["if", "then", "fi", ";"], depth: depth)
        case "elif_clause":
            try statements(in: node, tokens: ["elif", "then", ";"], depth: depth)
        case "else_clause":
            try statements(in: node, tokens: ["else", ";"], depth: depth)
        case "while_statement":
            try statements(in: node, tokens: ["while", "until", ";"], depth: depth)
        case "do_group":
            try statements(in: node, tokens: ["do", "done", ";"], depth: depth)
        case "redirected_statement":
            var hasBody = false
            for child in node.children {
                switch child.kind {
                case "file_redirect", "herestring_redirect", "heredoc_redirect":
                    try redirect(child, depth: depth + 1)
                case "comment":
                    try comment(child)
                default:
                    guard child.isNamed else { throw Rejection.unsupportedSyntax(child.kind) }
                    try statement(child, depth: depth + 1)
                    hasBody = true
                }
            }
            // A redirection alone runs zsh's `$NULLCMD` or `$READNULLCMD`.
            guard hasBody else { throw Rejection.unsupportedSyntax("redirection without a command") }
        case "test_command":
            try testCommand(node, depth: depth)
        case "variable_assignment", "variable_assignments", "declaration_command", "unset_command":
            throw Rejection.variableAssignment
        default:
            // Functions, `case`, `for` (which assigns its loop variable),
            // `select`, C-style loops, and anything unknown.
            throw Rejection.unsupportedSyntax(node.kind)
        }
    }

    /// Both lexers start a comment at a `#` that begins a word. zsh reads a `#`
    /// right after anything but a blank (`]#`, `}#`) as part of that word, so a
    /// comment the grammar starts there hides text zsh runs.
    private func comment(_ node: BashNode) throws {
        let start = Int(node.startByte)
        guard start == 0 || (start <= tree.source.count && Self.blanks.contains(tree.source[start - 1])) else {
            throw Rejection.unsupportedSyntax("# after a non-blank")
        }
    }

    // MARK: Commands

    private func command(_ node: BashNode, depth: Int) throws {
        var name: String?
        var words: [BashNode] = []
        var arguments: [BashNode] = []
        for child in node.children {
            switch child.kind {
            case "command_name":
                guard child.namedChildCount == 1, let word = child.namedChild(0),
                      let literal = plainLiteral(word) else {
                    throw Rejection.nonLiteralCommandName
                }
                name = literal
                words.append(child)
            case "variable_assignment", "variable_assignments":
                throw Rejection.variableAssignment
            case "file_redirect", "herestring_redirect":
                try redirect(child, depth: depth + 1)
            case "$":
                // A lone `$` expands nothing. `$"…"` is quoting the grammar reads
                // as two words; the adjacency check below refuses it.
                words.append(child)
                arguments.append(child)
            default:
                guard child.isNamed else { throw Rejection.unsupportedSyntax(child.kind) }
                try word(child, depth: depth + 1)
                words.append(child)
                arguments.append(child)
            }
        }
        // Two words the grammar split with nothing between them are one word to
        // zsh.
        for (previous, next) in zip(words, words.dropFirst()) where previous.endByte >= next.startByte {
            throw Rejection.unsupportedSyntax("adjacent words")
        }
        guard let name else { throw Rejection.nonLiteralCommandName }
        var argv = [name]
        let program = name.split(separator: "/").last.map(String.init)
        if let program, AICommandSecretFree.inspectedCommands.contains(program) {
            for argument in arguments {
                guard let value = decodedArgument(argument) else {
                    throw Rejection.nonLiteralArgument(command: program)
                }
                argv.append(value)
            }
        } else if let program, program == "bd" || localCommands.commands[program] != nil {
            // Only the words up to the subcommand decide what bd or a local
            // command runs, so only they must be literal. After them come the
            // operands and option values of a subcommand that starts nothing they
            // name, so a note may carry a quoted `$(date …)`.
            var literalPrefixEnded = false
            for argument in arguments {
                guard let value = decodedArgument(argument) else {
                    literalPrefixEnded = true
                    break
                }
                argv.append(value)
            }
            let rejection = AICommandSecretFree.invocationRejection(
                argv, referenceVariables: referenceVariables, localCommands: localCommands)
            if literalPrefixEnded, program == "bd", rejection == .bdSubcommand("") {
                throw Rejection.nonLiteralArgument(command: "bd")
            }
            if literalPrefixEnded, let local = localCommands.commands[program],
               case .localSubcommand = rejection,
               argv.count - 1 < local.decidingWords(Array(argv.dropFirst())) {
                throw Rejection.nonLiteralArgument(command: program)
            }
            if let rejection { throw rejection }
            return
        }
        if let rejection = AICommandSecretFree.invocationRejection(
            argv, referenceVariables: referenceVariables, localCommands: localCommands) {
            throw rejection
        }
    }

    private func plainLiteral(_ node: BashNode) -> String? {
        ShellLiteralWords.plainLiteral(node, in: tree)
    }

    private func decodedArgument(_ node: BashNode) -> String? {
        ShellLiteralWords.decodedArgument(node, in: tree)
    }

    // MARK: Redirections

    private func redirect(_ node: BashNode, depth: Int) throws {
        guard depth < Self.maximumDepth else { throw Rejection.nestingTooDeep }
        switch node.kind {
        case "file_redirect", "herestring_redirect":
            var targets = 0
            for child in node.children {
                if child.kind == "file_descriptor" { continue }
                if child.isNamed {
                    targets += 1
                    try word(child, depth: depth + 1)
                } else if !Self.redirectOperators.contains(child.kind) {
                    throw Rejection.unsupportedSyntax(child.kind)
                }
            }
            // The grammar hangs words that follow a redirection's target on the
            // redirection, where the shell passes them to the command (`find . >
            // out -exec …`). Those would escape the command's argument checks.
            guard targets <= 1 else { throw Rejection.unsupportedSyntax("words after a redirection") }
        case "heredoc_redirect":
            try heredoc(node, depth: depth)
        default:
            throw Rejection.unsupportedSyntax(node.kind)
        }
    }

    private func heredoc(_ node: BashNode, depth: Int) throws {
        var quotedDelimiter = false
        for child in node.children {
            switch child.kind {
            case "<<", "<<-", "file_descriptor", "heredoc_end":
                continue
            case "heredoc_start":
                guard let delimiter = tree.text(child) else { throw Rejection.unparsable }
                quotedDelimiter = delimiter.unicodeScalars.contains { $0 == "'" || $0 == "\"" || $0 == "\\" }
            case "heredoc_body":
                // A quoted delimiter makes the body literal. The shell expands an
                // unquoted body, and the grammar does not parse every expansion
                // in one (a backquote stays content), so accept only a body with
                // nothing to expand.
                guard let body = tree.text(child) else { throw Rejection.unparsable }
                guard quotedDelimiter || !body.unicodeScalars.contains(where: { $0 == "$" || $0 == "`" }) else {
                    throw Rejection.unsupportedSyntax("expanding heredoc")
                }
            case "file_redirect", "herestring_redirect":
                try redirect(child, depth: depth + 1)
            case "pipeline", "list", "command", "redirected_statement", "subshell", "compound_statement",
                 "negated_command", "test_command":
                // The rest of the line after `<<EOF` (`| rg x`, `&& ls`).
                try statement(child, depth: depth + 1)
            case "&&", "||":
                continue
            default:
                // Words after the delimiter are the command's arguments, out of
                // reach of its checks.
                throw Rejection.unsupportedSyntax(child.isNamed ? "heredoc argument" : child.kind)
            }
        }
    }

    // MARK: `[ … ]`

    /// `[` is an ordinary command to zsh, so every operator and operand must be
    /// its own word, separated by blanks, and `]` must end its word.
    private func testCommand(_ node: BashNode, depth: Int) throws {
        // `[[ … ]]` evaluates arithmetic and patterns and is not on the list.
        guard node.children.first?.kind == "[" else {
            throw Rejection.unlistedCommand(node.children.first?.kind ?? node.kind)
        }
        var units: [BashNode] = []
        for child in node.children {
            if child.isNamed {
                try testOperand(child, depth: depth + 1, units: &units)
            } else if child.kind == "[" || child.kind == "]" {
                units.append(child)
            } else {
                throw Rejection.unsupportedSyntax(child.kind)
            }
        }
        units.sort { $0.startByte < $1.startByte }
        for (previous, next) in zip(units, units.dropFirst()) {
            let gap = tree.source[Int(previous.endByte)..<Int(max(previous.endByte, next.startByte))]
            guard !gap.isEmpty, gap.allSatisfy({ $0 == 0x20 || $0 == 0x09 }) else {
                throw Rejection.unsupportedSyntax("[ ] words not separated by blanks")
            }
        }
        let end = Int(node.endByte)
        if end < tree.source.count {
            let boundaries: Set<UInt8> = [0x20, 0x09, 0x0A, UInt8(ascii: ";"), UInt8(ascii: "&"),
                                          UInt8(ascii: "|"), UInt8(ascii: ")")]
            guard boundaries.contains(tree.source[end]) else {
                throw Rejection.unsupportedSyntax("] not ending its word")
            }
        }
    }

    private func testOperand(_ node: BashNode, depth: Int, units: inout [BashNode]) throws {
        guard depth < Self.maximumDepth else { throw Rejection.nestingTooDeep }
        switch node.kind {
        case "unary_expression", "binary_expression":
            for child in node.children {
                if child.kind == "test_operator" {
                    units.append(child)
                } else if child.isNamed {
                    try testOperand(child, depth: depth + 1, units: &units)
                } else if Self.testTokens.contains(child.kind) {
                    units.append(child)
                } else {
                    throw Rejection.unsupportedSyntax(child.kind)
                }
            }
        default:
            // A `parenthesized_expression` lands here and is refused.
            try word(node, depth: depth)
            units.append(node)
        }
    }

    // MARK: Words

    /// `quoted` is true inside double quotes. An expansion outside them is
    /// refused (after its contents are checked, so a reference or an unlisted
    /// command is still named): a user's startup files may set GLOB_SUBST, which
    /// makes the value a pattern, glob qualifiers included (`cat ${_}` after
    /// `echo '*(+cmd)'` runs cmd), and SH_WORD_SPLIT, which splits it.
    private func word(_ node: BashNode, depth: Int, quoted: Bool = false) throws {
        guard depth < Self.maximumDepth else { throw Rejection.nestingTooDeep }
        switch node.kind {
        case "word", "number", "regex":
            // A number carrying an expansion (`0x$n`) is not worth accepting.
            guard node.namedChildCount == 0 else { throw Rejection.unsupportedSyntax(node.kind) }
            try unquotedText(node)
        case "raw_string":
            return
        case "string_content":
            try quotedText(node)
        case "string":
            try sequence(node, depth: depth, quoted: true)
        case "concatenation":
            try sequence(node, depth: depth, quoted: quoted)
        case "simple_expansion":
            var exitStatus = false
            for child in node.children {
                switch child.kind {
                case "$":
                    continue
                case "special_variable_name":
                    // zsh reads `$#NAME` as the length of NAME.
                    if tree.text(child) == "#" { throw Rejection.unsupportedSyntax("$#") }
                    exitStatus = tree.text(child) == "?"
                case "variable_name":
                    try variable(child)
                default:
                    throw Rejection.unsupportedSyntax(child.kind)
                }
            }
            // `$?` (`echo exit=$?`) is the last exit status, always decimal
            // digits, which no option makes a pattern; at worst an IFS holding
            // digits splits it.
            guard quoted || exitStatus else { throw Rejection.unsupportedSyntax("unquoted expansion") }
        case "expansion":
            try expansion(node, depth: depth, quoted: quoted)
            guard quoted else { throw Rejection.unsupportedSyntax("unquoted expansion") }
        case "command_substitution":
            // `$(…)` and backquotes; `$(<file)` reads a file with no command.
            for child in node.children {
                switch child.kind {
                case "$(", "`", ")", ";": continue
                case "file_redirect": try redirect(child, depth: depth + 1)
                default:
                    guard child.isNamed else { throw Rejection.unsupportedSyntax(child.kind) }
                    try statement(child, depth: depth + 1)
                }
            }
            guard quoted else { throw Rejection.unsupportedSyntax("unquoted expansion") }
        case "process_substitution":
            try statements(in: node, tokens: ["<(", ">(", ")", ";"], depth: depth)
        case "brace_expression":
            for child in node.children where child.isNamed {
                try word(child, depth: depth + 1)
            }
        default:
            // ANSI-C `$'…'` (the grammar's regex does not honour `\\`), `$"…"`,
            // `arithmetic_expansion` (reads variables by bare name), arrays,
            // subscripts, extglob patterns, and anything unknown.
            throw Rejection.unsupportedSyntax(node.kind)
        }
    }

    /// A double-quoted string or a concatenation: its parts in order.
    private func sequence(_ node: BashNode, depth: Int, quoted: Bool) throws {
        let children = node.children
        // zsh expands `~` after brace and parameter expansion and quote
        // removal, so a bare `~` joined to anything (`~{NAME,}`, `~$X`, `~""NAME`)
        // is `~NAME`.
        if node.kind == "concatenation", children.count > 1, let first = children.first,
           first.kind == "word", tree.text(first) == "~" {
            throw Rejection.unsupportedSyntax("~ expansion")
        }
        for (index, child) in children.enumerated() {
            let next = index + 1 < children.count ? children[index + 1] : nil
            if child.isNamed {
                try word(child, depth: depth + 1, quoted: quoted)
            } else if child.kind == "$" {
                // A `$` that ends a word (`x$`) or comes before the closing
                // quote expands nothing; followed by a quote it is `$'…'`/`$"…"`.
                let endsWord = node.kind == "concatenation" && next == nil
                let beforeClosingQuote = node.kind == "string" && next?.kind == "\""
                guard endsWord || beforeClosingQuote else {
                    throw Rejection.unsupportedSyntax("$ quoting")
                }
            } else if child.kind != "\"" {
                throw Rejection.unsupportedSyntax(child.kind)
            }
            guard let next else { continue }
            // zsh subscripts `$name[…]` and `${name}[…]`, evaluating the
            // subscript as arithmetic, which reads variables by bare name.
            if child.kind == "simple_expansion" || child.kind == "expansion",
               let text = tree.text(next), text.hasPrefix("[") {
                throw Rejection.unsupportedSyntax("subscript")
            }
            // `x$` then a quote is `$'…'` or `$"…"` to zsh.
            if child.kind == "word", let text = tree.text(child), text.hasSuffix("$") {
                throw Rejection.unsupportedSyntax("$ quoting")
            }
        }
    }

    /// `${…}`: one variable, then only operators that transform its value.
    private func expansion(_ node: BashNode, depth: Int, quoted: Bool) throws {
        var sawName = false
        for child in node.children {
            switch child.kind {
            case "${", "}":
                continue
            case "#" where !sawName:
                // `${#name}`: the length.
                continue
            case "variable_name" where !sawName:
                try variable(child)
                sawName = true
            case "special_variable_name" where !sawName:
                sawName = true
            default:
                if !child.isNamed {
                    guard sawName, Self.expansionOperators.contains(child.kind) else {
                        throw child.kind == "!"
                            ? Rejection.indirectExpansion
                            : Rejection.unsupportedSyntax("${ \(child.kind) }")
                    }
                } else {
                    guard sawName else { throw Rejection.unsupportedSyntax(child.kind) }
                    try word(child, depth: depth + 1, quoted: quoted)
                }
            }
        }
        guard sawName else { throw Rejection.unsupportedSyntax("expansion") }
    }

    private func variable(_ node: BashNode) throws {
        guard let name = tree.text(node) else { throw Rejection.unparsable }
        if referenceVariables.contains(name) { throw Rejection.expandsReference(name) }
    }

    /// An unquoted word the grammar left as text must not hide a construct zsh
    /// reads in it: a command substitution or expansion (a backquote stays a
    /// word inside `${x:-…}`), a glob qualifier or `<(…)` (parentheses), a `#`,
    /// or a `~` expansion other than `~` and `~/…`. zsh expands `~NAME` (reading
    /// NAME) at a word start, and after `=` or `:` under MAGIC_EQUAL_SUBST; a
    /// `~` elsewhere (`HEAD~1`) is literal (see `isUnquotedLiteral`).
    private func unquotedText(_ node: BashNode) throws {
        guard let text = tree.text(node) else { throw Rejection.unparsable }
        let scalars = Array(text.unicodeScalars)
        var index = 0
        while index < scalars.count {
            switch scalars[index] {
            case "\\":
                index += 1
            case "`":
                throw Rejection.unsupportedSyntax("unparsed command substitution")
            case "$":
                if index + 1 < scalars.count { throw Rejection.unsupportedSyntax("unparsed expansion") }
            case "(", ")":
                throw Rejection.unsupportedSyntax("parenthesis in a word")
            case "#":
                throw Rejection.unsupportedSyntax("# in a word")
            case "~":
                if index == 0 {
                    guard index + 1 == scalars.count || scalars[index + 1] == "/" else {
                        throw Rejection.unsupportedSyntax("~ expansion")
                    }
                } else if scalars[index - 1] == "=" || scalars[index - 1] == ":" {
                    throw Rejection.unsupportedSyntax("~ expansion")
                }
            default:
                break
            }
            index += 1
        }
    }

    /// Double-quoted text: only `$` and backquotes expand there. A `$` before a
    /// blank expands nothing; a backslash escapes the next character.
    private func quotedText(_ node: BashNode) throws {
        guard let text = tree.text(node) else { throw Rejection.unparsable }
        let scalars = Array(text.unicodeScalars)
        var index = 0
        while index < scalars.count {
            switch scalars[index] {
            case "\\":
                index += 1
            case "`":
                throw Rejection.unsupportedSyntax("unparsed command substitution")
            case "$":
                if index + 1 < scalars.count, scalars[index + 1] != " ", scalars[index + 1] != "\t" {
                    throw Rejection.unsupportedSyntax("unparsed expansion")
                }
            default:
                break
            }
            index += 1
        }
    }
}
