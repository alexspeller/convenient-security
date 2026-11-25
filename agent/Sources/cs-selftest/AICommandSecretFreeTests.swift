import Foundation
import ConvenientSecurity

/// `csec ai`'s secret-free classification (`AICommandSecretFree`) and the
/// bridge's optional TTL. Every reference below is synthetic; nothing resolves.
func aiCommandSecretFreeTests() {
    print("\n# AICommandSecretFree (secret-free csec ai programs)")

    // A direnv-shaped environment with references from two schemes, one of them
    // through a `csec_` alias.
    let environment = [
        "DATABASE_URL": "op://synthetic-vault/db/url",
        "csec_API_TOKEN": "csec://synthetic-store/API_TOKEN",
        "HOME": "/Users/synthetic",
        "PATH": "/usr/bin:/bin",
        "PLAIN_SETTING": "not-a-reference",
    ]
    let plan: ExecPlanner.Plan
    do {
        plan = try ExecPlanner.plan(environment: environment, explicit: [], knownSchemes: ["op", "csec"])
    } catch {
        check(false, "the synthetic secret-free environment plans (\(error))")
        return
    }
    let references = AICommandSecretFree.referenceVariables(of: plan)
    check(references == ["DATABASE_URL", "API_TOKEN", "csec_API_TOKEN"],
          "reference variables are every injected name plus every csec_ alias, across schemes")
    check(AICommandSecretFree.environmentWithoutReferences(environment, plan: plan)
            == ["HOME": "/Users/synthetic", "PATH": "/usr/bin:/bin", "PLAIN_SETTING": "not-a-reference"],
          "a secret-free child sees neither a reference nor its alias, and keeps everything else")

    // A synthetic local list (`AICommandSecretFree.LocalCommands`): `tasks`
    // stands for a session tool this Mac's administrator vouches for, which
    // also runs bd.
    let localCommands = AICommandSecretFree.LocalCommands(commands: [
        "tasks": .init(subcommands: ["show", "note", "park", "page", "where", "search"],
                       subcommandsWithSecondWord: ["plugins": ["list", "search", "read"]],
                       credentialVariablePrefixes: ["TASKS_", "BD_", "BEADS_", "DOLT_"]),
    ])

    // Every program classified below also runs under the real zsh at the end.
    var corpus: [String] = []
    func verdict(_ program: String) -> AICommandSecretFree.Verdict {
        corpus.append(program)
        return AICommandSecretFree.classify(program, referenceVariables: references, localCommands: localCommands)
    }
    func secretFree(_ program: String, _ label: String) {
        let result = verdict(program)
        check(result == .secretFree, "secret-free: \(label) (\(result))")
    }
    func rejected(_ program: String, _ rejection: AICommandSecretFree.Rejection, _ label: String) {
        let result = verdict(program)
        check(result == .needsSecrets(rejection), "needs secrets, \(rejection): \(label) (\(result))")
    }
    func needsSecrets(_ program: String, _ label: String) {
        let result = verdict(program)
        check(!result.isSecretFree, "needs secrets: \(label) (\(result))")
    }

    // The plan's list, verbatim.
    let planList = """
        ls cat head tail wc sort uniq cut tr paste comm nl fold column rev grep egrep fgrep rg find fd sed jq diff \
        cmp file stat du df tree realpath readlink basename dirname pwd cd echo printf true false test [ which \
        type sleep date whoami id uname sw_vers hostname mkdir touch cp mv rm rmdir ln chmod xxd od hexdump \
        strings shasum md5 cksum plutil otool nm lipo dwarfdump ps pgrep lsof
        """.split(separator: " ").map(String.init)
    check(planList.count == 74 && Set(planList) == AICommandSecretFree.listedCommands
            && AICommandSecretFree.listedCommands.isDisjoint(with: AICommandSecretFree.bannedCommands),
          "the listed tools are exactly the plan's 74, none of them banned; git has its own rules")
    check(AICommandSecretFree.bannedCommands == [
        "eval", "source", ".", "exec", "env", "xargs", "command", "builtin", "sudo", "nohup", "time", "timeout",
    ] && AICommandSecretFree.readOnlyGitSubcommands == [
        "status", "log", "diff", "show", "branch", "rev-parse", "ls-files", "blame", "grep", "merge-base",
        "cat-file", "describe", "reflog", "shortlog", "for-each-ref", "check-ignore", "name-rev",
    ], "the banned commands and read-only git subcommands are the plan's")

    // MARK: Positive cases

    for command in AICommandSecretFree.listedCommands.sorted() where command != "[" {
        secretFree("\(command) synthetic-argument", "listed command \(command)")
    }
    secretFree("[ -f synthetic-file ]", "listed command [ (the test builtin)")
    for subcommand in AICommandSecretFree.readOnlyGitSubcommands.sorted() {
        secretFree("git \(subcommand)", "git \(subcommand)")
    }
    for (program, label) in [
        ("", "an empty program"),
        ("   \n", "a blank program"),
        ("# only a comment", "a comment-only program"),
        ("ls -la\npwd # where am I", "newline-separated commands with a trailing comment"),
        ("rg -n FIXME src | head -20", "a pipeline"),
        ("ls |& cat", "a pipeline that includes stderr"),
        ("cd sub && ls -la || pwd; echo done", "a list"),
        ("(cd sub; ls)", "a subshell"),
        ("{ ls; pwd; } 2>&1 | head", "a redirected group"),
        ("! test -e synthetic-file", "a negated command"),
        ("echo \"$(pwd)\" \"$(ls | wc -l)\"", "quoted $(…) of listed commands"),
        ("echo \"`pwd`\" \"in `basename x`\"", "quoted backquotes of listed commands"),
        ("diff <(sort a) <(sort b)", "process substitution of listed commands"),
        ("cat < <(ls)", "a process substitution as a redirection target"),
        ("echo \"$(<synthetic-file)\"", "$(<file), which reads a file with no command"),
        ("ls 2>/dev/null >| out &> both < in 1>&2 2>&-", "file redirections"),
        ("cat <<< hello", "a here-string"),
        ("cat > out.txt <<'EOF'\nbody $DATABASE_URL `ls`\nEOF", "a quoted heredoc stays literal"),
        ("cat <<\\EOF\nbody $DATABASE_URL\nEOF", "a backslash-quoted heredoc stays literal"),
        ("cat <<EOF\nplain text\nEOF", "an unquoted heredoc with nothing to expand"),
        ("cat <<'EOF' | rg x && wc -l f\na\nEOF", "a heredoc followed by the rest of the line"),
        ("[ -n \"$HOME\" ] && [ \"$HOME\" != / ] || [ ! -d x -o -f y ]", "[ … ] tests"),
        ("[ -f a.txt ]; [ a = a ] && ls", "[ … ] followed by ; and &&"),
        ("if [ -d x ]; then ls x; elif true; then pwd; else echo none; fi", "if/elif/else"),
        ("while false; do ls; done; until true; do pwd; done", "while and until"),
        ("/bin/cat", "the sudo PAM redactor's program (`tool-exec --destination ai -- /bin/cat`)"),
        ("/bin/cat synthetic-file", "a listed tool named by a system path"),
        ("/opt/homebrew/bin/rg x | /usr/bin/head", "listed tools in Homebrew and /usr/bin"),
        ("echo \"$HOME\" \"${HOME}\" \"${HOME:-/}\" \"${HOME%/}\" \"${#HOME}\" \"$PLAIN_SETTING\"",
         "quoted expansions of variables that hold no reference"),
        ("echo \"$?\" \"$$\" \"$@\" \"$0\" \"$1\"", "quoted special and positional parameters"),
        ("echo $ \"$\" 'a$' grep x$ \"cost: $ 5\"", "a literal $"),
        ("echo \\$DATABASE_URL '$DATABASE_URL' \"\\$DATABASE_URL\"", "an escaped or single-quoted $ is literal"),
        ("echo DATABASE_URL", "a reference variable's name as plain text"),
        ("ls ~ ~/x *.c {a,b} x{1..3} =cat", "globs, braces, ~, ~/ and =cmd"),
        ("grep '#include' src; echo \"a#b\" 'c#d'", "a quoted #"),
        ("echo \"(a)\" '(b)' \"x ~y\" '~z'", "quoted parentheses and ~"),
        ("find . -name x.c -type f -delete | wc -l", "find without -exec (-delete runs nothing)"),
        ("fd -e swift -t f src", "fd without --exec"),
        ("rg --max-count 3 pattern", "rg without --pre or -z"),
        ("sort -u -k2 --check f", "sort without --compress-program"),
        ("jq -r .env f; jq .environment g", "jq reading fields named env"),
        ("printf %s x; printf -- '%s' x", "printf without -v"),
        ("git -C src --no-pager log --oneline -5 -- src/", "git with -C and --no-pager"),
        ("git --git-dir=.git --work-tree . -P diff --stat", "git with --git-dir and --work-tree"),
        ("git log --oneline | head -3", "git log in a pipeline"),
        ("git grep -n --or -e x -- src", "git grep without a pager"),
        ("git branch --list", "git branch without --edit-description"),
        // Quoted literals both shells read alike, decoded for the option checks.
        ("rg \"pattern\" src", "a double-quoted rg pattern"),
        ("rg 'a b' -g '*.swift'", "single-quoted rg pattern and glob"),
        ("rg -n \"func runAI\" src", "a double-quoted pattern with a space"),
        ("find . -name '*.swift' -type f", "a quoted find glob"),
        ("find . -name \"*.swift\" -o -name 'x'\"y\"z", "double quotes and a concatenation"),
        ("jq '.a' file.json", "a quoted jq filter"),
        ("jq -r '.scripts | keys' package.json", "a quoted jq pipeline"),
        ("git diff HEAD~1", "a ~ inside a git revision"),
        ("git show HEAD~2 -- src", "a ~ after the git subcommand"),
        ("git log --oneline -5", "git log"),
        ("git log --format='%H %s' | head -3", "a quoted git format"),
        ("git grep -n 'a b' -- '*.swift'", "quoted git grep pattern and pathspec"),
        ("grep -rn \"foo\" .", "a double-quoted grep pattern"),
        ("printf '%s\\n' x \"y z\"", "a quoted printf format"),
        ("sort -t, -k2 'f g'", "a quoted sort file"),
        ("rg \"\" x", "an empty quoted argument"),
        ("cat a~b", "a ~ inside a word"),
        // A ~ inside a word stays literal even under EXTENDED_GLOB and NULL_GLOB
        // (the hostile differential run below passes these through unchanged).
        ("find . -exec~x npm +", "-exec~x is not -exec"),
        ("git -C d~x status push", "a ~ in a git -C value"),
        ("printf %s a~b", "a ~ in a printf argument"),
    ] {
        secretFree(program, label)
    }
    rejected("rg x --pre=npm~y .", .runsProgram(command: "rg", option: "--pre=npm~y"),
             "an rg --pre value with a ~ is still --pre")
    rejected("git lo~g", .gitSubcommand("lo~g"), "a ~ in the git subcommand")
    // Shapes coding agents actually send.
    for program in [
        "git diff -- agent/Sources/csec/main.swift | head -100",
        "git log --oneline -5 && git status --short",
        "rg -n runAI agent/Sources",
        "sed -n '190,260p' agent/Sources/csec/main.swift",
        "jq .scripts package.json",
        "git ls-files | wc -l",
        "ls -la agent/.build/debug/ 2>&1 | head",
        "ps aux | grep csecd | grep -v grep",
        "lsof -nP -iTCP -sTCP:LISTEN",
        "mkdir -p /tmp/synthetic && cp a.txt /tmp/synthetic/",
        "echo \"$PATH\" | tr ':' '\\n'",
        "cd agent && ls Sources | sort",
    ] {
        secretFree(program, "an agent's read-only command: \(program)")
    }

    // MARK: bd

    for subcommand in AICommandSecretFree.bdSubcommands.sorted() {
        secretFree("bd \(subcommand) synthetic-argument", "bd \(subcommand)")
    }
    for (program, label) in [
        ("bd show csec-0.22", "bd show"),
        ("bd update csec-0.22 --append-notes \"$(date -u +%Y-%m-%dT%H:%M:%SZ) ($BEADS_ACTOR): done\"",
         "a dated note: a quoted $(date …) and a quoted plain variable after the subcommand"),
        ("bd update csec-0.22 --if-assignee queue-runner --assignee \"$BEADS_ACTOR\"; echo exit=$?",
         "the launch prompt's takeover, quoted, then the exit status"),
        ("bd create \"Title\" -t task -p 1 --parent csec-0 --description \"$(cat <<'EOF'\nbody `x` $y\nEOF\n)\"",
         "a description from a quoted heredoc"),
        ("bd --json list --status open | jq -r '.[].id'", "a global flag, then a pipeline"),
        ("bd -C sub --actor synthetic --db x --database y --dolt-auto-commit off -q show x",
         "every global option that takes a value, and a flag"),
        ("bd --actor=synthetic --directory=sub show x", "global options with =value"),
        ("bd --readonly --sandbox --global --ignore-schema-skew --no-color -v --verbose --quiet show x",
         "every boolean global option"),
        ("bd --actor show list", "--actor takes the next word, so the subcommand is list, as cobra reads it"),
        ("bd show x && bd close x --reason \"done\" || echo \"failed $?\"", "a list of bd commands"),
        ("/opt/homebrew/bin/bd show x", "bd named by a system path"),
        ("bd dep add a b; bd label add a x; bd comments add a \"c\"; bd kv set k v",
         "nested subcommands of listed bd subcommands"),
        ("bd show \"$PLAIN_SETTING\" x*", "operands after the subcommand need not be literal"),
    ] {
        secretFree(program, label)
    }
    for subcommand in ["edit", "create-form", "hooks", "mail", "preflight", "orphans", "worktree", "gate", "dolt",
                       "sync", "federation", "vc", "backup", "github", "gitlab", "jira", "linear", "notion", "ado",
                       "init", "setup", "config", "upgrade", "migrate", "find-duplicates", "compact", "serve",
                       "help", "Show", "sh"] {
        rejected("bd \(subcommand) x", .bdSubcommand(subcommand), "bd \(subcommand)")
    }
    for (program, rejection, label) in [
        ("bd", .bdSubcommand(""), "bd with no subcommand"),
        ("bd --json", .bdSubcommand(""), "bd with a global option and no subcommand"),
        ("bd --actor show", .bdSubcommand(""), "--actor taking the only other word"),
        ("bd '' show x", .bdSubcommand(""), "an empty word, which cobra skips"),
        ("bd --actor edit x", .bdSubcommand("x"), "--actor taking edit, so the subcommand is x"),
        ("bd -- show x", .bdGlobalOption("--"), "--, after which cobra finds no subcommand"),
        ("bd --unknown show x", .bdGlobalOption("--unknown"), "an unknown option, which cobra reads as taking a value"),
        ("bd -Cx show", .bdGlobalOption("-Cx"), "a short option with its value attached"),
        ("bd --cpu-profile show", .bdGlobalOption("--cpu-profile"), "an unlisted global option"),
        ("bd --json=true show", .bdGlobalOption("--json=true"), "a boolean with =value"),
        ("bd \"--actor\" \"show\" edit", .bdSubcommand("edit"), "quoted words read as cobra reads them"),
        ("bd \"$SUBCOMMAND\" x", .nonLiteralArgument(command: "bd"), "a non-literal subcommand"),
        ("bd --actor \"$BEADS_ACTOR\" show x", .nonLiteralArgument(command: "bd"),
         "a non-literal global option value"),
        ("bd sh\\ow x", .nonLiteralArgument(command: "bd"), "an escaped subcommand"),
        ("bd {show,edit} x", .nonLiteralArgument(command: "bd"), "a brace-expanded subcommand"),
        ("bd show $DATABASE_URL", .expandsReference("DATABASE_URL"), "a reference variable after the subcommand"),
        ("bd update x --assignee $BEADS_ACTOR", .unsupportedSyntax("unquoted expansion"),
         "an unquoted plain variable (quote it)"),
        ("bd show x | python3", .unlistedCommand("python3"), "an unlisted command after bd"),
        ("/Users/synthetic/.local/bin/bd show x",
         .commandPathOutsideSystemDirectories("/Users/synthetic/.local/bin/bd"), "bd named by a user path"),
    ] as [(String, AICommandSecretFree.Rejection, String)] {
        rejected(program, rejection, label)
    }
    // A reference in a variable bd reads its own credential from keeps bd on the
    // ordinary path, whatever the subcommand; other tools are unaffected.
    for name in ["BEADS_DOLT_PASSWORD", "DOLT_REMOTE_PASSWORD", "BD_LINEAR_API_KEY"] {
        let withCredential = references.union([name, "csec_\(name)"])
        check(AICommandSecretFree.classify("bd show x", referenceVariables: withCredential)
                == .needsSecrets(.readsCredential(command: "bd", variable: name))
              && AICommandSecretFree.classify("ls; echo \"$?\"", referenceVariables: withCredential) == .secretFree,
              "a reference in \(name) keeps bd, and only bd, on the ordinary path")
    }

    // MARK: Local commands

    for subcommand in ["show", "note", "park", "page", "where", "search"] {
        secretFree("tasks \(subcommand) synthetic-argument", "local tasks \(subcommand)")
    }
    for word in ["list", "search", "read"] {
        secretFree("tasks plugins \(word) synthetic-argument", "local tasks plugins \(word)")
    }
    for (program, label) in [
        ("tasks park task-1 --on task-1.1,task-1.2", "a local command parking on its asks"),
        ("tasks page /private/tmp/tasks-page-501-abcd1234:4000", "a local page by cursor"),
        ("cd /tmp && tasks show task-1 2>&1 | head -100", "cd, a local command, then a pipeline"),
        ("tasks note task-1 --next \"$(cat <<'EOF'\nrun `x` $y\nEOF\n)\"", "a local note from a quoted heredoc"),
        ("tasks search --files agent/a.swift DESIGN.md --json | jq -r '.[].id'", "a local search, then jq"),
        ("bd update task-1 --assignee \"$BEADS_ACTOR\"; echo exit=$?; tasks where",
         "bd and a local command in one list"),
        ("tasks note task-1 \"Title\" --description \"$PLAIN_SETTING\"",
         "operands after a local subcommand need not be literal"),
        ("/opt/homebrew/bin/tasks where", "a local command named by a system path"),
    ] {
        secretFree(program, label)
    }
    for subcommand in ["edit", "login", "help", "--help", "-h", "Show", "sho"] {
        rejected("tasks \(subcommand) x", .localSubcommand(command: "tasks", subcommand: subcommand),
                 "local tasks \(subcommand)")
    }
    for (program, rejection, label) in [
        ("tasks", .localSubcommand(command: "tasks", subcommand: ""), "a local command with no subcommand"),
        ("tasks '' show x", .localSubcommand(command: "tasks", subcommand: ""), "an empty local subcommand"),
        ("tasks plugins", .localSubcommand(command: "tasks", subcommand: "plugins"),
         "a second-word subcommand alone"),
        ("tasks plugins install x", .localSubcommand(command: "tasks", subcommand: "plugins install"),
         "an unlisted second word"),
        ("tasks \"$SUBCOMMAND\" x", .nonLiteralArgument(command: "tasks"), "a non-literal local subcommand"),
        ("tasks plugins \"$WORD\" x", .nonLiteralArgument(command: "tasks"), "a non-literal second word"),
        ("tasks sh\\ow x", .nonLiteralArgument(command: "tasks"), "an escaped local subcommand"),
        ("tasks {show,edit} x", .nonLiteralArgument(command: "tasks"), "a brace-expanded local subcommand"),
        ("tasks show $DATABASE_URL", .expandsReference("DATABASE_URL"),
         "a reference variable after a local subcommand"),
        ("tasks show x --on $BEADS_ACTOR", .unsupportedSyntax("unquoted expansion"),
         "an unquoted plain variable after a local subcommand (quote it)"),
        ("tasks where | python3", .unlistedCommand("python3"), "an unlisted command after a local command"),
        ("/Users/synthetic/.local/bin/tasks where",
         .commandPathOutsideSystemDirectories("/Users/synthetic/.local/bin/tasks"), "a local command by a user path"),
    ] as [(String, AICommandSecretFree.Rejection, String)] {
        rejected(program, rejection, label)
    }
    // A reference in a variable the local command reads a credential from keeps
    // it on the ordinary path, whatever the subcommand; other tools are
    // unaffected, and so is the command under any other reference.
    for name in ["TASKS_TOKEN", "BEADS_DOLT_PASSWORD", "DOLT_REMOTE_PASSWORD", "BD_LINEAR_API_KEY"] {
        let withCredential = references.union([name, "csec_\(name)"])
        check(AICommandSecretFree.classify("tasks where", referenceVariables: withCredential,
                                           localCommands: localCommands)
                == .needsSecrets(.readsCredential(command: "tasks", variable: name))
              && AICommandSecretFree.classify("ls; echo \"$?\"", referenceVariables: withCredential,
                                              localCommands: localCommands) == .secretFree,
              "a reference in \(name) keeps the local command on the ordinary path")
    }
    let withServiceToken = references.union(["SERVICE_TOKEN", "csec_SERVICE_TOKEN"])
    check(AICommandSecretFree.classify("tasks park x --on y", referenceVariables: withServiceToken,
                                       localCommands: localCommands) == .secretFree,
          "another tool's token reference leaves a local command's listed subcommands secret-free")
    // Nothing is listed beyond the built-ins without a local list.
    check(AICommandSecretFree.classify("tasks where", referenceVariables: references)
            == .needsSecrets(.unlistedCommand("tasks"))
          && AICommandSecretFree.invocationRejection(["tasks", "where"], referenceVariables: references)
            == .unlistedCommand("tasks"),
          "without a local list, a session tool is an unlisted command")
    secretFreeLocalCommandsFileTests()

    // MARK: $?

    for (program, label) in [
        ("false; echo exit=$?", "an unquoted $? joined to text"),
        ("ls x; echo $?", "an unquoted $?"),
        ("[ $? -eq 0 ] && ls", "an unquoted $? in [ … ]"),
    ] {
        secretFree(program, label)
    }
    for (program, rejection, label) in [
        ("echo ${?}", .unsupportedSyntax("unquoted expansion"), "an unquoted ${?}"),
        ("echo $$", .unsupportedSyntax("unquoted expansion"), "an unquoted $$"),
        ("echo $?[1]", .unsupportedSyntax("subscript"), "a subscript after $?"),
        ("$? x", .nonLiteralCommandName, "$? as a command name"),
        ("git log $?", .nonLiteralArgument(command: "git"), "$? as an argument of a checked command"),
    ] as [(String, AICommandSecretFree.Rejection, String)] {
        rejected(program, rejection, label)
    }

    // MARK: Bytes the bash grammar and zsh read differently

    let backslashBlank = AICommandSecretFree.Rejection.unsafeCharacters(
        "a backslash before whitespace or a control character")
    let invisible = AICommandSecretFree.Rejection.unsafeCharacters(
        "a control, format or non-ASCII whitespace character")
    let processSubstitution = AICommandSecretFree.Rejection.unsafeCharacters("=(")
    for (program, rejection, label) in [
        ("ls\\\n#; npm test", backslashBlank, "an escaped newline before # (the grammar starts a comment)"),
        ("echo a\\\n#b; npm test", backslashBlank, "an escaped newline inside a word before #"),
        ("cat a.txt\\\n#|npm test", backslashBlank, "an escaped newline before #|"),
        ("echo a\\\t#b; npm test", backslashBlank, "an escaped tab before #"),
        ("echo a\\\u{0B}#b; npm test", backslashBlank, "an escaped vertical tab before #"),
        ("echo a\\\u{0C}#b; npm test", backslashBlank, "an escaped form feed before #"),
        ("ls\\\r\nnpm test", backslashBlank, "a backslash, CR, LF continuation"),
        ("ls ./a\\ b", backslashBlank, "an escaped space"),
        ("echo a\u{0B}#; npm test", invisible, "a vertical tab before #"),
        ("echo a\u{0C}#; npm test", invisible, "a form feed before #"),
        ("echo a\r#; npm test", invisible, "a carriage return before #"),
        ("ls\r\n", invisible, "a CRLF line ending"),
        ("ls\u{00A0}#; npm test", invisible, "a no-break space before #"),
        ("ls\u{3000}x", invisible, "an ideographic space"),
        ("ls\u{200B}x", invisible, "a zero-width space"),
        ("ls \u{0}", invisible, "a NUL"),
        ("ls \\", .unsafeCharacters("a trailing backslash"), "a trailing backslash"),
        ("cat =(ls)", processSubstitution, "zsh =(…) process substitution"),
        ("[ -n =(npm) ]", processSubstitution, "=(…) inside [ … ]"),
        ("[ a =(npm) ]", processSubstitution, "=(…) as a [ … ] operand"),
        ("[ a =(npm) -o b ]", processSubstitution, "=(…) inside a [ … ] expression"),
        ("[ a = a ] && [ -n =(npm) ]", processSubstitution, "=(…) in a second [ … ]"),
        ("echo ${X:-=(npm test)}", processSubstitution, "=(…) in an expansion operand"),
        ("echo ${X-=(npm)}", processSubstitution, "=(…) in a - operand"),
        ("echo ${HOME:+=(npm)}", processSubstitution, "=(…) in a :+ operand"),
        ("echo ${HOME/x/=(npm)}", processSubstitution, "=(…) in a replacement"),
        ("ls ${X:-=(make)}", processSubstitution, "=(…) in an argument's operand"),
        ("echo ${X:-*(e:npm\\ test:)}", backslashBlank, "a glob qualifier with an escaped space"),
    ] {
        rejected(program, rejection, label)
    }

    // MARK: Parse errors and unsupported syntax

    for (program, label) in [
        ("echo \"unterminated", "an unterminated string (ERROR)"),
        ("echo $(ls", "an unterminated substitution (MISSING)"),
        ("ls *(e:'rm x':)", "a zsh glob qualifier that runs code"),
        ("echo ${(P)DATABASE_NAME}", "zsh parameter flags"),
    ] {
        rejected(program, .unparsable, label)
    }
    for (program, syntax, label) in [
        ("f() { ls; }", "function_definition", "a function definition"),
        ("case x in a) ls;; esac", "case_statement", "case"),
        ("for f in a b; do cat \"$f\"; done", "for_statement", "for, which assigns its loop variable"),
        ("select x in a; do ls; done", "for_statement", "select"),
        ("((x = 1))", "((", "an arithmetic command"),
        ("echo $((1 + 2))", "arithmetic_expansion", "arithmetic expansion"),
        ("ls &", "&", "a background job"),
        ("ls ;;", ";;", "a stray ;;"),
        ("[ a > b ]", ">", "a > inside [ … ], which the shell treats as a redirection"),
        ("> out", "redirection without a command", "a redirection with no command ($NULLCMD)"),
        ("cat <<EOF\n$(ls)\nEOF", "expanding heredoc", "an unquoted heredoc with a substitution"),
        ("cat <<EOF\n`ls`\nEOF", "expanding heredoc", "an unquoted heredoc with a backquote the grammar leaves as text"),
        ("cat <<EOF -n\nx\nEOF", "heredoc argument", "arguments after a heredoc delimiter"),
        ("find . -name x > out -exec cat {} +", "words after a redirection",
         "words after a redirection target, which the shell passes to the command"),
        ("echo \"$HOME[1]\"", "subscript", "a zsh subscript inside a string"),
        ("echo \"${HOME}[1]\"", "subscript", "a zsh subscript after ${…}"),
        ("echo ${HOME:0:2}", "${ : }", "a substring offset (arithmetic)"),
        ("echo ${HOME@P}", "${ @ }", "a prompt re-expansion"),
        ("echo ${HOME:=x}", "${ := }", "an assigning expansion"),
        ("echo ${list[0]}", "subscript", "an array subscript"),
        ("echo \"${HOME:-`ls`}\"", "unparsed command substitution", "a backquote the grammar leaves inside ${…}"),
        ("echo $'\\\\'; npm test #'", "ansi_c_string", "an ANSI-C string the grammar ends at an escaped quote"),
        ("echo $'a'", "ansi_c_string", "an ANSI-C string"),
        ("[ a = a ]#; npm test", "] not ending its word", "]# after [ … ], one word to zsh"),
        ("[ -f a.txt ]#|npm test", "] not ending its word", "]#| after [ … ]"),
        ("{ ls; }#; npm test", "# after a non-blank", "}# after a group"),
        ("ls;# c", "# after a non-blank", "a comment right after ;"),
        ("echo a#b", "# in a word", "an unquoted # inside a word"),
        ("echo ${X:-*(+npm)}", "parenthesis in a word", "a glob qualifier in an expansion operand"),
        ("echo ${X:-*(e:npm:)}", "parenthesis in a word", "an e: glob qualifier in an expansion operand"),
        ("echo $#DATABASE_URL", "$#", "zsh's $#NAME length of a reference"),
        ("echo \"$#DATABASE_URL\"", "$#", "zsh's $#NAME inside a string"),
        ("echo $#", "$#", "$#"),
        ("echo ~DATABASE_URL", "~ expansion", "zsh's ~NAME named directory of a reference"),
        ("echo ${X:-~DATABASE_URL}", "~ expansion", "~NAME in an expansion operand"),
        ("ls ~root", "~ expansion", "~user"),
        ("ls ~+", "~ expansion", "~+ (the directory stack)"),
        ("echo a=~DATABASE_URL", "~ expansion", "~NAME after = (MAGIC_EQUAL_SUBST)"),
        ("echo x=a:~DATABASE_URL", "~ expansion", "~NAME after : (MAGIC_EQUAL_SUBST)"),
    ] {
        rejected(program, .unsupportedSyntax(syntax), label)
    }
    rejected("[[ -f x ]]", .unlistedCommand("[["), "[[ … ]], which evaluates arithmetic and patterns")
    for (program, label) in [
        ("echo $\"x\"", "$\"…\", one word to zsh"),
        ("echo x$'a'", "x$'…'"),
        ("echo ${X:-<(npm)}", "<(…) in an expansion operand"),
        ("ls >>(npm)", ">>(…)"),
        ("ls &! npm", "zsh &! (disown)"),
        ("ls &| npm", "zsh &| (disown)"),
        ("[ a = a ]x", "a word glued to ]"),
    ] {
        needsSecrets(program, label)
    }
    for (program, label) in [
        ("X=1", "an assignment"),
        ("X=1 ls", "an assignment prefix"),
        ("PATH=/tmp/synthetic:$PATH ls", "a PATH assignment prefix"),
        ("export X=1; ls", "export"),
        ("local x", "local"),
        ("unset PATH; ls", "unset"),
        ("printf -v PATH %s /nonexistent; ls", "printf -v, which assigns PATH"),
        ("printf -vPATH %s /nonexistent", "printf -vNAME"),
    ] {
        rejected(program, .variableAssignment, label)
    }

    // MARK: Commands

    for (program, command, label) in [
        ("curl https://example.invalid", "curl", "an unlisted command"),
        ("ls | python3 -c pass", "python3", "an unlisted command in a pipeline"),
        ("ls && npm test", "npm", "an unlisted command in a list"),
        ("echo $(curl -s x)", "curl", "an unlisted command inside $(…)"),
        ("echo \"$(curl -s x)\"", "curl", "an unlisted command inside a quoted $(…)"),
        ("echo `make`", "make", "an unlisted command inside backquotes"),
        ("diff <(npm ls) b", "npm", "an unlisted command inside <(…)"),
        ("ls > >(tee copy)", "tee", "an unlisted command inside >(…)"),
        ("cat < <(make)", "make", "an unlisted command in a redirection target"),
        ("cat <<'EOF' | node\nx\nEOF", "node", "an unlisted command after a heredoc"),
        ("if make; then ls; fi", "make", "an unlisted command in a condition"),
        ("(cd x && python3 y)", "python3", "an unlisted command in a subshell"),
        ("{ ls; npm ls; }", "npm", "an unlisted command in a group"),
        ("echo ${HOME:-$(curl x)}", "curl", "an unlisted command in an expansion operand"),
        ("coproc ls", "coproc", "coproc"),
        ("ls; exit 0", "exit", "exit"),
    ] {
        rejected(program, .unlistedCommand(command), label)
    }
    for (program, label) in [
        ("$CMD x", "a variable command name"),
        ("${CMD} x", "a braced variable command name"),
        ("$(echo ls) x", "a substituted command name"),
        ("ls$PLAIN_SETTING", "a command name containing an expansion"),
        ("\\ls", "an escaped command name"),
        ("l* x", "a globbed command name"),
        ("~/bin/ls", "a tilde command name"),
        ("\"ls\" -la", "a double-quoted command name"),
        ("'cat' x", "a single-quoted command name"),
        ("l\"s\"", "a partly quoted command name"),
    ] {
        rejected(program, .nonLiteralCommandName, label)
    }
    for program in ["./ls", "bin/test", "node_modules/.bin/cat", "/Users/synthetic/bin/diff", "/bin//cat"] {
        rejected(program, .commandPathOutsideSystemDirectories(program),
                 "a listed basename outside the system tool directories: \(program)")
    }
    for banned in AICommandSecretFree.bannedCommands.sorted() {
        rejected("\(banned) ls", .bannedCommand(banned), "banned command \(banned)")
    }
    rejected("/usr/bin/env ls", .bannedCommand("env"), "a banned command named by path")
    rejected("ls | sudo tee x", .bannedCommand("sudo"), "a banned command in a pipeline")

    // MARK: Checked options: every argument a plain literal, then the option rules

    for (program, command, label) in [
        ("find . -exe\\c npm test \\;", "find", "an escaped -exec"),
        ("find . {-exec,npm} test \\;", "find", "-exec from a brace expansion"),
        ("find . \"${X:--exec}\" npm test ';'", "find", "-exec from a quoted unset variable's default"),
        ("find . \"${HOME:+-exec}\" npm test ';'", "find", "-exec from a quoted set variable's alternative"),
        ("find . -e\\xecdir npm \\;", "find", "an escaped -execdir"),
        ("find . -name x -exec cat {} +", "find", "{} is a brace word"),
        ("fd -\\x npm", "fd", "an escaped -x"),
        ("rg --pr\\e=curl hello .", "rg", "an escaped --pre"),
        ("rg \"a$b\" x", "rg", "a double-quoted expansion"),
        ("rg \"a\\\\b\" x", "rg", "a backslash inside double quotes"),
        ("rg \"a!b\" x", "rg", "a ! inside double quotes"),
        ("rg 'a''b' x", "rg", "adjacent single-quoted parts (one string under RC_QUOTES)"),
        ("rg -g *.swift x", "rg", "an unquoted glob"),
        ("jq -n e\\nv", "jq", "an escaped env"),
        ("jq -n \"$ENV.X\"", "jq", "a double-quoted $ENV"),
        ("git grep -\\Ocurl x", "git", "an escaped -O"),
        ("git -\\c x=y log", "git", "an escaped -c"),
        ("git lo\\g", "git", "an escaped subcommand"),
        ("git \"$SUBCOMMAND\"", "git", "a non-literal subcommand"),
        ("git -C \"$HOME/src\" status", "git", "a quoted -C value"),
        ("sort -t, -k2 \"$f\"", "sort", "a quoted file"),
        ("printf $ x", "printf", "a lone $"),
    ] {
        rejected(program, .nonLiteralArgument(command: command), label)
    }
    rejected("find . $'-exec' npm test \\;", .unsupportedSyntax("ansi_c_string"), "an ANSI-C -exec")
    for option in ["-exec", "-execdir", "-ok", "-okdir"] {
        rejected("find . -name x \(option) cat x +", .runsProgram(command: "find", option: option),
                 "find \(option)")
    }
    for option in ["-x", "--exec", "-X", "--exec-batch=wc", "-HIx"] {
        rejected("fd -e txt \(option) cat", .runsProgram(command: "fd", option: option), "fd \(option)")
    }
    for option in ["--pre", "--pre=cat", "-z", "--search-zip", "-nz"] {
        rejected("rg \(option) x .", .runsProgram(command: "rg", option: option), "rg \(option)")
    }
    rejected("sort --compress-program=gzip f", .runsProgram(command: "sort", option: "--compress-program=gzip"),
             "sort --compress-program")
    rejected("sort --compress=gzip f", .runsProgram(command: "sort", option: "--compress=gzip"),
             "an abbreviated sort --compress-program")
    for filter in ["env.GITHUB_TOKEN", "env", "env.X,.y"] {
        rejected("jq -n \(filter)", .readsEnvironment(command: "jq"), "jq \(filter)")
    }
    // Quoting does not hide an option: the checks read the decoded value.
    for (program, rejection, label) in [
        ("find . '-exec' npm test ';'", .runsProgram(command: "find", option: "-exec"), "a single-quoted -exec"),
        ("find . -name x \"-ok\"dir cat +", .runsProgram(command: "find", option: "-okdir"),
         "a partly quoted -okdir"),
        ("rg \"--pre=npm\" x", .runsProgram(command: "rg", option: "--pre=npm"), "a double-quoted --pre"),
        ("fd -e txt \"-x\" cat", .runsProgram(command: "fd", option: "-x"), "a double-quoted -x"),
        ("sort \"--compress-program=gzip\" f", .runsProgram(command: "sort", option: "--compress-program=gzip"),
         "a double-quoted --compress-program"),
        ("git grep \"-O\" x", .runsProgram(command: "git grep", option: "-O"), "a double-quoted git grep -O"),
        ("git '-c' core.pager=npm log", .gitConfigurationOverride("-c"), "a single-quoted git -c"),
        ("git 'push'", .gitSubcommand("push"), "a quoted git subcommand"),
        ("printf '-v' PATH %s x", .variableAssignment, "a quoted printf -v"),
        ("jq -n 'env.X'", .readsEnvironment(command: "jq"), "a quoted jq env"),
        ("jq -n '$ENV.X'", .readsEnvironment(command: "jq"), "a quoted jq $ENV"),
    ] as [(String, AICommandSecretFree.Rejection, String)] {
        rejected(program, rejection, label)
    }
    // Every argument is scanned: an option can take `--` as its value and the
    // tool keeps reading options after it (re-review R1). Also every option the
    // tools' own help documents as running a program (R2 and the audit).
    for (program, rejection, label) in [
        ("sort -o -- --compress-program=curl -S 1 big.txt",
         .runsProgram(command: "sort", option: "--compress-program=curl"), "sort -o taking -- as its value"),
        ("sort -T -- --compress-program=curl -S 1 big.txt",
         .runsProgram(command: "sort", option: "--compress-program=curl"), "sort -T taking -- as its value"),
        ("git -C . grep -e -- -Ocurl -- a.txt", .runsProgram(command: "git grep", option: "-Ocurl"),
         "git grep -e taking -- as its value, then -O"),
        ("git -C . grep -e -- --open-files-in-pager=curl -- a.txt",
         .runsProgram(command: "git grep", option: "--open-files-in-pager=curl"),
         "git grep -e taking --, then --open-files-in-pager"),
        ("rg -e -- --pre=curl .", .runsProgram(command: "rg", option: "--pre=curl"), "rg -e taking --, then --pre"),
        ("rg -r -- --pre=curl hello .", .runsProgram(command: "rg", option: "--pre=curl"),
         "rg -r taking --, then --pre"),
        ("rg x -- --pre=curl", .runsProgram(command: "rg", option: "--pre=curl"),
         "a literal --pre after -- (over-refused by design)"),
        ("rg --hostname-bin=curl --hyperlink-format=default hello .",
         .runsProgram(command: "rg", option: "--hostname-bin=curl"), "rg --hostname-bin="),
        ("rg --hostname-bin curl --hyperlink-format vscode --color always hello .",
         .runsProgram(command: "rg", option: "--hostname-bin"), "rg --hostname-bin as a separate value"),
        ("fd -l a", .runsProgram(command: "fd", option: "-l"), "fd -l (--exec-batch ls -l)"),
        ("fd --list-details a", .runsProgram(command: "fd", option: "--list-details"), "fd --list-details"),
        ("git log --ext-diff", .runsProgram(command: "git log", option: "--ext-diff"), "git log --ext-diff"),
        ("git diff --textconv", .runsProgram(command: "git diff", option: "--textconv"), "git diff --textconv"),
        ("git show --show-signature", .runsProgram(command: "git show", option: "--show-signature"),
         "git show --show-signature (gpg.program)"),
        ("git log --format='%G?'", .runsProgram(command: "git log", option: "--format=%G?"),
         "a %G pretty placeholder (gpg.program)"),
        ("git for-each-ref --format='%(signature)'",
         .runsProgram(command: "git for-each-ref", option: "--format=%(signature)"), "a %(signature) atom"),
        ("git cat-file --textconv HEAD:a.txt", .runsProgram(command: "git cat-file", option: "--textconv"),
         "git cat-file --textconv"),
        ("git cat-file --filters HEAD:a.txt", .runsProgram(command: "git cat-file", option: "--filters"),
         "git cat-file --filters (smudge filters)"),
        ("git grep --textc x", .runsProgram(command: "git grep", option: "--textc"),
         "an abbreviated git grep --textconv"),
        ("jq -f filter.jq", .readsEnvironment(command: "jq"), "jq -f (a filter the check cannot read)"),
        ("jq --from-file filter.jq", .readsEnvironment(command: "jq"), "jq --from-file"),
        ("jq -L modules .", .readsEnvironment(command: "jq"), "jq -L (modules)"),
        ("printf %s -v", .variableAssignment, "a -v anywhere in printf's arguments (over-refused by design)"),
    ] as [(String, AICommandSecretFree.Rejection, String)] {
        rejected(program, rejection, label)
    }
    secretFree("git diff --text HEAD", "git diff --text (diff options take no abbreviations)")
    // A word-initial `~` joined to anything reads that name (re-review R3).
    for (program, label) in [
        ("echo ~{DATABASE_URL,}", "~ then a brace expansion"),
        ("echo ~${X:-DATABASE_URL}", "~ then an expansion"),
        ("echo ~\"\"DATABASE_URL", "~ then empty double quotes"),
        ("echo ~''DATABASE_URL", "~ then empty single quotes"),
        ("echo ~\"x\"", "~ then a quoted name"),
        ("git log ~'x'", "~ then a quoted name in a checked command"),
    ] {
        rejected(program, .unsupportedSyntax("~ expansion"), label)
    }
    // An unquoted expansion is a pattern under GLOB_SUBST (re-review R4).
    for (program, label) in [
        ("echo '*(+npm)'; cat ${_}", "$_ carrying a glob qualifier"),
        ("mkdir -p q 'q(+npm)' && cd 'q(+npm)' && ls $PWD", "$PWD carrying a glob qualifier"),
        ("ls $PLAIN_SETTING", "a plain variable"),
        ("ls $(pwd)", "a command substitution"),
        ("ls `pwd`", "a backquoted substitution"),
        ("ls > $PLAIN_SETTING", "a redirection target"),
        ("[ -n $PLAIN_SETTING ]", "a [ … ] operand"),
        ("echo ${HOME:-x}", "an expansion with an operator"),
    ] {
        rejected(program, .unsupportedSyntax("unquoted expansion"), label)
    }
    secretFree("ls \"$PLAIN_SETTING\" \"$(pwd)\" \"${HOME:-x}\"", "double-quoted expansions")

    // MARK: git

    rejected("git -c core.pager=cat log", .gitConfigurationOverride("-c"), "git -c")
    rejected("git --config-env=core.pager=PAGER log", .gitConfigurationOverride("--config-env=core.pager=PAGER"),
             "git --config-env=")
    rejected("git --config-env core.pager=PAGER log", .gitConfigurationOverride("--config-env"),
             "git --config-env")
    rejected("git --exec-path=/tmp/synthetic status", .gitConfigurationOverride("--exec-path=/tmp/synthetic"),
             "git --exec-path=")
    rejected("git --exec-path status", .gitConfigurationOverride("--exec-path"), "git --exec-path")
    rejected("git -C x -c core.pager=cat log", .gitConfigurationOverride("-c"), "git -c after -C")
    for subcommand in ["push", "fetch", "pull", "commit", "checkout", "config", "st", "help", "submodule"] {
        rejected("git \(subcommand)", .gitSubcommand(subcommand), "git \(subcommand)")
    }
    rejected("git", .gitSubcommand(""), "git with no subcommand")
    rejected("git -C x", .gitSubcommand(""), "git -C with no subcommand")
    rejected("git -p log", .gitGlobalOption("-p"), "git -p, which pages through a configurable program")
    rejected("git --version", .gitGlobalOption("--version"), "git --version")
    for option in ["-O", "-Ovim", "-nO", "--open-files-in-pager", "--open-files-in-pager=vim", "--open"] {
        rejected("git grep \(option) pattern", .runsProgram(command: "git grep", option: option),
                 "git grep \(option)")
    }
    for option in ["--edit-description", "--edit-desc"] {
        rejected("git branch \(option)", .runsProgram(command: "git branch", option: option),
                 "git branch \(option), which starts the configured editor")
    }
    rejected("git log | git push", .gitSubcommand("push"), "git push later in a pipeline")

    // MARK: Reference variables

    for (program, name, label) in [
        ("echo $DATABASE_URL", "DATABASE_URL", "$VAR"),
        ("echo ${DATABASE_URL}", "DATABASE_URL", "${VAR}"),
        ("echo \"$DATABASE_URL\"", "DATABASE_URL", "\"$VAR\""),
        ("echo \"x${DATABASE_URL}y\"", "DATABASE_URL", "${VAR} inside a string"),
        ("echo ${DATABASE_URL:-fallback}", "DATABASE_URL", "${VAR:-…}"),
        ("echo ${#DATABASE_URL}", "DATABASE_URL", "${#VAR}"),
        ("echo ${DATABASE_URL%%@*}", "DATABASE_URL", "${VAR%%…}"),
        ("echo ${HOME:-$DATABASE_URL}", "DATABASE_URL", "an expansion's operand"),
        ("echo ${HOME:-\"x$API_TOKEN\"}", "API_TOKEN", "a quoted expansion operand"),
        ("echo $API_TOKEN", "API_TOKEN", "the destination of a csec_ alias"),
        ("echo $csec_API_TOKEN", "csec_API_TOKEN", "a csec_ alias itself"),
        ("cat <<< \"$DATABASE_URL\"", "DATABASE_URL", "a here-string"),
        ("ls > \"$DATABASE_URL\"", "DATABASE_URL", "a redirection target"),
        ("echo $(echo $DATABASE_URL)", "DATABASE_URL", "inside $(…)"),
        ("echo `echo $DATABASE_URL`", "DATABASE_URL", "inside backquotes"),
        ("diff <(echo $DATABASE_URL) f", "DATABASE_URL", "inside <(…)"),
        ("[ -n \"$DATABASE_URL\" ]", "DATABASE_URL", "inside [ … ]"),
        ("test -n \"$DATABASE_URL\"", "DATABASE_URL", "a test argument"),
        ("git -C \"$DATABASE_URL\" status", "DATABASE_URL", "a git -C value"),
        ("printf %s $DATABASE_URL | wc -c", "DATABASE_URL", "in a pipeline"),
    ] {
        rejected(program, .expandsReference(name), "a reference variable expanded as \(label)")
    }
    rejected("echo ${!DATABASE*}", .indirectExpansion, "${!prefix*} indirection")
    rejected("echo ${!HOME}", .indirectExpansion, "${!VAR} indirection through a plain variable")
    rejected("DATABASE_URL=$DATABASE_URL ls", .variableAssignment, "a reference in an assignment value")
    rejected("X=$DATABASE_URL", .variableAssignment, "a reference in a bare assignment value")
    rejected("echo $((DATABASE_URL + 1))", .unsupportedSyntax("arithmetic_expansion"),
             "a reference read by bare name in arithmetic")
    rejected("echo $(( $DATABASE_URL ))", .unsupportedSyntax("arithmetic_expansion"),
             "a reference expanded in arithmetic")
    rejected("echo ${HOME:DATABASE_URL}", .unsupportedSyntax("${ : }"),
             "a reference read by bare name in a substring offset")
    rejected("cat <<EOF\n$DATABASE_URL\nEOF", .unsupportedSyntax("expanding heredoc"),
             "a reference expanded in an unquoted heredoc")
    secretFree("echo \"$PLAIN_SETTING\" | wc -c", "a variable that holds no reference")
    check(AICommandSecretFree.classify("echo \"$DATABASE_URL\"", referenceVariables: []) == .secretFree,
          "with no reference variables, expanding that name is ordinary")

    // Deep nesting ends in a verdict, not a stack overflow.
    let depth = 400
    let nested = "echo " + String(repeating: "$(echo ", count: depth) + "x" + String(repeating: ")", count: depth)
    rejected(nested, .nestingTooDeep, "a program nested \(depth) substitutions deep")
    let shallow = String(repeating: "\"$(echo ", count: 8) + "x" + String(repeating: ")\"", count: 8)
    secretFree("echo " + shallow, "a program nested eight quoted substitutions deep")

    // MARK: One command as zsh runs it

    for (argv, expected) in [
        (["ls", "-la"], nil),
        (["/bin/cat"], nil),
        (["printf", "--", "x"], nil),
        (["printf", "--", "-v"], .variableAssignment),
        (["sort", "-o", "--", "--compress-program=curl"], .runsProgram(command: "sort", option: "--compress-program=curl")),
        (["rg", "--hostname-bin", "curl", "x"], .runsProgram(command: "rg", option: "--hostname-bin")),
        (["git", "-C", "src", "log"], nil),
        ([], AICommandSecretFree.Rejection.nonLiteralCommandName),
        (["npm", "test"], .unlistedCommand("npm")),
        (["./cat"], .commandPathOutsideSystemDirectories("./cat")),
        (["find", ".", "-exec", "npm", ";"], .runsProgram(command: "find", option: "-exec")),
        (["printf", "-v", "PATH", "%s", "x"], .variableAssignment),
        (["jq", "-n", "$ENV.X"], .readsEnvironment(command: "jq")),
        (["git", "-c", "x=y", "log"], .gitConfigurationOverride("-c")),
        (["bd", "update", "x", "--append-notes", "2026-10-20T10:00:00Z (synthetic): $(x)"], nil),
        (["bd", "--actor", "show", "list"], nil),
        (["/opt/homebrew/bin/bd", "show"], nil),
        (["bd", "--", "show"], .bdGlobalOption("--")),
        (["bd", "edit", "x"], .bdSubcommand("edit")),
        (["bd"], .bdSubcommand("")),
        (["./bd", "show"], .commandPathOutsideSystemDirectories("./bd")),
        (["tasks", "park", "x", "--on", "2026-11-03T20:00:00Z $(x)"], nil),
        (["/opt/homebrew/bin/tasks", "where"], nil),
        (["tasks", "plugins", "read", "x"], nil),
        (["tasks", "plugins", "install", "x"], .localSubcommand(command: "tasks", subcommand: "plugins install")),
        (["tasks", "login"], .localSubcommand(command: "tasks", subcommand: "login")),
        (["tasks"], .localSubcommand(command: "tasks", subcommand: "")),
        (["./tasks", "where"], .commandPathOutsideSystemDirectories("./tasks")),
    ] as [([String], AICommandSecretFree.Rejection?)] {
        check(AICommandSecretFree.invocationRejection(argv, referenceVariables: references,
                                                      localCommands: localCommands) == expected,
              "invocation \(argv) is \(expected.map { "refused: \($0)" } ?? "allowed")")
    }

    // The review's counterexamples: each makes the real zsh run something a
    // secret-free program may not, and each is refused above.
    let divergent = [
        "ls\\\n#; npm test", "echo a\\\n#b; npm test", "cat a.txt\\\n#|npm test", "echo a\\\t#b; npm test",
        "echo a\\\u{0B}#b; npm test", "echo a\\\u{0C}#b; npm test", "ls\\\r\nnpm test",
        "echo a\u{0B}#; npm test", "echo a\u{0C}#; npm test", "echo a\r#; npm test", "ls\u{00A0}#; npm test",
        "echo $'\\\\'; npm test #'", "[ a = a ]#; npm test", "[ -f a.txt ]#|npm test",
        "[ -n =(npm) ]", "[ a =(npm) ]", "[ a =(npm) -o b ]", "[ a = a ] && [ -n =(npm) ]",
        "echo ${X:-=(npm test)}", "echo ${X:-*(e:npm\\ test:)}", "echo ${X:-*(+npm)}", "echo ${X-=(npm)}",
        "echo ${HOME:+=(npm)}", "echo ${HOME/x/=(npm)}", "ls ${X:-=(make)}",
        "find . -exe\\c npm test \\;", "find . $'-exec' npm test \\;", "find . {-exec,npm} test \\;",
        "find . ${X:--exec} npm test \\;", "find . ${HOME:+-exec} npm test \\;", "find . -e\\xecdir npm \\;",
        "fd -\\x npm", "rg --pr\\e=curl hello .", "jq -n e\\nv", "git grep -\\Ocurl x", "git -\\c x=y log",
        "printf -v PATH %s /nonexistent; ls",
        // The re-review's R1 and R2 (the sentinels record the argv, which the
        // fixed rules now refuse; the real tools run them below).
        "sort -o -- --compress-program=curl -S 1 big.txt", "sort -T -- --compress-program=curl -S 1 big.txt",
        "git -C . grep -e -- -Ocurl -- a.txt", "git -C . grep -e -- --open-files-in-pager=curl -- a.txt",
        "rg -e -- --pre=curl .", "rg -r -- --pre=curl hello .",
        "rg --hostname-bin=curl --hyperlink-format=default hello .",
        "rg --hostname-bin curl --hyperlink-format vscode --color always hello .",
        // bd subcommands and options that are not allowed.
        "bd edit synthetic", "bd hooks run x", "bd -- edit x", "bd --actor edit x",
        // Local subcommands that are not allowed.
        "tasks login x", "tasks edit x", "tasks plugins install x", "tasks --help",
    ]
    // Refused programs the hostile options turn harmful: GLOB_SUBST globs an
    // expansion's `-*` into the files `-exec` and `--pre=npm`, and a `$_` or
    // `$PWD` carrying a glob qualifier runs it (re-review R4).
    let hostileDivergent = [
        "find . ${X:--*} npm +", "rg x ${X:---pre*} .", "echo '*(+npm)'; cat ${_}",
        "mkdir -p q 'q(+npm)' && cd 'q(+npm)' && ls $PWD",
    ]
    secretFreeZshDifferentialTests(corpus: corpus, divergent: divergent, hostileDivergent: hostileDivergent,
                                   references: references, localCommands: localCommands)
    secretFreeRealToolTests(references: references)
    secretFreeRealBdTests(references: references)

    bridgeRequestTests()
}

/// The classification corpus under the real `/bin/zsh -lc`, the way `csec ai`
/// launches it. A temporary `PATH` holds a sentinel for every listed command
/// and for the unlisted ones the corpus names, and `ZDOTDIR`'s `.zlogin` (read
/// after the system login files) records every builtin and every command not
/// found, so each run leaves the argv of everything zsh ran. Every program the
/// classifier calls secret-free must have run only invocations
/// `AICommandSecretFree.invocationRejection` allows. Hermetic: a temporary
/// home and working directory, no network, no references in the environment,
/// and sentinels that run nothing.
///
/// It runs twice: with empty startup files, and with a hostile `.zshenv` that
/// turns on the options that change how words expand (EXTENDED_GLOB,
/// GLOB_SUBST, SH_WORD_SPLIT, MAGIC_EQUAL_SUBST, RC_QUOTES, NULL_GLOB), in a
/// directory holding files named `-exec`, `--pre=npm` and `HEAD`, and
/// directories `q` and `q(+npm)`, for a glob to find.
private func secretFreeZshDifferentialTests(
    corpus: [String], divergent: [String], hostileDivergent: [String], references: Set<String>,
    localCommands: AICommandSecretFree.LocalCommands
) {
    print("\n# AICommandSecretFree differential (the corpus under /bin/zsh -lc)")
    let zsh = "/bin/zsh"
    guard FileManager.default.isExecutableFile(atPath: zsh) else {
        check(false, "the zsh differential needs /bin/zsh")
        return
    }
    let files = FileManager.default
    let root = files.temporaryDirectory.appendingPathComponent("csec-secret-free-zsh-\(UUID().uuidString)")
    defer { try? files.removeItem(at: root) }
    let bin = root.appendingPathComponent("bin")
    let plainStartup = root.appendingPathComponent("zdot")
    let hostileStartup = root.appendingPathComponent("zdot-hostile")
    // The name holds an `x` so `${HOME/x/…}` matches.
    let home = root.appendingPathComponent("xhome")
    let work = root.appendingPathComponent("work")
    let logs = root.appendingPathComponent("logs")
    let temporary = root.appendingPathComponent("tmp")
    do {
        for directory in [bin, plainStartup, hostileStartup, home, work, work.appendingPathComponent("sub"),
                          work.appendingPathComponent("q"), work.appendingPathComponent("q(+npm)"), logs,
                          temporary] {
            try files.createDirectory(at: directory, withIntermediateDirectories: true)
        }
        for name in ["a.txt", "x.c", "f", "g", "-exec", "--pre=npm", "HEAD"] {
            try Data("synthetic\n".utf8).write(to: work.appendingPathComponent(name))
        }
        // One write per record: the commands of a pipeline record concurrently.
        let sentinel = #"""
            #!/bin/sh
            r=$(printf '%s' "${0##*/}"; for a in "$@"; do printf '\037%s' "$a"; done; printf '\036')
            printf '%s' "$r" >> "$CSEC_DIFF_LOG"
            """#
        let unlisted = ["npm", "curl", "make", "node", "python3", "tee", "awk"]
        for name in AICommandSecretFree.listedCommands.union(["git", "bd"]).union(localCommands.commands.keys).union(unlisted) {
            let path = bin.appendingPathComponent(name).path
            try Data((sentinel + "\n").utf8).write(to: URL(fileURLWithPath: path))
            try files.setAttributes([.posixPermissions: 0o755], ofItemAtPath: path)
        }
        // Wrap every builtin zsh lets a function shadow, so builtins are recorded
        // too; the precommand modifiers and the reserved typeset family cannot be.
        let zlogin = #"""
            PATH=$CSEC_DIFF_PATH
            __csec_record() {
              local __csec_r=$1 __csec_a
              builtin shift
              for __csec_a in "$@"; do __csec_r+=$'\037'$__csec_a; done
              builtin print -rn -- "$__csec_r"$'\036' >> $CSEC_DIFF_LOG
            }
            command_not_found_handler() { __csec_record "$@"; builtin return 127 }
            () {
              local b
              for b in ${(k)builtins}; do
                case $b in
                  (builtin|command|exec|noglob|nocorrect|-|local|typeset|declare|export|readonly|integer|float|private) ;;
                  (*) functions[$b]="__csec_record ${(q)b} \"\$@\"; builtin ${(q)b} \"\$@\"" ;;
                esac
              done
            }
            """#
        for startup in [plainStartup, hostileStartup] {
            // /etc/zprofile runs path_helper, which moves the sentinels behind
            // the system directories; .zprofile runs right after it.
            try Data("PATH=$CSEC_DIFF_PATH\n".utf8).write(to: startup.appendingPathComponent(".zprofile"))
            try Data((zlogin + "\n").utf8).write(to: startup.appendingPathComponent(".zlogin"))
        }
        try Data("setopt extendedglob globsubst shwordsplit magicequalsubst rcquotes nullglob\n".utf8)
            .write(to: hostileStartup.appendingPathComponent(".zshenv"))
    } catch {
        check(false, "the zsh differential sets up its sentinels (\(error))")
        return
    }

    struct Run {
        var records: [[String]] = []
        var finished = false
    }
    func run(_ program: String, startup: URL, log: URL) -> Run {
        files.createFile(atPath: log.path, contents: Data())
        let process = Process()
        process.executableURL = URL(fileURLWithPath: zsh)
        process.arguments = ["-lc", program]
        process.currentDirectoryURL = work
        process.environment = [
            "PATH": bin.path, "CSEC_DIFF_PATH": bin.path, "CSEC_DIFF_LOG": log.path, "HOME": home.path,
            "ZDOTDIR": startup.path, "TMPDIR": temporary.path, "LANG": "en_US.UTF-8",
            "PLAIN_SETTING": "not-a-reference",
        ]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        let exited = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in exited.signal() }
        guard (try? process.run()) != nil else { return Run() }
        var result = Run()
        if exited.wait(timeout: .now() + 20) == .timedOut {
            process.terminate()
            _ = exited.wait(timeout: .now() + 5)
        } else {
            result.finished = true
        }
        let data = (try? Data(contentsOf: log)) ?? Data()
        result.records = data.split(separator: 0x1E).map { record in
            record.split(separator: 0x1F, omittingEmptySubsequences: false)
                .map { String(decoding: $0, as: UTF8.self) }
        }
        return result
    }
    func disallowed(_ run: Run) -> [String] {
        run.records.compactMap { argv in
            AICommandSecretFree.invocationRejection(argv, referenceVariables: references, localCommands: localCommands)
                .map { "\(argv): \($0)" }
        }
    }

    // A 400-deep substitution would fork 400 nested shells; the rest run.
    // Process arguments cannot carry a NUL.
    let programs = corpus.filter { $0.utf8.count <= 1_000 && !$0.unicodeScalars.contains("\u{0}") }
        + divergent + hostileDivergent
    let secretFree = programs.map {
        AICommandSecretFree.classify($0, referenceVariables: references, localCommands: localCommands).isSecretFree
    }
    for (mode, startup) in [("empty startup files", plainStartup), ("a hostile .zshenv", hostileStartup)] {
        var runs = [Run](repeating: Run(), count: programs.count)
        let lock = NSLock()
        DispatchQueue.concurrentPerform(iterations: programs.count) { index in
            let result = run(programs[index], startup: startup,
                             log: logs.appendingPathComponent("\(startup.lastPathComponent)-\(index).log"))
            lock.lock()
            runs[index] = result
            lock.unlock()
        }

        // The harness itself: builtins, sentinels and missing commands are recorded.
        for (program, expected) in [
            ("npm test", ["npm", "test"]),
            ("ls -la", ["ls", "-la"]),
            ("eval 'ls x'", ["eval", "ls x"]),
            ("printf -v X %s y", ["printf", "-v", "X", "%s", "y"]),
            ("[ a = a ] && cd sub", ["cd", "sub"]),
            ("synthetic-missing-command arg", ["synthetic-missing-command", "arg"]),
        ] {
            let canary = run(program, startup: startup,
                             log: logs.appendingPathComponent("\(startup.lastPathComponent)-canary.log"))
            check(canary.finished && canary.records.contains(expected),
                  "with \(mode), the zsh differential records \(expected) for \(program.debugDescription) "
                      + "(recorded \(canary.records))")
        }

        var failures: [String] = []
        for index in programs.indices where secretFree[index] {
            let bad = disallowed(runs[index])
            if !runs[index].finished || !bad.isEmpty {
                failures.append("\(programs[index].debugDescription) finished=\(runs[index].finished) ran \(bad)")
            }
        }
        let count = secretFree.filter { $0 }.count
        check(count > 150 && failures.isEmpty,
              "with \(mode), every one of \(count) secret-free programs ran only allowed commands under "
                  + "/bin/zsh -lc" + (failures.isEmpty ? "" : ": \(failures)"))

        // Each counterexample is refused, and zsh really runs something a
        // secret-free program may not: the review's in any configuration, the
        // exclusion-~ ones only under the hostile options.
        let expectDivergence = startup == hostileStartup ? hostileDivergent : divergent
        let offset = startup == hostileStartup ? divergent.count : 0
        for (position, program) in expectDivergence.enumerated() {
            let index = programs.count - divergent.count - hostileDivergent.count + offset + position
            let bad = disallowed(runs[index])
            check(!secretFree[index] && !bad.isEmpty,
                  "with \(mode), counterexample \(program.debugDescription) is refused, and zsh ran \(bad)"
                      + (bad.isEmpty ? " (recorded \(runs[index].records))" : ""))
        }
    }
}

/// The option rules against the tools' own parsers. The zsh differential above
/// replaces every tool with a sentinel and judges its argv with
/// `invocationRejection`, so it cannot find a rule that misreads a tool. Here
/// the real `find`, `sort` and `git` (and `rg` and `fd` when installed) run
/// under `/bin/zsh -lc`, and every program they could start (`curl`, `npm`,
/// an editor, a pager, `gpg`, decompressors, `ls`) is a recording sentinel on
/// a temporary PATH. Every program the classifier calls secret-free must leave
/// every sentinel unrun, and each refused one listed here must really run one,
/// so the check can fail. Hermetic: a temporary git repository and HOME, no
/// system or global git configuration, no pager, no network.
private func secretFreeRealToolTests(references: Set<String>) {
    print("\n# AICommandSecretFree real tools (the option rules against find, sort, git, rg and fd)")
    let files = FileManager.default
    let zsh = "/bin/zsh"
    var tools = ["find": "/usr/bin/find", "sort": "/usr/bin/sort", "git": "/usr/bin/git"]
    for name in ["rg", "fd"] {
        if let path = ["/opt/homebrew/bin/\(name)", "/usr/local/bin/\(name)"]
            .first(where: files.isExecutableFile(atPath:)) {
            tools[name] = path
        } else {
            print("note: \(name) is not installed; its real-tool cases are skipped")
        }
    }
    guard files.isExecutableFile(atPath: zsh), tools.values.allSatisfy(files.isExecutableFile(atPath:)) else {
        check(false, "the real-tool check needs /bin/zsh, /usr/bin/find, /usr/bin/sort and /usr/bin/git")
        return
    }
    let root = files.temporaryDirectory.appendingPathComponent("csec-secret-free-tools-\(UUID().uuidString)")
    defer { try? files.removeItem(at: root) }
    let bin = root.appendingPathComponent("bin")
    let startup = root.appendingPathComponent("zdot")
    let home = root.appendingPathComponent("home")
    let work = root.appendingPathComponent("work")
    let logs = root.appendingPathComponent("logs")
    let temporary = root.appendingPathComponent("tmp")
    let baseEnvironment = [
        "HOME": home.path, "TMPDIR": temporary.path, "LANG": "en_US.UTF-8", "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_PAGER": "cat", "PLAIN_SETTING": "not-a-reference",
        // git refuses to start its default editor on a dumb (or unset) terminal.
        "TERM": "xterm-256color",
    ]
    func runDirect(_ executable: String, _ arguments: [String]) -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.currentDirectoryURL = work
        process.environment = baseEnvironment.merging(["PATH": "/usr/bin:/bin"]) { $1 }
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        guard (try? process.run()) != nil else { return false }
        process.waitUntilExit()
        return process.terminationStatus == 0
    }
    do {
        for directory in [bin, startup, home, work, work.appendingPathComponent("--"), logs, temporary] {
            try files.createDirectory(at: directory, withIntermediateDirectories: true)
        }
        for (name, path) in tools {
            let wrapper = bin.appendingPathComponent(name).path
            try Data("#!/bin/sh\nexec '\(path)' \"$@\"\n".utf8).write(to: URL(fileURLWithPath: wrapper))
            try files.setAttributes([.posixPermissions: 0o755], ofItemAtPath: wrapper)
        }
        // Each records its argv, then copies stdin to stdout, so a tool that
        // pipes through it (sort's compressor) finishes instead of waiting.
        let sentinel = #"""
            #!/bin/sh
            r=$(printf '%s' "${0##*/}"; for a in "$@"; do printf '\037%s' "$a"; done; printf '\036')
            printf '%s' "$r" >> "$CSEC_DIFF_LOG"
            exec /bin/cat
            """#
        for name in ["curl", "npm", "gpg", "ssh-keygen", "vi", "vim", "nano", "less", "more", "gzip", "bzip2",
                     "xz", "lz4", "zstd", "brotli", "lzma", "ls"] {
            let path = bin.appendingPathComponent(name).path
            try Data((sentinel + "\n").utf8).write(to: URL(fileURLWithPath: path))
            try files.setAttributes([.posixPermissions: 0o755], ofItemAtPath: path)
        }
        let zlogin = #"""
            PATH=$CSEC_DIFF_PATH
            command_not_found_handler() {
              local r=$1 a
              shift
              for a in "$@"; do r+=$'\037'$a; done
              print -rn -- "$r"$'\036' >> $CSEC_DIFF_LOG
              return 127
            }
            """#
        try Data("PATH=$CSEC_DIFF_PATH\n".utf8).write(to: startup.appendingPathComponent(".zprofile"))
        try Data((zlogin + "\n").utf8).write(to: startup.appendingPathComponent(".zlogin"))
        // A line `--` for `grep -e --` to match, so -O has a file to open.
        try Data("hello\n--\n".utf8).write(to: work.appendingPathComponent("a.txt"))
        // Enough to spill `sort -S 1` into compressed temporary files, few
        // enough that the compressor starts only a few dozen times.
        try Data((0..<40).map { "synthetic line \(($0 * 7_919) % 40)\n" }.joined().utf8)
            .write(to: work.appendingPathComponent("big.txt"))
        try Data("synthetic, not really compressed hello\n".utf8).write(to: work.appendingPathComponent("c.gz"))
    } catch {
        check(false, "the real-tool check sets up its sentinels (\(error))")
        return
    }
    let git = tools["git"] ?? "/usr/bin/git"
    guard runDirect(git, ["init", "-q", "."]), runDirect(git, ["add", "a.txt"]),
          runDirect(git, ["-c", "user.name=csec", "-c", "user.email=csec@invalid", "-c", "commit.gpgsign=false",
                          "commit", "-q", "-m", "synthetic"]) else {
        check(false, "the real-tool check creates its temporary git repository")
        return
    }

    // (program, the tool it needs, whether the real tool runs a sentinel)
    let cases: [(String, String, Bool)] = [
        ("find . -name a.txt -type f", "find", false),
        ("find . -name '*.txt'", "find", false),
        ("find . -name \"a.txt\" -print", "find", false),
        ("find . -name a.txt -exec curl ';'", "find", true),
        ("find . -name a.txt -execdir curl ';'", "find", true),
        ("find . -name a.txt '-exec' curl ';'", "find", true),
        ("sort a.txt", "sort", false),
        ("sort -u -k1 big.txt", "sort", false),
        ("sort -o -- --compress-program=curl -S 1 big.txt", "sort", true),
        ("sort -T -- --compress-program=curl -S 1 big.txt", "sort", true),
        ("sort --compress-program=curl -S 1 big.txt", "sort", true),
        ("sort --compress=curl -S 1 big.txt", "sort", true),
        ("git log --oneline -1", "git", false),
        ("git log --format='%H %s' -1", "git", false),
        ("git grep -n hello", "git", false),
        ("git grep -e -- hello", "git", false),
        ("git diff HEAD", "git", false),
        ("git diff --text HEAD", "git", false),
        ("git show HEAD --stat", "git", false),
        ("git status --short", "git", false),
        ("git branch --list", "git", false),
        ("git cat-file -p HEAD:a.txt", "git", false),
        ("git -C . log -1", "git", false),
        ("git -C . grep -e -- -Ocurl -- a.txt", "git", true),
        ("git -C . grep -e -- --open-files-in-pager=curl -- a.txt", "git", true),
        ("git grep -Ocurl hello", "git", true),
        ("git grep --open-files-in-pager=curl hello", "git", true),
        ("git branch --edit-description", "git", true),
        ("rg hello .", "rg", false),
        ("rg -n \"hello\" a.txt", "rg", false),
        ("rg -e -- hello .", "rg", false),
        ("rg 'a b' -g '*.txt' .", "rg", false),
        ("rg --hyperlink-format=default hello .", "rg", false),
        ("rg -e -- --pre=curl .", "rg", true),
        ("rg -r -- --pre=curl hello .", "rg", true),
        ("rg --pre curl hello .", "rg", true),
        ("rg -z hello .", "rg", true),
        ("rg --hostname-bin=curl --hyperlink-format=default hello .", "rg", true),
        ("rg --hostname-bin curl --hyperlink-format vscode --color always hello .", "rg", true),
        ("fd a", "fd", false),
        ("fd -e txt", "fd", false),
        ("fd a -x curl", "fd", true),
        ("fd a -X curl", "fd", true),
        ("fd -l a", "fd", true),
    ].filter { tools[$0.1] != nil }

    var ran = [[[String]]](repeating: [], count: cases.count)
    var finished = [Bool](repeating: false, count: cases.count)
    let lock = NSLock()
    DispatchQueue.concurrentPerform(iterations: cases.count) { index in
        let log = logs.appendingPathComponent("\(index).log")
        files.createFile(atPath: log.path, contents: Data())
        let process = Process()
        process.executableURL = URL(fileURLWithPath: zsh)
        process.arguments = ["-lc", cases[index].0]
        process.currentDirectoryURL = work
        process.environment = baseEnvironment.merging([
            "PATH": bin.path, "CSEC_DIFF_PATH": bin.path, "CSEC_DIFF_LOG": log.path, "ZDOTDIR": startup.path,
        ]) { $1 }
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        let exited = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in exited.signal() }
        guard (try? process.run()) != nil else { return }
        var done = true
        if exited.wait(timeout: .now() + 30) == .timedOut {
            process.terminate()
            _ = exited.wait(timeout: .now() + 5)
            done = false
        }
        let records = ((try? Data(contentsOf: log)) ?? Data()).split(separator: 0x1E).map { record in
            record.split(separator: 0x1F, omittingEmptySubsequences: false)
                .map { String(decoding: $0, as: UTF8.self) }
        }
        lock.lock()
        ran[index] = records
        finished[index] = done
        lock.unlock()
    }

    for (index, (program, _, runsProgram)) in cases.enumerated() {
        let verdict = AICommandSecretFree.classify(program, referenceVariables: references)
        if runsProgram {
            check(!verdict.isSecretFree && finished[index] && !ran[index].isEmpty,
                  "the real tool runs a program for \(program.debugDescription), and it is refused "
                      + "(verdict \(verdict), finished \(finished[index]), ran \(ran[index].map { $0.first ?? "" }))")
        } else {
            check(verdict.isSecretFree && finished[index] && ran[index].isEmpty,
                  "secret-free \(program.debugDescription) runs no other program in the real tool "
                      + "(verdict \(verdict), ran \(ran[index]))")
        }
    }
}

/// bd's global options against the real bd's parser, when bd is installed
/// (`CSEC_SELFTEST_BD`, else the first `bd` on `PATH`). The classifier reads
/// `bd <option> version …` as cobra does only if it knows which options take
/// a value: one that does consumes `version`, and bd prints no version. Only
/// `bd <option> version` runs, which opens no database, with usage metrics
/// off; the classifier judges the same words followed by `edit`, which it
/// refuses exactly when `version` was consumed.
private func secretFreeRealBdTests(references: Set<String>) {
    print("\n# AICommandSecretFree real bd (global options as cobra reads them)")
    let files = FileManager.default
    let environment = ProcessInfo.processInfo.environment
    let candidates = [environment["CSEC_SELFTEST_BD"]].compactMap { $0 }
        + (environment["PATH"] ?? "").split(separator: ":").map { "\($0)/bd" }
    guard let bd = candidates.first(where: files.isExecutableFile(atPath:)) else {
        print("note: bd is not installed; its real-tool cases are skipped")
        return
    }
    let work = files.temporaryDirectory.appendingPathComponent("csec-secret-free-bd-\(UUID().uuidString)")
    defer { try? files.removeItem(at: work) }
    guard (try? files.createDirectory(at: work, withIntermediateDirectories: true)) != nil else {
        check(false, "the real bd check creates its working directory")
        return
    }
    func printsVersion(_ arguments: [String]) -> Bool? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: bd)
        process.arguments = arguments
        process.currentDirectoryURL = work
        process.environment = environment.merging(["BD_DISABLE_METRICS": "1"]) { $1 }
        let output = Pipe()
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        let exited = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in exited.signal() }
        guard (try? process.run()) != nil else { return nil }
        let data = output.fileHandleForReading.readDataToEndOfFile()
        guard exited.wait(timeout: .now() + 20) == .success else {
            process.terminate()
            return nil
        }
        let text = String(decoding: data, as: UTF8.self)
        return process.terminationStatus == 0 && (text.hasPrefix("bd version ") || text.contains("\"version\""))
    }
    guard printsVersion(["version"]) == true, printsVersion(["--json", "version"]) == true else {
        check(false, "the real bd at \(bd) prints its version")
        return
    }
    // Every global option bd 1.3.1 lists, and two it does not.
    let options = [
        "--actor", "--cpu-profile", "--database", "--db", "-C", "--directory", "--dolt-auto-commit", "--global",
        "--ignore-schema-skew", "--json", "--mem-profile", "--no-color", "-q", "--quiet", "--readonly",
        "--sandbox", "-v", "--verbose", "--", "--synthetic-unknown",
    ]
    for option in options {
        let ranVersion = printsVersion([option, "version"])
        let verdict = AICommandSecretFree.invocationRejection(["bd", option, "version", "edit"],
                                                              referenceVariables: references)
        switch verdict {
        case .bdGlobalOption(option)?:
            check(ranVersion != nil, "the real bd ran for refused global option \(option)")
        case nil:
            check(ranVersion == true, "bd \(option) is a flag, so the real bd runs version")
        case .bdSubcommand("edit")?:
            check(ranVersion == false, "bd \(option) takes a value, so the real bd does not run version")
        default:
            check(false, "bd \(option) version edit is judged \(String(describing: verdict))")
        }
    }
}

/// The bridge's TTL is optional: absent means the grant follows the root the
/// human approves, as for `csec exec`; present, it must be positive and is
/// otherwise passed through as csecd honours it.
private func bridgeRequestTests() {
    print("\n# BridgeRequest (optional TTL)")

    func decode(_ json: String) -> BridgeRequest? {
        try? JSONDecoder().decode(BridgeRequest.self, from: Data(json.utf8))
    }
    let withoutTTL = decode(#"{"version":1,"references":["op://synthetic/item/field"],"reason":"boot"}"#)
    check(withoutTTL?.ttlSeconds == nil && withoutTTL?.isWellFormed == true,
          "a bridge request without ttlSeconds decodes with no clock and is accepted")
    let nullTTL = decode(#"{"version":1,"references":["op://synthetic/item/field"],"reason":"boot","ttlSeconds":null}"#)
    check(nullTTL?.ttlSeconds == nil && nullTTL?.isWellFormed == true,
          "a null ttlSeconds is the same as an absent one")
    // No upper bound beyond csecd's: a large explicit lifetime passes through.
    for ttl in [1, 3_600, 172_800, 172_801, Int.max] {
        let request = decode(#"{"version":1,"references":["op://s/i/f"],"reason":"boot","ttlSeconds":\#(ttl)}"#)
        check(request?.ttlSeconds == ttl && request?.isWellFormed == true,
              "an explicit ttlSeconds of \(ttl) is honoured")
    }
    for ttl in ["0", "-1", "-9223372036854775808"] {
        let request = decode(#"{"version":1,"references":["op://s/i/f"],"reason":"boot","ttlSeconds":\#(ttl)}"#)
        check(request.map { !$0.isWellFormed } ?? false, "an explicit ttlSeconds of \(ttl) is refused")
    }
    for ttl in ["1.5", "\"60\"", "1e30"] {
        check(decode(#"{"version":1,"references":["op://s/i/f"],"reason":"boot","ttlSeconds":\#(ttl)}"#) == nil,
              "a ttlSeconds of \(ttl) is not an integer and does not decode")
    }
    for (json, label) in [
        (#"{"version":2,"references":["op://s/i/f"],"reason":"boot"}"#, "an unknown version"),
        (#"{"version":1,"references":[],"reason":"boot"}"#, "no references"),
        (#"{"version":1,"references":["op://s/i/f"],"reason":""}"#, "an empty reason"),
    ] {
        check(decode(json).map { !$0.isWellFormed } ?? false, "a bridge request with \(label) is refused")
    }
    let tooMany = BridgeRequest(references: (0...64).map { "op://s/i/f\($0)" }, reason: "boot")
    check(!tooMany.isWellFormed, "a bridge request with 65 references is refused")
    let longReason = BridgeRequest(references: ["op://s/i/f"], reason: String(repeating: "é", count: 257))
    check(!longReason.isWellFormed, "a bridge reason over 512 UTF-8 bytes is refused")

    let encodedWithout = (try? JSONEncoder().encode(BridgeRequest(references: ["op://s/i/f"], reason: "boot")))
        .flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
    check(encodedWithout.map { $0["ttlSeconds"] == nil } ?? false,
          "a TTL-free bridge request omits ttlSeconds on the wire")
    let encodedWith = (try? JSONEncoder().encode(BridgeRequest(references: ["op://s/i/f"], reason: "boot",
                                                               ttlSeconds: 60)))
        .flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
    check(encodedWith?["ttlSeconds"] as? Int == 60, "an explicit bridge TTL is sent as ttlSeconds")
}

/// `AICommandSecretFree.LocalCommands.load`: the file's protection and format.
/// Tests cannot create a root-owned file, so the accepted cases load with
/// `requireRootOwnership: false`; every other check still applies.
private func secretFreeLocalCommandsFileTests() {
    typealias LocalCommands = AICommandSecretFree.LocalCommands
    let files = FileManager.default
    let root = files.temporaryDirectory.appendingPathComponent("csec-secret-free-local-\(UUID().uuidString)")
    defer { try? files.removeItem(at: root) }
    let directory = root.appendingPathComponent("csec")
    let path = directory.appendingPathComponent("secret-free-commands.json").path
    do {
        try files.createDirectory(at: directory, withIntermediateDirectories: true,
                                  attributes: [.posixPermissions: 0o755])
    } catch {
        check(false, "the local secret-free list tests set up a directory (\(error))")
        return
    }
    func load(_ json: String?, requireRootOwnership: Bool = false) -> Result<LocalCommands, Error> {
        try? files.removeItem(atPath: path)
        if let json {
            files.createFile(atPath: path, contents: Data(json.utf8), attributes: [.posixPermissions: 0o644])
        }
        return Result { try LocalCommands.load(path: path, requireRootOwnership: requireRootOwnership) }
    }
    func invalid(_ result: Result<LocalCommands, Error>) -> Bool {
        if case let .failure(error as LocalCommands.LoadError) = result, case .invalid = error { return true }
        return false
    }
    func unsafe(_ result: Result<LocalCommands, Error>) -> Bool {
        if case let .failure(error as LocalCommands.LoadError) = result, case .unsafe = error { return true }
        return false
    }

    check(LocalCommands.path == "/private/etc/csec/secret-free-commands.json",
          "the local secret-free list lives in /etc/csec, outside the package's own directory")
    check((try? load(nil).get()) == LocalCommands.none, "no local list adds nothing")

    let valid = """
        {"version": 1, "commands": {"tasks": {
          "subcommands": ["show", "note"],
          "subcommandsWithSecondWord": {"plugins": ["list", "read"]},
          "credentialVariablePrefixes": ["TASKS_", "BD_"]},
          "notes": {"subcommands": ["list"]}}}
        """
    check((try? load(valid).get()) == LocalCommands(commands: [
        "tasks": .init(subcommands: ["show", "note"], subcommandsWithSecondWord: ["plugins": ["list", "read"]],
                       credentialVariablePrefixes: ["TASKS_", "BD_"]),
        "notes": .init(subcommands: ["list"]),
    ]), "a local list loads its commands, second words and credential prefixes")
    if getuid() != 0 {
        check(unsafe(load(valid, requireRootOwnership: true)), "a local list the user owns is ignored")
    }

    // Protection: the user's agent must not be able to swap or edit the list.
    _ = load(valid)
    try? files.setAttributes([.posixPermissions: 0o664], ofItemAtPath: path)
    check(unsafe(Result { try LocalCommands.load(path: path, requireRootOwnership: false) }),
          "a group-writable local list is ignored")
    let target = root.appendingPathComponent("elsewhere.json").path
    files.createFile(atPath: target, contents: Data(valid.utf8), attributes: [.posixPermissions: 0o644])
    try? files.removeItem(atPath: path)
    try? files.createSymbolicLink(atPath: path, withDestinationPath: target)
    check(unsafe(Result { try LocalCommands.load(path: path, requireRootOwnership: false) }),
          "a local list reached through a symbolic link is ignored")
    try? files.removeItem(atPath: path)
    try? files.linkItem(atPath: target, toPath: path)
    check(unsafe(Result { try LocalCommands.load(path: path, requireRootOwnership: false) }),
          "a hard-linked local list is ignored")
    _ = load(valid)
    try? files.setAttributes([.posixPermissions: 0o775], ofItemAtPath: directory.path)
    check(unsafe(Result { try LocalCommands.load(path: path, requireRootOwnership: false) }),
          "a local list in a group-writable directory is ignored")
    try? files.setAttributes([.posixPermissions: 0o755], ofItemAtPath: directory.path)

    // Format: anything unexpected refuses the whole list.
    for (json, label) in [
        ("not json", "text that is not JSON"),
        ("[]", "a JSON array"),
        (#"{"commands": {}}"#, "no version"),
        (#"{"version": 2, "commands": {}}"#, "another version"),
        (#"{"version": true, "commands": {}}"#, "a boolean version"),
        (#"{"version": 1}"#, "no commands"),
        (#"{"version": 1, "commands": {}, "extra": 1}"#, "an unknown top-level key"),
        (#"{"version": 1, "commands": {"tasks": {"subcommand": ["show"]}}}"#, "an unknown command key"),
        (#"{"version": 1, "commands": {"tasks": ["show"]}}"#, "a command that is not an object"),
        (#"{"version": 1, "commands": {"ls": {"subcommands": ["x"]}}}"#, "a listed tool"),
        (#"{"version": 1, "commands": {"bd": {"subcommands": ["edit"]}}}"#, "bd, which has built-in rules"),
        (#"{"version": 1, "commands": {"git": {"subcommands": ["push"]}}}"#, "git, which has built-in rules"),
        (#"{"version": 1, "commands": {"env": {"subcommands": ["x"]}}}"#, "a banned command"),
        (#"{"version": 1, "commands": {"bin/tasks": {"subcommands": ["x"]}}}"#, "a command path"),
        (#"{"version": 1, "commands": {"-tasks": {"subcommands": ["x"]}}}"#, "a name that is an option"),
        (#"{"version": 1, "commands": {"tasks": {"subcommands": ["--help"]}}}"#, "an option as a subcommand"),
        (#"{"version": 1, "commands": {"tasks": {"subcommands": ["a b"]}}}"#, "a subcommand of two words"),
        (#"{"version": 1, "commands": {"tasks": {"subcommands": ["*"]}}}"#, "a glob subcommand"),
        (#"{"version": 1, "commands": {"tasks": {"subcommands": [1]}}}"#, "a number subcommand"),
        (#"{"version": 1, "commands": {"tasks": {"subcommands": "show"}}}"#, "subcommands that are not a list"),
        (#"{"version": 1, "commands": {"tasks": {"subcommands": ["plugins"], "subcommandsWithSecondWord": {"plugins": ["list"]}}}}"#,
         "a subcommand listed with and without a second word"),
        (#"{"version": 1, "commands": {"tasks": {"subcommandsWithSecondWord": {"plugins": "list"}}}}"#,
         "second words that are not a list"),
        (#"{"version": 1, "commands": {"tasks": {"subcommandsWithSecondWord": {"plugins": ["$x"]}}}}"#,
         "an expansion as a second word"),
        (#"{"version": 1, "commands": {"tasks": {"credentialVariablePrefixes": [""]}}}"#, "an empty prefix"),
        (#"{"version": 1, "commands": {"tasks": {"credentialVariablePrefixes": ["1X"]}}}"#,
         "a prefix that is no variable name"),
    ] {
        check(invalid(load(json)), "a local list with \(label) is refused")
    }
    var reason = ""
    if case let .failure(error) = load(#"{"version": 1, "commands": {"bd": {}}}"#) {
        reason = String(describing: error)
    }
    check(reason.contains(path) && reason.contains("\"bd\" has built-in rules"),
          "a refused local list says which file and which rule")
}
