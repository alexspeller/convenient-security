import Foundation
import ConvenientSecurity

/// `LauncherScript` (simple commands of a shell text, argv matching). Every
/// script below is synthetic.
func launcherScriptTests() {
    print("\n# LauncherScript (simple commands, matching)")
    launcherSimpleCommandTests()
    launcherWordTests()
    launcherParseFailureTests()
    launcherEmptyBackquoteTests()
    launcherMatchTests()
    launcherRealWorldTests()
}

// MARK: - Helpers

private typealias Word = ShellCommandWord

private func lit(_ text: String) -> ShellPatternPiece { .literal(text) }

private func commands(_ text: String) -> [ShellSimpleCommand]? {
    LauncherScript.simpleCommands(in: text)
}

/// Name and arguments of each command, lines ignored.
private func shapes(_ text: String) -> [String]? {
    commands(text)?.map(describe)
}

private func describe(_ command: ShellSimpleCommand) -> String {
    let arguments = command.arguments.map { word -> String in
        switch word {
        case let .exact(value): return value
        case .any: return "<any>"
        case let .pattern(pieces):
            return "<" + pieces.map { piece -> String in
                if case let .literal(text) = piece { return text }
                return "*"
            }.joined() + ">"
        }
    }
    return ([command.name ?? "<nil>"] + arguments).joined(separator: " ")
}

// MARK: - Simple commands

private func launcherSimpleCommandTests() {
    check(shapes("git add a.txt; git commit -m x && git push || echo failed | tail -1 & ssh h true\nsleep 1")
            == ["git add a.txt", "git commit -m x", "git push", "echo failed", "tail -1", "ssh h true", "sleep 1"],
          "simple commands: ; && || | & and newlines all separate commands")
    check(shapes("( cd x && git push )") == ["cd x", "git push"], "simple commands: a subshell")
    check(shapes("{ git push; } 2>&1 | tail") == ["git push", "tail"], "simple commands: a group, redirected and piped")
    check(shapes("if git push; then echo ok; elif true; then :; else echo no; fi")
            == ["git push", "echo ok", "true", ":", "echo no"], "simple commands: if/elif/else")
    check(shapes("for r in a b; do git push \"$r\"; done") == ["git push <*>"], "simple commands: a for body")
    check(shapes("while git fetch; do sleep 1; done; until false; do :; done")
            == ["git fetch", "sleep 1", "false", ":"], "simple commands: while and until")
    check(shapes("case $x in a) git push ;; *) ssh h ;; esac") == ["git push", "ssh h"], "simple commands: case bodies")
    check(shapes("out=$(git push 2>&1); echo \"$out\"") == ["git push", "echo <*>"],
          "simple commands: a command substitution in an assignment")
    check(shapes("echo \"$(git push)\" `ssh h x` >\"$(git log)\"") == ["echo <*> <any>", "git push", "ssh h x", "git log"],
          "simple commands: substitutions in double quotes, backquotes and redirect targets")
    check(shapes("diff <(git show a) b") == ["diff <any> b", "git show a"], "simple commands: a process substitution")
    check(shapes("f() { git push; }; function g { ssh h; }; f") == ["git push", "ssh h", "f"],
          "simple commands: function bodies")
    check(shapes("! git push") == ["git push"], "simple commands: a negation")
    check(shapes("[[ -n $(git rev-parse HEAD) ]] && echo ok") == ["git rev-parse HEAD", "echo ok"],
          "simple commands: a substitution inside [[ ]]")
    check(shapes("cat <<EOF\nline $(git push)\nEOF") == ["cat", "git push"],
          "simple commands: a substitution in an unquoted heredoc body runs")
    check(shapes("echo hi # ; git push\necho \"ssh nimbus rm -rf /\" 'git push'") == ["echo hi", "echo ssh nimbus rm -rf / git push"],
          "simple commands: comments and quoted text are not commands")
    launcherPrefixTests()
    launcherHeredocCommandTests()
}

private func launcherPrefixTests() {
    for (text, label) in [
        ("FOO=1 git push", "a leading assignment"),
        ("env FOO=1 git push", "env NAME=VALUE"),
        ("env -i git push", "env -i"),
        ("env -i A=1 B=\"$x\" git push", "env -i with several assignments"),
        ("nice -n 5 git push", "nice -n N"),
        ("nice -5 git push", "nice -N"),
        ("nohup git push", "nohup"),
        ("noglob git push", "noglob"),
        ("nocorrect git push", "nocorrect"),
        ("time git push", "time"),
        ("time -p git push", "time -p"),
        ("command git push", "command"),
        ("builtin git push", "builtin"),
        ("exec nohup env -i nice -n 1 git push", "stacked prefixes"),
        ("mise exec -- git push", "mise exec --"),
        ("mise x node@20 --raw -- git push", "mise x with tools and options"),
        ("direnv exec . git push", "direnv exec DIR"),
        ("direnv exec . mise exec -- env A=1 git push", "direnv, mise and env stacked"),
    ] {
        check(shapes(text) == ["git push"], "prefix stripped: \(label)")
    }
    check(shapes("exec ssh nimbus true") == ["ssh nimbus true"], "prefix stripped: exec ssh")
    check(shapes("env -u X git push") == ["env -u X git push"], "prefix not stripped: env -u")
    check(shapes("command -v git") == ["command -v git"], "prefix not stripped: command -v")
    check(shapes("exec -a name ssh h") == ["exec -a name ssh h"], "prefix not stripped: exec -a")
    check(shapes("nice -x git push") == ["nice -x git push"], "prefix not stripped: nice with another option")
    check(shapes("mise exec git push") == ["mise exec git push"], "prefix not stripped: mise exec without --")
    check(shapes("mise exec -c 'git push' -- x") == ["mise exec -c git push -- x"],
          "prefix not stripped: mise exec -c, which runs a shell")
    check(shapes("mise run deploy") == ["mise run deploy"], "prefix not stripped: mise run (a task, run by a shell)")
    check(shapes("direnv allow .") == ["direnv allow ."], "prefix not stripped: direnv without exec")
    check(shapes("exec") == [] && shapes("exec >/dev/null 2>&1") == [] && shapes("env") == []
            && shapes("nice -n 5") == [] && shapes("time") == [],
          "a bare prefix yields no command")
    check(shapes("exec \"$@\"") == ["<nil>"] && commands("exec \"$@\"")?.first?.name == nil,
          "a prefix before a computed program leaves a nil name")
    check(shapes("$cmd x") == ["<nil> x"] && shapes("\"$(which git)\" push") == ["<nil> push", "which git"],
          "a non-literal command name is nil")
}

private func launcherHeredocCommandTests() {
    let commit = "git add a.txt && git commit -m \"$(cat <<'EOF'\nMessage\n\nBody $(not a command)\nEOF\n)\" && git push origin main 2>&1 | tail -5"
    let expected = [
        ShellSimpleCommand(name: "git", arguments: [.exact("add"), .exact("a.txt")], line: 1),
        ShellSimpleCommand(name: "git", arguments: [.exact("commit"), .exact("-m"), .pattern([.wildcard])], line: 1),
        ShellSimpleCommand(name: "cat", arguments: [], line: 1),
        ShellSimpleCommand(name: "git", arguments: [.exact("push"), .exact("origin"), .exact("main")], line: 6),
        ShellSimpleCommand(name: "tail", arguments: [.exact("-5")], line: 6),
    ]
    check(commands(commit) == expected,
          "a Claude Code commit-and-push: quoted heredoc body is data, lines follow the text (\(String(describing: commands(commit))))")
    let stdin = "git commit -F - <<'EOF'\nsource x\nEOF\ngit push"
    check(commands(stdin) == [
        ShellSimpleCommand(name: "git", arguments: [.exact("commit"), .exact("-F"), .exact("-")], line: 1),
        ShellSimpleCommand(name: "git", arguments: [.exact("push")], line: 4),
    ], "git commit -F - <<'EOF': the `-` the grammar drops is put back, the body is not a command")
    check(shapes("cat - <<EOF | tail -1\nb\nEOF") == ["cat -", "tail -1"],
          "a dropped `-` before a heredoc that pipes on is put back")
    // After `&&`, `||`, `|` or `!` the grammar hangs the heredoc on the whole
    // list, pipeline or negation; bash gives the `-` to the last command.
    for (text, expected, label) in [
        ("ssh nimbus x > f; cd /tmp && wc -l f && python3 - <<'EOF'\nprint(1)\nEOF",
         ["ssh nimbus x", "cd /tmp", "wc -l f", "python3 -"], "after a && list"),
        ("a || b - <<'E'\nx\nE", ["a", "b -"], "after ||"),
        ("ssh x | python3 - <<'E'\nx\nE", ["ssh x", "python3 -"], "after a pipe"),
        ("a | b | c - <<'E'\nx\nE", ["a", "b", "c -"], "at the end of a longer pipeline"),
        ("a && b | c - <<'E'\nx\nE", ["a", "b", "c -"], "in a pipeline ending a list"),
        ("a && ! b - <<'E'\nx\nE", ["a", "b -"], "after !"),
        ("a && b 2>&1 - <<'E'\nx\nE", ["a", "b -"], "after a redirect the grammar also hoists"),
        ("a && b > out - <<'E'\nx\nE", ["a", "b -"], "after an output file"),
        ("a && b - - <<'E'\nx\nE", ["a", "b - -"], "the second of two dashes"),
        ("a && b - <<E\n$(git push)\nE", ["a", "b -", "git push"], "an unquoted body's substitution is still a command"),
    ] {
        check(shapes(text) == expected, "a dropped `-` before a heredoc is put back \(label) (\(String(describing: shapes(text))))")
    }
    check(commands("a && b - <<'E'\nx\nE")?.last?.arguments == [.exact("-")],
          "the put-back `-` is an exact argument of the last command")
    check(shapes("jq . <<<\"$x\"") == ["jq ."], "a here-string is not an argument")
    check(shapes("git push 2>&1 >/dev/null; git push &>f; git push >>log 2>&-") == ["git push", "git push", "git push"],
          "redirects are not arguments")
    check(shapes("bin/nimbusssh cat \"/mnt/x\" > out.json && jq . out.json")
            == ["bin/nimbusssh cat /mnt/x", "jq . out.json"], "a script by relative path, its output redirected")
    check(shapes("cat <<-EOF\n\tindented $(git push)\n\tEOF\nssh h") == ["cat", "git push", "ssh h"],
          "a <<- heredoc with a tab-indented end line")
    // The grammar reads redirects after a heredoc's delimiter only before
    // `&&`, `||` or the end of the line; a `|` after them is an ERROR, though
    // bash runs a pipeline (csec-0.10: a Claude Code `ssh … <<'EOF' 2>&1 |
    // grep -v …` declined as command_mismatch).
    let relay = "ssh nimbus 'docker exec -i harbor-relay python -' <<'EOF' 2>&1 | grep -v \"^20.*INFO\"\nimport relay\nprint(1)\nEOF"
    check(commands(relay) == [
        ShellSimpleCommand(name: "ssh", arguments: [.exact("nimbus"), .exact("docker exec -i harbor-relay python -")], line: 1),
        ShellSimpleCommand(name: "grep", arguments: [.exact("-v"), .exact("^20.*INFO")], line: 1),
    ], "redirects after a heredoc's delimiter, then a pipe (\(String(describing: commands(relay))))")
    check(commands(relay)?.first?.matches(argumentTail: ["nimbus", "docker exec -i harbor-relay python -"]) == true,
          "ssh's argv matches the command before a heredoc, redirect and pipe")
    for (text, expected, label) in [
        ("ssh h x <<EOF >/dev/null 2>&1 |& tail -1\nb\nEOF\ngit push", ["ssh h x", "tail -1", "git push"],
         "two redirects, |&, and a command after the body"),
        ("cat <<EOF 2>&1 | grep x\n$(git push)\nEOF", ["cat", "grep x", "git push"],
         "an unquoted body's substitution is still a command"),
        ("python3 - <<'EOF' 2>&1 | tail -3\nx\nEOF", ["python3 -", "tail -3"], "with the dropped `-` put back"),
        ("a && b <<'E' 2>/dev/null | c\nx\nE", ["a", "b", "c"], "ending a list"),
        ("ssh h x <<'E' 2>&1 | grep y | tail -1\nx\nE", ["ssh h x", "grep y", "tail -1"], "into a longer pipeline"),
    ] {
        check(shapes(text) == expected, "a heredoc with redirects then a pipe \(label) (\(String(describing: shapes(text))))")
    }
    for (text, label) in [
        ("cat <<EOF 2>&1 | grep x )\nb\nEOF", "a second error after the pipe"),
        ("cat <<EOF 2>&1 | | grep x\nb\nEOF", "two pipes"),
        ("cat <<EOF 2>&1 \\\n| grep x\nb\nEOF", "a line continuation before the pipe"),
        ("cat <<EOF 2>&1 ) | grep x\nb\nEOF", "a stray token among the redirects"),
        ("cat <<EOF 2>&1 | grep x\nb\nEOF\ngit push )", "another error elsewhere in the text"),
    ] {
        check(commands(text) == nil, "a heredoc with redirects then a pipe stays refused: \(label)")
    }
    check(shapes("A=1 B=2\ngit push") == ["git push"] && commands("A=1 B=2\ngit push")?.first?.line == 2,
          "assignments on their own line before a command: the command keeps its own line")
}

private func launcherWordTests() {
    check(commands("ssh nimbus \"cd $REMOTE_DIR && git pull origin master\"")?.first?.arguments
            == [.exact("nimbus"), .pattern([lit("cd "), .wildcard, lit(" && git pull origin master")])],
          "a double-quoted string with an expansion is a pattern")
    check(commands("ssh nimbus \"$@\"")?.first?.arguments == [.exact("nimbus"), .any], "\"$@\" is any")
    check(commands("git push origin \"HEAD:refs/heads/$b\"")?.first?.arguments
            == [.exact("push"), .exact("origin"), .pattern([lit("HEAD:refs/heads/"), .wildcard])],
          "a quoted refspec with a variable suffix")
    let escapes = commands("a\\ b 'c d' $'e\\nf\\x41' \"g\\\"h\\$i\\\\j\" k\\$l \"m\\qn\"")?.first
    check(escapes?.name == "a b" && escapes?.arguments
            == [.exact("c d"), .exact("e\nfA"), .exact("g\"h$i\\j"), .exact("k$l"), .exact("m\\qn")],
          "escapes: backslash, single quotes, ANSI-C, double-quote escapes (\(String(describing: escapes)))")
    check(commands("x $'a\\\\\\'b' $'\\''")?.first?.arguments == [.exact("a\\'b"), .exact("'")],
          "ANSI-C escaped backslash and quote end where bash ends them")
    check(commands("x $'\\q' $'\\x80' $'\\u00e9'")?.first?.arguments == [.any, .any, .any],
          "ANSI-C escapes outside the decoded set are any")
    check(commands("echo *.txt a?b [ab] ~ ~/x ~user {a,b} {1..3} pre{x,y}post $x ${y} $(z) `w` $((1+2)) $*")?.first?.arguments
            == Array(repeating: Word.any, count: 15),
          "globs, tildes, brace expansion and unquoted expansions are any")
    check(commands("echo a~b =ls x=~/y a{b}c {} {a..}")?.first?.arguments
            == [.exact("a~b"), .exact("=ls"), .exact("x=~/y"), .exact("a{b}c"), .exact("{}"), .exact("{a..}")],
          "a mid-word tilde, a lone brace pair and a non-sequence stay exact")
    check(commands("echo \"${arr[@]}\" \"${@:2}\" \"${!arr[@]}\" \"x$@y\" \"$*\" \"${arr[*]}\"")?.first?.arguments
            == [.any, .any, .any, .any, .pattern([.wildcard]), .pattern([.wildcard])],
          "array expansions in double quotes are any; $* and [*] join into one word")
    check(commands("echo $\"translated\" x$ \"\" ''")?.first?.arguments == [.any, .exact("x$"), .exact(""), .exact("")],
          "$\"…\" is any, a trailing $ is literal, empty quotes are an empty argument")
    check(commands("echo a\\\nb\ngi\\\nt push")?.map(describe) == ["echo ab", "git push"],
          "a line continuation inside a word joins it, the command name included")
    check(commands("echo \"a\\\nb\" \"${x:-`ssh z`}\" \"$a$b\"")?.first?.arguments
            == [.exact("ab"), .pattern([.wildcard]), .pattern([.wildcard])],
          "inside double quotes a continuation vanishes and adjacent expansions collapse into one wildcard")
}

private func launcherParseFailureTests() {
    for (text, label) in [
        ("if then fi", "if then fi"),
        ("echo \"unbalanced", "an unbalanced double quote"),
        ("echo 'unbalanced", "an unbalanced single quote"),
        ("git push )", "a stray parenthesis"),
        ("cat <<E'O'F\n$(evil)\nEOF\nssh nimbus rm -rf /\n", "a heredoc delimiter quoted mid-word (the grammar swallows the rest)"),
        ("cat <<EOF\nbody\n", "a heredoc with no end line"),
        ("cat -<<EOF\nx\nEOF\n", "a word folded into the << token"),
        ("a && (b) - <<'E'\nx\nE", "a `-` after a subshell before a heredoc (a bash syntax error)"),
        ("a && { b; } - <<'E'\nx\nE", "a `-` after a group before a heredoc (a bash syntax error)"),
        ("cat <<A <<B\na\nA\nb\nB\n", "two heredocs on one line"),
        ("echo $'\\\\'; ssh nimbus rm #'", "an ANSI-C string the grammar ends after bash does ($'\\\\')"),
        ("git push\r\nssh h\r\n", "carriage returns (bash keeps them in the word)"),
        ("git push\u{0B}origin", "a vertical tab the grammar treats as a blank (bash keeps it in the word)"),
        ("git push\0", "a NUL byte"),
    ] {
        check(commands(text) == nil, "does not parse cleanly, nil: \(label)")
    }
    // zsh-only syntax the bash grammar cannot read is refused, never misread
    // into a command that could match.
    check(commands("print -r -- ${(q)x}") == nil && commands("ssh nimbus ${(q)x}") == nil,
          "zsh parameter flags: nil, so no spurious match")
    check(commands("") == [] && commands("# just a comment\n") == [], "an empty text has no commands")
    check(shapes("echo input.$$ \"pid $$ $?\"") == ["echo <any> <pid * *>"],
          "$$ (a `$` token to the grammar) and $? are expansions, quoted or not")
    check(shapes("x=${old//./\\\\.}; v=\"${v//|/\\\\|}\"; y=$((10#${n}))") == [],
          "grammar quirks that leave a backslash or number text between tokens still parse")
    check(commands("echo \"\\\n  ${a}/x \\\n  $b\"")?.first?.arguments
            == [.pattern([lit("  "), .wildcard, lit("/x   "), .wildcard])],
          "continuations and blanks the grammar folds into an expansion token stay string content")
    check(commands("line=\"`hostname` `cat $k`\"") == nil,
          "two backquote substitutions in one string, which the grammar reads as one, are refused")
    check(shapes("git push\u{00A0}origin") == ["git push\u{00A0}origin"],
          "a non-breaking space stays inside the word, as bash and zsh keep it")
}

// MARK: - Empty backquotes

/// The grammar needs a command between backquotes, so an empty substitution
/// inside double quotes is an ERROR it repairs (csec-7eoh: a Claude Code
/// `git commit -m "…``…"` made a sudo later in the text decline as
/// command_mismatch). Every accepted text is also run under the real bash and
/// zsh, whose argv must be the analysis's.
private func launcherEmptyBackquoteTests() {
    let commit = "git commit -q -m \"Fix the parser\n\nAn empty `` pair, then \\`\\`\\`\\` escaped\" && git push"
    for (text, expected, label) in [
        ("git commit -m \"before `` after\" && sudo /usr/bin/true",
         [["git", "commit", "-m", "before  after"], ["sudo", "/usr/bin/true"]], "in a commit message, before a sudo"),
        (commit, [["git", "commit", "-q", "-m", "Fix the parser\n\nAn empty  pair, then ```` escaped"], ["git", "push"]],
         "in a multi-line commit message beside escaped backquotes"),
        ("tool \"a ````b\"", [["tool", "a b"]], "two pairs in a row"),
        ("tool \"``\"", [["tool", ""]], "the whole string"),
        ("tool \"a\\```b\"", [["tool", "a`b"]], "after an escaped backquote"),
        ("tool x\"``\"y", [["tool", "xy"]], "between unquoted text"),
        ("tool \"a``b\"c\"d``\"", [["tool", "abcd"]], "twice in one word"),
        ("tool 'a``b' \"c``d\"", [["tool", "a``b", "cd"]], "after single-quoted backquotes the grammar reads"),
        ("{ tool \"p``q\"; } 2>&1 | tool r", [["tool", "pq"], ["tool", "r"]], "in a redirected group in a pipeline"),
        ("! tool \"p``q\"", [["tool", "pq"]], "in a negation"),
        ("(tool \"p``q\")", [["tool", "pq"]], "in a subshell"),
    ] {
        let argv = commands(text)?.map { command in
            [command.name ?? "<nil>"] + command.arguments.map { argument in
                if case let .exact(value) = argument { return value }
                return "<not exact>"
            }
        }
        check(argv == expected, "an empty backquote pair \(label): exact argv (\(String(describing: argv)))")
        for shell in ["/bin/bash", "/bin/zsh"] {
            // The commands of a pipeline record concurrently.
            let ran = argvUnderShell(shell, text)?.sorted { $0.lexicographicallyPrecedes($1) }
            check(ran == expected.sorted { $0.lexicographicallyPrecedes($1) },
                  "an empty backquote pair \(label): \(shell) runs the same argv (\(String(describing: ran)))")
        }
    }
    let unquotedFirst = "tool a``b \"c``d\""
    check(commands(unquotedFirst) != nil && commands(unquotedFirst) == commands("tool a``b \"cd\""),
          "an unquoted pair before the ERROR is left as it was: the same commands as the text without the quoted pair")
    check(commands(commit)?.last?.line == 3, "the repaired text keeps every command's line")
    check(commands("git commit -m \"before `` after\" && sudo /usr/bin/true")?.last?.matches(argumentTail: ["/usr/bin/true"])
            == true, "the sudo after a repaired commit message matches its argv")

    for (text, label) in [
        ("tool \"c``d\" 'a``b'", "single-quoted backquotes inside the ERROR"),
        ("tool \"c``d\" a``b", "an unquoted pair inside the ERROR"),
        ("X=\"a``b\" tool", "an assignment"),
        ("tool > \"a``b\"", "a redirect target"),
        ("\"to``ol\" x", "a command name"),
        ("tool \"$(tool \"a``b\")\"", "inside $(…)"),
        ("tool `tool \"a``b\"`", "inside backquotes, where a backquote ends the outer substitution"),
        ("if true; then tool \"a``b\"; fi", "a control-flow body"),
        ("for x in \"a``b\"; do tool; done", "a for list"),
        ("tool \"a$``b\"", "a $ just before the pair"),
        ("tool \"a``b\" )", "another syntax error in the text"),
        ("tool \"a```b\"", "three backquotes (bash: an unterminated substitution)"),
        ("tool \"a``b", "an unterminated string"),
        ("cat <<EOF 2>&1 | grep \"a``b\"\nx\nEOF", "a text that also needs the heredoc repair"),
    ] {
        check(commands(text) == nil, "an empty backquote pair stays refused: \(label)")
    }
}

/// The argv of every command `text` runs under `shell` with no startup files:
/// each name is a sentinel in a temporary `PATH` that records its argv and
/// runs nothing. Nil when the shell could not run.
private func argvUnderShell(_ shell: String, _ text: String) -> [[String]]? {
    let files = FileManager.default
    let root = files.temporaryDirectory.appendingPathComponent("csec-backquote-\(UUID().uuidString)")
    defer { try? files.removeItem(at: root) }
    let bin = root.appendingPathComponent("bin")
    let log = root.appendingPathComponent("log")
    let sentinel = #"""
        #!/bin/sh
        r=$(printf '%s' "${0##*/}"; for a in "$@"; do printf '\037%s' "$a"; done; printf '\036')
        printf '%s' "$r" >> "$CSEC_DIFF_LOG"
        """#
    do {
        try files.createDirectory(at: bin, withIntermediateDirectories: true)
        for name in ["git", "sudo", "tool"] {
            let path = bin.appendingPathComponent(name).path
            try Data((sentinel + "\n").utf8).write(to: URL(fileURLWithPath: path))
            try files.setAttributes([.posixPermissions: 0o755], ofItemAtPath: path)
        }
        try Data().write(to: log)
    } catch {
        return nil
    }
    let process = Process()
    process.executableURL = URL(fileURLWithPath: shell)
    process.arguments = shell.hasSuffix("zsh") ? ["-f", "-c", text] : ["--norc", "--noprofile", "-c", text]
    process.currentDirectoryURL = root
    process.environment = ["PATH": bin.path, "CSEC_DIFF_LOG": log.path, "HOME": root.path, "LANG": "en_US.UTF-8"]
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    let exited = DispatchSemaphore(value: 0)
    process.terminationHandler = { _ in exited.signal() }
    guard (try? process.run()) != nil else { return nil }
    if exited.wait(timeout: .now() + 20) == .timedOut {
        process.terminate()
        return nil
    }
    let data = (try? Data(contentsOf: log)) ?? Data()
    return data.split(separator: 0x1E).map { record in
        record.split(separator: 0x1F, omittingEmptySubsequences: false).map { String(decoding: $0, as: UTF8.self) }
    }
}

// MARK: - Matching

private func launcherMatchTests() {
    func command(_ arguments: [Word]) -> ShellSimpleCommand {
        ShellSimpleCommand(name: "ssh", arguments: arguments, line: 1)
    }
    check(command([]).matches(argumentTail: []) && !command([]).matches(argumentTail: ["x"]),
          "no words match only an empty tail")
    check(command([.exact("a")]).matches(argumentTail: ["a"]) && !command([.exact("a")]).matches(argumentTail: ["b"])
            && !command([.exact("a")]).matches(argumentTail: []) && !command([.exact("a")]).matches(argumentTail: ["a", "a"]),
          "exact consumes exactly one equal element")
    check(command([.any]).matches(argumentTail: []) && command([.any]).matches(argumentTail: ["x", "y", "z"]),
          "any absorbs zero or many elements")
    let middle = command([.exact("a"), .any, .exact("b")])
    check(middle.matches(argumentTail: ["a", "b"]) && middle.matches(argumentTail: ["a", "x", "y", "b"])
            && !middle.matches(argumentTail: ["a", "x"]) && !middle.matches(argumentTail: ["x", "b"]),
          "any between exact words backtracks")
    check(command([.any, .exact("x"), .any]).matches(argumentTail: ["x"])
            && command([.any, .exact("x"), .any]).matches(argumentTail: ["a", "x", "b"])
            && !command([.any, .exact("x"), .any]).matches(argumentTail: ["a", "b"]),
          "an exact word anywhere among anys")
    let glob = command([.pattern([lit("a"), .wildcard, lit("b"), .wildcard, lit("c")])])
    check(glob.matches(argumentTail: ["abc"]) && glob.matches(argumentTail: ["aXbYc"]) && glob.matches(argumentTail: ["abbc"])
            && !glob.matches(argumentTail: ["acb"]) && !glob.matches(argumentTail: ["abcX"]) && !glob.matches(argumentTail: ["Xabc"]),
          "a pattern is anchored at both ends and finds literals in order")
    check(command([.pattern([.wildcard])]).matches(argumentTail: [""]) && !command([.pattern([.wildcard])]).matches(argumentTail: []),
          "a lone wildcard pattern matches any one element, never zero")
    let pull = command([.exact("nimbus"), .pattern([lit("cd "), .wildcard, lit(" && git pull origin master")])])
    check(!pull.matches(argumentTail: ["nimbus", "rm -rf /"]),
          "the trojan case: a pattern from \"cd $D && git pull origin master\" does not match rm -rf /")
    check(pull.matches(argumentTail: ["nimbus", "cd /mnt/x && git pull origin master"])
            && pull.matches(argumentTail: ["nimbus", "cd  && git pull origin master"]),
          "the same pattern matches the command it was written for, empty expansion included")
    check(!pull.matches(argumentTail: ["nimbus", "cd /mnt/x && git pull origin master", "extra"])
            && !pull.matches(argumentTail: ["nimbus"]),
          "a pattern consumes exactly one element")
    let derived = commands("ssh nimbus \"cd $D && git pull origin master\"")?.first
    check(derived.map { !$0.matches(argumentTail: ["nimbus", "rm -rf /"])
            && $0.matches(argumentTail: ["nimbus", "cd /mnt/x && git pull origin master"]) } ?? false,
          "the trojan case, end to end from the text")
    check(!command([.exact("caf\u{E9}")]).matches(argumentTail: ["cafe\u{301}"]),
          "elements compare byte for byte, not by Unicode equivalence")
    let many = command(Array(repeating: .any, count: 40) + [.exact("end")])
    check(!many.matches(argumentTail: Array(repeating: "x", count: 200)) && many.matches(argumentTail: Array(repeating: "x", count: 200) + ["end"]),
          "many anys over many elements stays polynomial")
    let longGlob = command([.pattern(Array(repeating: [ShellPatternPiece.wildcard, lit("a")], count: 50).flatMap { $0 } + [lit("b")])])
    check(!longGlob.matches(argumentTail: [String(repeating: "a", count: 20_000)]),
          "a long glob over a long element stays linear")
}

// MARK: - Real-world shapes (synthetic)

private let haPush = """
    #!/usr/bin/env bash
    # Push the config and reload it on the server.
    set -euo pipefail
    source "$(dirname -- "${BASH_SOURCE[0]}")/_ha-common.sh"

    LOCAL_DIR="$HA_REPO_ROOT/config"
    REMOTE_DIR=/mnt/data/config
    reload_out="$(mktemp)"
    trap 'rm -f "$reload_out"' EXIT

    cd "$LOCAL_DIR"
    bin/ha-pull
    git push origin master
    ssh nimbus "cd $REMOTE_DIR && git pull origin master"
    if ! ha_api POST services/reload_all >"$reload_out"; then
      echo "reload failed" >&2
      exit 1
    fi

    """

private let haCommonHelpers = """

    _ha_is_reference() {
      case "${1:-}" in csec://*|op://*) return 0 ;; *) return 1 ;; esac
    }

    _ha_trim() {
      local val="$1"
      val="${val%"${val##*[!$'\\n']}"}"
      printf '%s' "$val"
    }

    _ha_export() {
      local v="$1" val="$2"
      printf -v "$v" '%s' "$val"
      export "${v?}"
    }

    ha_api() {
      local method="$1" path="$2" out rc=0 status data
      out="$(mktemp)"
      local -a args=(-sS --connect-timeout 10 -w '%{http_code}' -o "$out" -H "Authorization: Bearer $HA_TOKEN")
      status="$(curl "${args[@]}" -X "$method" "$HA_URL/api/$path")" || rc=$?
      if (( rc != 0 )); then
        echo "curl failed: $rc" >&2
        return "$rc"
      fi
      data="$(cat "$out")"
      if jq empty <<<"$data" 2>/dev/null; then
        jq . <<<"$data"
      fi
      [[ "$status" == 2* ]]
    }

    """

private let haCommonCurrent = """
    # shellcheck shell=bash
    # Shared helpers for the ha-* scripts; source it, do not run it.

    _ha_repo_root() { CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd; }
    HA_REPO_ROOT="$(_ha_repo_root)"

    if [[ -z "${HA_URL:-}" ]] && [[ -f "$HA_REPO_ROOT/.envrc" ]]; then
      # Read .envrc; then source it with every variable exported.
      set -a
      . "$HA_REPO_ROOT/.envrc" >/dev/null 2>&1 || true
      set +a
    fi

    """ + haCommonHelpers

private let haCommonInlined = """
    # shellcheck shell=bash
    # Shared helpers for the ha-* scripts; source it, do not run it.

    HA_REPO_ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

    if [[ -z "${HA_URL:-}" ]] && [[ -f "$HA_REPO_ROOT/.envrc" ]]; then
      # Read .envrc; then source it with every variable exported.
      set -a
      . "$HA_REPO_ROOT/.envrc" >/dev/null 2>&1 || true
      set +a
    fi

    """ + haCommonHelpers

private let nimbusssh = """
    #!/usr/bin/env bash
    set -exuo pipefail
    ssh nimbus "$@"

    """

private func launcherRealWorldTests() {
    for (name, text) in [("ha-push", haPush), ("_ha-common.sh (current)", haCommonCurrent),
                         ("_ha-common.sh (inlined)", haCommonInlined), ("nimbusssh", nimbusssh)] {
        check(commands(text) != nil, "the synthetic \(name) parses with no ERROR node")
    }
    check(commands("val=\"${val%\"${val##*[!$'\\n']}\"}\"") == []
            && commands("printf -v \"$v\" '%s' \"$val\"") != nil && commands("export \"${v?}\"") == []
            && commands("local -a args=(-sS -w '%{http_code}' -o \"$out\" -H \"Authorization: Bearer $T\")") == []
            && commands("status=\"$(curl \"${args[@]}\" \"$url\")\" || rc=$?") != nil
            && commands("if (( rc != 0 )); then exit 1; fi") != nil
            && commands("jq empty <<<\"$data\" 2>/dev/null") != nil
            && commands("case \"${1:-}\" in csec://*|op://*) return 0 ;; *) return 1 ;; esac") != nil,
          "each construct of the helpers parses on its own")
    check(shapes(haPush)?.contains("git push origin master") == true
            && shapes(haPush)?.contains("ssh nimbus <cd * && git pull origin master>") == true
            && shapes(nimbusssh) == ["set -exuo pipefail", "ssh nimbus <any>"],
          "the synthetic scripts' commands include their git push and ssh")
}
