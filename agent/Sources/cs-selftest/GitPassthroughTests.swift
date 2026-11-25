import ConvenientSecurity
import Foundation

// The Claude Code hook's git passthrough (`AICommandGitPassthrough`): which
// Bash commands reach Claude Code unwrapped, so its worktree guard can read
// the git they run; which of them register with csecd, marked unwrapped, so
// the SSH signing their git asks for can be delegated (those that reach a
// remote); what the hook prints and registers for each; and that the real zsh,
// running each unwrapped one the way Claude Code's Bash tool shell does, runs
// nothing but git, with every git argv one of the text's simple commands.

func gitPassthroughTests() async {
    print("\n# AICommandGitPassthrough (plain git commands reach Claude Code unwrapped)")
    var corpus: [String] = []

    func unwrapped(_ command: String, _ label: String) {
        corpus.append(command)
        let verdict = AICommandGitPassthrough.classify(command)
        check(verdict == .unwrapped(registersForDelegation: false),
              "passthrough: \(label) runs unwrapped and registers nothing (\(verdict))")
    }
    func delegable(_ command: String, _ label: String) {
        corpus.append(command)
        let verdict = AICommandGitPassthrough.classify(command)
        check(verdict == .unwrapped(registersForDelegation: true),
              "passthrough: \(label) runs unwrapped and registers for delegation (\(verdict))")
    }
    func wrapped(_ command: String, _ rejection: AICommandGitPassthrough.Rejection, _ label: String) {
        corpus.append(command)
        let verdict = AICommandGitPassthrough.classify(command)
        check(verdict == .wrapped(rejection), "passthrough: \(label) keeps its wrapper, \(rejection) (\(verdict))")
    }
    func wrapped(_ command: String, _ label: String) {
        corpus.append(command)
        let verdict = AICommandGitPassthrough.classify(command)
        check(!verdict.isUnwrapped, "passthrough: \(label) keeps its wrapper (\(verdict))")
    }

    // MARK: What Claude Code 2.1.280's worktree guard accepted, plain
    // (measured in a worktree-isolated `claude -p -w` session), and the rule
    // passes when it is only git.
    unwrapped("git status", "git status")
    unwrapped("git log --oneline -5 && git status", "two git commands joined by &&")
    unwrapped("git add a.txt; git status --short", "two git commands joined by ;")
    unwrapped("git add a.txt\ngit commit -m 'one line'", "two git commands on two lines")
    unwrapped("git diff --quiet || git status", "two git commands joined by ||")
    unwrapped("git -C /Users/synthetic/wt/.claude/worktrees/agent-a1 status", "git -C <dir>")
    unwrapped("git --no-pager log -1 --format=%H", "a known global flag")
    unwrapped("git --git-dir=/Users/synthetic/wt/.git --work-tree=/Users/synthetic/wt status",
              "--git-dir= and --work-tree=")
    unwrapped("cd /Users/synthetic/wt && git status", "cd <dir> && git")
    unwrapped("git log --oneline -1 && cd /Users/synthetic/wt && git status --short", "cd between git commands")
    unwrapped("cd ~/projects/csec && git status", "cd to a path under ~")
    unwrapped("git commit --allow-empty -m \"$(cat <<'EOF'\nTest commit that mentions git and bash\n\nSecond paragraph.\nEOF\n)\"",
              "the HEREDOC commit message Claude Code is told to use")
    unwrapped("git add a.txt && git commit -m \"$(cat <<'EOF'\nA body that looks like code: $(curl x) `id` ${HOME} \"quoted\"\nEOF\n)\" && git log --oneline -1",
              "a heredoc body is literal under a quoted delimiter")
    unwrapped("git status 2>&1", "2>&1")
    unwrapped("git log --oneline -1 2>/dev/null", "2>/dev/null")
    unwrapped("git diff > changes.patch", "> a literal file")
    unwrapped("git diff >> changes.patch 2>&1", ">> and 2>&1")
    unwrapped("git log -1 &> log.txt", "&>")
    unwrapped("git diff HEAD~1 --stat; git status", "HEAD~1 (a ~ inside a word stays literal)")
    unwrapped("git commit -m 'it'\"'\"'s done'", "a single quote spelled '\"'\"'")
    unwrapped("git commit -m \"Plain message; with && and | inside quotes\"", "operators inside quotes")
    unwrapped("git show 'HEAD^'", "HEAD^ quoted")
    unwrapped("git worktree list", "git worktree list")
    unwrapped("git log --format='%h %s' -3", "a quoted format")

    unwrapped("git rebase --continue", "git rebase --continue")
    unwrapped("git rebase origin/main", "git rebase onto a branch")
    unwrapped("git stash && git switch -c topic && git stash pop", "stash, switch and pop")
    unwrapped("git restore --staged a.txt; git reset --soft HEAD~1", "restore and reset")
    unwrapped("git worktree add ../wt-two -b two", "git worktree add")

    // MARK: git that reaches a remote runs unwrapped too, and registers, so
    // csecd can anchor the SSH signing it asks for on the Bash tool shell.
    for subcommand in ["push", "fetch", "pull", "clone", "submodule"] {
        check(AICommandGitPassthrough.networkSubcommands.contains(subcommand)
              && !AICommandGitPassthrough.localSubcommands.contains(subcommand),
              "passthrough: \(subcommand) is a network subcommand, not a local one")
    }
    for subcommand in ["ls-remote", "remote", "archive", "request-pull", "maintenance", "lfs", "svn", "fetch-pack",
                       "send-pack"] {
        check(!AICommandGitPassthrough.localSubcommands.contains(subcommand)
              && !AICommandGitPassthrough.networkSubcommands.contains(subcommand),
              "passthrough: \(subcommand) is neither a local nor a network subcommand")
    }
    delegable("git push", "git push")
    delegable("git  push  origin  main", "git push with doubled spaces")
    delegable("git push -u origin wt/csec-yi6t.3", "git push -u (--set-upstream, not a program)")
    delegable("git push --force-with-lease origin HEAD:refs/heads/topic", "a forced push with a refspec")
    delegable("git push --dry-run origin HEAD:refs/heads/probe", "a dry-run push")
    delegable("git -C /Users/synthetic/wt push -u origin feature", "git -C <dir> push")
    delegable("git fetch origin && git status", "git fetch then git status")
    delegable("git status && git fetch origin", "git status then git fetch")
    delegable("git fetch origin && git rebase origin/main", "fetch then rebase")
    delegable("git pull --ff-only", "git pull")
    delegable("git pull --rebase origin main", "git pull --rebase")
    delegable("git clone git@github.com:synthetic/repo.git", "git clone")
    delegable("git clone --depth 1 -b main git@github.com:synthetic/repo.git /Users/synthetic/wt/clone",
              "git clone with a branch and a target")
    delegable("git submodule update --init --recursive", "git submodule update")
    delegable("cd /Users/synthetic/wt && git push", "cd <dir> && git push")
    delegable("cd /Users/synthetic/wt && git add -A && git commit -m \"$(cat <<'EOF'\nShip it\nEOF\n)\" && git push",
              "add, commit with a heredoc, then push")
    delegable("git add a.txt && git commit -m 'one line' && git push -u origin HEAD", "add, commit, push")
    // A program the command line names keeps the wrapper on every network
    // subcommand, as on rebase and grep.
    wrapped("git push --receive-pack=/tmp/x origin main", .runsProgram("push --receive-pack"), "push --receive-pack")
    wrapped("git push --rec=/tmp/x origin main", .runsProgram("push --receive-pack"), "an abbreviated --receive-pack")
    wrapped("git push --exec=/tmp/x origin main", .runsProgram("push --exec"), "push --exec")
    wrapped("git fetch --upload-pack=/tmp/x origin", .runsProgram("fetch --upload-pack"), "fetch --upload-pack")
    wrapped("git fetch --upl /tmp/x origin", .runsProgram("fetch --upload-pack"), "an abbreviated --upload-pack")
    wrapped("git pull --upload-pack /tmp/x origin main", .runsProgram("pull --upload-pack"), "pull --upload-pack")
    wrapped("git clone -u /tmp/x git@github.com:synthetic/repo.git", .runsProgram("clone --upload-pack"), "clone -u")
    wrapped("git clone -qu /tmp/x git@github.com:synthetic/repo.git", .runsProgram("clone --upload-pack"),
            "clone -u in a short cluster")
    wrapped("git clone --template=/tmp/t git@github.com:synthetic/repo.git", .runsProgram("clone --template"),
            "clone --template (its hooks run)")
    wrapped("git clone -c core.hooksPath=/tmp/h git@github.com:synthetic/repo.git", .runsProgram("clone --config"),
            "clone -c")
    wrapped("git clone --config core.sshCommand=/tmp/x git@github.com:synthetic/repo.git", .runsProgram("clone --config"),
            "clone --config")
    wrapped("git submodule foreach 'git status'", .runsProgram("submodule foreach"), "submodule foreach")
    wrapped("git submodule --quiet foreach --recursive 'git status'", .runsProgram("submodule foreach"),
            "submodule foreach after an option")
    // The rest of git that reaches a remote keeps its wrapper. Claude Code's
    // auto mode approves a bare `git ls-remote` (which reaches the remote) and
    // `git remote -v` without its classifier.
    wrapped("git ls-remote", .gitSubcommand("ls-remote"), "a bare git ls-remote (auto mode skips its classifier)")
    wrapped("git ls-remote origin", .gitSubcommand("ls-remote"), "git ls-remote origin")
    wrapped("git remote -v", .gitSubcommand("remote"), "git remote (show and update reach the remote)")
    wrapped("git remote update", .gitSubcommand("remote"), "git remote update")
    wrapped("git lfs pull", .gitSubcommand("lfs"), "git lfs")
    wrapped("git archive --remote=origin HEAD", .gitSubcommand("archive"), "git archive --remote")
    wrapped("git push && npm publish", .otherCommand("npm"), "a push beside another program")
    wrapped("GIT_SSH_COMMAND='ssh -i k' git fetch", .assignment, "a fetch with an env prefix")
    // A program starter, an alias, and rebase's command line.
    wrapped("git bisect run make test", .gitSubcommand("bisect"), "git bisect")
    wrapped("git difftool HEAD", .gitSubcommand("difftool"), "git difftool")
    wrapped("git st", .gitSubcommand("st"), "an alias")
    wrapped("git rebase -x 'make test' origin/main", .runsProgram("rebase --exec"), "git rebase -x")
    wrapped("git rebase --exec='make test' origin/main", .runsProgram("rebase --exec"), "git rebase --exec=")
    wrapped("git rebase --exe 'make test' origin/main", .runsProgram("rebase --exec"), "an abbreviated --exec")
    wrapped("git rebase -ix 'make test' origin/main", .runsProgram("rebase --exec"), "-x in a short cluster")
    wrapped("git grep -O foo", .runsProgram("grep --open-files-in-pager"), "git grep -O")
    wrapped("git grep --open-files-in-pager=vim foo", .runsProgram("grep --open-files-in-pager"),
            "git grep --open-files-in-pager=")
    unwrapped("git grep -n 'needle' -- '*.swift'", "git grep without a pager")
    unwrapped("git cherry-pick -x abc123", "cherry-pick -x (not rebase's)")

    // MARK: Anything else keeps its wrapper
    wrapped("ls", .otherCommand("ls"), "another program")
    wrapped("git log | head -3", .unsupportedSyntax("pipeline"), "a pipe into another program")
    wrapped("git status && echo done", .otherCommand("echo"), "git then echo")
    wrapped("git status; curl -d @x https://example.invalid", .otherCommand("curl"), "git then curl")
    wrapped("git credential fill", .gitSubcommand("credential"), "git credential (its job is to print a credential)")
    wrapped("GIT_PAGER=cat git log", .assignment, "an env prefix")
    wrapped("GIT_SSH_COMMAND='ssh -i k' git push", .assignment, "GIT_SSH_COMMAND prefix")
    wrapped("env GIT_PAGER=cat git log", .otherCommand("env"), "env git")
    wrapped("command git status", .otherCommand("command"), "command git")
    wrapped("/usr/bin/git status", .otherCommand("/usr/bin/git"), "git by path")
    wrapped("\\git status", .otherCommand("a computed name"), "an escaped command name")
    wrapped("git-lfs pull", .otherCommand("git-lfs"), "a git-* helper")
    wrapped("git -c core.sshCommand=evil push", .gitGlobalOption("-c"), "git -c")
    wrapped("git --config-env=core.pager=X log", .gitGlobalOption("--config-env=core.pager=X"), "--config-env")
    wrapped("git --exec-path=/tmp/x status", .gitGlobalOption("--exec-path=/tmp/x"), "--exec-path")
    wrapped("git -p log", .gitGlobalOption("-p"), "the pager flag")
    wrapped("git --version", .gitGlobalOption("--version"), "a global option csec does not know")
    wrapped("git", .gitGlobalOption(""), "git with no subcommand")
    wrapped("git log $(cat secrets)", .nonLiteralWord(command: "git"), "a command substitution in an argument")
    wrapped("git log \"$HOME\"", .nonLiteralWord(command: "git"), "an expansion in an argument")
    wrapped("git log `id`", "a backquote substitution")
    wrapped("git log 'a''b'", .nonLiteralWord(command: "git"), "adjacent single quotes (zsh RC_QUOTES)")
    wrapped("git log =x", .nonLiteralWord(command: "git"), "a leading = (zsh's =cmd)")
    wrapped("git add *.swift", .nonLiteralWord(command: "git"), "a glob")
    wrapped("git diff HEAD^", .nonLiteralWord(command: "git"), "an unquoted ^ (EXTENDED_GLOB)")
    wrapped("git log {a,b}", .nonLiteralWord(command: "git"), "a brace expansion")
    wrapped("git commit -m \"$(cat <<EOF\nunquoted $HOME\nEOF\n)\"", .redirection("heredoc delimiter"),
            "a heredoc with an unquoted delimiter")
    wrapped("git commit -m \"$(cat <<\"EOF\"\nmsg\nEOF\n)\"", .redirection("heredoc delimiter"),
            "a heredoc with a double-quoted delimiter")
    wrapped("git commit -m \"$(cat <<-'EOF'\n\tmsg\n\tEOF\n)\"", "<<- (tab-stripping)")
    wrapped("git commit -m \"$(cat x <<'EOF'\nmsg\nEOF\n)\"", .nonLiteralWord(command: "git"), "cat with an argument")
    wrapped("git commit -m \"$(sh <<'EOF'\nid\nEOF\n)\"", .nonLiteralWord(command: "git"),
            "another program reading the heredoc")
    wrapped("git commit -m \"$(cat <<'EOF'\nmsg\nEOF\n) and more\"", "text beside the substitution")
    wrapped("git commit -m \"$(cat <<'EOF'\nmsg\nEOF\n)\" ; id", .otherCommand("id"), "a command after the heredoc")
    wrapped("git commit -F - <<'EOF'\nmsg\nEOF", .redirection("heredoc_redirect"), "a heredoc fed to git")
    wrapped("git apply < x.patch", .redirection("<"), "an input redirection")
    wrapped("git log <<< x", "a here-string")
    wrapped("git log > out --oneline", .redirection(">"), "a word after a redirection's target")
    wrapped("git log >&out", .redirection(">& onto a file"), ">& onto a file")
    wrapped("git log > \"$OUT\"", .redirection(">"), "a computed redirection target")
    wrapped("git status &", .unsupportedSyntax("&"), "a background job")
    wrapped("(cd /tmp && git status)", .unsupportedSyntax("subshell"), "a subshell")
    wrapped("{ git status; }", .unsupportedSyntax("compound_statement"), "a group")
    wrapped("git status # look", .unsupportedSyntax("comment"), "a comment")
    wrapped("! git diff --quiet", .unsupportedSyntax("negated_command"), "a negation")
    wrapped("cd", .cdOperand, "cd with no operand")
    wrapped("cd - && git status", .cdOperand, "cd -")
    wrapped("cd a b && git status", .cdOperand, "cd with two operands")
    wrapped("cd \"$HOME\" && git status", .cdOperand, "cd to an expansion")
    wrapped("cd /tmp", .noGit, "cd alone")
    wrapped("git status\r", "a carriage return")
    wrapped("git status\u{00A0}x", "a non-breaking space")
    wrapped("git log \\\nx", "a line continuation")
    wrapped("for b in a; do git log $b; done", "a loop")

    // MARK: csecd reads each command back off the Bash tool shell
    claudeToolShellTests(corpus: corpus)

    // MARK: The real zsh runs only git, as Claude Code's Bash tool shell does
    gitPassthroughZshDifferentialTests(corpus: corpus)

    await gitPassthroughHookTests()
}

// MARK: - The Bash tool shell

/// The script Claude Code 2.1.280's Bash tool shell runs for `command`, exactly
/// as `ps -ww` showed it on this Mac: the command single-quoted, each `'`
/// spelled `'"'"'`, inside one `eval`.
func claudeToolShellScript(
    _ command: String,
    snapshot: String = "/Users/synthetic/.claude/shell-snapshots/snapshot-zsh-1791848598521-4wb3kj.sh",
    cwdFile: String = "/tmp/claude-87c6-cwd",
    stdinFromNull: Bool? = nil
) -> String {
    let quoted = "'" + command.replacingOccurrences(of: "'", with: "'\"'\"'") + "'"
    // Claude Code leaves out `< /dev/null` for a command holding a heredoc, a
    // here-string or an input redirection (measured: `eval 'x <<'"'"'EOF'…`).
    let redirect = (stdinFromNull ?? !command.contains("<")) ? " < /dev/null" : ""
    return "source \(snapshot) 2>/dev/null || true && setopt NO_EXTENDED_GLOB NO_BARE_GLOB_QUAL 2>/dev/null || true"
        + " && { \\builtin unalias -- 'unsetenv'; \\builtin unset -f -- 'unsetenv'; } >/dev/null 2>&1 || true"
        + " && eval \(quoted)\(redirect) && pwd -P >| \(cwdFile)"
}

/// The Bash tool shell's argv for `command`.
func claudeToolShellArgv(_ command: String) -> [String] {
    ["/bin/zsh", "-c", claudeToolShellScript(command)]
}

/// `ClaudeToolShell`: csecd reads back, off the tool shell's kernel argv,
/// exactly the command the hook saw, or nothing.
private func claudeToolShellTests(corpus: [String]) {
    print("\n# ClaudeToolShell (the command a Bash tool shell evaluates)")
    let measured = "source /Users/alex/.claude/shell-snapshots/snapshot-zsh-1791848598521-4wb3kj.sh 2>/dev/null || true"
        + " && setopt NO_EXTENDED_GLOB NO_BARE_GLOB_QUAL 2>/dev/null || true && { \\builtin unalias -- 'unsetenv';"
        + " \\builtin unset -f -- 'unsetenv'; } >/dev/null 2>&1 || true && eval 'csec ai -- '\"'\"'ps -ww -o args= -p 74675"
        + " 2>/dev/null || true'\"'\"'' < /dev/null && pwd -P >| /tmp/claude-87c6-cwd"
    check(ClaudeToolShell.program(executablePath: "/bin/zsh", argv: ["/bin/zsh", "-c", measured])
            == "csec ai -- 'ps -ww -o args= -p 74675 2>/dev/null || true'",
          "tool shell: the script measured with ps reads back as the hook's command")
    // Every command of the passthrough corpus, wrapped or not, reads back
    // byte for byte through Claude Code's quoting.
    let extra = ["git log 'a''b'", "git commit -m ''", "'", "''", "x'", "git commit -m \"it's\" && git push",
                 "git commit -m \"$(cat <<'EOF'\nquote ' and '' and \\ and $HOME\nEOF\n)\" && git push"]
    var lost: [String] = []
    for command in corpus + extra {
        for stdinFromNull in [true, false] {
            let argv = ["/bin/zsh", "-c", claudeToolShellScript(command, stdinFromNull: stdinFromNull)]
            if ClaudeToolShell.program(executablePath: "/bin/zsh", argv: argv) != command { lost.append(command) }
        }
    }
    // A command of one plain word reaches eval unquoted.
    check(ClaudeToolShell.program(executablePath: "/bin/zsh", argv: [
        "/bin/zsh", "-c", "source /dev/null 2>/dev/null || true && eval /usr/bin/true < /dev/null && pwd -P >| /tmp/x",
    ]) == "/usr/bin/true", "tool shell: a one-word command Claude Code leaves unquoted reads back")
    check(lost.isEmpty, "tool shell: every corpus command reads back exactly, with and without < /dev/null "
        + "(\(corpus.count + extra.count) commands)"
        + (lost.isEmpty ? "" : ": \(lost.prefix(5).map(\.debugDescription))"))

    let script = claudeToolShellScript("git push")
    for (label, path, argv) in [
        ("another shell", "/bin/bash", ["/bin/bash", "-c", script]),
        ("zsh by another path", "/usr/local/bin/zsh", ["/usr/local/bin/zsh", "-c", script]),
        ("-lc in place of -c", "/bin/zsh", ["/bin/zsh", "-lc", script]),
        ("an extra argument", "/bin/zsh", ["/bin/zsh", "-c", script, "x"]),
        ("no script", "/bin/zsh", ["/bin/zsh", "-c"]),
        ("a second eval", "/bin/zsh", ["/bin/zsh", "-c", script + "; eval 'git status'"]),
        ("a second eval behind an assignment", "/bin/zsh", ["/bin/zsh", "-c", script + "; X=1 eval 'git status'"]),
        ("a second eval behind builtin", "/bin/zsh", ["/bin/zsh", "-c", script + "; builtin eval 'git status'"]),
        ("a second eval behind \\builtin and options", "/bin/zsh",
         ["/bin/zsh", "-c", script + "; \\builtin -- eval 'git status'"]),
        ("an escaped second eval", "/bin/zsh", ["/bin/zsh", "-c", script + "; \\eval 'git status'"]),
        ("a computed command name", "/bin/zsh", ["/bin/zsh", "-c", script + "; $cmd 'git status'"]),
        ("no eval", "/bin/zsh", ["/bin/zsh", "-c", "git push < /dev/null && pwd -P >| /tmp/x"]),
        ("an eval with two words", "/bin/zsh", ["/bin/zsh", "-c", "eval 'git push' 'x'"]),
        ("an eval of an expansion", "/bin/zsh", ["/bin/zsh", "-c", "eval \"$CMD\""]),
        ("an eval of a double-quoted $", "/bin/zsh", ["/bin/zsh", "-c", "eval \"git push $X\""]),
        ("an eval behind an assignment", "/bin/zsh", ["/bin/zsh", "-c", "X=1 eval 'git push'"]),
        ("an eval with a here-string", "/bin/zsh", ["/bin/zsh", "-c", "eval 'git push' <<< x"]),
        ("an empty eval", "/bin/zsh", ["/bin/zsh", "-c", "eval ''"]),
        ("a script that does not parse", "/bin/zsh", ["/bin/zsh", "-c", "eval 'git push' && ("]),
        ("the credential-scrub framing's \\builtin eval probe", "/bin/zsh",
         ["/bin/zsh", "-c", "\\builtin eval 'true' 2>/dev/null; " + script]),
    ] {
        check(ClaudeToolShell.program(executablePath: path, argv: argv) == nil, "tool shell: \(label) is not one")
    }
    check(ClaudeToolShell.program(executablePath: "/bin/zsh", argv: nil) == nil
          && ClaudeToolShell.program(executablePath: nil, argv: claudeToolShellArgv("git push")) == nil,
          "tool shell: an unreadable path or argv is not one")

    // A real `/bin/zsh -c` started with the framing: csecd's read of its
    // kernel argv gives the command back.
    let files = FileManager.default
    let root = files.temporaryDirectory.appendingPathComponent("csec-tool-shell-\(UUID().uuidString)")
    defer { try? files.removeItem(at: root) }
    try? files.createDirectory(at: root, withIntermediateDirectories: true)
    let command = "sleep 30"
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/zsh")
    process.arguments = ["-c", claudeToolShellScript(
        command, snapshot: "/dev/null", cwdFile: root.appendingPathComponent("cwd").path
    )]
    process.environment = ["PATH": "/usr/bin:/bin", "HOME": root.path, "ZDOTDIR": root.path]
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    guard (try? process.run()) != nil else {
        check(false, "tool shell: a real zsh starts with the framing")
        return
    }
    let provider = LiveClaudeSessionFactProvider()
    let shell = provider.incarnation(of: process.processIdentifier)
    let read = shell.flatMap { shell in
        ClaudeToolShell.program(executablePath: provider.executablePath(of: shell), argv: provider.argv(of: shell))
    }
    process.terminate()
    process.waitUntilExit()
    check(read == command, "tool shell: a real zsh's kernel argv reads back as its command (\(read ?? "nil"))")
}

// MARK: - The hook's output

private let passthroughCsecPath = "/Applications/ConvenientSecurity.app/Contents/MacOS/csec"

private func passthroughHookInput(_ command: String, permissionMode: String = "auto", agentID: Any? = nil) -> Data {
    var object: [String: Any] = [
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": ["command": command, "description": "synthetic"],
        "permission_mode": permissionMode,
        "session_id": "0f3c2a4e-1b2d-4c6e-8f90-a1b2c3d4e5f6",
        "tool_use_id": "toolu_01ABCdef_ghi-J",
        "cwd": "/Users/synthetic/project",
    ]
    if let agentID { object["agent_id"] = agentID }
    return (try? JSONSerialization.data(withJSONObject: object)) ?? Data()
}

private final class PassthroughRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: [AgentCommandRegistration] = []
    var all: [AgentCommandRegistration] { lock.withLock { stored } }
    func append(_ value: AgentCommandRegistration) { lock.withLock { stored.append(value) } }
}

private func gitPassthroughHookTests() async {
    // Claude: a plain list of local git commands prints nothing, so Claude
    // Code runs it as is, and registers nothing.
    for command in [
        "git status", "git log --oneline -5 && git status", "cd /Users/synthetic/wt && git status",
        "git add a.txt && git commit -m \"$(cat <<'EOF'\nmsg\nEOF\n)\"",
    ] {
        let result = try? AICommandHook.rewriteWithContext(
            input: passthroughHookInput(command), client: .claude, csecExecutablePath: passthroughCsecPath)
        check(result?.output.isEmpty == true && result?.registration == nil,
              "passthrough hook: \(command.debugDescription) prints nothing and registers nothing for Claude Code")
        let rewrite = try? AICommandHook.rewrite(
            input: passthroughHookInput(command), client: .claude, csecExecutablePath: passthroughCsecPath)
        check(rewrite?.isEmpty == true, "passthrough hook: rewrite agrees for \(command.debugDescription)")
    }
    let quiet = PassthroughRecorder()
    let printed = try? AICommandHook.output(
        input: passthroughHookInput("git status"), client: .claude, csecExecutablePath: passthroughCsecPath,
        register: { quiet.append($0) })
    check(printed?.isEmpty == true && quiet.all.isEmpty,
          "passthrough hook: git status calls no registrar and prints nothing")

    // git that reaches a remote prints nothing too, and registers the command
    // exactly as typed (the text the Bash tool shell's eval runs: no space
    // normalising, unlike a bare `csec ai` word), marked unwrapped, before
    // the hook returns.
    for command in ["git push", "git  push origin  main", "git fetch origin && git status",
                    "git add a.txt && git commit -m \"$(cat <<'EOF'\nmsg\nEOF\n)\" && git push -u origin HEAD"] {
        let received = PassthroughRecorder()
        let output = try? AICommandHook.output(
            input: passthroughHookInput(command), client: .claude, csecExecutablePath: passthroughCsecPath,
            register: { received.append($0) })
        check(output?.isEmpty == true
              && received.all.count == 1
              && received.all.first?.unwrapped == true
              && received.all.first?.programSHA256 == AICommandHook.programDigest(command)
              && received.all.first?.permissionMode == "auto"
              && received.all.first?.toolUseID == "toolu_01ABCdef_ghi-J",
              "passthrough hook: \(command.debugDescription) prints nothing and registers itself, unwrapped")
    }
    // In every permission mode (csecd declines the others with a reason).
    let defaultMode = try? AICommandHook.rewriteWithContext(
        input: passthroughHookInput("git push", permissionMode: "default"), client: .claude,
        csecExecutablePath: passthroughCsecPath)
    check(defaultMode?.output.isEmpty == true && defaultMode?.registration?.permissionMode == "default"
          && defaultMode?.registration?.unwrapped == true,
          "passthrough hook: an unwrapped git push registers in default mode too")
    // A subagent's id is carried; a malformed one registers nothing, and the
    // command still runs unwrapped.
    let subagent = try? AICommandHook.rewriteWithContext(
        input: passthroughHookInput("git push", agentID: "agent-7f3a"), client: .claude,
        csecExecutablePath: passthroughCsecPath)
    check(subagent?.output.isEmpty == true && subagent?.registration?.agentID == "agent-7f3a",
          "passthrough hook: a subagent's unwrapped git push registers with its agent id")
    let malformed = try? AICommandHook.rewriteWithContext(
        input: passthroughHookInput("git push", agentID: 7), client: .claude, csecExecutablePath: passthroughCsecPath)
    check(malformed?.output.isEmpty == true && malformed?.registration == nil,
          "passthrough hook: a malformed agent id registers nothing and leaves git push unwrapped")
    // A program the command line names keeps its wrapper and its wrapped
    // registration.
    let program = try? AICommandHook.rewriteWithContext(
        input: passthroughHookInput("git push --receive-pack=/tmp/x origin"), client: .claude,
        csecExecutablePath: passthroughCsecPath)
    check(program.flatMap { passthroughUpdatedCommand($0.output) }?.hasPrefix("csec ai -- ") == true
          && program?.registration?.unwrapped == false,
          "passthrough hook: push --receive-pack keeps its csec ai wrapper and a wrapped registration")

    // Anything mixed with another program is wrapped exactly as before.
    let mixed = try? AICommandHook.rewriteWithContext(
        input: passthroughHookInput("git status && npm test"), client: .claude, csecExecutablePath: passthroughCsecPath)
    check(mixed.flatMap { passthroughUpdatedCommand($0.output) } == "csec ai -- 'git status && npm test'"
          && mixed?.registration?.programSHA256 == AICommandHook.programDigest("git status && npm test")
          && mixed?.registration?.unwrapped == false,
          "passthrough hook: git mixed with another program keeps its csec ai wrapper and registration")

    // Codex has no worktree guard: its git commands keep the wrapper.
    for command in ["git status", "git log --oneline -1", "git push"] {
        let codex = try? AICommandHook.rewriteWithContext(
            input: passthroughHookInput(command), client: .codex, csecExecutablePath: passthroughCsecPath)
        check(codex.flatMap { passthroughUpdatedCommand($0.output) } == "csec ai -- \(command)"
              && codex?.registration == nil,
              "passthrough hook: Codex keeps wrapping \(command.debugDescription)")
    }
}

private func passthroughUpdatedCommand(_ output: Data) -> String? {
    guard let object = (try? JSONSerialization.jsonObject(with: output)) as? [String: Any],
          let specific = object["hookSpecificOutput"] as? [String: Any],
          let updated = specific["updatedInput"] as? [String: Any] else { return nil }
    return updated["command"] as? String
}

// MARK: - The real zsh

/// Runs every unwrapped command of the corpus under the real `/bin/zsh -c`,
/// as Claude Code's Bash tool shell evaluates it, with only sentinel `git`
/// and `cat` on `PATH`, every builtin zsh lets a function shadow recorded
/// (`eval` and `source` included), and a `command_not_found_handler`
/// recording anything else. Each must have run only `git`, the `cat` of its
/// heredoc, and `cd`. It runs with empty startup files and with a `.zshenv`
/// that turns on the options that change how words expand. For a command that
/// registers for delegation, every git it ran must also match one of the
/// command's simple commands (`ShellSimpleCommand.matches`), so
/// `LauncherScript`'s reading of the text agrees with what zsh runs.
private func gitPassthroughZshDifferentialTests(corpus: [String]) {
    print("\n# AICommandGitPassthrough differential (each unwrapped command under the real zsh)")
    let zsh = "/bin/zsh"
    let files = FileManager.default
    let root = files.temporaryDirectory.appendingPathComponent("csec-git-passthrough-\(UUID().uuidString)")
    defer { try? files.removeItem(at: root) }
    let bin = root.appendingPathComponent("bin")
    let plain = root.appendingPathComponent("zdot")
    let hostile = root.appendingPathComponent("zdot-hostile")
    let work = root.appendingPathComponent("work")
    let logs = root.appendingPathComponent("logs")
    do {
        for directory in [bin, plain, hostile, work, logs] {
            try files.createDirectory(at: directory, withIntermediateDirectories: true)
        }
        let sentinel = #"""
            #!/bin/sh
            r=$(printf '%s' "${0##*/}"; for a in "$@"; do printf '\037%s' "$a"; done; printf '\036')
            printf '%s' "$r" >> "$CSEC_DIFF_LOG"
            """#
        for name in ["git", "cat"] {
            let path = bin.appendingPathComponent(name).path
            try Data((sentinel + "\n").utf8).write(to: URL(fileURLWithPath: path))
            try files.setAttributes([.posixPermissions: 0o755], ofItemAtPath: path)
        }
        let recorder = #"""
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
        try Data((recorder + "\n").utf8).write(to: plain.appendingPathComponent(".zshenv"))
        try Data(("setopt extendedglob globsubst shwordsplit magicequalsubst rcquotes nullglob\n" + recorder + "\n").utf8)
            .write(to: hostile.appendingPathComponent(".zshenv"))
    } catch {
        check(false, "the passthrough differential sets up its sentinels (\(error))")
        return
    }

    let commands = corpus.filter { AICommandGitPassthrough.classify($0).isUnwrapped }
    check(commands.count >= 25, "the passthrough differential has the corpus's unwrapped commands (\(commands.count))")
    // The harness itself: a builtin, a missing program and a hidden eval are
    // each recorded, so a passthrough command that ran one would fail.
    let controls = [
        ("git status && echo done", "echo"), ("git log `id`", "id"), ("eval 'git status'", "eval"),
        ("source /dev/null; git status", "source"),
    ]
    var failures: [String] = []
    var controlFailures: [String] = []
    var mismatches: [String] = []
    var delegableRuns = 0
    let runs = commands.map { ($0, false) } + controls.map { ($0.0, true) }
    for (mode, startup) in [("empty startup files", plain), ("a hostile .zshenv", hostile)] {
        for (index, (command, isControl)) in runs.enumerated() {
            let log = logs.appendingPathComponent("\(startup.lastPathComponent)-\(index).log")
            files.createFile(atPath: log.path, contents: Data())
            let process = Process()
            process.executableURL = URL(fileURLWithPath: zsh)
            process.arguments = ["-c", command]
            process.currentDirectoryURL = work
            process.environment = [
                "PATH": bin.path, "CSEC_DIFF_LOG": log.path, "HOME": work.path, "ZDOTDIR": startup.path,
                "LANG": "en_US.UTF-8",
            ]
            process.standardInput = FileHandle.nullDevice
            process.standardOutput = FileHandle.nullDevice
            process.standardError = FileHandle.nullDevice
            let exited = DispatchSemaphore(value: 0)
            process.terminationHandler = { _ in exited.signal() }
            guard (try? process.run()) != nil else {
                failures.append("\(mode): \(command.debugDescription) did not start")
                continue
            }
            if exited.wait(timeout: .now() + 20) == .timedOut {
                process.terminate()
                failures.append("\(mode): \(command.debugDescription) timed out")
                continue
            }
            let records = ((try? Data(contentsOf: log)) ?? Data()).split(separator: 0x1E).map { record in
                record.split(separator: 0x1F, omittingEmptySubsequences: false).map { String(decoding: $0, as: UTF8.self) }
            }
            let ranGit = records.contains { $0.first == "git" }
            let others = records.filter { !["git", "cat", "cd"].contains($0.first ?? "") }
            if isControl {
                let expected = controls.first { $0.0 == command }?.1
                if !others.contains(where: { $0.first == expected }) {
                    controlFailures.append("\(mode): \(command.debugDescription) recorded \(records)")
                }
                continue
            }
            if !ranGit && !command.hasPrefix("cd ") { failures.append("\(mode): \(command.debugDescription) ran no git") }
            if !others.isEmpty { failures.append("\(mode): \(command.debugDescription) ran \(others)") }
            if AICommandGitPassthrough.classify(command).registersForDelegation {
                delegableRuns += 1
                let texts = LauncherScript.simpleCommands(in: command) ?? []
                for record in records where record.first == "git" {
                    let tail = Array(record.dropFirst())
                    let matched = texts.contains { text in text.name == "git" && text.matches(argumentTail: tail) }
                    if !matched { mismatches.append("\(mode): \(command.debugDescription) ran git \(tail)") }
                }
            }
        }
    }
    check(controlFailures.isEmpty,
          "the passthrough differential records a builtin, a missing program and a hidden eval"
              + (controlFailures.isEmpty ? "" : ": \(controlFailures.prefix(3))"))
    check(failures.isEmpty,
          "every unwrapped command ran only git (and its heredoc's cat) under the real zsh, with and without a hostile .zshenv"
              + (failures.isEmpty ? "" : ": \(failures.prefix(5))"))
    check(delegableRuns >= 30 && mismatches.isEmpty,
          "every git a registering command ran under the real zsh matches one of its text's simple commands "
              + "(\(delegableRuns) runs)" + (mismatches.isEmpty ? "" : ": \(mismatches.prefix(5))"))
}
