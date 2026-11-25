import ConvenientSecurity
import Foundation

// The Claude Code hook's worktree escape check (`AICommandWorktreeEscape`):
// when a session or subagent is isolated in a Claude Code worktree, a wrapped
// command that names git is refused unless its git can only run, directly, in
// that worktree. Covers how isolation is detected, how git is named, each rule,
// the three escapes csec-jmjy measured, the shapes Claude Code's own guard
// lets an isolated agent run, the hook's denial, and that the real zsh runs
// every accepted command's git in the worktree with no git variable set.

private let escapeWorktree = "/Users/synthetic/repo/.claude/worktrees/agent-a1b2c3"

/// No directory exists but the main checkout, its worktrees, `src` and
/// `agent/Sources` in the worktree, and `link`, a symbolic link in the
/// worktree to the main checkout.
private let escapeDirectories: Set<String> = [
    "/Users/synthetic/repo", "/Users/synthetic/repo/.claude/worktrees", escapeWorktree, escapeWorktree + "/src",
    escapeWorktree + "/agent", escapeWorktree + "/agent/Sources",
]
private let escapeEnvironment = AICommandWorktreeEscape.Environment(
    isDirectory: { escapeDirectories.contains(($0 as NSString).standardizingPath) },
    cdpath: [],
    realPath: { path in
        let standardized = (path as NSString).standardizingPath
        if standardized == escapeWorktree + "/link" { return "/Users/synthetic/repo" }
        return escapeDirectories.contains(standardized) ? standardized : nil
    }
)

func worktreeEscapeTests() {
    print("\n# AICommandWorktreeEscape (git stays in a worktree-isolated session's worktree)")
    var accepted: [String] = []

    // MARK: Isolation, as Claude Code 2.1.280 reports it to a hook.
    typealias Isolation = AICommandWorktreeEscape.Isolation
    let probe5 = "/private/tmp/jmjy/repo/.claude/worktrees/probe5"
    let probe5Transcript = "/Users/alex/.claude/projects/-private-tmp-jmjy-repo--claude-worktrees-probe5/45eb.jsonl"
    let longRoot = "/Users/synthetic/" + String(repeating: "deep-directory-name/", count: 10) + "repo/.claude/worktrees/w1"
    let longProject = String(longRoot.map { $0.isLetter || $0.isNumber ? $0 : "-" }.prefix(200)) + "-1x2y3z"
    let isolations: [(Any?, Any?, Any?, Isolation, String)] = [
        (escapeWorktree, nil, "a1b2c3", .inWorktree(root: escapeWorktree), "an isolated subagent's worktree"),
        (probe5, probe5Transcript, nil, .inWorktree(root: probe5), "a claude -w session in its worktree"),
        (escapeWorktree + "/agent/Sources", nil, nil, .inWorktree(root: escapeWorktree),
         "a directory inside the worktree"),
        ("/private/tmp", probe5Transcript, nil, .outsideWorktree,
         "a -w session whose cwd moved to /tmp (its transcript names its worktree)"),
        ("/private/tmp/jmjy/repo", probe5Transcript, nil, .outsideWorktree,
         "a -w session whose cwd moved to the main checkout"),
        ("/private/tmp/jmjy/repo/.claude/worktrees/agent-zz", probe5Transcript, nil, .outsideWorktree,
         "a -w session whose cwd moved into another agent's worktree"),
        ("/private/tmp/jmjy/repo/.claude/worktrees/agent-a9", probe5Transcript, "a9", .inWorktree(
            root: "/private/tmp/jmjy/repo/.claude/worktrees/agent-a9"), "a -w session's isolated subagent"),
        (longRoot + "/src", "/Users/alex/.claude/projects/\(longProject)/t.jsonl", nil, .inWorktree(root: longRoot),
         "a worktree whose project directory name Claude Code cut to 200 characters"),
        (nil, nil, nil, .outsideWorktree, "no cwd (fail closed)"),
        ("", nil, nil, .outsideWorktree, "an empty cwd (fail closed)"),
        (7, nil, nil, .outsideWorktree, "a cwd that is not a string (fail closed)"),
        ("/Users/synthetic/repo", "/Users/alex/.claude/projects/-Users-synthetic-repo/1.jsonl", nil, .none,
         "not isolated: the main checkout"),
        ("/Users/synthetic/repo/.claude/worktrees", nil, nil, .none, "not isolated: the worktrees directory"),
        ("/Users/synthetic/worktrees/repo/csec-x", nil, nil, .none, "not isolated: a worktree Claude Code did not make"),
        ("/Users/synthetic/repo/.claude/worktreesX/a", nil, nil, .none, "not isolated: a look-alike directory"),
        ("/private/tmp", "/Users/alex/.claude/projects/-private-tmp/2.jsonl", nil, .none,
         "not isolated: a session that started in /tmp"),
    ]
    for (cwd, transcript, agent, expected, label) in isolations {
        let isolation = AICommandWorktreeEscape.isolation(workingDirectory: cwd, transcriptPath: transcript, agentID: agent)
        check(isolation == expected, "worktree escape: \(label) is \(expected) (\(isolation))")
    }
    check(AICommandWorktreeEscape.refusal(for: "git status | cat", isolation: .outsideWorktree,
                                          workingDirectory: "/private/tmp", environment: escapeEnvironment)
            == .outsideWorktree
          && AICommandWorktreeEscape.refusal(for: "ls | cat", isolation: .outsideWorktree,
                                             workingDirectory: "/private/tmp", environment: escapeEnvironment) == nil
          && AICommandWorktreeEscape.refusal(for: "env git push", isolation: .none,
                                             workingDirectory: "/Users/synthetic/repo", environment: escapeEnvironment)
            == nil,
          "worktree escape: outside its worktree git is refused and other commands pass; unisolated, nothing is checked")

    // MARK: Naming git, as Claude Code's guard reads it.
    for text in ["git status", "true&&git push", "env git push", "/usr/bin/git status", "gi''t push", "g\\it push",
                 "GIT push", "git-lfs pull", "git.exe status", "x;git", "echo $(git rev-parse HEAD)", "git-upload-pack x"] {
        check(AICommandWorktreeEscape.namesGit(text), "worktree escape: \(text.debugDescription) names git")
    }
    for text in ["cat .gitignore", "ls .github", "echo digit", "rg AICommandGitPassthrough", "open github.com",
                 "gitk", "git-2", "GIT_DIR=/x make", "legit", "cd /x && make"] {
        check(!AICommandWorktreeEscape.namesGit(text), "worktree escape: \(text.debugDescription) does not name git")
    }

    func refusal(_ command: String) -> AICommandWorktreeEscape.Refusal? {
        AICommandWorktreeEscape.refusal(
            for: command, isolation: .inWorktree(root: escapeWorktree), workingDirectory: escapeWorktree,
            environment: escapeEnvironment)
    }
    func allowed(_ command: String, _ label: String) {
        accepted.append(command)
        let result = refusal(command)
        check(result == nil, "worktree escape: allows \(label) (\(result.map { "\($0)" } ?? "allowed"))")
    }
    func refused(_ command: String, _ expected: AICommandWorktreeEscape.Refusal, _ label: String) {
        let result = refusal(command)
        check(result == expected, "worktree escape: refuses \(label), \(expected) (\(result.map { "\($0)" } ?? "allowed"))")
    }
    func refused(_ command: String, _ label: String) {
        let result = refusal(command)
        check(result != nil, "worktree escape: refuses \(label) (\(result.map { "\($0)" } ?? "allowed"))")
    }

    // MARK: The escapes csec-jmjy measured, wrapped, and their kin.
    refused("cd /Users/synthetic/repo && git commit -m x && git push origin main && echo done", .shellState("cd"),
            "cd to the shared checkout before git, mixed with another program")
    refused("env git push", .launchesGit("env"), "env git push")
    refused("env -C /Users/synthetic/repo git push", .launchesGit("env"), "env -C <shared> git push")
    refused("pushd /Users/synthetic/repo; git status; popd", .shellState("pushd"), "pushd")
    refused("chdir /x; git status | cat", .shellState("chdir"), "zsh chdir")
    refused("export GIT_DIR=/Users/synthetic/repo/.git; git status | cat", .assignment, "export GIT_DIR")
    refused("export GIT_DIR; git status | cat", .assignment, "export of a name")
    refused("PATH=/x:$PATH swift build && git status | cat", .assignment, "PATH before a program")
    refused("HOME=/x npm test && git status | cat", .assignment, "HOME before a program")
    refused("FOO=1 git status | cat", .assignment, "an assignment before git")
    refused("FOO=1 echo hi; git status | cat", .assignment, "an assignment before a builtin")
    refused("path=(/x $path); git status | cat", "zsh's path array")
    refused("commands[git]=/tmp/x; git status | cat", "zsh's commands table")
    refused("commands[gh]=/tmp/x; git status | cat", .assignment, "an assignment to a subscript")
    refused("export -n FOO; git status | cat", .assignment, "export with an option")
    refused("X='cd /x && git push'; sh -c \"$X\"", .mentionFlows("a variable"), "git text in a variable")
    refused("X=$(echo git push) && sh -c \"$X\"", .mentionFlows("a variable"), "a substitution naming git in a variable")
    refused("GIT_DIR=/Users/synthetic/repo/.git git status | cat", .assignment, "a GIT_DIR prefix assignment")
    refused("GIT_WORK_TREE=/x; git status | cat", .assignment, "a bare assignment")
    refused("typeset -x GIT_DIR=/x; git status | cat", .assignment, "typeset -x")
    refused("source ./env.sh && git status | cat", .shellState("source"), "source")
    refused(". ./env.sh && git status | cat", .shellState("."), "the . builtin")
    refused("eval 'git push'", .shellState("eval"), "eval")
    refused("exec git push", .shellState("exec"), "exec git")
    refused("command git push", .shellState("command"), "command git")
    refused("builtin cd /x; git status | cat", .shellState("builtin"), "builtin cd")
    refused("noglob cd /x; git status | cat", .shellState("noglob"), "noglob cd")
    refused("setopt autocd; git status | cat", .shellState("setopt"), "setopt")
    refused("set -a; git status | cat", .shellState("set"), "set -a")
    refused("emulate sh; git status | cat", .shellState("emulate"), "emulate")
    refused("alias git='git -C /x'; git status | cat", .shellState("alias"), "an alias")
    refused("hash -d s=/Users/synthetic/repo; git status | cat", .shellState("hash"), "hash -d")
    refused("time git push", .shellState("time"), "time git")
    refused("trap 'cd /x' DEBUG; git status | cat", .shellState("trap"), "trap")
    refused("f() { git push; }; f", .unsupportedSyntax("a function definition"), "a function definition")
    refused("xargs git push < refs.txt", .launchesGit("xargs"), "xargs git")
    refused("find . -name .git -execdir git status \\;", .launchesGit("find"), "find -execdir git")
    refused("sh -c 'cd /Users/synthetic/repo && git push'", .launchesGit("sh"), "sh -c with cd and git")
    refused("bash -lc \"git push\"", .launchesGit("bash"), "bash -lc git")
    refused("nohup git push &", .launchesGit("nohup"), "nohup git")
    refused("sudo git push", .launchesGit("sudo"), "sudo git")
    refused("timeout 5 git fetch", .launchesGit("timeout"), "timeout git")
    refused("swift run tool \"$(echo git push)\"", .launchesGit("swift"), "a substitution's mention passed to a program")
    refused("/usr/bin/git status | cat", .gitSpelling("/usr/bin/git"), "git by its path")
    refused("git-lfs pull && echo ok", .gitSpelling("git-lfs"), "git-lfs as a command")
    refused("git -C /Users/synthetic/repo status | cat", .gitOption("-C"), "git -C")
    refused("git --git-dir=/Users/synthetic/repo/.git log | head", .gitOption("--git-dir"), "git --git-dir=")
    refused("git --work-tree /x status | cat", .gitOption("--work-tree"), "git --work-tree")
    refused("git --bare log | head", .gitOption("--bare"), "git --bare")
    refused("git -c core.worktree=/x status | cat", .gitOption("-c"), "git -c")
    refused("git | cat", .gitOption(""), "git with no subcommand")
    refused("git rebase -x 'cd /x && git push' main && echo ok", .gitProgramOption("rebase --exec"),
            "rebase --exec running git")
    refused("git submodule foreach 'git pull' | cat", .gitProgramOption("submodule"), "submodule foreach git")
    refused("git bisect run sh -c 'git log' | cat", .gitProgramOption("bisect"), "bisect run git")

    // A mention of git that reaches something that could run it.
    refused("echo 'cd /x && git push' | sh", .mentionFlows("sh"), "echo … git … | sh")
    refused("cat <<< 'git push' | bash", .mentionFlows("bash"), "a here-string piped to bash")
    refused("python3 <<'EOF'\nimport subprocess\nsubprocess.run(['git', 'push'], cwd='/x')\nEOF",
            .mentionFlows("python3"), "a python heredoc that runs git")
    refused("bash <<'EOF'\ncd /x\ngit pull\nEOF", .mentionFlows("bash"), "a bash heredoc")
    refused("cat <<'EOF' | sh\ngit push\nEOF", .unsupportedSyntax("a command after a heredoc's delimiter"),
            "a heredoc piped on its first line")
    refused("printf 'cd /x && git push' > /tmp/s.sh; sh /tmp/s.sh", .mentionFlows("a file"),
            "a script written then run")
    refused("echo 'git push' | tee /tmp/s.sh; zsh /tmp/s.sh", .mentionFlows("a file"), "tee into a script")
    refused("cat > s.sh <<'EOF'\ncd /main && git push\nEOF\ngit rebase -x 'sh s.sh' main", .mentionFlows("a file"),
            "a script written then run by rebase --exec")
    refused("for c in git; do \"$c\" push; done", .mentionFlows("a loop variable"), "git through a loop variable")
    refused("echo git | read -r c", .mentionFlows("read"), "git read into a variable")
    refused("echo 'git push' | { read -r c; sh -c \"$c\"; }", .mentionFlows("a compound command"),
            "git piped into a group")
    refused("echo 'git push' | while read -r c; do sh -c \"$c\"; done", .mentionFlows("a loop"),
            "git piped into a loop")
    refused("echo \"$(echo git push)\" | sh", .mentionFlows("sh"), "a substitution's mention piped to sh")
    refused("rg --pre ./x.sh 'git' .", .commandOption("rg --pre"), "rg --pre beside a mention")
    refused("printf -v c 'git push'", .assignment, "printf -v")
    refused("printf -v GIT_DIR /x; git status | cat", .assignment, "printf -v GIT_DIR")
    refused("sh <<< 'cd /x && git push'", .mentionFlows("sh"), "a here-string into sh")
    refused("git config alias.p '!cd /x && git push' && git p | cat", .gitProgramOption("config"),
            "a git alias that runs git elsewhere")
    refused("gh alias set p 'git push'", .launchesGit("gh"), "gh alias")
    refused("tee >(sh) <<< 'git push'", .unsupportedSyntax(">(…)"), ">(…)")

    // State the check cannot follow.
    refused("case x in x) git status;; esac", .unsupportedSyntax("case"), "case")
    refused("echo ${x:=y}; git status | cat", .unsupportedSyntax("${…} with = or flags"), "${x:=y}")
    refused("echo ${(e)x}; git status | cat", "zsh's (e) flag")
    refused("echo $((1+2)); git status | cat", .unsupportedSyntax("arithmetic"), "arithmetic")
    refused("(( i++ )); git status | cat", .unsupportedSyntax("arithmetic"), "an arithmetic command")
    refused("let x=1; git status | cat", .shellState("let"), "let")
    refused("select x in a; do git status; done", .unsupportedSyntax("select"), "select")
    refused("for path in /x; do git status; done", .assignment, "a loop over zsh's path array")
    refused("for GIT_DIR in /x; do git status; done", .assignment, "a loop over GIT_DIR")
    refused("read -r path < f; git status | cat", .shellState("read with that option or variable"), "read path")
    refused(".. ; git status | cat", .directoryCommandName, "a directory as a command (AUTO_CD)")
    refused("cd \(escapeWorktree)/link && git push && echo", .shellState("cd"), "cd through a link to the main checkout")
    refused("cd .. && git status && echo", .shellState("cd"), "cd .. out of the worktree")
    refused("cd src; cd ..; git status | cat", .shellState("cd"), "a second relative cd")
    refused("while true; do cd src; done; git status | cat", .shellState("cd"), "a relative cd in a loop")
    refused("cd ~/x && git status && echo", .shellState("cd"), "cd to ~")
    refused("cd - && git status && echo", .shellState("cd"), "cd -")
    refused("cd /Users/synthetic/nowhere && git status && echo", .shellState("cd"), "cd to a directory that does not exist")
    refused("../../.. && git push", .directoryCommandName, "a relative directory as a command")
    refused("src && git status | cat", .directoryCommandName, "a subdirectory as a command")
    refused("\"$G\" push && git status | cat", .computedCommandName, "a computed command name")
    refused("$(echo git) push", .computedCommandName, "a substituted command name")
    refused("ls *(e:'git push':)", .unparsable, "a zsh glob qualifier")
    refused("echo ok\u{0B}; git status | cat", .unparsable, "a byte zsh reads differently")

    // MARK: What Claude Code's guard lets an isolated agent run (measured
    // with no hooks), and what isolated agents commonly run.
    allowed("true && git status --short", "true && git (measured, vanilla ran it)")
    allowed("git log --oneline | head -3", "git piped to head (measured)")
    allowed("echo hi; git rev-parse --show-toplevel", "echo then git (measured)")
    allowed("git status > f && cat f", "git to a file, then cat (measured)")
    allowed("for f in a; do git status; done", "a for loop around git (measured)")
    allowed("echo \"$(git rev-parse HEAD)\"", "git in a command substitution")
    allowed("swift build && git add -A && git commit -m \"Fix the git hook\"", "build, then commit")
    allowed("git commit -m \"$(cat <<'EOF'\nFix git push\n\nBody about git.\nEOF\n)\" && swift test",
            "the heredoc commit message, then tests")
    allowed("cat > notes.md <<'EOF'\nNotes about git.\nEOF\ngit add notes.md", "a heredoc note, then git add")
    allowed("rg -n \"git push\" docs/ | head -20", "rg for git text")
    allowed("grep -rn 'git' README.md | wc -l", "grep for git")
    allowed("bd update csec-x --append-notes \"ran git status\"", "a bd note that mentions git")
    allowed("gh pr create --title \"Fix git hook\" --body x", "a gh pr with git in its title")
    allowed("git diff | cat", "git diff | cat")
    allowed("git status 2>&1 | tail -5", "git status 2>&1 | tail")
    allowed("which git && git --no-pager log -1 | cat", "which git, then git")
    allowed("command -v git && git status | cat", "command -v git")
    allowed("[ -d .git ] && git status | cat", "[ -d .git ]")
    allowed("test -n \"$(git status --porcelain)\" && echo dirty", "test -n with git in a substitution")
    allowed("[ \"$(git rev-list --count HEAD)\" -gt 0 ] && echo some", "[ with -gt ] on a substituted count")
    let hiddenSubscript = AICommandWorktreeEscape.Refusal.unsupportedSyntax("text zsh could evaluate in a subscript")
    refused("[ 'a[$(cd /x; git push)]' -eq 1 ] && git status | cat", hiddenSubscript, "[ ] arithmetic on quoted text")
    refused("test 'x[$(git push)]' -gt 0 && git status | cat", hiddenSubscript, "test arithmetic on quoted text")
    refused("printf '%d\\n' 'HOME[$(cd /tmp && git status)]'", hiddenSubscript, "printf %d on a quoted subscript")
    refused("[ -t 'path[$(cd /tmp; git status)]' ]", hiddenSubscript, "[ -t ] on a quoted subscript")
    refused("git log -1 $PWD['$(cd /tmp; git status)']", hiddenSubscript, "a subscript after $PWD")
    refused("echo \"${path['`cd /tmp; git status`']}\"", hiddenSubscript, "a backquote in a ${…} subscript")
    allowed("while read -r f; do git add \"$f\"; done < files.txt", "while read -r, git add")
    allowed("git log --format=%H | wc -l", "git log | wc")
    allowed("git status; npm test", "git then npm")
    allowed("(git status) & wait", "a background subshell")
    allowed("{ git status; git diff --stat; } 2>&1 | head", "a group piped to head")
    allowed("if git diff --quiet; then echo clean; else git status --short; fi", "if/else around git")
    allowed("git log --oneline | grep -i git | head", "git log | grep git")
    allowed("echo 'git push' > notes.txt && cat notes.txt", "a note written and read by trusted commands")
    allowed("git fetch && git rebase origin/main && swift build", "fetch, rebase and build")
    allowed("git rebase -x 'swift test' main && echo ok", "rebase --exec with a program that does not name git")
    allowed("echo ok && git push origin HEAD", "echo then push")
    allowed("cd \(escapeWorktree)/src && swift build && git status", "cd into the worktree by absolute path")
    allowed("cd \(escapeWorktree) && git status && swift build", "cd to the worktree itself")
    allowed("cd src && swift build && git status", "a first relative cd inside the worktree")
    allowed("cd agent/Sources && swift build && cd \(escapeWorktree) && git status", "relative then absolute cd")
    allowed("CI=1 npm test && git add -A && git commit -m x", "an assignment before a program")
    allowed("export RUST_LOG=debug; cargo test && git status | cat", "export of an ordinary variable")
    allowed("[[ -n $(git status --porcelain) ]] && echo dirty", "[[ ]] with git in a substitution")
    allowed("[[ -d .git ]] && git status | cat", "[[ -d .git ]]")
    allowed("git commit -m \"$(cat <<'EOF'\nFix [x] in git: $(not run) `nor this`\nEOF\n)\" && echo ok",
            "a commit message heredoc holding brackets and substitution text")

    // A command that does not name git is not checked.
    check(refusal("cd /Users/synthetic/repo && make deploy") == nil,
          "worktree escape: a command that names no git is not checked")

    worktreeEscapeHookTests()
    worktreeEscapeZshDifferentialTests(accepted)
}

// MARK: - The hook

private let escapeCsecPath = "/Applications/ConvenientSecurity.app/Contents/MacOS/csec"

private func escapeHookInput(_ command: String, cwd: Any? = escapeWorktree, transcript: String? = nil) -> Data {
    var object: [String: Any] = [
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": ["command": command, "description": "synthetic"],
        "permission_mode": "auto",
        "session_id": "0f3c2a4e-1b2d-4c6e-8f90-a1b2c3d4e5f6",
        "tool_use_id": "toolu_01ABCdef_ghi-J",
        "agent_id": "a1b2c3",
    ]
    if let cwd { object["cwd"] = cwd }
    if let transcript { object["transcript_path"] = transcript }
    return (try? JSONSerialization.data(withJSONObject: object)) ?? Data()
}

private func worktreeEscapeHookTests() {
    func rewrite(_ input: Data, _ client: AICommandHookClient = .claude)
        -> (output: Data, registration: AgentCommandRegistration?)? {
        try? AICommandHook.rewriteWithContext(
            input: input, client: client, csecExecutablePath: escapeCsecPath, worktreeEnvironment: escapeEnvironment)
    }
    func denial(_ output: Data) -> String? {
        guard let object = (try? JSONSerialization.jsonObject(with: output)) as? [String: Any],
              object.keys.sorted() == ["hookSpecificOutput"],
              let specific = object["hookSpecificOutput"] as? [String: Any],
              specific.keys.sorted() == ["hookEventName", "permissionDecision", "permissionDecisionReason"],
              specific["hookEventName"] as? String == "PreToolUse",
              specific["permissionDecision"] as? String == "deny" else { return nil }
        return specific["permissionDecisionReason"] as? String
    }
    func updatedCommand(_ output: Data) -> String? {
        guard let object = (try? JSONSerialization.jsonObject(with: output)) as? [String: Any],
              let specific = object["hookSpecificOutput"] as? [String: Any],
              specific["permissionDecision"] == nil,
              let updated = specific["updatedInput"] as? [String: Any] else { return nil }
        return updated["command"] as? String
    }

    let escape = "cd /Users/synthetic/repo && git push && echo pushed"
    let refused = rewrite(escapeHookInput(escape))
    let reason = refused.flatMap { denial($0.output) }
    check(reason?.contains("isolated in a Claude Code git worktree") == true
          && reason?.contains("runs a cd csec can't show stays in your worktree") == true && refused?.registration == nil,
          "worktree escape hook: an isolated cd-and-git compound is denied with a reason, registering nothing")
    check(reason.map { !$0.contains("/Users/synthetic/repo") } == true,
          "worktree escape hook: the reason names no path or argument from the command")

    let drifted = rewrite(escapeHookInput(
        "env git push", cwd: "/private/tmp",
        transcript: "/Users/alex/.claude/projects/-Users-synthetic-repo--claude-worktrees-probe5/x.jsonl"))
    check(drifted.flatMap { denial($0.output) }?.contains("move back first with a plain `cd <your worktree> && git status`")
            == true,
          "worktree escape hook: denied after the session's cwd moved out of its worktree")
    let noCWD = rewrite(escapeHookInput("env git push", cwd: nil))
    check(noCWD.flatMap { denial($0.output) } != nil, "worktree escape hook: denied with no cwd (fail closed)")

    // What an isolated session wraps starts with a space, so Claude Code's
    // guard does not read a leading git as a git launch (csec-m8sl); the
    // registration digests the program with its space, as csec ai runs it.
    let allowed = rewrite(escapeHookInput("git log --oneline | head -3"))
    check(allowed.flatMap { updatedCommand($0.output) } == "csec ai -- ' git log --oneline | head -3'"
          && allowed?.registration?.unwrapped == false
          && allowed?.registration?.programSHA256 == AICommandHook.programDigest(" git log --oneline | head -3"),
          "worktree escape hook: an isolated git pipe is wrapped after a space and registered as csec ai runs it")
    let chained = rewrite(escapeHookInput("git fetch && swift build"))
    check(chained.flatMap { updatedCommand($0.output) } == "csec ai -- ' git fetch && swift build'",
          "worktree escape hook: an isolated git-first chain is wrapped after a space")
    let bare = rewrite(escapeHookInput("grep -rn git docs"))
    check(bare.flatMap { updatedCommand($0.output) } == "csec ai -- ' grep -rn git docs'"
          && bare?.registration?.programSHA256 == AICommandHook.programDigest(" grep -rn git docs"),
          "worktree escape hook: an isolated bare-safe command is quoted after a space, so no git word stands alone")
    let quoted = rewrite(escapeHookInput("echo 'it''s' && git status"))
    check(quoted.flatMap { updatedCommand($0.output) }
            == "csec ai -- ' echo '\"'\"'it'\"'\"''\"'\"'s'\"'\"' && git status'",
          "worktree escape hook: an isolated command's quotes are escaped after the space as before")
    let elsewhere = rewrite(escapeHookInput(
        "swift build", cwd: "/private/tmp",
        transcript: "/Users/alex/.claude/projects/-Users-synthetic-repo--claude-worktrees-probe5/x.jsonl"))
    check(elsewhere.flatMap { updatedCommand($0.output) } == "csec ai -- swift build",
          "worktree escape hook: an isolated session outside its worktree wraps a command naming no git as before")
    let shellFirst = rewrite(escapeHookInput("bash scripts/x.sh | tail"))
    check(shellFirst.flatMap { updatedCommand($0.output) } == "csec ai -- 'bash scripts/x.sh | tail'",
          "worktree escape hook: an isolated command naming no git, which csec does not judge, keeps the guard's form")
    let plain = rewrite(escapeHookInput("cd /Users/synthetic/repo && git push"))
    check(plain?.output.isEmpty == true,
          "worktree escape hook: a plain cd/git list still reaches Claude Code's guard unwrapped")
    let unisolated = rewrite(escapeHookInput(escape, cwd: "/Users/synthetic/repo"))
    check(unisolated.flatMap { updatedCommand($0.output) } == "csec ai -- '\(escape)'"
          && rewrite(escapeHookInput("grep -rn git docs", cwd: "/Users/synthetic/repo"))
            .flatMap { updatedCommand($0.output) } == "csec ai -- grep -rn git docs",
          "worktree escape hook: outside isolation commands are wrapped as before, with no leading space")
    let codex = rewrite(escapeHookInput(escape), .codex)
    check(codex.flatMap { updatedCommand($0.output) } == nil && codex.flatMap { denial($0.output) } == nil
          && codex?.output.isEmpty == false,
          "worktree escape hook: Codex is never refused by it")
    let codexPipe = rewrite(escapeHookInput("git log --oneline | head -3"), .codex)
    check(codexPipe.flatMap { output -> String? in
        guard let object = (try? JSONSerialization.jsonObject(with: output.output)) as? [String: Any],
              let specific = object["hookSpecificOutput"] as? [String: Any],
              let updated = specific["updatedInput"] as? [String: Any] else { return nil }
        return updated["command"] as? String
    } == "csec ai -- 'git log --oneline | head -3'",
          "worktree escape hook: Codex's rewrite has no leading space")
}

// MARK: - The real zsh

/// Runs every accepted command under the real `/bin/zsh -c` in a scratch
/// worktree, with a sentinel `git` first on `PATH` that records the directory
/// it ran in and any git variable set, and stand-ins for the other programs.
/// Every git that ran must have run in the worktree with no git variable.
private func worktreeEscapeZshDifferentialTests(_ commands: [String]) {
    print("\n# AICommandWorktreeEscape differential (each accepted command under the real zsh)")
    let files = FileManager.default
    let root = files.temporaryDirectory.appendingPathComponent("csec-worktree-escape-\(UUID().uuidString)")
    defer { try? files.removeItem(at: root) }
    let bin = root.appendingPathComponent("bin")
    let work = root.appendingPathComponent("repo/.claude/worktrees/agent-a1")
    let log = root.appendingPathComponent("git.log")
    do {
        for directory in [bin, work, work.appendingPathComponent("docs")] {
            try files.createDirectory(at: directory, withIntermediateDirectories: true)
        }
        let git = #"""
            #!/bin/sh
            printf '%s|%s|%s|%s\n' "$(pwd -P)" "${GIT_DIR-}" "${GIT_WORK_TREE-}" "$1" >> "$CSEC_ESCAPE_LOG"
            """#
        let standIn = "#!/bin/sh\nexit 0\n"
        let programs = ["git": git, "swift": standIn, "npm": standIn, "bd": standIn, "gh": standIn, "rg": standIn]
        for (name, script) in programs {
            let path = bin.appendingPathComponent(name).path
            try Data((script + "\n").utf8).write(to: URL(fileURLWithPath: path))
            try files.setAttributes([.posixPermissions: 0o755], ofItemAtPath: path)
        }
        try Data("files.txt\n".utf8).write(to: work.appendingPathComponent("files.txt"))
    } catch {
        check(false, "the worktree escape differential sets up its sentinels (\(error))")
        return
    }
    // `pwd -P` reads /var as /private/var; Foundation's own symlink
    // resolution strips the /private again, so ask realpath.
    guard let resolved = realpath(work.path, nil) else {
        check(false, "the worktree escape differential resolves its worktree")
        return
    }
    let workPath = String(cString: resolved)
    free(resolved)
    check(commands.count >= 25, "the worktree escape differential has the accepted corpus (\(commands.count))")
    /// The git runs `command` made, and those outside the worktree (or a
    /// directory inside it) or with a git variable set; nil if zsh could not
    /// run it.
    func run(_ command: String) -> (ran: Int, escaped: Int)? {
        try? files.removeItem(at: log)
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/zsh")
        process.arguments = ["-f", "-c", command]
        process.currentDirectoryURL = work
        process.environment = [
            "PATH": bin.path + ":/usr/bin:/bin", "HOME": root.path, "CSEC_ESCAPE_LOG": log.path,
        ]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            return nil
        }
        let lines = ((try? String(contentsOf: log, encoding: .utf8)) ?? "").split(separator: "\n")
        let escaped = lines.filter { line in
            let fields = line.split(separator: "|", maxSplits: 3, omittingEmptySubsequences: false)
            let directory = fields.first.map(String.init) ?? ""
            let inside = directory == workPath || directory.hasPrefix(workPath + "/")
            return fields.count < 3 || !inside || !fields[1].isEmpty || !fields[2].isEmpty
        }
        return (lines.count, escaped.count)
    }
    // The harness itself: each escape the check refuses is seen as one.
    for escape in ["cd ../../.. && git status && echo x", "GIT_DIR=/tmp git status | cat",
                   "sh -c 'cd .. && git status'", "export GIT_WORK_TREE=/tmp; git status | cat"] {
        check(run(escape)?.escaped == 1 && AICommandWorktreeEscape.refusal(
                  for: escape, isolation: .inWorktree(root: workPath), workingDirectory: workPath,
                  environment: .live) != nil,
              "worktree escape differential: the harness sees \(escape.debugDescription) escape, and the check refuses it")
    }
    // A cd the check allows, against the real file system, stays inside.
    var commands = commands
    for command in ["cd \(workPath)/docs && git status && echo x", "cd docs && git status && cd \(workPath) && git log | cat"] {
        let refusal = AICommandWorktreeEscape.refusal(
            for: command, isolation: .inWorktree(root: workPath), workingDirectory: workPath, environment: .live)
        check(refusal == nil, "worktree escape differential: allows \(command.debugDescription) (\(String(describing: refusal)))")
        commands.append(command)
    }
    var ranGit = 0
    for command in commands {
        guard let result = run(command) else {
            check(false, "worktree escape differential: \(command.debugDescription) runs")
            continue
        }
        if result.ran > 0 { ranGit += 1 }
        check(result.escaped == 0,
              "worktree escape differential: \(command.debugDescription) ran git \(result.ran)x, only in the worktree")
    }
    check(ranGit >= 20, "the worktree escape differential saw git run in most commands (\(ranGit))")
}
