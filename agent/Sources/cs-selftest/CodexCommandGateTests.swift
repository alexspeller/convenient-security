import Foundation
import ConvenientSecurity

/// One script as Codex's own crates see it: codex-shell-command and
/// codex-execpolicy at rust-v0.155.0-alpha.9.2 (unchanged at
/// rust-v0.155.0-alpha.16.4 and rust-v0.156.1, re-checked 2026-09-24), run over
/// `[/bin/zsh, -lc, script]`.
private struct CodexGateVector {
    let script: String
    /// `dangerous_command_match` on the whole `[/bin/zsh, -lc, script]`.
    let heuristic: CodexCommandGate.DangerousCommandMatch?
    /// `parse_shell_lc_plain_commands`.
    let plain: [[String]]?
    /// Codex's heuristic flags a command it checks (the plain commands, else
    /// the whole invocation), with no rules.
    let gatedWithoutRules: Bool
    /// Codex gates it under `codexProbeRules`: its heuristic where no rule
    /// matched, or a `prompt`/`forbidden` rule.
    let gatedWithProbeRules: Bool

    init(_ script: String, _ heuristic: CodexCommandGate.DangerousCommandMatch?, _ plain: [[String]]?,
         _ gatedWithoutRules: Bool, _ gatedWithProbeRules: Bool) {
        self.script = script
        self.heuristic = heuristic
        self.plain = plain
        self.gatedWithoutRules = gatedWithoutRules
        self.gatedWithProbeRules = gatedWithProbeRules
    }
}

/// The spec's 142 vectors, every shape from the adversarial review of the
/// earlier hand-written lexer (heredocs with odd quotes, ANSI-C strings, leading
/// redirections, non-identifier assignments, `env`/`sudo` operand rules,
/// `function`, `case` and comments inside `$(…)`, shared wrapper depth, shell
/// file stems), and edge cases of Codex's path and wrapper handling. Generated
/// from Codex's crates by the scratch oracle described in the port report; do
/// not edit by hand.
private let codexGateVectors: [CodexGateVector] = [
    .init("rm -rf /", .forcedRm, [["rm", "-rf", "/"]], true, false),
    .init("rm -f /", .forcedRm, [["rm", "-f", "/"]], true, false),
    .init("/bin/rm -fr /tmp/example", .forcedRm, [["/bin/rm", "-fr", "/tmp/example"]], true, false),
    .init("rm -r -f /tmp/example", .forcedRm, [["rm", "-r", "-f", "/tmp/example"]], true, false),
    .init("rm --force /tmp/example", .forcedRm, [["rm", "--force", "/tmp/example"]], true, false),
    .init("rm /tmp/example -f", .forcedRm, [["rm", "/tmp/example", "-f"]], true, false),
    .init("sudo rm -rf /tmp/example", .forcedRm, [["sudo", "rm", "-rf", "/tmp/example"]], true, true),
    .init("env TARGET=/tmp/example rm -rf /tmp/example", .forcedRm, [["env", "TARGET=/tmp/example", "rm", "-rf", "/tmp/example"]], true, true),
    .init("printf x | rm -rf /tmp/example", .forcedRm, [["printf", "x"], ["rm", "-rf", "/tmp/example"]], true, false),
    .init("if test -d /tmp/example; then rm --force /tmp/example; fi", .forcedRm, nil, true, true),
    .init("rm -rf \"$TARGET\" >/dev/null", .forcedRm, nil, true, true),
    .init("for target in /tmp/a /tmp/b; do rm -r -f \"$target\"; done", .forcedRm, nil, true, true),
    .init("echo \"$(rm -rf /tmp/example)\"", .forcedRm, nil, true, true),
    .init("bash -c 'rm -rf /tmp/example'", .forcedRm, [["bash", "-c", "rm -rf /tmp/example"]], true, true),
    .init("trap 'rm -rf /tmp/example' EXIT", .forcedRm, [["trap", "rm -rf /tmp/example", "EXIT"]], true, true),
    .init("rm -r /tmp/example", nil, [["rm", "-r", "/tmp/example"]], false, false),
    .init("rm -- -f", nil, [["rm", "--", "-f"]], false, false),
    .init("echo 'rm -rf /tmp/example'", nil, [["echo", "rm -rf /tmp/example"]], false, false),
    .init("cmd=rm; $cmd -rf /tmp/example", nil, nil, false, false),
    .init("if then rm -rf /tmp/example", nil, nil, false, false),
    .init("env TARGET=/tmp/example rm -r /tmp/example", nil, [["env", "TARGET=/tmp/example", "rm", "-r", "/tmp/example"]], false, false),
    .init("trap 'echo rm -rf /tmp/example' EXIT", nil, [["trap", "echo rm -rf /tmp/example", "EXIT"]], false, false),
    .init("git reset --hard", nil, [["git", "reset", "--hard"]], false, true),
    .init("git clean -fdx", nil, [["git", "clean", "-fdx"]], false, true),
    .init("git push --force", nil, [["git", "push", "--force"]], false, true),
    .init("chmod -R 777 /", nil, [["chmod", "-R", "777", "/"]], false, false),
    .init("dd if=/dev/zero of=/dev/disk2", nil, [["dd", "if=/dev/zero", "of=/dev/disk2"]], false, false),
    .init("mkfs.ext4 /dev/sda1", nil, [["mkfs.ext4", "/dev/sda1"]], false, false),
    .init("find . -delete", nil, [["find", ".", "-delete"]], false, false),
    .init("xargs rm -rf", nil, [["xargs", "rm", "-rf"]], false, false),
    .init("command rm -rf x", nil, [["command", "rm", "-rf", "x"]], false, false),
    .init("nohup rm -rf x", nil, [["nohup", "rm", "-rf", "x"]], false, false),
    .init("time rm -rf x", nil, [["time", "rm", "-rf", "x"]], false, false),
    .init("exec rm -rf x", nil, [["exec", "rm", "-rf", "x"]], false, false),
    .init("\\rm -rf x", nil, nil, false, false),
    .init("\"rm\" -rf x", .forcedRm, nil, true, true),
    .init("r''m -rf x", .forcedRm, nil, true, true),
    .init("rm -rf ~/x", .forcedRm, nil, true, true),
    .init("rm -Rf x", .forcedRm, [["rm", "-Rf", "x"]], true, false),
    .init("rm -fv x", .forcedRm, [["rm", "-fv", "x"]], true, false),
    .init("rm -rfv -- x", .forcedRm, [["rm", "-rfv", "--", "x"]], true, false),
    .init("rm -r -- -f x", nil, [["rm", "-r", "--", "-f", "x"]], false, false),
    .init("./rm -rf x", .forcedRm, [["./rm", "-rf", "x"]], true, false),
    .init("$(which rm) -rf x", nil, nil, false, false),
    .init("bash -c \"rm -rf x\"", .forcedRm, [["bash", "-c", "rm -rf x"]], true, true),
    .init("bash -c 'rm -rf x' extra", nil, [["bash", "-c", "rm -rf x", "extra"]], false, false),
    .init("bash -e -c 'rm -rf x'", nil, [["bash", "-e", "-c", "rm -rf x"]], false, false),
    .init("sh -c 'rm -rf x'", .forcedRm, [["sh", "-c", "rm -rf x"]], true, true),
    .init("zsh -lc 'rm -rf x'", .forcedRm, [["zsh", "-lc", "rm -rf x"]], true, true),
    .init("dash -c 'rm -rf x'", nil, [["dash", "-c", "rm -rf x"]], false, false),
    .init("fish -c 'rm -rf x'", nil, [["fish", "-c", "rm -rf x"]], false, false),
    .init("eval 'rm -rf x'", nil, [["eval", "rm -rf x"]], false, false),
    .init("trap -- 'rm -rf x' EXIT", .forcedRm, [["trap", "--", "rm -rf x", "EXIT"]], true, true),
    .init("(rm -rf x)", .forcedRm, nil, true, true),
    .init("{ rm -rf x; }", .forcedRm, nil, true, true),
    .init("cat <<EOF\nrm -rf x\nEOF", nil, nil, false, false),
    .init("echo rm -rf", nil, [["echo", "rm", "-rf"]], false, false),
    .init("FOO=1 rm -rf x", .forcedRm, nil, true, true),
    .init("rm -rf x 2>/dev/null", .forcedRm, nil, true, true),
    .init("ls && rm -rf x", .forcedRm, [["ls"], ["rm", "-rf", "x"]], true, false),
    .init("ls; rm -f x", .forcedRm, [["ls"], ["rm", "-f", "x"]], true, false),
    .init("ls || rm -f x", .forcedRm, [["ls"], ["rm", "-f", "x"]], true, false),
    .init("ls | rm -f x", .forcedRm, [["ls"], ["rm", "-f", "x"]], true, false),
    .init("ls & rm -f x", .forcedRm, nil, true, true),
    .init("rm -rf x &&", nil, nil, false, false),
    .init("sudo -u root rm -rf x", nil, [["sudo", "-u", "root", "rm", "-rf", "x"]], false, false),
    .init("sudo -- rm -rf x", nil, [["sudo", "--", "rm", "-rf", "x"]], false, false),
    .init("env -u FOO rm -rf x", nil, [["env", "-u", "FOO", "rm", "-rf", "x"]], false, false),
    .init("env -i rm -rf x", .forcedRm, [["env", "-i", "rm", "-rf", "x"]], true, true),
    .init("env -- rm -rf x", .forcedRm, [["env", "--", "rm", "-rf", "x"]], true, true),
    .init("sudo env A=1 sudo rm -f x", .forcedRm, [["sudo", "env", "A=1", "sudo", "rm", "-f", "x"]], true, true),
    .init("rm -f$(echo) x", nil, nil, false, false),
    .init("rm -\"f\" x", .forcedRm, [["rm", "-f", "x"]], true, false),
    .init("rm '-f' x", .forcedRm, [["rm", "-f", "x"]], true, false),
    .init("rm --forc x", nil, [["rm", "--forc", "x"]], false, false),
    .init("rm --force=yes x", nil, [["rm", "--force=yes", "x"]], false, false),
    .init("rm -- --force", nil, [["rm", "--", "--force"]], false, false),
    .init("rm x --", nil, [["rm", "x", "--"]], false, false),
    .init("rm x -- -f", nil, [["rm", "x", "--", "-f"]], false, false),
    .init("trap -p", nil, [["trap", "-p"]], false, false),
    .init("trap 'rm -f a' INT; ls", .forcedRm, [["trap", "rm -f a", "INT"], ["ls"]], true, true),
    .init("csec ai -- rm -rf x", nil, [["csec", "ai", "--", "rm", "-rf", "x"]], false, false),
    .init("csec ai -- 'rm -rf x'", nil, [["csec", "ai", "--", "rm -rf x"]], false, false),
    .init("csec ai -- 'git reset --hard && rm -rf /tmp/x'", nil, [["csec", "ai", "--", "git reset --hard && rm -rf /tmp/x"]], false, false),
    .init("git push", nil, [["git", "push"]], false, true),
    .init("git push origin main", nil, [["git", "push", "origin", "main"]], false, true),
    .init("git -C repo push", nil, [["git", "-C", "repo", "push"]], false, false),
    .init("/usr/bin/git push", nil, [["/usr/bin/git", "push"]], false, true),
    .init("/opt/homebrew/bin/git push", nil, [["/opt/homebrew/bin/git", "push"]], false, false),
    .init("git reset --hard HEAD~1", nil, nil, false, false),
    .init("git clean -n", nil, [["git", "clean", "-n"]], false, true),
    .init("git status", nil, [["git", "status"]], false, false),
    .init("npm publish", nil, [["npm", "publish"]], false, true),
    .init("pnpm publish --dry-run", nil, [["pnpm", "publish", "--dry-run"]], false, true),
    .init("/usr/local/bin/npm publish", nil, [["/usr/local/bin/npm", "publish"]], false, true),
    .init("sudo git push", nil, [["sudo", "git", "push"]], false, false),
    .init("bash -c 'git push'", nil, [["bash", "-c", "git push"]], false, false),
    .init("git push | cat", nil, [["git", "push"], ["cat"]], false, true),
    .init("git push > out.txt", nil, nil, false, false),
    .init("ls && git push", nil, [["ls"], ["git", "push"]], false, true),
    .init("kubectl delete pod x", nil, [["kubectl", "delete", "pod", "x"]], false, true),
    .init("terraform apply", nil, [["terraform", "apply"]], false, false),
    .init("rm -rf x && git status", .forcedRm, [["rm", "-rf", "x"], ["git", "status"]], true, false),
    .init("FOO=bar git push", nil, nil, false, false),
    .init("git push 2>&1", nil, nil, false, false),
    .init("echo \"$(git push)\"", nil, nil, false, false),
    .init("git commit -m \"line1\nline2\"", nil, [["git", "commit", "-m", "line1\nline2"]], false, false),
    .init("rg -g\"*.py\" pattern", nil, [["rg", "-g*.py", "pattern"]], false, false),
    .init("echo ~", nil, nil, false, false),
    .init("echo HEAD~1", nil, nil, false, false),
    .init("! rm -rf x", .forcedRm, nil, true, true),
    .init("f() { rm -rf x; }", .forcedRm, nil, true, true),
    .init("export X=$(rm -rf y)", .forcedRm, nil, true, true),
    .init("[[ -n $(rm -rf x) ]]", .forcedRm, nil, true, true),
    .init("case a in a) rm -rf z;; esac", .forcedRm, nil, true, true),
    .init("while true; do rm -rf x; done", .forcedRm, nil, true, true),
    .init("rm -rf x | tee log", .forcedRm, [["rm", "-rf", "x"], ["tee", "log"]], true, false),
    .init("cat <(rm -rf x)", .forcedRm, nil, true, true),
    .init("for f in *.txt; rm -f $f", nil, nil, false, false),
    .init("rm -f **/*.log", .forcedRm, nil, true, true),
    .init("noglob rm -rf x", nil, [["noglob", "rm", "-rf", "x"]], false, false),
    .init("rm -rf x(N)", nil, nil, false, false),
    .init("echo $((1+1)); rm -f y", .forcedRm, nil, true, true),
    .init("local x=1; rm -f y", .forcedRm, nil, true, true),
    .init("rm -f \"a\\$b\"", .forcedRm, nil, true, true),
    .init("rm -f \"a\\nb\"", .forcedRm, [["rm", "-f", "a\\nb"]], true, false),
    .init("rm \"-f\" x", .forcedRm, [["rm", "-f", "x"]], true, false),
    .init("sudo bash -c 'rm -f x'", .forcedRm, [["sudo", "bash", "-c", "rm -f x"]], true, true),
    .init("env A=1 B=2 bash -lc 'trap \"rm -f x\" EXIT'", .forcedRm, [["env", "A=1", "B=2", "bash", "-lc", "trap \"rm -f x\" EXIT"]], true, true),
    .init("trap 'sh -c \"rm -f x\"' EXIT", .forcedRm, [["trap", "sh -c \"rm -f x\"", "EXIT"]], true, true),
    .init("rm -f x\nls", .forcedRm, [["rm", "-f", "x"], ["ls"]], true, false),
    .init("ls\n\nrm -f x", .forcedRm, [["ls"], ["rm", "-f", "x"]], true, false),
    .init("rm -f x # comment", .forcedRm, nil, true, true),
    .init("# rm -f x", nil, nil, false, false),
    .init("rm -f x;", .forcedRm, [["rm", "-f", "x"]], true, false),
    .init("rm -f x &", .forcedRm, nil, true, true),
    .init("(ls) && rm -f x", .forcedRm, nil, true, true),
    .init("ls && (rm -f x)", .forcedRm, nil, true, true),
    .init("rm -f -- x", .forcedRm, [["rm", "-f", "--", "x"]], true, false),
    .init("apply_patch <<'EOF'\n*** Begin Patch\n*** End Patch\nEOF", nil, nil, false, false),
    .init("cd sub && apply_patch <<'EOF'\n*** Begin Patch\n*** End Patch\nEOF", nil, nil, false, false),
    .init("rm -rf x", .forcedRm, [["rm", "-rf", "x"]], true, false),
    .init("ls", nil, [["ls"]], false, false),
    .init("cat <<'EOF'\nIt's done\nEOF\nrm -rf build", .forcedRm, nil, true, true),
    .init("cat > notes.md <<EOF\nHe said \"hi\nEOF\nrm -rf build", .forcedRm, nil, true, true),
    .init("git commit -m \"$(cat <<'EOF'\nIt's fixed\nEOF\n)\" && rm -rf dist", .forcedRm, nil, true, true),
    .init("echo $'it\\'s'; rm -rf x", .forcedRm, nil, true, true),
    .init("function f { rm -rf x; }", .forcedRm, nil, true, true),
    .init("function f { rm -rf x; }; f", .forcedRm, nil, true, true),
    .init(">/dev/null rm -rf x", .forcedRm, nil, true, true),
    .init("2>/dev/null rm -f x", .forcedRm, nil, true, true),
    .init("</dev/null rm -f x", .forcedRm, nil, true, true),
    .init("2>&1 rm -rf x", .forcedRm, nil, true, true),
    .init("env a.b=1 rm -rf x", .forcedRm, [["env", "a.b=1", "rm", "-rf", "x"]], true, true),
    .init("env 1=2 rm -rf x", .forcedRm, [["env", "1=2", "rm", "-rf", "x"]], true, true),
    .init("env A-B=1 rm -rf x", .forcedRm, [["env", "A-B=1", "rm", "-rf", "x"]], true, true),
    .init("echo $(case a in a) rm -rf x;; esac)", .forcedRm, nil, true, true),
    .init("env env env env env env env env ls", .other, [["env", "env", "env", "env", "env", "env", "env", "env", "ls"]], false, false),
    .init("env env env env env env env sh -c 'ls'", .other, [["env", "env", "env", "env", "env", "env", "env", "sh", "-c", "ls"]], false, false),
    .init("bash.exe -c 'rm -rf x'", .forcedRm, [["bash.exe", "-c", "rm -rf x"]], true, true),
    .init("echo \"${x:-\"}\"}\"; rm -rf y", .forcedRm, nil, true, true),
    .init("echo $(ls # it's\n) ; echo ')'; rm -rf x", .forcedRm, nil, true, true),
    .init("time -p rm -rf x", nil, [["time", "-p", "rm", "-rf", "x"]], false, false),
    .init("coproc rm -rf x", nil, [["coproc", "rm", "-rf", "x"]], false, false),
    .init("select x in a; do rm -rf y; done", .forcedRm, nil, true, true),
    .init("env env env env env env env env ls >/dev/null", .other, nil, true, true),
    .init("env env env env env env env sh -c 'ls' >/dev/null", .other, nil, true, true),
    .init("env env env env env env env env ls; echo $(date)", .other, nil, true, true),
    .init("sudo sudo sudo sudo sudo sudo sudo sudo git status 2>&1", .other, nil, true, true),
    .init("FOO+=1 rm -rf x", .forcedRm, nil, true, true),
    .init("a[0]=1 rm -rf x", .forcedRm, nil, true, true),
    .init("echo $'\\''; rm -rf x", .forcedRm, nil, true, true),
    .init("/usr/bin/sudo rm -rf x", .forcedRm, [["/usr/bin/sudo", "rm", "-rf", "x"]], true, true),
    .init("/usr/bin/env rm -rf x", .forcedRm, [["/usr/bin/env", "rm", "-rf", "x"]], true, true),
    .init("apply_patch <<'EOF'\n*** Begin Patch\n*** Add File: a.txt\n+it's\n*** End Patch\nEOF", nil, nil, false, false),
    .init("cd 'it s' && apply_patch <<'EOF'\n*** Begin Patch\n*** Add File: a.txt\n+hi\n*** End Patch\nEOF", nil, nil, false, false),
    .init("rm\u{a0}-rf x", nil, [["rm\u{a0}-rf", "x"]], false, false),
    .init("rm -rf x\r", .forcedRm, [["rm", "-rf", "x"]], true, false),
    .init("rm\r -rf x", .forcedRm, [["rm", "-rf", "x"]], true, false),
    .init("rm\u{b}-rf x", .forcedRm, [["rm", "-rf", "x"]], true, false),
    .init("rm\u{c}-rf x", .forcedRm, [["rm", "-rf", "x"]], true, false),
    .init("cat <<-'EOF'\n\tdon't\n\tEOF\nrm -rf x", .forcedRm, nil, true, true),
    .init("x=$(cat <<EOF\nit's\nEOF\n); rm -rf y", .forcedRm, nil, true, true),
    .init("cat <<EOF | sh\nrm -rf x\nEOF", nil, nil, false, false),
    .init("echo `echo \"it's\"`; rm -rf x", .forcedRm, nil, true, true),
    .init("echo \"`echo \\\"`\"; rm -rf x", .forcedRm, nil, true, true),
    .init("trap 'rm -rf x' EXIT", .forcedRm, [["trap", "rm -rf x", "EXIT"]], true, true),
    .init("if true; then rm -f x; fi", .forcedRm, nil, true, true),
    .init("function f() { rm -rf x; }", .forcedRm, nil, true, true),
    .init("function f\n{\n rm -rf x\n}", .forcedRm, nil, true, true),
    .init("rm -f x # c", .forcedRm, nil, true, true),
    .init("/usr/bin/git push origin", nil, [["/usr/bin/git", "push", "origin"]], false, true),
    .init("./git push", nil, [["./git", "push"]], false, false),
    .init("git/ push", nil, [["git/", "push"]], false, false),
    .init("git/. push", nil, [["git/.", "push"]], false, false),
    .init("pnpm publish", nil, [["pnpm", "publish"]], false, true),
    .init("echo $(date)", nil, nil, false, false),
    .init("ls > /dev/null", nil, nil, false, false),
    .init("git status && git push", nil, [["git", "status"], ["git", "push"]], false, true),
    .init("git status\ngit push", nil, [["git", "status"], ["git", "push"]], false, true),
    .init("sudo $UNSET rm -rf x", .forcedRm, nil, true, true),
    .init("env $UNSET rm -rf x", .forcedRm, nil, true, true),
    .init("sudo \"$@\" rm -rf x", .forcedRm, nil, true, true),
    .init("env A.B=1 bash -c 'rm -rf x'", .forcedRm, [["env", "A.B=1", "bash", "-c", "rm -rf x"]], true, true),
    .init("cat <<EOF\nit's $(rm -rf x)\nEOF", .forcedRm, nil, true, true),
    .init("<<EOF rm -rf x\nhi\nEOF", nil, nil, false, false),
    .init("2>/dev/null FOO=1 rm -rf x", .forcedRm, nil, true, true),
    .init("x=$(echo \"a\" # it's\n); rm -rf y", .forcedRm, nil, true, true),
    .init("echo $(cat <<'EOF'\n)\nEOF\n); rm -rf x", .forcedRm, nil, true, true),
    .init("git commit -F - <<'EOF'\nDon't panic\nEOF\nrm -f .git/index.lock", .forcedRm, nil, true, true),
    .init("bash -lc \"cat <<'EOF'\nit's\nEOF\nrm -rf x\"", .forcedRm, [["bash", "-lc", "cat <<'EOF'\nit's\nEOF\nrm -rf x"]], true, true),
    .init("echo ${x:-'}'} ; rm -rf y", .forcedRm, nil, true, true),
    .init("echo \"it's\" `true` ; rm -rf y", .forcedRm, nil, true, true),
    .init("tmp=$'a\\'b' rm -rf x", .forcedRm, nil, true, true),
    .init("cat <<'EOF' > f.txt\nwe're\nEOF\nsudo rm -f /tmp/f", .forcedRm, nil, true, true),
    .init("printf '%s\\n' \"$(cat <<EOF\nshe said \"hi\nEOF\n)\"; rm -rf out", .forcedRm, nil, true, true),
    .init("env env env env env env env env env ls", .other, [["env", "env", "env", "env", "env", "env", "env", "env", "env", "ls"]], true, true),
    .init("env env env env env env env env rm -rf x", .other, [["env", "env", "env", "env", "env", "env", "env", "env", "rm", "-rf", "x"]], true, true),
    .init("zsh/ -c 'rm -rf x'", nil, [["zsh/", "-c", "rm -rf x"]], false, false),
    .init("zsh/. -c 'rm -rf x'", nil, [["zsh/.", "-c", "rm -rf x"]], false, false),
    .init("zsh.exe.exe -c 'rm -rf x'", .forcedRm, [["zsh.exe.exe", "-c", "rm -rf x"]], true, true),
    .init("./bash -c 'rm -rf x'", .forcedRm, [["./bash", "-c", "rm -rf x"]], true, true),
    .init(".bash -c 'rm -rf x'", nil, [[".bash", "-c", "rm -rf x"]], false, false),
    .init("bash. -c 'rm -rf x'", .forcedRm, [["bash.", "-c", "rm -rf x"]], true, true),
    .init("bash5 -c 'rm -rf x'", nil, [["bash5", "-c", "rm -rf x"]], false, false),
    .init("/usr/bin/../bin/sh -c 'rm -rf x'", .forcedRm, [["/usr/bin/../bin/sh", "-c", "rm -rf x"]], true, true),
    .init("sh -lc 'rm -rf x'", .forcedRm, [["sh", "-lc", "rm -rf x"]], true, true),
    .init("sh -xc 'rm -rf x'", nil, [["sh", "-xc", "rm -rf x"]], false, false),
    .init("bash -c ''", nil, [["bash", "-c", ""]], false, false),
    .init("trap '' EXIT", nil, [["trap", "", "EXIT"]], false, false),
    .init("trap -- '' EXIT", nil, [["trap", "--", "", "EXIT"]], false, false),
    .init("rm -rf \u{fc} && echo \u{e9}", .forcedRm, [["rm", "-rf", "\u{fc}"], ["echo", "\u{e9}"]], true, false),
    .init("echo \u{e9}; rm -f x", .forcedRm, [["echo", "\u{e9}"], ["rm", "-f", "x"]], true, false),
    .init(" ", nil, [], false, false),
    .init(";", nil, nil, false, false),
    .init("#", nil, nil, false, false),
    .init("rm/ -rf x", nil, [["rm/", "-rf", "x"]], false, false),
    .init("x/rm -rf y", .forcedRm, [["x/rm", "-rf", "y"]], true, false),
    .init("rm -f", .forcedRm, [["rm", "-f"]], true, false),
    .init("rm", nil, [["rm"]], false, false),
    .init("sudo", nil, [["sudo"]], false, false),
    .init("env", nil, [["env"]], false, false),
    .init("env A=1", nil, [["env", "A=1"]], false, false),
    .init("trap", nil, [["trap"]], false, false),
    .init("./npm publish", nil, [["./npm", "publish"]], false, true),
    .init("npm/ publish", nil, [["npm/", "publish"]], false, true),
    .init("~/bin/npm publish", nil, nil, false, false),
    .init("/usr/bin/../bin/git push", nil, [["/usr/bin/../bin/git", "push"]], false, true),
    .init("\"git\" push", nil, nil, false, false),
    .init("git 'push'", nil, [["git", "push"]], false, true),
    .init("git push\\ origin", nil, nil, false, false),
    .init("git   push", nil, [["git", "push"]], false, true),
    .init("rm -f\u{301} x", .forcedRm, [["rm", "-f\u{301}", "x"]], true, false),
    .init("rm\u{301} -rf x", nil, [["rm\u{301}", "-rf", "x"]], false, false),
    .init("env A\u{301}=1 rm -rf x", .forcedRm, [["env", "A\u{301}=1", "rm", "-rf", "x"]], true, true),
    .init("env \u{301}=1 rm -rf x", .forcedRm, [["env", "\u{301}=1", "rm", "-rf", "x"]], true, true),
    .init("\"\u{301}rm\" -rf x", nil, nil, false, false),
    .init("echo \"\u{301}a\" '\u{301}b'", nil, [["echo", "\u{301}a", "\u{301}b"]], false, false),
    .init("bash -c \"\u{301}rm -rf x\"", nil, [["bash", "-c", "\u{301}rm -rf x"]], false, false),
    .init("/\u{301}bin/rm -rf x", .forcedRm, [["/\u{301}bin/rm", "-rf", "x"]], true, false),
    .init("=\u{301}rm -rf x", nil, nil, false, false),
    .init("sudo\u{301} rm -rf x", nil, [["sudo\u{301}", "rm", "-rf", "x"]], false, false),
    .init("rm -\u{301}f x", .forcedRm, [["rm", "-\u{301}f", "x"]], true, false),
    .init("rm \"-f\u{301}\" x", .forcedRm, [["rm", "-f\u{301}", "x"]], true, false),
    .init("trap '\u{301}rm -rf x' EXIT", nil, [["trap", "\u{301}rm -rf x", "EXIT"]], false, false),
    .init("trap -\u{301} 'rm -rf x' EXIT", nil, [["trap", "-\u{301}", "rm -rf x", "EXIT"]], false, false),
    .init("bash\u{301} -c 'rm -rf x'", nil, [["bash\u{301}", "-c", "rm -rf x"]], false, false),
    .init("rm -f x\u{a0}", .forcedRm, [["rm", "-f", "x\u{a0}"]], true, false),
    .init("rm\u{2028}-rf x", nil, [["rm\u{2028}-rf", "x"]], false, false),
]

/// The probe rules the vectors were computed with: an `rm` allow rule and a
/// `terraform` rule without a decision gate nothing.
private let codexProbeRules = [
    CodexCommandGate.PrefixRule(pattern: [["git"], ["push"]], decision: .prompt),
    CodexCommandGate.PrefixRule(pattern: [["git"], ["reset", "clean"]], decision: .forbidden),
    CodexCommandGate.PrefixRule(pattern: [["npm", "pnpm"], ["publish"]], decision: .prompt),
    CodexCommandGate.PrefixRule(pattern: [["rm"]], decision: .allow),
    CodexCommandGate.PrefixRule(pattern: [["kubectl"], ["delete"]], decision: .prompt),
    CodexCommandGate.PrefixRule(pattern: [["terraform"]], decision: .allow),
]

/// Scripts whose only extra gate is Codex's apply_patch interception, which
/// the vectors' oracle does not model.
private func runsPatchTool(_ script: String) -> Bool {
    script.contains("apply_patch") || script.contains("applypatch")
}

/// Exact equality, scalar by scalar: Swift's `==` on strings treats
/// canonically equivalent spellings as equal, and Codex does not.
private func sameScalars(_ lhs: [[String]]?, _ rhs: [[String]]?) -> Bool {
    guard let lhs, let rhs else { return lhs == nil && rhs == nil }
    return lhs.count == rhs.count && zip(lhs, rhs).allSatisfy { left, right in
        left.count == right.count
            && zip(left, right).allSatisfy { $0.unicodeScalars.elementsEqual($1.unicodeScalars) }
    }
}

private func reportMismatches(_ label: String, _ mismatches: [String]) {
    check(mismatches.isEmpty, "\(label) (\(codexGateVectors.count) vectors)")
    for mismatch in mismatches.prefix(20) {
        print("       mismatch: \(mismatch)")
    }
}

func codexCommandGateTests() {
    print("\n# Codex command gate (commands csec leaves unwrapped for Codex)")

    // The ported parser and heuristic agree with Codex's exactly.
    var heuristicMismatches: [String] = []
    var plainMismatches: [String] = []
    for vector in codexGateVectors {
        let command = ["/bin/zsh", "-lc", vector.script]
        let heuristic = CodexCommandGate.dangerousCommandMatch(command)
        if heuristic != vector.heuristic {
            heuristicMismatches.append("\(vector.script.debugDescription): Codex \(String(describing: vector.heuristic)), csec \(String(describing: heuristic))")
        }
        let plain = CodexCommandGate.plainCommands(command)
        if !sameScalars(plain, vector.plain) {
            plainMismatches.append("\(vector.script.debugDescription): Codex \(String(describing: vector.plain)), csec \(String(describing: plain))")
        }
    }
    reportMismatches("Codex's dangerous-command heuristic, ported, gives Codex's verdict on every vector",
                     heuristicMismatches)
    reportMismatches("Codex's plain-command split, ported, gives Codex's argv on every vector", plainMismatches)

    // Without rules the gate is exactly Codex's heuristic, plus apply_patch.
    var ruleFreeMismatches: [String] = []
    for vector in codexGateVectors {
        let gated = CodexCommandGate.requiresCodexGate(vector.script, rules: [])
        let expected = vector.gatedWithoutRules || runsPatchTool(vector.script)
        if gated != expected {
            ruleFreeMismatches.append("\(vector.script.debugDescription): expected \(expected), csec \(gated)")
        }
    }
    reportMismatches("with no rules, csec leaves unwrapped exactly what Codex's heuristic gates, plus apply_patch",
                     ruleFreeMismatches)

    // With rules the gate may flag more than Codex, never less.
    var probeMisses: [String] = []
    var extraWithRules = 0
    for vector in codexGateVectors {
        let gated = CodexCommandGate.requiresCodexGate(vector.script, rules: codexProbeRules)
        if vector.gatedWithProbeRules && !gated {
            probeMisses.append(vector.script.debugDescription)
        } else if gated && !vector.gatedWithProbeRules {
            extraWithRules += 1
        }
    }
    reportMismatches("with rules, every command Codex gates is left unwrapped", probeMisses)
    print("note - with the probe rules csec also leaves \(extraWithRules) of \(codexGateVectors.count) vectors "
        + "unwrapped that Codex would not gate (allow rules ignored, apply_patch, path forms)")

    // A rule on the shell itself, by any spelling Codex resolves to one.
    for shellRule in [[["/bin/zsh"]], [["zsh"]], [["bash.exe"]], [["git", "/usr/local/bin/sh"]]] {
        let rules = [CodexCommandGate.PrefixRule(pattern: shellRule, decision: .forbidden)]
        check(["echo $(date)", "ls > /dev/null", "ls"].allSatisfy { CodexCommandGate.requiresCodexGate($0, rules: rules) },
              "a forbidden rule on the shell \(shellRule) leaves every command to Codex")
    }
    check(!CodexCommandGate.requiresCodexGate("ls > /dev/null",
                                               rules: [.init(pattern: [["/bin/zsh"]], decision: .allow)]),
          "an allow rule on the shell gates nothing")

    // Nesting deeper than Codex follows fails closed, counted as Codex counts.
    let wrappers = { (count: Int) in Array(repeating: "env", count: count).joined(separator: " ") }
    check(!CodexCommandGate.requiresCodexGate(wrappers(8) + " ls", rules: []),
          "eight wrappers on a plain command are within Codex's limit")
    check(CodexCommandGate.requiresCodexGate(wrappers(9) + " ls", rules: []),
          "nine wrappers exceed Codex's limit and fail closed")
    check(CodexCommandGate.requiresCodexGate(wrappers(8) + " ls >/dev/null", rules: []),
          "a non-plain script starts one level deeper, so eight wrappers already fail closed")
    check(CodexCommandGate.requiresCodexGate("bash -c \"bash -c 'env env env env env env env ls'\"", rules: [])
          && !CodexCommandGate.requiresCodexGate("bash -c \"bash -c 'env env env env env env ls'\"", rules: []),
          "nested shells and wrappers share Codex's one depth limit")
    // Codex reads a nested script only when it is a literal word; `'\''`
    // escaping hides it from Codex's heuristic, and so from csec's.
    let escapedNesting = (0..<3).reduce("rm -rf x") { inner, _ in
        "bash -c " + "'" + inner.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
    check(CodexCommandGate.dangerousCommandMatch(["/bin/zsh", "-lc", escapedNesting]) == nil,
          "a nested script Codex cannot read literally is not judged by Codex's heuristic")

    // Large input stays linear: a megabyte of plain commands parses and is
    // judged whole.
    let manyCommands = String(repeating: "echo a; ", count: 128 * 1024)
    check(!CodexCommandGate.requiresCodexGate(manyCommands, rules: [])
          && CodexCommandGate.requiresCodexGate(manyCommands + "rm -f x", rules: []),
          "a megabyte of commands is parsed whole, including its last command")
}
