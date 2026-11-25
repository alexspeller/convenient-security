#!/usr/bin/env python3
"""Focused macOS csec ai regression; only a private, in-memory fake agent.

Build first with `mise exec -- swift build --package-path agent`, then run
`mise exec -- python3 bin/test-ai-sandbox.py`. No installed service, providers,
bulk-protection operations, user shell startup files, or real credentials are
used. Every fixture/CLI process is denied filesystem writes outside its private
temporary directory, including the fake agent's canonical-directory setup.
"""

import base64
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time


REPO = Path(__file__).resolve().parent.parent
BUILD = REPO / "agent/.build/debug"
CSEC = BUILD / "csec"
FAKE_AGENT = BUILD / "cs-fake-agent"
SELFTEST = BUILD / "cs-selftest"
SYNTHETIC = "postgres://s3cr3t"


def check(condition, label):
    if not condition:
        raise AssertionError(label)
    print("ok - " + label, flush=True)


def main():
    for binary in (CSEC, FAKE_AGENT, SELFTEST):
        if not binary.is_file():
            raise RuntimeError("build the debug targets before running this test")

    with tempfile.TemporaryDirectory(prefix="csec-ai-test-", dir="/private/tmp") as directory:
        root = Path(directory)
        endpoint = root / "agent.sock"
        marker = root / "must-not-exist"
        environment = {
            "HOME": str(Path.home()),
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "TMPDIR": directory + "/",
            "ZDOTDIR": directory,
            "CSEC_SOCKET": str(endpoint),
            "CSEC_SETUP_TEST_DIRECTORY": directory,
        }
        safety_policy = (
            "(version 1)(allow default)"
            "(deny file-write* (require-not (require-any (subpath "
            + json.dumps(directory) + ")(literal \"/dev/null\"))))"
        )
        # Verify the write boundary before starting even the synthetic daemon.
        forbidden = root.parent / (root.name + "-outside")
        guard = subprocess.run(
            ["/usr/bin/sandbox-exec", "-p", safety_policy, "/usr/bin/touch", str(forbidden)],
            env=environment, cwd=root, capture_output=True, timeout=5,
        )
        check(guard.returncode != 0 and not forbidden.exists(),
              "fixture sandbox denies writes outside its temporary directory")

        setup_tests = subprocess.run(
            ["/usr/bin/sandbox-exec", "-p", safety_policy, str(SELFTEST), "--codex-sandbox-only"],
            env=environment, cwd=root, stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=15,
        )
        print(setup_tests.stdout, end="", flush=True)
        check(setup_tests.returncode == 0, "isolated automatic Codex setup regression passes")

        agent = subprocess.Popen(
            ["/usr/bin/sandbox-exec", "-p", safety_policy, str(FAKE_AGENT)],
            env=environment, cwd=root, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            started = time.monotonic()
            # A loaded Mac can take more than five seconds to launch the fixture.
            # Keep waiting only while it is alive; a failed launch stops at once.
            deadline = started + 30
            while not endpoint.exists() and agent.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            seconds = time.monotonic() - started
            endpoint_exists = endpoint.exists()
            status = agent.poll()
            check(endpoint_exists and status is None,
                  f"private synthetic agent started (seconds={seconds:.2f}, "
                  f"status={status}, endpoint={endpoint_exists})")

            def run(program, rules="", extra_env=None, verb="ai", encoded=False, input_text=None,
                    timeout=10, binary=CSEC):
                env = dict(environment)
                env.update(extra_env or {})
                started = time.monotonic()
                arguments = ["--", program]
                if encoded:
                    arguments = ["--encoded-shell-command",
                                 base64.urlsafe_b64encode(program.encode()).decode().rstrip("=")]
                result = subprocess.run(
                    ["/usr/bin/sandbox-exec", "-p", safety_policy + rules, str(binary), verb] + arguments,
                    env=env, cwd=root, stdin=subprocess.DEVNULL if input_text is None else None,
                    input=input_text, capture_output=True, text=True, timeout=timeout,
                )
                return result, time.monotonic() - started

            seeded, _ = run(
                'printf %s "$CSEC_SYNTHETIC_VALUE"',
                extra_env={"CSEC_SYNTHETIC_VALUE": "op://demo/db/url"},
            )
            if seeded.returncode != 0:
                print("synthetic setup status:", seeded.returncode,
                      "diagnostic:", seeded.stderr.replace(SYNTHETIC, "<fixture>"), flush=True)
            check(seeded.returncode == 0 and "[csec:secret-" in seeded.stdout
                  and SYNTHETIC not in seeded.stdout + seeded.stderr,
                  "synthetic reference injection and output redaction work")

            # Direct CLI calls used to bypass csec's resident provider and raise
            # another 1Password prompt. The fake op must NEVER start.
            op_bin = root / "fake-bin"
            op_bin.mkdir()
            op_marker = root / "op-started"
            fake_op = op_bin / "op"
            fake_op.write_text("#!/bin/sh\n/usr/bin/touch " + shlex.quote(str(op_marker))
                               + "\nprintf unexpected-op\n")
            fake_op.chmod(0o700)
            # Login startup can replace PATH and define op. The guard has to run
            # after startup, without suppressing the user's other startup state.
            (root / ".zprofile").write_text(
                "export PATH=" + shlex.quote(str(op_bin) + ":/usr/bin:/bin") + "\n"
                "export CSEC_STARTUP_FIXTURE=kept\n"
                "op() { printf startup-op; }\n"
            )
            programs = [
                ("literal CLI", "op read ignored"),
                ("absolute CLI", shlex.join([str(fake_op), "read", "ignored"])),
                ("shell child", "/bin/sh -c 'op read ignored'"),
                ("login-shell child", "/bin/zsh -lc 'op read ignored'"),
                ("Python child", shlex.join([sys.executable, "-c",
                    "import subprocess; raise SystemExit(subprocess.call(['op', 'read', 'ignored']))"])),
                ("dynamic command", 'tool=op; "$tool" read ignored'),
                ("command prefix", 'command op read ignored'),
            ]
            for verb in ("ai", "tool-exec"):
                for missing_agent in (False, True):
                    extra = {"CSEC_SOCKET": str(root / "missing.sock")} if missing_agent else {}
                    for case, program in programs:
                        refused, _ = run(program, extra_env=extra, verb=verb)
                        check(refused.returncode == 126 and not op_marker.exists()
                              and "use csec" in refused.stderr.lower()
                              and "unexpected-op" not in refused.stdout
                              and "startup-op" not in refused.stdout,
                              f"{verb} refuses {case} with daemon missing={missing_agent}")
                        check(not list(root.glob("csec-ai-tools.*")),
                              "the per-command op shim is removed after refusal")
            encoded, _ = run('tool=op; "$tool" read ignored', encoded=True)
            check(encoded.returncode == 126 and not op_marker.exists(),
                  "legacy encoded ai commands retain the op refusal")
            ordinary, _ = run('printf "%s" "$CSEC_STARTUP_FIXTURE"; '
                              + shlex.join(["/bin/sh", "-c", 'printf " op read is text"']) + "; exit 7")
            check(ordinary.returncode == 7 and ordinary.stdout == "kept op read is text",
                  "ordinary text, startup state, quoting and exit status survive the guard")
            piped, _ = run("/bin/cat", input_text="synthetic stdin\nsecond line\n")
            check(piped.returncode == 0 and piped.stdout == "synthetic stdin\nsecond line\n",
                  "the launch prelude preserves stdin")
            quoted_tmp = root / "temp's space"
            quoted_tmp.mkdir()
            modes, _ = run(shlex.join([sys.executable, "-c",
                "import pathlib,shutil,stat; p=pathlib.Path(shutil.which('op')); "
                "print(oct(stat.S_IMODE(p.stat().st_mode)), oct(stat.S_IMODE(p.parent.stat().st_mode)))"]),
                extra_env={"TMPDIR": str(quoted_tmp) + "/"})
            check(modes.returncode == 0 and modes.stdout.strip() == "0o700 0o700"
                  and not list(quoted_tmp.glob("csec-ai-tools.*")),
                  "a quoted temporary path works and the shim/directory stay private")
            (root / ".zprofile").unlink()

            command = shlex.join(["/usr/bin/touch", str(marker)])
            blocked_tmp = root / "blocked-tmp"
            blocked_tmp.mkdir()
            guard_denied, _ = run(command,
                "(deny file-write* (subpath " + json.dumps(str(blocked_tmp)) + "))",
                extra_env={"TMPDIR": str(blocked_tmp) + "/"})
            check(guard_denied.returncode == 126 and not marker.exists()
                  and "could not prepare the direct op guard" in guard_denied.stderr,
                  "an unavailable shim never starts an unguarded command")

            # The app bundle ships the shim, so a child whose sandbox allows no
            # writes at all (Codex's read-only mode) still runs, and is guarded.
            contents = root / "Shipped's App.app" / "Contents"
            (contents / "MacOS").mkdir(parents=True)
            shipped_csec = contents / "MacOS" / "csec"
            shutil.copy2(CSEC, shipped_csec)
            shipped = contents / "Resources" / "ai-guard"
            shipped.mkdir(parents=True)
            shipped_op = shipped / "op"
            shutil.copy2(REPO / "packaging/agent/ai-guard/op", shipped_op)
            shipped_op.chmod(0o755)
            no_writes = "(deny file-write* (subpath " + json.dumps(str(root)) + "))"
            read_only_probe = 'command -v op; tool=op; "$tool" read ignored'
            read_only, _ = run(read_only_probe, no_writes, binary=shipped_csec)
            check(read_only.returncode == 126 and Path(read_only.stdout.strip()).resolve() == shipped_op.resolve()
                  and "use csec" in read_only.stderr.lower() and not op_marker.exists(),
                  "a read-only sandbox runs commands with the bundle's shipped op guard")
            ordinary, _ = run("pwd", no_writes, binary=shipped_csec)
            check(ordinary.returncode == 0 and ordinary.stdout.strip() == str(root.resolve()),
                  "an ordinary command runs in a read-only sandbox")
            kept, _ = run("printf kept", binary=shipped_csec)
            check(kept.returncode == 0 and kept.stdout == "kept" and shipped_op.is_file()
                  and not list(root.glob("csec-ai-tools.*")),
                  "the shipped shim is used without a temporary copy and survives cleanup")

            # Anything but the exact private shim alone falls back to the
            # temporary one, so with no writable TMPDIR the command is refused.
            def tampered(label, damage, repair):
                damage()
                try:
                    result, _ = run(read_only_probe, no_writes, binary=shipped_csec)
                    check(result.returncode == 126
                          and "could not prepare the direct op guard" in result.stderr
                          and result.stdout == "",
                          f"a shipped shim that is {label} is not trusted")
                finally:
                    repair()
            extra = shipped / "git"
            tampered("joined by another command",
                     lambda: (extra.write_text("#!/bin/sh\n"), extra.chmod(0o755)), extra.unlink)
            tampered("group-writable", lambda: shipped_op.chmod(0o775), lambda: shipped_op.chmod(0o755))
            tampered("not executable", lambda: shipped_op.chmod(0o644), lambda: shipped_op.chmod(0o755))
            original_shim = shipped_op.read_bytes()
            tampered("edited", lambda: shipped_op.write_bytes(original_shim + b"exit 0\n"),
                     lambda: shipped_op.write_bytes(original_shim))
            shutil.rmtree(contents.parent)

            # A daemon/setup failure still runs ordinary commands, retaining the
            # op guard. It warns on stderr (naming the cause and fix) and runs
            # the command WITHOUT csec — references left unresolved, no secrets
            # injected or revealed — instead of refusing and bricking the shell.
            def degraded(result, label, *, guidance=None):
                ran = result.returncode == 0 and marker.exists()
                warned = "Running the command WITHOUT csec" in result.stderr
                ok = ran and warned and (guidance is None or guidance in result.stderr)
                check(ok, label)
                if marker.exists():
                    marker.unlink()

            denied, denied_seconds = run(command, "(deny network*)")
            degraded(denied, "a sandbox-denied socket warns and runs the command",
                     guidance="config.toml")
            check("agent socket access denied" in denied.stderr and str(endpoint) in denied.stderr
                  and "csec doctor" not in denied.stderr,
                  "the sandbox warning names the socket and does not misdirect to csec doctor")
            check('sandbox_permissions="require_escalated"' in denied.stderr
                  and "network.unix_sockets" in denied.stderr
                  and "csec setup" in denied.stderr and "features.network_proxy=true" in denied.stderr,
                  "the sandbox warning gives the approved-retry and automatic/manual setup instructions")

            inaccessible = root / "inaccessible"
            inaccessible.mkdir(mode=0o000)
            try:
                denied_access, _ = run(command, extra_env={
                    "CSEC_SOCKET": str(inaccessible / "agent.sock"),
                })
                degraded(denied_access, "an inaccessible socket path warns and runs the command",
                         guidance="agent socket access denied")
            finally:
                inaccessible.chmod(0o700)

            allow_socket = (
                "(deny network-outbound (require-not (remote unix-socket (literal "
                + json.dumps(str(endpoint)) + "))))"
            )
            deny_marker = "(deny file-write* (literal " + json.dumps(str(marker)) + "))"
            allowed, _ = run(
                "if " + command + " 2>/dev/null; then printf escaped; "
                "else printf write-denied; fi; printf %s " + shlex.quote(SYNTHETIC),
                allow_socket + deny_marker,
            )
            check(allowed.returncode == 0 and "write-denied" in allowed.stdout
                  and "[csec:secret-" in allowed.stdout
                  and SYNTHETIC not in allowed.stdout + allowed.stderr and not marker.exists(),
                  "exact socket allowance restores redaction and retains the child's write denial")

            other_path = root / "other.sock"
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as other:
                other.bind(str(other_path))
                other.listen()
                # The sandbox allows only the fake agent's endpoint, so connecting
                # to this other socket is denied — still a warn-and-run, never a block.
                other_result, _ = run(command, allow_socket, {"CSEC_SOCKET": str(other_path)})
                degraded(other_result, "a sandbox-denied non-agent socket warns and runs the command",
                         guidance="agent socket access denied")

            # A transport that closes after receiving request bytes is not a
            # missing daemon; csec ai still runs the command rather than blocking.
            broken_path = root / "broken.sock"
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as broken:
                broken.bind(str(broken_path))
                broken.listen()
                # The client verifies this Python process's code identity before
                # sending anything. Give startup/authentication the same headroom
                # as the fake agent's startup, within one accept/read deadline.
                deadline = time.monotonic() + 30
                broken.settimeout(30)

                def close_request():
                    connection, _ = broken.accept()
                    with connection:
                        connection.settimeout(max(0.001, deadline - time.monotonic()))
                        return connection.recv(4096)

                with ThreadPoolExecutor(max_workers=1) as executor:
                    worker = executor.submit(close_request)
                    broken_result, _ = run(
                        command, extra_env={"CSEC_SOCKET": str(broken_path)}, timeout=45,
                    )
                    # result() propagates fixture failures; a dead thread alone
                    # also passed when recv timed out or the client sent nothing.
                    check(worker.result(timeout=5), "the broken-socket worker received request bytes")
                degraded(broken_result, "a transport failure warns and runs the command",
                         guidance="the connection to csecd failed mid-request")

            missing, missing_seconds = run(command, extra_env={
                "CSEC_SOCKET": str(root / "missing.sock"),
            })
            degraded(missing, "a missing daemon warns with service-repair advice and runs the command",
                     guidance="csec doctor")
            check("not reachable" in missing.stderr,
                  "the missing-daemon warning says the agent is unreachable")
            check(missing_seconds >= 2, "a real outage retains the bounded reconnect window")
            # Leave generous process-startup headroom while detecting the old
            # unconditional two-second retry on a permanent permission denial.
            check(denied_seconds < 2, "permission denial does not wait through the reconnect window")

            # The security property of the degraded path: a reference is passed
            # through UNRESOLVED — csec never resolves or reveals a secret when it
            # cannot operate, so a bare op:// reference reaches the child, never a value.
            unresolved, _ = run(
                'printf %s "$CSEC_SYNTHETIC_VALUE"',
                extra_env={"CSEC_SOCKET": str(root / "missing.sock"),
                           "CSEC_SYNTHETIC_VALUE": "op://demo/db/url"},
            )
            check(unresolved.returncode == 0 and unresolved.stdout == "op://demo/db/url"
                  and "Running the command WITHOUT csec" in unresolved.stderr,
                  "an unreachable daemon leaves references unresolved — no secret is revealed")
        finally:
            agent.terminate()
            try:
                agent.wait(timeout=5)
            except subprocess.TimeoutExpired:
                agent.kill()
                agent.wait(timeout=5)


if __name__ == "__main__":
    main()
