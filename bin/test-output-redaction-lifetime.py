#!/usr/bin/env python3
"""Synthetic scanner-lifetime regression; no installed service or real secrets.

The fake agent advances only its redaction clock by two days between chunks.
Every fixture process is denied writes outside one private temporary directory.
"""

import http.client
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import time


BUILD = Path(__file__).resolve().parent.parent / "agent/.build/debug"
SYNTHETIC = "postgres://s3cr3t"
SERVER = r'''
import http.server
import os
from pathlib import Path
import sys

secret = os.environ["CSEC_SYNTHETIC_VALUE"]
first = True
stopping = False
sys.stdout.write(secret[:9])
sys.stdout.flush()

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        global first, stopping
        if self.path == "/stop":
            stopping = True
        else:
            print(secret[9:] if first else secret, flush=True)
            print(secret, file=sys.stderr, flush=True)
            first = False
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass

with http.server.HTTPServer(("127.0.0.1", 0), Handler) as server:
    Path(sys.argv[1]).write_text(str(server.server_port))
    while not stopping:
        server.handle_request()
'''


def check(condition, label):
    if not condition:
        raise AssertionError(label)
    print("ok - " + label, flush=True)


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def main():
    with tempfile.TemporaryDirectory(prefix="csec-lifetime-", dir="/private/tmp") as directory:
        root = Path(directory)
        endpoint = root / "agent.sock"
        environment = {
            "HOME": str(Path.home()), "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "TMPDIR": directory + "/", "ZDOTDIR": directory,
            "CSEC_SOCKET": str(endpoint),
        }
        policy = (
            '(version 1)(allow default)(deny file-write* '
            '(require-not (require-any (subpath ' + json.dumps(directory)
            + ')(literal "/dev/null"))))'
        )
        sandbox = ["/usr/bin/sandbox-exec", "-p", policy]
        forbidden = root.parent / (root.name + "-outside")
        guard = subprocess.run(sandbox + ["/usr/bin/touch", str(forbidden)],
                               env=environment, cwd=root, capture_output=True, timeout=5)
        check(guard.returncode != 0 and not forbidden.exists(),
              "lifetime fixtures cannot write outside temporary storage")
        unit = subprocess.run(sandbox + [str(BUILD / "cs-selftest"), "--redaction-lifetime-only"],
                              env=environment, cwd=root, capture_output=True, text=True,
                              stdin=subprocess.DEVNULL, timeout=15)
        print(unit.stdout, end="", flush=True)
        check(unit.returncode == 0, "deterministic scanner ownership and lifetime checks pass")

        fixture_environment = dict(environment, CSEC_FAKE_REDACTION_ADVANCE_SECONDS="172800")
        agent = subprocess.Popen(sandbox + [str(BUILD / "cs-fake-agent")],
                                 env=fixture_environment, cwd=root, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        children = []
        try:
            deadline = time.monotonic() + 5
            while not endpoint.exists() and agent.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            check(endpoint.exists() and agent.poll() is None, "isolated synthetic scanner started")
            script = root / "server.py"
            script.write_text(SERVER)

            def start_server(name):
                ready = root / (name + ".port")
                stdout, stderr = root / (name + ".stdout"), root / (name + ".stderr")
                with stdout.open("wb") as out, stderr.open("wb") as err:
                    process = subprocess.Popen(
                        sandbox + [str(BUILD / "csec"), "ai", "--",
                                   shlex.join(["/usr/bin/python3", "-B", str(script), str(ready)])],
                        env=dict(environment, CSEC_SYNTHETIC_VALUE="op://demo/db/url"),
                        cwd=root, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                    )
                children.append(process)
                deadline = time.monotonic() + 5
                while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.02)
                check(ready.exists() and process.poll() is None, name + " background server started")
                # Allow the initial partial output to reach the scanner before
                # any HTTP request produces the remaining bytes.
                time.sleep(0.3)
                return process, int(ready.read_text()), stdout, stderr

            def request(port, path):
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
                try:
                    connection.request("GET", path)
                    response = connection.getresponse()
                    return response.status, response.read()
                finally:
                    connection.close()

            server, port, stdout, stderr = start_server("idle")
            for index in range(2):
                check(request(port, "/later") == (200, b"ok"),
                      "background server responds after simulated idle days (request %s)" % (index + 1))
                time.sleep(0.1)
                check(server.poll() is None, "scanner retains the running background command")
            check(request(port, "/stop") == (200, b"ok") and server.wait(timeout=5) == 0,
                  "the background command exits normally when explicitly stopped")
            captured = stdout.read_text() + stderr.read_text()
            check(SYNTHETIC not in captured and captured.count("[csec:secret-") == 4,
                  "split stdout and stderr secrets remain redacted across idle days")

            server, port, stdout, stderr = start_server("scanner-loss")
            stop(agent)
            try:
                request(port, "/later")
            except (OSError, http.client.HTTPException):
                pass
            check(server.wait(timeout=5) == 1, "actual scanner loss still terminates the command")
            captured = stdout.read_text() + stderr.read_text()
            check(SYNTHETIC not in captured
                  and "csecd stopped while this command held values it had delivered; command terminated"
                  in captured,
                  "scanner loss never forwards the withheld or newly emitted secret, and says csecd stopped")
        finally:
            for child in children:
                stop(child)
            stop(agent)


if __name__ == "__main__":
    main()
