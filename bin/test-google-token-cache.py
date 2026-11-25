#!/usr/bin/env python3
"""Google sign-in confinement against real consumers; offline, synthetic values only.

csec's Google sign-in is an external-account credential file whose executable
source runs `csec creds google`. That keeps the *subject* token (the Mac's
signed JWT) off disk, but what the consumer does with the access token it
exchanges the JWT for is the consumer's business, and the docs make claims
about both. This checks those claims against the real consumers:

- the credential file comes from the debug `csec identity setup google`,
  talking to cs-fake-agent (software key, scripted consent);
- the real gcloud CLI runs through the installed shell function and csec
  wrapper; google-auth independently uses the executable credential file;
- Google's endpoints are answered by synthetic exchanges in the fake agent
  and a requests-transport stub for client libraries. Every fixture runs under
  sandbox-exec with no IP network and no writes outside one temporary
  directory.

Usage: mise exec -- python3 bin/test-google-token-cache.py <gcloud SDK root>
"""

import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time


BUILD = Path(__file__).resolve().parent.parent / "agent/.build/debug"
AUDIENCE = ("//iam.googleapis.com/projects/123456/locations/global/"
            "workloadIdentityPools/fixture-pool/providers/fixture-provider")
SERVICE_ACCOUNT = "fixture@fixture-project.iam.gserviceaccount.com"

# Runs one consumer in its own process, the way a terminal would, with Google's
# endpoints stubbed at the transport. Every token it hands out names the
# process that asked, so a token seen later shows which process exchanged it.
DRIVER = r'''
import datetime
import json
import os
import socket
import subprocess
import sys
import urllib.parse

sdk, report_path, mode = sys.argv[1:4]
arguments = sys.argv[4:]
sys.path[:0] = [os.path.join(sdk, "lib"), os.path.join(sdk, "lib", "third_party")]

report = {"requests": [], "unexpected": [], "executable_runs": 0, "subject_tokens": [], "bearer": []}

def write_report():
    with open(report_path, "w") as handle:
        json.dump(report, handle)

original_connect = socket.socket.connect
def refuse_ip(self, address):
    if self.family in (socket.AF_INET, socket.AF_INET6):
        report["unexpected"].append("socket:%r" % (address,))
        raise OSError("the fixture refuses IP network")
    return original_connect(self, address)
socket.socket.connect = refuse_ip

original_run = subprocess.run
def counted_run(args, *rest, **options):
    words = args.split() if isinstance(args, str) else list(args)
    if words[1:3] == ["creds", "google"]:
        report["executable_runs"] += 1
    return original_run(args, *rest, **options)
subprocess.run = counted_run

import requests
import requests.adapters

def later(seconds):
    return datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=seconds)

def answer(url, body):
    tag = "%s-%d" % (mode, os.getpid())
    if url == "https://sts.googleapis.com/v1/token":
        form = urllib.parse.parse_qs(body)
        report["subject_tokens"] += form.get("subject_token", [])
        return 200, {"access_token": "FIXTURE-FEDERATED-" + tag, "token_type": "Bearer",
                     "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                     "expires_in": 3600}
    if url.startswith("https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/") \
            and url.endswith(":generateAccessToken"):
        return 200, {"accessToken": "FIXTURE-IMPERSONATED-" + tag,
                     "expireTime": later(3600).strftime("%Y-%m-%dT%H:%M:%SZ")}
    if url == "https://sts.googleapis.com/v1/introspect":
        return 200, {"active": True, "username": "principal://fixture-introspected"}
    # google-auth's regional access boundary lookup and its project lookup
    # (load_credentials_from_file asks for the project id): inert answers.
    if url.startswith("https://iamcredentials.googleapis.com/v1/") and url.endswith("/allowedLocations"):
        return 200, {"locations": [], "encodedLocations": "0x0"}
    if url == "https://cloudresourcemanager.googleapis.com/v1/projects/123456":
        return 200, {"projectId": "fixture-project", "projectNumber": "123456"}
    if url == "https://storage.googleapis.com/storage/v1/b":
        return 200, {"kind": "storage#buckets", "items": [{"name": "fixture-bucket", "location": "EU"}]}
    return None, None

def stubbed_send(self, request, **options):
    body = request.body or ""
    if isinstance(body, bytes):
        body = body.decode("utf-8")
    status, payload = answer(request.url.split("?")[0], body)
    report["requests"].append(request.url.split("?")[0])
    authorization = request.headers.get("Authorization", "")
    if isinstance(authorization, bytes):
        authorization = authorization.decode("ascii")
    if request.url.startswith(("https://cloudresourcemanager.googleapis.com/", "https://storage.googleapis.com/")) and authorization.startswith("Bearer "):
        report.setdefault("bearer", []).append(authorization[len("Bearer "):])
    response = requests.Response()
    response.request = request
    response.url = request.url
    if status is None:
        report["unexpected"].append(request.url)
        status, payload = 404, {"error": "not served by the fixture"}
    response.status_code = status
    response.headers["Content-Type"] = "application/json"
    response._content = json.dumps(payload).encode("utf-8")
    return response
requests.adapters.HTTPAdapter.send = stubbed_send

code = 0
try:
    if mode == "library":
        import google.auth
        import google.auth.transport.requests
        credentials, _ = google.auth.load_credentials_from_file(
            arguments[0], scopes=["https://www.googleapis.com/auth/cloud-platform"])
        credentials.refresh(google.auth.transport.requests.Request())
        print(credentials.token)
    elif mode == "reload":
        from googlecloudsdk.core.credentials import store
        first = store.Load()
        second = store.Load()
        report["reload_ok"] = bool(first.token) and first.token == second.token
        print("credential transports reloaded")
    else:
        import runpy
        sys.argv = ["gcloud"] + arguments
        runpy.run_path(os.path.join(sdk, "lib", "gcloud.py"), run_name="__main__")
except SystemExit as exit:
    code = exit.code if isinstance(exit.code, int) else (0 if exit.code is None else 1)
finally:
    report["exit"] = code
    write_report()
sys.exit(code)
'''


def check(condition, label, *, result=None, outcome=None):
    if not condition:
        if result is not None:
            print("consumer Python: %s (%s)" % (sys.executable, sys.version.split()[0]), file=sys.stderr)
            print("consumer return code: %s" % result.returncode, file=sys.stderr)
            # Every consumer is confined to synthetic fixture credentials.
            # Bound the streams; import failures can happen before a report exists.
            print("consumer stdout (last 4000 characters):\n" + result.stdout[-4000:], file=sys.stderr)
            print("consumer stderr (last 4000 characters):\n" + result.stderr[-4000:], file=sys.stderr)
        if outcome is not None:
            metadata = {key: outcome.get(key) for key in ("exit", "executable_runs", "unexpected")}
            metadata["subject_token_count"] = len(outcome.get("subject_tokens", []))
            print("consumer outcome: " + json.dumps(metadata, sort_keys=True), file=sys.stderr)
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


def files_holding(root, needle):
    """Every file under root whose bytes contain needle."""
    found = []
    for path in sorted(Path(root).rglob("*")):
        if path.is_file() and not path.is_symlink() and needle.encode() in path.read_bytes():
            found.append(str(path.relative_to(root)))
    return found


def main():
    if len(sys.argv) != 2 or not (Path(sys.argv[1]) / "lib/gcloud.py").is_file():
        sys.exit("usage: test-google-token-cache.py <gcloud SDK root>")
    sdk = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix="csec-google-cache-", dir="/private/tmp") as directory:
        root = Path(directory)
        endpoint = root / "agent.sock"
        reports = root / "reports"
        work = root / "work"
        for path in (reports, work):
            path.mkdir()
        driver = reports / "driver.py"
        driver.write_text(DRIVER)
        fixture_bin = root / "bin"
        fixture_bin.mkdir()
        gcloud = fixture_bin / "gcloud"
        gcloud.write_text("#!/bin/sh\nexec " + " ".join(map(shlex.quote, [sys.executable, "-I", "-B", str(driver), sdk]))
                          + ' "$CSEC_GOOGLE_REPORT" "${CSEC_GOOGLE_DRIVER_MODE:-gcloud}" "$@"\n')
        gcloud.chmod(0o700)
        state = root / "google-state"
        state.mkdir()
        base = {
            "PATH": str(fixture_bin) + ":/usr/bin:/bin:/usr/sbin:/sbin", "TMPDIR": directory + "/",
            "CSEC_SOCKET": str(endpoint), "LANG": "en_US.UTF-8",
            "CSEC_FAKE_GOOGLE_STATE": str(state),
        }
        policy = (
            '(version 1)(allow default)'
            '(deny network-outbound (remote ip))'
            '(deny file-write* (require-not (require-any (subpath ' + json.dumps(directory)
            + ')(literal "/dev/null")(literal "/dev/tty"))))'
        )
        sandbox = ["/usr/bin/sandbox-exec", "-p", policy]
        forbidden = root.parent / (root.name + "-outside")
        guard = subprocess.run(sandbox + ["/usr/bin/touch", str(forbidden)],
                               env=base, cwd=work, capture_output=True, timeout=5)
        check(guard.returncode != 0 and not forbidden.exists(),
              "fixtures cannot write outside temporary storage")
        guard = subprocess.run(sandbox + ["/usr/bin/nc", "-z", "-G", "2", "1.1.1.1", "443"],
                               env=base, cwd=work, capture_output=True, timeout=10)
        check(guard.returncode != 0, "fixtures cannot reach the IP network")

        agent = subprocess.Popen(sandbox + [str(BUILD / "cs-fake-agent")],
                                 env=dict(base, HOME=str(root / "agent-home")), cwd=work,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 5
            while not endpoint.exists() and agent.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            check(endpoint.exists() and agent.poll() is None, "isolated fake agent started")

            def csec(*arguments, home):
                result = subprocess.run(sandbox + [str(BUILD / "csec")] + list(arguments),
                                        env=dict(base, HOME=str(home), CLOUDSDK_CONFIG=str(home / "gcloud")),
                                        cwd=work, stdin=subprocess.DEVNULL, capture_output=True,
                                        text=True, timeout=30)
                if result.returncode != 0:
                    print(result.stdout + result.stderr, file=sys.stderr)
                return result

            setup_home = root / "setup-home"
            check(csec("identity", "create", "--issuer", "https://issuer.invalid",
                       "--subject", "fixture-mac", home=setup_home).returncode == 0,
                  "fixture identity created")
            files = {}
            setup_homes = {}
            for name, extra in (("impersonated", ["--service-account", SERVICE_ACCOUNT]), ("direct", [])):
                setup_homes[name] = setup_home / name
                setup_homes[name].mkdir(parents=True)
                (setup_homes[name] / ".zshrc").write_text("# preserved fixture startup\n")
                check(csec("identity", "target", "add", "default/gcp-" + name, "--audience", AUDIENCE,
                           home=setup_homes[name]).returncode == 0, "%s: OIDC sign-in created" % name)
                files[name] = work / ("cred-%s.json" % name)
                result = csec("identity", "setup", "google", "default/gcp-" + name, "--file", str(files[name]),
                              *extra, home=setup_homes[name])
                configuration = json.loads(files[name].read_text())
                executable = configuration["credential_source"]["executable"]
                check(result.returncode == 0 and "output_file" not in executable
                      and executable["command"].split()[1:3] == ["creds", "google"],
                      "%s: csec identity setup google wrote an executable source with no output file" % name)
                check("wrapper writes no access token or gcloud file log" in result.stdout
                      and "same-user process inspection" in result.stdout,
                      "%s: setup explains the confinement and its process-environment limit" % name)
                startup = (setup_homes[name] / ".zshrc").read_text()
                again = csec("identity", "setup", "google", "default/gcp-" + name, "--file", str(files[name]),
                             *extra, home=setup_homes[name])
                check(again.returncode == 0 and startup.startswith("# preserved fixture startup\n")
                      and (setup_homes[name] / ".zshrc").read_text() == startup,
                      "%s: setup preserves shell content and installs idempotently" % name)

            def consumer(mode, home, *arguments, reference=None, shell=None):
                report = reports / ("%s-%d.json" % (mode, len(list(reports.glob("*.json")))))
                environment = dict(
                    base, HOME=str(home), CLOUDSDK_CONFIG=str(home / "gcloud"),
                    GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES="1",
                    CLOUDSDK_CORE_DISABLE_USAGE_REPORTING="true",
                    CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK="true",
                    CLOUDSDK_CORE_DISABLE_PROMPTS="1",
                    CSEC_GOOGLE_REPORT=str(report),
                )
                if reference is None:
                    command = [sys.executable, "-I", "-B", str(driver), sdk, str(report), mode] + list(arguments)
                else:
                    # Poison inherited settings: the wrapper must override these,
                    # including named-config impersonation (tested below).
                    environment.update(CLOUDSDK_CORE_LOG_HTTP="true", CLOUDSDK_CORE_DISABLE_FILE_LOGGING="false",
                                       CLOUDSDK_AUTH_ACCESS_TOKEN="FIXTURE-AMBIENT-TOKEN")
                    if mode == "reload":
                        environment["CSEC_GOOGLE_DRIVER_MODE"] = "reload"
                    if shell:
                        executable, source = shell
                        if "fish" in executable:
                            command = [executable, "--no-config", "-c",
                                       'source $argv[1]; set -e argv[1]; gcloud $argv', "--", str(source)]
                        else:
                            command = [executable, "-c", '. "$1"; shift; gcloud "$@"', "fixture", str(source)]
                        command += list(arguments)
                    else:
                        command = [str(BUILD / "csec"), "gcloud", "--item", reference, "--"] + list(arguments)
                result = subprocess.run(
                    sandbox + command, env=environment, cwd=work, stdin=subprocess.DEVNULL,
                    capture_output=True, text=True, timeout=120)
                outcome = json.loads(report.read_text()) if report.exists() else {"exit": None}
                if outcome.get("unexpected"):
                    print(result.stdout + result.stderr, file=sys.stderr)
                return result, outcome

            def events():
                path = state / "events"
                return path.read_text().splitlines() if path.exists() else []

            for name in ("impersonated", "direct"):
                token_prefix = "FIXTURE-IMPERSONATED-" if name == "impersonated" else "FIXTURE-FEDERATED-"

                # The client libraries (here google-auth, which gcloud bundles):
                # the exchanged token lives in the process and nowhere else.
                home = root / ("library-" + name)
                home.mkdir()
                result, outcome = consumer("library", home, str(files[name]))
                token = result.stdout.strip()
                check(result.returncode == 0 and token.startswith(token_prefix)
                      and outcome["executable_runs"] >= 1
                      and len(outcome["subject_tokens"]) == outcome["executable_runs"]
                      and not outcome["unexpected"],
                      "%s: google-auth ran csec creds google and exchanged its token offline" % name,
                      result=result, outcome=outcome)
                check(files_holding(home, token) == [] and list(home.rglob("*")) == [],
                      "%s: google-auth keeps the exchanged token in memory and writes no file" % name)
                check(all(files_holding(home, subject) == [] and files_holding(work, subject) == []
                          for subject in outcome["subject_tokens"]),
                      "%s: the subject token csec printed is written nowhere" % name)

                # The real gcloud CLI through csec's ordinary exec delivery.
                # Every process has an independent, explicitly reviewed scope;
                # csecd may hold a token already, which must not bypass review.
                home = root / ("gcloud-" + name)
                home.mkdir()
                config = home / "gcloud/configurations"
                config.mkdir(parents=True)
                (config / "config_default").write_text(
                    "[auth]\nimpersonate_service_account = unapproved@fixture-project.iam.gserviceaccount.com\n")
                reference = "csec-identity://default/gcp-%s-gcloud" % name
                token = "FIXTURE-CSECD-IMPERSONATED" if name == "impersonated" else "FIXTURE-CSECD-FEDERATED"
                describe = ["projects", "describe", "123456", "--format=value(projectId)"]
                before = events()
                first, first_outcome = consumer("wrapped", home, *describe, reference=reference)
                after = events()[len(before):]
                check(first.returncode == 0 and first.stdout.strip() == "fixture-project"
                      and first_outcome.get("bearer") == [token] and not first_outcome["unexpected"],
                      "%s: wrapped gcloud uses csecd's exchanged access token for its API request" % name)
                if not after:
                    print("fixture review trace:", json.dumps(before), flush=True)
                check(bool(after) and after[0].startswith("review ") and after[1:] == (
                    ["sts", "impersonation"] if name == "impersonated" else ["sts"]),
                    "%s: csecd exchanges only after that process's review" % name)
                check(first_outcome["executable_runs"] == 0 and not first_outcome["subject_tokens"]
                      and not any(url.endswith((":generateAccessToken", "/v1/token")) for url in first_outcome["requests"]),
                      "%s: gcloud never receives a JWT or performs its own cached exchange/impersonation" % name)
                check(files_holding(home, token) == [] and not (home / "gcloud/access_tokens.db").exists()
                      and not (home / "gcloud/logs").exists(),
                      "%s: no access token, token database or file log in CLOUDSDK_CONFIG" % name)
                first_review = after[0]
                before = events()
                second, second_outcome = consumer("wrapped", home, *describe, reference=reference)
                after = events()[len(before):]
                check(second.returncode == 0 and second_outcome.get("bearer") == [token]
                      and len(after) == 1 and after[0].startswith("review ")
                      and after[0] != first_review,
                      "%s: an independent process gets a fresh review even while csecd holds its token" % name)
                (state / "deny").touch()
                before = events()
                refused, refused_outcome = consumer("wrapped", home, *describe, reference=reference)
                (state / "deny").unlink()
                check(refused.returncode != 0 and refused_outcome["exit"] is None
                      and len(events()) == len(before) + 1 and events()[-1].startswith("review "),
                      "%s: denial prevents gcloud from starting despite an existing token in csecd" % name)
                reloaded, reload_outcome = consumer("reload", home, *describe, reference=reference)
                check(reloaded.returncode == 0 and reload_outcome.get("reload_ok"),
                      "%s: repeated real gcloud credential loads retain the supplied token" % name)
                storage, storage_outcome = consumer("wrapped", home, "storage", "ls", "--project=123456", reference=reference)
                check(storage.returncode == 0 and "gs://fixture-bucket" in storage.stdout
                      and storage_outcome.get("bearer") == [token] and not storage_outcome["unexpected"],
                      "%s: gcloud storage uses the reviewed token without a gsutil cache" % name)
                for executable in ("/bin/bash", "/bin/zsh", "/opt/homebrew/bin/fish"):
                    if not Path(executable).exists():
                        continue
                    fish = "fish" in executable
                    source = setup_homes[name] / (".config/fish/conf.d/csec-gcloud.fish" if fish else ".config/csec/gcloud.sh")
                    wrapped, wrapped_outcome = consumer("wrapped", home, *describe, reference=reference,
                                                        shell=(executable, source))
                    check(wrapped.returncode == 0 and wrapped_outcome.get("bearer") == [token],
                          "%s: installed %s function runs the reviewed gcloud wrapper" % (name, Path(executable).name))
                before = events()
                for args in (["auth", "print-access-token"], ["auth", "login"], ["config", "list"],
                             ["projects", "list", "--impersonate-service-account=" + SERVICE_ACCOUNT],
                             ["--flags-file=hidden.yaml"], ["--access-token-file=/tmp/token"]):
                    rejected, _ = consumer("wrapped", home, *args, reference=reference)
                    check(rejected.returncode == 2, "%s: unsafe credential path refused before review" % name)
                check(events() == before and files_holding(home, token) == []
                      and not (home / "gcloud/access_tokens.db").exists() and not (home / "gcloud/logs").exists(),
                      "%s: all wrapped commands leave the token off disk" % name)

            # Storage-neutral delivery: neither this command nor its wrapper
            # relies on machine identity or any particular provider.
            for reference in ("op://demo/google/token", "csec://demo/GOOGLE_TOKEN"):
                home = root / ("stored-" + reference.split(":")[0])
                home.mkdir()
                result, outcome = consumer("wrapped", home, *describe, reference=reference)
                check(result.returncode == 0 and outcome.get("bearer") == ["FIXTURE-STORED-ACCESS-TOKEN"]
                      and files_holding(home, "FIXTURE-STORED-ACCESS-TOKEN") == [],
                      "gcloud delivery stays backend-neutral for the %s provider" % reference.split(":")[0])
        finally:
            stop(agent)


if __name__ == "__main__":
    main()
