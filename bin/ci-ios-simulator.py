#!/usr/bin/env python3
"""Run iPhone CI on an app-fresh clone under a shared host lifetime gate.

Cold-base migration and clone tests have separate exact-device leases. Selectors
never boot; lock order is host admission, project base lock, then native work.
Warm bases stay in the default set. Legacy/live devices are never adopted.
CSEC_CI_SIMULATOR_WAIT_S bounds the admission wait of all of a run's leases
together; a run never admitted within it exits NOT_ADMITTED.
"""

import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import uuid

SIMCTL = shlex.split(os.environ.get("CSEC_CI_SIMCTL", "xcrun simctl"))
LOCK = Path(os.environ.get("CSEC_CI_SIMULATOR_LOCK", Path.home()
                           / "Library/Caches/convenient-security/ci-ios-simulator.lock"))
# A Mac whose coding-agent sessions share their simulators runs every lifetime
# through one host gate, named by CSEC_CI_SIMULATOR_RUN or else by the running
# user's `git config csec.simulatorRun` (`direct` for none). The gate speaks
# simulator-run's protocol: `GATE --helper SELECTOR --boot-log LOG -- COMMAND`,
# bounded by SIMULATOR_RUN_BOOT_S and SIMULATOR_RUN_WAIT_S, handing COMMAND its
# device as SIMULATOR_RUN_UDID and SIMULATOR_RUN_SET.
BASE_PREFIX = "csec-ci-uitests-base "
OWNED_NAME = re.compile(r"csec-ci-(?:uitests|base-pending)-([0-9]+)-[0-9a-f]{32}")
SIMCTL_LIMIT = 300
# bootstatus -b prints this terminal status and still exits 0, leaving a booted
# device whose system services never settle. On hosted run 45867216121 the UI
# tests ran on one at load averages near 200 on 3 CPUs and 11 of them failed.
MIGRATION_FAILED = "Data Migration Failed"
TEMPFAIL = 75
NOT_ADMITTED = 76
NEEDS_BASE = 78
BASE_READY = 79
STOPPED = 0
GATE_CHILD = None


class Failure(Exception):
    def __init__(self, message, code=TEMPFAIL):
        super().__init__(message)
        self.code = code


def request():
    return json.loads(Path(os.environ["CSEC_CI_SIMULATOR_REQUEST"]).read_text())


def simctl(*arguments, check=True):
    device_set = request()["device_set"]
    command = [*SIMCTL, *([] if device_set == "default" else ["--set", device_set]), *arguments]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=SIMCTL_LIMIT)
    except subprocess.TimeoutExpired as error:
        raise Failure(f"simctl {' '.join(arguments)} did not finish in {SIMCTL_LIMIT} s") from error
    if check and result.returncode:
        raise Failure(f"simctl {' '.join(arguments)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def devices():
    listing = json.loads(simctl("list", "devices", "--json"))
    return [device for runtime in listing["devices"].values() for device in runtime]


def has_apps(device):
    applications = Path(device["dataPath"]) / "Containers/Bundle/Application"
    return applications.is_dir() and any(applications.iterdir())


def locked():
    LOCK.parent.mkdir(parents=True, exist_ok=True)
    lock = open(LOCK, "a")
    deadline = time.monotonic() + SIMCTL_LIMIT
    while True:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return lock
        except BlockingIOError:
            if time.monotonic() >= deadline:
                lock.close()
                raise Failure(f"another bin/ci run held the Simulator base lock ({LOCK}) for {SIMCTL_LIMIT} s")
            time.sleep(.1)


def stale_devices(listing):
    """Only the new ownership format, with a gone owner and confirmed Shutdown.

    Legacy numeric-PID clones/pending bases can still belong to old live runs;
    do not infer their ownership or shut down any device for housekeeping.
    """
    for device in listing:
        owner = OWNED_NAME.fullmatch(device["name"])
        if owner is None or device["state"] != "Shutdown":
            continue
        pid = int(owner[1])
        if pid <= 1:
            continue
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            simctl("delete", device["udid"])
        except PermissionError:
            pass


def select():
    config = request()
    # Only an admitted lease runs the selector: this stamp ends its admission wait.
    Path(config["admitted"]).write_text(str(time.time()))
    if config["device_set"] != "default":
        Path(config["device_set"]).mkdir(parents=True, exist_ok=True)
    with locked():
        listing = devices()
        stale_devices(listing)
        base = next((device for device in listing
                     if device["name"] == config["base_name"]
                     and device["state"] == "Shutdown" and device.get("isAvailable")
                     and device.get("dataPath") and not has_apps(device)), None)
        if config["stage"] == "base":
            if base is not None:
                Path(config["selection_status"]).write_text(str(BASE_READY))
                raise Failure("another run has already warmed the base", BASE_READY)
            name = f"csec-ci-base-pending-{config['owner']}-{uuid.uuid4().hex}"
            udid = simctl("create", name, config["device_type"], config["runtime"])
        else:
            if base is None:
                Path(config["selection_status"]).write_text(str(NEEDS_BASE))
                raise Failure("a cold base needs its own admitted first boot", NEEDS_BASE)
            name = f"csec-ci-uitests-{config['owner']}-{uuid.uuid4().hex}"
            udid = simctl("clone", base["udid"], name)
        Path(config["selected"]).write_text(json.dumps(dict(udid=udid, name=name)))
        print(udid, flush=True)


def shutdown(udid):
    listing = devices()
    device = next((d for d in listing if d["udid"] == udid), None)
    if device is None:
        raise Failure(f"owned Simulator {udid} disappeared before shutdown")
    if device["state"] != "Shutdown":
        simctl("shutdown", udid)
    deadline = time.monotonic() + SIMCTL_LIMIT
    while True:
        device = next((d for d in devices() if d["udid"] == udid), None)
        if device and device["state"] == "Shutdown":
            return
        if time.monotonic() >= deadline:
            raise Failure(f"owned Simulator {udid} did not reach Shutdown")
        time.sleep(.1)


def finish_base():
    config = request()
    selected = json.loads(Path(config["selected"]).read_text())
    udid = os.environ["SIMULATOR_RUN_UDID"]
    if udid != selected["udid"] or os.environ["SIMULATOR_RUN_SET"] != config["device_set"]:
        raise Failure("base finalization does not match the admitted device")
    # Rename only after migration and confirmed shutdown, while still admitted.
    shutdown(udid)
    with locked():
        simctl("rename", udid, config["base_name"])


def cleanup(config, code):
    """The gate already reaped/shut down. Delete only this run's Shutdown device.

    A failed/uncertain gate must retain its recovery evidence and device; this
    outer process must never perform an independent shutdown after admission.
    """
    path = Path(config["selected"])
    if not path.exists():
        return True
    selected = json.loads(path.read_text())
    with locked():
        device = next((d for d in devices() if d["udid"] == selected["udid"]), None)
        if device is None:
            return True
        if device["state"] != "Shutdown":
            print(f"Preserving {device['udid']}: shared shutdown is incomplete ({device['state']})", file=sys.stderr)
            return False
        if code in (TEMPFAIL, 137):
            # Exit 75 can mean shutdown could not be confirmed; 137 can mean
            # supervisor death. Its recovery record may still name this device.
            # The next admitted selector runs only after the gate recovered it.
            print(f"Preserving {device['udid']} for the next admitted cleanup after exit {code}", file=sys.stderr)
            return True
        if config["stage"] == "base" and device["name"] == config["base_name"]:
            return True
        if device["name"] != selected["name"]:
            print(f"Preserving {device['udid']}: its ownership name changed", file=sys.stderr)
            return False
        simctl("delete", device["udid"])
    return True


def load_note():
    load = os.getloadavg()
    return f"Load averages {load[0]:.0f} {load[1]:.0f} {load[2]:.0f} on {os.cpu_count() or 1} CPUs."


def stop(signum, _frame):
    global STOPPED
    STOPPED = STOPPED or signum
    if GATE_CHILD is not None and GATE_CHILD.poll() is None:
        GATE_CHILD.send_signal(signum)


def configured_gate():
    """The host's gate from CSEC_CI_SIMULATOR_RUN or git config csec.simulatorRun, or None when neither is set."""
    if "CSEC_CI_SIMULATOR_RUN" in os.environ:
        return os.environ["CSEC_CI_SIMULATOR_RUN"]
    try:
        result = subprocess.run(["git", "config", "--type=path", "--get", "csec.simulatorRun"],
                                cwd=Path(__file__).resolve().parent, capture_output=True, text=True, timeout=SIMCTL_LIMIT)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise Failure(f"could not read git config csec.simulatorRun: {error}") from error
    if result.returncode == 1:  # git config --get: the key is not set
        return None
    if result.returncode:
        raise Failure(f"could not read git config csec.simulatorRun: {result.stderr.strip()}")
    return result.stdout.strip()


def gate_command():
    direct = [sys.executable, str(Path(__file__).resolve()), "_direct"]
    gate = configured_gate()
    # A Mac with nothing else booting simulators asks for no gate by name, so a
    # gate that went missing or was never configured is never bypassed silently.
    if gate == "direct":
        return direct
    if gate and Path(gate).is_file() and os.access(gate, os.X_OK):
        return [gate]
    # GitHub-hosted VMs are disposable and run nothing else.
    if (gate is None
            and os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"):
        return direct
    how = ("set `git config --global csec.simulatorRun` (or CSEC_CI_SIMULATOR_RUN) to the host's simulator gate, "
           "or to `direct` when nothing else on this Mac boots simulators")
    if gate is None:
        raise Failure(f"no simulator gate is configured: {how}")
    raise Failure(f"the simulator gate is missing or not executable: {gate}; {how}")


def admitted(config, command, gate, config_path, caller):
    global GATE_CHILD
    config_path.write_text(json.dumps(config))
    limit = config["base_boot_limit"] if config["stage"] == "base" else config["boot_limit"]
    env = dict(os.environ, CSEC_CI_SIMULATOR_REQUEST=str(config_path), SIMULATOR_RUN_BOOT_S=str(limit))
    log = str(config_path.parent / f"{config['stage']}-boot.log")
    try:
        GATE_CHILD = subprocess.Popen([*gate, "--helper", str(Path(__file__).resolve()),
                                       "--boot-log", log, "--", *command], env=env)
        if STOPPED:
            GATE_CHILD.send_signal(STOPPED)
        while True:
            if os.getppid() != caller and not STOPPED:
                stop(signal.SIGTERM, None)
            try:
                code = GATE_CHILD.wait(timeout=.1)
                return code if code >= 0 else 128 - code
            except subprocess.TimeoutExpired:
                pass
    finally:
        GATE_CHILD = None


def admission_budget():
    """Seconds all leases may wait for admission together, or None for the gate's own bound."""
    value = os.environ.get("CSEC_CI_SIMULATOR_WAIT_S")
    if value is None:
        return None
    try:
        budget = float(value)
    except ValueError:
        budget = -1
    if not 0 <= budget < float("inf"):
        raise Failure("CSEC_CI_SIMULATOR_WAIT_S must be a finite nonnegative number of seconds", 2)
    return budget


def run(arguments):
    caller = os.getppid()
    gate = gate_command()  # Fail before creating/selecting a device.
    budget = admission_budget()
    waited = 0.0
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, stop)
    with tempfile.TemporaryDirectory(prefix="csec-ios-lease-") as directory:
        root = Path(directory)
        config_path = root / "request.json"
        config = dict(runtime=arguments.runtime, device_type=arguments.device_type,
                      base_name=f"{BASE_PREFIX}{arguments.runtime_build} {arguments.device_type.rpartition('.')[2]}",
                      device_set=arguments.device_set, owner=os.getpid(),
                      base_boot_limit=arguments.base_boot_limit, boot_limit=arguments.boot_limit,
                      selected=str(root / "selected.json"), selection_status=str(root / "selection-status"),
                      admitted=str(root / "admitted"), stage="clone")
        # A missing base is detected by the nonbooting clone selector under
        # admission. Release that lease before requesting the cold-base one.
        os.environ["CSEC_CI_SIMULATOR_REQUEST"] = str(config_path)
        for stage in ("clone", "base", "clone"):
            if STOPPED:
                return 128 + STOPPED
            config["stage"] = stage
            Path(config["selected"]).unlink(missing_ok=True)
            Path(config["selection_status"]).unlink(missing_ok=True)
            admitted_path = Path(config["admitted"])
            admitted_path.unlink(missing_ok=True)
            command = ([sys.executable, str(Path(__file__).resolve()), "_finish-base"]
                       if stage == "base" else arguments.child)
            if budget is not None:
                os.environ["SIMULATOR_RUN_WAIT_S"] = f"{max(budget - waited, 0):.3f}"
            asked = time.time()
            code = TEMPFAIL
            try:
                code = admitted(config, command, gate, config_path, caller)
            finally:
                if not cleanup(config, code):
                    code = TEMPFAIL
            if admitted_path.exists():
                waited += max(float(admitted_path.read_text()) - asked, 0)
                if code == NOT_ADMITTED:
                    # bin/ci reads NOT_ADMITTED as "no simulator started", so an
                    # admitted command's own 76 must not be taken for it.
                    print(f"the admitted command exited {NOT_ADMITTED}, reported as 1", file=sys.stderr)
                    code = 1
            else:
                waited += time.time() - asked
                if code == TEMPFAIL and budget is not None and waited >= budget:
                    print(f"simulator admission did not start within CSEC_CI_SIMULATOR_WAIT_S={budget:g}s; "
                          f"no simulator started. {load_note()}", file=sys.stderr)
                    return NOT_ADMITTED
            if code not in (0, NEEDS_BASE, BASE_READY):
                print(load_note(), file=sys.stderr)
            status_path = Path(config["selection_status"])
            selection_status = int(status_path.read_text()) if status_path.exists() else None
            if stage == "clone" and (code != NEEDS_BASE or selection_status != NEEDS_BASE):
                return code
            if stage == "base" and code != 0 and (code != BASE_READY or selection_status != BASE_READY):
                return code
        raise Failure("no clean shutdown base is available after its admitted bootstrap")


def direct_process(command, limit, caller, **kwargs):
    """Bound/reap one command where no shared gate runs (a GitHub VM, or by request)."""
    child = subprocess.Popen(command, start_new_session=True, **kwargs)
    deadline = time.monotonic() + limit
    try:
        while True:
            if STOPPED or os.getppid() != caller or time.monotonic() >= deadline:
                raise Failure("Simulator command cancelled or timed out", 128 + STOPPED if STOPPED else TEMPFAIL)
            try:
                code = child.wait(timeout=.05)
                if code:
                    raise Failure(f"{command[0]} exited {code}", code if code > 0 else 128 - code)
                return
            except subprocess.TimeoutExpired:
                pass
    finally:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()


def direct(argv):
    caller = os.getppid()
    parser = argparse.ArgumentParser()
    parser.add_argument("--helper", required=True)
    parser.add_argument("--boot-log", required=True)
    parser.add_argument("child", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.child[1:] if args.child[:1] == ["--"] else args.child
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, stop)
    # Selector output is captured, so no device ID contaminates command stdout.
    config = request()
    with tempfile.TemporaryFile("w+") as selected:
        direct_process([args.helper], float(os.environ["SIMULATOR_RUN_BOOT_S"]), caller, stdout=selected)
        selected.seek(0)
        udid = selected.read().strip()
    device = next((d for d in devices() if d["udid"] == udid), None)
    if device is None or device["state"] != "Shutdown":
        raise Failure("the selector did not return a Shutdown device")
    set_args = [] if config["device_set"] == "default" else ["--set", config["device_set"]]
    code = TEMPFAIL
    boot_log = Path(args.boot_log)
    boot_log.write_text("")
    try:
        limit = float(os.environ["SIMULATOR_RUN_BOOT_S"])
        for attempt in (1, 2):
            start = boot_log.stat().st_size
            with open(boot_log, "a") as log:
                direct_process([*SIMCTL, *set_args, "bootstatus", udid, "-b"], limit, caller,
                               stdout=log, stderr=subprocess.STDOUT)
            if MIGRATION_FAILED.encode() not in boot_log.read_bytes()[start:]:
                break
            if attempt == 2:
                raise Failure(f"the Simulator's data migration failed on both boots of {udid}")
            # An erased device boots as a new one, through a full first-boot
            # migration, so it gets the cold base's allowance.
            shutdown(udid)
            simctl("erase", udid)
            limit = float(config["base_boot_limit"])
        direct_process(command, float(os.environ.get("SIMULATOR_RUN_RUN_S", "7200")), caller,
                       env=dict(os.environ, SIMULATOR_RUN_SET=config["device_set"], SIMULATOR_RUN_UDID=udid))
        code = 0
    except Failure as error:
        print(error, file=sys.stderr)
        print(Path(args.boot_log).read_text(), file=sys.stderr)
        code = error.code
    finally:
        shutdown(udid)
    return code


def choose(listing):
    """bin/ci's runtime and iPhone, tab-separated, from `simctl list runtimes --json`.

    The newest iOS version, and across every runtime of that version the
    smallest Face ID screen: the xcode-27 hosted image lists a second iOS 27.2
    runtime offering only iPhone Duo, whose first boot ends "Data Migration
    Failed" (hosted runs 45867216121 and 45904084139), and the newest-version
    pick alone took whichever of the two came first.
    """
    runtimes = [r for r in listing["runtimes"] if r.get("isAvailable") and r.get("platform") == "iOS"]
    if not runtimes:
        raise Failure("no iOS Simulator runtime is installed: xcodebuild -downloadPlatform iOS", 1)
    version = max([int(part) for part in r["version"].split(".")] for r in runtimes)
    newest = [r for r in runtimes if [int(part) for part in r["version"].split(".")] == version]
    # The smallest screens with Face ID first; any Face ID iPhone after them.
    preferred = ["iPhone 13 mini", "iPhone 12 mini", "iPhone 16e", "iPhone 17e"]
    candidates = sorted(
        ((preferred.index(t["name"]) if t["name"] in preferred else len(preferred), t["name"], r["identifier"], r, t)
         for r in newest for t in r.get("supportedDeviceTypes", [])
         if t["name"].startswith("iPhone") and "SE" not in t["name"]),
        key=lambda candidate: candidate[:3])
    if not candidates:
        raise Failure(f"{newest[0]['name']} offers no iPhone with Face ID", 1)
    *_, runtime, device = candidates[0]
    return "\t".join([runtime["identifier"], runtime["buildversion"], device["identifier"],
                      f"{device['name']}, {runtime['name']}"])


def main():
    argv = sys.argv[1:]
    if argv == ["choose"]:
        print(choose(json.load(sys.stdin)))
        return 0
    if not argv:
        select()
        return 0
    if argv == ["set"]:
        print(request()["device_set"])
        return 0
    if argv == ["_finish-base"]:
        finish_base()
        return 0
    if argv[:1] == ["_direct"]:
        return direct(argv[1:])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", choices=["run"])
    parser.add_argument("--runtime", required=True)
    parser.add_argument("--runtime-build", required=True)
    parser.add_argument("--device-type", required=True)
    parser.add_argument("--set", dest="device_set", default="default")
    parser.add_argument("--base-boot-limit", type=int, default=1200)
    parser.add_argument("--boot-limit", type=int, default=300)
    arguments, child = parser.parse_known_args()
    if child[:1] != ["--"] or len(child) < 2:
        parser.error("run requires -- COMMAND ARGS...")
    if arguments.device_set != "default":
        if not Path(arguments.device_set).is_absolute():
            parser.error("--set must be default or an absolute device-set path")
        arguments.device_set = str(Path(arguments.device_set).resolve())
    arguments.child = child[1:]
    return run(arguments)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (Failure, OSError, ValueError, KeyError) as failure:
        print(failure, file=sys.stderr)
        sys.exit(failure.code if isinstance(failure, Failure) else TEMPFAIL)
