#!/usr/bin/env python3
"""Stateful simulator/admission stand-ins; no test touches CoreSimulator."""

import fcntl
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import signal
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid

HELPER = Path(__file__).resolve().parent / "ci-ios-simulator.py"


def host_gate():
    """The simulator gate this host configures for bin/ci, when one is installed; its real supervisor is tested too."""
    try:
        configured = subprocess.run(["git", "config", "--type=path", "--get", "csec.simulatorRun"], cwd=HELPER.parent,
                                    capture_output=True, text=True, timeout=30).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        configured = ""
    gate = os.environ.get("CSEC_CI_SIMULATOR_RUN", configured)
    return Path(gate) if gate not in ("", "direct") and Path(gate).is_file() else None


HOST_GATE = host_gate()
RUNTIME = "com.apple.CoreSimulator.SimRuntime.iOS-26-5"
DEVICE_TYPE = "com.apple.CoreSimulator.SimDeviceType.iPhone-13-mini"
BASE = "csec-ci-uitests-base 23F77 iPhone-13-mini"
# These budgets include scheduling several Python/ps children on busy CI hosts.
# Only tests deliberately hanging a boot use the shorter allowance below.
WORKFLOW_TIMEOUT = 60
HUNG_BOOT_TIMEOUT = 10

FAKE_SIMCTL = r'''#!/usr/bin/env python3
import fcntl, json, os, sys, time, uuid
from pathlib import Path
args = sys.argv[1:]
if args[:1] == ['simctl']: args = args[1:]
if args[:1] == ['--set']: args = args[2:]
path = Path(os.environ['FAKE_SIMCTL_STATE'])
lock = open(str(path) + '.lock', 'a')
def load():
    fcntl.flock(lock, fcntl.LOCK_EX)
    return json.loads(path.read_text())
def save(state):
    path.write_text(json.dumps(state))
    fcntl.flock(lock, fcntl.LOCK_UN)
def find(state, udid):
    return next(d for d in state['devices'] if d['udid'] == udid)
state = load()
state['calls'].append(args)
cmd = args[0]
if cmd == 'list':
    save(state)
    print(json.dumps({'devices': {'runtime': state['devices']}}))
elif cmd in ('create', 'clone'):
    # Selection/creation must happen under host admission, before any boot.
    probe = open(os.environ['SIMULATOR_RUN_LOCK'], 'a')
    try:
        fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        raise AssertionError('device selection ran without host admission')
    except BlockingIOError:
        pass
    source = find(state, args[1]) if cmd == 'clone' else None
    if source: assert source['state'] == 'Shutdown'
    udid = str(uuid.uuid4()).upper()
    data = path.parent / udid / 'data'
    data.mkdir(parents=True)
    device = dict(source or {}, udid=udid, name=args[2] if source else args[1],
                  state='Shutdown', isAvailable=True, dataPath=str(data))
    if not source: device['booted_once'] = False
    state['devices'].append(device)
    save(state)
    print(udid)
elif cmd == 'rename':
    find(state, args[1])['name'] = args[2]
    save(state)
elif cmd == 'delete':
    device = find(state, args[1])
    assert device['state'] == 'Shutdown', 'deleting a live device'
    state['devices'].remove(device)
    save(state)
elif cmd == 'shutdown':
    device = find(state, args[1])
    if state.get('shutdown_fails') and device['name'].startswith('csec-ci-uitests-') and not device['name'].startswith('csec-ci-uitests-base '):
        save(state); sys.exit(8)
    device['state'] = 'Shutdown'
    save(state)
elif cmd == 'bootstatus':
    device = find(state, args[1])
    assert not any(d['state'] in ('Booted', 'Booting') and not d.get('foreign')
                   for d in state['devices']), 'overlapping booted owned devices'
    hangs = any(device['name'].startswith(prefix) for prefix in state.get('boot_hangs', []))
    device['state'] = 'Booting'
    save(state)
    print('Waiting on Data Migration\nReason:Running plugin com.apple.locationd.migrator\n', flush=True)
    while hangs: time.sleep(.05)
    time.sleep(float(os.environ.get('FAKE_BOOT_SECONDS', '0')))
    state = load()
    device = find(state, args[1])
    device['state'] = 'Booted'
    device['migrated_on_this_boot'] = not device['booted_once']
    device['booted_once'] = True
    state.setdefault('boots', []).append(dict(device))
    save(state)
    print('Finished', flush=True)
else:
    save(state)
    raise AssertionError(args)
'''

# This stand-in supplies only capacity; the direct adapter exercises the
# selector/boot/command/shutdown contract. Real shared-supervisor coverage is
# also run below when this host configures its own gate, with the same fake devices.
FAKE_GATE = r'''#!/usr/bin/env python3
import fcntl, os, signal, subprocess, sys, time
lock = open(os.environ['SIMULATOR_RUN_LOCK'], 'a')
stopped = [0]
signal.signal(signal.SIGTERM, lambda s, _: stopped.__setitem__(0, s))
signal.signal(signal.SIGINT, lambda s, _: stopped.__setitem__(0, s))
# Like the shipped gate, SIMULATOR_RUN_WAIT_S bounds admission and a lapse exits 75.
wait = float(os.environ['SIMULATOR_RUN_WAIT_S'])
if os.environ.get('FAKE_GATE_WAITS'):
    with open(os.environ['FAKE_GATE_WAITS'], 'a') as waits: waits.write(f'{wait}\n')
asked = time.monotonic()
while True:
    if stopped[0]: sys.exit(128 + stopped[0])
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB); break
    except BlockingIOError:
        if time.monotonic() - asked >= wait:
            print('admission timed out; no simulator started', file=sys.stderr); sys.exit(75)
        time.sleep(.02)
child = subprocess.Popen([sys.executable, os.environ['CSEC_TEST_HELPER'], '_direct', *sys.argv[1:]])
sent = False
while child.poll() is None:
    if stopped[0] and not sent: child.send_signal(stopped[0]); sent = True
    time.sleep(.02)
sys.exit(child.returncode)
'''

COMMAND = r'''import json, os, pathlib, sys, time
path = pathlib.Path(os.environ['FAKE_SIMCTL_STATE'])
import fcntl
with open(str(path) + '.lock', 'a') as lock:
    fcntl.flock(lock, fcntl.LOCK_EX)
    state = json.loads(path.read_text())
    udid = os.environ['SIMULATOR_RUN_UDID']
    device = next(d for d in state['devices'] if d['udid'] == udid)
    assert device['state'] == 'Booted'
    assert not device['migrated_on_this_boot'], 'clone repeated first-boot migration'
    state.setdefault('commands', []).append(dict(udid=udid, args=sys.argv[1:],
        device_set=os.environ['SIMULATOR_RUN_SET']))
    path.write_text(json.dumps(state))
release = os.environ.get('COMMAND_RELEASE')
while release and not pathlib.Path(release).exists(): time.sleep(.02)
sys.exit(int(os.environ.get('COMMAND_EXIT', '0')))
'''


class CISimulatorTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="csec simulator tests ")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.state_path = self.root / "state.json"
        self.state_path.write_text(json.dumps({"devices": [], "calls": []}))
        for name, body in (("xcrun", FAKE_SIMCTL), ("gate", FAKE_GATE), ("command.py", COMMAND)):
            path = self.root / name
            path.write_text(body)
            path.chmod(0o755)
        self.environment = {
            **{k: v for k, v in os.environ.items() if not k.startswith(("SIMULATOR_RUN_", "CSEC_CI_SIMULATOR_"))},
            "PATH": f"{self.root}:{os.environ['PATH']}",
            "FAKE_SIMCTL_STATE": str(self.state_path),
            "CSEC_CI_SIMCTL": shlex.join([str(self.root / "xcrun")]),
            "CSEC_CI_SIMULATOR_LOCK": str(self.root / "base.lock"),
            "CSEC_CI_SIMULATOR_RUN": str(self.root / "gate"),
            "CSEC_TEST_HELPER": str(HELPER),
            # Only the tests that ask for one see a configured gate.
            "GIT_CONFIG_GLOBAL": str(self.root / "gitconfig"),
            "GIT_CONFIG_NOSYSTEM": "1",
            "SIMULATOR_RUN_LOCK": str(self.root / "host.lock"),
            "SIMULATOR_RUN_PRIORITY": "3",
            "SIMULATOR_RUN_WAIT_S": str(WORKFLOW_TIMEOUT),
            "SIMULATOR_RUN_STOP_S": ".2",
            "SIMULATOR_RUN_SHUTDOWN_S": str(WORKFLOW_TIMEOUT),
            # The shipped gate's host-load admission protects real simulator
            # boots; these boot fakes, so the busy host must not decide them.
            "SIMULATOR_RUN_LOAD_PER_CORE": "0",
            "SIMULATOR_RUN_STATE_DIR": str(self.root / "ledger"),
        }
        self.processes = []
        self.addCleanup(self.stop_processes)

    def stop_processes(self):
        (self.root / "release").touch()
        for process in self.processes:
            if process.poll() is None:
                process.terminate()
            process.communicate(timeout=WORKFLOW_TIMEOUT * 2)

    def state(self):
        with open(str(self.state_path) + ".lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_SH)
            return json.loads(self.state_path.read_text())

    def update(self, change):
        with open(str(self.state_path) + ".lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            state = json.loads(self.state_path.read_text())
            change(state)
            self.state_path.write_text(json.dumps(state))

    def start(self, *, cwd=None, device_set="default", boot_limit=WORKFLOW_TIMEOUT, **environment):
        command = [sys.executable, str(HELPER), "run", "--runtime", RUNTIME,
                   "--runtime-build", "23F77", "--device-type", DEVICE_TYPE,
                   "--set", str(device_set),
                   "--base-boot-limit", str(boot_limit), "--boot-limit", str(boot_limit), "--",
                   sys.executable, str(self.root / "command.py"), "argument with spaces"]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, cwd=cwd or self.root,
                                   env=dict(self.environment, **environment))
        self.processes.append(process)
        return process

    def finish(self, process):
        out, err = process.communicate(timeout=WORKFLOW_TIMEOUT * 2)
        return process.returncode, out, err

    def run_check(self, **environment):
        return self.finish(self.start(**environment))

    def wait_for(self, predicate, *, process=None):
        deadline = time.monotonic() + WORKFLOW_TIMEOUT
        while not predicate():
            if process is not None and process.poll() is not None:
                if predicate():
                    return
                self.fail(f"workflow exited before expected state: {self.finish(process)!r}")
            if time.monotonic() >= deadline:
                self.fail(f"workflow did not reach expected state: {self.state()!r}")
            time.sleep(.02)

    def add_device(self, name, *, state="Shutdown", foreign=False, app=False):
        udid = str(uuid.uuid4()).upper()
        data = self.root / udid / "data"
        data.mkdir(parents=True)
        if app:
            (data / "Containers/Bundle/Application/ABC").mkdir(parents=True)
        self.update(lambda s: s["devices"].append(dict(udid=udid, name=name, state=state,
            foreign=foreign, isAvailable=True, booted_once=True, dataPath=str(data))))
        return udid

    def test_cold_base_and_clone_have_separate_leases_and_fresh_app_state(self):
        code, out, err = self.run_check()
        self.assertEqual(code, 0, (out, err))
        state = self.state()
        self.assertEqual([d["name"] for d in state["devices"]], [BASE])
        self.assertEqual(state["devices"][0]["state"], "Shutdown")
        self.assertEqual(len(state["boots"]), 2)
        self.assertTrue(state["boots"][0]["migrated_on_this_boot"])
        self.assertFalse(state["boots"][1]["migrated_on_this_boot"])
        self.assertNotEqual(state["boots"][0]["udid"], state["boots"][1]["udid"])
        self.assertEqual(state["commands"][0]["args"], ["argument with spaces"])
        self.assertEqual(state["commands"][0]["device_set"], "default")

    def test_warm_base_is_kept_without_another_base_boot(self):
        self.assertEqual(self.run_check()[0], 0)
        base = self.state()["devices"][0]["udid"]
        result = self.run_check()
        self.assertEqual(result[0], 0, result)
        self.assertEqual([d["udid"] for d in self.state()["devices"]], [base])
        self.assertEqual(len(self.state()["boots"]), 3)

    def test_preserves_legacy_pending_live_and_other_runtime_devices(self):
        names = [BASE, "csec-ci-uitests-base 23A100 iPhone-13-mini",
                 "csec-ci-uitests-base-pending", "csec-ci-uitests-99999999", "foreign"]
        originals = [self.add_device(name, state="Booted" if n in (0, 2, 3) else "Shutdown", foreign=True)
                     for n, name in enumerate(names)]
        result = self.run_check()
        self.assertEqual(result[0], 0, result)
        devices = {d["udid"]: d for d in self.state()["devices"]}
        self.assertTrue(all(udid in devices for udid in originals))
        self.assertTrue(all(devices[originals[n]]["state"] == "Booted" for n in (0, 2, 3)))
        touched = [c[1] for c in self.state()["calls"] if c[0] in ("shutdown", "delete", "clone")]
        self.assertTrue(all(udid not in touched for udid in originals))

    def test_contaminated_base_is_preserved_but_not_cloned(self):
        old = self.add_device(BASE, app=True)
        result = self.run_check()
        self.assertEqual(result[0], 0, result)
        self.assertIn(old, [d["udid"] for d in self.state()["devices"]])
        self.assertNotIn(["clone", old], [c[:2] for c in self.state()["calls"]])
        self.assertEqual(len(self.state()["devices"]), 2)

    def test_command_failure_keeps_status_and_cleans_clone(self):
        result = self.run_check(COMMAND_EXIT="17")
        self.assertEqual(result[0], 17, result)
        self.assertEqual([d["name"] for d in self.state()["devices"]], [BASE])

    def test_command_exit_matching_selector_status_is_not_retried(self):
        result = self.run_check(COMMAND_EXIT="78")
        self.assertEqual(result[0], 78, result)
        self.assertEqual(len(self.state()["commands"]), 1)

    def test_base_boot_timeout_has_status_and_preserves_shutdown_recovery_device(self):
        self.update(lambda s: s.update(boot_hangs=["csec-ci-base-pending-"]))
        result = self.run_check(boot_limit=HUNG_BOOT_TIMEOUT)
        self.assertEqual(result[0], 75, result)
        self.assertIn("com.apple.locationd.migrator", result[2])
        self.assertIn("Load averages", result[2])
        self.assertEqual(len(self.state()["devices"]), 1)
        self.assertEqual(self.state()["devices"][0]["state"], "Shutdown")
        self.assertNotIn("commands", self.state())

    def test_clone_boot_timeout_preserves_shutdown_recovery_device_and_warm_base(self):
        self.add_device(BASE)
        self.update(lambda s: s.update(boot_hangs=["csec-ci-uitests-"]))
        result = self.run_check(boot_limit=HUNG_BOOT_TIMEOUT)
        self.assertEqual(result[0], 75, result)
        self.assertEqual(len(self.state()["devices"]), 2)
        self.assertTrue(all(d["state"] == "Shutdown" for d in self.state()["devices"]))

    def test_incomplete_shutdown_fails_and_never_deletes_live_clone(self):
        self.add_device(BASE)
        release = self.root / "release"
        process = self.start(COMMAND_RELEASE=str(release))
        self.wait_for(lambda: len(self.state().get("commands", [])) == 1, process=process)
        # Exercise shutdown failure only after selection and boot have succeeded.
        self.update(lambda s: s.update(shutdown_fails=True))
        release.touch()
        result = self.finish(process)
        self.assertEqual(result[0], 75, result)
        state = self.state()
        self.assertEqual(len(state["devices"]), 2)
        clone = state["devices"][1]
        self.assertEqual(clone["udid"], state["commands"][0]["udid"])
        self.assertEqual(clone["state"], "Booted")
        self.assertIn(["shutdown", clone["udid"]], state["calls"])
        self.assertNotIn(["delete", clone["udid"]], state["calls"])
        self.assertIn("preserv", result[2].lower())

    def test_concurrent_checkouts_share_one_base_and_whole_test_lifetime(self):
        release = self.root / "release"
        one = self.start(COMMAND_RELEASE=str(release))
        self.wait_for(lambda: len(self.state().get("commands", [])) == 1, process=one)
        other = self.root / "other checkout"
        other.mkdir()
        two = self.start(cwd=other)
        time.sleep(.3)
        self.assertEqual(len(self.state()["boots"]), 2)
        self.assertIsNone(two.poll())
        release.touch()
        results = [self.finish(p) for p in (one, two)]
        self.assertEqual([r[0] for r in results], [0, 0], results)
        self.assertEqual(len(self.state()["boots"]), 3)
        self.assertEqual([d["name"] for d in self.state()["devices"]], [BASE])

    def test_waiting_for_host_admission_does_not_take_project_lock_or_select(self):
        private_set = self.root / "private device set"
        with open(self.environment["SIMULATOR_RUN_LOCK"], "a") as host:
            fcntl.flock(host, fcntl.LOCK_EX)
            process = self.start(device_set=private_set)
            time.sleep(.3)
            self.assertIsNone(process.poll())
            self.assertEqual(self.state()["calls"], [])
            self.assertFalse(private_set.exists(), "even private-set creation waits for admission")
            with open(self.environment["CSEC_CI_SIMULATOR_LOCK"], "a") as project:
                fcntl.flock(project, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = self.finish(process)
        self.assertEqual(result[0], 0, result)
        self.assertTrue(private_set.is_dir())
        self.assertEqual(self.state()["commands"][0]["device_set"], str(private_set.resolve()))

    def test_unmet_admission_budget_exits_not_admitted_without_selecting(self):
        with open(self.environment["SIMULATOR_RUN_LOCK"], "a") as host:
            fcntl.flock(host, fcntl.LOCK_EX)
            started = time.monotonic()
            result = self.run_check(CSEC_CI_SIMULATOR_WAIT_S=".5")
        self.assertEqual(result[0], 76, result)
        # The run's budget, not the gate's own (much longer) bound, ended the wait.
        self.assertLess(time.monotonic() - started, WORKFLOW_TIMEOUT / 2)
        self.assertIn("did not start within CSEC_CI_SIMULATOR_WAIT_S=0.5s", result[2])
        self.assertIn("Load averages", result[2])
        self.assertEqual(self.state()["calls"], [])

    def test_admission_budget_is_shared_by_cold_base_and_clone_leases(self):
        waits = self.root / "waits"
        release = threading.Timer(.5, lambda: fcntl.flock(host, fcntl.LOCK_UN))
        with open(self.environment["SIMULATOR_RUN_LOCK"], "a") as host:
            fcntl.flock(host, fcntl.LOCK_EX)
            release.start()
            result = self.run_check(CSEC_CI_SIMULATOR_WAIT_S="30", FAKE_GATE_WAITS=str(waits))
        self.assertEqual(result[0], 0, result)
        first, base, clone = (float(line) for line in waits.read_text().split())
        self.assertEqual(first, 30)
        # The first lease waited about .5 s; admitted time (boots, commands) is not admission.
        self.assertLessEqual(base, 29.6)
        self.assertGreater(base, 25)
        self.assertLessEqual(clone, base)
        self.assertGreater(clone, 25)

    def test_an_admitted_commands_own_76_is_not_reported_as_not_admitted(self):
        result = self.run_check(CSEC_CI_SIMULATOR_WAIT_S="30", COMMAND_EXIT="76")
        self.assertEqual(result[0], 1, result)
        self.assertIn("exited 76, reported as 1", result[2])
        self.assertEqual(len(self.state()["commands"]), 1)

    def test_invalid_admission_budget_fails_before_any_selection(self):
        for value in ("-1", "nan", "inf", "soon"):
            with self.subTest(value=value):
                result = self.run_check(CSEC_CI_SIMULATOR_WAIT_S=value)
                self.assertEqual(result[0], 2, result)
                self.assertIn("CSEC_CI_SIMULATOR_WAIT_S", result[2])
                self.assertEqual(self.state()["calls"], [])

    def test_term_during_command_reaps_it_and_deletes_shutdown_clone(self):
        process = self.start(COMMAND_RELEASE=str(self.root / "release"))
        self.wait_for(lambda: len(self.state().get("commands", [])) == 1, process=process)
        process.terminate()
        result = self.finish(process)
        self.assertEqual(result[0], 143, result)
        self.assertEqual([d["name"] for d in self.state()["devices"]], [BASE])

    def test_term_during_cold_boot_cleans_only_own_pending_base(self):
        self.update(lambda s: s.update(boot_hangs=["csec-ci-base-pending-"]))
        process = self.start()
        self.wait_for(lambda: any(d["state"] == "Booting" for d in self.state()["devices"]),
                      process=process)
        process.terminate()
        result = self.finish(process)
        self.assertEqual(result[0], 143, result)
        self.assertEqual(self.state()["devices"], [])

    def test_stale_new_devices_are_deleted_only_after_shutdown_and_owner_exit(self):
        stale = self.add_device("csec-ci-uitests-99999999-" + uuid.uuid4().hex)
        live = self.add_device(f"csec-ci-uitests-{os.getpid()}-" + uuid.uuid4().hex)
        running = self.add_device("csec-ci-uitests-99999999-" + uuid.uuid4().hex,
                                  state="Booted", foreign=True)
        result = self.run_check()
        self.assertEqual(result[0], 0, result)
        ids = [d["udid"] for d in self.state()["devices"]]
        self.assertNotIn(stale, ids)
        self.assertIn(live, ids)
        self.assertIn(running, ids)

    def test_missing_local_gate_fails_before_any_selection(self):
        result = self.run_check(CSEC_CI_SIMULATOR_RUN=str(self.root / "missing"),
                                GITHUB_ACTIONS="", RUNNER_ENVIRONMENT="")
        self.assertEqual(result[0], 75, result)
        self.assertIn(f"the simulator gate is missing or not executable: {self.root / 'missing'}", result[2])
        self.assertEqual(self.state()["calls"], [])

    def test_unconfigured_mac_fails_before_any_selection(self):
        del self.environment["CSEC_CI_SIMULATOR_RUN"]
        result = self.run_check(GITHUB_ACTIONS="", RUNNER_ENVIRONMENT="")
        self.assertEqual(result[0], 75, result)
        self.assertIn("no simulator gate is configured", result[2])
        self.assertIn("csec.simulatorRun", result[2])
        self.assertEqual(self.state()["calls"], [])

    def test_git_config_names_the_gate_from_the_users_home(self):
        del self.environment["CSEC_CI_SIMULATOR_RUN"]
        (self.root / "gitconfig").write_text("[csec]\n\tsimulatorRun = ~/gate\n")
        waits = self.root / "gate waits"
        result = self.run_check(HOME=str(self.root), FAKE_GATE_WAITS=str(waits),
                                GITHUB_ACTIONS="true", RUNNER_ENVIRONMENT="github-hosted")
        self.assertEqual(result[0], 0, result)
        # The stand-in gate admitted all three of the cold run's leases, though a hosted VM would otherwise go direct.
        self.assertEqual(len(waits.read_text().splitlines()), 3)

    def test_direct_is_asked_for_by_name_on_a_mac_without_a_gate(self):
        spec = importlib.util.spec_from_file_location("ci_simulator", HELPER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        environment = dict(self.environment, CSEC_CI_SIMULATOR_RUN="direct", GITHUB_ACTIONS="", RUNNER_ENVIRONMENT="")
        from unittest.mock import patch
        with patch.dict(os.environ, environment, clear=True):
            self.assertEqual(module.gate_command(), [sys.executable, str(HELPER), "_direct"])
        result = self.run_check(CSEC_CI_SIMULATOR_RUN=str(self.root / "missing"),
                                GITHUB_ACTIONS="", RUNNER_ENVIRONMENT="")
        self.assertIn("or to `direct` when nothing else on this Mac boots simulators", result[2])

    def test_disposable_github_vm_can_run_without_a_shared_gate(self):
        spec = importlib.util.spec_from_file_location("ci_simulator", HELPER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        environment = dict(self.environment, GITHUB_ACTIONS="true", RUNNER_ENVIRONMENT="github-hosted")
        environment.pop("CSEC_CI_SIMULATOR_RUN")
        from unittest.mock import patch
        with patch.dict(os.environ, environment, clear=True):
            self.assertEqual(module.gate_command(), [sys.executable, str(HELPER), "_direct"])
        # All the admission stand-in tests above run this same direct adapter.

    def run_ui_driver(self, selected="26.6", installed=("26.6", "27.1"), macos="27.2", **extra):
        """bin/ci-ios-ui-tests against stub Xcodes; returns its result and xcodebuild calls."""
        applications = self.root / "Applications"
        for version in installed:
            app = applications / f"Xcode-{version}.0.app"
            (app / "Contents/Developer").mkdir(parents=True)
            (app / "Contents/version.plist").write_bytes(plistlib.dumps({"CFBundleShortVersionString": version}))
        for name, body in (
                # Like the real one, xcode-select -p names a caller's DEVELOPER_DIR.
                ("xcode-select", '#!/bin/sh\necho "${DEVELOPER_DIR:-$FAKE_SELECTED}"\n'),
                ("sw_vers", '#!/bin/sh\necho "$FAKE_MACOS"\n'),
                # Named interpreter, not env python3: where /usr/bin/python3 leads
                # PATH it is an xcrun shim, which refuses the stub Xcodes' DEVELOPER_DIR.
                ("xcodebuild", f"""#!{sys.executable}
import json, os, pathlib, sys
with open(os.environ['XCODE_CALLS'], 'a') as out:
    out.write(json.dumps(dict(args=sys.argv[1:], developer=os.environ.get('DEVELOPER_DIR'))) + '\\n')
if 'test-without-building' in sys.argv: print('    Executed 42 tests, with 0 failures')
""")):
            (self.root / name).write_text(body)
            (self.root / name).chmod(0o755)
        calls = self.root / "xcode.jsonl"
        calls.touch()
        environment = {k: v for k, v in self.environment.items() if k != "DEVELOPER_DIR"}
        result = subprocess.run([str(HELPER.parent / "ci-ios-ui-tests"), str(self.root), "test device"],
            env=dict(environment, SIMULATOR_RUN_SET=str(self.root / "private set"),
                     SIMULATOR_RUN_UDID="owned-udid", XCODE_CALLS=str(calls),
                     CSEC_CI_XCODE_SEARCH=str(applications), FAKE_MACOS=macos,
                     FAKE_SELECTED=str(applications / f"Xcode-{selected}.0.app/Contents/Developer"), **extra),
            capture_output=True, text=True, timeout=10)
        return result, [json.loads(line) for line in calls.read_text().splitlines()]

    def developer(self, version):
        return str(self.root / f"Applications/Xcode-{version}.0.app/Contents/Developer")

    def test_ui_driver_keeps_build_signing_and_test_bounds(self):
        result, calls = self.run_ui_driver()
        self.assertEqual(result.returncode, 0, result.stderr)
        build, tests = calls
        self.assertIn('build-for-testing', build['args'])
        self.assertIn('CODE_SIGN_IDENTITY=-', build['args'])
        self.assertIn('SWIFT_TREAT_WARNINGS_AS_ERRORS=YES', build['args'])
        for call in (build, tests):
            self.assertIn('id=owned-udid', call['args'])
            self.assertIn('-DVTSimulatorSetLocation=' + str(self.root / 'private set'), call['args'])
        for key, value in (('-parallel-testing-enabled', 'NO'),
                           ('-test-timeouts-enabled', 'YES'),
                           ('-default-test-execution-time-allowance', '300'),
                           ('-maximum-test-execution-time-allowance', '300')):
            self.assertEqual(tests['args'][tests['args'].index(key) + 1], value)

    def test_ui_tests_run_on_newest_xcode_27_while_the_build_keeps_the_selected_xcode(self):
        # macOS 27.2 refuses Xcode 26's DTServiceHub, so its runner never connects.
        result, (build, tests) = self.run_ui_driver(installed=("26.6", "27.1", "27.10", "27.2"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNone(build['developer'])
        self.assertIn('test-without-building', tests['args'])
        self.assertEqual(tests['developer'], self.developer("27.10"))
        self.assertIn("Xcode 27.10", result.stdout)

    def test_selected_xcode_27_runs_both_steps(self):
        result, calls = self.run_ui_driver(selected="27.1", installed=("26.6", "27.1", "27.2"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call['developer'] for call in calls], [None, None])

    def test_callers_developer_dir_runs_both_steps(self):
        result, calls = self.run_ui_driver(installed=("26.6", "27.1"), DEVELOPER_DIR=str(self.root / "chosen"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call['developer'] for call in calls], [str(self.root / "chosen")] * 2)

    def test_refused_xcode_without_a_newer_one_fails_before_building(self):
        result, calls = self.run_ui_driver(installed=("26.6",), macos="27.2.1")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(calls, [])
        self.assertIn("refuses the selected Xcode 26.6's DTServiceHub", result.stderr)

    def test_older_macos_keeps_xcode_26_when_no_newer_one_is_installed(self):
        for macos in ("27.0.1", "27.1", "26.6.2"):
            with self.subTest(macos=macos):
                result, calls = self.run_ui_driver(installed=("26.6",), macos=macos)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual([call['developer'] for call in calls], [None, None])
                (self.root / "xcode.jsonl").unlink()
                shutil.rmtree(self.root / "Applications")

    @unittest.skipUnless(HOST_GATE, "this host configures no simulator gate (git config csec.simulatorRun)")
    def test_shipped_gate_handles_cold_warm_command_failure_and_shutdown(self):
        first = self.run_check(CSEC_CI_SIMULATOR_RUN=str(HOST_GATE))
        self.assertEqual(first[0], 0, first)
        second = self.run_check(CSEC_CI_SIMULATOR_RUN=str(HOST_GATE), COMMAND_EXIT="19")
        self.assertEqual(second[0], 19, second)
        self.assertEqual(len(self.state()["boots"]), 3)
        self.assertEqual([d["name"] for d in self.state()["devices"]], [BASE])
        holder = json.loads(Path(self.environment["SIMULATOR_RUN_LOCK"]).read_text())
        self.assertEqual(holder["phase"], "released")

    @unittest.skipUnless(HOST_GATE, "this host configures no simulator gate (git config csec.simulatorRun)")
    def test_shipped_gate_honours_the_admission_budget(self):
        with open(self.environment["SIMULATOR_RUN_LOCK"], "a") as host:
            fcntl.flock(host, fcntl.LOCK_EX)
            result = self.run_check(CSEC_CI_SIMULATOR_RUN=str(HOST_GATE), CSEC_CI_SIMULATOR_WAIT_S="1")
        self.assertEqual(result[0], 76, result)
        self.assertIn("admission timed out", result[2])
        self.assertEqual(self.state()["calls"], [])

    @unittest.skipUnless(HOST_GATE, "this host configures no simulator gate (git config csec.simulatorRun)")
    def test_shipped_gate_cleans_after_orchestrator_sigkill_then_reclaims_clone(self):
        process = self.start(CSEC_CI_SIMULATOR_RUN=str(HOST_GATE),
                             COMMAND_RELEASE=str(self.root / "release"))
        self.wait_for(lambda: len(self.state().get("commands", [])) == 1, process=process)
        process.kill()
        self.finish(process)
        self.wait_for(lambda: all(d["state"] == "Shutdown" for d in self.state()["devices"]))
        result = self.run_check(CSEC_CI_SIMULATOR_RUN=str(HOST_GATE))
        self.assertEqual(result[0], 0, result)
        self.assertEqual([d["name"] for d in self.state()["devices"]], [BASE])


if __name__ == "__main__":
    unittest.main()
