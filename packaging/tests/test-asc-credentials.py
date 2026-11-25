"""Exercise packaging credential delivery with synthetic broker/Apple doubles.

No real broker, provider, keychain, signing identity, device or network is used.
"""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

PACKAGING = Path(__file__).resolve().parents[1]
HARNESS = r'''
source "$1"
shift
asc_csec_app="$FAKE_CSEC_APP"
asc_run_csec() { "$FAKE_CSEC" "$@"; }
main "$@"
'''
BROKER = r'''#!/usr/bin/env python3
import fcntl, json, os, subprocess, sys
args = sys.argv[1:]
with open(os.environ['TRACE'], 'a') as trace:
    trace.write(json.dumps(['broker', args]) + '\n')
if args == ['doctor', '--check', '--runtime']:
    sys.exit(int(os.environ.get('BROKER_STATUS', '0')))
if os.environ.get('BROKER_STATUS'):
    sys.exit(int(os.environ['BROKER_STATUS']))
assert args.pop(0) == 'exec-fd'
bindings = {}
while args[0] != '--':
    flag, value = args[:2]; del args[:2]
    if flag == '--fd':
        name, reference = value.split('=', 1)
        bindings[name] = reference
    else:
        assert flag == '--reason'
del args[0]
values = {'ASC_KEY_ID_FILE': b'synthetic-key-id',
          'ASC_ISSUER_ID_FILE': b'synthetic-issuer-id',
          'ASC_PRIVATE_KEY_FILE': b'synthetic-private-key\nexact bytes\n'}
assert set(bindings) == set(values)
environment = os.environ.copy()
descriptors = []
for name in bindings:
    reader, writer = os.pipe()
    descriptor = fcntl.fcntl(reader, fcntl.F_DUPFD, 64)
    os.close(reader)
    os.write(writer, values[name]); os.close(writer)
    descriptors.append(descriptor)
    environment[name] = '/dev/fd/' + str(descriptor)
try:
    result = subprocess.run(args, env=environment, pass_fds=descriptors)
finally:
    for descriptor in descriptors: os.close(descriptor)
sys.exit(result.returncode)
'''
APPLE = r'''#!/usr/bin/env python3
import json, os, pathlib, stat, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
assert 'synthetic-private-key' not in '\n'.join(args)
assert not any('synthetic-private-key' in value for value in os.environ.values())
record = [name, args]
if name == 'xcrun' and args[:2] == ['notarytool', 'submit']:
    key = pathlib.Path(args[args.index('--key') + 1])
    assert key.read_bytes() == b'synthetic-private-key\nexact bytes\n'
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert stat.S_IMODE(key.parent.stat().st_mode) == 0o700
    assert args[args.index('--key-id') + 1] == 'synthetic-key-id'
    assert args[args.index('--issuer') + 1] == 'synthetic-issuer-id'
    if os.environ.get('SUBMIT_SIGNAL'):
        import signal
        os.kill(os.getppid(), signal.SIGTERM)
    if os.environ.get('SUBMIT_STATUS'):
        with open(os.environ['TRACE'], 'a') as trace:
            trace.write(json.dumps(record) + '\n')
        sys.exit(int(os.environ['SUBMIT_STATUS']))
    print(json.dumps({'status': os.environ.get('APPLE_STATUS', 'Accepted')}))
elif name == 'ditto':
    pathlib.Path(args[-1]).touch()
elif name == 'mise':
    assert args[-5:-1] == ['bundle', 'exec', '--keep-file-descriptors', 'fastlane']
    assert args[-1] in ('provision', 'testflight')
    assert os.environ['ASC_KEY_ID'] == 'synthetic-key-id'
    assert os.environ['ASC_ISSUER_ID'] == 'synthetic-issuer-id'
    assert pathlib.Path(os.environ['ASC_KEY_FILE']).read_bytes() == b'synthetic-private-key\nexact bytes\n'
with open(os.environ['TRACE'], 'a') as trace:
    trace.write(json.dumps(record) + '\n')
'''
# 1Password's CLI on a Mac with no csec yet: it prints the field a reference
# names, and records how it was called and whether a service account could
# have answered instead of the user.
OP = r'''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
with open(os.environ['TRACE'], 'a') as trace:
    trace.write(json.dumps(['op', args, {
        'unattended': sorted(k for k in os.environ
                             if k in ('OP_SERVICE_ACCOUNT_TOKEN', 'OP_CONNECT_HOST', 'OP_CONNECT_TOKEN')),
    }]) + '\n')
if os.environ.get('OP_STATUS'):
    print('[ERROR] authorization prompt dismissed', file=sys.stderr)
    sys.exit(int(os.environ['OP_STATUS']))
assert args[0] == 'read' and '--no-newline' in args and args[-2] == '--'
values = {'key_id': b'synthetic-key-id', 'issuer_id': b'synthetic-issuer-id',
          'key': b'synthetic-private-key\nexact bytes\n'}
sys.stdout.buffer.write(values[args[-1].rsplit('/', 1)[1]])
'''
# Stands in for build-pkg.sh between the two notarizations: it runs after the
# app is stapled and inherits neither the credential descriptors nor the key.
BUILD_PKG = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
inherited = []
for descriptor in range(3, 256):
    try:
        os.fstat(descriptor)
        inherited.append(descriptor)
    except OSError:
        pass
trace = pathlib.Path(os.environ['TRACE'])
records = [json.loads(line) for line in trace.read_text().splitlines()]
with trace.open('a') as handle:
    handle.write(json.dumps(['build-pkg', sys.argv[1:], {
        'inherited': inherited,
        'credential_variables': sorted(k for k in os.environ if k.startswith('ASC_') and k.endswith('_FILE')),
        'key_in_environment': any('synthetic-private-key' in v for v in os.environ.values()),
        'notary_variables': sorted(k for k in os.environ if k.startswith('NOTARY_')),
        'app_stapled_first': any(r[0] == 'xcrun' and r[1][:2] == ['stapler', 'staple']
                                 and r[1][2].endswith('.app') for r in records),
    }]) + '\n')
if os.environ.get('BUILD_PKG_STATUS'):
    sys.exit(int(os.environ['BUILD_PKG_STATUS']))
pathlib.Path(os.environ['PACKAGE_TARGET']).touch()
'''


class CredentialTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="csec-asc-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        # Copy only source, never the developer's gitignored .env or profiles.
        self.packaging = self.root / "packaging"
        (self.packaging / "bin").mkdir(parents=True)
        (self.packaging / "lib").mkdir()
        for relative in ("bin/notarize.sh", "bin/provision.sh", "lib/asc-credentials.sh", "lib/identity.sh"):
            shutil.copyfile(PACKAGING / relative, self.packaging / relative)
        shutil.copyfile(PACKAGING.parent / "identity.xcconfig", self.root / "identity.xcconfig")
        self.trace = self.root / "trace.jsonl"
        for name, body in [("csec", BROKER), *[(n, APPLE) for n in
                           ("xcrun", "ditto", "spctl", "mise")]]:
            path = self.bin / name
            path.write_text(body)
            path.chmod(0o700)
        self.build_pkg = self.packaging / "bin" / "build-pkg.sh"
        self.build_pkg.write_text(BUILD_PKG)
        self.build_pkg.chmod(0o700)
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(("OP_", "ASC_", "NOTARY_"))}
        # An installed csec unless a test removes it; never the real /Applications.
        self.csec_app = self.root / "ConvenientSecurity.app"
        self.csec_app.mkdir()
        self.env.update(PATH=str(self.bin) + ":/usr/bin:/bin", TRACE=str(self.trace),
                        FAKE_CSEC=str(self.bin / "csec"), TMPDIR=str(self.root),
                        FAKE_CSEC_APP=str(self.csec_app),
                        OP_ASC_ITEM="op://synthetic-vault/signing-item")
        self.env.pop("CSEC_BUILD_AND_INSTALL_PIPELINE", None)
        self.target = self.root / "Artifact.pkg"
        self.target.touch()

    def run_wrapper(self, script="notarize.sh", *args):
        return subprocess.run(["/bin/bash", "-c", HARNESS, "asc-test",
                               str(self.packaging / "bin" / script), *args],
                              env=self.env, text=True, capture_output=True, timeout=20)

    def records(self):
        return [json.loads(line) for line in self.trace.read_text().splitlines()]

    def assert_clean(self, result):
        self.assertNotIn("synthetic-private-key", result.stdout + result.stderr)
        self.assertEqual(list(self.root.glob("convenient-security-notary.*")), [])

    def test_preflight_checks_broker_without_access_or_signin(self):
        result = self.run_wrapper("notarize.sh", "--check-auth")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.records(), [["broker", ["doctor", "--check", "--runtime"]]])
        self.assert_clean(result)

    def test_preflight_refuses_unavailable_broker(self):
        self.env["BROKER_STATUS"] = "17"
        result = self.run_wrapper("notarize.sh", "--check-auth")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(self.records()), 1)
        self.assert_clean(result)

    def test_package_uses_one_batch_and_private_temporary_key(self):
        result = self.run_wrapper("notarize.sh", str(self.target))
        self.assertEqual(result.returncode, 0, result.stderr)
        records = self.records()
        self.assertEqual(sum(record[0] == "broker" for record in records), 1)
        args = records[0][1]
        for field in ("key_id", "issuer_id", "key"):
            self.assertTrue(any(value.endswith("op://synthetic-vault/signing-item/" + field)
                                for value in args))
        self.assertEqual([r[1][0] for r in records if r[0] == "xcrun"],
                         ["notarytool", "stapler", "stapler"])
        self.assert_clean(result)

    def test_explicit_references_are_backend_neutral(self):
        self.env.pop("OP_ASC_ITEM")
        self.env.update(ASC_KEY_ID_REF="csec://signing/key-id",
                        ASC_ISSUER_ID_REF="op://elsewhere/identity/issuer",
                        ASC_KEY_REF="csec://signing/private-key")
        result = self.run_wrapper("notarize.sh", str(self.target))
        self.assertEqual(result.returncode, 0, result.stderr)
        args = self.records()[0][1]
        for name in ("ASC_KEY_ID_REF", "ASC_ISSUER_ID_REF", "ASC_KEY_REF"):
            self.assertTrue(any(value.endswith("=" + self.env[name]) for value in args))
        self.assert_clean(result)

    def test_broker_denial_never_starts_submission(self):
        self.env["BROKER_STATUS"] = "23"
        result = self.run_wrapper("notarize.sh", str(self.target))
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assertEqual(len(self.records()), 1)
        self.assert_clean(result)

    def test_failed_submission_cleans_key_and_does_not_staple(self):
        self.env["SUBMIT_STATUS"] = "29"
        result = self.run_wrapper("notarize.sh", str(self.target))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([r[1][0] for r in self.records() if r[0] == "xcrun"], ["notarytool"])
        self.assert_clean(result)

    def test_signal_during_submission_cleans_private_key(self):
        self.env["SUBMIT_SIGNAL"] = "1"
        result = self.run_wrapper("notarize.sh", str(self.target))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([r[1][0] for r in self.records() if r[0] == "xcrun"], ["notarytool"])
        self.assert_clean(result)

    def test_internal_consumer_refuses_missing_descriptors(self):
        result = self.run_wrapper("notarize.sh", "--with-asc-credentials", str(self.target))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.trace.exists())
        self.assert_clean(result)

    def test_rejected_submission_cleans_key_and_does_not_staple(self):
        self.env["APPLE_STATUS"] = "Invalid"
        result = self.run_wrapper("notarize.sh", str(self.target))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([r[1][0] for r in self.records() if r[0] == "xcrun"], ["notarytool"])
        self.assert_clean(result)

    def test_app_zips_then_submits_and_staples_bundle(self):
        target = self.root / "Artifact.app"
        target.mkdir()
        result = self.run_wrapper("notarize.sh", str(target))
        self.assertEqual(result.returncode, 0, result.stderr)
        records = self.records()
        self.assertIn(["xcrun", ["stapler", "staple", str(target)]], records)
        self.assertFalse(target.with_suffix(".notarize.zip").exists())
        self.assert_clean(result)

    def release(self, build_pkg=None):
        app = self.root / "Artifact.app"
        app.mkdir()
        self.target.unlink()
        self.env["PACKAGE_TARGET"] = str(self.target)
        result = self.run_wrapper("notarize.sh", str(app), "--build-package",
                                  str(build_pkg or self.build_pkg), str(self.target))
        return app, result

    def steps(self):
        return [record[0] if record[0] != "xcrun" else " ".join(record[1][:2])
                for record in self.records()]

    def test_app_and_package_share_one_delivery_around_the_package_build(self):
        app, result = self.release()
        self.assertEqual(result.returncode, 0, result.stderr)
        records = self.records()
        self.assertEqual(self.steps(), [
            "broker", "ditto", "notarytool submit", "stapler staple", "spctl", "stapler validate",
            "build-pkg",
            "notarytool submit", "stapler staple", "spctl", "stapler validate"])
        self.assertIn(["xcrun", ["stapler", "staple", str(app)]], records)
        self.assertIn(["xcrun", ["stapler", "staple", str(self.target)]], records)
        build = next(record for record in records if record[0] == "build-pkg")
        self.assertEqual(build[1], [])
        self.assertEqual(build[2], {"inherited": [], "credential_variables": [],
                                       "key_in_environment": False, "notary_variables": [],
                                       "app_stapled_first": True})
        self.assert_clean(result)

    def test_failed_package_build_stops_before_the_package_submission(self):
        self.env["BUILD_PKG_STATUS"] = "31"
        _, result = self.release()
        self.assertEqual(result.returncode, 31, result.stderr)
        self.assertEqual(self.steps().count("notarytool submit"), 1)
        self.assertEqual(self.steps()[-1], "build-pkg")
        self.assert_clean(result)

    def test_failed_app_submission_never_builds_the_package(self):
        self.env["SUBMIT_STATUS"] = "29"
        _, result = self.release()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.steps(), ["broker", "ditto", "notarytool submit"])
        self.assert_clean(result)

    def test_only_its_own_build_pkg_runs_between_the_notarizations(self):
        other = self.root / "build-pkg.sh"
        other.write_text(BUILD_PKG)
        other.chmod(0o700)
        _, result = self.release(build_pkg=other)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--build-package", result.stderr)
        self.assertFalse(self.trace.exists())
        self.assert_clean(result)

    def test_provisioning_keeps_private_key_on_inherited_descriptor(self):
        result = self.run_wrapper("provision.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([r[0] for r in self.records()], ["broker", "mise"])
        self.assert_clean(result)

    def test_testflight_lane_keeps_private_key_on_inherited_descriptor(self):
        result = self.run_wrapper("provision.sh", "testflight")
        self.assertEqual(result.returncode, 0, result.stderr)
        records = self.records()
        self.assertEqual([r[0] for r in records], ["broker", "mise"])
        self.assertEqual(records[0][1][-4:], ["/bin/bash", str(self.packaging / "bin" / "provision.sh"),
                                              "--with-asc-credentials", "testflight"])
        self.assertEqual(records[1][1][-1], "testflight")
        self.assert_clean(result)

    def test_unknown_lane_stops_before_broker(self):
        for args in (("deliver",), ("testflight", "extra")):
            with self.subTest(args=args):
                self.trace.unlink(missing_ok=True)
                result = self.run_wrapper("provision.sh", *args)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.trace.exists())
                self.assert_clean(result)

    def caller_key(self):
        """What a signing wrapper hands its command once its owner approved the build."""
        key = self.root / "caller" / "AuthKey.p8"
        key.parent.mkdir(mode=0o700)
        key.write_bytes(b"synthetic-private-key\nexact bytes\n")
        key.chmod(0o600)
        self.env.update(NOTARY_KEY=str(key), NOTARY_KEY_ID="synthetic-key-id",
                        NOTARY_ISSUER="synthetic-issuer-id")
        return key

    def test_a_callers_key_notarizes_both_without_asking_csec(self):
        key = self.caller_key()
        self.env.pop("OP_ASC_ITEM")
        app, result = self.release()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.steps(), [
            "ditto", "notarytool submit", "stapler staple", "spctl", "stapler validate",
            "build-pkg",
            "notarytool submit", "stapler staple", "spctl", "stapler validate"])
        build = next(record for record in self.records() if record[0] == "build-pkg")
        self.assertEqual(build[2], {"inherited": [], "credential_variables": [],
                                       "key_in_environment": False, "notary_variables": [],
                                       "app_stapled_first": True})
        self.assertTrue(key.exists(), "the caller's key is the caller's to remove")
        self.assert_clean(result)

    def test_a_callers_key_provisions_and_passes_preflight_without_asking_csec(self):
        self.caller_key()
        result = self.run_wrapper("provision.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([r[0] for r in self.records()], ["mise"])
        result = self.run_wrapper("notarize.sh", "--check-auth")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("csec is not asked", result.stdout)
        self.assertEqual([r[0] for r in self.records()], ["mise"])
        self.assert_clean(result)

    def test_an_incomplete_callers_key_refuses_and_never_falls_back_to_csec(self):
        for missing in ("NOTARY_KEY_ID", "NOTARY_ISSUER", "file"):
            with self.subTest(missing=missing):
                key = self.caller_key()
                if missing == "file":
                    key.unlink()
                else:
                    self.env.pop(missing)
                for args in (("notarize.sh", str(self.target)), ("notarize.sh", "--check-auth"), ("provision.sh",)):
                    result = self.run_wrapper(*args)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("NOTARY_KEY needs", result.stderr)
                self.assertFalse(self.trace.exists())
                shutil.rmtree(key.parent)

    def first_build(self, op=True):
        """A Mac where csec was never installed, inside build-and-install.sh."""
        self.csec_app.rmdir()
        self.env["CSEC_BUILD_AND_INSTALL_PIPELINE"] = "1"
        if op:
            path = self.bin / "op"
            path.write_text(OP)
            path.chmod(0o700)

    def op_reads(self):
        return [record for record in self.records() if record[0] == "op"]

    def test_a_first_build_notarizes_both_with_one_op_delivery(self):
        self.first_build()
        self.env["OP_SERVICE_ACCOUNT_TOKEN"] = "synthetic-service-account"
        app, result = self.release()
        self.assertEqual(result.returncode, 0, result.stderr)
        steps = self.steps()
        self.assertEqual(steps[:4], ["op"] * 4)
        self.assertEqual(steps[4:], [
            "ditto", "notarytool submit", "stapler staple", "spctl", "stapler validate",
            "build-pkg",
            "notarytool submit", "stapler staple", "spctl", "stapler validate"])
        reads = self.op_reads()
        # The first read settles 1Password's approval; its value is discarded.
        self.assertEqual(reads[0][1][-1], "op://synthetic-vault/signing-item/key_id")
        self.assertEqual(sorted(read[1][-1] for read in reads[1:]), [
            "op://synthetic-vault/signing-item/issuer_id",
            "op://synthetic-vault/signing-item/key",
            "op://synthetic-vault/signing-item/key_id"])
        self.assertEqual([read[2]["unattended"] for read in reads], [[]] * 4)
        build = next(record for record in self.records() if record[0] == "build-pkg")
        self.assertEqual(build[2], {"inherited": [], "credential_variables": [],
                                       "key_in_environment": False, "notary_variables": [],
                                       "app_stapled_first": True})
        self.assertIn("1Password asks you to approve", result.stderr)
        self.assert_clean(result)

    def test_a_first_build_provisions_from_op_on_inherited_descriptors(self):
        self.first_build()
        self.env["OP_ACCOUNT"] = "synthetic.1password.example"
        result = self.run_wrapper("provision.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([r[0] for r in self.records()], ["op"] * 4 + ["mise"])
        for read in self.op_reads():
            self.assertEqual(read[1][1:3], ["--account", "synthetic.1password.example"])
        self.assert_clean(result)

    def test_a_first_build_preflight_reads_nothing(self):
        self.first_build()
        result = self.run_wrapper("notarize.sh", "--check-auth")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("no csec is installed", result.stdout)
        self.assertFalse(self.trace.exists())
        self.assert_clean(result)

    def test_a_first_build_refuses_references_op_cannot_read(self):
        self.first_build()
        self.env.pop("OP_ASC_ITEM")
        self.env.update(ASC_KEY_ID_REF="op://synthetic-vault/signing-item/key_id",
                        ASC_ISSUER_ID_REF="op://synthetic-vault/signing-item/issuer_id",
                        ASC_KEY_REF="csec://signing/private-key")
        for args in (("notarize.sh", "--check-auth"), ("notarize.sh", str(self.target)), ("provision.sh",)):
            with self.subTest(args=args):
                result = self.run_wrapper(*args)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("ASC_KEY_REF must be an op:// reference", result.stderr)
        self.assertFalse(self.trace.exists())

    def test_a_first_build_without_op_stops_before_anything_runs(self):
        self.first_build(op=False)
        for args in (("notarize.sh", "--check-auth"), ("notarize.sh", str(self.target))):
            with self.subTest(args=args):
                result = self.run_wrapper(*args)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("needs 1Password's CLI", result.stderr)
        self.assertFalse(self.trace.exists())

    def test_a_declined_op_approval_never_starts_submission(self):
        self.first_build()
        self.env["OP_STATUS"] = "6"
        result = self.run_wrapper("notarize.sh", str(self.target))
        self.assertEqual(result.returncode, 6, result.stderr)
        self.assertEqual(self.steps(), ["op"])
        self.assert_clean(result)

    def test_an_installed_csec_is_always_asked_instead_of_op(self):
        self.first_build()
        self.csec_app.mkdir()
        result = self.run_wrapper("notarize.sh", str(self.target))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.steps()[0], "broker")
        self.assertEqual(self.op_reads(), [])
        self.assert_clean(result)

    def test_op_is_never_used_outside_build_and_install(self):
        self.first_build()
        self.env.pop("CSEC_BUILD_AND_INSTALL_PIPELINE")
        result = self.run_wrapper("notarize.sh", str(self.target))
        self.assertEqual(self.op_reads(), [])
        self.assertEqual(self.steps()[0], "broker")
        self.assert_clean(result)

    def test_missing_configuration_stops_before_broker(self):
        self.env.pop("OP_ASC_ITEM")
        result = self.run_wrapper("notarize.sh", "--check-auth")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.trace.exists())
        self.assert_clean(result)


if __name__ == "__main__":
    unittest.main()
