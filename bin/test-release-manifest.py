"""bin/release-manifest.py writes the next manifest from this checkout and
checks a signed one with stock OpenSSH against the keys pinned in the source.
Keys here are throwaway ones made for each test."""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("release_manifest", ROOT / "bin/release-manifest.py")
release_manifest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release_manifest)


class ReleaseManifestToolTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def run_tool(self, *arguments):
        return subprocess.run([sys.executable, str(ROOT / "bin/release-manifest.py"), *arguments],
                              text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)

    def key(self, name):
        path = self.root / name
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", str(path)], check=True)
        return path, (self.root / f"{name}.pub").read_text().strip()

    def sign(self, key, manifest, namespace=release_manifest.NAMESPACE):
        subprocess.run(["ssh-keygen", "-q", "-Y", "sign", "-f", str(key), "-n", namespace, str(manifest)],
                       check=True)
        return Path(f"{manifest}.sig")

    def test_write_numbers_the_next_manifest_and_keeps_other_sections(self):
        first = self.root / "first.json"
        result = self.run_tool("write", "--download", "https://convenientsecurity.app/download", str(first))
        self.assertEqual(result.returncode, 0, result.stderr)
        document = json.loads(first.read_text())
        self.assertEqual(document["schema"], 1)
        self.assertEqual(document["sequence"], 1)
        self.assertEqual(document["release"]["version"], (ROOT / "VERSION").read_text().strip())
        count = int(subprocess.run(["git", "-C", str(ROOT), "rev-list", "--count", "HEAD"], check=True,
                                   text=True, stdout=subprocess.PIPE).stdout)
        self.assertEqual(document["release"]["build"], count)

        document["claudeCode"] = {"kept": True}
        first.write_text(json.dumps(document))
        second = self.root / "second.json"
        result = self.run_tool("write", "--download", "https://convenientsecurity.app/download",
                               "--previous", str(first), str(second))
        self.assertEqual(result.returncode, 0, result.stderr)
        following = json.loads(second.read_text())
        self.assertEqual(following["sequence"], 2)
        self.assertEqual(following["claudeCode"], {"kept": True})

    def test_write_refuses_to_announce_an_older_release(self):
        previous = self.root / "previous.json"
        previous.write_text(json.dumps({"schema": 1, "sequence": 4, "release": {
            "version": "999.0.0", "build": 1, "download": "https://convenientsecurity.app/download"}}))
        result = self.run_tool("write", "--download", "https://convenientsecurity.app/download",
                               "--previous", str(previous), str(self.root / "out.json"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is older than the release the previous manifest announces", result.stderr)

    def test_write_refuses_a_download_address_csec_would_refuse(self):
        for download in ["http://convenientsecurity.app/download", "https://convenientsecurity.app/a b"]:
            result = self.run_tool("write", "--download", download, str(self.root / "out.json"))
            self.assertNotEqual(result.returncode, 0, download)

    def verify(self, manifest, signature, keys):
        try:
            release_manifest.verify(SimpleNamespace(manifest=str(manifest), signature=str(signature)), keys=keys)
        except SystemExit as exit_:
            return exit_.code
        return 0

    def test_verify_accepts_only_a_pinned_key_for_the_manifest_namespace(self):
        release_key, release_public = self.key("release")
        other_key, other_public = self.key("other")
        manifest = self.root / "manifest.json"
        manifest.write_text(json.dumps({"schema": 1, "sequence": 1, "release": {
            "version": "1.0.0", "build": 10, "download": "https://convenientsecurity.app/download"}}))
        signature = self.sign(release_key, manifest)
        self.assertEqual(self.verify(manifest, signature, [release_public]), 0)
        self.assertEqual(self.verify(manifest, signature, [other_public]), 1)
        self.assertEqual(self.verify(manifest, signature, []), 1)

        wrong_namespace = self.root / "wrong.json"
        wrong_namespace.write_text(manifest.read_text())
        self.assertEqual(self.verify(wrong_namespace, self.sign(release_key, wrong_namespace, "file"),
                                     [release_public]), 1)
        manifest.write_text(manifest.read_text().replace("10", "11"))
        self.assertEqual(self.verify(manifest, signature, [release_public]), 1)

    def test_verify_checks_the_signed_manifest_is_schema_one(self):
        release_key, release_public = self.key("release")
        manifest = self.root / "manifest.json"
        manifest.write_text(json.dumps({"schema": 1, "sequence": 0}))
        self.assertEqual(self.verify(manifest, self.sign(release_key, manifest), [release_public]), 1)

    def test_claude_writes_the_checkout_catalog_and_keeps_the_release(self):
        previous = self.root / "previous.json"
        release = {"version": "1.0.0", "build": 10, "download": "https://convenientsecurity.app/download"}
        previous.write_text(json.dumps({"schema": 1, "sequence": 4, "release": release, "other": [1],
                                        "claude_code": {"checked": [{"cdhash": "f" * 40, "version": "old"}]}}))
        out = self.root / "out.json"
        result = self.run_tool("claude", "--previous", str(previous), str(out))
        self.assertEqual(result.returncode, 0, result.stderr)
        document = json.loads(out.read_text())
        self.assertEqual(document["sequence"], 5)
        self.assertEqual(document["release"], release)
        self.assertEqual(document["other"], [1])
        compiled = release_manifest.compiled_claude_builds()
        self.assertEqual(document["claude_code"], {"checked": compiled})
        self.assertIn({"cdhash": "cb0b92a2ee6314aeadf4303ca2b503a181ad9f7f", "version": "2.1.325"}, compiled)
        # The custom tweakcc image was a developer's own build and is offered to no one.
        self.assertNotIn("64a09464023aa47514a78be456da5b89e01b50a6", {build["cdhash"] for build in compiled})
        self.assertIn(f"{len(compiled)} added, 1 removed", result.stdout)

    def test_claude_refuses_a_catalog_it_cannot_read_whole(self):
        source = self.root / "ClaudeBuildVerification.swift"
        source.write_text('    public static let shipped = ClaudeBuildVerification(records: [\n'
                          '        Record(\n            cdHash: "' + "a" * 40 + '", version: "2.1.1",\n'
                          '            evidence: "x"\n        ),\n'
                          '        Record(cdHash: makeHash(), version: "2.1.2", evidence: "x"),\n    ])\n')
        with self.assertRaises(SystemExit):
            release_manifest.compiled_claude_builds(source)

    def test_claude_code_section_is_checked_the_way_csec_checks_it(self):
        good = {"cdhash": "a" * 40, "version": "2.1.325"}
        for section in [{"checked": [good, dict(good)]}, {"checked": [{"cdhash": "A" * 40, "version": "1"}]},
                        {"checked": [{"cdhash": "a" * 40, "version": "two words"}]}, {"checked": "x"}, [],
                        {"checked": [{"cdhash": "a" * 39, "version": "1"}]},
                        {"checked": [{"cdhash": "a" * 40, "version": ""}]}]:
            with self.assertRaises(SystemExit, msg=section):
                release_manifest.check_manifest({"schema": 1, "sequence": 1, "claude_code": section})
        release_manifest.check_manifest({"schema": 1, "sequence": 1, "claude_code": {"checked": [good]}})

    def test_pinned_keys_are_read_from_the_swift_source(self):
        source = self.root / "ReleaseManifest.swift"
        source.write_text('public enum ReleaseSigningKeys {\n    public static let pinned: [String] = [\n'
                          '        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICa2 csec release 2026",\n'
                          '        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkn",\n    ]\n}\n')
        self.assertEqual(release_manifest.pinned_keys(source), [
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICa2 csec release 2026",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkn"])
        # The checkout's own list parses (and is empty until a key is pinned).
        self.assertIsInstance(release_manifest.pinned_keys(), list)


if __name__ == "__main__":
    unittest.main()
