#!/usr/bin/env python3
"""publish-snapshot against throwaway private and public repositories; gitleaks is a stand-in."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parent / "publish-snapshot.py"
NOREPLY = "1+someone@users.noreply.github.com"
# Stands in for a value gitleaks would redact: it must never reach the output.
SENTINEL = "sentinel-value-0123456789"

FAKE_GITLEAKS = r'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
Path(os.environ["FAKE_GITLEAKS_ARGS"]).write_text(json.dumps(args))
report = Path(args[args.index("--report-path") + 1])
ignore = Path(args[args.index("--gitleaks-ignore-path") + 1]) / ".gitleaksignore"
ignored = set(ignore.read_text().split()) if ignore.is_file() else set()
findings = []
for path in sorted(Path(".").rglob("*")):
    if not path.is_file() or path.is_symlink():
        continue
    for number, line in enumerate(path.read_bytes().split(b"\n"), 1):
        if b"FAKE-LEAK" in line:
            fingerprint = f"{path.as_posix()}:fake-rule:{number}"
            if fingerprint not in ignored:
                findings.append({"RuleID": "fake-rule", "File": path.as_posix(), "StartLine": number,
                                 "Fingerprint": fingerprint, "Secret": os.environ["SENTINEL"],
                                 "Match": "key = " + os.environ["SENTINEL"]})
report.write_text(json.dumps(findings))
sys.exit(1 if findings else 0)
'''


class PublishSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="publish-snapshot-test-"))
        self.addCleanup(subprocess.run, ["rm", "-rf", str(self.tmp)])
        gitleaks = self.tmp / "gitleaks"
        gitleaks.write_text(FAKE_GITLEAKS)
        gitleaks.chmod(0o755)
        self.gitleaks_args = self.tmp / "gitleaks-args.json"
        self.env = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1",
                    "CSEC_GITLEAKS": str(gitleaks), "FAKE_GITLEAKS_ARGS": str(self.gitleaks_args),
                    "SENTINEL": SENTINEL}
        self.public = self.tmp / "public.git"
        self.git("init", "--quiet", "--bare", "--initial-branch=main", str(self.public), cwd=self.tmp)
        self.origin = self.tmp / "origin.git"
        self.git("init", "--quiet", "--bare", "--initial-branch=main", str(self.origin), cwd=self.tmp)
        self.repo = self.tmp / "private"
        self.git("init", "--quiet", "--initial-branch=main", str(self.repo), cwd=self.tmp)
        self.git("config", "user.name", "Some One")
        self.git("config", "user.email", NOREPLY)
        self.git("config", "commit.gpgsign", "false")
        self.git("remote", "add", "origin", str(self.origin))
        self.git("remote", "add", "public", str(self.public))
        self.write(".gitattributes", "/publish export-ignore\n/.gitattributes export-ignore\n")
        self.write("publish/terms", "# private names\nHomeServer\n10.99.98.\n")
        self.write("README.md", "A tool.\n")
        self.write("src/tool.py", "print('hello')\n")
        os.symlink("README.md", self.repo / "LINK.md")
        self.commit("Work on the tool (bead-1.2, from homeserver)")

    def git(self, *args, cwd=None):
        return subprocess.run(["git", *args], cwd=cwd or self.repo, env=self.env, check=True,
                              capture_output=True, text=True).stdout.strip()

    def write(self, path, text):
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)

    def commit(self, message):
        self.git("add", "--all")
        self.git("commit", "--quiet", "-m", message)
        return self.git("rev-parse", "HEAD")

    def publish(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *args], cwd=self.repo, env=self.env,
                              capture_output=True, text=True)

    def public_git(self, *args):
        return self.git("--git-dir", str(self.public), *args)

    def public_main(self):
        return self.git("ls-remote", str(self.public), "refs/heads/main").split("\t")[0]

    def test_dry_run_checks_and_pushes_nothing(self):
        done = self.publish()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("checks clean", done.stdout)
        self.assertIn("dry run", done.stdout)
        self.assertEqual(self.public_main(), "")

    def test_check_needs_no_public_remote(self):
        self.git("remote", "remove", "public")
        done = self.publish("--check")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("3 files, 2 left out; checks clean", done.stdout)
        self.write("README.md", "on homeserver\n")
        self.commit("Name it")
        self.assertIn("README.md:1: HomeServer", self.publish("--check").stderr)

    def test_push_publishes_the_tree_without_private_paths_or_history(self):
        private_head = self.git("rev-parse", "HEAD")
        done = self.publish("--push")
        self.assertEqual(done.returncode, 0, done.stderr)
        head = self.public_main()
        self.assertTrue(head)
        self.assertEqual(self.public_git("rev-list", "--count", head), "1")
        self.assertEqual(self.public_git("ls-tree", "-r", "--name-only", head).split(),
                         ["LINK.md", "README.md", "src/tool.py"])
        self.assertEqual(self.public_git("cat-file", "-p", f"{head}:LINK.md"), "README.md")
        self.assertNotEqual(self.public_git("rev-parse", f"{head}^{{tree}}"), self.git("rev-parse", "HEAD^{tree}"))
        message = self.public_git("log", "-1", "--format=%B%n%an <%ae>%n%cn <%ce>", head)
        self.assertNotIn("bead-1.2", message)
        self.assertNotIn("homeserver", message.lower())
        self.assertIn(f"Some One <{NOREPLY}>", message)
        missing = subprocess.run(["git", "--git-dir", str(self.public), "cat-file", "-e", private_head],
                                 env=self.env, capture_output=True)
        self.assertNotEqual(missing.returncode, 0, "the private commit reached the public repository")

    def test_next_publish_builds_on_the_public_main_and_refuses_an_unchanged_tree(self):
        self.assertEqual(self.publish("--push").returncode, 0)
        first = self.public_main()
        unchanged = self.publish("--push")
        self.assertEqual(unchanged.returncode, 0, unchanged.stderr)
        self.assertIn("nothing to publish", unchanged.stdout)
        self.assertEqual(self.public_main(), first)
        self.write("src/tool.py", "print('hello, world')\n")
        self.commit("Greet the world")
        self.assertEqual(self.publish("--push").returncode, 0)
        second = self.public_main()
        self.assertEqual(self.public_git("rev-parse", f"{second}^"), first)
        self.assertEqual(self.public_git("rev-list", "--count", second), "2")

    def test_a_private_term_anywhere_refuses_case_insensitively(self):
        self.write("docs/notes.md", "one\nrun it on homeserver.local\n")
        self.write("assets/blob.bin", "\x00\x01HOMESERVER\x00")
        self.write("src/homeserver-config.txt", "nothing\n")
        os.symlink("/srv/HomeServer/data", self.repo / "data")
        self.commit("More")
        done = self.publish("--push")
        self.assertEqual(done.returncode, 1)
        self.assertIn("docs/notes.md:2: HomeServer", done.stderr)
        self.assertIn("assets/blob.bin:1: HomeServer", done.stderr)
        self.assertIn("src/homeserver-config.txt: path contains HomeServer", done.stderr)
        self.assertIn("data:1: HomeServer", done.stderr)
        self.assertEqual(self.public_main(), "")

    def test_a_leak_finding_refuses_without_printing_its_value(self):
        self.write("src/config.py", "token = 'x'  # FAKE-LEAK\n")
        self.commit("Config")
        done = self.publish("--push")
        self.assertEqual(done.returncode, 1)
        self.assertIn("src/config.py:1: fake-rule (src/config.py:fake-rule:1)", done.stderr)
        self.assertNotIn(SENTINEL, done.stdout + done.stderr)
        self.assertEqual(self.public_main(), "")
        self.assertIn("--ignore-gitleaks-allow", json.loads(self.gitleaks_args.read_text()))

    def test_reviewed_fingerprints_in_the_private_ignore_file_pass(self):
        self.write("src/config.py", "token = 'x'  # FAKE-LEAK\n")
        self.write("publish/.gitleaksignore", "src/config.py:fake-rule:1\n")
        self.commit("Config, reviewed")
        done = self.publish("--push")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("src/config.py", self.public_git("ls-tree", "-r", "--name-only", self.public_main()))

    def test_scanner_configuration_in_the_published_tree_refuses(self):
        for name in (".gitleaksignore", ".gitleaks.toml"):
            with self.subTest(name=name):
                self.write(name, "anything\n")
                self.commit(f"Add {name}")
                done = self.publish()
                self.assertEqual(done.returncode, 1)
                self.assertIn(f"published tree has a {name}", done.stderr)
                (self.repo / name).unlink()
                self.commit(f"Drop {name}")

    def test_publish_directory_must_be_export_ignored(self):
        self.write(".gitattributes", "")
        self.commit("Forget the attributes")
        done = self.publish()
        self.assertEqual(done.returncode, 1)
        self.assertIn("publish/ would be published", done.stderr)

    def test_missing_or_empty_term_list_refuses(self):
        self.write("publish/terms", "# nothing yet\n")
        self.commit("Empty terms")
        self.assertIn("lists no terms", self.publish().stderr)
        (self.repo / "publish/terms").unlink()
        self.commit("No terms")
        done = self.publish()
        self.assertEqual(done.returncode, 1)
        self.assertIn("has no publish/terms", done.stderr)

    def test_checks_read_the_commit_not_the_working_tree(self):
        self.write("README.md", "uncommitted homeserver note\n")
        done = self.publish("--push")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(self.public_git("cat-file", "-p", f"{self.public_main()}:README.md"), "A tool.")

    def test_a_personal_address_refuses(self):
        self.git("config", "user.email", "someone@example.com")
        done = self.publish("--push")
        self.assertEqual(done.returncode, 1)
        self.assertIn("noreply", done.stderr)
        self.assertEqual(self.public_main(), "")

    def test_the_public_remote_must_not_be_the_private_repository(self):
        self.git("remote", "set-url", "public", str(self.origin))
        done = self.publish("--push")
        self.assertEqual(done.returncode, 1)
        self.assertIn("same URL as origin", done.stderr)


if __name__ == "__main__":
    unittest.main()
