"""Exercise the package's uninstaller against a fake root with command doubles.

The real script is sourced (its main does not run when sourced); every path it
removes is pointed into a temporary tree and every host command (launchctl,
pkgutil, codesign, umount, the guarded sudo removal, the bridge csec) is a
harmless double that records what it was asked to do.
"""

import json
import os
import plistlib
import subprocess
import tempfile
import unittest
from pathlib import Path

from csec_identity import IDENTIFIER


SCRIPT = Path(__file__).resolve().parents[1] / "libexec/uninstall-csec.sh"

HARNESS = r'''
set -euo pipefail
source "$1"
fake="$2"
root="$3"
app="$root/Applications/ConvenientSecurity.app"
bridge_root="$root/Library/Application Support/ConvenientSecurity"
bridge_csec="$bridge_root/bin/csec"
script_path="$bridge_root/libexec/uninstall-csec.sh"
sudo_removal="$bridge_root/libexec/install-sudo-review.sh"
sudo_local="$root/etc/pam.d/sudo_local"
sudo_module="$root/usr/local/lib/pam/pam_csec_sudo.so"
sudo_helper="$root/usr/local/libexec/csec-sudo-review"
codex_directory="$root/etc/codex"
codex_hooks="$codex_directory/hooks.json"
root_helper="$root/Library/PrivilegedHelperTools/$root_label"
root_plist="$root/Library/LaunchDaemons/$root_label.plist"
runtime_directory="$root/var/run/convenient-security"
path_link="$root/usr/local/bin/csec"
expected_owner="$(/usr/bin/id -u)"
launchctl="$fake/launchctl"
pkgutil="$fake/pkgutil"
codesign="$fake/codesign"
umount="$fake/umount"
stop_polls=5
stop_poll_delay=0
current_uid() { cat "$fake/uid"; }
uid_of() { echo 501; }
is_mount_point() { [ -f "$fake/mounted" ]; }
main
'''

LAUNCHCTL = r'''#!/bin/bash
state="$(dirname "$0")"
echo "launchctl $*" >>"$state/log"
case "$1 $2" in
  "print gui/501/IDENTIFIER") [ -f "$state/agent-loaded" ] ;;
  "print system/IDENTIFIER.rootd")
    if [ -f "$state/rootd-stopping" ]; then
      left="$(cat "$state/rootd-stopping")"
      if [ "$left" -le 0 ]; then rm -f "$state/rootd-stopping" "$state/rootd-loaded"; exit 1; fi
      echo $((left - 1)) >"$state/rootd-stopping"
      exit 0
    fi
    [ -f "$state/rootd-loaded" ] ;;
  "bootout system/IDENTIFIER.rootd") echo 2 >"$state/rootd-stopping" ;;
  *) echo "unexpected launchctl $*" >&2; exit 99 ;;
esac
'''.replace("IDENTIFIER", IDENTIFIER)

PKGUTIL = r'''#!/bin/bash
state="$(dirname "$0")"
echo "pkgutil $*" >>"$state/log"
case "$1" in
  --pkgs=*) [ -f "$state/receipts" ] && cat "$state/receipts" ;;
  --forget) grep -vx "$2" "$state/receipts" >"$state/receipts.new" || true; mv "$state/receipts.new" "$state/receipts" ;;
  *) exit 99 ;;
esac
'''

CODESIGN = r'''#!/bin/bash
state="$(dirname "$0")"
echo "codesign $*" >>"$state/log"
[ ! -f "$state/codesign-fails" ]
'''

UMOUNT = r'''#!/bin/bash
state="$(dirname "$0")"
echo "umount $*" >>"$state/log"
[ -f "$state/umount-fails" ] && exit 1
rm -f "$state/mounted"
'''

SUDO_REMOVAL = r'''#!/bin/bash
state="FAKE"
echo "sudo-removal $*" >>"$state/log"
exit "$(cat "$state/sudo-status")"
'''

BRIDGE_CSEC = r'''#!/bin/bash
state="FAKE"
echo "bridge-csec $*" >>"$state/log"
[ "$*" = "hook-config codex --system --remove" ] || exit 99
cat "$state/codex-output"
'''

OTHER_HOOKS = {"hooks": {"PreToolUse": [{"matcher": "Write", "hooks": [{"type": "command", "command": "true"}]}]}}


class UninstallCsecTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        base = Path(self.temporary.name)
        self.fake = base / "fake"
        self.root = base / "root"
        self.fake.mkdir()
        self.root.mkdir()
        for name, text in [("launchctl", LAUNCHCTL), ("pkgutil", PKGUTIL), ("codesign", CODESIGN), ("umount", UMOUNT)]:
            self.write(self.fake / name, text, 0o755)
        (self.fake / "uid").write_text("0\n")
        (self.fake / "sudo-status").write_text("0\n")
        (self.fake / "log").write_text("")
        (self.fake / "rootd-loaded").write_text("")
        (self.fake / "receipts").write_text(f"{IDENTIFIER}.pkg\n")
        (self.fake / "codex-output").write_text(json.dumps(OTHER_HOOKS))
        self.install_everything()

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, path, text, mode=0o644):
        path.parent.mkdir(parents=True, exist_ok=True)
        for parent in [path.parent, *path.parent.parents]:
            if parent == self.root.parent or not str(parent).startswith(str(self.root.parent)):
                break
            os.chmod(parent, 0o755)
        path.write_text(text)
        os.chmod(path, mode)

    def path(self, relative):
        return self.root / relative

    def install_everything(self):
        info = plistlib.dumps({"CFBundleIdentifier": IDENTIFIER}).decode()
        self.write(self.path("Applications/ConvenientSecurity.app/Contents/Info.plist"), info)
        self.write(self.path("Applications/ConvenientSecurity.app/Contents/MacOS/csec"), "app", 0o755)
        support = "Library/Application Support/ConvenientSecurity"
        self.write(self.path(f"{support}/bin/csec"), BRIDGE_CSEC.replace("FAKE", str(self.fake)), 0o755)
        self.write(self.path(f"{support}/libexec/install-sudo-review.sh"), SUDO_REMOVAL.replace("FAKE", str(self.fake)), 0o755)
        self.write(self.path(f"{support}/libexec/uninstall-csec.sh"), SCRIPT.read_text(), 0o755)
        self.write(self.path(f"{support}/install-receipt.json"), "{}")
        self.write(self.path(f"Library/PrivilegedHelperTools/{IDENTIFIER}.rootd"), "rootd", 0o755)
        self.write(self.path(f"Library/LaunchDaemons/{IDENTIFIER}.rootd.plist"), "plist")
        self.write(self.path("etc/codex/hooks.json"), json.dumps({"description": "csec"}))
        self.write(self.path("usr/local/lib/pam/pam_csec_sudo.so"), "module")
        self.write(self.path("var/run/convenient-security/files/.keep"), "")
        os.remove(self.path("var/run/convenient-security/files/.keep"))
        link = self.path("usr/local/bin/csec")
        link.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(self.path("Applications/ConvenientSecurity.app/Contents/MacOS/csec"), link)

    def run_uninstaller(self):
        result = subprocess.run(
            ["/bin/bash", "-c", HARNESS, "harness", str(SCRIPT), str(self.fake), str(self.root)],
            capture_output=True, text=True, env={"PATH": "/usr/bin:/bin", "SUDO_USER": "someone"},
        )
        self.log = (self.fake / "log").read_text()
        return result

    def assert_nothing_removed(self):
        self.assertTrue(self.path("Applications/ConvenientSecurity.app").is_dir())
        self.assertTrue(self.path("Library/Application Support/ConvenientSecurity/bin/csec").exists())
        self.assertTrue(self.path(f"Library/PrivilegedHelperTools/{IDENTIFIER}.rootd").exists())
        self.assertTrue(self.path("etc/codex/hooks.json").exists())
        self.assertTrue(os.path.islink(self.path("usr/local/bin/csec")))
        self.assertNotIn("bootout", self.log)
        self.assertNotIn("--forget", self.log)

    def test_removes_everything_in_order_and_keeps_other_codex_hooks(self):
        result = self.run_uninstaller()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.path("Applications/ConvenientSecurity.app").exists())
        self.assertFalse(self.path("Library/Application Support/ConvenientSecurity").exists())
        self.assertFalse(self.path(f"Library/PrivilegedHelperTools/{IDENTIFIER}.rootd").exists())
        self.assertFalse(self.path(f"Library/LaunchDaemons/{IDENTIFIER}.rootd.plist").exists())
        self.assertFalse(self.path("var/run/convenient-security").exists())
        self.assertFalse(os.path.lexists(self.path("usr/local/bin/csec")))
        self.assertEqual(json.loads(self.path("etc/codex/hooks.json").read_text()), OTHER_HOOKS)
        self.assertEqual((self.fake / "receipts").read_text(), "")
        order = [self.log.index(marker) for marker in [
            "sudo-removal --uninstall", "codesign --verify", "bridge-csec hook-config",
            f"bootout system/{IDENTIFIER}.rootd", "pkgutil --forget"]]
        self.assertEqual(order, sorted(order), self.log)
        self.assertIn("csec is removed from this Mac", result.stdout)

    def test_a_second_run_finds_nothing_left_and_succeeds(self):
        self.assertEqual(self.run_uninstaller().returncode, 0)
        os.remove(self.path("usr/local/lib/pam/pam_csec_sudo.so"))
        os.remove(self.path("etc/codex/hooks.json"))
        result = self.run_uninstaller()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("the csec sudo review is not installed", result.stdout)
        self.assertIn("there is no managed Codex hook", result.stdout)

    def test_codex_file_holding_only_csec_is_deleted_with_its_empty_directory(self):
        (self.fake / "codex-output").write_text("")
        result = self.run_uninstaller()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.path("etc/codex").exists())

    def test_codex_file_without_csec_is_left_byte_for_byte(self):
        original = self.path("etc/codex/hooks.json").read_bytes()
        (self.fake / "codex-output").write_bytes(original)
        result = self.run_uninstaller()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.path("etc/codex/hooks.json").read_bytes(), original)
        self.assertIn("holds no csec hook", result.stdout)

    def test_a_failed_sudo_removal_stops_before_anything_else(self):
        (self.fake / "sudo-status").write_text("1\n")
        result = self.run_uninstaller()
        self.assertNotEqual(result.returncode, 0)
        self.assert_nothing_removed()
        self.assertNotIn("bridge-csec", self.log)
        self.assertIn("run this again", result.stderr)

    def test_an_unverified_bridge_leaves_the_codex_hook_and_the_app(self):
        (self.fake / "codesign-fails").write_text("")
        result = self.run_uninstaller()
        self.assertNotEqual(result.returncode, 0)
        self.assert_nothing_removed()
        self.assertNotIn("bridge-csec", self.log)

    def test_a_running_agent_means_the_account_part_was_skipped(self):
        (self.fake / "agent-loaded").write_text("")
        result = self.run_uninstaller()
        self.assertNotEqual(result.returncode, 0)
        self.assert_nothing_removed()
        self.assertNotIn("sudo-removal", self.log)
        self.assertIn("csec uninstall --all", result.stderr)

    def test_refuses_without_root(self):
        (self.fake / "uid").write_text("501\n")
        result = self.run_uninstaller()
        self.assertNotEqual(result.returncode, 0)
        self.assert_nothing_removed()
        self.assertIn("through sudo", result.stderr)

    def test_a_sudo_review_without_its_removal_is_refused(self):
        os.remove(self.path("Library/Application Support/ConvenientSecurity/libexec/install-sudo-review.sh"))
        result = self.run_uninstaller()
        self.assertNotEqual(result.returncode, 0)
        self.assert_nothing_removed()

    def test_a_foreign_command_link_and_app_are_left_alone(self):
        link = self.path("usr/local/bin/csec")
        os.remove(link)
        os.symlink("/opt/other/csec", link)
        info = plistlib.dumps({"CFBundleIdentifier": "com.example.other"}).decode()
        self.write(self.path("Applications/ConvenientSecurity.app/Contents/Info.plist"), info)
        result = self.run_uninstaller()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(os.readlink(link), "/opt/other/csec")
        self.assertTrue(self.path("Applications/ConvenientSecurity.app").is_dir())
        self.assertTrue(self.path("Library/Application Support/ConvenientSecurity").is_dir())
        self.assertIn("not csec's app", result.stderr)

    def test_the_protected_file_tmpfs_is_unmounted_before_the_runtime_directory_goes(self):
        (self.fake / "mounted").write_text("")
        result = self.run_uninstaller()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("umount", self.log)
        self.assertFalse(self.path("var/run/convenient-security").exists())

    def test_a_busy_tmpfs_is_left_for_the_next_restart_and_the_rest_still_goes(self):
        (self.fake / "mounted").write_text("")
        (self.fake / "umount-fails").write_text("")
        result = self.run_uninstaller()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.path("var/run/convenient-security/files").is_dir())
        self.assertIn("next restart", result.stderr)
        self.assertFalse(self.path("Applications/ConvenientSecurity.app").exists())

    def test_a_writable_bridge_is_not_trusted_to_edit_the_codex_hook(self):
        os.chmod(self.path("Library/Application Support/ConvenientSecurity/bin/csec"), 0o777)
        result = self.run_uninstaller()
        self.assertNotEqual(result.returncode, 0)
        self.assert_nothing_removed()
        self.assertNotIn("bridge-csec", self.log)


if __name__ == "__main__":
    unittest.main()
