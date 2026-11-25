#!/usr/bin/env python3
"""Render sudo-local migrations without privilege or host configuration writes."""
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
REVIEW = "auth       sufficient     /usr/local/lib/pam/pam_csec_sudo.so"
GUARD = "auth       requisite      /usr/local/lib/pam/pam_csec_sudo.so review_guard"
TID = "auth       sufficient     pam_tid.so"


def render(policy):
    return subprocess.run(
        ["/bin/bash", "-c", 'source "$1"; csec_sudo_policy "$2" "$3" "$4"',
         "policy-test", str(ROOT / "lib/sudo-review-policy.sh"), REVIEW, GUARD, TID],
        input=policy, text=True, capture_output=True, timeout=5, check=False,
    )


class SudoPolicyTests(unittest.TestCase):
    def test_fresh_install_with_or_without_touch_id(self):
        for original in ["", "# local preferences\n", "# local preferences\n" + TID + "\n"]:
            with self.subTest(original=original):
                result = render(original)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "# local preferences\n" * bool(original)
                                 + "\n".join([REVIEW, GUARD, TID]) + "\n")

    def test_migrate_existing_install_and_preserve_unrelated_lines(self):
        original = "# custom\n" + REVIEW + "\n# retain this\n" + TID + "\n"
        expected = "# custom\n" + REVIEW + "\n" + GUARD + "\n# retain this\n" + TID + "\n"
        result = render(original)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, expected)
        repeated = render(result.stdout)
        self.assertEqual(repeated.returncode, 0, repeated.stderr)
        self.assertEqual(repeated.stdout, expected)

    def test_reject_ambiguous_or_bypassed_configuration_before_emitting_anything(self):
        cases = [
            REVIEW + "\n" + REVIEW + "\n" + TID,
            GUARD + "\n" + TID,
            REVIEW + "\n" + GUARD + "\n" + GUARD + "\n" + TID,
            TID + "\n" + REVIEW,
            REVIEW + "\n" + GUARD,  # no retained Apple recovery
            REVIEW + "\nauth optional pam_permit.so\n" + GUARD + "\n" + TID,
            REVIEW.replace("sufficient", "required") + "\n" + TID,
            REVIEW + "\n" + TID + "\n" + REVIEW + " unexpected",
        ]
        for original in cases:
            with self.subTest(original=original):
                result = render(original)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    def test_commented_integration_is_inactive(self):
        result = render("# " + REVIEW + "\n" + TID)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "# " + REVIEW + "\n" + "\n".join([REVIEW, GUARD, TID]) + "\n")

    def test_failed_upgrade_restores_the_previous_csec_policy_not_stock(self):
        # Exercise the installer's real exit/rollback function. Only the
        # privileged atomic file replacement is replaced by a temporary-file
        # copy; no host path or authentication is touched.
        installer = (ROOT / "bin/install-sudo-review.sh").read_text()
        finish = installer[installer.index("finish() {"):installer.index("\ntrap finish EXIT")]
        with tempfile.TemporaryDirectory(prefix="csec-sudo-policy-") as directory:
            root = pathlib.Path(directory)
            old = REVIEW + "\n# keep this prior local policy\n" + TID + "\n"
            (root / "original").write_text(old)
            (root / "stock").write_text(TID + "\n")
            (root / "live").write_text(render(old).stdout)
            script = '''
sudo_local="$1/live"
sudo_local_backup="$1/stock"
configuration_backup="$1/original"
keep_active=0 config_activated=1 sudo_local_existed=1
module_replaced=0 module_directory_created=0 helper_replaced=0 helper_directory_created=0
module_backup= helper_backup= staged_module= staged_helper= candidate_sudo_local=
replace_sudo_local() { /bin/cp "$1" "$sudo_local"; }
'''
            result = subprocess.run(
                ["/bin/bash", "-c", script + finish + "\n(exit 23)\nfinish\n", "rollback-test", directory],
                text=True, capture_output=True, timeout=5, check=False,
            )
            self.assertEqual(result.returncode, 23, result.stderr)
            self.assertEqual((root / "live").read_text(), old)
            self.assertEqual((root / "stock").read_text(), TID + "\n")


def remove(policy):
    return subprocess.run(
        ["/bin/bash", "-c", 'source "$1"; csec_sudo_policy_removed "$2" "$3"',
         "removal-test", str(ROOT / "lib/sudo-review-policy.sh"), REVIEW, GUARD],
        input=policy, text=True, capture_output=True, timeout=5, check=False,
    )


class SudoPolicyRemovalTests(unittest.TestCase):
    def test_removes_only_the_csec_lines(self):
        for original, expected in [
            ("# custom\n" + REVIEW + "\n" + GUARD + "\n# retain\n" + TID + "\n",
             "# custom\n# retain\n" + TID + "\n"),
            # The one-line integration from before the deadline guard.
            (REVIEW + "\n" + TID + "\n", TID + "\n"),
            ("# " + REVIEW + "\n" + REVIEW + "\n" + GUARD + "\n" + TID + "\n",
             "# " + REVIEW + "\n" + TID + "\n"),
            ("# nothing of csec's\n" + TID + "\n", "# nothing of csec's\n" + TID + "\n"),
        ]:
            with self.subTest(original=original):
                result = remove(original)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, expected)

    def test_refuses_what_a_person_must_look_at_before_emitting_anything(self):
        for original in [
            REVIEW.replace("sufficient", "required") + "\n" + TID,
            REVIEW + "\n" + GUARD + "\nauth optional /opt/pam_csec_sudo.so\n" + TID,
            REVIEW + "\n" + REVIEW + "\n" + GUARD + "\n" + TID,
            REVIEW + "\n" + GUARD + "\n" + GUARD + "\n" + TID,
        ]:
            with self.subTest(original=original):
                result = remove(original)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")


INSTALLER = ROOT / "bin/install-sudo-review.sh"


def removal_definitions():
    """The installer's live check and removal, exactly as the root script defines them."""
    text = INSTALLER.read_text()
    return text[text.index("verification_shell="):text.index("\nfinish() {")]


# Every host path the removal touches lives under $ROOT, and only the
# root-only primitives are replaced: install's ownership flags, stat's owner
# (the test files are the caller's, standing in for root's), the atomic
# sudo_local replacement and sudo, whose calls are recorded.
REMOVAL_HARNESS = r'''
set -euo pipefail
source "$LIB"
die() { echo "install-sudo-review: $*" >&2; exit 1; }
pam_directory="$ROOT/pam.d"
sudo_local="$pam_directory/sudo_local"
sudo_local_backup="$pam_directory/sudo_local.csec-context-backup"
module_directory="$ROOT/lib/pam"
helper_directory="$ROOT/libexec"
destination_helper="$helper_directory/csec-sudo-review"
custom_line="$REVIEW"
guard_line="$GUARD"
touch_id_line="$TID"
stock_header='# sudo_local: local config file which survives system update and is included for sudo'
login_user=alex
replace_sudo_local() { /bin/cp "$1" "$sudo_local"; }
function /usr/bin/install {
  local mode=""
  while [[ "$#" -gt 2 ]]; do
    case "$1" in
      -o|-g) shift 2 ;;
      -m) mode="$2"; shift 2 ;;
      *) echo "unexpected install: $*" >&2; return 99 ;;
    esac
  done
  /bin/cp -- "$1" "$2"
  [[ -z "$mode" ]] || /bin/chmod "$mode" "$2"
}
function /usr/bin/stat {
  if [[ "$1 $2" == "-f %u" ]]; then echo 0; else command /usr/bin/stat "$@"; fi
}
function /usr/bin/sudo {
  printf '%s\n' "$*" >>"$ROOT/sudo-calls"
  if [[ "$*" == "-u alex -H -- /usr/bin/sudo -k" ]]; then return 0; fi
  [[ "$1 $2 $3 $4 $5 $6" == "-u alex -H -- /bin/sh -c" && "$7" == "$verification_shell" &&
     "$8" == "csec-sudo-verify" && "$#" -eq 9 ]] || { echo "unexpected sudo: $*" >&2; return 99; }
  # What PAM would read for this sudo.
  /bin/cat "$sudo_local" >"$ROOT/pam-at-verification" 2>/dev/null || : >"$ROOT/pam-at-verification"
  case "$SCENARIO" in
    deny) return 1 ;;
    interrupt) kill -TERM "$$" ;;
  esac
  echo 4242
}
'''


class SudoRemovalTests(unittest.TestCase):
    STOCK = "# sudo_local: local config file which survives system update and is included for sudo"

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="csec-sudo-removal-")
        self.root = pathlib.Path(self.directory.name)
        for name in ["pam.d", "lib/pam", "libexec"]:
            (self.root / name).mkdir(parents=True)
        self.sudo_local = self.root / "pam.d/sudo_local"
        self.backup = self.root / "pam.d/sudo_local.csec-context-backup"
        self.module = self.root / "lib/pam/pam_csec_sudo.so"
        self.helper = self.root / "libexec/csec-sudo-review"
        self.spike = self.root / "libexec/csec-sudo-review-spike"
        (self.root / "pam.d/sudo").write_text("auth       include        sudo_local\n")

    def tearDown(self):
        self.directory.cleanup()

    def install_binaries(self):
        for path in [self.module, self.helper, self.spike,
                     self.root / "libexec/csec-sudo-review.csec.AbC123"]:
            path.write_text("binary\n")

    def installed_from(self, stock):
        """What the installer writes over this stock sudo_local."""
        rendered = render(stock)
        self.assertEqual(rendered.returncode, 0, rendered.stderr)
        return rendered.stdout

    def run_removal(self, scenario="approve"):
        script = REMOVAL_HARNESS + removal_definitions() + (
            "\ntrap finish_uninstall EXIT\ntrap 'exit 130' HUP INT TERM\nuninstall_integration\nexit 0\n")
        result = subprocess.run(
            ["/bin/bash", "-c", script, "removal-test"],
            text=True, capture_output=True, timeout=10, check=False,
            env={"PATH": "/usr/bin:/bin", "ROOT": str(self.root), "SCENARIO": scenario,
                 "LIB": str(ROOT / "lib/sudo-review-policy.sh"),
                 "REVIEW": REVIEW, "GUARD": GUARD, "TID": TID})
        calls_file = self.root / "sudo-calls"
        calls = calls_file.read_text().splitlines() if calls_file.exists() else []
        return result, calls

    def assert_binaries_removed(self):
        self.assertEqual(sorted(p.name for p in (self.root / "libexec").iterdir()), [])
        self.assertFalse((self.root / "lib/pam").exists())

    def assert_unchanged(self, before, result):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.sudo_local.read_text(), before)
        for path in [self.module, self.helper, self.spike]:
            self.assertTrue(path.exists(), path)

    def test_unchanged_install_puts_the_stock_file_back_and_deletes_every_csec_file(self):
        for stock in [self.STOCK + "\n" + TID + "\n", "# no Touch ID yet\n"]:
            with self.subTest(stock=stock):
                self.tearDown()
                self.setUp()
                temporaries = set(pathlib.Path("/private/tmp").glob("csec-sudo-local-*"))
                self.backup.write_text(stock)
                self.sudo_local.write_text(self.installed_from(stock))
                self.install_binaries()
                result, calls = self.run_removal()
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                # Exact stock bytes: pam_tid only where the stock file had it.
                self.assertEqual(self.sudo_local.read_text(), stock)
                self.assertEqual((self.root / "pam-at-verification").read_text(), stock)
                self.assertFalse(self.backup.exists())
                self.assert_binaries_removed()
                self.assertEqual(len(calls), 2)
                self.assertIn("checking that sudo works without csec", calls[1])
                self.assertIn("removed: " + str(self.spike), result.stdout)
                self.assertIn("sudo now uses the stock", result.stdout)
                # The transaction's own temporaries are gone.
                self.assertEqual(set(pathlib.Path("/private/tmp").glob("csec-sudo-local-*")),
                                 temporaries)

    def test_a_sudo_local_changed_since_the_install_keeps_its_changes(self):
        stock = self.STOCK + "\n" + TID + "\n"
        self.backup.write_text(stock)
        self.sudo_local.write_text(self.installed_from(stock) + "# added later\n")
        self.install_binaries()
        result, _ = self.run_removal()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.sudo_local.read_text(), stock + "# added later\n")
        self.assertEqual(self.backup.read_text(), stock)
        self.assertIn("kept: " + str(self.backup), result.stdout)
        self.assert_binaries_removed()

    def test_a_sudo_local_csec_created_is_deleted(self):
        self.sudo_local.write_text(self.installed_from(self.STOCK + "\n"))
        self.install_binaries()
        result, calls = self.run_removal()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.sudo_local.exists())
        self.assertEqual((self.root / "pam-at-verification").read_text(), "")
        self.assertEqual(len(calls), 2)
        self.assert_binaries_removed()

    def test_a_failed_or_interrupted_live_sudo_restores_everything(self):
        for scenario in ["deny", "interrupt"]:
            with self.subTest(scenario=scenario):
                self.tearDown()
                self.setUp()
                stock = self.STOCK + "\n" + TID + "\n"
                self.backup.write_text(stock)
                installed = self.installed_from(stock)
                self.sudo_local.write_text(installed)
                self.install_binaries()
                result, _ = self.run_removal(scenario)
                self.assert_unchanged(installed, result)
                self.assertEqual((self.root / "pam-at-verification").read_text(), stock)
                self.assertEqual(self.backup.read_text(), stock)
                self.assertIn("the sudo integration is still installed", result.stdout)

    def test_refusals_change_nothing_and_run_no_sudo(self):
        stock = self.STOCK + "\n" + TID + "\n"
        cases = {
            "another service loads the module": (
                self.installed_from(stock), "auth sufficient /usr/local/lib/pam/pam_csec_sudo.so\n"),
            "an unrecognized csec line": (
                REVIEW.replace("sufficient", "required") + "\n" + TID + "\n", None),
        }
        for name, (live, other) in cases.items():
            with self.subTest(name):
                self.tearDown()
                self.setUp()
                self.backup.write_text(stock)
                self.sudo_local.write_text(live)
                if other:
                    (self.root / "pam.d/login").write_text(other)
                self.install_binaries()
                result, calls = self.run_removal()
                self.assert_unchanged(live, result)
                self.assertEqual(calls, [])

    def test_leftovers_without_an_active_line_go_without_a_live_sudo(self):
        stock = self.STOCK + "\n" + TID + "\n"
        self.sudo_local.write_text(stock)
        self.spike.write_text("binary\n")
        result, calls = self.run_removal()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(calls, [])
        self.assertEqual(self.sudo_local.read_text(), stock)
        self.assertFalse(self.spike.exists())
        self.assertIn("was not active; its leftover files are removed", result.stdout)

    def test_a_sudo_local_without_csec_is_not_rewritten(self):
        # No trailing newline: a re-rendering would differ by one byte.
        self.sudo_local.write_text(TID)
        result, calls = self.run_removal()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(calls, [])
        self.assertEqual(self.sudo_local.read_text(), TID)
        self.assertIn("nothing to remove", result.stdout)

    def test_nothing_installed_is_nothing_to_remove(self):
        result, calls = self.run_removal()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(calls, [])
        self.assertIn("nothing to remove", result.stdout)

    def test_a_link_in_place_of_a_csec_file_is_left_and_reported(self):
        target = self.root / "elsewhere"
        target.write_text("not csec's\n")
        self.helper.symlink_to(target)
        result, _ = self.run_removal()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertTrue(self.helper.is_symlink())
        self.assertEqual(target.read_text(), "not csec's\n")
        self.assertIn("not a regular file", result.stderr)


def architecture_check():
    """The installer's architecture check, exactly as the root script defines it."""
    text = INSTALLER.read_text()
    start = text.index("has_architectures() {")
    return text[start:text.index("\n}\n", start) + 3]


class SudoArchitectureTests(unittest.TestCase):
    """Runs the check with the host's own lipo, against real fat files.

    Xcode 27.1's lipo takes one architecture per -verify_arch and reads any
    further names as input files, so a single multi-architecture
    -verify_arch failed every install (csec-0.64.16).
    """

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="csec-sudo-arch-")
        root = pathlib.Path(cls.directory.name)
        source = root / "module.c"
        source.write_text("int csec_arch_probe(void) { return 0; }\n")
        cls.fat = {}
        for name, architectures in [("all", ["x86_64", "arm64", "arm64e"]),
                                    ("no-x86_64", ["arm64", "arm64e"])]:
            output = root / f"{name}.so"
            command = ["/usr/bin/xcrun", "clang", "-dynamiclib", "-o", str(output), str(source)]
            for architecture in architectures:
                command[2:2] = ["-arch", architecture]
            subprocess.run(command, check=True, capture_output=True, timeout=120)
            cls.fat[name] = output

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def check(self, path, *architectures):
        return subprocess.run(
            ["/bin/bash", "-c", 'set -euo pipefail; eval "$1"; shift; has_architectures "$@"',
             "arch-test", architecture_check(), str(path), *architectures],
            text=True, capture_output=True, timeout=30, check=False,
        )

    def test_every_architecture_present_passes(self):
        result = self.check(self.fat["all"], "x86_64", "arm64", "arm64e")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_missing_architecture_fails(self):
        for missing_last in [["arm64", "arm64e", "x86_64"], ["x86_64", "arm64", "arm64e"]]:
            with self.subTest(order=missing_last):
                result = self.check(self.fat["no-x86_64"], *missing_last)
                self.assertNotEqual(result.returncode, 0)

    def test_the_installer_checks_the_module_with_it(self):
        text = INSTALLER.read_text()
        self.assertEqual(text.count("/usr/bin/lipo "), 1, "only has_architectures may run lipo")
        self.assertEqual(text.count('has_architectures "$source_module" x86_64 arm64 arm64e'), 1)
        self.assertEqual(text.count('has_architectures "$destination_module" x86_64 arm64 arm64e'), 1)


if __name__ == "__main__":
    unittest.main()
