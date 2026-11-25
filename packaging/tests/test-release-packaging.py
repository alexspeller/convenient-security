"""Release numbering and the package's own upgrade rules (csec-0.39.11):
build-agent.sh reads the release from VERSION and the build number from the
commit count and stamps both into every binary; preinstall refuses to replace
a higher release before anything is written; and after an upgrade every
running csecd is restarted onto the new build and the console user is asked to
reopen their approvals.

Both scripts run against fakes here: a synthetic target volume for preinstall,
and recording launchctl/ps/sudo stand-ins for the restart helper. Nothing is
installed and no real service is touched.
"""

import os
import plistlib
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from csec_identity import IDENTIFIER


PACKAGING = Path(__file__).resolve().parents[1]
SCRIPTS = PACKAGING / "pkg-scripts"
LABEL = IDENTIFIER
CSECD = "/Applications/ConvenientSecurity.app/Contents/MacOS/csecd"
CSEC = "/Applications/ConvenientSecurity.app/Contents/MacOS/csec"


class PreinstallTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.scripts = self.root / "scripts"
        self.scripts.mkdir()
        shutil.copy2(SCRIPTS / "preinstall", self.scripts / "preinstall")
        self.volume = self.root / "volume"
        self.volume.mkdir()

    def package(self, version, build, allow_downgrade=0):
        (self.scripts / "package-release").write_text(
            f"version={version}\nbuild={build}\nallow_downgrade={allow_downgrade}\n")

    def installed(self, version=None, build=None):
        contents = self.volume / "Applications/ConvenientSecurity.app/Contents"
        contents.mkdir(parents=True, exist_ok=True)
        info = {"CFBundleIdentifier": LABEL}
        if version is not None:
            info["CFBundleShortVersionString"] = version
        if build is not None:
            info["CFBundleVersion"] = build
        with open(contents / "Info.plist", "wb") as handle:
            plistlib.dump(info, handle)

    def run_preinstall(self):
        return subprocess.run(
            [str(self.scripts / "preinstall"), "/tmp/ConvenientSecurity.pkg", "/", str(self.volume)],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)

    def assert_installs(self):
        result = self.run_preinstall()
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def assert_refuses(self):
        result = self.run_preinstall()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("would downgrade csec, so nothing was changed", result.stderr)
        return result

    def test_a_first_install_has_nothing_to_compare(self):
        self.package("0.9.0", "4000")
        self.assert_installs()

    def test_an_upgrade_installs(self):
        self.package("1.0.0", "4100")
        self.installed("0.9.0", "4000")
        self.assert_installs()
        self.installed("1.0.0", "4099")
        self.assert_installs()

    def test_reinstalling_the_same_release_repairs(self):
        self.package("1.0.0", "4100")
        self.installed("1.0.0", "4100")
        self.assert_installs()

    def test_a_lower_build_of_the_same_version_is_refused(self):
        self.package("1.0.0", "4100")
        self.installed("1.0.0", "4101")
        result = self.assert_refuses()
        self.assertIn("1.0.0 (build 4101) is installed", result.stderr)

    def test_a_lower_version_is_refused_whatever_its_build(self):
        self.package("1.0.0", "9999")
        self.installed("1.0.1", "10")
        self.assert_refuses()
        self.package("1.9.0", "9999")
        self.installed("1.10.0", "10")
        self.assert_refuses()

    def test_a_rollback_package_may_downgrade(self):
        self.package("1.0.0", "4100", allow_downgrade=1)
        self.installed("1.0.1", "4200")
        result = self.assert_installs()
        self.assertIn("as this package allows", result.stdout)

    def test_an_app_from_before_release_numbers_is_replaced(self):
        self.package("0.9.0", "4000")
        self.installed()
        self.assert_installs()
        # The last unnumbered builds all said 0.1.0 (1), below any release.
        self.installed("0.1.0", "1")
        self.assert_installs()

    def test_a_package_without_a_valid_release_refuses_itself(self):
        for version, build in [("1.0", "4"), ("1.0.0", "0"), ("1.0.0-beta", "4"), ("", "")]:
            with self.subTest(version=version, build=build):
                self.package(version, build)
                result = self.run_preinstall()
                self.assertEqual(result.returncode, 1)
                self.assertIn("carries no valid release", result.stderr)


# What ps and launchd really report for a csecd SMAppService started: the
# bundle-relative BundleProgram, never the absolute path (csec-0.39.11.2).
PS_CSECD = "Contents/MacOS/csecd"


def launchctl_print(state, pid=None):
    """`launchctl print gui/<uid>/<label>` for the csecd job, trimmed to its
    shape: top-level fields one tab deep, and an endpoint block nested inside
    whose own fields must never count as the job's."""
    lines = [f"gui/501/{LABEL} = {{", "\tactive count = 1", f"\tstate = {state}",
             f"\tprogram identifier = {PS_CSECD}"]
    if pid is not None:
        lines.append(f"\tpid = {pid}")
    lines += ["\tendpoints = {", f"\t\t\"{LABEL}.socket\" = {{", "\t\t\tport = 0x1a2b",
              "\t\t\tstate = running", "\t\t\tpid = 4242", "\t\t}", "\t}", "}"]
    return "\n".join(lines) + "\n"


class RestartUserAgentsTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.log = self.root / "launchctl.log"
        self.uid = os.getuid()
        self.console = self.root / "console"
        self.console.write_text("")
        self.failing = self.root / "failing-kickstarts"
        self.failing.write_text("")
        # One file per service target: what `launchctl print` shows for it.
        # A target without one is not loaded, which launchctl reports as 113.
        self.jobs = self.root / "jobs"
        self.jobs.mkdir()

        self.launchctl = self.root / "launchctl"
        self.launchctl.write_text(f"""#!/bin/bash
echo "$*" >> {self.log}
if [ "$1" = print ]; then
  job="{self.jobs}/$(printf '%s' "$2" | tr / _)"
  [ -f "$job" ] || {{ echo "Could not find service" >&2; exit 113; }}
  cat "$job"; exit 0
fi
if [ "$1" = kickstart ] && grep -qxF "$3" {self.failing}; then exit 1; fi
exit 0
""")
        self.launchctl.chmod(0o755)
        self.listing = self.root / "ps-output"
        self.ps = self.root / "ps"
        self.ps.write_text(f"#!/bin/bash\n[ \"$*\" = '-axo uid=,comm=' ] || exit 9\ncat {self.listing}\n")
        self.ps.chmod(0o755)

    def job(self, uid, state="running", pid=None):
        if state == "running" and pid is None:
            pid = 12208
        (self.jobs / f"gui_{uid}_{LABEL}").write_text(launchctl_print(state, pid))

    def run_helper(self, console=None):
        return subprocess.run(
            [str(SCRIPTS / "restart-user-agents"), str(self.launchctl), str(self.ps), "/usr/bin/sudo",
             str(console or self.console), LABEL, CSECD, CSEC],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)

    def calls(self, wait_for=None):
        deadline = time.monotonic() + 5
        while True:
            lines = self.log.read_text().splitlines() if self.log.exists() else []
            if wait_for is None or any(line.startswith(wait_for) for line in lines) \
                    or time.monotonic() > deadline:
                return lines
            time.sleep(0.05)

    def changes(self, wait_for=None):
        """The calls that act on a job; `print` only reads one."""
        return [line for line in self.calls(wait_for) if not line.startswith("print ")]

    def test_every_running_csecd_restarts_once_and_the_console_user_restores(self):
        other = self.uid + 1
        self.job(self.uid)
        self.job(other)
        self.listing.write_text(
            f"  {self.uid} {PS_CSECD}\n"
            f"  {other} {PS_CSECD}\n"
            f"  {self.uid} {PS_CSECD}\n"
            f"  {self.uid} /usr/libexec/other\n")
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"restarted csecd for user {self.uid} on the new build", result.stdout)
        self.assertIn(f"asked user {self.uid} to reopen their approvals", result.stdout)
        calls = self.changes(wait_for="asuser")
        kickstarts = [line for line in calls if line.startswith("kickstart")]
        self.assertEqual(sorted(kickstarts), sorted([
            f"kickstart -k gui/{self.uid}/{LABEL}", f"kickstart -k gui/{other}/{LABEL}"]))
        restores = [line for line in calls if line.startswith("asuser")]
        self.assertEqual(len(restores), 1, calls)
        self.assertTrue(restores[0].startswith(
            f"asuser {self.uid} /usr/bin/sudo -H -u #{self.uid} -- /bin/sh -c "), restores[0])
        self.assertTrue(restores[0].endswith(f"csec-restore {CSEC}"), restores[0])
        self.assertIn("doctor --runtime", restores[0])
        self.assertIn("restore", restores[0])

    def test_a_csecd_started_by_its_relative_bundle_program_restarts(self):
        # csec-0.39.11.2: the live 0.9.0.815 upgrade restarted nobody, because
        # the helper looked for the absolute path ps never shows.
        self.job(self.uid)
        self.listing.write_text(f"  {self.uid} {PS_CSECD}\n")
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"restarted csecd for user {self.uid} on the new build", result.stdout)
        self.assertIn(f"kickstart -k gui/{self.uid}/{LABEL}", self.changes(wait_for="asuser"))

    def test_a_csecd_started_by_its_absolute_path_restarts(self):
        self.job(self.uid)
        self.listing.write_text(f"  {self.uid} {CSECD}\n")
        self.assertEqual(self.run_helper().returncode, 0)
        self.assertIn(f"kickstart -k gui/{self.uid}/{LABEL}", self.changes(wait_for="asuser"))

    def test_another_apps_csecd_is_not_ours_unless_launchd_runs_our_job(self):
        other = self.uid + 1
        self.listing.write_text(
            f"  {self.uid} /Applications/Other.app/{PS_CSECD}\n"
            f"  {other} {PS_CSECD}\n")
        self.assertEqual(self.run_helper().returncode, 0)
        time.sleep(0.3)
        self.assertEqual(self.changes(), [])
        self.assertEqual(sorted(self.calls()), sorted([
            f"print gui/{self.uid}/{LABEL}", f"print gui/{other}/{LABEL}"]))

    def test_a_loaded_job_that_is_not_running_is_left_alone(self):
        # Only its nested endpoint says running with a pid; the job itself
        # does not run, and kickstart -k would start one nobody asked for.
        self.job(self.uid, state="not running")
        self.listing.write_text(f"  {self.uid} {PS_CSECD}\n")
        self.assertEqual(self.run_helper().returncode, 0)
        time.sleep(0.3)
        self.assertEqual(self.changes(), [])

    def test_a_name_that_only_ends_in_csecd_is_no_candidate(self):
        self.job(self.uid)
        self.listing.write_text(f"  {self.uid} /usr/local/bin/notcsecd\n  {self.uid} csecd-helper\n")
        self.assertEqual(self.run_helper().returncode, 0)
        time.sleep(0.3)
        self.assertEqual(self.calls(), [])

    def test_no_restore_when_the_console_user_runs_no_csecd(self):
        self.job(self.uid + 1)
        self.listing.write_text(f"{self.uid + 1} {PS_CSECD}\n")
        self.assertEqual(self.run_helper().returncode, 0)
        time.sleep(0.3)
        self.assertEqual(self.changes(), [f"kickstart -k gui/{self.uid + 1}/{LABEL}"])

    def test_no_restore_without_a_person_at_the_mac(self):
        self.job(self.uid)
        self.listing.write_text(f"{self.uid} {PS_CSECD}\n")
        self.assertEqual(self.run_helper(console=self.root / "no-console").returncode, 0)
        time.sleep(0.3)
        self.assertEqual(self.changes(), [f"kickstart -k gui/{self.uid}/{LABEL}"])

    def test_a_failed_restart_never_fails_the_install(self):
        other = self.uid + 1
        self.job(self.uid)
        self.job(other)
        self.listing.write_text(f"{self.uid} {PS_CSECD}\n{other} {PS_CSECD}\n")
        self.failing.write_text(f"gui/{self.uid}/{LABEL}\n")
        result = self.run_helper()
        self.assertEqual(result.returncode, 0)
        self.assertIn(f"could not restart csecd for user {self.uid}; csec doctor will", result.stderr)
        time.sleep(0.3)
        calls = self.changes()
        self.assertIn(f"kickstart -k gui/{other}/{LABEL}", calls)
        # The console user's csecd did not restart, so nothing asks them yet.
        self.assertFalse(any(line.startswith("asuser") for line in calls), calls)

    def test_nobody_running_csecd_changes_nothing(self):
        self.listing.write_text("")
        self.assertEqual(self.run_helper().returncode, 0)
        time.sleep(0.3)
        self.assertEqual(self.calls(), [])


def run_build_agent_function(script, *arguments):
    return subprocess.run(
        ["/bin/bash", "-c", f'build_agent="$1"; shift; source "$build_agent" && {script}', "release-test",
         str(PACKAGING / "bin/build-agent.sh"), *arguments],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)


class ReleaseNumberingTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def test_the_repository_version_is_a_release(self):
        result = run_build_agent_function('read_release_version "$1"', str(PACKAGING.parent / "VERSION"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, r"^\d+\.\d+\.\d+\n$")

    def test_only_major_minor_patch_is_a_release_version(self):
        version = self.root / "VERSION"
        for good in ["0.9.0\n", "1.0.0", "10.20.30\n"]:
            version.write_text(good)
            result = run_build_agent_function('read_release_version "$1"', str(version))
            self.assertEqual((result.returncode, result.stdout), (0, good.strip() + "\n"), result.stderr)
        for bad in ["1.0\n", "1.0.0-beta\n", "01.0.0\n", "v1.0.0\n", "1.0.0\n2.0.0\n", ""]:
            with self.subTest(bad=bad):
                version.write_text(bad)
                result = run_build_agent_function('read_release_version "$1"', str(version))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("MAJOR.MINOR.PATCH", result.stderr)

    def git(self, repository, *arguments):
        subprocess.run(["git", "-C", str(repository), *arguments], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
                            "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"})

    def test_the_build_number_is_the_commit_count_and_a_shallow_clone_is_refused(self):
        repository = self.root / "repository"
        repository.mkdir()
        self.git(repository, "init", "-q")
        for number in range(3):
            self.git(repository, "commit", "-q", "--allow-empty", "-m", f"c{number}")
        result = run_build_agent_function('read_build_number "$1"', str(repository))
        self.assertEqual((result.returncode, result.stdout), (0, "3\n"), result.stderr)

        shallow = self.root / "shallow"
        self.git(self.root, "clone", "-q", "--depth", "1", f"file://{repository}", str(shallow))
        result = run_build_agent_function('read_build_number "$1"', str(shallow))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("shallow clone", result.stderr)

    def test_the_stamp_is_exactly_the_json_the_agent_decodes(self):
        stamp = self.root / "stamp.json"
        commit = "a" * 40
        result = run_build_agent_function('write_release_stamp "$1" 0.9.0 4567 "$2"', str(stamp), commit)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stamp.read_text(), '{"version":"0.9.0","build":4567,"commit":"%s"}' % commit)
        result = run_build_agent_function('write_release_stamp "$1" 0.9.0 4567 abc', str(stamp))
        self.assertNotEqual(result.returncode, 0)

    def test_a_binary_must_carry_this_builds_stamp(self):
        stamp = self.root / "stamp.json"
        stamp.write_text('{"version":"0.9.0","build":1,"commit":"%s"}' % ("b" * 40))
        source = self.root / "main.c"
        source.write_text("int main(void) { return 0; }\n")
        stamped = self.root / "stamped"
        unstamped = self.root / "unstamped"
        subprocess.run(["/usr/bin/cc", "-o", str(stamped), str(source),
                        "-Wl,-sectcreate,__TEXT,__csec_stamp," + str(stamp)], check=True)
        subprocess.run(["/usr/bin/cc", "-o", str(unstamped), str(source)], check=True)
        result = run_build_agent_function('verify_release_stamp "$1" "$2"', str(stamped), str(stamp))
        self.assertEqual(result.returncode, 0, result.stderr)
        result = run_build_agent_function('verify_release_stamp "$1" "$2"', str(unstamped), str(stamp))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not carry this build's release stamp", result.stderr)
        other = self.root / "other.json"
        other.write_text('{"version":"0.9.0","build":2,"commit":"%s"}' % ("b" * 40))
        result = run_build_agent_function('verify_release_stamp "$1" "$2"', str(stamped), str(other))
        self.assertNotEqual(result.returncode, 0)


class PostinstallWiringTests(unittest.TestCase):
    def test_postinstall_restarts_user_agents_after_the_root_helper_and_never_fails_on_it(self):
        text = (SCRIPTS / "postinstall").read_text()
        reload_at = text.index('"$script_directory/reload-launch-daemon" /bin/launchctl')
        restart_at = text.index('"$script_directory/restart-user-agents" /bin/launchctl /bin/ps /usr/bin/sudo /dev/console')
        self.assertLess(reload_at, restart_at)
        call = text[restart_at:text.index("\n\n", restart_at)]
        self.assertIn('"$csec_identifier" "$app/Contents/MacOS/csecd" "$app/Contents/MacOS/csec" || true', call)

    def test_build_pkg_ships_every_script_and_the_package_release(self):
        text = (PACKAGING / "bin/build-pkg.sh").read_text()
        # Every script in pkg-scripts is copied into the staged scripts the
        # package carries, so a new helper cannot be left behind there.
        copy_at = text.index('cp -p "$scripts/preinstall"')
        copy = text[copy_at:text.index('"$staged_scripts/"', copy_at)]
        scripts = sorted(path.name for path in SCRIPTS.iterdir() if path.is_file())
        self.assertIn("preinstall", scripts)
        for script in scripts:
            self.assertIn(f'"$scripts/{script}"', copy)
        self.assertIn('--scripts "$staged_scripts"', text)
        # The component and the distribution's pkg-ref carry the same VERSION.BUILD.
        self.assertIn('package_version="$version.$build_number"', text)
        self.assertIn('--version "$package_version"', text)
        self.assertIn('s/@VERSION@/$package_version/g', text)
        self.assertIn("allow_downgrade=%s", text)


if __name__ == "__main__":
    unittest.main()
