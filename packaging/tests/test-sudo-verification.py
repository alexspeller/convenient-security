#!/usr/bin/env python3
"""Decide the sudo installer's live check without privilege, sudo or host logs.

The installer keeps an installation only when the value-free unified-log trail
of the one sudo it ran shows the installed helper approving it. These tests
drive the shared evidence functions and the installer's own live-check
function against a fake unified log and a fake sudo; nothing authenticates,
installs or reads the host's log.
"""
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest

# The fake log reader runs this file again under `python -I`, which leaves its
# directory off the path.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from csec_identity import IDENTIFIER, IDENTITY_FILE, IDENTITY_LIBRARY  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]
LIB = ROOT / "lib/sudo-review-policy.sh"
INSTALLER = ROOT / "bin/install-sudo-review.sh"
HELPER = "/usr/local/libexec/csec-sudo-review"
SUDO = "/usr/bin/sudo"
SUBSYSTEM = IDENTIFIER
STARTED = "2026-10-25 21:00:00"
VERIFY_PID = 4242
OTHER_PID = 5151
HELPER_PID = 4300
OTHER_HELPER_PID = 5200

# A compact-style header and entry exactly as `log show --style compact`
# printed them on macOS 27.0.1.
HEADER = "Timestamp               Ty Process[PID:TID]"


def compact(pid, image, category, message, second):
    process = os.path.basename(image)
    return (f"2026-10-25 21:00:{second:02d}.562 Df {process}[{pid}:eb2e178] "
            f"[{SUBSYSTEM}:{category}] {message}")


def module(pid, *messages):
    return [(pid, SUDO, "process-liveness", "sudo " + m) for m in messages]


def helper(pid, *messages, image=HELPER):
    return [(pid, image, "sudo-review", m) for m in messages]


def approved_module(pid, helper_pid):
    return module(
        pid,
        "stage=redactor event=finished",
        "stage=review event=launch-started",
        f"stage=review event=signature-check-started pid={helper_pid}",
        "stage=review event=running",
        "stage=review event=helper-exit status=0",
        "stage=review event=approved",
    )


def approved_helper(pid, parent, route="mac", image=HELPER):
    middle = (["event=delegation decision=approved"] if route == "delegation" else
              ["event=delegation decision=not_applicable",
               f"event=outcome result=approved surface={route} status=0"])
    return helper(pid, f"event=started parent={parent}", *middle, "event=exit status=0", image=image)


def refusing_module(pid, helper_pid, fallback_osstatus):
    return module(
        pid,
        "stage=review event=launch-started",
        f"stage=review event=signature-check-started pid={helper_pid}",
        "stage=review event=running",
        "stage=review event=helper-exit status=69",
        "stage=review event=unsuccessful",
        "stage=fallback event=apple-prompt reason=review-unsuccessful",
        f"stage=fallback event=finished osstatus={fallback_osstatus}",
    )


def refusing_helper(pid, parent):
    return helper(pid, f"event=started parent={parent}",
                  "event=delegation decision=not_applicable",
                  "event=outcome result=use-password status=69", "event=exit status=69")


# Replaces the one log reader with a fake over a TSV store (fake_log below).
# Every read's start and predicate is recorded, and the first $SKIP_READS
# reads see an empty log, as a slow log delivery would.
FAKE_LOG = r"""
csec_sudo_log_show() {
  printf '%s\t%s\n' "$1" "$2" >>"$FAKE_DIR/reads"
  [[ ! -e "$FAKE_DIR/unreadable" ]] || return 1
  "$FAKE_PYTHON" -I "$FAKE_LOG_SCRIPT" "$FAKE_DIR" "$2"
}
"""


def fake_log(directory, predicate):
    """Print the stored entries a `log show` predicate of the installer's shapes selects."""
    root = pathlib.Path(directory)
    print(HEADER)
    reads = len((root / "reads").read_text().splitlines())
    if reads <= int(os.environ.get("SKIP_READS", "0")):
        return
    prefix = f'subsystem == "{SUBSYSTEM}" AND '
    assert predicate.startswith(prefix), predicate
    rest = predicate[len(prefix):]
    if rest.startswith("((") and rest.endswith("))"):
        clauses = rest[2:-2].split(") OR (")
    else:
        clauses = [rest]
    parsed = []
    for clause in clauses:
        conditions = {}
        for condition in clause.split(" AND "):
            match = re.fullmatch(r'(\w+) == (?:"([^"]*)"|(\d+))', condition)
            assert match, condition
            conditions[match.group(1)] = match.group(2) if match.group(2) is not None else match.group(3)
        assert set(conditions) <= {"category", "processID", "processImagePath", "process"}, clause
        parsed.append(conditions)
    for row in (root / "log").read_text().splitlines():
        pid, image, category, _, entry = row.split("\t")
        facts = {"processID": pid, "processImagePath": image, "category": category,
                 "process": os.path.basename(image)}
        if any(all(facts[key] == value for key, value in conditions.items())
               for conditions in parsed):
            print(entry)


class Harness:
    def __init__(self, directory, entries):
        self.dir = pathlib.Path(directory)
        rows = []
        for second, (pid, image, category, message) in enumerate(entries):
            rows.append("\t".join([str(pid), image, category, message,
                                   compact(pid, image, category, message, second % 60)]))
        (self.dir / "log").write_text("".join(row + "\n" for row in rows))
        (self.dir / "reads").write_text("")

    def bash(self, script, env=None):
        environment = {"PATH": "/usr/bin:/bin", "FAKE_DIR": str(self.dir),
                       "FAKE_PYTHON": sys.executable, "FAKE_LOG_SCRIPT": str(pathlib.Path(__file__).resolve())}
        environment.update(env or {})
        return subprocess.run(
            ["/bin/bash", "-c", "set -euo pipefail\nsource \"$1\"\nsource \"$2\"\ncsec_identity_load \"$3\"\n"
             + FAKE_LOG + script, "verification-test", str(LIB), str(IDENTITY_LIBRARY), str(IDENTITY_FILE)],
            text=True, capture_output=True, timeout=20, check=False, env=environment,
        )

    def reads(self):
        return [line.split("\t", 1) for line in (self.dir / "reads").read_text().splitlines()]


def verified(entries, pid=VERIFY_PID, env=None):
    with tempfile.TemporaryDirectory(prefix="csec-sudo-verify-") as directory:
        harness = Harness(directory, entries)
        result = harness.bash(
            f'csec_sudo_verified_approval "{STARTED}" {pid} "{HELPER}"', env)
        return result, harness.reads()


class EvidenceTests(unittest.TestCase):
    def assertVerified(self, entries, route):
        result, reads = verified(entries)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, route + "\n")
        # Every read is bounded to the verification's start and its own PIDs.
        self.assertTrue(reads)
        for start, predicate in reads:
            self.assertEqual(start, STARTED)
            self.assertIn(f'subsystem == "{SUBSYSTEM}"', predicate)
        self.assertIn(f"processID == {VERIFY_PID}", reads[0][1])
        self.assertIn('processImagePath == "/usr/bin/sudo"', reads[0][1])
        self.assertIn(f"processID == {HELPER_PID}", reads[1][1])
        self.assertIn('process == "csec-sudo-review"', reads[1][1])
        self.assertNotIn("processImagePath", reads[1][1])

    def assertRefused(self, entries, reason):
        result, _ = verified(entries)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(reason, result.stdout)

    def test_exact_helper_approval_on_the_mac_phone_or_by_delegation(self):
        for route in ["mac", "phone", "delegation"]:
            with self.subTest(route=route):
                self.assertVerified(approved_module(VERIFY_PID, HELPER_PID)
                                    + approved_helper(HELPER_PID, VERIFY_PID, route), route)

    def test_an_unrelated_concurrent_approval_cannot_stand_in(self):
        # Another sudo's review approved while the verification sudo went
        # through Apple's fallback: the exit statuses and a process listing
        # would both have looked like success.
        concurrent = (approved_module(OTHER_PID, OTHER_HELPER_PID)
                      + approved_helper(OTHER_HELPER_PID, OTHER_PID))
        self.assertRefused(concurrent + module(
            VERIFY_PID, "stage=redactor event=unavailable reason=stderr-output",
            "stage=fallback event=apple-prompt reason=redactor-unavailable",
            "stage=fallback event=finished osstatus=0"),
            "last: sudo stage=fallback event=finished osstatus=0")
        self.assertRefused(concurrent, "the module logged nothing for this sudo")

    def test_a_helper_started_by_another_sudo_cannot_stand_in(self):
        self.assertRefused(approved_module(VERIFY_PID, OTHER_HELPER_PID)
                           + approved_helper(OTHER_HELPER_PID, OTHER_PID),
                           "the review helper was not started by this sudo")

    def test_helper_rejection_then_fallback_success_is_refused(self):
        # Use Password in the review, then Apple's prompt approved.
        self.assertRefused(refusing_module(VERIFY_PID, HELPER_PID, 0)
                           + refusing_helper(HELPER_PID, VERIFY_PID),
                           "last: sudo stage=fallback event=finished osstatus=0")
        # Apple's prompt cancelled, then stock pam_tid approved: the module
        # wrote nothing more, so its trail still ends in the fallback.
        self.assertRefused(refusing_module(VERIFY_PID, HELPER_PID, -60006)
                           + refusing_helper(HELPER_PID, VERIFY_PID),
                           "last: sudo stage=fallback event=finished osstatus=-60006")

    def test_fallback_only_and_skipped_reviews_are_refused(self):
        for messages in [
            ["stage=redactor event=unavailable reason=stderr-output",
             "stage=fallback event=apple-prompt reason=redactor-unavailable",
             "stage=fallback event=finished osstatus=0"],
            ["stage=review event=skipped reason=no-gui-session"],
            ["stage=review event=launch-started",
             "stage=review event=signature-check-started pid=4300",
             "stage=review event=unsuccessful reason=signature-rejected",
             "stage=fallback event=apple-prompt reason=review-unsuccessful",
             "stage=fallback event=finished osstatus=0"],
        ]:
            with self.subTest(last=messages[-1]):
                self.assertRefused(module(VERIFY_PID, *messages),
                                   "did not end with the review helper approving")

    def test_an_approved_retry_after_a_failed_attempt_is_an_approval(self):
        first = refusing_module(VERIFY_PID, 4299, -60006)
        self.assertVerified(first + refusing_helper(4299, VERIFY_PID)
                            + approved_module(VERIFY_PID, HELPER_PID)
                            + approved_helper(HELPER_PID, VERIFY_PID), "mac")

    def test_approval_needs_the_helper_exit_and_the_helper_own_trail(self):
        lines = approved_module(VERIFY_PID, HELPER_PID)
        without_exit = [line for line in lines if "helper-exit" not in line[3]]
        self.assertRefused(without_exit + approved_helper(HELPER_PID, VERIFY_PID),
                           "without the helper exit")
        relaunched = module(VERIFY_PID, "stage=review event=launch-started",
                            "stage=review event=helper-exit status=0",
                            "stage=review event=approved")
        self.assertRefused(lines[:3] + relaunched, "without the helper exit")
        self.assertRefused(lines, "the review helper logged nothing")
        self.assertRefused(lines + approved_helper(HELPER_PID, VERIFY_PID)[:-1]
                           + helper(HELPER_PID, "event=exit status=1"),
                           "did not exit 0 last (last: event=exit status=1)")
        self.assertRefused(lines + helper(HELPER_PID, f"event=started parent={VERIFY_PID}",
                                          "event=exit status=0"),
                           "did not record an approval")
        self.assertRefused(lines + helper(HELPER_PID, f"event=started parent={VERIFY_PID}",
                                          "event=rejected reason=untrusted-parent status=69",
                                          "event=outcome result=approved surface=mac status=0",
                                          "event=exit status=0"),
                           "refused the review")

    def test_lines_from_another_image_under_the_same_pids_do_not_count(self):
        # A process that only logs under the subsystem is not /usr/bin/sudo,
        # and a differently named helper (a spike) is not the review helper.
        forged = [(VERIFY_PID, "/private/tmp/forger", c, m)
                  for _, _, c, m in approved_module(VERIFY_PID, HELPER_PID)]
        self.assertRefused(forged + approved_helper(HELPER_PID, VERIFY_PID),
                           "the module logged nothing for this sudo")
        self.assertRefused(approved_module(VERIFY_PID, HELPER_PID)
                           + [(p, HELPER + "-spike", c, m) for p, _, c, m in
                              approved_helper(HELPER_PID, VERIFY_PID)],
                           "the review helper logged nothing")

    def test_the_installed_helper_logged_under_the_build_tree_path_counts(self):
        # logd names an image by its UUID, so once the build has run the
        # identical binary, the installed helper's lines carry the build
        # tree's path (seen on the 26 Oct 2026 install, phone approval).
        build_copy = "/Users/someone/convenient-security/packaging/build/sudo-review/csec-sudo-review"
        self.assertVerified(approved_module(VERIFY_PID, HELPER_PID)
                            + approved_helper(HELPER_PID, VERIFY_PID, "phone", image=build_copy),
                            "phone")

    def test_an_unreadable_log_is_not_evidence(self):
        with tempfile.TemporaryDirectory(prefix="csec-sudo-verify-") as directory:
            harness = Harness(directory, approved_module(VERIFY_PID, HELPER_PID)
                              + approved_helper(HELPER_PID, VERIFY_PID))
            (harness.dir / "unreadable").write_text("")
            result = harness.bash(f'csec_sudo_verified_approval "{STARTED}" {VERIFY_PID} "{HELPER}"')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("the unified log could not be read", result.stdout)

    def test_compact_entries_parse_to_their_messages(self):
        with tempfile.TemporaryDirectory(prefix="csec-sudo-verify-") as directory:
            harness = Harness(directory, [])
            text = "\n".join([
                HEADER,
                "2026-10-25 20:27:16.562 Df sudo[71816:eb2e178] "
                f"[{SUBSYSTEM}:process-liveness] sudo stage=review event=approved",
                "a stray line without the entry shape",
                "2026-10-25 20:27:16.600 Df csec-sudo-review[71900:1a] "
                f"[{SUBSYSTEM}:sudo-review] event=exit status=0",
            ]) + "\n"
            result = subprocess.run(
                ["/bin/bash", "-c", 'source "$1"; csec_log_messages', "parse", str(LIB)],
                input=text, text=True, capture_output=True, timeout=5, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout,
                             "sudo stage=review event=approved\nevent=exit status=0\n")


def installer_live_check():
    """The installer's own live-check definitions, as the root script runs them."""
    text = INSTALLER.read_text()
    start = text.index("verification_shell=")
    end = text.index("# The end of the live check's definitions")
    return text[start:end]


# A fake sudo shaped exactly like the installer's two calls: the `-k` reset
# and the verification itself, which prints the PID the real shell would.
FAKE_SUDO = r'''
function /usr/bin/sudo {
  printf '%s\n' "$*" >>"$FAKE_DIR/sudo-calls"
  if [[ "$*" == "-u alex -H -- /usr/bin/sudo -k" ]]; then return 0; fi
  [[ "$1 $2 $3 $4 $5 $6" == "-u alex -H -- /bin/sh -c" && "$7" == "$verification_shell" &&
     "$8" == "csec-sudo-verify" && "$#" -eq 9 ]] || { echo "unexpected sudo: $*" >&2; return 99; }
  printf '%s\n' "$FAKE_PID_OUTPUT"
  return "$FAKE_SUDO_STATUS"
}
function /bin/sleep { :; }
login_user=alex
destination_helper=/usr/local/libexec/csec-sudo-review
'''


class InstallerLiveCheckTests(unittest.TestCase):
    def run_check(self, entries, pid_output=str(VERIFY_PID), status=0, skip_reads=0):
        with tempfile.TemporaryDirectory(prefix="csec-sudo-live-") as directory:
            harness = Harness(directory, entries)
            result = harness.bash(
                installer_live_check() + FAKE_SUDO +
                'approval_route=""\nif run_live_verification; then echo "kept $approval_route"; '
                'else echo "restored"; fi\n',
                {"FAKE_PID_OUTPUT": pid_output, "FAKE_SUDO_STATUS": str(status),
                 "SKIP_READS": str(skip_reads)})
            return result, harness.reads()

    def test_exact_approval_keeps_the_installation(self):
        result, reads = self.run_check(approved_module(VERIFY_PID, HELPER_PID)
                                       + approved_helper(HELPER_PID, VERIFY_PID, "phone"))
        self.assertEqual(result.stdout, "kept phone\n", result.stderr)
        started = reads[0][0]
        self.assertRegex(started, r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$")
        self.assertTrue(all(start == started for start, _ in reads))

    def test_a_slow_log_delivery_is_waited_for(self):
        result, reads = self.run_check(approved_module(VERIFY_PID, HELPER_PID)
                                       + approved_helper(HELPER_PID, VERIFY_PID),
                                       skip_reads=3)
        self.assertEqual(result.stdout, "kept mac\n", result.stderr)
        self.assertEqual(len(reads), 5)

    def test_fallback_success_restores_and_prints_only_this_sudo_trail(self):
        entries = (approved_module(OTHER_PID, OTHER_HELPER_PID)
                   + approved_helper(OTHER_HELPER_PID, OTHER_PID)
                   + refusing_module(VERIFY_PID, HELPER_PID, 0)
                   + refusing_helper(HELPER_PID, VERIFY_PID))
        result, reads = self.run_check(entries)
        self.assertEqual(result.stdout, "restored\n")
        self.assertIn("did not end with the review helper approving", result.stderr)
        self.assertIn("restoring", result.stderr)
        trail = reads[-1][1]
        self.assertIn(f"processID == {VERIFY_PID})", trail)
        self.assertIn(f"processID == {HELPER_PID})", trail)
        self.assertNotIn(str(OTHER_PID), trail)
        self.assertIn("sudo stage=fallback event=finished osstatus=0", result.stderr)
        self.assertNotIn(f"[{OTHER_PID}:", result.stderr)

    def test_a_failed_sudo_restores_whatever_its_trail_says(self):
        result, _ = self.run_check(approved_module(VERIFY_PID, HELPER_PID)
                                   + approved_helper(HELPER_PID, VERIFY_PID), status=1)
        self.assertEqual(result.stdout, "restored\n")
        self.assertIn("the verification sudo did not succeed (status 1)", result.stderr)

    def test_a_sudo_that_reports_no_pid_restores(self):
        for output in ["", "0", "42 43", "pid", "-1"]:
            with self.subTest(output=output):
                result, reads = self.run_check(approved_module(VERIFY_PID, HELPER_PID)
                                               + approved_helper(HELPER_PID, VERIFY_PID),
                                               pid_output=output)
                self.assertEqual(result.stdout, "restored\n")
                self.assertIn("did not report its PID", result.stderr)
                # Unbound, the trail is every sudo's since the start.
                self.assertIn('process == "sudo"', reads[-1][1])

    def test_the_shell_keeps_its_pid_across_exec(self):
        # The verification shell prints $$ and execs sudo; run the real snippet
        # with sudo swapped for a script that records the PID it runs as.
        snippet = installer_live_check().split("\n", 1)[0]
        self.assertTrue(snippet.startswith("verification_shell='") and snippet.endswith("'"))
        snippet = snippet[len("verification_shell='"):-1]
        self.assertIn("exec /usr/bin/sudo -p \"$1\" /usr/bin/true", snippet)
        with tempfile.TemporaryDirectory(prefix="csec-sudo-pid-") as directory:
            recorder = pathlib.Path(directory) / "record"
            recorder.write_text('#!/bin/sh\necho "$$ $*" >"$0.out"\n')
            recorder.chmod(0o755)
            result = subprocess.run(
                ["/bin/sh", "-c", snippet.replace("/usr/bin/sudo", str(recorder)),
                 "csec-sudo-verify", "Password for %u: "],
                text=True, capture_output=True, timeout=5, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            printed = result.stdout.strip()
            self.assertRegex(printed, r"^[1-9][0-9]*$")
            self.assertEqual((pathlib.Path(str(recorder) + ".out")).read_text(),
                             f"{printed} -p Password for %u:  /usr/bin/true\n")


if __name__ == "__main__":
    if len(sys.argv) == 3 and pathlib.Path(sys.argv[1]).is_dir():
        fake_log(sys.argv[1], sys.argv[2])
    else:
        unittest.main()
