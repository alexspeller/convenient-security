"""Exercise the real installer orchestration with harmless command doubles."""

import fcntl
import hashlib
import json
import os
import plistlib
import signal
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from csec_identity import CLOUDKIT_CONTAINER, IDENTIFIER, IDENTITY_FILE, IDENTITY_LIBRARY


INSTALLER = Path(__file__).resolve().parents[1] / "bin/build-and-install.sh"
CONTAINER = CLOUDKIT_CONTAINER

# Source only function definitions, then replace the host-I/O boundaries.
# Run the pipeline normally, not in an if/&& context: Bash disables errexit
# inside functions used as conditional expressions, masking real failures.
HARNESS = r'''
source "$1"
scenario="$2"
PROFILE_PATH="$1"
runtime_state=healthy
sudo_state=healthy
runtime_attempts=0

run() {
  local command
  case "$1" in
    /usr/bin/sudo)
      case "$2" in
        /usr/sbin/installer) command=package ;;
        */install-sudo-review.sh)
          if [ "${3-}" = --uninstall ]; then command=sudo_uninstall; else command=sudo; fi ;;
        */install-codex-hook.sh) command=codex_hook ;;
        *) echo "unexpected sudo command"; exit 99 ;;
      esac ;;
    "$installed_csec")
      case "${2-} ${3-}" in
        'doctor --runtime') command=runtime ;;
        'doctor --check') command=check ;;
        'doctor ') command=doctor ;;
        'status ') command=status ;;
        'restore ') command=restore ;;
        *) echo "unexpected csec command"; exit 99 ;;
      esac ;;
    mise)
      [ "${2-} ${3-} ${5-} ${6-} ${7-}" = "exec -C -- xcodegen generate" ] || { echo "unexpected mise command"; exit 99; }
      command=xcodegen ;;
    /usr/bin/xcrun)
      [ "${2-} ${3-} ${4-} ${5-}" = "devicectl device install app" ] || { echo "unexpected xcrun command"; exit 99; }
      [ "${7-}" = "$iphone_device" ] || { echo "installing onto an unselected device"; exit 99; }
      command=iphone_install ;;
    "${presence_checkpoint:-/no/checkpoint}")
      [ "${2-} ${3-} ${4-} ${5-} ${6-}" = "checkpoint synthetic-job --attempt synthetic-attempt --stage" ] ||
        { echo "unexpected checkpoint command"; exit 99; }
      command="checkpoint ${7-}" ;;
    */notarize.sh) command="notarize.sh ${2##*/}${3:+ $3 ${4##*/} ${5##*/}}" ;;
    *) command="${1##*/}" ;;
  esac
  echo "TRACE $command"
  case "$command" in
    checkpoint*)
      # The worker refuses a cancelled or stale attempt before the next stage.
      if [ "$scenario" = "cancel_at_${command#checkpoint }" ]; then return 75; fi ;;
    build-agent.sh)
      if [ "$scenario" = build_failure ]; then return 21; fi ;;
    xcodebuild)
      if [ "$scenario" = iphone_build_failure ]; then return 31; fi ;;
    iphone_install)
      if [ "$scenario" = iphone_install_failure ]; then return 32; fi ;;
    package)
      # Files may change even when installer exits nonzero.
      runtime_state=stale
      if [ "$scenario" = package_failure ]; then return 22; fi
      if [ "$scenario" = package_signal ]; then kill -TERM "$$"; fi
      echo 'installer: The upgrade was successful.' ;;
    runtime)
      runtime_attempts=$((runtime_attempts + 1))
      if [ "$scenario" = recovery_failure ]; then return 23; fi
      if [ "$scenario" = runtime_failure ] && [ "$runtime_attempts" -eq 1 ]; then return 24; fi
      runtime_state=healthy ;;
    codex_hook)
      # The root stage runs the installed csec, so the runtime must be repaired first.
      if [ "$runtime_state" != healthy ]; then echo 'STALE AGENT'; return 98; fi
      if [ "$scenario" = codex_hook_failure ]; then return 29; fi ;;
    restore)
      if [ "$runtime_state" != healthy ]; then echo 'STALE AGENT'; return 98; fi
      case "$scenario" in
        restore_failure) return 35 ;;
        restore_interrupt) kill -INT "$$" ;;
        restore_forget) echo 'Restored approvals forgotten as requested.' ;;
        restore_not_needed) echo 'No approvals need reopening.' ;;
      esac ;;
    sudo)
      # A regression that moves runtime repair later fails even on happy paths.
      if [ "$runtime_state" != healthy ]; then echo 'STALE AGENT'; return 98; fi
      case "$scenario" in
        sudo_failure)
          sudo_state=broken
          echo 'sudo succeeded without the csec review helper ever running; restoring'
          return 25 ;;
        sudo_interrupt) kill -INT "$$" ;;
        sudo_hangup) kill -HUP "$$" ;;
        premature_success) exit 0 ;;
      esac ;;
    sudo_uninstall)
      case "$scenario" in
        uninstall_failure)
          echo 'the verification sudo did not succeed without csec (status 1); restoring'
          return 36 ;;
        uninstall_interrupt) kill -INT "$$" ;;
      esac ;;
    doctor)
      if [ "$scenario" = doctor_failure ]; then return 26; fi ;;
    status)
      if [ "$scenario" = status_failure ]; then return 27; fi ;;
    check)
      [ "$runtime_state" = healthy ] && [ "$sudo_state" = healthy ]
      return ;;
  esac
  return 0
}

write_codex_hook_document() {
  echo "TRACE codex-document"
  if [ "$scenario" = codex_document_failure ]; then return 30; fi
}

verify_same_file() {
  echo "TRACE verify $2"
  if [ "$scenario" = payload_failure ]; then return 28; fi
}

verify_command_link() {
  echo "TRACE command-link"
  if [ "$scenario" = command_link_failure ]; then return 39; fi
}

verify_install_receipt() {
  echo "TRACE receipt"
  if [ "$scenario" = receipt_failure ]; then return 38; fi
}

verify_cloudkit_signature() {
  echo "TRACE cloudkit $2"
  if [ "$scenario" = entitlement_failure ] && [ "$2" = "installed csecd" ]; then return 34; fi
}

strip_iphone_debugger_entitlement() {
  echo "TRACE iphone-strip-debugger"
}

select_iphone() {
  echo "TRACE select-iphone"
  iphone_device=synthetic-iphone-identifier
  iphone_name="Synthetic iPhone"
}

verify_iphone_build() {
  echo "TRACE iphone-build-check"
  verify_cloudkit_signature "$ios_app" "iPhone app"
}

verify_sudo_integration_removed() {
  echo "TRACE removed-check"
  if [ "$scenario" = uninstall_leftover ]; then return 37; fi
}

verify_installed_iphone_app() {
  echo "TRACE iphone-verify"
  if [ "$scenario" = iphone_verify_failure ]; then return 33; fi
}

case "$scenario" in
  skip_sudo|checkpoints_skip_sudo) install_sudo=0 ;;
  skip_iphone) install_iphone=0 ;;
esac
case "$scenario" in
  checkpoints*|cancel_at_*)
    # What configure_presence_checkpoints sets under an unattended worker.
    presence_checkpoint=/synthetic/worker/bin/install-wait
    presence_job=synthetic-job
    presence_attempt=synthetic-attempt ;;
esac
begin_install_session
if [[ "$scenario" == uninstall* || "$scenario" == checkpoints_uninstall ]]; then
  # main's --uninstall-sudo path, without its host preflight.
  uninstall_sudo=1
  perform_sudo_uninstall
elif [ "$scenario" = only_iphone ] || [ "$scenario" = only_iphone_failure ] ||
    [ "$scenario" = checkpoints_only_iphone ]; then
  # main's --only-iphone path, without its host preflight.
  only_iphone=1
  if [ "$scenario" = only_iphone_failure ]; then scenario=iphone_install_failure; fi
  perform_iphone_install
  finish_dry_run_or_verify
else
  perform_install
fi
'''


def default_interruptions():
    # A non-interactive bash can neither trap nor take a signal ignored when it
    # started, so a runner that ignores SIGHUP (a detached supervisor) would
    # make the hangup scenarios exit 0; a person's terminal never does.
    for interruption in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(interruption, signal.SIG_DFL)


class InstallerTests(unittest.TestCase):
    def run_scenario(self, scenario):
        return subprocess.run(
            ["/bin/bash", "-c", HARNESS, "installer-test", str(INSTALLER), scenario],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10,
            preexec_fn=default_interruptions,
        )

    def assert_failure(self, scenario, code, stage, recovery=True):
        result = self.run_scenario(scenario)
        output = result.stdout
        self.assertEqual(result.returncode, code, output)
        self.assertIn(f"INSTALLATION FAILED during {stage}", output)
        self.assertTrue(output.rstrip().endswith(f"INSTALLATION INCOMPLETE; exiting {code}."), output)
        self.assertNotIn("Build and installation complete:", output)
        self.assertNotIn("STALE AGENT", output)
        failure = output.index("INSTALLATION FAILED")
        if recovery:
            self.assertIn("TRACE runtime", output[failure:])
            self.assertIn("TRACE check", output[failure:])
        else:
            self.assertNotIn("TRACE runtime", output)
            self.assertIn("No installation of host payloads was attempted.", output)
        return output

    def test_success_requires_all_checks_and_repairs_before_sudo(self):
        result = self.run_scenario("success")
        self.assertEqual(result.returncode, 0, result.stdout)
        output = result.stdout
        positions = [output.index(step) for step in [
            "TRACE package", "TRACE runtime", "TRACE restore", "TRACE codex_hook", "TRACE sudo",
            "TRACE verify /Applications/ConvenientSecurity.app/Contents/MacOS/csecd",
            "TRACE verify /Applications/ConvenientSecurity.app/Contents/Resources/ai-guard/op",
            "TRACE verify /Applications/ConvenientSecurity.app/Contents/Resources/claude-code-shell/csec-claude-code-shell",
            "TRACE cloudkit installed csecd",
            "TRACE verify /Library/Application Support/ConvenientSecurity/libexec/uninstall-csec.sh",
            f"TRACE verify /Library/PrivilegedHelperTools/{IDENTIFIER}.rootd",
            "TRACE verify /Library/Application Support/ConvenientSecurity/libexec/install-codex-hook.sh",
            "TRACE verify /Library/Application Support/ConvenientSecurity/libexec/install-sudo-review.sh",
            "TRACE verify /Library/Application Support/ConvenientSecurity/libexec/sudo-review-policy.sh",
            "TRACE verify /Library/Application Support/ConvenientSecurity/libexec/identity.sh",
            "TRACE verify /Library/Application Support/ConvenientSecurity/libexec/identity.xcconfig",
            "TRACE verify /Library/Application Support/ConvenientSecurity/sudo-review/pam_csec_sudo.so",
            "TRACE verify /Library/Application Support/ConvenientSecurity/sudo-review/csec-sudo-review",
            "TRACE command-link",
            "TRACE receipt",
            "TRACE codex-document", "TRACE verify /private/etc/codex/hooks.json",
            "TRACE doctor", "TRACE status", "Build and installation complete:",
        ]]
        self.assertEqual(positions, sorted(positions))
        self.assertNotIn("INSTALLATION FAILED", output)
        self.assertEqual(output.count("TRACE runtime"), 1)
        self.assertEqual(output.count("TRACE verify"), 17)

    def test_iphone_stage_follows_the_verified_mac_install(self):
        result = self.run_scenario("success")
        self.assertEqual(result.returncode, 0, result.stdout)
        output = result.stdout
        positions = [output.index(step) for step in [
            "TRACE status", "TRACE xcodegen", "TRACE xcodebuild",
            "TRACE iphone-strip-debugger",
            "TRACE iphone-build-check", "TRACE cloudkit iPhone app",
            "TRACE select-iphone", "TRACE iphone_install", "TRACE iphone-verify",
            "Build and installation complete:",
            "iPhone approval app installed and verified on Synthetic iPhone",
        ]]
        self.assertEqual(positions, sorted(positions))

    def test_a_stale_install_receipt_fails_payload_verification(self):
        output = self.assert_failure("receipt_failure", 38, "installed payload verification")
        self.assertNotIn("TRACE doctor\n", output)
        self.assertNotIn("TRACE xcodebuild", output)

    def test_installed_csecd_without_cloudkit_fails_payload_verification(self):
        output = self.assert_failure("entitlement_failure", 34, "installed payload verification")
        self.assertNotIn("TRACE doctor\n", output)
        self.assertNotIn("TRACE xcodebuild", output)

    def test_iphone_failure_leaves_the_verified_mac_alone_and_says_how_to_rerun(self):
        for scenario, code, stage in [
            ("iphone_build_failure", 31, "iPhone app build and signing"),
            ("iphone_install_failure", 32, "iPhone app installation"),
            ("iphone_verify_failure", 33, "iPhone app verification"),
        ]:
            with self.subTest(scenario=scenario):
                result = self.run_scenario(scenario)
                output = result.stdout
                self.assertEqual(result.returncode, code, output)
                self.assertIn(f"INSTALLATION FAILED during {stage}", output)
                self.assertIn("The Mac installation is complete and verified", output)
                self.assertIn("packaging/bin/build-and-install.sh --only-iphone", output)
                self.assertTrue(output.rstrip().endswith(f"INSTALLATION INCOMPLETE; exiting {code}."), output)
                self.assertNotIn("Build and installation complete:", output)
                # The Mac passed doctor and status; nothing there to repair.
                self.assertEqual(output.count("TRACE runtime"), 1)
                self.assertNotIn("TRACE check", output)

    def test_skip_iphone_installs_the_mac_only(self):
        result = self.run_scenario("skip_iphone")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("TRACE status", result.stdout)
        self.assertIn("Build and installation complete:", result.stdout)
        for step in ["TRACE xcodegen", "TRACE xcodebuild", "TRACE select-iphone",
                     "TRACE iphone", "iPhone approval app installed"]:
            self.assertNotIn(step, result.stdout)

    def test_only_iphone_touches_nothing_on_the_mac(self):
        result = self.run_scenario("only_iphone")
        output = result.stdout
        self.assertEqual(result.returncode, 0, output)
        self.assertEqual(
            [line for line in output.splitlines() if line.startswith("TRACE")],
            ["TRACE csec_identity_write_swift", "TRACE xcodegen", "TRACE xcodebuild",
             "TRACE iphone-strip-debugger",
             "TRACE iphone-build-check", "TRACE cloudkit iPhone app", "TRACE select-iphone",
             "TRACE iphone_install", "TRACE iphone-verify"])
        self.assertNotIn("Build and installation complete:", output)
        self.assertIn("iPhone approval app installed and verified on Synthetic iPhone", output)

    def test_only_iphone_failure_says_the_mac_was_not_changed(self):
        result = self.run_scenario("only_iphone_failure")
        output = result.stdout
        self.assertEqual(result.returncode, 32, output)
        self.assertIn("INSTALLATION FAILED during iPhone app installation", output)
        self.assertIn("The Mac installation was not changed.", output)
        self.assertIn("--only-iphone", output)
        self.assertNotIn("TRACE runtime", output)

    def test_uninstall_sudo_runs_only_the_guarded_removal_then_checks_it(self):
        for scenario, checkpoint in [("uninstall", []),
                                     ("checkpoints_uninstall", ["TRACE checkpoint sudo-integration-uninstall"])]:
            with self.subTest(scenario=scenario):
                result = self.run_scenario(scenario)
                output = result.stdout
                self.assertEqual(result.returncode, 0, output)
                self.assertEqual([line for line in output.splitlines() if line.startswith("TRACE")],
                                 checkpoint + ["TRACE sudo_uninstall", "TRACE removed-check"])
                self.assertIn("Sudo integration removed and verified", output)
                self.assertNotIn("Build and installation complete:", output)

    def test_a_failed_removal_says_so_and_repairs_nothing_else(self):
        for scenario, code, stage in [
            ("uninstall_failure", 36, "sudo integration removal and live verification"),
            ("uninstall_interrupt", 130, "sudo integration removal and live verification"),
            ("uninstall_leftover", 37, "sudo integration removal verification"),
        ]:
            with self.subTest(scenario=scenario):
                result = self.run_scenario(scenario)
                output = result.stdout
                self.assertEqual(result.returncode, code, output)
                self.assertIn(f"SUDO INTEGRATION REMOVAL FAILED during {stage} (exit {code})", output)
                self.assertIn("rerun: packaging/bin/build-and-install.sh --uninstall-sudo", output)
                self.assertNotIn("Sudo integration removed and verified", output)
                self.assertNotIn("INSTALLATION", output)
                self.assertNotIn("TRACE runtime", output)
                self.assertNotIn("TRACE check", output)
                if scenario != "uninstall_leftover":
                    self.assertNotIn("TRACE removed-check", output)

    def test_codex_hook_failure_recovers_before_sudo(self):
        output = self.assert_failure("codex_hook_failure", 29, "managed Codex hook installation")
        self.assertNotIn("TRACE sudo", output)
        self.assertIn("Runtime recovery verified", output)

    def test_restore_failure_or_interrupt_stops_without_retrying(self):
        for scenario, code in [("restore_failure", 35), ("restore_interrupt", 130)]:
            with self.subTest(scenario=scenario):
                output = self.assert_failure(scenario, code, "approval restoration")
                self.assertEqual(output.count("TRACE restore"), 1)
                for later in ["TRACE codex_hook", "TRACE sudo", "TRACE iphone_install"]:
                    self.assertNotIn(later, output)

    def test_forget_or_nothing_to_restore_completes_the_stage(self):
        for scenario in ["restore_forget", "restore_not_needed"]:
            with self.subTest(scenario=scenario):
                result = self.run_scenario(scenario)
                self.assertEqual(result.returncode, 0, result.stdout)
                self.assertEqual(result.stdout.count("TRACE restore"), 1)
                self.assertIn("Build and installation complete:", result.stdout)

    def test_codex_document_failure_fails_payload_verification(self):
        self.assert_failure("codex_document_failure", 30, "installed payload verification")

    def test_reported_sudo_failure_recovers_and_retains_failure(self):
        output = self.assert_failure("sudo_failure", 25, "sudo integration installation")
        self.assertIn("installer: The upgrade was successful.", output)
        self.assertIn("Runtime recovery verified", output)
        self.assertIn("complete installation still has health-check failures", output)
        self.assertEqual(output.count("TRACE runtime"), 2)

    def test_build_failure_never_touches_host_recovery(self):
        self.assert_failure("build_failure", 21, "build and signing", recovery=False)

    def test_partial_package_failure_still_recovers(self):
        self.assert_failure("package_failure", 22, "package installation")

    def test_runtime_failure_stops_before_sudo_then_retries_recovery(self):
        output = self.assert_failure("runtime_failure", 24, "installed runtime repair")
        self.assertNotIn("TRACE sudo", output)
        self.assertIn("Runtime recovery verified", output)

    def test_recovery_failure_is_explicit(self):
        output = self.assert_failure("recovery_failure", 23, "installed runtime repair")
        self.assertIn("RUNTIME RECOVERY FAILED", output)
        self.assertNotIn("Runtime recovery verified", output)

    def test_later_verification_failures_recover(self):
        for scenario, code, stage in [
            ("payload_failure", 28, "installed payload verification"),
            ("command_link_failure", 39, "installed payload verification"),
            ("doctor_failure", 26, "complete installation health checks"),
            ("status_failure", 27, "complete installation health checks"),
        ]:
            with self.subTest(scenario=scenario):
                self.assert_failure(scenario, code, stage)

    def test_catchable_interruptions_recover_and_fail(self):
        for scenario, code, stage in [
            ("package_signal", 143, "package installation"),
            ("sudo_interrupt", 130, "sudo integration installation"),
            ("sudo_hangup", 129, "sudo integration installation"),
        ]:
            with self.subTest(scenario=scenario):
                self.assert_failure(scenario, code, stage)

    def test_premature_zero_exit_cannot_claim_success(self):
        self.assert_failure("premature_success", 1, "sudo integration installation")

    def test_skip_sudo_still_requires_complete_health(self):
        result = self.run_scenario("skip_sudo")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertNotIn("TRACE sudo\n", result.stdout)
        # The package carries the sudo payload for csec setup, so it is built
        # and its installed copies verified even when the stage is skipped.
        self.assertIn("TRACE build-sudo-pam.sh\nTRACE build-sudo-review.sh", result.stdout)
        self.assertIn("TRACE verify /Library/Application Support/ConvenientSecurity/sudo-review/csec-sudo-review",
                      result.stdout)
        self.assertNotIn("TRACE verify /usr/local/libexec/csec-sudo-review", result.stdout)
        self.assertIn("TRACE codex_hook", result.stdout)
        self.assertEqual(result.stdout.count("TRACE verify"), 15)
        self.assertIn("TRACE doctor\nTRACE status", result.stdout)

    # Each checkpoint, the stage it reports when it refuses, and the command
    # it must come straight before: every native request in the pipeline.
    CHECKPOINTS = [
        ("notarization-authorization", "notarization authorization", "TRACE notarize.sh --check-auth"),
        # One key delivery covers both notarizations and the package build.
        ("app-notarization", "app notarization, package build and package notarization",
         "TRACE notarize.sh ConvenientSecurity.app --build-package build-pkg.sh ConvenientSecurity.pkg"),
        ("package-install", "package installation", "TRACE package"),
        ("approval-restore", "approval restoration", "TRACE restore"),
        ("codex-hook-install", "managed Codex hook installation", "TRACE codex_hook"),
        ("sudo-integration-install", "sudo integration installation and live verification", "TRACE sudo"),
        ("iphone-install", "iPhone app installation", "TRACE iphone_install"),
    ]

    def test_without_a_worker_there_are_no_checkpoints(self):
        for scenario in ["success", "skip_sudo", "only_iphone"]:
            with self.subTest(scenario=scenario):
                result = self.run_scenario(scenario)
                self.assertEqual(result.returncode, 0, result.stdout)
                self.assertNotIn("TRACE checkpoint", result.stdout)

    def test_the_worker_waits_at_the_mac_right_before_each_native_request(self):
        result = self.run_scenario("checkpoints")
        output = result.stdout
        self.assertEqual(result.returncode, 0, output)
        self.assertIn("Build and installation complete:", output)
        traces = [line for line in output.splitlines() if line.startswith("TRACE")]
        checkpoints = [line for line in traces if line.startswith("TRACE checkpoint ")]
        self.assertEqual(checkpoints, [f"TRACE checkpoint {name}" for name, _, _ in self.CHECKPOINTS])
        for name, _, request in self.CHECKPOINTS:
            with self.subTest(checkpoint=name):
                self.assertEqual(traces[traces.index(f"TRACE checkpoint {name}") + 1], request)
        # The build and the iPhone build run unattended, after the checkpoint
        # before them, and every stage still runs once in its usual order.
        positions = [traces.index(step) for step in [
            "TRACE checkpoint notarization-authorization", "TRACE build-agent.sh",
            "TRACE build-sudo-review.sh", "TRACE checkpoint app-notarization", "TRACE runtime",
            "TRACE checkpoint approval-restore", "TRACE restore", "TRACE doctor", "TRACE status",
            "TRACE xcodebuild", "TRACE checkpoint iphone-install", "TRACE iphone-verify",
        ]]
        self.assertEqual(positions, sorted(positions))
        without = [line for line in self.run_scenario("success").stdout.splitlines()
                   if line.startswith("TRACE")]
        self.assertEqual([line for line in traces if line not in checkpoints], without)

    def test_a_refused_checkpoint_stops_before_its_request_and_recovers_as_usual(self):
        package = [name for name, _, _ in self.CHECKPOINTS].index("package-install")
        for index, (name, stage, request) in enumerate(self.CHECKPOINTS):
            with self.subTest(checkpoint=name):
                result = self.run_scenario(f"cancel_at_{name}")
                output = result.stdout
                self.assertEqual(result.returncode, 75, output)
                self.assertIn(f"INSTALLATION FAILED during presence checkpoint before {stage} (exit 75)", output)
                self.assertTrue(output.rstrip().endswith("INSTALLATION INCOMPLETE; exiting 75."), output)
                self.assertNotIn(request, output)
                self.assertNotIn("Build and installation complete:", output)
                for later, _, _ in self.CHECKPOINTS[index + 1:]:
                    self.assertNotIn(f"TRACE checkpoint {later}", output)
                failure = output[output.index("INSTALLATION FAILED"):]
                if name == "iphone-install":
                    self.assertIn("The Mac installation is complete and verified", output)
                    self.assertNotIn("TRACE check\n", output)
                elif index > package:
                    # The package is installed: the usual runtime recovery.
                    self.assertIn("TRACE runtime", failure)
                    self.assertIn("TRACE check\n", failure)
                else:
                    self.assertIn("No installation of host payloads was attempted.", output)
                    self.assertNotIn("TRACE runtime", output)

    def test_skip_sudo_has_no_sudo_integration_checkpoint(self):
        result = self.run_scenario("checkpoints_skip_sudo")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("TRACE checkpoint codex-hook-install\nTRACE codex_hook", result.stdout)
        self.assertNotIn("TRACE checkpoint sudo-integration-install", result.stdout)

    def test_only_iphone_waits_before_the_phone_install_alone(self):
        result = self.run_scenario("checkpoints_only_iphone")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(
            [line for line in result.stdout.splitlines() if line.startswith("TRACE")],
            ["TRACE csec_identity_write_swift", "TRACE xcodegen", "TRACE xcodebuild",
             "TRACE iphone-strip-debugger",
             "TRACE iphone-build-check", "TRACE cloudkit iPhone app", "TRACE select-iphone",
             "TRACE checkpoint iphone-install", "TRACE iphone_install", "TRACE iphone-verify"])

    def dry_run(self, *arguments):
        return subprocess.run(
            [str(INSTALLER), "--dry-run", *arguments], env=clean_environment(),
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10,
        )

    def test_real_entrypoint_dry_run_has_no_success_or_recovery(self):
        result = self.dry_run("--refresh-profile")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("Dry run complete; no build", result.stdout)
        self.assertNotIn("Build and installation complete:", result.stdout)
        self.assertNotIn("Checking and repairing", result.stdout)

    def test_real_entrypoint_iphone_options(self):
        only = self.dry_run("--only-iphone")
        self.assertEqual(only.returncode, 0, only.stdout)
        commands = [line for line in only.stdout.splitlines() if line.startswith("+ ")]
        self.assertEqual(len(commands), 14, only.stdout)
        for step, count in [("csec_identity_write_swift", 1), ("xcodegen generate", 1), ("xcodebuild", 1),
                            ("codesign --display --extract-certificates=", 2),
                            ("codesign --force --sign", 2), ("codesign --display --entitlements", 2),
                            ("devicectl list devices", 1), ("devicectl device install app", 1),
                            ("devicectl device info apps", 1)]:
            self.assertEqual(sum(step in command for command in commands), count, step)
        app = "/Debug-iphoneos/ConvenientSecurityApproval.app"
        extension = app + "/PlugIns/ConvenientSecurityApprovalNotifications.appex"

        def at(fragment, bundle):
            return next(i for i, command in enumerate(commands)
                        if fragment in command and command.endswith(bundle))
        # Xcode signs; the extension and then the app that seals it are
        # re-signed without get-task-allow; only then are both signatures
        # checked and the app installed.
        positions = [
            next(i for i, command in enumerate(commands) if "xcodebuild" in command),
            at("--extract-certificates=", extension), at("codesign --force --sign", extension),
            at("--extract-certificates=", app), at("codesign --force --sign", app),
            at("codesign --display --entitlements - --xml", extension),
            at("codesign --display --entitlements - --xml", app),
            next(i for i, command in enumerate(commands) if "devicectl device install app" in command),
        ]
        self.assertEqual(positions, sorted(positions), only.stdout)
        for bundle in (extension, app):
            resign = commands[at("codesign --force --sign", bundle)]
            self.assertIn("--generate-entitlement-der", resign)
        skipped = self.dry_run("--skip-iphone")
        self.assertEqual(skipped.returncode, 0, skipped.stdout)
        self.assertNotIn("xcodebuild", skipped.stdout)
        self.assertNotIn("devicectl", skipped.stdout)
        for conflicting in ["--skip-iphone", "--skip-sudo", "--refresh-profile"]:
            with self.subTest(conflicting=conflicting):
                refused = self.dry_run("--only-iphone", conflicting)
                self.assertEqual(refused.returncode, 1, refused.stdout)
                self.assertNotIn("+ ", refused.stdout)

    def test_real_entrypoint_uninstall_sudo_plans_the_removal_alone(self):
        plan = self.dry_run("--uninstall-sudo")
        self.assertEqual(plan.returncode, 0, plan.stdout)
        commands = [line for line in plan.stdout.splitlines() if line.startswith("+ ")]
        self.assertEqual(len(commands), 3, plan.stdout)
        self.assertIn("merge-base --is-ancestor origin/main HEAD", commands[0])
        self.assertRegex(commands[1], r"^\+ /usr/bin/sudo \S+/packaging/bin/install-sudo-review\.sh --uninstall$")
        self.assertIn("loads pam_csec_sudo.so", commands[2])
        self.assertIn("Dry run complete; no build", plan.stdout)
        for conflicting in ["--only-iphone", "--skip-iphone", "--skip-sudo", "--refresh-profile",
                            "--allow-downgrade"]:
            with self.subTest(conflicting=conflicting):
                refused = self.dry_run("--uninstall-sudo", conflicting)
                self.assertEqual(refused.returncode, 1, refused.stdout)
                self.assertNotIn("+ ", refused.stdout)
                self.assertIn("--uninstall-sudo removes only the sudo integration", refused.stdout)


def clean_environment(**extra):
    """The caller's environment without an unattended worker's variables, plus extra."""
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith("INSTALL_CHECKPOINT") and key != "CSEC_BUILD_AND_INSTALL_LOCK"}
    environment.update(extra)
    return environment


def write_executable(path, text):
    path.write_text(text)
    path.chmod(0o755)
    return path


class PresenceCheckpointTests(unittest.TestCase):
    """The checkpoint an unattended worker gives the real script: the
    contract's exact argv, called through the real run()."""

    JOB = "0f" * 32
    ATTEMPT = "a1b2c3d4" * 4

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.record = self.root / "record"
        # Records its arguments, whatever it can read from stdin, and whether
        # it inherited the install lock's descriptor.
        self.checkpoint = write_executable(self.root / "install-wait", f'''#!/bin/sh
for argument in "$@"; do printf 'ARG %s\\n' "$argument"; done >>"{self.record}"
printf 'STDIN %s\\n' "$(cat)" >>"{self.record}"
if {{ true >&9; }} 2>/dev/null; then echo 'FD9 open' >>"{self.record}"; fi
exit "${{CHECKPOINT_EXIT:-0}}"
''')

    def tearDown(self):
        self.directory.cleanup()

    def environment(self, **extra):
        worker = {"INSTALL_CHECKPOINT": str(self.checkpoint),
                  "INSTALL_CHECKPOINT_JOB": self.JOB, "INSTALL_CHECKPOINT_ATTEMPT": self.ATTEMPT}
        return clean_environment(**{**worker, **extra})

    def call(self, **extra):
        # Descriptor 9 stands in for the install lock; stdin carries text the
        # checkpoint must not be handed.
        return subprocess.run(
            ["/bin/bash", "-c", '''
source "$1"
exec 9>>"$2"
dry_run=0
configure_presence_checkpoints
trap 'echo "STAGE $stage"' EXIT
stage="app notarization"
presence_checkpoint app-notarization
echo "AFTER $stage"
''', "checkpoint-test", str(INSTALLER), str(self.root / "lock")],
            input="the installer's own stdin\n", env=self.environment(**extra),
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10,
        )

    def test_the_checkpoint_gets_exactly_the_contract_and_nothing_of_ours(self):
        result = self.call()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.record.read_text().splitlines(), [
            "ARG checkpoint", f"ARG {self.JOB}", "ARG --attempt", f"ARG {self.ATTEMPT}",
            "ARG --stage", "ARG app-notarization", "STDIN "])
        self.assertIn("AFTER app notarization", result.stdout)

    def test_a_refusing_checkpoint_ends_the_run_at_that_checkpoint(self):
        result = self.call(CHECKPOINT_EXIT="75")
        self.assertEqual(result.returncode, 75, result.stdout)
        self.assertNotIn("AFTER", result.stdout)
        self.assertIn("STAGE presence checkpoint before app notarization", result.stdout)

    def test_the_variables_are_all_set_or_none(self):
        for missing in ["INSTALL_CHECKPOINT", "INSTALL_CHECKPOINT_JOB", "INSTALL_CHECKPOINT_ATTEMPT"]:
            with self.subTest(missing=missing):
                environment = self.environment()
                del environment[missing]
                result = subprocess.run([str(INSTALLER), "--dry-run"], env=environment, text=True,
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn("set together or not at all", result.stdout)
                self.assertNotIn("+ ", result.stdout)

    def test_a_bad_checkpoint_or_identifier_is_refused_before_anything_runs(self):
        plain = self.root / "not-executable"
        plain.write_text("#!/bin/sh\n")
        for name, value, message in [
            ("INSTALL_CHECKPOINT", "install-wait", "absolute path of an executable"),
            ("INSTALL_CHECKPOINT", str(plain), "absolute path of an executable"),
            ("INSTALL_CHECKPOINT", str(self.root), "absolute path of an executable"),
            ("INSTALL_CHECKPOINT_JOB", "--stage", "letters, digits"),
            ("INSTALL_CHECKPOINT_ATTEMPT", "an attempt", "letters, digits"),
            ("INSTALL_CHECKPOINT_JOB", "j" * 129, "letters, digits"),
        ]:
            with self.subTest(name=name, value=value):
                result = subprocess.run([str(INSTALLER), "--dry-run"], env=self.environment(**{name: value}),
                                        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn(message, result.stdout)
                self.assertNotIn("+ ", result.stdout)

    def test_a_dry_run_plans_each_checkpoint_without_calling_it(self):
        result = subprocess.run([str(INSTALLER), "--dry-run"], env=self.environment(), text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout)
        planned = [line.split(" --stage ")[1] for line in result.stdout.splitlines()
                   if line.startswith(f"+ {self.checkpoint} checkpoint {self.JOB} --attempt {self.ATTEMPT} --stage ")]
        self.assertEqual(planned, [name for name, _, _ in InstallerTests.CHECKPOINTS])
        self.assertFalse(self.record.exists())

    def test_the_marker_a_worker_checks_is_present(self):
        self.assertIn("\n# install-checkpoint-v1\n", INSTALLER.read_text())


class InstallLockTests(unittest.TestCase):
    """One install at a time: a second run, by hand or from a worker, exits 75
    at once with nothing attempted, and a dry run is never held up."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.lock = self.root / "locks" / "build-and-install.lock"
        # A copy outside any Git checkout: if the lock ever let it through,
        # the checkout guard refuses it before any stage could run.
        self.copy = self.root / "checkout/packaging/bin/build-and-install.sh"
        self.copy.parent.mkdir(parents=True)
        self.copy.write_text(INSTALLER.read_text())
        self.copy.chmod(0o755)
        # It reads the build identity before anything else.
        (self.root / "checkout/packaging/lib").mkdir()
        (self.root / "checkout/packaging/lib/identity.sh").write_text(IDENTITY_LIBRARY.read_text())
        (self.root / "checkout/identity.xcconfig").write_text(IDENTITY_FILE.read_text())

    def tearDown(self):
        self.directory.cleanup()

    def install(self, *arguments, **extra):
        return subprocess.run(
            [str(self.copy), *arguments],
            env=clean_environment(CSEC_BUILD_AND_INSTALL_LOCK=str(self.lock), **extra),
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10,
        )

    def hold(self, holder="pid 4242, run by hand, from /elsewhere, since earlier"):
        self.lock.parent.mkdir(parents=True, exist_ok=True)
        handle = self.lock.open("a+")
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        handle.truncate(0)
        handle.write(holder + "\n")
        handle.flush()
        self.addCleanup(handle.close)
        return handle

    def is_free(self):
        with self.lock.open("a") as handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return False
            fcntl.flock(handle, fcntl.LOCK_UN)
            return True

    def test_a_second_install_exits_75_naming_the_first_with_nothing_attempted(self):
        self.hold()
        for arguments in [(), ("--only-iphone",), ("--uninstall-sudo",)]:
            with self.subTest(arguments=arguments):
                result = self.install(*arguments)
                self.assertEqual(result.returncode, 75, result.stdout)
                self.assertIn("another build-and-install.sh is installing "
                              "(pid 4242, run by hand, from /elsewhere, since earlier)", result.stdout)
                self.assertIn("nothing was attempted", result.stdout)
                self.assertNotIn("+ ", result.stdout)
                self.assertNotIn("INSTALLATION FAILED", result.stdout)

    def test_a_dry_run_neither_waits_for_nor_takes_the_lock(self):
        self.hold()
        # The real script: a dry run changes nothing, and needs its stages.
        result = subprocess.run(
            [str(INSTALLER), "--dry-run"], env=clean_environment(CSEC_BUILD_AND_INSTALL_LOCK=str(self.lock)),
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("Dry run complete", result.stdout)

    def test_the_lock_names_its_holder_and_ends_with_the_run(self):
        checkpoint = write_executable(self.root / "install-wait", "#!/bin/sh\n")
        script = '''
source "$1"
presence_checkpoint=""
repo_root=/synthetic/checkout
configure_presence_checkpoints
acquire_install_lock
cat "$build_and_install_lock"
# A child a stage leaves running must not keep later installs out.
dry_run=0
run /bin/sh -c '/bin/sleep 5 </dev/null >/dev/null 2>&1 & exit 0'
'''
        for extra, owner in [({}, "run by hand"),
                             ({"INSTALL_CHECKPOINT": str(checkpoint), "INSTALL_CHECKPOINT_JOB": "job-1",
                               "INSTALL_CHECKPOINT_ATTEMPT": "attempt-1"}, "install job job-1")]:
            with self.subTest(owner=owner):
                result = subprocess.run(
                    ["/bin/bash", "-c", script, "lock-test", str(INSTALLER)],
                    env=clean_environment(CSEC_BUILD_AND_INSTALL_LOCK=str(self.lock), **extra),
                    text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stdout)
                self.assertRegex(result.stdout, rf"pid \d+, {owner}, from /synthetic/checkout, since "
                                                 r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\n")
                self.assertTrue(self.is_free(), "the lock outlived its run")

    def test_the_lock_is_held_while_the_run_is_alive(self):
        process = subprocess.Popen(
            ["/bin/bash", "-c", 'source "$1"; acquire_install_lock; echo held; read -r _',
             "lock-test", str(INSTALLER)],
            env=clean_environment(CSEC_BUILD_AND_INSTALL_LOCK=str(self.lock)),
            text=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        try:
            self.assertEqual(process.stdout.readline(), "held\n")
            self.assertFalse(self.is_free())
            refused = self.install()
            self.assertEqual(refused.returncode, 75, refused.stdout)
        finally:
            process.communicate("\n", timeout=10)
        self.assertTrue(self.is_free())


def run_function(script, *arguments):
    """Sources the installer and runs one of its shell functions."""
    return subprocess.run(
        ["/bin/bash", "-c", 'source "$1"; shift; ' + script, "helper-test", str(INSTALLER),
         *arguments],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
    )


def device(identifier, name, *, platform="iOS", kind="iPhone", reality="physical",
           pairing="paired", tunnel="disconnected"):
    """One devicectl `list devices` entry, shaped like Xcode 26's JSON v3."""
    return {
        "identifier": identifier,
        "connectionProperties": {"pairingState": pairing, "tunnelState": tunnel,
                                 "transportType": "localNetwork"},
        "deviceProperties": {"name": name, "developerModeStatus": "enabled"},
        "hardwareProperties": {"platform": platform, "deviceType": kind,
                               "reality": reality, "udid": f"udid-{identifier}"},
    }


class IPhoneSelectionTests(unittest.TestCase):
    def select(self, devices, wanted=""):
        with tempfile.TemporaryDirectory() as directory:
            listing = Path(directory) / "devices.json"
            listing.write_text(json.dumps(
                {"info": {"outcome": "success"}, "result": {"devices": devices}}))
            return run_function('select_iphone_from_json "$1" "$2"', str(listing), wanted)

    def assert_selected(self, result, identifier, name):
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, f"{identifier}\t{name}\n")

    def assert_refused(self, result, *fragments):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout, "")
        for fragment in fragments + ("--skip-iphone",):
            self.assertIn(fragment, result.stderr)

    def test_the_one_available_paired_iphone_is_chosen(self):
        self.assert_selected(self.select([
            device("watch", "Watch", platform="watchOS", kind="appleWatch", tunnel="unavailable"),
            device("ipad", "iPad", kind="iPad"),
            device("phone", "Phone"),
            device("away", "Away Phone", tunnel="unavailable"),
            device("unpaired", "Unpaired Phone", pairing="unpaired"),
        ]), "phone", "Phone")

    def test_no_available_iphone_is_explained(self):
        self.assert_refused(self.select([device("away", "Away Phone", tunnel="unavailable")]),
                            "no available paired iPhone", "Devices and Simulators")

    def test_two_available_iphones_need_csec_iphone_device(self):
        phones = [device("one", "One"), device("two", "Two", tunnel="connected")]
        self.assert_refused(self.select(phones), "2 available paired iPhones (One, Two)",
                            "CSEC_IPHONE_DEVICE")
        self.assert_selected(self.select(phones, "Two"), "two", "Two")
        self.assert_selected(self.select(phones, "udid-one"), "one", "One")
        self.assert_selected(self.select(phones, "two"), "two", "Two")

    def test_csec_iphone_device_must_name_one_available_paired_iphone(self):
        phones = [device("one", "One"), device("away", "Away", tunnel="unavailable")]
        self.assert_refused(self.select(phones, "Other"), "CSEC_IPHONE_DEVICE=Other", "One")
        self.assert_refused(self.select(phones, "Away"), "Away is not an available paired iPhone")


RECEIPT_WRITER = Path(__file__).resolve().parents[1] / "pkg-scripts/write-install-receipt"


class InstallReceiptTests(unittest.TestCase):
    """The postinstall's receipt of the helper and bridge bytes, and the installer's check of it.

    A persistence watch reads it: the exact object below, root-owned, not
    group/world-writable, at most 1 MiB.
    """

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        root = Path(self.directory.name).resolve()
        self.receipt_directory = root / "Application Support" / "ConvenientSecurity"
        self.receipt_directory.mkdir(parents=True)
        self.receipt = self.receipt_directory / "install-receipt.json"
        self.helper = root / "PrivilegedHelperTools" / "com.example.rootd"
        self.helper.parent.mkdir()
        self.helper.write_bytes(b"first helper build")
        self.bridge = root / "bridge" / "bin" / "csec"
        self.bridge.parent.mkdir(parents=True)
        self.bridge.write_bytes(b"first bridge build")
        self.built = root / "csec-rootd"
        self.built_bridge = root / "csec"

    def tearDown(self):
        self.directory.cleanup()

    def write(self, receipt=None, artifacts=None):
        return subprocess.run(
            [str(RECEIPT_WRITER), str(receipt or self.receipt),
             *map(str, artifacts or [self.helper, self.bridge])],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
        )

    def expected(self, helper, bridge=b"first bridge build"):
        return {"schema": 1, "producer": "csec",
                "artifacts": {str(self.helper): hashlib.sha256(helper).hexdigest(),
                              str(self.bridge): hashlib.sha256(bridge).hexdigest()}}

    def check(self, built_bytes, owner=None, bridge_bytes=b"first bridge build"):
        self.built.write_bytes(built_bytes)
        self.built_bridge.write_bytes(bridge_bytes)
        return run_function('check_install_receipt "$@"', str(self.receipt),
                            str(os.getuid() if owner is None else owner),
                            str(self.built), str(self.helper), str(self.built_bridge), str(self.bridge))

    def test_records_the_installed_bytes_world_readable_and_alone(self):
        result = self.write()
        self.assertEqual(result.returncode, 0, result.stderr)
        recorded = json.loads(self.receipt.read_bytes())
        self.assertEqual(recorded, self.expected(b"first helper build"))
        self.assertEqual(list(recorded["artifacts"]), [str(self.helper), str(self.bridge)])
        self.assertIs(type(recorded["schema"]), int)
        info = self.receipt.lstat()
        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o644)
        self.assertEqual(info.st_uid, os.getuid())
        self.assertEqual(sorted(path.name for path in self.receipt_directory.iterdir()),
                         ["install-receipt.json"])

    def test_an_upgrade_replaces_the_receipt_by_rename(self):
        self.assertEqual(self.write().returncode, 0)
        before = self.receipt.stat().st_ino
        self.helper.write_bytes(b"second helper build")
        self.bridge.write_bytes(b"second bridge build")
        result = self.write()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.receipt.read_bytes()),
                         self.expected(b"second helper build", b"second bridge build"))
        self.assertNotEqual(self.receipt.stat().st_ino, before)
        self.assertEqual(stat.S_IMODE(self.receipt.stat().st_mode), 0o644)
        self.assertEqual([path.name for path in self.receipt_directory.iterdir()], ["install-receipt.json"])

    def test_unsafe_paths_are_refused_and_leave_the_old_receipt(self):
        self.assertEqual(self.write().returncode, 0)
        old = self.receipt.read_bytes()
        linked_helper = self.helper.with_name("linked-rootd")
        linked_helper.symlink_to(self.helper)
        linked_directory = self.receipt_directory.with_name("Linked")
        linked_directory.symlink_to(self.receipt_directory)
        quoted_helper = self.helper.with_name('quoted"rootd')
        quoted_helper.write_bytes(b"x")
        # A bad artifact anywhere in the list, before or after a good one,
        # refuses the whole receipt; so does naming one artifact twice.
        for receipt, artifacts in [
            (self.receipt, [linked_helper, self.bridge]),
            (linked_directory / "install-receipt.json", [self.helper, self.bridge]),
            (self.receipt, [quoted_helper, self.bridge]),
            (self.receipt, [self.helper, Path("relative/csec")]),
            (self.receipt, [self.helper.parent, self.bridge]),
            (self.receipt, [self.helper, self.bridge.with_name("missing")]),
            (self.receipt, [self.helper, self.bridge, self.helper]),
        ]:
            with self.subTest(receipt=receipt, artifacts=artifacts):
                result = self.write(receipt, artifacts)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("write-install-receipt:", result.stderr)
                self.assertEqual(self.receipt.read_bytes(), old)
                self.assertEqual([path.name for path in self.receipt_directory.iterdir()],
                                 ["install-receipt.json"])

    def test_a_symlinked_receipt_is_refused(self):
        target = self.receipt_directory / "elsewhere.json"
        target.write_text("{}")
        self.receipt.symlink_to(target)
        result = self.write()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("existing receipt has an unsafe path shape", result.stderr)
        self.assertEqual(target.read_text(), "{}")

    def test_the_installer_accepts_the_receipt_for_the_built_helper_and_bridge(self):
        self.assertEqual(self.write().returncode, 0)
        result = self.check(b"first helper build")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_the_installer_refuses_a_stale_missing_or_unprotected_receipt(self):
        result = self.check(b"first helper build")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is unreadable", result.stderr)

        self.assertEqual(self.write().returncode, 0)
        result = self.check(b"a newer build the package did not install")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("does not record exactly the built sha256", result.stderr)

        result = self.check(b"first helper build", bridge_bytes=b"a newer bridge the package did not install")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("does not record exactly the built sha256", result.stderr)

        # A receipt from before the bridge was recorded names the helper alone.
        self.assertEqual(self.write(artifacts=[self.helper]).returncode, 0)
        result = self.check(b"first helper build")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("does not record exactly the built sha256", result.stderr)
        self.assertEqual(self.write().returncode, 0)

        result = self.check(b"first helper build", owner=os.getuid() + 1)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("writable only by it", result.stderr)

        self.receipt.chmod(0o664)
        result = self.check(b"first helper build")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("writable only by it", result.stderr)

        self.receipt.chmod(0o644)
        for changed in [{"producer": "other"}, {"schema": True}, {"schema": 1.0}, {"extra": 1}]:
            with self.subTest(changed=changed):
                self.receipt.write_text(json.dumps({**self.expected(b"first helper build"), **changed}))
                result = self.check(b"first helper build")
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("does not record exactly", result.stderr)

        self.receipt.write_text(json.dumps(self.expected(b"first helper build")) + " " * 1024 * 1024)
        result = self.check(b"first helper build")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("is larger than 1 MiB", result.stderr)

        moved = self.receipt.with_name("moved.json")
        self.receipt.rename(moved)
        self.receipt.symlink_to(moved)
        result = self.check(b"first helper build")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is unreadable", result.stderr)


class InstalledVersionTests(unittest.TestCase):
    def versions(self, apps):
        with tempfile.TemporaryDirectory() as directory:
            listing = Path(directory) / "apps.json"
            listing.write_text(json.dumps({"result": {"apps": apps}}))
            return run_function('installed_iphone_app_versions "$1" "$2"', str(listing),
                                f"{IDENTIFIER}.approval")

    def test_reports_the_installed_build_and_version(self):
        result = self.versions([{
            "bundleIdentifier": f"{IDENTIFIER}.approval",
            "bundleVersion": "1.1790000000", "version": "0.1.0", "name": "Convenient Security",
        }])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "1.1790000000\t0.1.0\n")

    def test_a_missing_app_is_an_error(self):
        result = self.versions([{"bundleIdentifier": "com.example.other", "bundleVersion": "1"}])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("0 installed apps", result.stderr)


class DebuggerEntitlementTests(unittest.TestCase):
    """The installed iPhone app must not carry get-task-allow."""

    def check(self, entitlements):
        with tempfile.TemporaryDirectory() as directory:
            signed = Path(directory) / "signed.plist"
            signed.write_bytes(plistlib.dumps(entitlements))
            return run_function('check_no_debugger_entitlement "$1" "$2"', str(signed), "signed app")

    def test_no_get_task_allow_passes(self):
        for entitlements in [{}, {"get-task-allow": False},
                             {"application-identifier": "TEAM.com.example.app"}]:
            with self.subTest(entitlements=entitlements):
                result = self.check(entitlements)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_get_task_allow_fails(self):
        for key in ["get-task-allow", "com.apple.security.get-task-allow"]:
            for value in [True, "YES", 1]:
                with self.subTest(key=key, value=value):
                    result = self.check({key: value})
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertIn(f"signed app: {key} is signed in", result.stderr)

    def test_unreadable_entitlements_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            broken = Path(directory) / "signed.plist"
            broken.write_text("not a plist")
            result = run_function('check_no_debugger_entitlement "$1" "$2"', str(broken), "signed app")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("no readable signed entitlements", result.stderr)

    def test_removal_keeps_every_other_entitlement(self):
        kept = {
            "application-identifier": "TEAM.com.example.app",
            "com.apple.developer.team-identifier": "TEAM",
            "aps-environment": "development",
            "com.apple.developer.icloud-container-environment": "Production",
            "com.apple.developer.icloud-container-identifiers": [CONTAINER],
            "com.apple.developer.icloud-services": ["CloudKit"],
        }
        with tempfile.TemporaryDirectory() as directory:
            signed = Path(directory) / "signed.plist"
            signed.write_bytes(plistlib.dumps(
                {**kept, "get-task-allow": True, "com.apple.security.get-task-allow": True}))
            result = run_function('remove_debugger_entitlements "$1"', str(signed))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(plistlib.loads(signed.read_bytes()), kept)

    def verify_build(self, entitlements, extension_entitlements=None,
                     extension_version="1.42", with_extension=True):
        """Runs the real verify_iphone_build against a built app whose signed
        entitlements are `entitlements`, holding a notification extension
        signed with `extension_entitlements` (the app's when omitted); only the
        codesign read is replaced."""
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory) / "ConvenientSecurityApproval.app"
            app.mkdir()
            (app / "Info.plist").write_bytes(plistlib.dumps({"CFBundleVersion": "1.42"}))
            extension = app / "PlugIns" / "ConvenientSecurityApprovalNotifications.appex"
            if with_extension:
                extension.mkdir(parents=True)
                (extension / "Info.plist").write_bytes(
                    plistlib.dumps({"CFBundleVersion": extension_version}))
            fixture = Path(directory) / "entitlements.plist"
            fixture.write_bytes(plistlib.dumps(entitlements))
            extension_fixture = Path(directory) / "extension-entitlements.plist"
            extension_fixture.write_bytes(plistlib.dumps(
                entitlements if extension_entitlements is None else extension_entitlements))
            return run_function(
                'dry_run=0; ios_app="$1"; ios_extension="$1/PlugIns/ConvenientSecurityApprovalNotifications.appex"; '
                'iphone_build_number=1.42; '
                'read_signed_entitlements() { case "$1" in *.appex) /bin/cp "$EXTENSION_FIXTURE" "$2" ;; '
                '*) /bin/cp "$FIXTURE" "$2" ;; esac; }; '
                'FIXTURE="$2" EXTENSION_FIXTURE="$3" verify_iphone_build',
                str(app), str(fixture), str(extension_fixture))

    def cloudkit_entitlements(self, **extra):
        return {
            "com.apple.developer.icloud-container-identifiers": [CONTAINER],
            "com.apple.developer.icloud-services": ["CloudKit"],
            "com.apple.developer.icloud-container-environment": "Production",
            **extra,
        }

    def test_verify_iphone_build_fails_on_a_debuggable_app(self):
        result = self.verify_build(self.cloudkit_entitlements(**{"get-task-allow": True}),
                                   extension_entitlements=self.cloudkit_entitlements())
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("iPhone app: get-task-allow is signed in", result.stderr)
        self.assertIn("must not be debuggable", result.stderr)
        self.assertNotIn("verified iPhone app signature", result.stdout)

    def test_verify_iphone_build_passes_a_release_signed_app(self):
        result = self.verify_build(self.cloudkit_entitlements())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("no get-task-allow", result.stdout)

    def test_verify_iphone_build_checks_the_notification_extension(self):
        good = self.cloudkit_entitlements()
        passed = self.verify_build(good)
        self.assertEqual(passed.returncode, 0, passed.stderr)
        self.assertIn("verified iPhone notification extension signature", passed.stdout)
        debuggable = self.verify_build(good, self.cloudkit_entitlements(**{"get-task-allow": True}))
        self.assertNotEqual(debuggable.returncode, 0, debuggable.stdout)
        self.assertIn("iPhone notification extension: get-task-allow is signed in", debuggable.stderr)
        no_cloudkit = self.verify_build(good, {"application-identifier": "TEAM.com.example.ext"})
        self.assertNotEqual(no_cloudkit.returncode, 0, no_cloudkit.stdout)
        self.assertIn("iPhone notification extension is not signed for CloudKit container", no_cloudkit.stderr)
        stale = self.verify_build(good, extension_version="1.41")
        self.assertNotEqual(stale.returncode, 0, stale.stdout)
        self.assertIn("notification extension has build 1.41, not 1.42", stale.stderr)
        missing = self.verify_build(good, with_extension=False)
        self.assertNotEqual(missing.returncode, 0, missing.stdout)
        self.assertIn("has no notification extension", missing.stderr)

    def test_verify_iphone_build_still_requires_cloudkit(self):
        result = self.verify_build({"application-identifier": "TEAM.com.example.app"},
                                   extension_entitlements=self.cloudkit_entitlements())
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("is not signed for CloudKit container", result.stderr)


class CloudKitSignatureTests(unittest.TestCase):
    def check(self, entitlements, environment="Production"):
        with tempfile.TemporaryDirectory() as directory:
            signed = Path(directory) / "signed.plist"
            signed.write_bytes(plistlib.dumps(entitlements))
            return run_function('check_cloudkit_entitlements "$1" "$2" "$3" "$4"',
                                str(signed), CONTAINER, environment, "signed code")

    def entitlements(self, **overrides):
        signed = {
            "com.apple.developer.icloud-container-identifiers": [CONTAINER],
            "com.apple.developer.icloud-services": ["CloudKit"],
            "com.apple.developer.icloud-container-environment": "Production",
        }
        signed.update(overrides)
        return {key: value for key, value in signed.items() if value is not None}

    def test_production_container_passes(self):
        result = self.check(self.entitlements())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_each_missing_piece_is_named(self):
        for key, value, message in [
            ("com.apple.developer.icloud-container-environment", "Development",
             "is Development, not Production"),
            ("com.apple.developer.icloud-container-environment", None, "is absent, not Production"),
            ("com.apple.developer.icloud-container-identifiers", ["iCloud.com.example"],
             f"does not name {CONTAINER}"),
            ("com.apple.developer.icloud-services", ["CloudDocuments"], "does not name CloudKit"),
        ]:
            with self.subTest(key=key, value=value):
                result = self.check(self.entitlements(**{key: value}))
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn(f"signed code: {key} {message}", result.stderr)

    def test_the_container_is_the_build_identitys(self):
        result = run_function("cloudkit_container")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, CONTAINER + "\n")

    def test_the_ios_build_number_base_is_one_integer(self):
        result = run_function("ios_base_build_number")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, r"^[0-9]+\n$")



class CheckoutGuardTests(unittest.TestCase):
    """build-and-install installs what the checkout holds, so it refuses a
    checkout that lacks a commit already on origin/main: installing it would
    replace a newer csec with an older one."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        root = Path(self.directory.name)
        self.origin = root / "origin.git"
        self.checkout = root / "checkout"
        self.git(root, "init", "--quiet", "--bare", "--initial-branch=main", str(self.origin))
        self.git(root, "clone", "--quiet", str(self.origin), str(self.checkout))
        self.commit("first")
        self.git(self.checkout, "push", "--quiet", "origin", "HEAD:main")

    def tearDown(self):
        self.directory.cleanup()

    def git(self, directory, *arguments):
        subprocess.run(
            ["git", "-C", str(directory), "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
             "-c", "commit.gpgsign=false", *arguments],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10,
        )

    def commit(self, subject):
        self.git(self.checkout, "commit", "--quiet", "--allow-empty", "-m", subject)

    def push_from_elsewhere(self, subject):
        """A commit pushed to origin/main from another worktree, which moves
        this checkout's origin/main but not its HEAD."""
        self.git(self.checkout, "worktree", "add", "--quiet", "--detach", "../elsewhere", "origin/main")
        elsewhere = self.checkout.parent / "elsewhere"
        self.git(elsewhere, "commit", "--quiet", "--allow-empty", "-m", subject)
        self.git(elsewhere, "push", "--quiet", "origin", "HEAD:main")

    def guard(self, dry_run=0):
        return run_function(
            'repo_root="$1"; dry_run="$2"; require_checkout_contains_main',
            str(self.checkout), str(dry_run),
        )

    def test_a_checkout_at_origin_main_passes(self):
        result = self.guard()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_branch_ahead_of_origin_main_passes(self):
        self.commit("unpushed work")
        result = self.guard()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_checkout_behind_origin_main_is_refused_and_names_what_it_lacks(self):
        self.push_from_elsewhere("Let auto mode sign the ssh that timeout runs")
        result = self.guard()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("lacks 1 commit already on origin/main", result.stderr)
        self.assertIn("Let auto mode sign the ssh that timeout runs", result.stderr)
        self.assertIn("git pull --ff-only", result.stderr)

    def test_a_branch_that_diverged_from_origin_main_is_refused(self):
        self.push_from_elsewhere("pushed elsewhere")
        self.commit("local only")
        result = self.guard()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("lacks 1 commit already on origin/main", result.stderr)

    def test_a_checkout_with_no_origin_main_is_refused(self):
        self.git(self.checkout, "update-ref", "-d", "refs/remotes/origin/main")
        result = self.guard()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("no origin/main", result.stderr)

    def test_a_dry_run_prints_the_check_and_refuses_nothing(self):
        self.push_from_elsewhere("pushed elsewhere")
        result = self.guard(dry_run=1)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("merge-base --is-ancestor origin/main HEAD", result.stdout)

    def test_every_install_path_runs_the_check_before_anything_else(self):
        for arguments in (["--refresh-profile"], ["--only-iphone"]):
            with self.subTest(arguments=arguments):
                result = subprocess.run(
                    [str(INSTALLER), "--dry-run", *arguments],
                    text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stdout)
                commands = [line for line in result.stdout.splitlines() if line.startswith("+ ")]
                self.assertIn("merge-base --is-ancestor origin/main HEAD", commands[0], result.stdout)


class InstalledCommitGuardTests(unittest.TestCase):
    """The installed app names the commit it was built from, and
    build-and-install refuses missing changes, while accepting equivalent
    rewritten history without a deliberate rollback (--allow-downgrade)."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        root = Path(self.directory.name)
        self.checkout = root / "checkout"
        self.info = root / "Info.plist"
        self.git(root, "init", "--quiet", "--initial-branch=main", str(self.checkout))
        self.first = self.commit("first")

    def tearDown(self):
        self.directory.cleanup()

    def git(self, directory, *arguments):
        return subprocess.run(
            ["git", "-C", str(directory), "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
             "-c", "commit.gpgsign=false", *arguments],
            check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10,
        ).stdout.strip()

    def commit(self, subject):
        self.git(self.checkout, "commit", "--quiet", "--allow-empty", "-m", subject)
        return self.git(self.checkout, "rev-parse", "HEAD")

    def change(self, path, content, subject):
        (self.checkout / path).write_text(content)
        self.git(self.checkout, "add", path)
        return self.commit(subject)

    def install(self, commit):
        """An installed Info.plist, stamped the way build-agent.sh stamps it."""
        plist = {"CFBundleIdentifier": IDENTIFIER}
        if commit is not None:
            plist["CSECSourceCommit"] = commit
        with open(self.info, "wb") as handle:
            plistlib.dump(plist, handle)

    def guard(self, dry_run=0, allow_downgrade=0):
        return run_function(
            'repo_root="$1"; installed_info="$2"; dry_run="$3"; allow_downgrade="$4"; '
            'require_checkout_contains_installed',
            str(self.checkout), str(self.info), str(dry_run), str(allow_downgrade),
        )

    def test_the_installed_commit_itself_passes(self):
        self.install(self.first)
        result = self.guard()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_checkout_ahead_of_the_installed_commit_passes(self):
        self.install(self.first)
        self.commit("newer work")
        result = self.guard()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_checkout_behind_the_installed_commit_is_refused_and_names_what_it_lacks(self):
        installed = self.commit("Keep saved items an older csecd cannot read")
        self.install(installed)
        self.git(self.checkout, "checkout", "--quiet", "--detach", self.first)
        result = self.guard()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("lacks 1 commit the installed csec", result.stderr)
        self.assertIn("Keep saved items an older csecd cannot read", result.stderr)
        self.assertIn("--allow-downgrade", result.stderr)

    def test_a_diverged_branch_is_refused(self):
        installed = self.change("shipped", "installed change\n", "installed from a worktree")
        self.install(installed)
        self.git(self.checkout, "checkout", "--quiet", "-b", "other", self.first)
        self.change("other", "different change\n", "other work")
        result = self.guard()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("lacks 1 commit", result.stderr)

    def test_a_flattened_merge_with_later_work_passes(self):
        self.git(self.checkout, "checkout", "--quiet", "-b", "feature")
        self.change("shipped", "installed change\n", "shipped feature")
        self.git(self.checkout, "checkout", "--quiet", "main")
        self.git(self.checkout, "merge", "--quiet", "--no-ff", "-m", "installed merge", "feature")
        installed = self.git(self.checkout, "rev-parse", "HEAD")
        self.install(installed)
        # Normal rebase drops the merge, even when its full result is retained.
        self.git(self.checkout, "rebase", "--force-rebase", self.first)
        self.assertNotIn(installed, self.git(self.checkout, "rev-list", "HEAD").splitlines())
        self.assertEqual(self.git(self.checkout, "rev-list", "--merges", "HEAD"), "")
        self.change("later", "newer work\n", "work after flattening")
        result = self.guard()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("equivalent", result.stderr)
        self.assertNotIn("Installing anyway", result.stderr)

    def test_a_rebased_patch_series_with_later_work_passes(self):
        self.git(self.checkout, "checkout", "--quiet", "-b", "shipped")
        self.change("one", "first shipped change\n", "shipped one")
        installed = self.change("two", "second shipped change\n", "shipped two")
        self.install(installed)
        self.git(self.checkout, "checkout", "--quiet", "main")
        self.change("upstream", "unrelated upstream work\n", "upstream work")
        self.git(self.checkout, "checkout", "--quiet", "shipped")
        self.git(self.checkout, "rebase", "main")
        self.assertNotIn(installed, self.git(self.checkout, "rev-list", "HEAD").splitlines())
        self.change("later", "newer work\n", "work after rebase")
        result = self.guard()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("equivalent", result.stderr)

    def test_a_copied_patch_does_not_hide_another_missing_patch(self):
        self.change("missing", "missing installed change\n", "missing shipped change")
        installed = self.change("copied", "copied installed change\n", "copied shipped change")
        self.install(installed)
        self.git(self.checkout, "checkout", "--quiet", "-b", "other", self.first)
        self.git(self.checkout, "cherry-pick", installed)
        result = self.guard()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("missing shipped change", result.stderr)

    def test_an_equivalent_patch_does_not_hide_a_later_missing_patch(self):
        copied = self.change("copied", "copied installed change\n", "copied shipped change")
        installed = self.change("missing", "missing installed change\n", "missing shipped change")
        self.install(installed)
        self.git(self.checkout, "checkout", "--quiet", "-b", "other", self.first)
        self.git(self.checkout, "cherry-pick", copied)
        result = self.guard()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("missing shipped change", result.stderr)

    def test_a_flattened_merge_amendment_with_its_full_tree_retained_passes(self):
        self.git(self.checkout, "checkout", "--quiet", "-b", "feature")
        feature = self.change("feature", "feature change\n", "shipped feature")
        self.git(self.checkout, "checkout", "--quiet", "main")
        main = self.change("main", "main change\n", "main work")
        self.git(self.checkout, "merge", "--quiet", "--no-ff", "--no-commit", "feature")
        installed = self.change("merge-only", "merge resolution\n", "installed merge resolution")
        self.install(installed)
        self.git(self.checkout, "reset", "--hard", main)
        self.git(self.checkout, "cherry-pick", feature)
        self.change("merge-only", "merge resolution\n", "retain merge resolution")
        self.change("later", "newer work\n", "later work")
        result = self.guard()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("equivalent", result.stderr)

    def test_merge_only_changes_are_required_even_with_equivalent_parent_patches(self):
        self.git(self.checkout, "checkout", "--quiet", "-b", "feature")
        feature = self.change("feature", "feature change\n", "shipped feature")
        self.git(self.checkout, "checkout", "--quiet", "main")
        main = self.change("main", "main change\n", "main work")
        self.git(self.checkout, "merge", "--quiet", "--no-ff", "--no-commit", "feature")
        installed = self.change("merge-only", "merge resolution\n", "installed merge resolution")
        self.install(installed)
        # All non-merge patches are present, but the merge's amendment is lost.
        self.git(self.checkout, "reset", "--hard", main)
        self.git(self.checkout, "cherry-pick", feature)
        self.assertFalse((self.checkout / "merge-only").exists())
        result = self.guard()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("installed merge resolution", result.stderr)

    def test_a_matching_tip_does_not_hide_an_unmatched_earlier_merge_tree(self):
        self.git(self.checkout, "checkout", "--quiet", "-b", "feature")
        feature = self.change("feature", "feature change\n", "shipped feature")
        self.git(self.checkout, "checkout", "--quiet", "-b", "second", self.first)
        second = self.change("second", "second change\n", "second feature")
        self.git(self.checkout, "checkout", "--quiet", "main")
        main = self.change("main", "main change\n", "main work")
        self.git(self.checkout, "merge", "--quiet", "--no-ff", "--no-commit", "feature")
        self.change("merge-only", "intermediate merge amendment\n", "first merge amendment")
        self.git(self.checkout, "merge", "--quiet", "--no-ff", "--no-commit", "second")
        self.git(self.checkout, "rm", "merge-only")
        installed = self.commit("second merge amendment")
        self.install(installed)
        self.git(self.checkout, "reset", "--hard", main)
        self.git(self.checkout, "cherry-pick", feature, second)
        self.assertEqual(self.git(self.checkout, "rev-parse", "HEAD^{tree}"),
                         self.git(self.checkout, "rev-parse", f"{installed}^{{tree}}"))
        result = self.guard()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("first merge amendment", result.stderr)

    def test_matching_trees_do_not_hide_a_missing_non_merge_commit(self):
        self.change("temporary", "shipped briefly\n", "installed addition")
        self.git(self.checkout, "rm", "temporary")
        installed = self.commit("installed removal")
        self.install(installed)
        self.git(self.checkout, "checkout", "--quiet", "--detach", self.first)
        self.assertEqual(self.git(self.checkout, "rev-parse", "HEAD^{tree}"),
                         self.git(self.checkout, "rev-parse", f"{installed}^{{tree}}"))
        result = self.guard()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("lacks 2 commits", result.stderr)

    def test_an_installed_commit_this_checkout_does_not_have_is_refused(self):
        self.install("0123456789abcdef0123456789abcdef01234567")
        result = self.guard()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("a commit this checkout does not have", result.stderr)

    def test_allow_downgrade_installs_and_says_so(self):
        installed = self.commit("newer")
        self.install(installed)
        self.git(self.checkout, "checkout", "--quiet", "--detach", self.first)
        result = self.guard(allow_downgrade=1)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--allow-downgrade", result.stderr)

    def test_an_app_without_the_stamp_or_no_app_is_not_compared(self):
        self.install(None)
        result = self.guard()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("predates the commit stamp", result.stderr)
        self.info.unlink()
        result = self.guard()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_stamp_that_is_not_a_commit_id_is_refused(self):
        self.install("HEAD~3")
        result = self.guard()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("not a commit id", result.stderr)

    def test_a_dry_run_prints_the_check_and_refuses_nothing(self):
        self.install("0123456789abcdef0123456789abcdef01234567")
        result = self.guard(dry_run=1)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("merge-base --is-ancestor INSTALLED_CSECSourceCommit HEAD", result.stdout)

    def test_every_install_path_runs_the_check_right_after_the_origin_main_check(self):
        for arguments in (["--refresh-profile"], ["--only-iphone"], ["--allow-downgrade"]):
            with self.subTest(arguments=arguments):
                result = subprocess.run(
                    [str(INSTALLER), "--dry-run", *arguments],
                    text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stdout)
                commands = [line for line in result.stdout.splitlines() if line.startswith("+ ")]
                self.assertIn("merge-base --is-ancestor origin/main HEAD", commands[0], result.stdout)
                self.assertIn("merge-base --is-ancestor INSTALLED_CSECSourceCommit HEAD", commands[1],
                              result.stdout)

    def test_the_agent_build_stamps_the_commit_into_the_bundle(self):
        build_agent = (INSTALLER.parent / "build-agent.sh").read_text()
        self.assertIn('plutil -insert CSECSourceCommit -string "$source_commit" "$app/Contents/Info.plist"',
                      build_agent)
        self.assertLess(build_agent.index("plutil -insert CSECSourceCommit"),
                        build_agent.index("--- signing inside-out"))


if __name__ == "__main__":
    unittest.main()
