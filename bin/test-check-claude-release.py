#!/usr/bin/env python3
"""Synthetic contract tests for the watchdog's quiet/trip/unknown behavior."""

import importlib.util
import io
import json
from pathlib import Path
import re
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("check_claude_release", Path(__file__).with_name("check-claude-release.py"))
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def image(cdhash="a" * 40, checked=None, path="/synthetic/claude", label="forged-new-version"):
    return dict(cdHash=cdhash, path=path, versionLabel=label, checkedVersion=checked, running=False)


def report(*images, unreadable=()):
    return dict(schemaVersion=1, builds=list(images), unreadablePaths=list(unreadable), checkedReleases=["2.1.280"])


class ReleaseCheckTests(unittest.TestCase):
    def run_check(self, inventory, upstream=b"2.1.280"):
        completed = subprocess.CompletedProcess([], 0, stdout=json.dumps(inventory).encode())
        with patch.object(check.subprocess, "run", return_value=completed) as run:
            with patch.object(check.urllib.request, "urlopen", return_value=io.BytesIO(upstream)):
                result = check.check()
        return result, run.call_args.args[0]

    def test_installed_launcher_contract_and_real_check_envelope(self):
        installer = (Path(__file__).resolve().parents[1] / "packaging/bin/build-and-install.sh").read_text()
        installed = re.search(r'^installed_csec="([^"]+)"$', installer, re.MULTILINE).group(1)
        app = re.search(r'^installed_app="([^"]+)"$', installer, re.MULTILINE).group(1)
        installed = installed.replace("$installed_app", app)
        result, command = self.run_check(report(image(checked="2.1.280")))
        self.assertEqual(command, [installed, "status", "--claude-builds-json"])
        self.assertEqual(result, {"status": "clear"})

    def test_check_envelope_passes_a_real_unknown_identity_to_the_runner(self):
        result, _ = self.run_check(report(image()), b"2.1.302")
        self.assertEqual(result["status"], "trip")
        self.assertEqual(result["payload"]["uncheckedImages"][0]["cdHash"], "a" * 40)
        self.assertEqual(result["payload"]["upstreamRelease"], "2.1.302")

    def test_failed_cli_never_clears_or_copies_its_output(self):
        with patch.object(check.subprocess, "run", side_effect=subprocess.CalledProcessError(
                1, ["csec", "status"], output=b"synthetic-private-output")):
            result = check.check()
        self.assertEqual(result["status"], "error")
        self.assertNotIn("synthetic-private-output", json.dumps(result))

    def test_checked_images_are_quiet(self):
        self.assertEqual(check.evaluate(report(image(checked="checked-release"))), {"status": "clear"})

    def test_update_trips_until_shipped_catalog_recovers(self):
        current = report(image(checked="old-release"), image("b" * 40, path="/synthetic/new"))
        self.assertEqual(check.evaluate(current)["status"], "trip")
        current["builds"][1]["checkedVersion"] = "new-release"
        self.assertEqual(check.evaluate(current), {"status": "clear"})

    def test_labels_do_not_check_a_build(self):
        self.assertEqual(check.evaluate(report(image(label="2.1.280")))["status"], "trip")
        self.assertEqual(check.evaluate(report(image(cdhash=None)))["status"], "trip")

    def test_legacy_script_paths_remain_separate_until_each_install_is_removed(self):
        first = image(cdhash=None, path="/synthetic/mise/0/bin/claude", label="0")
        second = image(cdhash=None, path="/synthetic/mise/1.0.41/bin/claude", label="1.0.41")
        native = image(checked="2.1.280")
        result = check.evaluate(report(native, first, second))
        self.assertEqual(result["payload"]["uncheckedImages"], [
            dict(cdHash=None, path=first["path"], versionLabel="0"),
            dict(cdHash=None, path=second["path"], versionLabel="1.0.41"),
        ])
        remaining = check.evaluate(report(native, second))
        self.assertEqual(remaining["status"], "trip")
        self.assertEqual(remaining["payload"]["uncheckedImages"][0]["path"], second["path"])
        self.assertEqual(check.evaluate(report(native)), {"status": "clear"})

    def test_a_script_cannot_claim_compatibility_without_a_code_identity(self):
        with self.assertRaises(ValueError):
            check.evaluate(report(image(cdhash=None, checked="2.1.280", label="2.1.280")))

    def test_copy_is_one_audit_and_running_does_not_retrigger(self):
        first = image(path="/synthetic/a")
        second = image(path="/synthetic/b")
        second["running"] = True
        self.assertEqual(check.evaluate(report(first, second)), check.evaluate(report(first)))

    def test_unknown_never_clears(self):
        for value in [None, {}, dict(schemaVersion=2), report(unreadable=["/synthetic/unreadable"]),
                      report(image(cdhash="bad")), report(image(checked="")), report(image(path="relative"))]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                check.evaluate(value)

    def test_partial_inventory_still_trips_known_unknown_image(self):
        self.assertEqual(check.evaluate(report(image(), unreadable=["/synthetic/unreadable"]))["status"], "trip")

    def test_many_images_stay_bounded(self):
        result = check.evaluate(report(*(image(f"{i:040x}", path=f"/synthetic/{i}") for i in range(64))))
        self.assertEqual(len(result["payload"]["uncheckedImages"]), 8)
        self.assertEqual(result["payload"]["additionalImages"], 56)

    def test_upstream_schedules_before_install_and_clears_after_catalog_ships(self):
        current = report(image(checked="2.1.280"))
        result = check.evaluate(current, "2.1.302")
        self.assertEqual(result["payload"]["upstreamRelease"], "2.1.302")
        current["checkedReleases"].append("2.1.302")
        self.assertEqual(check.evaluate(current, "2.1.302"), {"status": "clear"})
        current["builds"].append(image("b" * 40, label="2.1.302"))
        self.assertEqual(check.evaluate(current, "2.1.302")["status"], "trip")


if __name__ == "__main__":
    unittest.main()
