#!/usr/bin/env python3
"""The product archive's distribution refuses a Mac csec cannot run on.

The definition is checked as build-pkg.sh fills it in (from the app's own
Info.plist), and its installation check is run under JavaScript for Automation
with the Installer's `system` and `my` objects stood in, so the refusal a
buyer would see on an Intel Mac or an older macOS is exercised, not just read.
"""

import json
import plistlib
import re
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ElementTree
from pathlib import Path

from csec_identity import IDENTIFIER

PACKAGING = Path(__file__).resolve().parents[1]
TEMPLATE = PACKAGING / "installer/Distribution.xml"
BUILD_PKG = PACKAGING / "bin/build-pkg.sh"
INFO_PLIST = PACKAGING / "agent/Info.plist"

# The Installer JavaScript API calls the check names; enough of it to run it.
JXA_HARNESS = r"""
function run(argv) {
  var scenario = JSON.parse(argv[0]);
  var my = { result: {} };
  var system = {
    sysctl: function (name) { return scenario.sysctl[name]; },
    version: { ProductVersion: scenario.productVersion },
    compareVersions: function (left, right) {
      var a = left.split('.').map(Number), b = right.split('.').map(Number);
      for (var i = 0; i < Math.max(a.length, b.length); i++) {
        var x = a[i] || 0, y = b[i] || 0;
        if (x !== y) { return x < y ? -1 : 1; }
      }
      return 0;
    }
  };
  // JXA's eval is global, so the check runs as a function of the two objects.
  var check = new Function('my', 'system', scenario.script + '\nreturn ' + scenario.call + ';');
  var passed = check(my, system);
  return JSON.stringify({ passed: passed, result: my.result });
}
"""


def filled_distribution():
    with INFO_PLIST.open("rb") as handle:
        info = plistlib.load(handle)
    text = TEMPLATE.read_text()
    return (
        text.replace("@VERSION@", info["CFBundleShortVersionString"])
        .replace("@MINIMUM_MACOS@", info["LSMinimumSystemVersion"])
        .replace("@CSEC_IDENTIFIER@", IDENTIFIER),
        info,
    )


class DistributionTests(unittest.TestCase):
    def setUp(self):
        self.text, self.info = filled_distribution()
        self.root = ElementTree.fromstring(self.text)

    def test_every_placeholder_is_one_build_pkg_fills(self):
        placeholders = set(re.findall(r"@[A-Z_]+@", TEMPLATE.read_text()))
        self.assertEqual(placeholders, {"@VERSION@", "@MINIMUM_MACOS@", "@CSEC_IDENTIFIER@"})
        self.assertNotRegex(self.text, r"@[A-Z_]+@")
        build_pkg = BUILD_PKG.read_text()
        self.assertIn('csec_identity_render "$distribution_template" "$distribution"', build_pkg)
        for placeholder in placeholders - {"@CSEC_IDENTIFIER@"}:
            self.assertIn(f"s/{placeholder}/", build_pkg)

    def test_apple_silicon_only_system_domain_only(self):
        options = self.root.find("options")
        self.assertEqual(options.get("hostArchitectures"), "arm64")
        self.assertEqual(options.get("customize"), "never")
        domains = self.root.find("domains")
        self.assertEqual(domains.get("enable_localSystem"), "true")
        self.assertEqual(domains.get("enable_currentUserHome"), "false")
        self.assertEqual(domains.get("enable_anywhere"), "false")

    def test_minimum_macos_is_the_apps(self):
        versions = self.root.findall("allowed-os-versions/os-version")
        self.assertEqual([version.get("min") for version in versions], [self.info["LSMinimumSystemVersion"]])

    def test_the_one_choice_installs_the_component_build_pkg_builds(self):
        build_pkg = BUILD_PKG.read_text()
        identifier = re.search(r'--identifier "([^"]+)"', build_pkg).group(1)
        identifier = identifier.replace("$csec_identifier", IDENTIFIER)
        component = re.search(r'component="\$component_directory/([^"]+)"', build_pkg).group(1)
        references = self.root.findall("pkg-ref")
        files = [reference for reference in references if (reference.text or "").strip()]
        self.assertEqual([reference.get("id") for reference in files], [identifier])
        self.assertEqual(files[0].text.strip(), component)
        self.assertEqual(files[0].get("version"), self.info["CFBundleShortVersionString"])
        outline = [line.get("choice") for line in self.root.iter("line")]
        self.assertEqual(outline, [identifier])

    def test_productbuild_and_installer_accept_it(self):
        with tempfile.TemporaryDirectory(prefix="csec-distribution.") as directory:
            directory = Path(directory)
            (directory / "root").mkdir()
            (directory / "component").mkdir()
            component = re.search(r'component="\$component_directory/([^"]+)"', BUILD_PKG.read_text()).group(1)
            distribution = directory / "Distribution.xml"
            distribution.write_text(self.text)
            subprocess.run(
                ["/usr/bin/pkgbuild", "--root", directory / "root", "--install-location", "/",
                 "--identifier", f"{IDENTIFIER}.pkg",
                 "--version", self.info["CFBundleShortVersionString"], directory / "component" / component],
                capture_output=True, check=True)
            subprocess.run(
                ["/usr/bin/productbuild", "--distribution", distribution,
                 "--package-path", directory / "component", directory / "product.pkg"],
                capture_output=True, check=True)
            info = subprocess.run(
                ["/usr/sbin/installer", "-pkginfo", "-pkg", directory / "product.pkg"],
                capture_output=True, text=True, check=True)
            self.assertEqual(info.stdout.strip(), "Convenient Security")

    def run_check(self, sysctl, product_version):
        check = self.root.find("installation-check").get("script")
        script = self.root.find("script").text
        scenario = {"sysctl": sysctl, "productVersion": product_version, "script": script, "call": check}
        completed = subprocess.run(
            ["/usr/bin/osascript", "-l", "JavaScript", "-e", JXA_HARNESS, json.dumps(scenario)],
            capture_output=True, text=True, check=True)
        return json.loads(completed.stdout)

    def test_an_apple_silicon_mac_on_a_supported_macos_installs(self):
        outcome = self.run_check({"hw.optional.arm64": 1}, self.info["LSMinimumSystemVersion"])
        self.assertTrue(outcome["passed"])
        self.assertEqual(outcome["result"], {})

    def test_an_intel_mac_is_refused_plainly(self):
        # Intel Macs have no hw.optional.arm64 at all.
        outcome = self.run_check({}, "15.0")
        self.assertFalse(outcome["passed"])
        self.assertEqual(outcome["result"]["type"], "Fatal")
        self.assertIn("Apple silicon", outcome["result"]["title"])
        self.assertIn("Intel", outcome["result"]["message"])
        self.assertIn("nothing has been installed", outcome["result"]["message"])

    def test_an_older_macos_is_refused_plainly(self):
        minimum = self.info["LSMinimumSystemVersion"]
        major = int(minimum.split(".")[0])
        outcome = self.run_check({"hw.optional.arm64": 1}, f"{major - 1}.7.1")
        self.assertFalse(outcome["passed"])
        self.assertEqual(outcome["result"]["type"], "Fatal")
        self.assertIn(f"macOS {minimum} or later", outcome["result"]["title"])
        self.assertIn("Nothing has been installed", outcome["result"]["message"])


if __name__ == "__main__":
    unittest.main()
