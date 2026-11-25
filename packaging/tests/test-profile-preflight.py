"""Prove build-agent.sh refuses a profile that does not authorize csecd's
restricted entitlements, before it builds or signs anything.

Every profile here is a synthetic plist shaped like a decoded Developer ID
profile (the shapes of real ones: an environment string, a "*" services
wildcard, a "TEAM.*" keychain group). No real profile, identity, or network is
involved.
"""

import os
import plistlib
import subprocess
import tempfile
import unittest
from pathlib import Path

from csec_identity import CLOUDKIT_CONTAINER, IDENTIFIER, TEAM_ID


PACKAGING = Path(__file__).resolve().parents[1]
BUILD_AGENT = PACKAGING / "bin/build-agent.sh"
CSECD_ENTITLEMENTS = PACKAGING / "agent/csecd.entitlements"
TEAM = TEAM_ID
APP_ID = IDENTIFIER
CONTAINER = CLOUDKIT_CONTAINER

# The profile build-and-install.sh has been embedding: no iCloud keys.
CURRENT_PROFILE = {
    "com.apple.application-identifier": f"{TEAM}.{APP_ID}",
    "com.apple.developer.team-identifier": TEAM,
    "keychain-access-groups": [f"{TEAM}.*"],
}

# What the portal issues once iCloud is enabled with the container on the App ID.
ICLOUD_PROFILE = {
    **CURRENT_PROFILE,
    "com.apple.developer.icloud-container-environment": "Production",
    "com.apple.developer.icloud-container-identifiers": [CONTAINER, "iCloud.com.example.other"],
    "com.apple.developer.icloud-services": "*",
    "com.apple.developer.ubiquity-container-identifiers": [CONTAINER],
    "com.apple.developer.ubiquity-kvstore-identifier": f"{TEAM}.*",
}


class ProfilePreflightTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def write(self, name, value):
        path = self.root / name
        path.write_bytes(plistlib.dumps(value))
        return path

    def preflight(self, profile_entitlements, signed=CSECD_ENTITLEMENTS):
        """Runs the preflight with the CMS decode replaced by a decoded profile
        plist; the Entitlements extraction itself is the script's own plutil."""
        decoded = self.write("decoded-profile.plist", {
            "Name": "synthetic", "Entitlements": profile_entitlements,
        })
        harness = r'''
set -euo pipefail
source "$1"
extract_profile_entitlements() {
  /usr/bin/plutil -extract Entitlements xml1 -o "$2" -- "$1"
}
# As build-agent.sh signs them: the identity filled in.
csec_identity_render "$3" "$4"
preflight_profile_entitlements "$2" "$4"
'''
        return subprocess.run(
            ["/bin/bash", "-c", harness, "preflight-test", str(BUILD_AGENT), str(decoded),
             str(signed), str(self.root / "signed.entitlements")],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20,
        )

    def assert_refused(self, result, *keys):
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("does not authorize every restricted entitlement csecd is signed with",
                      result.stderr)
        for key in keys:
            self.assertIn(f"  {key}: ", result.stderr)
        self.assertIn("packaging/bin/build-and-install.sh --refresh-profile", result.stderr)

    def test_current_profile_without_icloud_is_refused_with_the_portal_fix(self):
        result = self.preflight(CURRENT_PROFILE)
        self.assert_refused(result,
                            "com.apple.developer.icloud-container-environment",
                            "com.apple.developer.icloud-container-identifiers",
                            "com.apple.developer.icloud-services")
        self.assertIn(f"enable iCloud (CloudKit) with container {CONTAINER} on App ID {APP_ID}",
                      result.stderr)
        # Only the missing keys are reported.
        self.assertNotIn("  keychain-access-groups: ", result.stderr)
        self.assertNotIn("  com.apple.application-identifier: ", result.stderr)

    def test_icloud_enabled_profile_authorizes_the_checked_in_entitlements(self):
        result = self.preflight(ICLOUD_PROFILE)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")

    def test_array_valued_profile_keys_are_accepted(self):
        profile = {
            **ICLOUD_PROFILE,
            "com.apple.application-identifier": f"{TEAM}.*",
            "com.apple.developer.icloud-container-environment": ["Development", "Production"],
            "com.apple.developer.icloud-services": ["CloudKit", "CloudDocuments"],
        }
        result = self.preflight(profile)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_development_only_profile_is_refused(self):
        profile = {**ICLOUD_PROFILE,
                   "com.apple.developer.icloud-container-environment": ["Development"]}
        result = self.preflight(profile)
        self.assert_refused(result, "com.apple.developer.icloud-container-environment")
        self.assertIn("signed Production; the profile allows only Development", result.stderr)

    def test_another_container_is_refused(self):
        profile = {**ICLOUD_PROFILE,
                   "com.apple.developer.icloud-container-identifiers": ["iCloud.com.example"]}
        self.assert_refused(self.preflight(profile),
                            "com.apple.developer.icloud-container-identifiers")

    def test_services_that_omit_cloudkit_are_refused(self):
        profile = {**ICLOUD_PROFILE,
                   "com.apple.developer.icloud-services": ["CloudDocuments"]}
        self.assert_refused(self.preflight(profile), "com.apple.developer.icloud-services")

    def test_a_team_wildcard_does_not_cover_another_team(self):
        profile = {**ICLOUD_PROFILE,
                   "keychain-access-groups": ["ABCDE12345.*"],
                   "com.apple.application-identifier": f"ABCDE12345.{APP_ID}"}
        result = self.preflight(profile)
        self.assert_refused(result, "keychain-access-groups", "com.apple.application-identifier")
        self.assertIn(f"make the App ID {APP_ID}", result.stderr)

    def test_signature_granted_keys_need_no_profile_but_others_do(self):
        signed = self.write("signed.plist", {
            "com.apple.application-identifier": f"{TEAM}.{APP_ID}",
            "com.apple.security.automation.apple-events": True,
            "com.apple.security.cs.disable-library-validation": True,
            "com.apple.developer.aps-environment": "production",
            "get-task-allow": True,
        })
        profile = {**CURRENT_PROFILE, "get-task-allow": False}
        result = self.preflight(profile, signed)
        self.assert_refused(result, "com.apple.developer.aps-environment", "get-task-allow")
        self.assertNotIn("com.apple.security.", result.stderr)

    def test_an_unreadable_profile_stops_the_build_before_it_starts(self):
        """The real script, with a profile the real CMS decoder rejects."""
        not_a_profile = self.root / "not-a-profile.mobileprovision"
        not_a_profile.write_text("synthetic, not CMS\n")
        environment = {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": os.environ.get("HOME", str(self.root)),
            "TMPDIR": str(self.root),
            "SIGN_IDENTITY": "synthetic identity that must never be used",
            "PROFILE_PATH": str(not_a_profile),
        }
        result = subprocess.run(
            [str(BUILD_AGENT)], env=environment,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60,
        )
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("could not read the Entitlements of provisioning profile", result.stdout)
        self.assertNotIn("--- building", result.stdout)
        self.assertNotIn("--- signing", result.stdout)


if __name__ == "__main__":
    unittest.main()
