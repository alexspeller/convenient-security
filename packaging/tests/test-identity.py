#!/usr/bin/env python3
"""The build identity reader (packaging/lib/identity.sh) the build stages and
the package's root-run scripts share.

It must accept the checked-in identity.xcconfig, derive every name from its two
settings, and refuse anything else without executing it: root sources the
reader and loads the file the package installed beside it.
"""
import subprocess
import tempfile
import unittest
from pathlib import Path

from csec_identity import IDENTITY_FILE, IDENTITY_LIBRARY

GENERATED_SWIFT = IDENTITY_FILE.parent / "agent/Sources/CSECBuildIdentity/BuildIdentity.swift"


def bash(script, *arguments):
    return subprocess.run(
        ["/bin/bash", "-c", 'set -euo pipefail\n. "$1"\nshift\n' + script, "identity-test",
         str(IDENTITY_LIBRARY), *arguments],
        text=True, capture_output=True, timeout=10, check=False)


LOAD = 'csec_identity_load "$1"\nprintf "%s\\n" "$csec_team_id" "$csec_identifier" ' \
       '"$csec_keychain_access_group" "$csec_cloudkit_container" "$csec_product_requirement"\n'


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="csec-identity-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def identity(self, text):
        path = self.root / "identity.xcconfig"
        path.write_text(text)
        return path

    def test_the_checked_in_identity_loads(self):
        result = bash(LOAD, str(IDENTITY_FILE))
        self.assertEqual(result.returncode, 0, result.stderr)
        team, identifier, group, container, requirement = result.stdout.splitlines()
        self.assertRegex(team, r"^[A-Z0-9]{10}$")
        self.assertEqual(group, f"{team}.{identifier}")
        self.assertEqual(container, f"iCloud.{identifier}")
        self.assertEqual(requirement, f'anchor apple generic and certificate leaf[subject.OU] = "{team}"')

    def test_another_team_derives_every_name_from_its_two_settings(self):
        path = self.identity("// a self-build\n\nCSEC_TEAM_ID = ABCDE12345\nCSEC_IDENTIFIER=org.example.csec\n")
        result = bash(LOAD, str(path))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [
            "ABCDE12345", "org.example.csec", "ABCDE12345.org.example.csec", "iCloud.org.example.csec",
            'anchor apple generic and certificate leaf[subject.OU] = "ABCDE12345"'])

    def test_malformed_files_are_refused(self):
        good_team, good_identifier = "CSEC_TEAM_ID = ABCDE12345\n", "CSEC_IDENTIFIER = org.example.csec\n"
        for name, text, message in [
            ("short team", "CSEC_TEAM_ID = ABCDE1234\n" + good_identifier, "10-character"),
            ("lower-case team", "CSEC_TEAM_ID = abcde12345\n" + good_identifier, "10-character"),
            ("no team", good_identifier, "10-character"),
            ("one-label identifier", good_team + "CSEC_IDENTIFIER = csec\n", "reverse-DNS"),
            ("identifier with a slash", good_team + "CSEC_IDENTIFIER = org.example/csec\n", "reverse-DNS"),
            ("no identifier", good_team, "reverse-DNS"),
            ("unknown setting", good_team + good_identifier + "CSEC_OTHER = x\n", "unknown setting CSEC_OTHER"),
            ("duplicate", good_team + good_identifier + good_team, "sets CSEC_TEAM_ID twice"),
            ("value with a space", good_team + "CSEC_IDENTIFIER = org.example csec\n", "NAME = value"),
            ("shell comment", "# a comment\n" + good_team + good_identifier, "NAME = value"),
            ("indented", " " + good_team + good_identifier, "NAME = value"),
        ]:
            with self.subTest(name):
                result = bash(LOAD, str(self.identity(text)))
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn(message, result.stderr)
                self.assertEqual(result.stdout, "")

    def test_a_missing_file_is_refused(self):
        result = bash(LOAD, str(self.root / "absent.xcconfig"))
        self.assertEqual(result.returncode, 1)
        self.assertIn("not found", result.stderr)

    def test_the_file_is_parsed_never_executed(self):
        marker = self.root / "ran"
        for text in [f"CSEC_TEAM_ID = $(touch {marker})\n", f"CSEC_TEAM_ID=`touch {marker}`\n",
                     f"touch {marker}\n"]:
            with self.subTest(text):
                result = bash(LOAD, str(self.identity(text + "CSEC_IDENTIFIER = org.example.csec\n")))
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertFalse(marker.exists())

    def test_render_fills_the_identity_and_refuses_a_leftover_placeholder(self):
        path = self.identity("CSEC_TEAM_ID = ABCDE12345\nCSEC_IDENTIFIER = org.example.csec\n")
        template = self.root / "template.plist"
        output = self.root / "output.plist"
        template.write_text("<string>@CSEC_TEAM_ID@.@CSEC_IDENTIFIER@</string>@VERSION@\n")
        result = bash('csec_identity_load "$1"\ncsec_identity_render "$2" "$3"\n', str(path), str(template),
                      str(output))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output.read_text(), "<string>ABCDE12345.org.example.csec</string>@VERSION@\n")
        template.write_text("@CSEC_TEAM_ID@ @CSEC_UNKNOWN@\n")
        result = bash('csec_identity_load "$1"\ncsec_identity_render "$2" "$3"\n', str(path), str(template),
                      str(output))
        self.assertEqual(result.returncode, 1)
        self.assertIn("unfilled placeholder", result.stderr)

    def test_the_generated_swift_follows_the_file(self):
        result = bash('csec_identity_load "$1"\ncsec_identity_swift\n', str(IDENTITY_FILE))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, GENERATED_SWIFT.read_text(),
                         "BuildIdentity.swift does not match identity.xcconfig")

        path = self.identity("CSEC_TEAM_ID = ABCDE12345\nCSEC_IDENTIFIER = org.example.csec\n")
        swift = self.root / "BuildIdentity.swift"
        write = 'csec_identity_load "$1"\ncsec_identity_write_swift "$2"\n'
        first = bash(write, str(path), str(swift))
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertIn("rewrote", first.stdout)
        self.assertIn('teamIdentifier = "ABCDE12345"', swift.read_text())
        self.assertIn('identifier = "org.example.csec"', swift.read_text())
        again = bash(write, str(path), str(swift))
        self.assertEqual((again.returncode, again.stdout), (0, ""))


if __name__ == "__main__":
    unittest.main()
