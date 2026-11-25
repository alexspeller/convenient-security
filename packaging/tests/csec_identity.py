"""The build identity (identity.xcconfig) as the packaging tests see it.

Read through packaging/lib/identity.sh, the same parser the build stages and
the package's scripts use, so the tests hold no team ID or identifier of their
own.
"""
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
IDENTITY_FILE = ROOT / "identity.xcconfig"
IDENTITY_LIBRARY = ROOT / "packaging/lib/identity.sh"


def _load():
    result = subprocess.run(
        ["/bin/bash", "-c", 'set -euo pipefail; . "$1"; csec_identity_load "$2"; '
         'printf "%s\\n" "$csec_team_id" "$csec_identifier"',
         "identity", str(IDENTITY_LIBRARY), str(IDENTITY_FILE)],
        text=True, capture_output=True, check=True, timeout=10)
    team, identifier = result.stdout.splitlines()
    return team, identifier


TEAM_ID, IDENTIFIER = _load()
CLOUDKIT_CONTAINER = f"iCloud.{IDENTIFIER}"
KEYCHAIN_ACCESS_GROUP = f"{TEAM_ID}.{IDENTIFIER}"
