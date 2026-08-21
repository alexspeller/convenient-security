#!/usr/bin/env bash
set -euo pipefail

# Build, sign, and run the keychain spike as a Developer-ID-signed .app so it can
# use the data-protection keychain. This is the one-command feedback loop that
# proves the SE-cache foundation on a real signed build.
#
# Requires two values (from the Developer ID cert + `fastlane provision`):
#   SIGN_IDENTITY  e.g. "Developer ID Application: Stateful Ltd (8RS6GD89Y7)"
#   PROFILE_PATH   path to the Developer ID .provisionprofile
#
# Usage:
#   SIGN_IDENTITY="Developer ID Application: Stateful Ltd (8RS6GD89Y7)" \
#   PROFILE_PATH=packaging/build/convenient-security.provisionprofile \
#   packaging/bin/build-spike.sh

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
app="$here/build/KeychainSpike.app"

: "${SIGN_IDENTITY:?set SIGN_IDENTITY to your Developer ID Application identity}"
: "${PROFILE_PATH:?set PROFILE_PATH to the fetched .provisionprofile}"

rm -rf "$app"
mkdir -p "$app/Contents/MacOS"

swiftc "$here/spike/main.swift" -o "$app/Contents/MacOS/spike"
cp "$here/spike/Info.plist" "$app/Contents/Info.plist"
cp "$PROFILE_PATH" "$app/Contents/embedded.provisionprofile"

codesign --force --options runtime --timestamp \
  --entitlements "$here/spike/spike.entitlements" \
  --sign "$SIGN_IDENTITY" \
  "$app"

echo "--- signature + entitlements ---"
codesign --display --verbose=2 --entitlements - "$app" 2>&1 || true

# The run needs an interactive Touch ID, so it's opt-out: set RUN_SPIKE=0 to
# build + sign only (e.g. to run it yourself later when you're at the keyboard).
if [ "${RUN_SPIKE:-1}" = "1" ]; then
  echo "--- running spike (expect a Touch ID prompt) ---"
  "$app/Contents/MacOS/spike"
else
  echo "--- built + signed (not run). Run it with: ---"
  echo "$app/Contents/MacOS/spike"
fi
