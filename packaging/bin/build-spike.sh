#!/usr/bin/env bash
set -euo pipefail

# Build, sign, and run the keychain spike as a Developer-ID-signed .app so it can
# use the data-protection keychain. This is the one-command feedback loop that
# proves the SE-cache and native-store-key foundations on a real signed build.
#
# Requires (from the Developer ID cert + `fastlane provision`):
#   SIGN_IDENTITY  e.g. "Developer ID Application: Your Team (TEAMID)"
#   PROFILE_PATH   the Developer ID provisioning profile; defaults, as in
#                  build-and-install.sh, to the one `fastlane provision` writes:
#                  packaging/build/convenient-security.mobileprovision
#
# Usage:
#   SIGN_IDENTITY="Developer ID Application: Your Team (TEAMID)" \
#   packaging/bin/build-spike.sh

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
app="$here/build/KeychainSpike.app"
# The team and identifier: the plist templates read the identity file, the
# Swift sources the identity module's files, compiled into each binary.
# shellcheck source=../lib/identity.sh
. "$here/lib/identity.sh"
csec_identity_load "$here/../identity.xcconfig"
identity_sources=("$here/../agent/Sources/CSECBuildIdentity/"*.swift)

: "${SIGN_IDENTITY:?set SIGN_IDENTITY to your Developer ID Application identity}"
PROFILE_PATH="${PROFILE_PATH:-$here/build/convenient-security.mobileprovision}"
if [ ! -f "$PROFILE_PATH" ]; then
  echo "build-spike: no provisioning profile at $PROFILE_PATH (run packaging/bin/provision.sh, or set PROFILE_PATH)" >&2
  exit 1
fi

rm -rf "$app"
mkdir -p "$app/Contents/MacOS"

swiftc "$here/spike/main.swift" "${identity_sources[@]}" -o "$app/Contents/MacOS/spike"
# A module's top-level code must be in its main.swift.
probe_source="$(mktemp -d "${TMPDIR:-/tmp}/csec-spike-probe.XXXXXX")"
cp "$here/spike/unentitled-keychain-probe.swift" "$probe_source/main.swift"
swiftc "$probe_source/main.swift" "${identity_sources[@]}" \
  -o "$app/Contents/MacOS/unentitled-keychain-probe"
rm -rf "$probe_source"
csec_identity_render "$here/spike/Info.plist" "$app/Contents/Info.plist"
spike_entitlements="$here/build/spike.entitlements"
csec_identity_render "$here/spike/spike.entitlements" "$spike_entitlements"
cp "$PROFILE_PATH" "$app/Contents/embedded.provisionprofile"

# Sign the attacker-model helper without restricted entitlements, then seal it
# inside the provisioned bundle whose main executable receives the access group.
codesign --force --options runtime --timestamp \
  --sign "$SIGN_IDENTITY" \
  "$app/Contents/MacOS/unentitled-keychain-probe"
codesign --force --options runtime --timestamp \
  --entitlements "$spike_entitlements" \
  --sign "$SIGN_IDENTITY" \
  "$app"

codesign --verify --deep --strict "$app"
helper_entitlements="$(
  codesign --display --entitlements - \
    "$app/Contents/MacOS/unentitled-keychain-probe" 2>&1
)"
if [[ "$helper_entitlements" == *"keychain-access-groups"* ]] || \
   [[ "$helper_entitlements" == *"com.apple.application-identifier"* ]]; then
  echo "error: attacker-model helper unexpectedly has restricted entitlements" >&2
  exit 1
fi

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
