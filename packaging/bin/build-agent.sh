#!/usr/bin/env bash
set -euo pipefail

# Build, assemble, and sign the resident agent as a Developer-ID-signed, hardened,
# provisioned .app bundle:
#
#   ConvenientSecurity.app/
#     Contents/Info.plist                        (CFBundleExecutable = csecd)
#     Contents/Resources/LICENSE.md              FSL-1.1-ALv2 terms
#     Contents/embedded.provisionprofile         (authorizes the keychain group)
#     Contents/MacOS/csecd                        (MAIN executable; the resident agent)
#     Contents/MacOS/csec                         (secondary CLI + `csec install`)
#     Contents/Library/LaunchAgents/<label>.plist
#
# csecd MUST be the main executable: the embedded profile only authorizes the
# restricted keychain-access-groups entitlement for the main executable, and AMFI
# SIGKILLs a secondary binary that claims it. csec is a plain signed CLI (no
# restricted entitlements); run from inside the bundle it still sees Bundle.main =
# this .app, so `csec install` registers the LaunchAgent via SMAppService.
#
# Requires (same values as build-spike.sh):
#   SIGN_IDENTITY  e.g. "Developer ID Application: Stateful Ltd (8RS6GD89Y7)"
#   PROFILE_PATH   path to the Developer ID .provisionprofile / .mobileprovision
#
# Usage:
#   SIGN_IDENTITY="Developer ID Application: Stateful Ltd (8RS6GD89Y7)" \
#   PROFILE_PATH=packaging/build/convenient-security.mobileprovision \
#   packaging/bin/build-agent.sh

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # packaging/
root="$(cd "$here/.." && pwd)"                            # repo root
app="$here/build/ConvenientSecurity.app"
label="com.alexspeller.convenient-security"

: "${SIGN_IDENTITY:?set SIGN_IDENTITY to your Developer ID Application identity}"
: "${PROFILE_PATH:?set PROFILE_PATH to the fetched .provisionprofile/.mobileprovision}"

echo "--- building release binaries (csec, csecd) ---"
swift build --package-path "$root/agent" -c release
bin="$root/agent/.build/release"

echo "--- assembling $app ---"
rm -rf "$app"
mkdir -p \
  "$app/Contents/MacOS" \
  "$app/Contents/Resources" \
  "$app/Contents/Library/LaunchAgents"
cp "$bin/csec"  "$app/Contents/MacOS/csec"
cp "$bin/csecd" "$app/Contents/MacOS/csecd"
cp "$here/agent/Info.plist" "$app/Contents/Info.plist"
cp "$root/LICENSE.md" "$app/Contents/Resources/LICENSE.md"
cp "$here/agent/LaunchAgents/$label.plist" "$app/Contents/Library/LaunchAgents/$label.plist"
cp "$PROFILE_PATH" "$app/Contents/embedded.provisionprofile"

echo "--- signing inside-out: csec (secondary, no entitlements) first ---"
codesign --force --options runtime --timestamp \
  --identifier "com.alexspeller.convenient-security.csec" \
  --sign "$SIGN_IDENTITY" \
  "$app/Contents/MacOS/csec"

echo "--- then the bundle: signs csecd (main executable) WITH the keychain entitlements ---"
codesign --force --options runtime --timestamp \
  --entitlements "$here/agent/csecd.entitlements" \
  --sign "$SIGN_IDENTITY" \
  "$app"

echo "--- signature (bundle / csecd main, must show keychain-access-groups) ---"
codesign --display --verbose=2 --entitlements - "$app" 2>&1 || true
echo "--- verify ---"
codesign --verify --deep --strict --verbose=2 "$app" 2>&1

cat <<EOF

Built + signed: $app

Next (needs you, at the keyboard):
  1. Install it where SMAppService trusts it:
       cp -R "$app" /Applications/
  2. Register the background agent (runs from inside the bundle):
       /Applications/ConvenientSecurity.app/Contents/MacOS/csec install
     Approve "ConvenientSecurity" in System Settings › General › Login Items if asked.
  3. Check it:
       /Applications/ConvenientSecurity.app/Contents/MacOS/csec status
EOF
