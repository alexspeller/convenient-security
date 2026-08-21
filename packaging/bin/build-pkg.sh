#!/usr/bin/env bash
set -euo pipefail

# Build a signed .pkg installer that drops ConvenientSecurity.app into
# /Applications and a root-owned bridge copy into /Library/Application Support.
# Signing a .pkg needs a **Developer ID Installer** certificate —
# a DIFFERENT cert from the Developer ID *Application* one used to sign the .app
# (create it once in the developer portal, Account-Holder only).
#
# Run AFTER build-agent.sh (and ideally after notarize.sh on the .app, so the
# installed app carries its own stapled ticket). Then notarize the .pkg:
#   packaging/bin/build-pkg.sh
#   packaging/bin/notarize.sh packaging/build/ConvenientSecurity.pkg
#
# Requires:
#   INSTALLER_IDENTITY  e.g. "Developer ID Installer: Stateful Ltd (8RS6GD89Y7)"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
app="$here/build/ConvenientSecurity.app"
pkg="$here/build/ConvenientSecurity.pkg"
stage="$here/build/pkg-root"
scripts="$here/pkg-scripts"

: "${INSTALLER_IDENTITY:?set INSTALLER_IDENTITY to your Developer ID Installer identity}"
[ -d "$app" ] || { echo "build-pkg: $app not found — run build-agent.sh first" >&2; exit 1; }

# Never wrap a stale or damaged app in a valid installer signature.
codesign --verify --deep --strict --verbose=2 "$app" 2>&1
codesign --verify --strict --verbose=2 "$app/Contents/MacOS/csec" 2>&1

version="$(plutil -extract CFBundleShortVersionString raw "$app/Contents/Info.plist")"
echo "--- building signed pkg for ConvenientSecurity.app $version ---"

# Stage both locations. The bridge is the already-signed csec bytes, copied to a
# parent the login user cannot replace. The postinstall script fixes ownership
# explicitly; `--ownership recommended` is retained as defense in depth.
rm -rf "$stage"
mkdir -p "$stage/Applications" "$stage/Library/Application Support/ConvenientSecurity/bin"
ditto "$app" "$stage/Applications/ConvenientSecurity.app"
cp "$app/Contents/MacOS/csec" "$stage/Library/Application Support/ConvenientSecurity/bin/csec"
chmod 0755 "$stage/Library/Application Support/ConvenientSecurity/bin/csec"

pkgbuild \
  --root "$stage" \
  --install-location / \
  --scripts "$scripts" \
  --ownership recommended \
  --identifier "com.alexspeller.convenient-security.pkg" \
  --version "$version" \
  --sign "$INSTALLER_IDENTITY" \
  "$pkg"

echo "--- verify pkg signature ---"
pkgutil --check-signature "$pkg" 2>&1

cat <<EOF

Built + signed: $pkg

Next:
  1. Notarize + staple it:
       packaging/bin/notarize.sh "$pkg"
  2. Ship $pkg. On install it places ConvenientSecurity.app in /Applications
     and the root-owned Ruby bridge in /Library/Application Support;
     the user then runs:
       /Applications/ConvenientSecurity.app/Contents/MacOS/csec install
EOF
