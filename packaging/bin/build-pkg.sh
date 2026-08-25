#!/usr/bin/env bash
set -euo pipefail

# Build a signed .pkg installer that drops ConvenientSecurity.app into
# /Applications, a root-owned bridge copy into /Library/Application Support,
# and the signed root helper plus LaunchDaemon definition.
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
root_helper="$here/build/csec-rootd"
root_label="com.alexspeller.convenient-security.rootd"
root_plist="$here/root/LaunchDaemons/$root_label.plist"

: "${INSTALLER_IDENTITY:?set INSTALLER_IDENTITY to your Developer ID Installer identity}"
[ -d "$app" ] || { echo "build-pkg: $app not found — run build-agent.sh first" >&2; exit 1; }
[ -f "$root_helper" ] || { echo "build-pkg: $root_helper not found — run build-agent.sh first" >&2; exit 1; }
[ -f "$root_plist" ] || { echo "build-pkg: $root_plist not found" >&2; exit 1; }
[ -x "$scripts/postinstall" ] || { echo "build-pkg: executable postinstall script not found" >&2; exit 1; }
[ -x "$scripts/reload-launch-daemon" ] || { echo "build-pkg: executable LaunchDaemon reload helper not found" >&2; exit 1; }

# Never wrap a stale or damaged app in a valid installer signature.
codesign --verify --deep --strict --verbose=2 "$app" 2>&1
codesign --verify --strict --verbose=2 "$app/Contents/MacOS/csec" 2>&1
codesign --verify --strict --verbose=2 "$root_helper" 2>&1
product_requirement='anchor apple generic and certificate leaf[subject.OU] = "8RS6GD89Y7"'
codesign --verify --deep --strict \
  -R="$product_requirement and identifier \"com.alexspeller.convenient-security\"" \
  "$app"
codesign --verify --strict \
  -R="$product_requirement and identifier \"com.alexspeller.convenient-security.csec\"" \
  "$app/Contents/MacOS/csec"
codesign --verify --strict \
  -R="$product_requirement and identifier \"$root_label\"" \
  "$root_helper"

version="$(plutil -extract CFBundleShortVersionString raw "$app/Contents/Info.plist")"
echo "--- building signed pkg for ConvenientSecurity.app $version ---"

# Stage both locations. The bridge is the already-signed csec bytes, copied to a
# parent the login user cannot replace. The postinstall script fixes ownership
# explicitly; `--ownership recommended` is retained as defense in depth.
rm -rf "$stage"
mkdir -p \
  "$stage/Applications" \
  "$stage/Library/Application Support/ConvenientSecurity/bin" \
  "$stage/Library/PrivilegedHelperTools" \
  "$stage/Library/LaunchDaemons"
ditto "$app" "$stage/Applications/ConvenientSecurity.app"
cp "$app/Contents/MacOS/csec" "$stage/Library/Application Support/ConvenientSecurity/bin/csec"
cp "$root_helper" "$stage/Library/PrivilegedHelperTools/$root_label"
cp "$root_plist" "$stage/Library/LaunchDaemons/$root_label.plist"
chmod 0755 "$stage/Library/Application Support/ConvenientSecurity/bin/csec"
chmod 0755 "$stage/Library/PrivilegedHelperTools/$root_label"
chmod 0644 "$stage/Library/LaunchDaemons/$root_label.plist"

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
EOF

if [ "${CSEC_BUILD_AND_INSTALL_PIPELINE:-0}" != "1" ]; then
  cat <<EOF
Next:
  1. Notarize + staple it:
       packaging/bin/notarize.sh "$pkg"
  2. Ship $pkg. On install it places ConvenientSecurity.app in /Applications,
     the root-owned language bridge in /Library/Application Support, and loads
     the signed protected-file LaunchDaemon;
     the user then runs:
       /Applications/ConvenientSecurity.app/Contents/MacOS/csec install
EOF
fi
