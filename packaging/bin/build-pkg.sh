#!/usr/bin/env bash
set -euo pipefail

# Build the signed product archive a buyer installs: ConvenientSecurity.app in
# /Applications, a root-owned bridge copy in /Library/Application Support, the
# signed root helper plus its LaunchDaemon definition, `csec` on PATH, and the
# payload `csec setup` installs from without a checkout (the guarded Codex-hook
# and sudo-review installers, the PAM module and the review helper), plus the
# package's own uninstaller (`csec uninstall --all`). The component package is
# wrapped by productbuild in a distribution (packaging/installer/Distribution.xml)
# that refuses an Intel Mac or an older macOS before anything is written.
# Signing a .pkg needs a **Developer ID Installer** certificate —
# a DIFFERENT cert from the Developer ID *Application* one used to sign the .app
# (create it once in the developer portal, Account-Holder only).
#
# Run AFTER build-agent.sh, build-sudo-pam.sh and build-sudo-review.sh (and
# ideally after notarize.sh on the .app, so the installed app carries its own
# stapled ticket). Then notarize the .pkg:
#   packaging/bin/build-pkg.sh
#   packaging/bin/notarize.sh packaging/build/ConvenientSecurity.pkg
# build-and-install.sh has notarize.sh run this between the two notarizations
# (notarize.sh APP --build-package build-pkg.sh PKG), under one key delivery.
#
# Requires:
#   INSTALLER_IDENTITY  e.g. "Developer ID Installer: Your Team (TEAMID)"
# Optional:
#   CSEC_PKG_ALLOW_DOWNGRADE=1  build a package whose preinstall lets it replace
#     a higher version or build (build-and-install.sh --allow-downgrade, a
#     deliberate rollback). Every other package refuses that.

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
identity_file="$here/../identity.xcconfig"
identity_library="$here/lib/identity.sh"
# shellcheck source=../lib/identity.sh
. "$identity_library"
csec_identity_load "$identity_file"
app="$here/build/ConvenientSecurity.app"
pkg="$here/build/ConvenientSecurity.pkg"
stage="$here/build/pkg-root"
scripts="$here/pkg-scripts"
staged_scripts="$here/build/pkg-scripts"
root_helper="$here/build/csec-rootd"
root_label="$csec_identifier.rootd"
root_plist="$here/root/LaunchDaemons/rootd.plist"
uninstaller="$here/libexec/uninstall-csec.sh"
sudo_module="$here/build/sudo-pam/pam_csec_sudo.so"
sudo_helper="$here/build/sudo-review/csec-sudo-review"
distribution_template="$here/installer/Distribution.xml"
distribution="$here/build/Distribution.xml"
component_directory="$here/build/pkg-component"
component="$component_directory/ConvenientSecurity-component.pkg"

: "${INSTALLER_IDENTITY:?set INSTALLER_IDENTITY to your Developer ID Installer identity}"
[ -d "$app" ] || { echo "build-pkg: $app not found — run build-agent.sh first" >&2; exit 1; }
[ -f "$root_helper" ] || { echo "build-pkg: $root_helper not found — run build-agent.sh first" >&2; exit 1; }
[ -f "$root_plist" ] || { echo "build-pkg: $root_plist not found" >&2; exit 1; }
[ -f "$uninstaller" ] || { echo "build-pkg: $uninstaller not found" >&2; exit 1; }
[ -f "$sudo_module" ] || { echo "build-pkg: $sudo_module not found — run build-sudo-pam.sh first" >&2; exit 1; }
[ -f "$sudo_helper" ] || { echo "build-pkg: $sudo_helper not found — run build-sudo-review.sh first" >&2; exit 1; }
[ -f "$distribution_template" ] || { echo "build-pkg: $distribution_template not found" >&2; exit 1; }
[ -x "$scripts/preinstall" ] || { echo "build-pkg: executable preinstall script not found" >&2; exit 1; }
[ -x "$scripts/postinstall" ] || { echo "build-pkg: executable postinstall script not found" >&2; exit 1; }
[ -x "$scripts/restart-user-agents" ] || { echo "build-pkg: executable csecd restart helper not found" >&2; exit 1; }
[ -x "$scripts/reload-launch-daemon" ] || { echo "build-pkg: executable LaunchDaemon reload helper not found" >&2; exit 1; }
[ -x "$scripts/write-install-receipt" ] || { echo "build-pkg: executable install-receipt writer not found" >&2; exit 1; }
[ -x "$scripts/link-command" ] || { echo "build-pkg: executable PATH link helper not found" >&2; exit 1; }

# Never wrap a stale or damaged app in a valid installer signature.
codesign --verify --deep --strict --verbose=2 "$app" 2>&1
codesign --verify --strict --verbose=2 "$app/Contents/MacOS/csec" 2>&1
codesign --verify --strict --verbose=2 "$root_helper" 2>&1
product_requirement="$csec_product_requirement"
codesign --verify --deep --strict \
  -R="$product_requirement and identifier \"$csec_identifier\"" \
  "$app"
codesign --verify --strict \
  -R="$product_requirement and identifier \"$csec_identifier.csec\"" \
  "$app/Contents/MacOS/csec"
codesign --verify --strict \
  -R="$product_requirement and identifier \"$root_label\"" \
  "$root_helper"
codesign --verify --strict \
  -R="$product_requirement and identifier \"$csec_identifier.sudo-review\"" \
  "$sudo_helper"
codesign --verify --strict \
  -R="$product_requirement and identifier \"$csec_identifier.sudo-pam\"" \
  "$sudo_module"

version="$(plutil -extract CFBundleShortVersionString raw "$app/Contents/Info.plist")"
build_number="$(plutil -extract CFBundleVersion raw "$app/Contents/Info.plist")"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] && [[ "$build_number" =~ ^[1-9][0-9]*$ ]] || {
  echo "build-pkg: the app carries no release version and build ($version, $build_number); build it with build-agent.sh" >&2
  exit 1
}
minimum_macos="$(plutil -extract LSMinimumSystemVersion raw "$app/Contents/Info.plist")"
case "$minimum_macos" in
  *[!0-9.]* | "")
    echo "build-pkg: the app's minimum macOS is not a plain dotted number" >&2
    exit 1
    ;;
esac
package_version="$version.$build_number"
echo "--- building signed pkg for ConvenientSecurity.app $version (build $build_number; macOS $minimum_macos or later, Apple silicon) ---"

# The scripts travel with the package's own release, which preinstall compares
# with the installed app before anything is written. The payload is not
# extracted when preinstall runs, so it cannot read the new app's Info.plist.
allow_downgrade=0
[ "${CSEC_PKG_ALLOW_DOWNGRADE:-0}" = "1" ] && allow_downgrade=1
rm -rf "$staged_scripts"
mkdir -p "$staged_scripts"
cp -p "$scripts/preinstall" "$scripts/postinstall" "$scripts/reload-launch-daemon" \
  "$scripts/write-install-receipt" "$scripts/restart-user-agents" "$scripts/link-command" \
  "$staged_scripts/"
# postinstall reads the team and identifier the way the checkout's scripts do.
cp "$identity_library" "$identity_file" "$staged_scripts/"
chmod 0644 "$staged_scripts/identity.sh" "$staged_scripts/identity.xcconfig"
printf 'version=%s\nbuild=%s\nallow_downgrade=%s\n' "$version" "$build_number" "$allow_downgrade" \
  > "$staged_scripts/package-release"
chmod 0644 "$staged_scripts/package-release"
if [ "$allow_downgrade" -eq 1 ]; then
  echo "--- this package may replace a higher version or build (CSEC_PKG_ALLOW_DOWNGRADE=1) ---"
fi

# Stage every location. The bridge is the already-signed csec bytes, copied to
# a parent the login user cannot replace, and the setup payload sits beside it
# for the same reason: root runs those installers. The postinstall script fixes
# ownership explicitly; `--ownership recommended` is retained as defense in
# depth.
support="$stage/Library/Application Support/ConvenientSecurity"
rm -rf "$stage" "$component_directory"
mkdir -p \
  "$stage/Applications" \
  "$support/bin" \
  "$support/libexec" \
  "$support/sudo-review" \
  "$stage/Library/PrivilegedHelperTools" \
  "$stage/Library/LaunchDaemons" \
  "$component_directory"
ditto "$app" "$stage/Applications/ConvenientSecurity.app"
cp "$app/Contents/MacOS/csec" "$support/bin/csec"
cp "$root_helper" "$stage/Library/PrivilegedHelperTools/$root_label"
csec_identity_render "$root_plist" "$stage/Library/LaunchDaemons/$root_label.plist"
cp "$here/bin/install-codex-hook.sh" "$support/libexec/install-codex-hook.sh"
cp "$here/bin/install-sudo-review.sh" "$support/libexec/install-sudo-review.sh"
cp "$here/lib/sudo-review-policy.sh" "$support/libexec/sudo-review-policy.sh"
# The identity the installers and the uninstaller below read, beside them.
cp "$identity_library" "$support/libexec/identity.sh"
cp "$identity_file" "$support/libexec/identity.xcconfig"
cp "$sudo_module" "$support/sudo-review/pam_csec_sudo.so"
cp "$sudo_helper" "$support/sudo-review/csec-sudo-review"
# The package's own uninstaller (`csec uninstall --all` runs it through sudo),
# beside the bridge for the same reason: only root can replace it there.
cp "$uninstaller" "$support/libexec/uninstall-csec.sh"
chmod 0755 "$support/bin/csec"
chmod 0755 "$stage/Library/PrivilegedHelperTools/$root_label"
chmod 0644 "$stage/Library/LaunchDaemons/$root_label.plist"
chmod 0755 "$support/libexec/install-codex-hook.sh" "$support/libexec/install-sudo-review.sh" \
  "$support/libexec/uninstall-csec.sh"
chmod 0644 "$support/libexec/sudo-review-policy.sh" "$support/libexec/identity.sh" \
  "$support/libexec/identity.xcconfig"
chmod 0755 "$support/sudo-review/pam_csec_sudo.so" "$support/sudo-review/csec-sudo-review"

pkgbuild \
  --root "$stage" \
  --install-location / \
  --scripts "$staged_scripts" \
  --ownership recommended \
  --identifier "$csec_identifier.pkg" \
  --version "$package_version" \
  "$component"

csec_identity_render "$distribution_template" "$distribution"
sed -i '' -e "s/@VERSION@/$package_version/g" -e "s/@MINIMUM_MACOS@/$minimum_macos/g" \
  "$distribution"
if grep -q '@[A-Z_]*@' "$distribution"; then
  echo "build-pkg: $distribution still has an unfilled placeholder" >&2
  exit 1
fi
productbuild \
  --distribution "$distribution" \
  --package-path "$component_directory" \
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
     the root-owned language bridge and setup payload in /Library/Application
     Support, csec on PATH, and loads the signed protected-file LaunchDaemon;
     the user then runs:
       csec setup
EOF
fi
