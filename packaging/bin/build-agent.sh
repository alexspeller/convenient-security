#!/usr/bin/env bash
set -euo pipefail

# Build, assemble, and sign the resident agent as a hardened, provisioned,
# Developer-ID-signed .app bundle, under the team and identifier in
# identity.xcconfig. Every build is remote-approval capable:
# csecd is always signed with packaging/agent/csecd.entitlements, which carries
# the CloudKit Production container the iPhone relay uses. Remote approval stays
# off until the user pairs a phone.
#
#   ConvenientSecurity.app/
#     Contents/Info.plist                        (CFBundleExecutable = csecd)
#     Contents/Resources/LICENSE.md              FSL-1.1-ALv2 terms
#     Contents/Resources/ai-guard/op             (csec ai's direct-op refusal shim)
#     Contents/Resources/claude-code-shell/csec-claude-code-shell  (Claude Code's shell prefix)
#     Contents/Resources/uninstall/uninstall-csec.sh  (the package uninstaller, for doctor to compare)
#     Contents/embedded.provisionprofile         (authorizes the keychain group)
#     Contents/MacOS/csecd                        (MAIN executable; the resident agent)
#     Contents/MacOS/csec                         (secondary CLI + `csec install`)
#     Contents/MacOS/csec-op-bridge               (holds one 1Password SDK session per account)
#     Contents/Library/LaunchAgents/<label>.plist
#
#   packaging/build/csec-rootd                    (standalone privileged helper)
#
# csecd MUST be the main executable: the embedded profile only authorizes the
# restricted keychain-access-groups entitlement for the main executable, and AMFI
# SIGKILLs a secondary binary that claims it. csec is a plain signed CLI (no
# restricted keychain entitlements). It carries only the Calendar capability
# required when its supervised automation descendants use EventKit-backed
# Calendar or Reminders tools; TCC permission remains user-granted. Run from
# inside the bundle it still sees Bundle.main = this .app, so `csec install`
# registers the LaunchAgent via SMAppService.
#
# Requires (same values as build-spike.sh):
#   SIGN_IDENTITY  the Developer ID Application identity
#   PROFILE_PATH   the Developer ID provisioning profile for the App ID
#
# Before building anything it checks that the profile authorizes every
# restricted entitlement csecd is signed with. codesign does not check that;
# AMFI does, by killing csecd at launch.
#
# Usage:
#   SIGN_IDENTITY="Developer ID Application: Your Team (TEAMID)" \
#   PROFILE_PATH=packaging/build/convenient-security.mobileprovision \
#   packaging/bin/build-agent.sh

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # packaging/
root="$(cd "$here/.." && pwd)"                            # repo root
app="$here/build/ConvenientSecurity.app"
# shellcheck source=../lib/identity.sh
. "$here/lib/identity.sh"
csec_identity_load "$root/identity.xcconfig"
label="$csec_identifier"
root_helper="$here/build/csec-rootd"
# csecd's entitlements with the team and identifier filled in (rendered below).
agent_entitlements_template="$here/agent/csecd.entitlements"
agent_entitlements="$here/build/csecd.entitlements"
launcher_entitlements="$here/agent/csec.entitlements"
bridge_entitlements="$here/agent/csec-op-bridge.entitlements"

# Writes the Entitlements dictionary of a provisioning profile ($1) to a plist
# ($2). The profile is a CMS-signed plist; only its metadata is read.
extract_profile_entitlements() {
  local profile="$1"
  local output="$2"
  /usr/bin/security cms -D -i "$profile" |
    /usr/bin/plutil -extract Entitlements xml1 -o "$output" -- -
}

# Compares the entitlements csecd is signed with ($1) against a profile's
# Entitlements plist ($2). Prints one line per restricted key the profile does
# not authorize, then the fix, and returns nonzero. Only identifiers are
# printed; a profile carries no secret material in its Entitlements.
#
# Restricted means every key outside com.apple.security.*: the hardened-runtime
# and sandbox keys there (and macOS's team-prefixed app groups) are granted by
# the signature itself. A profile value may be a string, an array, or a
# wildcard ("*", "TEAMID.*"); every signed value must match one of the
# profile's values for its key.
check_profile_authorizes_entitlements() {
  /usr/bin/python3 - "$1" "$2" <<'PY'
import plistlib
import sys

signed_path, profile_path = sys.argv[1], sys.argv[2]
with open(signed_path, "rb") as handle:
    signed = plistlib.load(handle)
with open(profile_path, "rb") as handle:
    profile = plistlib.load(handle)
if not isinstance(signed, dict) or not isinstance(profile, dict):
    sys.exit("error: entitlements are not a dictionary")


def restricted(key):
    return not key.startswith("com.apple.security.")


def matches(pattern, value):
    if isinstance(pattern, str) and isinstance(value, str):
        if pattern.endswith("*"):
            return value.startswith(pattern[:-1])
        return pattern == value
    return type(pattern) is type(value) and pattern == value


def as_list(value):
    return value if isinstance(value, list) else [value]


def show(value):
    return ", ".join(str(item) for item in as_list(value)) or "(empty)"


problems = []
for key in sorted(signed):
    if not restricted(key):
        continue
    if key not in profile:
        problems.append((key, f"signed {show(signed[key])}; the profile has no {key}"))
        continue
    allowed = as_list(profile[key])
    missing = [value for value in as_list(signed[key])
               if not any(matches(pattern, value) for pattern in allowed)]
    if missing:
        problems.append((key, f"signed {show(missing)}; the profile allows only {show(profile[key])}"))

if not problems:
    sys.exit(0)

print("error: the provisioning profile does not authorize every restricted "
      "entitlement csecd is signed with; AMFI would kill csecd at launch:", file=sys.stderr)
for key, detail in problems:
    print(f"  {key}: {detail}", file=sys.stderr)

application_identifier = str(signed.get("com.apple.application-identifier", ""))
app_id = application_identifier.split(".", 1)[-1] or "the App ID"
containers = show(signed.get("com.apple.developer.icloud-container-identifiers", []))
if any(key.startswith("com.apple.developer.icloud") for key, _ in problems):
    print(f"Fix: in the Apple Developer portal, enable iCloud (CloudKit) with container "
          f"{containers} on App ID {app_id}, then run "
          f"packaging/bin/build-and-install.sh --refresh-profile", file=sys.stderr)
else:
    print(f"Fix: make the App ID {app_id} in the Apple Developer portal grant the keys "
          f"above, then run packaging/bin/build-and-install.sh --refresh-profile",
          file=sys.stderr)
sys.exit(1)
PY
}

# Fails, before anything is built or signed, unless the profile ($1) authorizes
# every restricted entitlement in the entitlements file ($2).
preflight_profile_entitlements() {
  local profile="$1"
  local entitlements="$2"
  local workdir
  local result=0
  workdir="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/csec-profile-preflight.XXXXXX")"
  if ! extract_profile_entitlements "$profile" "$workdir/profile-entitlements.plist"; then
    echo "error: could not read the Entitlements of provisioning profile $profile" >&2
    result=1
  elif ! check_profile_authorizes_entitlements \
      "$entitlements" "$workdir/profile-entitlements.plist"; then
    result=1
  fi
  /bin/rm -rf "$workdir"
  return "$result"
}

# The release version is the repository's VERSION file: MAJOR.MINOR.PATCH,
# digits only, as semantic versioning writes a release. Prints it, or fails.
read_release_version() {
  local version_file="$1"
  local version
  [ -f "$version_file" ] || { echo "error: $version_file is missing" >&2; return 1; }
  version="$(/usr/bin/tr -d '\n' < "$version_file")"
  if [[ ! "$version" =~ ^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$ ]]; then
    echo "error: $version_file must hold one MAJOR.MINOR.PATCH release version, not: $version" >&2
    return 1
  fi
  printf '%s\n' "$version"
}

# The build number is the commit count of the history being built, so a later
# commit on the same line always numbers higher; the package refuses to
# install a lower version or build over a higher one. A shallow clone would
# count only what it fetched, so it is refused.
read_build_number() {
  local repository="$1"
  local shallow count
  shallow="$(git -C "$repository" rev-parse --is-shallow-repository)" || return 1
  if [ "$shallow" != "false" ]; then
    echo "error: $repository is a shallow clone; its commit count is not the build number (git fetch --unshallow)" >&2
    return 1
  fi
  count="$(git -C "$repository" rev-list --count HEAD)" || return 1
  [[ "$count" =~ ^[1-9][0-9]*$ ]] || { echo "error: could not count the commits in $repository" >&2; return 1; }
  printf '%s\n' "$count"
}

# Writes the stamp every release binary carries as its __TEXT,__csec_stamp
# section (ReleaseStamp in the agent): exactly this JSON, no newline.
write_release_stamp() {
  local output="$1" version="$2" build="$3" commit="$4"
  [[ "$commit" =~ ^[0-9a-f]{40}$ ]] || { echo "error: not a commit id: $commit" >&2; return 1; }
  printf '{"version":"%s","build":%s,"commit":"%s"}' "$version" "$build" "$commit" > "$output"
}

# Fails unless the binary ($1) carries exactly the stamp file ($2).
verify_release_stamp() {
  local binary="$1" stamp="$2" extracted
  extracted="$(/usr/bin/mktemp "${TMPDIR:-/tmp}/csec-stamp.XXXXXX")"
  if ! /usr/bin/segedit "$binary" -extract __TEXT __csec_stamp "$extracted" >/dev/null 2>&1 \
      || ! /usr/bin/cmp -s "$extracted" "$stamp"; then
    /bin/rm -f "$extracted"
    echo "error: $binary does not carry this build's release stamp" >&2
    return 1
  fi
  /bin/rm -f "$extracted"
}

# Sourceable so packaging/tests can exercise the preflight on synthetic plists
# without building or signing anything.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  return 0
fi

: "${SIGN_IDENTITY:?set SIGN_IDENTITY to a matching Apple code-signing identity}"
: "${PROFILE_PATH:?set PROFILE_PATH to the fetched .provisionprofile/.mobileprovision}"

mkdir -p "$here/build"
csec_identity_render "$agent_entitlements_template" "$agent_entitlements"
echo "--- preflight: the provisioning profile must authorize csecd's restricted entitlements ---"
preflight_profile_entitlements "$PROFILE_PATH" "$agent_entitlements"

release_version="$(read_release_version "$root/VERSION")"
build_number="$(read_build_number "$root")"
# The commit this bundle was built from. build-and-install.sh reads it from the
# installed app and refuses a checkout that lacks it, so an older build never
# lands over a newer one by accident.
source_commit="$(git -C "$root" rev-parse --verify HEAD^{commit})"
mkdir -p "$here/build"
release_stamp="$here/build/release-stamp.json"
write_release_stamp "$release_stamp" "$release_version" "$build_number" "$source_commit"
echo "--- release $release_version, build $build_number, commit $source_commit ---"

# Swift reads the identity from a generated source file; bring it up to date
# with identity.xcconfig before compiling (a no-op unless the file changed).
csec_identity_write_swift "$root/agent/Sources/CSECBuildIdentity/BuildIdentity.swift"
echo "--- building release binaries (csec, csecd, csec-rootd) ---"
bin="$root/agent/.build/release"
# SwiftPM does not track the stamp file as a link input, so remove the
# products to make it link them again with this stamp; each is then checked.
/bin/rm -f "$bin/csec" "$bin/csecd" "$bin/csec-rootd"
swift build --package-path "$root/agent" -c release --jobs 2 \
  -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __csec_stamp -Xlinker "$release_stamp"
for stamped in csec csecd csec-rootd; do
  verify_release_stamp "$bin/$stamped" "$release_stamp"
done

"$here/bin/build-bridge.sh" "$here/build/csec-op-bridge" "$here/build/csec-op-bridge-notices"

echo "--- assembling $app ---"
rm -rf "$app"
mkdir -p \
  "$app/Contents/MacOS" \
  "$app/Contents/Resources" \
  "$app/Contents/Library/LaunchAgents"
cp "$bin/csec"  "$app/Contents/MacOS/csec"
cp "$bin/csecd" "$app/Contents/MacOS/csecd"
cp "$here/build/csec-op-bridge" "$app/Contents/MacOS/csec-op-bridge"
cp "$bin/csec-rootd" "$root_helper"
csec_identity_render "$here/agent/Info.plist" "$app/Contents/Info.plist"
# The app shows the same release as its binaries' stamps.
plutil -replace CFBundleShortVersionString -string "$release_version" "$app/Contents/Info.plist"
plutil -replace CFBundleVersion -string "$build_number" "$app/Contents/Info.plist"
plutil -insert CSECSourceCommit -string "$source_commit" "$app/Contents/Info.plist"
cp "$root/LICENSE.md" "$app/Contents/Resources/LICENSE.md"
# Notices for the vendored tree-sitter runtime and bash grammar (MIT, with the
# runtime's ICU-derived Unicode tables) compiled into every csec binary.
vendored="$root/agent/Sources/CTreeSitterBash"
mkdir -p "$app/Contents/Resources/ThirdParty"
cp "$vendored/tree-sitter/LICENSE" "$app/Contents/Resources/ThirdParty/tree-sitter-LICENSE"
cp "$vendored/tree-sitter-bash/LICENSE" "$app/Contents/Resources/ThirdParty/tree-sitter-bash-LICENSE"
cp "$vendored/tree-sitter/src/unicode/LICENSE" "$app/Contents/Resources/ThirdParty/icu-LICENSE"
# Go's and each linked module's licence and NOTICE files for csec-op-bridge.
cp -R "$here/build/csec-op-bridge-notices" "$app/Contents/Resources/ThirdParty/csec-op-bridge"
# csec ai puts this directory first on every child's PATH. Shipping it means a
# child whose sandbox allows no writes (Codex read-only) is still guarded,
# instead of csec ai refusing the command for want of a temporary shim. csec
# uses it only while it holds exactly this one file, unwritable by others.
mkdir -p "$app/Contents/Resources/ai-guard"
install -m 0755 "$here/agent/ai-guard/op" "$app/Contents/Resources/ai-guard/op"
# Claude Code's CLAUDE_CODE_SHELL_PREFIX: one absolute path with no options
# (stdio MCP servers run the prefix as their executable), which execs this
# bundle's csec as `csec ai --claude-code-shell` (ClaudeCodeShellPrefix).
# The package's uninstaller, sealed into the app so csec doctor can compare
# the copy the package installs beside the bridge with the one it shipped.
mkdir -p "$app/Contents/Resources/uninstall"
install -m 0755 "$here/libexec/uninstall-csec.sh" "$app/Contents/Resources/uninstall/uninstall-csec.sh"
mkdir -p "$app/Contents/Resources/claude-code-shell"
install -m 0755 "$here/agent/claude-code-shell/csec-claude-code-shell" \
  "$app/Contents/Resources/claude-code-shell/csec-claude-code-shell"
csec_identity_render "$here/agent/LaunchAgents/csecd.plist" "$app/Contents/Library/LaunchAgents/$label.plist"
cp "$PROFILE_PATH" "$app/Contents/embedded.provisionprofile"

for purpose_key in \
  NSCalendarsUsageDescription \
  NSCalendarsFullAccessUsageDescription \
  NSRemindersUsageDescription \
  NSRemindersFullAccessUsageDescription \
  NSAppleEventsUsageDescription; do
  if ! plutil -extract "$purpose_key" raw "$app/Contents/Info.plist" >/dev/null; then
    echo "error: app Info.plist is missing privacy purpose string: $purpose_key" >&2
    exit 1
  fi
done

echo "--- signing inside-out: csec (secondary, Calendar automation entitlement) first ---"
codesign --force --options runtime --timestamp \
  --entitlements "$launcher_entitlements" \
  --identifier "$label.csec" \
  --sign "$SIGN_IDENTITY" \
  "$app/Contents/MacOS/csec"

# The one binary allowed to disable library validation, because the 1Password
# SDK loads AgileBits' dylib. See packaging/agent/csec-op-bridge.entitlements.
echo "--- signing csec-op-bridge (library-validation exemption, scoped here) ---"
codesign --force --options runtime --timestamp \
  --entitlements "$bridge_entitlements" \
  --identifier "$label.opbridge" \
  --sign "$SIGN_IDENTITY" \
  "$app/Contents/MacOS/csec-op-bridge"

echo "--- signing csec-rootd (standalone, no entitlements) ---"
codesign --force --options runtime --timestamp \
  --identifier "$label.rootd" \
  --sign "$SIGN_IDENTITY" \
  "$root_helper"

echo "--- then the bundle: signs csecd (main executable) WITH the keychain and CloudKit entitlements ---"
codesign --force --options runtime --timestamp \
  --entitlements "$agent_entitlements" \
  --sign "$SIGN_IDENTITY" \
  "$app"

# Inspect the final nested signature after the enclosing bundle has been sealed.
for guarded in csec csecd; do
  guarded_entitlements="$(codesign --display --entitlements - "$app/Contents/MacOS/$guarded" 2>&1)"
  if [[ "$guarded_entitlements" == *"disable-library-validation"* ]]; then
    echo "error: $guarded must not carry disable-library-validation" >&2
    exit 1
  fi
done

bridge_entitlements_output="$(codesign --display --entitlements - "$app/Contents/MacOS/csec-op-bridge" 2>&1)"
if [[ "$bridge_entitlements_output" != *"disable-library-validation"* ]]; then
  echo "error: signed csec-op-bridge cannot load the 1Password SDK library" >&2
  exit 1
fi

launcher_entitlements_output="$(codesign --display --entitlements - "$app/Contents/MacOS/csec" 2>&1)"
if [[ "$launcher_entitlements_output" != *"com.apple.security.personal-information.calendars"* ]]; then
  echo "error: signed csec is missing the Calendar automation entitlement" >&2
  exit 1
fi

echo "--- signature (bundle / csecd main, must show keychain-access-groups) ---"
codesign --display --verbose=2 --entitlements - "$app" 2>&1 || true
echo "--- verify ---"
codesign --verify --deep --strict --verbose=2 "$app" 2>&1
codesign --verify --strict --verbose=2 "$root_helper" 2>&1

cat <<EOF

Built + signed:
  $app
  $root_helper
EOF

if [ "${CSEC_BUILD_AND_INSTALL_PIPELINE:-0}" != "1" ]; then
  cat <<EOF
Next (needs you, at the keyboard):
  1. Install it where SMAppService trusts it:
       cp -R "$app" /Applications/
  2. Register the background agent (runs from inside the bundle):
       /Applications/ConvenientSecurity.app/Contents/MacOS/csec install
     Approve "ConvenientSecurity" in System Settings › General › Login Items if asked.
  3. Check it:
       /Applications/ConvenientSecurity.app/Contents/MacOS/csec status

The standalone root helper is installed only by build-pkg.sh; copying the app
alone intentionally does not enable protected regular-file delivery.
EOF
fi
