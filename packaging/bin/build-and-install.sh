#!/usr/bin/env bash
set -euo pipefail

# Build, sign, notarize, package, install, register, and verify every shipping
# component. Run this script as the login user: it elevates only Apple's package
# installer, then registers the per-user LaunchAgent without sudo.

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo_root="$(cd "$here/.." && pwd)"
build="$here/build"
default_profile="$build/convenient-security.mobileprovision"
app="$build/ConvenientSecurity.app"
pkg="$build/ConvenientSecurity.pkg"
root_helper="$build/csec-rootd"

installed_app="/Applications/ConvenientSecurity.app"
installed_csec="$installed_app/Contents/MacOS/csec"
installed_bridge="/Library/Application Support/ConvenientSecurity/bin/csec"
root_label="com.alexspeller.convenient-security.rootd"
agent_label="com.alexspeller.convenient-security"
installed_root_helper="/Library/PrivilegedHelperTools/$root_label"

dry_run=0
refresh_profile=0

usage() {
  cat <<'EOF'
usage: packaging/bin/build-and-install.sh [--refresh-profile] [--dry-run]

Build and install the complete signed Convenient Security stack in one command:
  1. fetch a provisioning profile when missing (or when explicitly refreshed)
  2. build and sign the app, CLI, resident agent, and root helper
  3. notarize and staple the app
  4. build, sign, notarize, and staple the full installer package
  5. install the package with sudo
  6. register or restart the per-user LaunchAgent without sudo
  7. verify installed payload bytes, registration, and root-helper reachability

Options:
  --refresh-profile  Fetch a fresh Developer ID profile before building.
  --dry-run          Print the planned commands without changing anything.
  -h, --help         Show this help.

Configuration is read from packaging/.env. SIGN_IDENTITY and
INSTALLER_IDENTITY default to this repository's documented Stateful Ltd
identities; PROFILE_PATH defaults to packaging/build/convenient-security.mobileprovision.
EOF
}

die() {
  echo "build-and-install: $*" >&2
  exit 1
}

print_command() {
  printf '+'
  printf ' %q' "$@"
  printf '\n'
}

run() {
  print_command "$@"
  if [ "$dry_run" -eq 0 ]; then
    "$@"
  fi
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --refresh-profile)
      refresh_profile=1
      ;;
    --dry-run)
      dry_run=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      die "unknown argument: $1"
      ;;
  esac
  shift
done

cd "$repo_root"

# This file contains only references and identity names. The provisioning and
# notarization scripts retrieve private-key bytes just in time using their
# separately constrained transports; this wrapper never handles those bytes.
requested_dry_run="$dry_run"
requested_refresh_profile="$refresh_profile"
if [ -f "$here/.env" ]; then
  # shellcheck disable=SC1091
  source "$here/.env"
fi
dry_run="$requested_dry_run"
refresh_profile="$requested_refresh_profile"

SIGN_IDENTITY="${SIGN_IDENTITY:-Developer ID Application: Stateful Ltd (8RS6GD89Y7)}"
INSTALLER_IDENTITY="${INSTALLER_IDENTITY:-Developer ID Installer: Stateful Ltd (8RS6GD89Y7)}"
PROFILE_PATH="${PROFILE_PATH:-$default_profile}"
if [[ "$PROFILE_PATH" != /* ]]; then
  PROFILE_PATH="$repo_root/$PROFILE_PATH"
fi
export SIGN_IDENTITY INSTALLER_IDENTITY PROFILE_PATH
export CSEC_BUILD_AND_INSTALL_PIPELINE=1

if [ "$dry_run" -eq 0 ]; then
  [ "$(uname -s)" = "Darwin" ] || die "macOS is required"
  [ "$EUID" -ne 0 ] || die "run as the login user, not root; the script invokes sudo only for package installation"
  : "${OP_ACCOUNT:?set OP_ACCOUNT in packaging/.env}"
  : "${OP_ASC_ITEM:?set OP_ASC_ITEM in packaging/.env}"
  export OP_ACCOUNT OP_ASC_ITEM

  if ! signing_identities="$(/usr/bin/security find-identity -v 2>/dev/null)"; then
    die "could not inspect signing identities in the user keychain"
  fi
  for required_identity in "$SIGN_IDENTITY" "$INSTALLER_IDENTITY"; do
    if [[ "$signing_identities" != *"\"$required_identity\""* ]]; then
      die "missing valid signing identity (certificate plus private key): $required_identity; see packaging/README.md prerequisites"
    fi
  done
fi

for required_script in \
  "$here/bin/provision.sh" \
  "$here/bin/build-agent.sh" \
  "$here/bin/notarize.sh" \
  "$here/bin/build-pkg.sh"; do
  [ -x "$required_script" ] || die "required script is not executable: $required_script"
done

if [ "$refresh_profile" -eq 1 ]; then
  run "$here/bin/provision.sh"
  PROFILE_PATH="$default_profile"
  export PROFILE_PATH
elif [ ! -f "$PROFILE_PATH" ]; then
  if [ "$PROFILE_PATH" != "$default_profile" ]; then
    die "custom PROFILE_PATH does not exist: $PROFILE_PATH"
  fi
  run "$here/bin/provision.sh"
fi

if [ "$dry_run" -eq 0 ]; then
  [ -f "$PROFILE_PATH" ] || die "provisioning profile was not created: $PROFILE_PATH"
fi

run "$here/bin/build-agent.sh"
run "$here/bin/notarize.sh" "$app"
run "$here/bin/build-pkg.sh"
run "$here/bin/notarize.sh" "$pkg"
run /usr/bin/sudo /usr/sbin/installer -pkg "$pkg" -target /

verify_same_file() {
  local built_path="$1"
  local installed_path="$2"
  if ! /usr/bin/cmp -s "$built_path" "$installed_path"; then
    die "installed payload does not match the build: $installed_path"
  fi
  echo "verified installed payload: $installed_path"
}

if [ "$dry_run" -eq 1 ]; then
  print_command /usr/bin/cmp -s "$app/Contents/MacOS/csec" "$installed_csec"
  print_command /usr/bin/cmp -s "$app/Contents/MacOS/csecd" "$installed_app/Contents/MacOS/csecd"
  print_command /usr/bin/cmp -s "$app/Contents/MacOS/csec" "$installed_bridge"
  print_command /usr/bin/cmp -s "$root_helper" "$installed_root_helper"
  print_command "$installed_csec" status
  echo "+ $installed_csec install  # only when the LaunchAgent is not registered"
  echo "+ /bin/launchctl kickstart -k gui/$(id -u)/$agent_label  # when enabled"
  print_command "$installed_csec" status
  print_command "$installed_csec" root-status
  echo "Dry run complete; no build, signing, network, installation, or service changes were made."
  exit 0
fi

verify_same_file "$app/Contents/MacOS/csec" "$installed_csec"
verify_same_file "$app/Contents/MacOS/csecd" "$installed_app/Contents/MacOS/csecd"
verify_same_file "$app/Contents/MacOS/csec" "$installed_bridge"
verify_same_file "$root_helper" "$installed_root_helper"

# SMAppService.register() reports an error for an already-registered service.
# Preserve its approval state on upgrades, registering only when necessary, and
# restart an enabled job so it immediately executes the newly installed bytes.
agent_status="$("$installed_csec" status)"
printf '%s\n' "$agent_status"
case "$agent_status" in
  *"enabled — starts at login"*)
    ;;
  *"registered, awaiting your approval"*)
    ;;
  *)
    run "$installed_csec" install
    ;;
esac

agent_status="$("$installed_csec" status)"
printf '%s\n' "$agent_status"
if [[ "$agent_status" == *"enabled — starts at login"* ]]; then
  run /bin/launchctl kickstart -k "gui/$(id -u)/$agent_label"
  /bin/launchctl print "gui/$(id -u)/$agent_label" >/dev/null
elif [[ "$agent_status" == *"registered, awaiting your approval"* ]]; then
  echo "Convenient Security is installed but needs approval in System Settings > General > Login Items."
else
  die "LaunchAgent did not reach a registered state"
fi

root_ready=0
root_status=""
attempts=0
while [ "$attempts" -lt 10 ]; do
  attempts=$((attempts + 1))
  if root_status="$("$installed_csec" root-status 2>&1)"; then
    printf '%s\n' "$root_status"
    root_ready=1
    break
  fi
  /bin/sleep 0.25
done
[ "$root_ready" -eq 1 ] || die "${root_status:-authenticated root helper did not become reachable}"

echo "Build and installation complete: $installed_app"
