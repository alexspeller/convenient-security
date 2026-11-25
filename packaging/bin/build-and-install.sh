#!/usr/bin/env bash
set -euo pipefail

# Build, sign, notarize, package, install, register, and verify every shipping
# component: the app bundle (csecd, csec, the 1Password bridge), the root
# helper and its LaunchDaemon, the managed Codex hook in /etc/codex, the
# contextual sudo integration (the PAM module and the sudo review helper), and
# the iPhone remote-approval app on the user's paired iPhone. This is the one
# entry point that installs anything; the other scripts in this directory are
# the stages it runs. --uninstall-sudo runs the sudo stage in reverse and
# nothing else.
#
# Run it as the login user: it elevates only Apple's package installer and the
# guarded Codex-hook and sudo-integration installers, then registers the
# per-user LaunchAgent without sudo.
#
# One run at a time per user: a real run holds build_and_install_lock for its
# whole life, waits included, and a second run exits 75 without starting.
#
# An unattended install worker can run this script and wait at the Mac before
# each stage that can raise a native request (presence_checkpoint). The marker
# below tells such a worker this script supports those checkpoints.
# install-checkpoint-v1

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo_root="$(cd "$here/.." && pwd)"
# The Apple team and identifier every component is built and signed under.
# shellcheck source=../lib/identity.sh
. "$here/lib/identity.sh"
csec_identity_load "$repo_root/identity.xcconfig"
build="$here/build"
default_profile="$build/convenient-security.mobileprovision"
app="$build/ConvenientSecurity.app"
pkg="$build/ConvenientSecurity.pkg"
root_helper="$build/csec-rootd"
sudo_module="$build/sudo-pam/pam_csec_sudo.so"
sudo_review_helper="$build/sudo-review/csec-sudo-review"
# Remote approval works only while the Mac and the phone use the same CloudKit
# database. A Developer ID app reaches CloudKit only in Production, so both
# sides are built against Production.
cloudkit_environment="Production"

# The iPhone app is dev-signed by Xcode's automatic signing (the account set up
# in Xcode) and installed on the user's paired iPhone. Its build number is
# stamped per build so the on-device check proves this build is the one there.
# It is then re-signed without get-task-allow (strip_iphone_debugger_entitlement)
# so no debugger can attach to the app that holds the approval keys.
ios_dir="$repo_root/ios"
ios_project="$ios_dir/ConvenientSecurityApproval.xcodeproj"
ios_scheme="ConvenientSecurityApproval"
ios_configuration="Debug"
ios_bundle_id="$csec_identifier.approval"
ios_build="$build/ios"
ios_derived_data="$ios_build/DerivedData"
ios_app="$ios_derived_data/Build/Products/$ios_configuration-iphoneos/ConvenientSecurityApproval.app"
# The notification service extension, embedded in the app and signed on its own.
ios_extension="$ios_app/PlugIns/ConvenientSecurityApprovalNotifications.appex"
ios_devices_json="$ios_build/devices.json"
ios_installed_json="$ios_build/installed-app.json"
ios_signed_entitlements="$ios_build/signed-entitlements.plist"
ios_signing_certificate="$ios_build/signing-certificate"

installed_app="/Applications/ConvenientSecurity.app"
installed_info="$installed_app/Contents/Info.plist"
installed_csec="$installed_app/Contents/MacOS/csec"
installed_bridge="/Library/Application Support/ConvenientSecurity/bin/csec"
installed_uninstaller="/Library/Application Support/ConvenientSecurity/libexec/uninstall-csec.sh"
root_label="$csec_identifier.rootd"
installed_root_helper="/Library/PrivilegedHelperTools/$root_label"
install_receipt="/Library/Application Support/ConvenientSecurity/install-receipt.json"
installed_sudo_module="/usr/local/lib/pam/pam_csec_sudo.so"
installed_sudo_review_helper="/usr/local/libexec/csec-sudo-review"
installed_codex_hook="/private/etc/codex/hooks.json"
# The payload csec setup installs from, and the privileged stages below run
# the same copies, so every install here exercises a buyer's path.
installed_support="/Library/Application Support/ConvenientSecurity"
installed_codex_installer="$installed_support/libexec/install-codex-hook.sh"
installed_sudo_installer="$installed_support/libexec/install-sudo-review.sh"
installed_sudo_policy="$installed_support/libexec/sudo-review-policy.sh"
installed_identity_library="$installed_support/libexec/identity.sh"
installed_identity_file="$installed_support/libexec/identity.xcconfig"
installed_payload_module="$installed_support/sudo-review/pam_csec_sudo.so"
installed_payload_helper="$installed_support/sudo-review/csec-sudo-review"
command_link="/usr/local/bin/csec"
pam_directory="/private/etc/pam.d"
build_and_install_lock="${CSEC_BUILD_AND_INSTALL_LOCK:-$HOME/Library/Caches/convenient-security/build-and-install.lock}"
codex_hook_document="$build/codex-hooks.json"

dry_run=0
# The checkpoint program, job and attempt, when an unattended worker runs this.
presence_checkpoint=""
presence_job=""
presence_attempt=""
refresh_profile=0
allow_downgrade=0
install_sudo=1
install_iphone=1
only_iphone=0
uninstall_sudo=0
iphone_device=""
iphone_name=""
iphone_build_number=""

usage() {
  cat <<'EOF'
usage: packaging/bin/build-and-install.sh [--refresh-profile] [--skip-sudo] [--skip-iphone] [--allow-downgrade] [--dry-run]
       packaging/bin/build-and-install.sh --only-iphone [--allow-downgrade] [--dry-run]
       packaging/bin/build-and-install.sh --uninstall-sudo [--dry-run]

Build and install the complete signed Convenient Security stack in one command:
  1. check that the App Store Connect key can be delivered (csec, or on a
     first build with no csec installed 1Password's CLI) before starting the
     expensive build
  2. fetch a provisioning profile when missing (or when explicitly refreshed)
  3. build and sign the app, CLI, resident agent, and root helper
  4. build and verify the sudo PAM module and the sudo review helper, which
     the package carries for csec setup even with --skip-sudo
  5. notarize and staple the app
  6. build, sign, notarize, and staple the full installer package; steps 5
     and 6 share one delivery of the App Store Connect key
  7. install the package with sudo
  8. register or restart the per-user LaunchAgent without sudo and require
     authenticated control, SSH, and root-helper health
  9. install the managed Codex hook with sudo: the package's copy of the
     guarded installer, the one csec setup runs, merges csec's handler into
     /etc/codex/hooks.json using the installed, verified csec, keeps every
     other hook, and restores the previous file on failure
 10. install the sudo integration with sudo: the package's copy of the
     guarded installer, the one csec setup runs, activates the PAM line when
     absent, replaces the module and helper with the package's, and keeps
     them only after a live sudo it runs as you was approved through the new
     helper
 11. verify every installed payload against the build (the setup payload and
     the csec link on PATH included), that the package's
     root-owned install receipt records the built root helper's sha256, and
     that the installed csecd is signed with the CloudKit container in the
     Production environment
 12. run csec doctor and require authenticated control, SSH, root-helper,
     managed-Codex-hook, and sudo-review health
 13. build the iPhone approval app (XcodeGen pinned by mise, xcodebuild with
     Xcode's automatic Apple Development signing), re-sign it without
     get-task-allow and require that, install it on the paired iPhone with
     devicectl, and verify the build number the phone reports

Before building, the Developer ID profile must authorize every restricted
entitlement csecd is signed with, the CloudKit container included; the build
stops with the portal fix otherwise. The iPhone stage checks for mise, Xcode
and exactly one available paired iPhone before the Mac build starts.

Options:
  --refresh-profile  Fetch a fresh Developer ID profile before building.
  --skip-sudo        Build and install everything except the sudo integration
                     (the package still carries its payload for csec setup).
                     An already active but stale integration then still fails
                     csec doctor at the end, by design.
  --skip-iphone      Build and install everything except the iPhone app.
  --only-iphone      Build and install only the iPhone app (step 13), leaving
                     the Mac installation alone: the rerun after an iPhone
                     stage failure.
  --uninstall-sudo   Remove the sudo integration and nothing else, building
                     nothing: the guarded stage takes csec's lines out of
                     /etc/pam.d/sudo_local (putting back the stock file it
                     kept when nothing else changed since), runs a live sudo
                     as you that must succeed through Apple's Touch ID or
                     password, and only then deletes the PAM module, the
                     review helper and any other csec-sudo-review file; a
                     failed sudo restores sudo_local. The run then checks that
                     nothing of the integration is left.
  --allow-downgrade  Install even though this checkout lacks the commit the
                     installed csec was built from, or numbers a lower
                     version or build: a deliberate rollback. Without it the
                     package itself refuses to replace a higher release.
                     csecd keeps saved approvals it cannot read as found, and
                     the final csec doctor fails until the newer build is
                     back. A build from before that hold existed (before the
                     CSECSourceCommit stamp) overwrites them instead.
  --dry-run          Print the planned commands without changing anything.
  -h, --help         Show this help.

Configuration is read from packaging/.env. SIGN_IDENTITY and
INSTALLER_IDENTITY default to this repository's documented Stateful Ltd
identities; PROFILE_PATH defaults to packaging/build/convenient-security.mobileprovision.
CSEC_IPHONE_DEVICE names the iPhone to install onto (its name, UDID or
devicectl identifier) when more than one paired iPhone is available.

Only one run installs at a time: a real run (not --dry-run) holds
~/Library/Caches/convenient-security/build-and-install.lock until it exits, and
another run exits 75 at once, naming the holder, with nothing attempted.

An unattended install worker sets INSTALL_CHECKPOINT (the absolute path of its
checkpoint program), INSTALL_CHECKPOINT_JOB and INSTALL_CHECKPOINT_ATTEMPT.
Before each stage that can raise a native request (provisioning and
notarization's key, approval restoration, each sudo, the iPhone install) the
run then calls
  "$INSTALL_CHECKPOINT" checkpoint "$INSTALL_CHECKPOINT_JOB" --attempt "$INSTALL_CHECKPOINT_ATTEMPT" --stage STAGE
which returns once someone is at the Mac. A nonzero exit (a cancelled or stale
attempt) stops the run there, with the usual recovery. The checkpoint only
says the Mac is attended: every request still needs its own approval, and a
failed one is never retried. Set all three or none.
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
    # The install lock's descriptor stays with this script: a child that
    # outlived it must not keep every later install out.
    "$@" 9>&-
  fi
}

# Takes the per-user install lock for the rest of this run, or exits 75
# (EX_TEMPFAIL) at once, before any stage, naming the run that holds it. The
# lock is a flock on descriptor 9, so it ends with this process however it
# ends, and no stale file can keep a later install out.
acquire_install_lock() {
  local holder
  /bin/mkdir -p "$(dirname "$build_and_install_lock")" ||
    die "could not create the directory of the install lock $build_and_install_lock"
  exec 9>>"$build_and_install_lock" ||
    die "could not open the install lock $build_and_install_lock"
  if ! /usr/bin/lockf -s -t 0 9; then
    holder="$(/usr/bin/head -c 512 "$build_and_install_lock" 2>/dev/null | /usr/bin/tr -cd '[:print:]' || true)"
    echo "build-and-install: another build-and-install.sh is installing (${holder:-holder unknown}); its lock is $build_and_install_lock." >&2
    echo "build-and-install: nothing was attempted; run again once it has finished." >&2
    exit 75
  fi
  local owner="run by hand"
  if [ -n "$presence_checkpoint" ]; then
    owner="install job $presence_job"
  fi
  printf 'pid %s, %s, from %s, since %s\n' "$$" "$owner" "$repo_root" \
    "$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ)" >"$build_and_install_lock"
}

# An unattended worker sets all three variables; a manual run sets none.
# Anything in between is a broken caller, refused before anything runs.
configure_presence_checkpoints() {
  local checkpoint="${INSTALL_CHECKPOINT:-}" job="${INSTALL_CHECKPOINT_JOB:-}"
  local attempt="${INSTALL_CHECKPOINT_ATTEMPT:-}"
  presence_checkpoint=""
  if [ -z "$checkpoint$job$attempt" ]; then
    return
  fi
  if [ -z "$checkpoint" ] || [ -z "$job" ] || [ -z "$attempt" ]; then
    die "INSTALL_CHECKPOINT, INSTALL_CHECKPOINT_JOB and INSTALL_CHECKPOINT_ATTEMPT are set together or not at all"
  fi
  if [[ "$checkpoint" != /* ]] || [ ! -f "$checkpoint" ] || [ ! -x "$checkpoint" ]; then
    die "INSTALL_CHECKPOINT must be the absolute path of an executable: $checkpoint"
  fi
  # Each becomes an argument of the checkpoint, so neither may read as an option.
  local identifier='^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'
  if ! [[ "$job" =~ $identifier ]] || ! [[ "$attempt" =~ $identifier ]]; then
    die "INSTALL_CHECKPOINT_JOB and INSTALL_CHECKPOINT_ATTEMPT must be 1-128 letters, digits, '.', '_' or '-', starting with a letter or digit"
  fi
  presence_checkpoint="$checkpoint"
  presence_job="$job"
  presence_attempt="$attempt"
}

# Under an unattended worker, waits for someone at the Mac before the stage
# named in $stage, which can raise a native request; $1 names that stage for
# the worker.
# It only says the Mac is attended. It never answers or repeats a request: a
# stage that fails ends the run. Unattended, csec roots a grant at the command
# that asked for it, so this sibling process can use none of them.
presence_checkpoint() {
  [ -n "$presence_checkpoint" ] || return 0
  local next_stage="$stage"
  stage="presence checkpoint before $next_stage"
  run "$presence_checkpoint" checkpoint "$presence_job" \
    --attempt "$presence_attempt" --stage "$1" </dev/null
  stage="$next_stage"
}

# Sourceable so regression tests can replace command execution without any host
# installation, signing, or service changes. Production always enters main below.
# The managed Codex hook document is generated rather than built: csec merges
# its handler into the installed file, deterministically, so regenerating it as
# the login user and comparing bytes verifies what the root stage installed.
write_codex_hook_document() {
  if [ "$dry_run" -eq 1 ]; then
    print_command "$installed_csec" hook-config codex --system
    return
  fi
  "$installed_csec" hook-config codex --system > "$codex_hook_document"
}

# The build installs what this checkout holds. A checkout that lacks a commit
# already on origin/main (a main nobody pulled, while worktrees pushed past it)
# would replace a newer csec with an older one and silently take back whatever
# those commits fixed, so it is refused before anything is built. origin/main
# is read as last fetched, which every push from this repository also moves, so
# the check needs no network. A rollback is a revert on main, not an install of
# an older commit.
require_checkout_contains_main() {
  local upstream="origin/main"
  if [ "$dry_run" -eq 1 ]; then
    print_command git -C "$repo_root" merge-base --is-ancestor "$upstream" HEAD
    return
  fi
  if ! git -C "$repo_root" rev-parse --verify --quiet "$upstream^{commit}" >/dev/null; then
    die "$repo_root has no $upstream to compare with, so it cannot tell whether this build is older than what is installed; run: git -C $repo_root fetch origin"
  fi
  if git -C "$repo_root" merge-base --is-ancestor "$upstream" HEAD; then
    return
  fi
  local missing count noun=commit
  count="$(git -C "$repo_root" rev-list --count "HEAD..$upstream")"
  missing="$(git -C "$repo_root" log --no-decorate --format='  %h %s' -n 10 "HEAD..$upstream")"
  [ "$count" -eq 1 ] || noun=commits
  die "this checkout lacks $count $noun already on $upstream, so installing it would replace csec with an older build:
$missing
Bring them in first: git pull --ff-only on main, or git merge $upstream on a branch."
}

# Rebase can replace the installed commits without dropping their changes.
# git cherry checks non-merge patches, but ignores merges: each absent merge's
# complete tree must also occur in HEAD's history, so a lost conflict resolution
# or manual merge amendment cannot pass just because its parent patches do.
# Every Git failure refuses equivalence; the caller keeps the downgrade guard.
checkout_has_equivalent_installed_history() {
  local installed="$1" patches merge_trees head_trees tree
  patches="$(git -C "$repo_root" cherry HEAD "$installed")" || return 1
  case "$patches" in
    +*|*$'\n+'*) return 1 ;;
  esac
  merge_trees="$(git -C "$repo_root" log --merges --format=%T "HEAD..$installed")" || return 1
  [ -n "$merge_trees" ] || return 0
  head_trees="$(git -C "$repo_root" log --format=%T HEAD)" || return 1
  for tree in $merge_trees; do
    case $'\n'"$head_trees"$'\n' in
      *$'\n'"$tree"$'\n'*) ;;
      *) return 1 ;;
    esac
  done
}

# The installed app names the commit it was built from (CSECSourceCommit,
# stamped by build-agent.sh). Refuse a checkout that lacks its changes unless
# --allow-downgrade says the rollback is deliberate. An ancestor proves they
# are in this history; otherwise account for equivalent rebased patches and
# flattened merges. An app installed before the stamp existed is not compared.
require_checkout_contains_installed() {
  if [ "$dry_run" -eq 1 ]; then
    print_command git -C "$repo_root" merge-base --is-ancestor INSTALLED_CSECSourceCommit HEAD
    return
  fi
  [ -f "$installed_info" ] || return 0
  local installed
  if ! installed="$(/usr/bin/plutil -extract CSECSourceCommit raw -o - -- "$installed_info" 2>/dev/null)"; then
    echo "build-and-install: the installed csec predates the commit stamp, so it is not compared with this checkout" >&2
    return 0
  fi
  [[ "$installed" =~ ^[0-9a-f]{40}$ ]] ||
    die "the installed csec's commit stamp is not a commit id: $installed"
  if git -C "$repo_root" merge-base --is-ancestor "$installed" HEAD 2>/dev/null; then
    return
  fi
  local short="${installed:0:7}" problem
  if git -C "$repo_root" cat-file -e "$installed^{commit}" 2>/dev/null; then
    if checkout_has_equivalent_installed_history "$installed"; then
      echo "build-and-install: the installed csec ($short) has equivalent patches and merge trees in this checkout's history" >&2
      return
    fi
    local count noun=commit missing
    count="$(git -C "$repo_root" rev-list --count "HEAD..$installed")"
    missing="$(git -C "$repo_root" log --no-decorate --format='  %h %s' -n 10 "HEAD..$installed")"
    [ "$count" -eq 1 ] || noun=commits
    problem="this checkout lacks $count $noun the installed csec ($short) was built with:
$missing"
  else
    problem="the installed csec was built from $short, a commit this checkout does not have"
  fi
  if [ "$allow_downgrade" -eq 1 ]; then
    echo "build-and-install: $problem
Installing anyway (--allow-downgrade)." >&2
    return
  fi
  die "$problem
Installing this checkout would replace csec with an older build. Merge the installed commit first (git merge $short),
or pass --allow-downgrade for a deliberate rollback."
}

verify_same_file() {
  local built_path="$1"
  local installed_path="$2"
  if [ "$dry_run" -eq 1 ]; then
    print_command /usr/bin/cmp -s "$built_path" "$installed_path"
    return
  fi
  if ! /usr/bin/cmp -s "$built_path" "$installed_path"; then
    die "installed payload does not match the build: $installed_path"
  fi
  echo "verified installed payload: $installed_path"
}

# The package links csec onto PATH unless something else already holds the
# name; on this Mac that link must exist and name the installed launcher.
verify_command_link() {
  if [ "$dry_run" -eq 1 ]; then
    print_command /usr/bin/readlink "$command_link"
    return
  fi
  local linked
  linked="$(/usr/bin/readlink "$command_link" 2>/dev/null)" ||
    die "$command_link is not a symlink, so csec is not on PATH; move whatever is there aside and reinstall"
  [ "$linked" = "$installed_csec" ] ||
    die "$command_link links to $linked, not $installed_csec; remove it and reinstall"
  echo "verified csec on PATH: $command_link -> $installed_csec"
}

# Prints why the install receipt ($1), owned by uid $2 and writable only by it,
# does not record exactly each built file ($3, $5, ...) at its installed path
# ($4, $6, ...) and nothing else; returns nonzero if it does not. The
# postinstall writes the receipt; a stale or missing one makes a persistence
# watch that reads it treat this install as drift.
check_install_receipt() {
  /usr/bin/python3 - "$@" <<'PY'
import hashlib
import json
import os
import stat
import sys

receipt_path, owner, *pairs = sys.argv[1:]
if not pairs or len(pairs) % 2:
    sys.exit("build-and-install: check_install_receipt needs BUILT INSTALLED pairs")
artifacts = {}
for built_path, installed_path in zip(pairs[::2], pairs[1::2]):
    with open(built_path, "rb") as handle:
        artifacts[installed_path] = hashlib.sha256(handle.read()).hexdigest()
expected = {"schema": 1, "producer": "csec", "artifacts": artifacts}
try:
    descriptor = os.open(receipt_path, os.O_RDONLY | os.O_NOFOLLOW)
except OSError as error:
    sys.exit(f"build-and-install: install receipt {receipt_path} is unreadable: {error.strerror}")
with os.fdopen(descriptor, "rb") as handle:
    info = os.fstat(handle.fileno())
    data = handle.read(1024 * 1024 + 1)
problems = []
if not stat.S_ISREG(info.st_mode) or info.st_uid != int(owner) or info.st_mode & 0o022:
    problems.append("is not a regular file owned by the installer and writable only by it")
if len(data) > 1024 * 1024:
    problems.append("is larger than 1 MiB")
try:
    recorded = json.loads(data)
except ValueError:
    recorded = None
# json equality alone takes true or 1.0 for 1; the watch requires the integer.
if recorded != expected or type(recorded.get("schema")) is not int:
    problems.append(f"does not record exactly the built sha256 at each of {', '.join(artifacts)}")
for problem in problems:
    print(f"build-and-install: install receipt {receipt_path} {problem}", file=sys.stderr)
sys.exit(1 if problems else 0)
PY
}

verify_install_receipt() {
  if [ "$dry_run" -eq 1 ]; then
    print_command check_install_receipt "$install_receipt" 0 "$root_helper" "$installed_root_helper" \
      "$app/Contents/MacOS/csec" "$installed_bridge"
    return
  fi
  check_install_receipt "$install_receipt" 0 "$root_helper" "$installed_root_helper" \
    "$app/Contents/MacOS/csec" "$installed_bridge" ||
    die "the install receipt does not record the installed root helper and bridge: $install_receipt"
  echo "verified install receipt: $install_receipt"
}

# Prints each way a signed-entitlements plist ($1) misses the CloudKit container
# ($2) or environment ($3), naming the signed code ($4); returns nonzero if any.
check_cloudkit_entitlements() {
  /usr/bin/python3 - "$@" <<'PY'
import plistlib
import sys

signed_path, container, environment, label = sys.argv[1:5]
try:
    with open(signed_path, "rb") as handle:
        signed = plistlib.load(handle)
except Exception:
    signed = None
if not isinstance(signed, dict):
    sys.exit(f"build-and-install: {label} has no readable signed entitlements")
problems = []
containers = signed.get("com.apple.developer.icloud-container-identifiers")
if not isinstance(containers, list) or container not in containers:
    problems.append(f"com.apple.developer.icloud-container-identifiers does not name {container}")
services = signed.get("com.apple.developer.icloud-services")
if not isinstance(services, list) or "CloudKit" not in services:
    problems.append("com.apple.developer.icloud-services does not name CloudKit")
signed_environment = signed.get("com.apple.developer.icloud-container-environment")
if signed_environment != environment:
    problems.append(f"com.apple.developer.icloud-container-environment is "
                    f"{signed_environment or 'absent'}, not {environment}")
for problem in problems:
    print(f"build-and-install: {label}: {problem}", file=sys.stderr)
sys.exit(1 if problems else 0)
PY
}

# Prints why a signed-entitlements plist ($1) lets a debugger attach to the
# signed code ($2 names it); returns nonzero if it does. get-task-allow (and
# the macOS spelling) is refused unless it is absent or false.
check_no_debugger_entitlement() {
  /usr/bin/python3 - "$@" <<'PY'
import plistlib
import sys

signed_path, label = sys.argv[1:3]
try:
    with open(signed_path, "rb") as handle:
        signed = plistlib.load(handle)
except Exception:
    signed = None
if not isinstance(signed, dict):
    sys.exit(f"build-and-install: {label} has no readable signed entitlements")
problems = [key for key in ("get-task-allow", "com.apple.security.get-task-allow")
            if key in signed and signed[key] is not False]
for key in problems:
    print(f"build-and-install: {label}: {key} is signed in, so a debugger can attach to it",
          file=sys.stderr)
sys.exit(1 if problems else 0)
PY
}

# Rewrites a signed-entitlements plist ($1) in place without get-task-allow
# (and the macOS spelling), keeping every other entitlement exactly.
remove_debugger_entitlements() {
  /usr/bin/python3 - "$@" <<'PY'
import plistlib
import sys

path = sys.argv[1]
with open(path, "rb") as handle:
    signed = plistlib.load(handle)
if not isinstance(signed, dict):
    sys.exit(f"build-and-install: {path} is not an entitlements dictionary")
for key in ("get-task-allow", "com.apple.security.get-task-allow"):
    signed.pop(key, None)
with open(path, "wb") as handle:
    plistlib.dump(signed, handle, fmt=plistlib.FMT_XML)
PY
}

# The container the Mac and the phone share, derived from identity.xcconfig as
# csecd's entitlements and the iPhone app's are.
cloudkit_container() {
  printf '%s\n' "$csec_cloudkit_container"
}

# Writes the entitlements signed code ($1) carries, as an XML plist, to $2.
read_signed_entitlements() {
  /usr/bin/codesign --display --entitlements - --xml "$1" > "$2" 2>/dev/null
}

# Signed code ($1, an app bundle) must carry the shared CloudKit container in
# the Production environment, or its remote-approval mailbox is not the other
# side's. $2 names it in messages. With $3 = no-debugger, the same signed
# entitlements must also carry no get-task-allow.
verify_cloudkit_signature() {
  local signed_code="$1"
  local label="$2"
  local forbid_debugger="${3:-}"
  if [ "$dry_run" -eq 1 ]; then
    print_command /usr/bin/codesign --display --entitlements - --xml "$signed_code"
    return
  fi
  local container signed_entitlements result=0 debuggable=0
  container="$(cloudkit_container)"
  signed_entitlements="$(/usr/bin/mktemp "${TMPDIR:-/tmp}/csec-signed-entitlements.XXXXXX")"
  if ! read_signed_entitlements "$signed_code" "$signed_entitlements"; then
    result=1
    echo "build-and-install: cannot read the signed entitlements of $signed_code" >&2
  else
    if ! check_cloudkit_entitlements "$signed_entitlements" "$container" \
        "$cloudkit_environment" "$label"; then
      result=1
    fi
    if [ "$forbid_debugger" = no-debugger ] &&
        ! check_no_debugger_entitlement "$signed_entitlements" "$label"; then
      debuggable=1
    fi
  fi
  /bin/rm -f "$signed_entitlements"
  [ "$result" -eq 0 ] || die "$label is not signed for CloudKit container $container ($cloudkit_environment)"
  [ "$debuggable" -eq 0 ] || die "$label is signed with get-task-allow; it must not be debuggable"
  if [ "$forbid_debugger" = no-debugger ]; then
    echo "verified $label signature: CloudKit $container ($cloudkit_environment), no get-task-allow"
  else
    echo "verified $label signature: CloudKit $container ($cloudkit_environment)"
  fi
}

# Picks the iPhone to install onto from `devicectl list devices` JSON ($1):
# the one physical, paired, available iPhone, or the one CSEC_IPHONE_DEVICE
# ($2) names by devicectl identifier, UDID, or name. Prints
# "<identifier><TAB><name>"; explains and returns nonzero otherwise.
select_iphone_from_json() {
  /usr/bin/python3 - "$1" "${2-}" <<'PY'
import json
import sys

devices_path, wanted = sys.argv[1], sys.argv[2]
skip = "or pass --skip-iphone to install everything else"
try:
    with open(devices_path) as handle:
        devices = json.load(handle)["result"]["devices"]
except Exception as error:
    sys.exit(f"build-and-install: cannot read the devicectl device list ({type(error).__name__})")

phones = []
for device in devices:
    hardware = device.get("hardwareProperties", {})
    if (hardware.get("platform") != "iOS" or hardware.get("deviceType") != "iPhone"
            or hardware.get("reality") != "physical"):
        continue
    connection = device.get("connectionProperties", {})
    phones.append({
        "identifier": device.get("identifier", ""),
        "udid": hardware.get("udid", ""),
        "name": device.get("deviceProperties", {}).get("name", "iPhone"),
        "paired": connection.get("pairingState") == "paired",
        # devicectl lists a device it cannot reach as "unavailable".
        "available": connection.get("tunnelState", "unavailable") != "unavailable",
    })


def names(candidates):
    return ", ".join(sorted(phone["name"] for phone in candidates)) or "none"


if wanted:
    chosen = [phone for phone in phones
              if wanted in (phone["identifier"], phone["udid"], phone["name"])]
    if len(chosen) != 1:
        sys.exit(f"build-and-install: CSEC_IPHONE_DEVICE={wanted} names "
                 f"{len(chosen)} iPhones known to this Mac (known: {names(phones)}); "
                 f"set it to one iPhone's name, UDID or devicectl identifier, {skip}")
    phone = chosen[0]
    if not (phone["paired"] and phone["available"]):
        sys.exit(f"build-and-install: {phone['name']} is not an available paired iPhone: "
                 "unlock it, keep it on this Mac's network or cable, and check it is "
                 f"paired in Xcode (Window > Devices and Simulators), {skip}")
else:
    ready = [phone for phone in phones if phone["paired"] and phone["available"]]
    if len(ready) != 1:
        if not ready:
            reason = "no available paired iPhone"
            fix = ("connect and unlock the iPhone, enable Developer Mode, and pair it "
                   "in Xcode (Window > Devices and Simulators)")
        else:
            reason = f"{len(ready)} available paired iPhones ({names(ready)})"
            fix = "set CSEC_IPHONE_DEVICE in packaging/.env to the one to install onto"
        sys.exit(f"build-and-install: {reason}; {fix}, {skip}")
    phone = ready[0]
if not phone["identifier"]:
    sys.exit(f"build-and-install: devicectl reported no identifier for {phone['name']}")
print(f"{phone['identifier']}\t{phone['name']}")
PY
}

# Prints "<bundle version><TAB><short version>" for the app ($2) in a
# `devicectl device info apps` JSON result ($1); returns nonzero if absent.
installed_iphone_app_versions() {
  /usr/bin/python3 - "$1" "$2" <<'PY'
import json
import sys

apps_path, bundle_id = sys.argv[1], sys.argv[2]
try:
    with open(apps_path) as handle:
        apps = json.load(handle)["result"]["apps"]
except Exception as error:
    sys.exit(f"build-and-install: cannot read the devicectl app list ({type(error).__name__})")
matches = [app for app in apps if app.get("bundleIdentifier") == bundle_id]
if len(matches) != 1:
    sys.exit(f"build-and-install: the iPhone reports {len(matches)} installed apps "
             f"with bundle identifier {bundle_id}")
print(f"{matches[0].get('bundleVersion', '')}\t{matches[0].get('version', '')}")
PY
}

# CURRENT_PROJECT_VERSION in ios/project.yml, which must be one integer; the
# installer appends a per-build stamp to it.
ios_base_build_number() {
  local line base=""
  while IFS= read -r line; do
    if [[ "$line" =~ ^[[:space:]]+CURRENT_PROJECT_VERSION:[[:space:]]*\"?([0-9]+)\"?[[:space:]]*$ ]]; then
      [ -z "$base" ] || return 1
      base="${BASH_REMATCH[1]}"
    fi
  done < "$ios_dir/project.yml"
  [ -n "$base" ] || return 1
  printf '%s\n' "$base"
}

# Finds the iPhone to install onto; in a dry run, names it without asking.
select_iphone() {
  if [ "$dry_run" -eq 1 ]; then
    print_command /usr/bin/xcrun devicectl list devices --json-output "$ios_devices_json"
    iphone_device="${CSEC_IPHONE_DEVICE:-selected-iphone}"
    iphone_name="$iphone_device"
    return
  fi
  local selection
  /bin/mkdir -p "$ios_build"
  /bin/rm -f "$ios_devices_json"
  if ! /usr/bin/xcrun devicectl list devices --json-output "$ios_devices_json" >/dev/null; then
    die "devicectl could not list devices; check that full Xcode is selected (xcode-select -p), or pass --skip-iphone"
  fi
  selection="$(select_iphone_from_json "$ios_devices_json" "${CSEC_IPHONE_DEVICE:-}")" ||
    die "no iPhone to install the approval app onto (see above)"
  IFS=$'\t' read -r iphone_device iphone_name <<<"$selection"
  echo "iPhone for the approval app: $iphone_name"
}

# Xcode's development signing always gives the app get-task-allow, which lets
# a debugger attach to it — and to its Face ID-gated approval keys' users —
# from this Mac, through the paired phone's developer tunnel. The build setting
# meant for this, CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO, does not remove it
# from an iOS device build (the development profile's value is merged in
# regardless), and Xcode refuses an entitlements file that sets it false. So
# each bundle Xcode signed is re-signed here by the same identity, with exactly
# the entitlements Xcode computed for it minus get-task-allow: the development
# profile permits that entitlement but does not require it. Inside out: the
# notification extension first, then the app, whose seal covers the extension
# as re-signed.
strip_iphone_debugger_entitlement() {
  resign_without_debugger "$ios_extension" "iPhone notification extension" \
    "$ios_build/extension-signed-entitlements.plist" "$ios_build/extension-signing-certificate"
  resign_without_debugger "$ios_app" "iPhone app" "$ios_signed_entitlements" "$ios_signing_certificate"
}

# Re-signs one bundle ($1, named $2 in messages) without get-task-allow, by the
# identity that signed it; $3 and $4 are where its entitlements and signing
# certificates are read to.
resign_without_debugger() {
  local bundle="$1" label="$2" entitlements="$3" certificate="$4"
  if [ "$dry_run" -eq 1 ]; then
    print_command /usr/bin/codesign --display "--extract-certificates=$certificate" \
      --entitlements - --xml "$bundle"
    print_command /usr/bin/codesign --force --sign XCODE_SIGNING_IDENTITY_SHA1 \
      --entitlements "$entitlements" --timestamp=none --generate-entitlement-der "$bundle"
    return
  fi
  local identity
  [ -d "$bundle" ] || die "the iPhone build produced no $label at $bundle"
  /bin/mkdir -p "$ios_build"
  /bin/rm -f "$entitlements" "$certificate"*
  /usr/bin/codesign --display "--extract-certificates=$certificate" \
    --entitlements - --xml "$bundle" > "$entitlements" 2>/dev/null ||
    die "cannot read how Xcode signed $bundle"
  remove_debugger_entitlements "$entitlements" ||
    die "cannot read the entitlements Xcode signed $bundle with"
  # A codesign identity is named by its certificate's SHA-1: the leaf
  # certificate of the signature Xcode made.
  identity="$(/usr/bin/shasum -a 1 "${certificate}0" | /usr/bin/awk '{ print toupper($1) }')"
  [[ "$identity" =~ ^[0-9A-F]{40}$ ]] || die "cannot tell which identity signed $bundle"
  /usr/bin/codesign --force --sign "$identity" --entitlements "$entitlements" \
    --timestamp=none --generate-entitlement-der "$bundle" ||
    die "could not re-sign $bundle without get-task-allow"
  echo "re-signed the $label without get-task-allow"
}

# The built app, and the notification extension inside it, must be the build
# this run stamped, signed for the Mac's CloudKit database, and not debuggable.
verify_iphone_build() {
  if [ "$dry_run" -eq 0 ]; then
    local built_version extension_version
    built_version="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$ios_app/Info.plist")" ||
      die "the iPhone build produced no app at $ios_app"
    [ "$built_version" = "$iphone_build_number" ] ||
      die "the built iPhone app has build $built_version, not $iphone_build_number"
    extension_version="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$ios_extension/Info.plist")" ||
      die "the iPhone build has no notification extension at $ios_extension"
    [ "$extension_version" = "$iphone_build_number" ] ||
      die "the built notification extension has build $extension_version, not $iphone_build_number"
  fi
  verify_cloudkit_signature "$ios_extension" "iPhone notification extension" no-debugger
  verify_cloudkit_signature "$ios_app" "iPhone app" no-debugger
}

# Reads back what the phone has installed: this run's build number, and the
# version the build carries.
verify_installed_iphone_app() {
  if [ "$dry_run" -eq 1 ]; then
    print_command /usr/bin/xcrun devicectl device info apps --device "$iphone_device" \
      --bundle-id "$ios_bundle_id" --json-output "$ios_installed_json"
    return
  fi
  local installed installed_build installed_version built_version
  /bin/rm -f "$ios_installed_json"
  /usr/bin/xcrun devicectl device info apps --device "$iphone_device" \
    --bundle-id "$ios_bundle_id" --json-output "$ios_installed_json" >/dev/null ||
    die "devicectl could not list the apps on $iphone_name"
  installed="$(installed_iphone_app_versions "$ios_installed_json" "$ios_bundle_id")" ||
    die "the approval app is not installed on $iphone_name"
  IFS=$'\t' read -r installed_build installed_version <<<"$installed"
  built_version="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$ios_app/Info.plist")"
  if [ "$installed_build" != "$iphone_build_number" ] || [ "$installed_version" != "$built_version" ]; then
    die "$iphone_name has the approval app $installed_version ($installed_build), not the build just installed, $built_version ($iphone_build_number)"
  fi
  echo "verified iPhone app on $iphone_name: $ios_bundle_id $installed_version ($installed_build)"
}

# Fails before the Mac build starts when the iPhone stage cannot run at the end.
preflight_iphone() {
  command -v mise >/dev/null 2>&1 ||
    die "the iPhone stage needs mise, which installs the XcodeGen pinned in .tool-versions; install mise, or pass --skip-iphone"
  /usr/bin/xcrun --find devicectl >/dev/null 2>&1 ||
    die "the iPhone stage needs full Xcode (devicectl); select it with xcode-select, or pass --skip-iphone"
  select_iphone
}

perform_iphone_install() {
  stage="iPhone app project generation"
  # The app shares the agent package's generated identity source.
  run csec_identity_write_swift "$repo_root/agent/Sources/CSECBuildIdentity/BuildIdentity.swift"
  run mise exec -C "$repo_root" -- xcodegen generate --quiet --spec "$ios_dir/project.yml"

  stage="iPhone app build and signing"
  local base_build_number
  base_build_number="$(ios_base_build_number)" ||
    die "ios/project.yml must set CURRENT_PROJECT_VERSION once, to an integer"
  iphone_build_number="$base_build_number.$(/bin/date -u +%s)"
  run /usr/bin/xcodebuild -quiet -jobs 2 \
    -project "$ios_project" \
    -scheme "$ios_scheme" \
    -configuration "$ios_configuration" \
    -destination generic/platform=iOS \
    -derivedDataPath "$ios_derived_data" \
    -allowProvisioningUpdates \
    -allowProvisioningDeviceRegistration \
    "CURRENT_PROJECT_VERSION=$iphone_build_number" \
    build
  strip_iphone_debugger_entitlement
  verify_iphone_build

  stage="iPhone selection"
  select_iphone

  stage="iPhone app installation"
  presence_checkpoint iphone-install
  run /usr/bin/xcrun devicectl device install app --device "$iphone_device" "$ios_app"

  stage="iPhone app verification"
  verify_installed_iphone_app
}

begin_install_session() {
  stage="preflight"
  package_attempted=0
  mac_verified=0
  installation_verified=0
  trap 'finish_install "$?"' EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
}

finish_install() {
  local result="$1"
  trap - EXIT
  if [ "$uninstall_sudo" -eq 1 ]; then
    finish_sudo_uninstall "$result"
    return
  fi
  if [ "$result" -eq 0 ] && [ "$installation_verified" -eq 1 ]; then
    if [ "$only_iphone" -eq 0 ]; then
      echo "Build and installation complete: $installed_app"
    fi
    if [ "$install_iphone" -eq 1 ]; then
      echo "iPhone approval app installed and verified on $iphone_name: $ios_bundle_id ($iphone_build_number)"
    fi
    return
  fi
  if [ "$dry_run" -eq 1 ] && [ "$result" -eq 0 ]; then
    return
  fi
  # A premature successful exit is still an incomplete installation.
  [ "$result" -ne 0 ] || result=1
  echo >&2
  echo "build-and-install: INSTALLATION FAILED during $stage (exit $result)." >&2
  if [ "$only_iphone" -eq 1 ] || [ "$mac_verified" -eq 1 ]; then
    # The iPhone stage runs only once the Mac side has passed csec doctor and
    # csec status, and never touches it; there is nothing on the Mac to repair.
    if [ "$only_iphone" -eq 1 ]; then
      echo "The Mac installation was not changed." >&2
    else
      echo "The Mac installation is complete and verified (csec doctor and csec status passed); only the iPhone app stage failed." >&2
    fi
    echo "Fix the reported failure, then install just the iPhone app with: packaging/bin/build-and-install.sh --only-iphone" >&2
  elif [ "$package_attempted" -eq 1 ] && [ "$dry_run" -eq 0 ]; then
    echo "Installed files may have changed. Package-installer success is not overall installation success." >&2
    echo "Checking and repairing the installed runtime before exiting..." >&2
    # Preserve the original error even if recovery succeeds. A sudo failure must
    # stay a failure, and its guarded stage owns its own PAM/helper rollback.
    if run "$installed_csec" doctor --runtime; then
      echo "Runtime recovery verified: agent, SSH, and root-helper checks passed." >&2
    else
      echo "RUNTIME RECOVERY FAILED: run csec doctor; the installed runtime is not verified healthy." >&2
    fi
    if run "$installed_csec" doctor --check; then
      echo "Current installation health checks pass; the failed install stage still needs attention." >&2
    else
      echo "The complete installation still has health-check failures (see above)." >&2
    fi
    echo "Fix the reported failure and rerun packaging/bin/build-and-install.sh." >&2
  else
    echo "No installation of host payloads was attempted." >&2
  fi
  echo "build-and-install: INSTALLATION INCOMPLETE; exiting $result." >&2
  exit "$result"
}

finish_sudo_uninstall() {
  local result="$1"
  if [ "$result" -eq 0 ] && [ "$installation_verified" -eq 1 ]; then
    echo "Sudo integration removed and verified: sudo uses Apple's own authentication."
    return
  fi
  if [ "$dry_run" -eq 1 ] && [ "$result" -eq 0 ]; then
    return
  fi
  [ "$result" -ne 0 ] || result=1
  echo >&2
  echo "build-and-install: SUDO INTEGRATION REMOVAL FAILED during $stage (exit $result)." >&2
  echo "A live sudo that fails puts /etc/pam.d/sudo_local back, so the integration stays installed unless the stage said otherwise above." >&2
  echo "Fix the reported failure, then rerun: packaging/bin/build-and-install.sh --uninstall-sudo" >&2
  exit "$result"
}

# A second, unprivileged look after the root stage: no csec file is left
# where the installer puts them, and no PAM service names the module.
verify_sudo_integration_removed() {
  if [ "$dry_run" -eq 1 ]; then
    echo "+ check that nothing matches $installed_sudo_module* or $installed_sudo_review_helper*, and that no file in $pam_directory loads pam_csec_sudo.so"
    return
  fi
  local leftover service
  for leftover in "$installed_sudo_module"* "$installed_sudo_review_helper"*; do
    if [ -e "$leftover" ] || [ -L "$leftover" ]; then
      die "still installed after the removal: $leftover"
    fi
  done
  for service in "$pam_directory"/*; do
    [ -f "$service" ] || continue
    if /usr/bin/awk '$1 !~ /^#/ && index($0, "pam_csec_sudo.so") { found = 1 } END { exit !found }' "$service"; then
      die "$service still loads the csec PAM module after the removal"
    fi
  done
  echo "verified: no csec sudo module, review helper or PAM line remains"
}

perform_sudo_uninstall() {
  stage="sudo integration removal and live verification"
  presence_checkpoint sudo-integration-uninstall
  run /usr/bin/sudo "$here/bin/install-sudo-review.sh" --uninstall

  stage="sudo integration removal verification"
  verify_sudo_integration_removed
  finish_dry_run_or_verify
}

perform_install() {
  # Provisioning can ask for the App Store Connect key straight away.
  stage="notarization authorization"
  presence_checkpoint notarization-authorization
  run "$here/bin/notarize.sh" --check-auth

  stage="provisioning"
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

  stage="build and signing"
  run "$here/bin/build-agent.sh"
  # The package carries the sudo payload for csec setup, so it is built even
  # when this run leaves the installed integration alone.
  run "$here/bin/build-sudo-pam.sh"
  run "$here/bin/build-sudo-review.sh"
  # One csec request delivers the App Store Connect key for both
  # notarizations, with the package built between them, so the one review
  # comes straight after this checkpoint and none waits on the notary service.
  stage="app notarization, package build and package notarization"
  # The package's preinstall refuses to replace a higher version or build;
  # --allow-downgrade builds the one package that may, for this rollback.
  export CSEC_PKG_ALLOW_DOWNGRADE="$allow_downgrade"
  presence_checkpoint app-notarization
  run "$here/bin/notarize.sh" "$app" --build-package "$here/bin/build-pkg.sh" "$pkg"

  stage="package installation"
  presence_checkpoint package-install
  echo "Installing package; overall success requires runtime, sudo, and payload checks below."
  # installer can replace files before returning an error or receiving a signal.
  package_attempted=1
  run /usr/bin/sudo /usr/sbin/installer -pkg "$pkg" -target /

  # Replacing the app does not replace a running csecd's code image. Recover it
  # before any subsequent stage can fail, including the guarded sudo installer.
  # Sudo is checked later, after its freshly built payloads have been installed.
  stage="installed runtime repair and verification"
  run "$installed_csec" doctor --runtime

  # Own a live restore waiter while Alex is here: short-lived SSH/secret
  # requests can leave without repeatedly withdrawing the same review. A
  # failed or cancelled restore stops this install; recovery never retries it.
  stage="approval restoration"
  presence_checkpoint approval-restore
  run "$installed_csec" restore

  # Waiting between the sudo stages leaves the host as a failed stage would:
  # the new app with its runtime repaired, the older hook and sudo helper.
  stage="managed Codex hook installation"
  presence_checkpoint codex-hook-install
  run /usr/bin/sudo "$installed_codex_installer"

  stage="sudo integration installation and live verification"
  if [ "$install_sudo" -eq 1 ]; then
    presence_checkpoint sudo-integration-install
    run /usr/bin/sudo "$installed_sudo_installer"
  fi

  stage="installed payload verification"
  verify_same_file "$app/Contents/MacOS/csec" "$installed_csec"
  verify_same_file "$app/Contents/MacOS/csecd" "$installed_app/Contents/MacOS/csecd"
  verify_same_file "$app/Contents/Resources/ai-guard/op" "$installed_app/Contents/Resources/ai-guard/op"
  verify_same_file "$app/Contents/Resources/claude-code-shell/csec-claude-code-shell" \
    "$installed_app/Contents/Resources/claude-code-shell/csec-claude-code-shell"
  verify_cloudkit_signature "$installed_app" "installed csecd"
  verify_same_file "$app/Contents/MacOS/csec" "$installed_bridge"
  verify_same_file "$here/libexec/uninstall-csec.sh" "$installed_uninstaller"
  verify_same_file "$root_helper" "$installed_root_helper"
  verify_same_file "$here/bin/install-codex-hook.sh" "$installed_codex_installer"
  verify_same_file "$here/bin/install-sudo-review.sh" "$installed_sudo_installer"
  verify_same_file "$here/lib/sudo-review-policy.sh" "$installed_sudo_policy"
  verify_same_file "$here/lib/identity.sh" "$installed_identity_library"
  verify_same_file "$repo_root/identity.xcconfig" "$installed_identity_file"
  verify_same_file "$sudo_module" "$installed_payload_module"
  verify_same_file "$sudo_review_helper" "$installed_payload_helper"
  verify_command_link
  verify_install_receipt
  write_codex_hook_document
  verify_same_file "$codex_hook_document" "$installed_codex_hook"
  if [ "$install_sudo" -eq 1 ]; then
    verify_same_file "$sudo_module" "$installed_sudo_module"
    verify_same_file "$sudo_review_helper" "$installed_sudo_review_helper"
  fi

  # Full health remains mandatory, including any active sudo integration even
  # with --skip-sudo. Never announce overall success from the runtime-only gate.
  stage="complete installation health checks"
  run "$installed_csec" doctor
  run "$installed_csec" status
  if [ "$dry_run" -eq 0 ]; then
    mac_verified=1
  fi

  if [ "$install_iphone" -eq 1 ]; then
    perform_iphone_install
  fi
  finish_dry_run_or_verify
}

finish_dry_run_or_verify() {
  if [ "$dry_run" -eq 1 ]; then
    echo "Dry run complete; no build, signing, network, installation, or service changes were made."
  else
    installation_verified=1
  fi
}

main() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --refresh-profile)
        refresh_profile=1
        ;;
      --skip-sudo)
        install_sudo=0
        ;;
      --skip-iphone)
        install_iphone=0
        ;;
      --only-iphone)
        only_iphone=1
        ;;
      --uninstall-sudo)
        uninstall_sudo=1
        ;;
      --allow-downgrade)
        allow_downgrade=1
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
  if [ "$only_iphone" -eq 1 ] &&
      { [ "$install_iphone" -eq 0 ] || [ "$install_sudo" -eq 0 ] || [ "$refresh_profile" -eq 1 ]; }; then
    usage >&2
    die "--only-iphone installs only the iPhone app; it takes no other option but --allow-downgrade and --dry-run"
  fi
  if [ "$uninstall_sudo" -eq 1 ] &&
      { [ "$only_iphone" -eq 1 ] || [ "$install_iphone" -eq 0 ] || [ "$install_sudo" -eq 0 ] ||
        [ "$refresh_profile" -eq 1 ] || [ "$allow_downgrade" -eq 1 ]; }; then
    usage >&2
    die "--uninstall-sudo removes only the sudo integration; it takes no other option but --dry-run"
  fi
  configure_presence_checkpoints
  # A dry run changes nothing, so it neither waits for nor blocks an install.
  if [ "$dry_run" -eq 0 ]; then
    acquire_install_lock
  fi

  begin_install_session

  cd "$repo_root"
  require_checkout_contains_main

  # The removal builds and installs nothing, so the installed commit is not
  # compared; the checkout must still hold main, since it runs as root.
  if [ "$uninstall_sudo" -eq 1 ]; then
    if [ "$dry_run" -eq 0 ]; then
      [ "$(uname -s)" = "Darwin" ] || die "macOS is required"
      [ "$EUID" -ne 0 ] || die "run as the login user, not root; the script invokes sudo only for the sudo-integration removal"
      [ -x "$here/bin/install-sudo-review.sh" ] ||
        die "required script is not executable: $here/bin/install-sudo-review.sh"
    fi
    perform_sudo_uninstall
    return
  fi
  require_checkout_contains_installed

  # This file contains only references and identity names. The provisioning and
  # notarization scripts retrieve private-key bytes just in time using their
  # separately constrained transports; this wrapper never handles those bytes.
  requested_dry_run="$dry_run"
  requested_refresh_profile="$refresh_profile"
  requested_install_sudo="$install_sudo"
  requested_install_iphone="$install_iphone"
  requested_only_iphone="$only_iphone"
  requested_presence=("$presence_checkpoint" "$presence_job" "$presence_attempt")
  if [ -f "$here/.env" ]; then
    # shellcheck disable=SC1091
    source "$here/.env"
  fi
  dry_run="$requested_dry_run"
  refresh_profile="$requested_refresh_profile"
  install_sudo="$requested_install_sudo"
  install_iphone="$requested_install_iphone"
  only_iphone="$requested_only_iphone"
  presence_checkpoint="${requested_presence[0]}"
  presence_job="${requested_presence[1]}"
  presence_attempt="${requested_presence[2]}"

  if [ "$only_iphone" -eq 1 ]; then
    if [ "$dry_run" -eq 0 ]; then
      [ "$(uname -s)" = "Darwin" ] || die "macOS is required"
      [ "$EUID" -ne 0 ] || die "run as the login user, not root"
      preflight_iphone
    fi
    perform_iphone_install
    finish_dry_run_or_verify
    return
  fi

  SIGN_IDENTITY="${SIGN_IDENTITY:-Developer ID Application: Stateful Ltd ($csec_team_id)}"
  INSTALLER_IDENTITY="${INSTALLER_IDENTITY:-Developer ID Installer: Stateful Ltd ($csec_team_id)}"
  PROFILE_PATH="${PROFILE_PATH:-$default_profile}"
  if [[ "$PROFILE_PATH" != /* ]]; then
    PROFILE_PATH="$repo_root/$PROFILE_PATH"
  fi
  export SIGN_IDENTITY INSTALLER_IDENTITY PROFILE_PATH
  export CSEC_BUILD_AND_INSTALL_PIPELINE=1

  if [ "$dry_run" -eq 0 ]; then
    [ "$(uname -s)" = "Darwin" ] || die "macOS is required"
    [ "$EUID" -ne 0 ] || die "run as the login user, not root; the script invokes sudo only for the package, Codex-hook, and sudo-integration installers"
    # shellcheck source=../lib/asc-credentials.sh
    source "$here/lib/asc-credentials.sh"
    asc_configure_credentials
    export ASC_KEY_ID_REF ASC_ISSUER_ID_REF ASC_KEY_REF

    if ! signing_identities="$(/usr/bin/security find-identity -v 2>/dev/null)"; then
      die "could not inspect signing identities in the user keychain"
    fi
    for required_identity in "$SIGN_IDENTITY" "$INSTALLER_IDENTITY"; do
      if [[ "$signing_identities" != *"\"$required_identity\""* ]]; then
        die "missing valid signing identity (certificate plus private key): $required_identity; see packaging/README.md prerequisites"
      fi
    done

    # The iPhone stage runs last; learn now, not after the Mac build, that it
    # cannot run.
    if [ "$install_iphone" -eq 1 ]; then
      preflight_iphone
    fi
  fi

  for required_script in \
    "$here/bin/provision.sh" \
    "$here/bin/build-agent.sh" \
    "$here/bin/build-sudo-pam.sh" \
    "$here/bin/build-sudo-review.sh" \
    "$here/bin/install-sudo-review.sh" \
    "$here/bin/install-codex-hook.sh" \
    "$here/bin/notarize.sh" \
    "$here/bin/build-pkg.sh"; do
    [ -x "$required_script" ] || die "required script is not executable: $required_script"
  done

  perform_install
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
