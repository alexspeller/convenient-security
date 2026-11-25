#!/bin/bash
set -euo pipefail

# The package's own uninstaller: removes everything csec installed for every
# account on this Mac, with no source checkout. The package installs it at
#   /Library/Application Support/ConvenientSecurity/libexec/uninstall-csec.sh
# under directories only root can write, and `csec uninstall --all` runs it
# through sudo once it has removed the login user's own part (csecd's state,
# csec's Claude Code and Codex hooks, the LaunchAgent). It can also be run on
# its own the same way:
#   sudo '/Library/Application Support/ConvenientSecurity/libexec/uninstall-csec.sh'
#
# In order, stopping at the first step that fails so it can simply be run again
# (every step skips what is already gone):
#  1. The sudo review, through the package's guarded removal
#     (install-sudo-review.sh --uninstall): csec's PAM lines go first, and only
#     a harmless sudo that still works through Apple's Touch ID or password
#     lets the module and helper be deleted; a failed sudo puts sudo_local back.
#  2. csec's handler in the managed Codex hook /etc/codex/hooks.json (the file
#     goes when csec's hook was all it held). It fails closed, so it has to go
#     before the app: left behind, it would block every Codex Bash call.
#  3. csec-rootd: booted out, its LaunchDaemon and binary deleted, its tmpfs
#     unmounted and its runtime directory removed (never recursively).
#  4. /usr/local/bin/csec, only when it is csec's link to the app.
#  5. The app, then the bridge directory this script lives in (bash keeps
#     reading the open file, and everything runs from functions parsed before).
#  6. The package receipts, so the installer no longer lists csec.
# Secrets and where they are kept stay: csec never stored them here.

die() {
  echo "uninstall-csec: $*" >&2
  exit 1
}

# The team and identifier the package was built under, from the identity file
# build-pkg.sh installs beside this script (a checkout's copy, which only the
# tests source, reads the checkout's).
identity_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
if [ -f "$identity_directory/identity.sh" ]; then
  # shellcheck source=../lib/identity.sh
  . "$identity_directory/identity.sh"
  csec_identity_load "$identity_directory/identity.xcconfig"
else
  . "$identity_directory/../lib/identity.sh"
  csec_identity_load "$identity_directory/../../identity.xcconfig"
fi
app="/Applications/ConvenientSecurity.app"
app_identifier="$csec_identifier"
bridge_root="/Library/Application Support/ConvenientSecurity"
bridge_csec="$bridge_root/bin/csec"
script_path="$bridge_root/libexec/uninstall-csec.sh"
sudo_removal="$bridge_root/libexec/install-sudo-review.sh"
sudo_local="/private/etc/pam.d/sudo_local"
sudo_module="/usr/local/lib/pam/pam_csec_sudo.so"
sudo_helper="/usr/local/libexec/csec-sudo-review"
codex_directory="/private/etc/codex"
codex_hooks="$codex_directory/hooks.json"
root_label="$csec_identifier.rootd"
root_helper="/Library/PrivilegedHelperTools/$root_label"
root_plist="/Library/LaunchDaemons/$root_label.plist"
runtime_directory="/private/var/run/convenient-security"
path_link="/usr/local/bin/csec"
agent_label="$csec_identifier"
package_pattern="${csec_identifier//./\\.}.*"
product_requirement="$csec_product_requirement"
# Whom the paths above must belong to. Only the tests change it.
expected_owner=0

launchctl=/bin/launchctl
pkgutil=/usr/sbin/pkgutil
codesign=/usr/bin/codesign
umount=/sbin/umount
plutil=/usr/bin/plutil
stop_polls=200
stop_poll_delay=0.05

current_uid() { /usr/bin/id -u; }
uid_of() { /usr/bin/id -u "$1"; }

# Root-owned (or the test owner's) and writable by no one else.
require_protected() {
  local path="$1" owner mode
  owner="$(/usr/bin/stat -f %u "$path")"
  mode="$(/usr/bin/stat -f %Lp "$path")"
  if [ "$owner" != "$expected_owner" ] || [ $((8#$mode & 022)) -ne 0 ]; then
    die "not root-owned or writable by others: $path"
  fi
}

present() { [ -e "$1" ] || [ -L "$1" ]; }

# A directory holding a mount has a different device from its parent.
is_mount_point() {
  [ -d "$1" ] && [ ! -L "$1" ] &&
    [ "$(/usr/bin/stat -f %d "$1")" != "$(/usr/bin/stat -f %d "$(/usr/bin/dirname "$1")")" ]
}

# --- Before anything changes -------------------------------------------------

check_caller() {
  [ "$(current_uid)" -eq 0 ] || die "run it through sudo: sudo '$script_path'"
  login_user="${SUDO_USER:-}"
  [ -n "$login_user" ] && [ "$login_user" != root ] ||
    die "run it through sudo from your own account, not as root: removing the sudo review checks that sudo still works for you"
  login_uid="$(uid_of "$login_user")" || die "SUDO_USER does not name a local account"
  # The account's own part comes first, while the app is still here to do it.
  # csec unregisters the agent just before running this, and launchd stops it
  # moments later, so a still-running agent is given a few seconds.
  local poll=0
  while "$launchctl" print "gui/$login_uid/$agent_label" >/dev/null 2>&1; do
    poll=$((poll + 1))
    [ "$poll" -lt "$stop_polls" ] ||
      die "csec is still running for $login_user; run csec uninstall --all as $login_user instead, which removes that account's part first. Nothing was changed."
    /bin/sleep "$stop_poll_delay"
  done
}

# --- 1. The sudo review --------------------------------------------------------

sudo_review_present() {
  present "$sudo_module" || present "$sudo_helper" ||
    { [ -f "$sudo_local" ] && /usr/bin/grep -q 'pam_csec_sudo\.so' "$sudo_local"; }
}

remove_sudo_review() {
  if present "$sudo_removal"; then
    [ -f "$sudo_removal" ] && [ ! -L "$sudo_removal" ] || die "not a regular file: $sudo_removal"
    require_protected "$sudo_removal"
    echo "removing the sudo review: sudo has to work without csec before csec's module is deleted"
    /bin/bash "$sudo_removal" --uninstall ||
      die "the sudo review is still installed (the lines above say why) and nothing else was removed; once that is fixed, run this again: sudo '$script_path'"
  elif sudo_review_present; then
    die "the csec sudo review is installed, but this package carries no removal for it; nothing was removed"
  else
    echo "the csec sudo review is not installed"
  fi
}

# --- 2. The managed Codex hook -------------------------------------------------

codex_staged=""
remove_codex_hook() {
  if ! present "$codex_hooks"; then
    echo "there is no managed Codex hook"
    return 0
  fi
  [ -f "$codex_hooks" ] && [ ! -L "$codex_hooks" ] || die "not a regular file: $codex_hooks"
  require_protected "$codex_directory"
  require_protected "$codex_hooks"
  # The bridge copy sits under directories only root can write, so the binary
  # checked here is the one that runs.
  local path
  for path in "$bridge_root" "$bridge_root/bin" "$bridge_csec"; do
    present "$path" || die "$bridge_csec is missing, so csec's handler cannot be taken out of $codex_hooks; remove it by hand, then run this again. Nothing else was removed after the sudo review."
    [ ! -L "$path" ] || die "unexpected symlink: $path"
    require_protected "$path"
  done
  "$codesign" --verify --strict \
    -R="$product_requirement and identifier \"$app_identifier.csec\"" "$bridge_csec" ||
    die "$bridge_csec failed signature verification; $codex_hooks was left as it is"

  codex_staged="$(/usr/bin/mktemp "$codex_directory/.hooks.json.csec-removal.XXXXXX")"
  "$bridge_csec" hook-config codex --system --remove >"$codex_staged" ||
    die "csec could not take its hook out of $codex_hooks (the line above says why); remove csec's handler by hand, then run this again"
  if [ ! -s "$codex_staged" ]; then
    # The staged file sits in the same directory, so it goes first.
    /bin/rm -f -- "$codex_staged"
    codex_staged=""
    /bin/rm -f -- "$codex_hooks"
    echo "removed: $codex_hooks (csec's hook was all it held)"
    if /bin/rmdir "$codex_directory" 2>/dev/null; then
      echo "removed: $codex_directory (empty)"
    fi
  elif /usr/bin/cmp -s "$codex_staged" "$codex_hooks"; then
    echo "$codex_hooks holds no csec hook; left as it is"
  else
    "$plutil" -convert json -o /dev/null "$codex_staged" || die "the rewritten $codex_hooks is not valid JSON; left as it was"
    /bin/chmod 0644 "$codex_staged"
    [ "$expected_owner" != 0 ] || /usr/sbin/chown root:wheel "$codex_staged"
    /bin/mv -f -- "$codex_staged" "$codex_hooks"
    codex_staged=""
    echo "removed csec's hook from $codex_hooks, keeping its other hooks"
  fi
  [ -z "$codex_staged" ] || /bin/rm -f -- "$codex_staged"
  codex_staged=""
}

# --- 3. The root helper --------------------------------------------------------

remove_root_helper() {
  local service="system/$root_label" poll=0
  if "$launchctl" print "$service" >/dev/null 2>&1; then
    "$launchctl" bootout "$service" >/dev/null 2>&1 || true
    # bootout returns before launchd has finished removing a KeepAlive job.
    while "$launchctl" print "$service" >/dev/null 2>&1; do
      poll=$((poll + 1))
      [ "$poll" -lt "$stop_polls" ] || die "csec-rootd did not stop; run this again"
      /bin/sleep "$stop_poll_delay"
    done
    echo "stopped: csec-rootd"
  fi
  local path
  for path in "$root_plist" "$root_helper"; do
    present "$path" || continue
    [ -f "$path" ] && [ ! -L "$path" ] || die "not a regular file: $path"
    /bin/rm -f -- "$path"
    echo "removed: $path"
  done

  present "$runtime_directory" || return 0
  [ -d "$runtime_directory" ] && [ ! -L "$runtime_directory" ] || die "not a directory: $runtime_directory"
  local files="$runtime_directory/files"
  # The protected-file tmpfs outlives csec-rootd. Unmounting it discards the
  # copies it held; nothing is deleted through it, and a busy one stays until
  # the next restart.
  if is_mount_point "$files"; then
    if "$umount" "$files"; then
      echo "unmounted: $files"
    else
      echo "left mounted until the next restart: $files (a program still has a file open there)" >&2
      return 0
    fi
  fi
  [ ! -S "$runtime_directory/rootd.sock" ] || /bin/rm -f -- "$runtime_directory/rootd.sock"
  if [ -d "$files" ] && [ ! -L "$files" ]; then /bin/rmdir "$files" 2>/dev/null || true; fi
  if /bin/rmdir "$runtime_directory" 2>/dev/null; then
    echo "removed: $runtime_directory"
  else
    echo "left in place until the next restart: $runtime_directory (it is not empty)" >&2
  fi
}

# --- 4-5. The command link, the app and the bridge -----------------------------

remove_files() {
  if [ -L "$path_link" ]; then
    if [ "$(/usr/bin/readlink "$path_link")" = "$app/Contents/MacOS/csec" ]; then
      /bin/rm -f -- "$path_link"
      echo "removed: $path_link"
    else
      echo "left in place: $path_link, which is not csec's link"
    fi
  fi

  if present "$app"; then
    [ -d "$app" ] && [ ! -L "$app" ] || die "not the app bundle: $app"
    [ "$("$plutil" -extract CFBundleIdentifier raw "$app/Contents/Info.plist" 2>/dev/null || true)" = "$app_identifier" ] ||
      die "$app is not csec's app; it was left in place"
    /bin/rm -rf -- "$app"
    echo "removed: $app"
  fi

  if present "$bridge_root"; then
    [ -d "$bridge_root" ] && [ ! -L "$bridge_root" ] || die "not a directory: $bridge_root"
    /bin/rm -rf -- "$bridge_root"
    echo "removed: $bridge_root"
  fi
}

# --- 6. The package receipts ---------------------------------------------------

forget_receipts() {
  local receipt receipts
  receipts="$("$pkgutil" --pkgs="$package_pattern" 2>/dev/null || true)"
  for receipt in $receipts; do
    if "$pkgutil" --forget "$receipt" >/dev/null; then
      echo "forgot the package receipt: $receipt"
    else
      echo "could not forget the package receipt $receipt; sudo pkgutil --forget $receipt does it" >&2
    fi
  done
}

finish() {
  local status=$?
  trap - EXIT
  [ -z "$codex_staged" ] || /bin/rm -f -- "$codex_staged"
  exit "$status"
}

main() {
  [ "$#" -eq 0 ] || die "usage: sudo '$script_path'"
  trap finish EXIT
  check_caller
  remove_sudo_review
  remove_codex_hook
  remove_root_helper
  remove_files
  forget_receipts
  echo "csec is removed from this Mac; your secrets and where they are kept were not touched"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
  exit 0
fi
