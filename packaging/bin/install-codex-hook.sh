#!/usr/bin/env bash
set -euo pipefail

# Guarded, reversible installation of csec's Codex PreToolUse hook as a managed
# System-layer hook in /etc/codex/hooks.json. This is the Codex stage of
# packaging/bin/build-and-install.sh and of `csec setup`, which both run the
# copy the package installs; run it through sudo from the login user.
#
# Why the System layer: Codex runs a user-level hook from ~/.codex/hooks.json
# only while its bytes match a trust hash the user recorded, and silently skips
# it after any change until the user re-trusts it. Managed hooks need no trust
# hash and same-user code cannot edit a root-owned file, though Codex's own
# `features.hooks = false` still turns every hook off (csec doctor reports it).
# The hook applies to every account and Codex front end on this Mac.
#
# The document is generated here, as root, by a private copy of the installed
# csec that is signature-verified after copying (`csec hook-config codex
# --system --launcher <installed csec>`): csec's handler is merged into any
# existing file, every other hook and key is kept. Root never executes a path an
# admin-group process could swap after the check (/Applications is group-
# writable), and nothing the login user can write feeds the root-owned result.
# The previous file (or its absence, and the directory's) is restored on any
# failure.

die() {
  echo "install-codex-hook: $*" >&2
  exit 1
}

# The team and identifier the installed csec must be signed with: the package's
# copy reads the identity file installed beside it, a checkout's copy the
# checkout's. The location decides, never an argument or the environment.
script_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
if [[ "$script_directory" == "/Library/Application Support/ConvenientSecurity/libexec" ]]; then
  identity_library="$script_directory/identity.sh"
  identity_file="$script_directory/identity.xcconfig"
else
  identity_library="$script_directory/../lib/identity.sh"
  identity_file="$script_directory/../../identity.xcconfig"
fi
# shellcheck source=../lib/identity.sh
. "$identity_library"
csec_identity_load "$identity_file" || die "cannot read the build identity"

installed_csec="/Applications/ConvenientSecurity.app/Contents/MacOS/csec"
destination_directory="/private/etc/codex"
destination="$destination_directory/hooks.json"
product_requirement="$csec_product_requirement"

[ "$#" -eq 0 ] || die "usage: sudo packaging/bin/install-codex-hook.sh"
[ "$(/usr/bin/id -u)" -eq 0 ] || die "run through sudo"

# Only root-owned, non-group/other-writable path components may lead to the
# file every Codex session on this Mac will run.
require_protected() {
  local path="$1" owner mode
  owner="$(/usr/bin/stat -f %u "$path")"
  mode="$(/usr/bin/stat -f %Lp "$path")"
  if [ "$owner" != "0" ] || [ $((8#$mode & 022)) -ne 0 ]; then
    die "not root-owned or writable by others: $path"
  fi
}

[ -f "$installed_csec" ] && [ ! -L "$installed_csec" ] || die "installed csec is missing: $installed_csec"

created_directory=0
staged=""
backup=""
installed=0
private_directory=""
finish() {
  local result=$?
  trap - EXIT
  [ -z "$staged" ] || /bin/rm -f "$staged"
  [ -z "$private_directory" ] || /bin/rm -rf "$private_directory"
  if [ "$result" -ne 0 ] && [ "$installed" -eq 1 ]; then
    if [ -n "$backup" ]; then
      if /bin/mv -f "$backup" "$destination"; then
        backup=""
        echo "install-codex-hook: restored the previous $destination" >&2
      else
        # Never delete the only copy of the original.
        echo "install-codex-hook: could not restore $destination; the previous file is kept at $backup" >&2
        backup=""
      fi
    else
      /bin/rm -f "$destination"
      echo "install-codex-hook: removed the new $destination" >&2
    fi
  fi
  [ -z "$backup" ] || /bin/rm -f "$backup"
  if [ "$result" -ne 0 ] && [ "$created_directory" -eq 1 ]; then
    /bin/rmdir "$destination_directory" 2>/dev/null || true
  fi
  exit "$result"
}
trap finish EXIT

# Copy first, then verify and run only the copy, in a directory only root can
# reach.
private_directory="$(/usr/bin/mktemp -d /private/tmp/csec-codex-hook.XXXXXX)"
/bin/chmod 0700 "$private_directory"
private_csec="$private_directory/csec"
/bin/cp "$installed_csec" "$private_csec"
/usr/bin/codesign --verify --strict \
  -R="$product_requirement and identifier \"$csec_identifier.csec\"" \
  "$private_csec" || die "installed csec failed signature verification"

for protected_path in / /private /private/etc; do
  require_protected "$protected_path"
done
if [ -e "$destination_directory" ] || [ -L "$destination_directory" ]; then
  [ -d "$destination_directory" ] && [ ! -L "$destination_directory" ] \
    || die "not a directory: $destination_directory"
else
  /bin/mkdir -m 0755 "$destination_directory"
  created_directory=1
  /usr/sbin/chown root:wheel "$destination_directory"
fi
require_protected "$destination_directory"
if [ -e "$destination" ] || [ -L "$destination" ]; then
  [ -f "$destination" ] && [ ! -L "$destination" ] || die "not a regular file: $destination"
  require_protected "$destination"
fi

staged="$(/usr/bin/mktemp "$destination_directory/.hooks.json.csec.XXXXXX")"
"$private_csec" hook-config codex --system --launcher "$installed_csec" > "$staged" \
  || die "csec could not build the managed Codex hook document"
/usr/bin/plutil -convert json -o /dev/null "$staged" || die "generated document is not valid JSON"
/usr/sbin/chown root:wheel "$staged"
/bin/chmod 0644 "$staged"

if [ -f "$destination" ]; then
  backup="$(/usr/bin/mktemp "$destination_directory/.hooks.json.csec-backup.XXXXXX")"
  /bin/cp -p "$destination" "$backup"
fi
installed=1
/bin/mv -f "$staged" "$destination"
staged=""

# The document is deterministic: regenerating over the installed file must
# reproduce it exactly, or the merge did not converge and nothing is kept.
"$private_csec" hook-config codex --system --launcher "$installed_csec" | /usr/bin/cmp -s - "$destination" \
  || die "the installed document does not regenerate identically"
require_protected "$destination"
echo "installed managed Codex hook: $destination"
