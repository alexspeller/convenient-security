#!/usr/bin/env bash
set -euo pipefail

# Guarded, reversible installer for the contextual sudo PAM integration.
#
# Run this script as root only for an attended live test. It keeps the stock
# pam_tid entry in place and waits for an explicit `keep` decision. EOF, a
# signal, an invalid decision, or a five-minute timeout restores sudo_local and
# removes the test module.

die() {
  echo "install-sudo-pam: $*" >&2
  exit 1
}

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
source_module="$here/build/sudo-pam/pam_csec_sudo.so"
destination_directory="/usr/local/lib/pam"
destination_module="$destination_directory/pam_csec_sudo.so"
sudo_local="/private/etc/pam.d/sudo_local"
backup="/private/etc/pam.d/sudo_local.csec-context-backup"
custom_line="auth       sufficient     /usr/local/lib/pam/pam_csec_sudo.so"
temporary_config=""
directory_created=0
module_installed=0
config_activated=0
keep_active=0
backup_exists=0

replace_sudo_local() {
  local replacement_source="$1"
  local replacement
  replacement="$(/usr/bin/mktemp /private/etc/pam.d/.sudo_local.csec.XXXXXX)" ||
    return 1
  if ! /usr/bin/install -o root -g wheel -m 0644 \
      "$replacement_source" "$replacement"; then
    /bin/rm -f -- "$replacement"
    return 1
  fi
  if ! /bin/mv -f -- "$replacement" "$sudo_local"; then
    /bin/rm -f -- "$replacement"
    return 1
  fi
}

finish() {
  original_status="$?"
  restore_status=0
  trap - EXIT HUP INT TERM

  if [[ -n "$temporary_config" && -e "$temporary_config" ]]; then
    /bin/rm -f -- "$temporary_config" || restore_status=1
  fi

  if [[ "$keep_active" -eq 0 ]]; then
    if [[ "$config_activated" -eq 1 ]]; then
      if replace_sudo_local "$backup"; then
        echo "restored: $sudo_local"
      else
        echo "FATAL: could not restore $sudo_local from $backup" >&2
        restore_status=1
      fi
    fi
    if [[ "$module_installed" -eq 1 ]]; then
      /bin/rm -f -- "$destination_module" || restore_status=1
    fi
    if [[ "$directory_created" -eq 1 ]]; then
      /bin/rmdir "$destination_directory" 2>/dev/null || true
    fi
  fi

  if [[ "$restore_status" -ne 0 ]]; then
    exit "$restore_status"
  fi
  exit "$original_status"
}

trap finish EXIT
trap 'exit 130' HUP INT TERM

[[ "$(/usr/bin/uname -s)" == "Darwin" ]] || die "macOS is required"
[[ "$EUID" -eq 0 ]] || die "run with sudo; root is required for the guarded install"
[[ -f "$source_module" && ! -L "$source_module" ]] ||
  die "build the PAM module first: packaging/bin/build-sudo-pam.sh"
[[ -f "$sudo_local" && ! -L "$sudo_local" ]] || die "unexpected sudo_local file"
if [[ -e "$backup" ]]; then
  [[ -f "$backup" && ! -L "$backup" ]] || die "unexpected existing backup: $backup"
  [[ "$(/usr/bin/stat -f '%u' "$backup")" == "0" ]] ||
    die "existing backup is not root-owned: $backup"
  /usr/bin/cmp -s "$sudo_local" "$backup" ||
    die "existing backup no longer matches stock sudo_local: $backup"
  backup_exists=1
fi
[[ ! -e "$destination_module" ]] ||
  die "refusing to replace existing PAM module: $destination_module"

for protected_directory in /usr/local /usr/local/lib /private/etc /private/etc/pam.d; do
  [[ -d "$protected_directory" && ! -L "$protected_directory" ]] ||
    die "unexpected protected directory: $protected_directory"
  [[ "$(/usr/bin/stat -f '%u' "$protected_directory")" == "0" ]] ||
    die "protected directory is not root-owned: $protected_directory"
  protected_mode="$(/usr/bin/stat -f '%Lp' "$protected_directory")"
  if (( (8#$protected_mode & 0022) != 0 )); then
    die "protected directory is group- or world-writable: $protected_directory"
  fi
done

[[ "$(/usr/bin/stat -f '%u' "$sudo_local")" == "0" ]] ||
  die "sudo_local is not root-owned"
if /usr/bin/grep -Fqx "$custom_line" "$sudo_local"; then
  die "contextual PAM line is already active"
fi
if ! /usr/bin/awk '
  /^[[:space:]]*auth[[:space:]]+sufficient[[:space:]]+([^[:space:]]*\/)?pam_tid\.so([[:space:]]|$)/ {
    found = 1
  }
  END { exit(found ? 0 : 1) }
' "$sudo_local"; then
  die "active stock pam_tid fallback was not found"
fi

/usr/bin/codesign --verify --strict "$source_module" || die "module signature check failed"
/usr/bin/lipo "$source_module" -verify_arch x86_64 arm64 arm64e ||
  die "module does not contain all expected architectures"

temporary_config="$(/usr/bin/mktemp /private/tmp/csec-sudo-local.XXXXXX)"
/bin/chmod 0600 "$temporary_config"
if ! /usr/bin/awk -v custom="$custom_line" '
  BEGIN { inserted = 0 }
  /^[[:space:]]*auth[[:space:]]+sufficient[[:space:]]+([^[:space:]]*\/)?pam_tid\.so([[:space:]]|$)/ && !inserted {
    print custom
    inserted = 1
  }
  { print }
  END { if (!inserted) exit 42 }
' "$sudo_local" >"$temporary_config"; then
  die "could not construct candidate sudo_local"
fi
[[ "$(/usr/bin/grep -Fxc "$custom_line" "$temporary_config")" == "1" ]] ||
  die "candidate sudo_local does not contain exactly one contextual entry"

if [[ "$backup_exists" -eq 0 ]]; then
  /usr/bin/install -o root -g wheel -m 0644 "$sudo_local" "$backup"
  /usr/bin/cmp -s "$sudo_local" "$backup" || die "backup verification failed"
else
  echo "reusing verified stock backup: $backup"
fi

if [[ ! -e "$destination_directory" ]]; then
  /usr/bin/install -d -o root -g wheel -m 0755 "$destination_directory"
  directory_created=1
fi
[[ -d "$destination_directory" && ! -L "$destination_directory" ]] ||
  die "unexpected PAM module directory"
[[ "$(/usr/bin/stat -f '%u' "$destination_directory")" == "0" ]] ||
  die "PAM module directory is not root-owned"

/usr/bin/install -o root -g wheel -m 0755 "$source_module" "$destination_module"
module_installed=1
/usr/bin/cmp -s "$source_module" "$destination_module" ||
  die "installed module does not match the build"
/usr/bin/codesign --verify --strict "$destination_module" ||
  die "installed module signature check failed"

replace_sudo_local "$temporary_config"
config_activated=1
[[ "$(/usr/bin/grep -Fxc "$custom_line" "$sudo_local")" == "1" ]] ||
  die "installed sudo_local did not validate"

echo "guarded contextual sudo PAM installation is active"
echo "module: $destination_module"
echo "backup: $backup"
echo "enter 'keep' to retain it, or 'restore' to roll back; timeout/EOF also restores"

decision=""
if ! IFS= read -r -t 300 decision; then
  echo "no decision received; restoring" >&2
  exit 124
fi

case "$decision" in
  keep)
    keep_active=1
    echo "installed contextual PAM configuration; stock pam_tid remains as fallback"
    ;;
  restore)
    echo "restore requested"
    ;;
  *)
    echo "invalid decision; restoring" >&2
    exit 64
    ;;
esac
