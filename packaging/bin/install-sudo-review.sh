#!/usr/bin/env bash
set -euo pipefail

# Guarded, reversible installation of the contextual sudo review helper over an
# existing csec PAM module. PAM configuration is left unchanged: the module
# remains `sufficient` immediately before stock pam_tid, so the Apple/password
# path stays available on every helper failure.

die() {
  echo "install-sudo-review: $*" >&2
  exit 1
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
source_module="$repo_root/packaging/build/sudo-pam/pam_csec_sudo.so"
source_helper="$repo_root/packaging/build/sudo-review/csec-sudo-review"
destination_module="/usr/local/lib/pam/pam_csec_sudo.so"
helper_directory="/usr/local/libexec"
destination_helper="$helper_directory/csec-sudo-review"
sudo_local="/private/etc/pam.d/sudo_local"
custom_line="auth       sufficient     /usr/local/lib/pam/pam_csec_sudo.so"
module_backup=""
helper_backup=""
staged_module=""
staged_helper=""
helper_existed=0
helper_backup_hardened=0
helper_directory_created=0
module_replaced=0
helper_replaced=0
keep_active=0

atomic_install() {
  local source="$1"
  local destination="$2"
  local mode="$3"
  local temporary
  temporary="$(/usr/bin/mktemp "${destination}.csec.XXXXXX")" || return 1
  if ! /usr/bin/install -o root -g wheel -m "$mode" "$source" "$temporary"; then
    /bin/rm -f -- "$temporary"
    return 1
  fi
  if ! /bin/mv -f -- "$temporary" "$destination"; then
    /bin/rm -f -- "$temporary"
    return 1
  fi
}

has_hardened_runtime() {
  /usr/bin/codesign -dvv "$1" 2>&1 |
    /usr/bin/grep 'flags=.*runtime' >/dev/null
}

has_expected_identifier() {
  /usr/bin/codesign -dvv "$1" 2>&1 |
    /usr/bin/grep \
      '^Identifier=com.alexspeller.convenient-security.sudo-review$' \
      >/dev/null
}

finish() {
  original_status="$?"
  restore_status=0
  trap - EXIT HUP INT TERM

  if [[ "$keep_active" -eq 0 ]]; then
    if [[ "$module_replaced" -eq 1 ]]; then
      if atomic_install "$module_backup" "$destination_module" 0755 &&
          /usr/bin/codesign --verify --strict "$destination_module"; then
        echo "restored prior contextual module: $destination_module"
      else
        echo "FATAL: could not restore prior PAM module" >&2
        restore_status=1
      fi
    fi

    if [[ "$helper_replaced" -eq 1 ]]; then
      if [[ "$helper_existed" -eq 1 && "$helper_backup_hardened" -eq 1 ]]; then
        if ! atomic_install "$helper_backup" "$destination_helper" 0755 ||
            ! /usr/bin/codesign --verify --strict "$destination_helper"; then
          echo "FATAL: could not restore prior review helper" >&2
          restore_status=1
        fi
      elif ! /bin/rm -f -- "$destination_helper"; then
        echo "FATAL: could not remove newly installed review helper" >&2
        restore_status=1
      else
        echo "restored contextual-only fallback; prior helper was not hardened"
      fi
    fi
    if [[ "$helper_directory_created" -eq 1 ]]; then
      /bin/rmdir "$helper_directory" 2>/dev/null || true
    fi
  fi

  for temporary in \
      "$module_backup" "$helper_backup" "$staged_module" "$staged_helper"; do
    if [[ -n "$temporary" && -e "$temporary" ]]; then
      /bin/rm -f -- "$temporary" || restore_status=1
    fi
  done

  if [[ "$restore_status" -ne 0 ]]; then
    exit "$restore_status"
  fi
  exit "$original_status"
}

trap finish EXIT
trap 'exit 130' HUP INT TERM

[[ "$(/usr/bin/uname -s)" == "Darwin" ]] || die "macOS is required"
[[ "$EUID" -eq 0 ]] || die "run with sudo; root is required for the guarded install"
for source in "$source_module" "$source_helper"; do
  [[ -f "$source" && ! -L "$source" ]] || die "missing regular build artifact: $source"
done
[[ -f "$destination_module" && ! -L "$destination_module" ]] ||
  die "the contextual PAM module is not installed"
[[ -f "$sudo_local" && ! -L "$sudo_local" ]] || die "unexpected sudo_local file"
[[ "$(/usr/bin/grep -Fxc "$custom_line" "$sudo_local")" == "1" ]] ||
  die "the contextual PAM line is not active exactly once"

if ! /usr/bin/awk -v custom="$custom_line" '
  $0 == custom { custom_line_number = NR }
  /^[[:space:]]*auth[[:space:]]+sufficient[[:space:]]+([^[:space:]]*\/)?pam_tid\.so([[:space:]]|$)/ {
    if (custom_line_number > 0 && NR > custom_line_number) found_fallback = 1
  }
  END { exit(found_fallback ? 0 : 1) }
' "$sudo_local"; then
  die "stock pam_tid is not active after the csec module"
fi

for protected_directory in / /usr /usr/local /usr/local/lib /usr/local/lib/pam; do
  [[ -d "$protected_directory" && ! -L "$protected_directory" ]] ||
    die "unexpected protected directory: $protected_directory"
  [[ "$(/usr/bin/stat -f '%u' "$protected_directory")" == "0" ]] ||
    die "protected directory is not root-owned: $protected_directory"
  protected_mode="$(/usr/bin/stat -f '%Lp' "$protected_directory")"
  if (( (8#$protected_mode & 0022) != 0 )); then
    die "protected directory is group- or world-writable: $protected_directory"
  fi
done

/usr/bin/codesign --verify --strict "$source_module" || die "module signature check failed"
/usr/bin/lipo "$source_module" -verify_arch x86_64 arm64 arm64e ||
  die "module does not contain all expected architectures"
/usr/bin/codesign --verify --strict "$source_helper" || die "helper signature check failed"
has_hardened_runtime "$source_helper" || die "helper is not hardened-runtime signed"
has_expected_identifier "$source_helper" || die "helper signing identifier is unexpected"
/usr/bin/lipo "$source_helper" -verify_arch "$(/usr/bin/uname -m)" ||
  die "helper does not support this host architecture"
/usr/bin/codesign --verify --strict "$destination_module" ||
  die "installed module signature check failed"

# Copy user-writable build artifacts once into unpredictable root-owned staging
# files, then verify those exact bytes before they enter protected directories.
staged_module="$(/usr/bin/mktemp /private/tmp/csec-sudo-module-stage.XXXXXX)"
staged_helper="$(/usr/bin/mktemp /private/tmp/csec-sudo-helper-stage.XXXXXX)"
/usr/bin/install -o root -g wheel -m 0700 "$source_module" "$staged_module"
/usr/bin/install -o root -g wheel -m 0700 "$source_helper" "$staged_helper"
/usr/bin/codesign --verify --strict "$staged_module" || die "staged module signature failed"
/usr/bin/codesign --verify --strict "$staged_helper" || die "staged helper signature failed"
has_hardened_runtime "$staged_helper" || die "staged helper is not hardened-runtime signed"
has_expected_identifier "$staged_helper" || die "staged helper identifier is unexpected"
"$staged_helper" --self-test || die "staged helper self-test failed"

module_backup="$(/usr/bin/mktemp /private/tmp/csec-sudo-module-backup.XXXXXX)"
/usr/bin/install -o root -g wheel -m 0700 "$destination_module" "$module_backup"
/usr/bin/cmp -s "$destination_module" "$module_backup" || die "module backup failed"

if [[ -e "$destination_helper" ]]; then
  [[ -f "$destination_helper" && ! -L "$destination_helper" ]] ||
    die "unexpected existing review helper"
  [[ "$(/usr/bin/stat -f '%u' "$destination_helper")" == "0" ]] ||
    die "existing review helper is not root-owned"
  /usr/bin/codesign --verify --strict "$destination_helper" ||
    die "existing review helper signature failed"
  helper_existed=1
  if has_hardened_runtime "$destination_helper"; then
    helper_backup_hardened=1
  fi
  helper_backup="$(/usr/bin/mktemp /private/tmp/csec-sudo-helper-backup.XXXXXX)"
  /usr/bin/install -o root -g wheel -m 0700 "$destination_helper" "$helper_backup"
  /usr/bin/cmp -s "$destination_helper" "$helper_backup" || die "helper backup failed"
else
  if [[ ! -e "$helper_directory" ]]; then
    /usr/bin/install -d -o root -g wheel -m 0755 "$helper_directory"
    helper_directory_created=1
  fi
fi

[[ -d "$helper_directory" && ! -L "$helper_directory" ]] ||
  die "unexpected helper directory"
[[ "$(/usr/bin/stat -f '%u' "$helper_directory")" == "0" ]] ||
  die "helper directory is not root-owned"
helper_mode="$(/usr/bin/stat -f '%Lp' "$helper_directory")"
if (( (8#$helper_mode & 0022) != 0 )); then
  die "helper directory is group- or world-writable"
fi

# Helper first is safe with the installed module; replacing the module second
# atomically activates the custom handoff without a partial executable window.
helper_replaced=1
atomic_install "$staged_helper" "$destination_helper" 0755
/usr/bin/cmp -s "$staged_helper" "$destination_helper" || die "helper install mismatch"
/usr/bin/codesign --verify --strict "$destination_helper" ||
  die "installed helper signature failed"
has_hardened_runtime "$destination_helper" || die "installed helper is not hardened"
has_expected_identifier "$destination_helper" || die "installed helper identifier is unexpected"

module_replaced=1
atomic_install "$staged_module" "$destination_module" 0755
/usr/bin/cmp -s "$staged_module" "$destination_module" || die "module install mismatch"
/usr/bin/codesign --verify --strict "$destination_module" ||
  die "installed module signature failed"
/usr/bin/lipo "$destination_module" -verify_arch x86_64 arm64 arm64e ||
  die "installed module architecture check failed"

echo "guarded sudo review installation is active"
echo "the Apple contextual sheet and stock pam_tid remain as fallbacks"
echo "run a harmless sudo command in another terminal, then enter 'keep' or 'restore'"
echo "timeout/EOF/signal also restores the prior contextual PAM module"

decision=""
if ! IFS= read -r -t 600 decision; then
  echo "no decision received; restoring" >&2
  exit 124
fi

case "$decision" in
  keep)
    keep_active=1
    echo "installed sudo review helper and PAM module"
    ;;
  restore)
    echo "restore requested"
    ;;
  *)
    echo "invalid decision; restoring" >&2
    exit 64
    ;;
esac
