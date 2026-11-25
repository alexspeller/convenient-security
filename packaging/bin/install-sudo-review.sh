#!/usr/bin/env bash
set -euo pipefail

# Guarded, reversible installation of the contextual sudo review integration:
# the csec PAM module and the hardened review helper it hands off to. This is
# the sudo stage of packaging/bin/build-and-install.sh and of `csec setup`,
# which both run the copy the package installs; run it through sudo from the
# login user (it needs SUDO_USER to prove the live path as that user).
#
# On a Mac without the integration it activates the module in
# /etc/pam.d/sudo_local immediately before stock pam_tid, adding pam_tid when
# it is absent so Apple's Touch ID sheet stays behind the csec factor, then
# installs the module and the helper. On a Mac that already has the line it
# replaces the module and the helper in place and adds the requisite deadline
# guard to an older installation. The review remains sufficient, so Use
# Password and helper failures keep Apple's recovery; only an unanswered
# review's expiry aborts the authentication before another prompt can appear.
#
# The decision to keep the installation is not typed; it is made by the live
# path itself. After installing, the script runs a harmless sudo as the login
# user and reads that one sudo's value-free unified-log trail, found by its
# PID. Only a sudo that succeeded because the installed helper it started
# approved it keeps the installation; a failed, denied, or timed-out sudo, or
# one that succeeded any other way (Apple's fallback or pam_tid after the
# helper refused or failed, or no hand-off at all), restores the prior module,
# helper, and PAM configuration and exits non-zero, after printing what the
# module and the helper logged during that sudo. Another sudo's review running
# at the same time is not evidence for this one.
#
# The removal (--uninstall, build-and-install.sh --uninstall-sudo) is the same
# transaction in reverse. It takes csec's lines out of sudo_local first,
# putting back the stock file kept beside it when nothing else changed since
# the install, then runs the same harmless sudo, which must now succeed through
# Apple's Touch ID or password alone. Only then are the module, the helper and
# any other csec-sudo-review* file deleted; a failed sudo restores sudo_local
# exactly and exits non-zero with the integration still installed.
#
# Modes:
#   sudo packaging/bin/install-sudo-review.sh
#   sudo packaging/bin/install-sudo-review.sh --uninstall
#   packaging/bin/install-sudo-review.sh --print-installed-digests
#     (read-only, no root: prints the installed helper's and module's CDHash,
#     identifier, and hardened-runtime state, and which helper the module names)

die() {
  echo "install-sudo-review: $*" >&2
  exit 1
}

# Two copies of this script exist. The signed package installs one into its
# root-owned support directory beside the module and helper it carries, and
# `csec setup` (and build-and-install.sh) runs that one: it installs the
# package's payload, so no checkout is needed. A checkout's copy installs the
# checkout's own build. The location decides, never an argument or the
# environment, so the installed copy cannot be pointed at other files.
script_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
package_support="/Library/Application Support/ConvenientSecurity"
if [[ "$script_directory" == "$package_support/libexec" ]]; then
  from_package=1
  source_module="$package_support/sudo-review/pam_csec_sudo.so"
  source_helper="$package_support/sudo-review/csec-sudo-review"
  policy_library="$script_directory/sudo-review-policy.sh"
  identity_library="$script_directory/identity.sh"
  identity_file="$script_directory/identity.xcconfig"
  missing_payload_hint="reinstall the Convenient Security package"
else
  from_package=0
  repo_root="$(cd "$script_directory/../.." && pwd -P)"
  source_module="$repo_root/packaging/build/sudo-pam/pam_csec_sudo.so"
  source_helper="$repo_root/packaging/build/sudo-review/csec-sudo-review"
  policy_library="$repo_root/packaging/lib/sudo-review-policy.sh"
  identity_library="$repo_root/packaging/lib/identity.sh"
  identity_file="$repo_root/identity.xcconfig"
  missing_payload_hint="run packaging/bin/build-sudo-pam.sh and packaging/bin/build-sudo-review.sh"
fi
module_directory="/usr/local/lib/pam"
destination_module="$module_directory/pam_csec_sudo.so"
helper_directory="/usr/local/libexec"
destination_helper="$helper_directory/csec-sudo-review"
pam_directory="/private/etc/pam.d"
sudo_local="/private/etc/pam.d/sudo_local"
sudo_local_backup="/private/etc/pam.d/sudo_local.csec-context-backup"
custom_line="auth       sufficient     /usr/local/lib/pam/pam_csec_sudo.so"
guard_line="auth       requisite      /usr/local/lib/pam/pam_csec_sudo.so review_guard"
touch_id_line="auth       sufficient     pam_tid.so"
# The first line of a sudo_local this script creates on a Mac that had none.
stock_header='# sudo_local: local config file which survives system update and is included for sudo'
# shellcheck source=packaging/lib/sudo-review-policy.sh
source "$policy_library"
# The team and identifier the module and helper must be signed with.
# shellcheck source=packaging/lib/identity.sh
source "$identity_library"
csec_identity_load "$identity_file"
product_requirement="$csec_product_requirement"
helper_identifier="$csec_identifier.sudo-review"

module_backup=""
helper_backup=""
staged_module=""
staged_helper=""
candidate_sudo_local=""
configuration_backup=""
fresh_install=0
sudo_local_existed=0
module_existed=0
helper_existed=0
helper_backup_hardened=0
module_directory_created=0
helper_directory_created=0
module_replaced=0
helper_replaced=0
config_activated=0
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
  /usr/bin/codesign -dvvv "$1" 2>&1 |
    /usr/bin/grep 'flags=.*runtime' >/dev/null
}

has_expected_identifier() {
  # No `grep -q` (and no `awk ... exit` below): with this script's `set -o
  # pipefail`, an early-exiting reader closes the pipe on its first match, which
  # SIGPIPEs the upstream `codesign` into a non-zero exit and fails the whole
  # pipeline *even though the identifier matched*. Reading all of codesign's
  # output — as has_hardened_runtime already does — lets codesign exit 0.
  /usr/bin/codesign -dvvv "$1" 2>&1 |
    /usr/bin/grep -Fx -- "Identifier=${helper_identifier}" >/dev/null
}

has_architectures() {
  # One architecture per -verify_arch: Xcode 27.1's lipo reads any further
  # names as input files and fails ("-verify_arch requires exactly one input
  # file"), where earlier versions checked them all.
  local file="$1" architecture
  shift
  for architecture in "$@"; do
    /usr/bin/lipo "$file" -verify_arch "$architecture" || return 1
  done
}

cdhash_of() {
  # No `exit` in awk: see has_expected_identifier — an early close SIGPIPEs
  # codesign and, under pipefail, fails the pipeline. `^CDHash=` matches one line.
  /usr/bin/codesign -dvvv "$1" 2>&1 |
    /usr/bin/awk -F= '/^CDHash=/ { print $2 }'
}

# The module embeds the helper path and identifier it will hand off to as
# NUL-terminated C strings; `strings` prints each as one whole line, so a spike
# or otherwise foreign module (`…/csec-sudo-review-spike`) does not match.
module_names_installed_helper() {
  # No `grep -q`: under pipefail it exits on match and SIGPIPEs `strings` into a
  # non-zero exit, failing the pipeline even when the string is present (same bug
  # as has_expected_identifier). Read all of strings' output instead.
  /usr/bin/strings -a -- "$1" 2>/dev/null | /usr/bin/grep -Fx -- "$destination_helper" >/dev/null &&
    /usr/bin/strings -a -- "$1" 2>/dev/null | /usr/bin/grep -Fx -- "$helper_identifier" >/dev/null
}

print_installed_digests() {
  local status=0
  if [[ -f "$destination_helper" && ! -L "$destination_helper" ]]; then
    local hardened="no" identifier="unexpected"
    has_hardened_runtime "$destination_helper" && hardened="yes"
    has_expected_identifier "$destination_helper" && identifier="$helper_identifier"
    echo "helper: $destination_helper cdhash=$(cdhash_of "$destination_helper") identifier=$identifier hardened=$hardened"
  else
    echo "helper: $destination_helper absent"
    status=1
  fi
  if [[ -f "$destination_module" && ! -L "$destination_module" ]]; then
    local names="another helper"
    module_names_installed_helper "$destination_module" && names="$destination_helper"
    echo "module: $destination_module cdhash=$(cdhash_of "$destination_module") hands off to: $names"
  else
    echo "module: $destination_module absent"
    status=1
  fi
  if [[ -f "$sudo_local" ]] &&
      csec_sudo_policy "$custom_line" "$guard_line" "$touch_id_line" <"$sudo_local" |
        /usr/bin/cmp -s "$sudo_local" -; then
    echo "pam: csec review and deadline guard active in $sudo_local"
  else
    echo "pam: csec line not active in $sudo_local"
    status=1
  fi
  return "$status"
}

uninstall=0
if [[ "$#" -eq 1 && "$1" == "--print-installed-digests" ]]; then
  print_installed_digests
  exit "$?"
elif [[ "$#" -eq 1 && "$1" == "--uninstall" ]]; then
  uninstall=1
elif [[ "$#" -ne 0 ]]; then
  die "usage: sudo packaging/bin/install-sudo-review.sh [--uninstall] | packaging/bin/install-sudo-review.sh --print-installed-digests"
fi

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

# The live check. A harmless sudo as the login user must pass the new module,
# which must hand off to the installed helper, and the helper must approve it.
# Success keeps the installation; anything else restores it. sudo's exit status
# alone cannot tell: Apple's fallback and pam_tid approve a sudo the helper
# rejected or never saw, and another sudo's review can run at the same time.
# So the verdict comes from the value-free trail of this one sudo
# (csec_sudo_verified_approval): the login user's shell prints its PID and
# execs the sudo, which keeps it, and the module's lines under that PID must
# end in the approval of a helper that this sudo started and that exited 0.
verification_shell='echo "$$"; exec /usr/bin/sudo -p "$1" /usr/bin/true'
verification_pid=""
verification_started=""
# Prints the module's and helper's lines for the verification sudo, or for
# every sudo since it started when its PID is unknown.
print_sudo_trail() {
  echo "what the csec sudo module and review helper logged during the verification sudo:" >&2
  local predicate
  if [[ -n "$verification_pid" ]]; then
    predicate="subsystem == \"$csec_identifier\" AND ((category == \"process-liveness\" AND processID == $verification_pid)"
    local helper
    for helper in $(csec_sudo_module_trail "$verification_started" "$verification_pid" |
        csec_sudo_named_helpers); do
      predicate+=" OR (category == \"sudo-review\" AND processID == $helper)"
    done
    predicate+=")"
  else
    predicate="subsystem == \"$csec_identifier\" AND ((process == \"sudo\" AND category == \"process-liveness\") OR (process == \"csec-sudo-review\" AND category == \"sudo-review\"))"
  fi
  csec_sudo_log_show "$verification_started" "$predicate" >&2 ||
    echo "(the unified log could not be read)" >&2
}
# Runs the verification sudo and decides. On success sets approval_route.
run_live_verification() {
  verification_started="$(/bin/date '+%Y-%m-%d %H:%M:%S')"
  # Root invokes sudo as the login user without authenticating; the inner sudo
  # then authenticates that user through PAM exactly as their own shell would.
  /usr/bin/sudo -u "$login_user" -H -- /usr/bin/sudo -k
  local live_sudo_status=0 pid_output
  pid_output="$(/usr/bin/sudo -u "$login_user" -H -- /bin/sh -c "$verification_shell" \
    csec-sudo-verify "Password for %u (fallback for the csec sudo review check): ")" ||
    live_sudo_status=$?
  if [[ "$pid_output" =~ ^[1-9][0-9]*$ ]]; then
    verification_pid="$pid_output"
  fi
  if [[ "$live_sudo_status" -ne 0 ]]; then
    print_sudo_trail
    echo "the verification sudo did not succeed (status $live_sudo_status); restoring" >&2
    return 1
  fi
  if [[ -z "$verification_pid" ]]; then
    print_sudo_trail
    echo "the verification sudo succeeded but did not report its PID, so its review cannot be told from another; restoring" >&2
    return 1
  fi
  # The module and helper log before sudo exits; the retries only cover the
  # unified log's delivery, never a different verdict.
  local attempt verdict=""
  for attempt in 1 2 3 4 5 6 7 8 9 10; do
    if verdict="$(csec_sudo_verified_approval "$verification_started" \
        "$verification_pid" "$destination_helper")"; then
      approval_route="$verdict"
      return 0
    fi
    /bin/sleep 0.2
  done
  print_sudo_trail
  echo "sudo succeeded, but not through an approval by $destination_helper: $verdict (the trail above shows how far the hand-off got); restoring" >&2
  return 1
}
# The removal's live check. With csec's lines gone, the same harmless sudo must
# still succeed, now through Apple's Touch ID or password; anything else puts
# the integration back. Its exit status is the evidence: the removal has
# already shown that no PAM configuration loads the module any more, so
# whatever authenticated this sudo is the stock path that will remain.
run_removal_verification() {
  /usr/bin/sudo -u "$login_user" -H -- /usr/bin/sudo -k
  local removal_sudo_status=0
  /usr/bin/sudo -u "$login_user" -H -- /bin/sh -c "$verification_shell" \
    csec-sudo-verify "Password for %u (checking that sudo works without csec): " >/dev/null ||
    removal_sudo_status=$?
  if [[ "$removal_sudo_status" -ne 0 ]]; then
    echo "the verification sudo did not succeed without csec (status $removal_sudo_status); restoring" >&2
    return 1
  fi
}
# The end of the live check's definitions (the tests read up to here).

removal_candidate=""
removal_rendered=""
removal_backup=""
removal_deactivated=0
removal_kept=0

# Whether the PAM configuration file $1 has an active line naming the module.
loads_csec_module() {
  /usr/bin/awk '$1 !~ /^#/ && index($0, "pam_csec_sudo.so") { found = 1 } END { exit !found }' "$1"
}

finish_uninstall() {
  original_status="$?"
  restore_status=0
  trap - EXIT HUP INT TERM

  if [[ "$removal_kept" -eq 0 && "$removal_deactivated" -eq 1 ]]; then
    # Only sudo_local has changed; the module and helper are deleted after the
    # live check, so putting its exact prior bytes back reinstates everything.
    if replace_sudo_local "$removal_backup"; then
      echo "restored: $sudo_local; the sudo integration is still installed"
    else
      echo "FATAL: could not restore $sudo_local; its prior contents are kept at $removal_backup" >&2
      restore_status=1
      removal_backup=""
    fi
  fi

  for temporary in "$removal_candidate" "$removal_rendered" "$removal_backup"; do
    if [[ -n "$temporary" && -e "$temporary" ]]; then
      /bin/rm -f -- "$temporary" || restore_status=1
    fi
  done

  if [[ "$restore_status" -ne 0 ]]; then
    exit "$restore_status"
  fi
  exit "$original_status"
}

uninstall_integration() {
  local directory directory_mode service
  for directory in "$module_directory" "$helper_directory"; do
    [[ -e "$directory" || -L "$directory" ]] || continue
    [[ -d "$directory" && ! -L "$directory" ]] || die "unexpected directory: $directory"
    [[ "$(/usr/bin/stat -f '%u' "$directory")" == "0" ]] ||
      die "directory is not root-owned: $directory"
    directory_mode="$(/usr/bin/stat -f '%Lp' "$directory")"
    if (( (8#$directory_mode & 0022) != 0 )); then
      die "directory is group- or world-writable: $directory"
    fi
  done
  # Another PAM service that loads the module would fail once it is deleted.
  # The stock backup is no service; what it holds is checked before it is used.
  for service in "$pam_directory"/*; do
    [[ "$service" != "$sudo_local" && "$service" != "$sudo_local_backup" && -f "$service" ]] ||
      continue
    if loads_csec_module "$service"; then
      die "$service loads the csec PAM module; remove that line by hand first"
    fi
  done

  local active=0 remove_sudo_local=0 restoration=""
  if [[ -e "$sudo_local" ]]; then
    [[ -f "$sudo_local" && ! -L "$sudo_local" ]] || die "unexpected sudo_local file"
    [[ "$(/usr/bin/stat -f '%u' "$sudo_local")" == "0" ]] || die "sudo_local is not root-owned"
    removal_candidate="$(/usr/bin/mktemp /private/tmp/csec-sudo-local-removal.XXXXXX)"
    /bin/chmod 0600 "$removal_candidate"
    csec_sudo_policy_removed "$custom_line" "$guard_line" <"$sudo_local" >"$removal_candidate" ||
      die "$sudo_local names the csec module in a form this script does not recognise; repair it by hand"
    if loads_csec_module "$sudo_local"; then
      active=1
    fi
  fi

  if [[ "$active" -eq 1 ]]; then
    # An install renders the stock file deterministically, so when the live
    # file is exactly that rendering nothing else changed since, and the stock
    # bytes go back, pam_tid's presence or absence included. A file changed
    # since keeps its changes and loses only csec's lines.
    removal_rendered="$(/usr/bin/mktemp /private/tmp/csec-sudo-local-rendered.XXXXXX)"
    /bin/chmod 0600 "$removal_rendered"
    restoration="$sudo_local without csec's lines"
    if [[ -e "$sudo_local_backup" ]]; then
      [[ -f "$sudo_local_backup" && ! -L "$sudo_local_backup" ]] ||
        die "unexpected existing backup: $sudo_local_backup"
      [[ "$(/usr/bin/stat -f '%u' "$sudo_local_backup")" == "0" ]] ||
        die "existing backup is not root-owned: $sudo_local_backup"
      if csec_sudo_policy "$custom_line" "$guard_line" "$touch_id_line" \
          <"$sudo_local_backup" >"$removal_rendered" 2>/dev/null &&
          /usr/bin/cmp -s "$removal_rendered" "$sudo_local"; then
        /bin/cp -- "$sudo_local_backup" "$removal_candidate"
        restoration="the stock $sudo_local from $sudo_local_backup"
      else
        restoration="$sudo_local without csec's lines (it changed after csec was installed, so $sudo_local_backup is not put back)"
      fi
    elif printf '%s\n' "$stock_header" |
        csec_sudo_policy "$custom_line" "$guard_line" "$touch_id_line" >"$removal_rendered" &&
        /usr/bin/cmp -s "$removal_rendered" "$sudo_local"; then
      remove_sudo_local=1
      restoration="no $sudo_local, as before csec created it"
    fi
    if loads_csec_module "$removal_candidate"; then
      die "could not construct a sudo_local without csec"
    fi

    removal_backup="$(/usr/bin/mktemp /private/tmp/csec-sudo-local-prior.XXXXXX)"
    /usr/bin/install -o root -g wheel -m 0600 "$sudo_local" "$removal_backup"
    /usr/bin/cmp -s "$sudo_local" "$removal_backup" || die "configuration backup failed"

    # Deactivate first: from here no sudo reaches the module, so deleting it
    # after the live check cannot leave a PAM line naming a missing file.
    removal_deactivated=1
    if [[ "$remove_sudo_local" -eq 1 ]]; then
      /bin/rm -f -- "$sudo_local"
      echo "removed: $sudo_local (csec created it)"
    else
      replace_sudo_local "$removal_candidate"
      /usr/bin/cmp -s "$removal_candidate" "$sudo_local" || die "the new sudo_local did not validate"
      echo "deactivated: csec's lines are no longer in $sudo_local"
    fi

    echo "verifying that sudo works without csec as $login_user: use Touch ID or your password"
    run_removal_verification
    echo "verified: sudo succeeded through Apple's own authentication"
  else
    echo "$sudo_local does not activate csec; deleting whatever csec left behind"
  fi
  removal_kept=1

  # The canonical module and helper, the August 2026 spike helper beside it,
  # and any temporary an interrupted install left: nothing loads them now.
  local leftover removed=0 sweep_status=0
  for leftover in "$module_directory"/pam_csec_sudo.so* "$helper_directory"/csec-sudo-review*; do
    [[ -e "$leftover" || -L "$leftover" ]] || continue
    if [[ -L "$leftover" || ! -f "$leftover" ]]; then
      echo "left in place, not a regular file: $leftover" >&2
      sweep_status=1
    elif /bin/rm -f -- "$leftover"; then
      echo "removed: $leftover"
      removed=1
    else
      echo "could not remove: $leftover" >&2
      sweep_status=1
    fi
  done
  # Only an empty directory goes; csec creates this one when it is missing.
  if [[ -d "$module_directory" && ! -L "$module_directory" ]]; then
    /bin/rmdir "$module_directory" 2>/dev/null && echo "removed: $module_directory (empty)"
  fi

  if [[ -e "$sudo_local_backup" ]]; then
    if [[ -f "$sudo_local_backup" && ! -L "$sudo_local_backup" && -f "$sudo_local" ]] &&
        /usr/bin/cmp -s "$sudo_local_backup" "$sudo_local"; then
      /bin/rm -f -- "$sudo_local_backup"
      echo "removed: $sudo_local_backup (identical to $sudo_local)"
    else
      echo "kept: $sudo_local_backup, the stock file from before csec, which differs from $sudo_local"
    fi
  fi

  if [[ "$sweep_status" -ne 0 ]]; then
    echo "sudo no longer uses csec, but the files above remain; delete them by hand" >&2
    exit 1
  fi
  if [[ "$active" -eq 1 ]]; then
    echo "the csec sudo integration is removed; sudo now uses $restoration"
  elif [[ "$removed" -eq 1 ]]; then
    echo "the csec sudo integration was not active; its leftover files are removed"
  else
    echo "the csec sudo integration is not installed; nothing to remove"
  fi
}

finish() {
  original_status="$?"
  restore_status=0
  trap - EXIT HUP INT TERM

  if [[ "$keep_active" -eq 0 ]]; then
    # Deactivate first so no sudo can reach a module that is being restored.
    if [[ "$config_activated" -eq 1 ]]; then
      if [[ "$sudo_local_existed" -eq 1 ]]; then
        if replace_sudo_local "$configuration_backup"; then
          echo "restored: $sudo_local"
        else
          echo "FATAL: could not restore $sudo_local from $configuration_backup" >&2
          restore_status=1
        fi
      elif /bin/rm -f -- "$sudo_local"; then
        echo "removed: $sudo_local (it did not exist before)"
      else
        echo "FATAL: could not remove $sudo_local" >&2
        restore_status=1
      fi
    fi

    if [[ "$module_replaced" -eq 1 ]]; then
      if [[ "$module_existed" -eq 1 ]]; then
        if atomic_install "$module_backup" "$destination_module" 0755 &&
            /usr/bin/codesign --verify --strict "$destination_module"; then
          echo "restored prior contextual module: $destination_module"
        else
          echo "FATAL: could not restore prior PAM module" >&2
          restore_status=1
        fi
      elif ! /bin/rm -f -- "$destination_module"; then
        echo "FATAL: could not remove newly installed PAM module" >&2
        restore_status=1
      fi
    fi
    if [[ "$module_directory_created" -eq 1 ]]; then
      /bin/rmdir "$module_directory" 2>/dev/null || true
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
      elif [[ "$helper_existed" -eq 1 ]]; then
        echo "restored contextual-only fallback; prior helper was not hardened"
      fi
    fi
    if [[ "$helper_directory_created" -eq 1 ]]; then
      /bin/rmdir "$helper_directory" 2>/dev/null || true
    fi
  fi

  for temporary in \
      "$module_backup" "$helper_backup" "$staged_module" "$staged_helper" \
      "$candidate_sudo_local" "$configuration_backup"; do
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
login_user="${SUDO_USER:-}"
[[ -n "$login_user" && "$login_user" != "root" ]] ||
  die "run through sudo from the login user; the live check runs sudo as that user"
login_uid="$(/usr/bin/id -u "$login_user" 2>/dev/null)" ||
  die "SUDO_USER does not name a local account"
[[ "$login_uid" != "0" ]] || die "SUDO_USER must not be root"

for protected_directory in / /usr /usr/local /usr/local/lib /private/etc /private/etc/pam.d; do
  [[ -d "$protected_directory" && ! -L "$protected_directory" ]] ||
    die "unexpected protected directory: $protected_directory"
  [[ "$(/usr/bin/stat -f '%u' "$protected_directory")" == "0" ]] ||
    die "protected directory is not root-owned: $protected_directory"
  protected_mode="$(/usr/bin/stat -f '%Lp' "$protected_directory")"
  if (( (8#$protected_mode & 0022) != 0 )); then
    die "protected directory is group- or world-writable: $protected_directory"
  fi
done

if [[ "$uninstall" -eq 1 ]]; then
  trap finish_uninstall EXIT
  uninstall_integration
  exit 0
fi

for source in "$source_module" "$source_helper"; do
  [[ -f "$source" && ! -L "$source" ]] ||
    die "missing regular build artifact: $source ($missing_payload_hint)"
done

if [[ -e "$sudo_local" ]]; then
  [[ -f "$sudo_local" && ! -L "$sudo_local" ]] || die "unexpected sudo_local file"
  [[ "$(/usr/bin/stat -f '%u' "$sudo_local")" == "0" ]] || die "sudo_local is not root-owned"
  sudo_local_existed=1
  custom_count="$(/usr/bin/grep -Fxc "$custom_line" "$sudo_local" || true)"
else
  custom_count=0
fi
if [[ -e "$destination_module" ]]; then
  [[ -f "$destination_module" && ! -L "$destination_module" ]] ||
    die "unexpected existing PAM module: $destination_module"
  module_existed=1
fi

case "$custom_count" in
  1)
    # The pure renderer below validates both the old and guarded formats.
    ;;
  0)
    fresh_install=1
    [[ "$module_existed" -eq 0 ]] ||
      die "$destination_module exists but $sudo_local does not activate it; repair the PAM configuration by hand first"
    ;;
  *)
    die "the csec PAM line appears $custom_count times in $sudo_local; expected at most once"
    ;;
esac

/usr/bin/codesign --verify --strict "$source_module" || die "module signature check failed"
has_architectures "$source_module" x86_64 arm64 arm64e ||
  die "module does not contain all expected architectures"
/usr/bin/codesign --verify --strict "$source_helper" || die "helper signature check failed"
has_hardened_runtime "$source_helper" || die "helper is not hardened-runtime signed"
has_expected_identifier "$source_helper" || die "helper signing identifier is unexpected"
has_architectures "$source_helper" "$(/usr/bin/uname -m)" ||
  die "helper does not support this host architecture"
module_names_installed_helper "$source_module" ||
  die "the built module does not name $destination_helper / $helper_identifier"
if [[ "$module_existed" -eq 1 ]]; then
  /usr/bin/codesign --verify --strict "$destination_module" ||
    die "installed module signature check failed"
fi

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
module_names_installed_helper "$staged_module" || die "staged module names another helper"
if [[ "$from_package" -eq 1 ]]; then
  # The package only ever carries the product team's signed builds.
  /usr/bin/codesign --verify --strict \
    -R="$product_requirement and identifier \"$csec_identifier.sudo-pam\"" \
    "$staged_module" || die "the package's PAM module is not signed by the product team"
  /usr/bin/codesign --verify --strict \
    -R="$product_requirement and identifier \"$helper_identifier\"" \
    "$staged_helper" || die "the package's review helper is not signed by the product team"
fi
"$staged_helper" --self-test || die "staged helper self-test failed"

candidate_sudo_local="$(/usr/bin/mktemp /private/tmp/csec-sudo-local.XXXXXX)"
/bin/chmod 0600 "$candidate_sudo_local"
if [[ "$sudo_local_existed" -eq 1 ]]; then
  csec_sudo_policy "$custom_line" "$guard_line" "$touch_id_line" \
    <"$sudo_local" >"$candidate_sudo_local" || die "could not construct candidate sudo_local"
  # Rollback restores this transaction's exact prior configuration, which on
  # an upgrade already contains csec. The permanent backup is pre-csec stock.
  configuration_backup="$(/usr/bin/mktemp /private/tmp/csec-sudo-config-backup.XXXXXX)"
  /usr/bin/install -o root -g wheel -m 0600 "$sudo_local" "$configuration_backup"
  /usr/bin/cmp -s "$sudo_local" "$configuration_backup" || die "configuration backup failed"
else
  printf '%s\n' "$stock_header" |
    csec_sudo_policy "$custom_line" "$guard_line" "$touch_id_line" \
      >"$candidate_sudo_local" || die "could not construct new sudo_local"
fi

if [[ "$fresh_install" -eq 1 ]]; then
  if [[ "$sudo_local_existed" -eq 1 ]]; then
    # The pre-csec file is kept permanently beside the live one for a later
    # manual rollback; an existing backup must still describe this stock file.
    if [[ -e "$sudo_local_backup" ]]; then
      [[ -f "$sudo_local_backup" && ! -L "$sudo_local_backup" ]] ||
        die "unexpected existing backup: $sudo_local_backup"
      [[ "$(/usr/bin/stat -f '%u' "$sudo_local_backup")" == "0" ]] ||
        die "existing backup is not root-owned: $sudo_local_backup"
      /usr/bin/cmp -s "$sudo_local" "$sudo_local_backup" ||
        die "existing backup no longer matches the current sudo_local: $sudo_local_backup"
      echo "reusing verified stock backup: $sudo_local_backup"
    else
      /usr/bin/install -o root -g wheel -m 0644 "$sudo_local" "$sudo_local_backup"
      /usr/bin/cmp -s "$sudo_local" "$sudo_local_backup" || die "backup verification failed"
    fi
  fi
fi

if [[ "$module_existed" -eq 1 ]]; then
  module_backup="$(/usr/bin/mktemp /private/tmp/csec-sudo-module-backup.XXXXXX)"
  /usr/bin/install -o root -g wheel -m 0700 "$destination_module" "$module_backup"
  /usr/bin/cmp -s "$destination_module" "$module_backup" || die "module backup failed"
fi
if [[ ! -e "$module_directory" ]]; then
  /usr/bin/install -d -o root -g wheel -m 0755 "$module_directory"
  module_directory_created=1
fi
[[ -d "$module_directory" && ! -L "$module_directory" ]] || die "unexpected PAM module directory"
[[ "$(/usr/bin/stat -f '%u' "$module_directory")" == "0" ]] ||
  die "PAM module directory is not root-owned"
module_directory_mode="$(/usr/bin/stat -f '%Lp' "$module_directory")"
if (( (8#$module_directory_mode & 0022) != 0 )); then
  die "PAM module directory is group- or world-writable"
fi

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
elif [[ ! -e "$helper_directory" ]]; then
  /usr/bin/install -d -o root -g wheel -m 0755 "$helper_directory"
  helper_directory_created=1
fi
[[ -d "$helper_directory" && ! -L "$helper_directory" ]] || die "unexpected helper directory"
[[ "$(/usr/bin/stat -f '%u' "$helper_directory")" == "0" ]] ||
  die "helper directory is not root-owned"
helper_directory_mode="$(/usr/bin/stat -f '%Lp' "$helper_directory")"
if (( (8#$helper_directory_mode & 0022) != 0 )); then
  die "helper directory is group- or world-writable"
fi

# Helper first: with the old module still installed it is inert. Replacing the
# module second atomically switches the handoff without a partial window, and
# on a fresh Mac the PAM line is activated last, after both binaries verify.
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
has_architectures "$destination_module" x86_64 arm64 arm64e ||
  die "installed module architecture check failed"

if [[ "$sudo_local_existed" -eq 0 ]] || ! /usr/bin/cmp -s "$candidate_sudo_local" "$sudo_local"; then
  config_activated=1
  replace_sudo_local "$candidate_sudo_local"
  [[ "$(/usr/bin/grep -Fxc "$custom_line" "$sudo_local")" == "1" ]] ||
    die "installed sudo_local did not validate"
  [[ "$(/usr/bin/grep -Fxc "$guard_line" "$sudo_local")" == "1" ]] ||
    die "installed sudo_local omitted the deadline guard"
  echo "activated: $custom_line"
  echo "activated: $guard_line"
fi


echo "verifying the live sudo path as $login_user: approve the Convenient Security review that appears"
approval_route=""
run_live_verification

keep_active=1
echo "verified: the PAM module handed off to $destination_helper, which approved the verification sudo ($approval_route)"
# The August 2026 pre-release helper lived beside the real one under its own
# name; once the verified module hands off to the canonical helper, nothing
# can reach it, so it goes.
spike_helper="$helper_directory/csec-sudo-review-spike"
if [[ -f "$spike_helper" && ! -L "$spike_helper" ]]; then
  if /bin/rm -f -- "$spike_helper"; then
    echo "removed the dead pre-release helper: $spike_helper"
  else
    echo "could not remove the pre-release helper: $spike_helper (harmless; delete it by hand)" >&2
  fi
fi
echo "installed sudo review helper: cdhash=$(cdhash_of "$destination_helper") identifier=$helper_identifier"
echo "installed PAM module: cdhash=$(cdhash_of "$destination_module")"
if [[ "$fresh_install" -eq 1 && "$sudo_local_existed" -eq 1 ]]; then
  echo "stock sudo_local kept at: $sudo_local_backup"
fi
echo "the Apple Touch ID sheet and the password prompt remain the fallbacks after the csec factor"
