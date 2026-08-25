#!/usr/bin/env bash
set -euo pipefail

# Notarize and staple a signed artifact (the .app or the .pkg) with Apple, using
# the App Store Connect API key stored in 1Password — the SAME key used for
# provisioning (a Team key works for notarytool). Unlike Fastlane, notarytool
# requires --key to name a filesystem path. The .p8 is therefore written only
# while one submission is active, beneath an atomically created 0700 directory
# as a 0600 file, then removed on success, failure, or a handled signal. The key
# bytes never enter argv or the process environment.
#
# Config comes from packaging/.env (gitignored), same as provision.sh:
#   OP_ACCOUNT   1Password account shorthand (e.g. my.1password.com)
#   OP_ASC_ITEM  op:// item base with fields key_id / issuer_id / key
#
# Usage:
#   packaging/bin/notarize.sh packaging/build/ConvenientSecurity.app
#   packaging/bin/notarize.sh packaging/build/ConvenientSecurity.pkg

notary_key_directory=""
notary_key_file=""

cleanup_notary_key() {
  local failed=0
  local key_file="${notary_key_file:-}"
  local key_directory="${notary_key_directory:-}"

  if [ -n "$key_file" ] && { [ -e "$key_file" ] || [ -L "$key_file" ]; }; then
    /bin/rm -f "$key_file" || failed=1
  fi
  if [ -n "$key_directory" ] && [ -d "$key_directory" ]; then
    /bin/rmdir "$key_directory" || failed=1
  fi
  if [ "$failed" -eq 0 ]; then
    notary_key_file=""
    notary_key_directory=""
  fi
  return "$failed"
}

stage_notary_key_from_command() {
  [ "$#" -gt 0 ] || return 2

  local temporary_parent="${TMPDIR:-/tmp}"
  local previous_umask
  [ -d "$temporary_parent" ] || {
    echo "notarize: temporary directory is unavailable" >&2
    return 1
  }

  notary_key_directory="$(/usr/bin/mktemp -d "$temporary_parent/convenient-security-notary.XXXXXX")" || return 1
  if ! /bin/chmod 0700 "$notary_key_directory"; then
    cleanup_notary_key || true
    return 1
  fi
  notary_key_file="$notary_key_directory/AuthKey.p8"

  previous_umask="$(umask)"
  umask 077
  if ! "$@" > "$notary_key_file"; then
    umask "$previous_umask"
    cleanup_notary_key || true
    return 1
  fi
  umask "$previous_umask"

  if ! /bin/chmod 0600 "$notary_key_file" \
    || [ ! -f "$notary_key_file" ] \
    || [ -L "$notary_key_file" ] \
    || [ ! -s "$notary_key_file" ]; then
    echo "notarize: private-key staging failed" >&2
    cleanup_notary_key || true
    return 1
  fi
}

main() {
  local here target op_path key_id issuer_id
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  target="${1:?usage: notarize.sh <App.app | installer.pkg>}"
  [ -e "$target" ] || { echo "notarize: no such target: $target" >&2; exit 1; }
  # shellcheck disable=SC1091
  [ -f "$here/.env" ] && source "$here/.env"
  : "${OP_ACCOUNT:?set OP_ACCOUNT in packaging/.env}"
  : "${OP_ASC_ITEM:?set OP_ASC_ITEM in packaging/.env}"

  op_path=""
  for candidate in /opt/homebrew/bin/op /usr/local/bin/op /usr/bin/op; do
    if [ -x "$candidate" ]; then
      op_path="$candidate"
      break
    fi
  done
  [ -n "$op_path" ] || { echo "notarize: official op CLI not found" >&2; exit 1; }

  run_op() {
    env -i \
      HOME="${HOME:?HOME is required for 1Password CLI integration}" \
      USER="${USER:-$(id -un)}" \
      LOGNAME="${LOGNAME:-${USER:-$(id -un)}}" \
      PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
      "$op_path" "$@"
  }

  notary_key_directory=""
  notary_key_file=""
  cleanup_on_exit() {
    local original_status=$?
    if ! cleanup_notary_key; then
      echo "notarize: failed to remove the temporary private-key file" >&2
      [ "$original_status" -ne 0 ] || original_status=1
    fi
    exit "$original_status"
  }
  trap cleanup_on_exit EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM

  key_id="$(run_op read "$OP_ASC_ITEM/key_id" --account "$OP_ACCOUNT")"
  issuer_id="$(run_op read "$OP_ASC_ITEM/issuer_id" --account "$OP_ACCOUNT")"

  submit() {
    local result status
    stage_notary_key_from_command \
      run_op read "$OP_ASC_ITEM/key" --account "$OP_ACCOUNT"
    if ! result="$(xcrun notarytool submit "$1" \
      --key "$notary_key_file" --key-id "$key_id" --issuer "$issuer_id" \
      --wait --output-format json)"; then
      cleanup_notary_key || true
      return 1
    fi
    cleanup_notary_key
    printf '%s\n' "$result"
    status="$(printf '%s' "$result" | plutil -extract status raw -o - -)"
    if [ "$status" != "Accepted" ]; then
      echo "notarize: submission finished with status '$status', refusing to staple" >&2
      return 1
    fi
  }

  case "$target" in
    *.app)
      # A bundle can't be submitted directly — zip it, submit the zip, staple the
      # .app itself (you staple the bundle, never the zip).
      local zip="${target%.app}.notarize.zip"
      echo "--- zipping $target ---"
      ditto -c -k --keepParent "$target" "$zip"
      echo "--- submitting to notary service (waits for the result) ---"
      submit "$zip"
      rm -f "$zip"
      echo "--- stapling the ticket to $target ---"
      xcrun stapler staple "$target"
      ;;
    *.pkg)
      echo "--- submitting $target to notary service (waits for the result) ---"
      submit "$target"
      echo "--- stapling the ticket to $target ---"
      xcrun stapler staple "$target"
      ;;
    *)
      echo "notarize: target must be a .app or .pkg" >&2
      exit 1
      ;;
  esac

  echo "--- verify ---"
  if [[ "$target" == *.app ]]; then
    spctl --assess --type execute --verbose=2 "$target" 2>&1
  else
    spctl --assess --type install --verbose=2 "$target" 2>&1
  fi
  xcrun stapler validate "$target" 2>&1
  echo "Done: $target is notarized + stapled."
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
