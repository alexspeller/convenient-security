#!/usr/bin/env bash
set -euo pipefail

# Notarize and staple a signed artifact (the .app or the .pkg) with Apple, using
# the App Store Connect API key delivered by csec — the same key used for
# provisioning (a Team key works for notarytool). Unlike Fastlane, notarytool
# requires --key to name a filesystem path. The .p8 is therefore written only
# while one submission is active, beneath an atomically created 0700 directory
# as a 0600 file, then removed on success, failure, or a handled signal. The key
# bytes never enter argv or the process environment.
#
# The installer notarizes the app, packages it, then notarizes the package. Run
# with --build-package, all three happen under one csec delivery, so one install
# asks for the key once: the delivered descriptors are single-read pipes, so
# this process reads each once, keeps the values in unexported shell variables
# and closes the descriptors before build-pkg.sh runs, which inherits neither.
#
# Config comes from packaging/.env (gitignored), same as provision.sh:
#   ASC_KEY_ID_REF / ASC_ISSUER_ID_REF / ASC_KEY_REF: canonical csec refs
#   OP_ASC_ITEM: compatible item base with fields key_id / issuer_id / key
#
# Usage:
#   packaging/bin/notarize.sh --check-auth
#   packaging/bin/notarize.sh packaging/build/ConvenientSecurity.app
#   packaging/bin/notarize.sh packaging/build/ConvenientSecurity.pkg
#   packaging/bin/notarize.sh packaging/build/ConvenientSecurity.app \
#     --build-package packaging/bin/build-pkg.sh packaging/build/ConvenientSecurity.pkg

# shellcheck source=../lib/asc-credentials.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/asc-credentials.sh"

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

# Reads each inherited descriptor exactly once and closes it, leaving the
# values in key_id, issuer_id and private_key (never exported). read -d ''
# keeps every byte of the PEM, trailing newlines included.
read_inherited_credentials() {
  local path
  asc_require_credential_files || return
  key_id="$(/bin/cat "$ASC_KEY_ID_FILE")"
  issuer_id="$(/bin/cat "$ASC_ISSUER_ID_FILE")"
  private_key=""
  IFS= read -r -d '' private_key < "$ASC_PRIVATE_KEY_FILE" || true
  for path in "$ASC_KEY_ID_FILE" "$ASC_ISSUER_ID_FILE" "$ASC_PRIVATE_KEY_FILE"; do
    # asc_require_credential_files allowed only /dev/fd/<digits>.
    eval "exec ${path#/dev/fd/}<&-"
  done
  unset ASC_KEY_ID_FILE ASC_ISSUER_ID_FILE ASC_PRIVATE_KEY_FILE
  [ -n "$key_id" ] && [ -n "$issuer_id" ] && [ -n "$private_key" ]
}

main() {
  local here target auth_only inherited key_id issuer_id private_key
  local build_package="" package=""
  inherited=0
  if [ "${1:-}" = --with-asc-credentials ]; then
    inherited=1
    shift
  fi
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  target="${1:-}"
  auth_only=0
  case "$target" in
    --check-auth)
      auth_only=1
      ;;
    "")
      echo "usage: notarize.sh [--check-auth | <App.app | installer.pkg> | <App.app> --build-package <build-pkg.sh> <installer.pkg>]" >&2
      exit 2
      ;;
    *)
      [ -e "$target" ] || { echo "notarize: no such target: $target" >&2; exit 1; }
      ;;
  esac
  if [ "$#" -gt 1 ]; then
    # The package build is named so the installer's plan shows it, but the
    # credentialed process runs no other script than this one's sibling.
    if [ "$#" -ne 4 ] || [ "$2" != --build-package ] || [[ "$target" != *.app ]] ||
        [[ "$4" != *.pkg ]] || [ "$3" != "$here/bin/build-pkg.sh" ]; then
      echo "notarize: --build-package takes $here/bin/build-pkg.sh between an .app and the .pkg it builds" >&2
      exit 2
    fi
    build_package="$3"
    package="$4"
  fi
  if [ "$inherited" -eq 0 ]; then
    # shellcheck disable=SC1091
    [ -f "$here/.env" ] && source "$here/.env"
    if [ "$auth_only" -eq 1 ]; then
      asc_check_auth
      return
    fi
    case "$target" in
      *.app|*.pkg) ;;
      *) echo "notarize: target must be a .app or .pkg" >&2; return 1 ;;
    esac
    if [ -n "$build_package" ]; then
      asc_with_credentials "$here/bin/notarize.sh" "$target" --build-package "$build_package" "$package"
    else
      asc_with_credentials "$here/bin/notarize.sh" "$target"
    fi
    return
  fi
  [ "$auth_only" -eq 0 ] || return 2
  read_inherited_credentials || {
    echo "notarize: inherited credentials are incomplete" >&2
    return 1
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

  submit() {
    local result status
    stage_notary_key_from_command printf '%s' "$private_key"
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

  notarize_target() {
    local target="$1"
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

  notarize_target "$target"
  if [ -n "$build_package" ]; then
    "$build_package"
    [ -e "$package" ] || { echo "notarize: $build_package did not produce $package" >&2; return 1; }
    notarize_target "$package"
  fi
  private_key=""
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
