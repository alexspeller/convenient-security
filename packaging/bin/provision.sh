#!/usr/bin/env bash
set -euo pipefail

# Run Fastlane with csec-delivered App Store Connect credentials. Configuration
# is reference-only (see .env.example). Private-key bytes stay in an inherited
# pipe, outside argv, the process environment and the filesystem.
#
#   provision.sh              lane :provision, the Mac's Developer ID profile
#   provision.sh testflight   lane :testflight, the iPhone app's App Store build
#                             archived and uploaded to TestFlight
# shellcheck source=../lib/asc-credentials.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/asc-credentials.sh"

provision_lane() {
  case "$#:${1:-provision}" in
    0:provision | 1:provision | 1:testflight) echo "${1:-provision}" ;;
    *)
      echo "usage: packaging/bin/provision.sh [testflight]" >&2
      return 2
      ;;
  esac
}

main() {
  local here lane
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  if [ "${1:-}" != --with-asc-credentials ]; then
    # An unknown lane stops here, before csec is asked for anything.
    lane="$(provision_lane "$@")" || return
    # shellcheck disable=SC1091
    [ -f "$here/.env" ] && source "$here/.env"
    asc_with_credentials "$here/bin/provision.sh" "$lane"
    return
  fi
  shift
  lane="$(provision_lane "$@")" || return
  asc_require_credential_files
  command -v mise >/dev/null 2>&1 || {
    echo "provision: mise is required; it runs Fastlane on the Ruby pinned in packaging/.tool-versions" >&2
    return 1
  }
  ASC_KEY_ID="$(/bin/cat "$ASC_KEY_ID_FILE")"
  ASC_ISSUER_ID="$(/bin/cat "$ASC_ISSUER_ID_FILE")"
  [ -n "$ASC_KEY_ID" ] && [ -n "$ASC_ISSUER_ID" ] || return 1
  ASC_KEY_FILE="$ASC_PRIVATE_KEY_FILE"
  export ASC_KEY_ID ASC_ISSUER_ID ASC_KEY_FILE
  # The App ID and team Fastlane works with, from identity.xcconfig.
  # shellcheck source=../lib/identity.sh
  source "$here/lib/identity.sh"
  csec_identity_load "$here/../identity.xcconfig"
  CSEC_IDENTIFIER="$csec_identifier"
  CSEC_TEAM_ID="$csec_team_id"
  export CSEC_IDENTIFIER CSEC_TEAM_ID

  cd "$here"
  # Both mise and Bundler preserve csec's inherited descriptor. Fastlane reads
  # it once while building the API token; no second resolution is needed.
  BUNDLE_GEMFILE="$here/Gemfile" mise exec -C "$here" -- \
    bundle exec --keep-file-descriptors fastlane "$lane"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
