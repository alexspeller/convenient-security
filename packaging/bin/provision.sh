#!/usr/bin/env bash
set -euo pipefail

# Run `fastlane provision` (register the App ID + fetch a Developer ID profile)
# with the App Store Connect API key pulled from 1Password just-in-time. The
# private key reaches Fastlane through an inherited pipe fd, never a process
# environment, argv, or filesystem path.
#
# Config lives in packaging/.env (gitignored) so no personal 1Password paths are
# committed:
#   OP_ACCOUNT   the 1Password account shorthand (e.g. my.1password.com)
#   OP_ASC_ITEM  the op:// item base, e.g. "op://<Vault>/<Item Title>"
# The item must have fields: key_id, issuer_id, key (the .p8 contents).

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
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
[ -n "$op_path" ] || { echo "provision: official op CLI not found" >&2; exit 1; }

run_op() {
  env -i \
    HOME="${HOME:?HOME is required for 1Password CLI integration}" \
    USER="${USER:-$(id -un)}" \
    LOGNAME="${LOGNAME:-${USER:-$(id -un)}}" \
    PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
    "$op_path" "$@"
}

ASC_KEY_ID="$(run_op read "$OP_ASC_ITEM/key_id" --account "$OP_ACCOUNT")"
ASC_ISSUER_ID="$(run_op read "$OP_ASC_ITEM/issuer_id" --account "$OP_ACCOUNT")"
ASC_KEY_FILE="/dev/fd/3"
export ASC_KEY_ID ASC_ISSUER_ID ASC_KEY_FILE

# Fastlane reads key_filepath while constructing its API token. Anonymous pipe
# bytes are available only to this process lineage; another same-UID process's
# `/dev/fd/3` names its own descriptor, not ours.
exec 3< <(run_op read "$OP_ASC_ITEM/key" --account "$OP_ACCOUNT")
trap 'exec 3<&-' EXIT

cd "$here"
BUNDLE_GEMFILE="$here/Gemfile" bundle exec --keep-file-descriptors fastlane provision
