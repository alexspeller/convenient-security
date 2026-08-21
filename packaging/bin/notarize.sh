#!/usr/bin/env bash
set -euo pipefail

# Notarize and staple a signed artifact (the .app or the .pkg) with Apple, using
# the App Store Connect API key stored in 1Password — the SAME key used for
# provisioning (a Team key works for notarytool). The .p8 is streamed through
# an inherited anonymous pipe exposed to notarytool as `/dev/fd/3`; it never
# enters argv, environment, or a same-UID-readable temporary file.
#
# Config comes from packaging/.env (gitignored), same as provision.sh:
#   OP_ACCOUNT   1Password account shorthand (e.g. my.1password.com)
#   OP_ASC_ITEM  op:// item base with fields key_id / issuer_id / key
#
# Usage:
#   packaging/bin/notarize.sh packaging/build/ConvenientSecurity.app
#   packaging/bin/notarize.sh packaging/build/ConvenientSecurity.pkg

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target="${1:?usage: notarize.sh <App.app | installer.pkg>}"
[ -e "$target" ] || { echo "notarize: no such target: $target" >&2; exit 1; }
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

key_id="$(run_op read "$OP_ASC_ITEM/key_id" --account "$OP_ACCOUNT")"
issuer_id="$(run_op read "$OP_ASC_ITEM/issuer_id" --account "$OP_ACCOUNT")"
keyfile="/dev/fd/3"
exec 3< <(run_op read "$OP_ASC_ITEM/key" --account "$OP_ACCOUNT")
trap 'exec 3<&-' EXIT

submit() {
  local result status
  result="$(xcrun notarytool submit "$1" \
    --key "$keyfile" --key-id "$key_id" --issuer "$issuer_id" \
    --wait --output-format json)"
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
    zip="${target%.app}.notarize.zip"
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
