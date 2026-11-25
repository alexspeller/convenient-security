# Shared App Store Connect delivery for the packaging wrappers (source only).
# csec owns provider resolution and consent. These are canonical references;
# no provider CLI is used while csec is installed. The one exception is a first
# build on a Mac where csec has never been installed (asc_bootstrap_with_op).

asc_csec_app="/Applications/ConvenientSecurity.app"

asc_configure_credentials() {
  local base="${OP_ASC_ITEM:-}"
  base="${base%/}"
  ASC_KEY_ID_REF="${ASC_KEY_ID_REF:-${base:+$base/key_id}}"
  ASC_ISSUER_ID_REF="${ASC_ISSUER_ID_REF:-${base:+$base/issuer_id}}"
  ASC_KEY_REF="${ASC_KEY_REF:-${base:+$base/key}}"
  if [ -z "$ASC_KEY_ID_REF" ] || [ -z "$ASC_ISSUER_ID_REF" ] || [ -z "$ASC_KEY_REF" ]; then
    echo "packaging: set ASC_KEY_ID_REF, ASC_ISSUER_ID_REF and ASC_KEY_REF (or OP_ASC_ITEM) in packaging/.env" >&2
    return 1
  fi
}

asc_run_csec() {
  local cli="$asc_csec_app/Contents/MacOS/csec"
  if [ ! -x "$cli" ]; then
    echo "packaging: credential delivery requires an installed, running csec; no direct provider fallback is used" >&2
    return 1
  fi
  "$cli" "$@"
}

# A caller that already holds an App Store Connect key for this run names it
# here: NOTARY_KEY (a 0600 .p8 file), NOTARY_KEY_ID and NOTARY_ISSUER, for
# example from a signing wrapper that released the key after its owner approved
# the build. The key then comes from that file and csec is
# not asked, so one approval covers the build instead of a second one here.
asc_caller_key() {
  [ -n "${NOTARY_KEY:-}" ] || return 1
  if [ ! -f "$NOTARY_KEY" ] || [ ! -r "$NOTARY_KEY" ] ||
      [ -z "${NOTARY_KEY_ID:-}" ] || [ -z "${NOTARY_ISSUER:-}" ]; then
    echo "packaging: NOTARY_KEY needs a readable key file, NOTARY_KEY_ID and NOTARY_ISSUER" >&2
    return 2
  fi
}

# The first build on a Mac without csec has no broker to ask, so the key comes
# from 1Password's own CLI, which asks the user to approve in the 1Password app
# (Touch ID with its CLI integration on), straight into the same /dev/fd pipes
# csec would fill: never argv, the environment or a file of this script's.
# It applies only inside build-and-install.sh, the one install entry point, and
# only when no csec app exists at all, so a present but unhealthy csec still
# stops the build. Moving the app aside to reach this route gains nothing: the
# key is still released only by the user's own approval in 1Password.
asc_bootstrap_applies() {
  [ ! -e "$asc_csec_app" ] && [ "${CSEC_BUILD_AND_INSTALL_PIPELINE:-}" = 1 ]
}

asc_bootstrap_ready() {
  local name
  for name in ASC_KEY_ID_REF ASC_ISSUER_ID_REF ASC_KEY_REF; do
    if [[ "${!name}" != op://* ]]; then
      echo "packaging: no csec is installed, so this first build reads the App Store Connect key with 1Password's CLI; $name must be an op:// reference (or set OP_ASC_ITEM)" >&2
      return 1
    fi
  done
  if ! command -v op >/dev/null 2>&1; then
    echo "packaging: no csec is installed, so this first build needs 1Password's CLI (op) with its 1Password app integration on" >&2
    return 1
  fi
}

# A service account or Connect server would release an Admin key with no one
# approving it, so those are cleared: the release stays the user's own approval
# in the 1Password app.
asc_op_read() {
  env -u OP_SERVICE_ACCOUNT_TOKEN -u OP_CONNECT_HOST -u OP_CONNECT_TOKEN \
    op read ${OP_ACCOUNT:+--account "$OP_ACCOUNT"} --no-newline -- "$1"
}

asc_bootstrap_with_op() {
  local script="$1"
  shift
  asc_bootstrap_ready || return
  echo "packaging: no csec is installed; 1Password asks you to approve the App Store Connect key for this build" >&2
  # The three reads below start together. One read first, discarded, settles
  # 1Password's approval for this terminal so they do not each raise one.
  asc_op_read "$ASC_KEY_ID_REF" >/dev/null || return
  # The consumer gets each substitution's own /dev/fd path. Redirecting them
  # onto fixed numbers would leave bash's /dev/fd/6x copies open as well (macOS
  # bash 3.2 keeps them for the life of a function), and the consumer closes
  # only the descriptors it was named, so its children would inherit the rest.
  ASC_KEY_ID_FILE=<(asc_op_read "$ASC_KEY_ID_REF") \
    ASC_ISSUER_ID_FILE=<(asc_op_read "$ASC_ISSUER_ID_REF") \
    ASC_PRIVATE_KEY_FILE=<(asc_op_read "$ASC_KEY_REF") \
    /bin/bash "$script" --with-asc-credentials "$@"
}

asc_check_auth() {
  local caller=0
  asc_caller_key || caller=$?
  if [ "$caller" -eq 0 ]; then
    echo "notarize: the caller's App Store Connect key is ready; csec is not asked"
    return
  fi
  [ "$caller" -eq 1 ] || return 1
  asc_configure_credentials || return
  if asc_bootstrap_applies; then
    asc_bootstrap_ready || return
    echo "notarize: no csec is installed; 1Password's CLI is ready and asks for approval only for the consumer"
    return
  fi
  if ! asc_run_csec doctor --check --runtime >/dev/null; then
    echo "packaging: csec runtime is unavailable or unhealthy; run csec doctor before retrying" >&2
    return 1
  fi
  echo "notarize: csec runtime ready; credentials are requested only for the consumer"
}

asc_with_credentials() {
  local script="$1" caller=0
  shift
  asc_caller_key || caller=$?
  if [ "$caller" -eq 0 ]; then
    # The same /dev/fd contract as csec's delivery. The consumer keeps no
    # NOTARY_* name, so nothing it starts (build-pkg.sh) can find the key.
    (
      key_id="$NOTARY_KEY_ID" issuer="$NOTARY_ISSUER" key="$NOTARY_KEY"
      unset NOTARY_KEY NOTARY_KEY_ID NOTARY_ISSUER
      ASC_KEY_ID_FILE=/dev/fd/7 ASC_ISSUER_ID_FILE=/dev/fd/8 ASC_PRIVATE_KEY_FILE=/dev/fd/9 \
        /bin/bash "$script" --with-asc-credentials "$@" \
        7<<<"$key_id" 8<<<"$issuer" 9<"$key"
    )
    return
  fi
  [ "$caller" -eq 1 ] || return 1
  asc_configure_credentials || return
  if asc_bootstrap_applies; then
    asc_bootstrap_with_op "$script" "$@"
    return
  fi
  # Only /dev/fd paths enter the child's environment. csec requests all three
  # references together under its existing delivery policy; it does not expand
  # a grant or resolve a value before consent.
  asc_run_csec exec-fd --reason "Convenient Security signing credentials" \
    --fd "ASC_KEY_ID_FILE=$ASC_KEY_ID_REF" \
    --fd "ASC_ISSUER_ID_FILE=$ASC_ISSUER_ID_REF" \
    --fd "ASC_PRIVATE_KEY_FILE=$ASC_KEY_REF" \
    -- /bin/bash "$script" --with-asc-credentials "$@"
}

asc_require_credential_files() {
  local path
  for path in "${ASC_KEY_ID_FILE:-}" "${ASC_ISSUER_ID_FILE:-}" "${ASC_PRIVATE_KEY_FILE:-}"; do
    if ! [[ "$path" =~ ^/dev/fd/[0-9]+$ ]] || [ ! -r "$path" ]; then
      echo "packaging: inherited credential descriptors are unavailable" >&2
      return 1
    fi
  done
}
