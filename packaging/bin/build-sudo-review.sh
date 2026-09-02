#!/usr/bin/env bash
set -euo pipefail

# Build and verify the contextual sudo review helper. This script does
# not install the helper or alter PAM configuration.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
agent_directory="$repo_root/agent"
source_file="$repo_root/packaging/sudo/pam_csec_sudo.c"
heuristics_source="$repo_root/agent/Sources/CSECSecretHeuristics/CSECSecretHeuristics.c"
heuristics_include="$repo_root/agent/Sources/CSECSecretHeuristics/include"
output_directory="$repo_root/packaging/build/sudo-review"
helper="$output_directory/csec-sudo-review"
wire_probe="$output_directory/csec-sudo-review-wire-probe"
sdk="$(xcrun --sdk macosx --show-sdk-path)"

mkdir -p "$output_directory"
rm -f "$helper" "$wire_probe"

swift build \
  --package-path "$agent_directory" \
  -c release \
  --product csec-sudo-review
swift_binary_directory="$(
  swift build --package-path "$agent_directory" -c release --show-bin-path
)"
source_helper="$swift_binary_directory/csec-sudo-review"
[[ -f "$source_helper" && -x "$source_helper" ]] || {
  echo "linked sudo review helper was not found" >&2
  exit 1
}

/usr/bin/install -m 0755 "$source_helper" "$helper"
codesign --force \
  --identifier com.alexspeller.convenient-security.sudo-review \
  --options runtime \
  --timestamp=none \
  --sign - \
  "$helper"
codesign --verify --strict "$helper"
codesign -dvv "$helper" 2>&1 | /usr/bin/grep 'flags=.*runtime' >/dev/null || {
  echo "helper is missing the hardened-runtime signature flag" >&2
  exit 1
}
codesign -dvv "$helper" 2>&1 |
  /usr/bin/grep '^Identifier=com.alexspeller.convenient-security.sudo-review$' \
    >/dev/null || {
  echo "helper is missing the expected signing identifier" >&2
  exit 1
}
"$helper" --self-test

xcrun clang \
  -isysroot "$sdk" \
  -mmacosx-version-min=12.0 \
  -Os \
  -Wall \
  -Wextra \
  -Werror \
  -Wno-unused-function \
  -fstack-protector-strong \
  -I "$heuristics_include" \
  -DCSEC_PAM_PROMPT_PREVIEW=1 \
  -DCSEC_PAM_REVIEW_FRAME_PROBE=1 \
  "$source_file" \
  "$heuristics_source" \
  -framework Security \
  -lpam \
  -o "$wire_probe"

"$wire_probe" \
  sudo /usr/bin/true --api-key synthetic-short-value safe |
  "$helper" --validate-synthetic-frame

if "$helper" --not-a-supported-mode >/dev/null 2>&1; then
  echo "helper accepted an unsupported mode" >&2
  exit 1
fi
if /usr/bin/printf 'malformed' |
    "$helper" >/dev/null 2>&1; then
  echo "helper accepted a malformed review frame" >&2
  exit 1
fi

echo "built: $helper"
echo "architectures: $(lipo -archs "$helper")"
echo "sudo review checks: pass"
