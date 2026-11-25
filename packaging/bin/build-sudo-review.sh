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
rm -f "$helper" "$wire_probe" "$output_directory"/preview*.png

swift build \
  --package-path "$agent_directory" \
  -c release \
  --jobs 2 \
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
# csecd mirrors a sudo review to the paired phone only for a peer whose live
# code identity is this helper as the product team signed it
# (ProductCodeRole.sudoReviewHelper): the identifier, the team, hardened
# runtime and the Developer ID requirement below, as for csec and csecd.
# build-and-install.sh exports SIGN_IDENTITY, so an installed helper is always
# Developer ID signed. A standalone build without it (bin/ci) is ad-hoc signed:
# the PAM module still runs it, but csecd never answers it, so its review stays
# on the Mac.
# shellcheck source=../lib/identity.sh
. "$repo_root/packaging/lib/identity.sh"
csec_identity_load "$repo_root/identity.xcconfig"
team_identifier="$csec_team_id" # ProductCodeIdentity.teamIdentifier
helper_identifier="$csec_identifier.sudo-review"
if [[ -n "${SIGN_IDENTITY:-}" ]]; then
  signing=(--timestamp --sign "$SIGN_IDENTITY")
elif [[ "${CSEC_BUILD_AND_INSTALL_PIPELINE:-}" == 1 ]]; then
  echo "SIGN_IDENTITY is required to build the sudo review helper for installation" >&2
  exit 1
else
  signing=(--timestamp=none --sign -)
fi
codesign --force \
  --identifier "$helper_identifier" \
  --options runtime \
  "${signing[@]}" \
  "$helper"
codesign --verify --strict "$helper"
if [[ -n "${SIGN_IDENTITY:-}" ]]; then
  codesign --verify --strict \
    --test-requirement="=anchor apple generic and certificate leaf[subject.OU] = \"$team_identifier\" and identifier \"$helper_identifier\"" \
    "$helper" || {
    echo "helper does not satisfy the code requirement csecd checks before it answers it" >&2
    exit 1
  }
fi
codesign -dvv "$helper" 2>&1 | /usr/bin/grep 'flags=.*runtime' >/dev/null || {
  echo "helper is missing the hardened-runtime signature flag" >&2
  exit 1
}
codesign -dvv "$helper" 2>&1 |
  /usr/bin/grep -Fx "Identifier=$helper_identifier" \
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
  "-DCSEC_IDENTIFIER=\"$csec_identifier\"" \
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

# csecd matches a Claude Code sudo against the text auto mode approved by
# decoding this rendering, so the C rendering and the Swift decoder must agree
# byte for byte, quoting, escapes and non-ASCII included.
round_trip=(-u root fs_usage 'a b' 'x"y' '$HOME' '`id`' 'back\slash' $'\ttab' '' 'café' "launchctl print 'system/x'" -E)
"$wire_probe" sudo "${round_trip[@]}" |
  "$helper" --display-round-trip "${round_trip[@]}"

# Exercise the shipping entry point with a real same-user parent. It must
# reject even while stdin is held open, before reading a frame or showing UI.
# Live synthetic panel/phone modes belong only to debug builds.
python3 - "$helper" "$wire_probe" <<'PY_PARENT_TRUST'
import os
import subprocess
import sys

helper, wire_probe = sys.argv[1:]
if os.geteuid() == 0:
    raise SystemExit("sudo review checks must run as the login user")
child = subprocess.Popen([helper], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
try:
    status = child.wait(timeout=5)
    diagnostic = child.stderr.read()
    assert status == 69 and b"event=rejected reason=untrusted-parent status=69" in diagnostic, \
        "shipping helper did not reject its unprivileged parent before reading stdin"
finally:
    if child.poll() is None:
        child.kill()
        child.wait()
    child.stdin.close()
    child.stdout.close()
    child.stderr.close()

frame = subprocess.check_output([wire_probe, "sudo", "/usr/bin/true", "--api-key", "synthetic-short-value", "safe"])
result = subprocess.run([helper], input=frame, capture_output=True, timeout=5)
assert result.returncode == 69 and b"event=rejected reason=untrusted-parent status=69" in result.stderr, \
    "shipping helper accepted a valid forged frame"
for mode in ["--grace-probe", "--typing-probe", "--focus-probe", "--unlock-probe", "--deadline-probe",
             "--no-touch-id-probe", "--phone-probe", "--synthetic-review-probe"]:
    result = subprocess.run([helper, mode], input=frame, capture_output=True, timeout=8)
    assert result.returncode == 64 and b"event=rejected reason=unexpected-arguments status=64" in result.stderr, \
        f"shipping helper exposes a live synthetic review mode: {mode}"
print("sudo review root-parent and release-mode checks: pass")
PY_PARENT_TRUST

if "$helper" --not-a-supported-mode >/dev/null 2>&1; then
  echo "helper accepted an unsupported mode" >&2
  exit 1
fi
if /usr/bin/printf 'malformed' |
    "$helper" >/dev/null 2>&1; then
  echo "helper accepted a malformed review frame" >&2
  exit 1
fi

# The helper must also build the real panel: a layout assertion or a nil unwrap
# in window construction would otherwise ship unnoticed. --preview renders a
# synthetic review offscreen without ordering the window in or starting Touch
# ID, so it is safe unattended. Every fixture renders, since long-argv and
# multi-line build the command card's scroller and wrapping that basic does not.
for fixture in basic long-argv multi-line; do
  preview_png="$output_directory/preview-$fixture.png"
  "$helper" --preview "$fixture" "$preview_png" dark
  [[ -s "$preview_png" ]] || {
    echo "helper did not render the $fixture review panel preview" >&2
    exit 1
  }
done
if "$helper" --preview "$output_directory/preview-basic.png" dark >/dev/null 2>&1; then
  echo "helper took an output path as a preview fixture name" >&2
  exit 1
fi

echo "built: $helper"
echo "architectures: $(lipo -archs "$helper")"
echo "sudo review checks: pass"
