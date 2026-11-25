#!/usr/bin/env bash
set -euo pipefail

# On-device check of the sudo review's typing guard on the production code path.
# Builds the sampler, then spawns the debug helper's fixed-fixture mode
# (synthetic frame on a pipe, sharing PAM's review body) and prints its
# activation policy, active state, and on-screen window count as they change.
# The window appears for about two seconds and Touch ID is armed for that long;
# nothing is approved. Expected shape: the process stays `prohibited` and
# inactive while it looks the terminal tab up, its window appears while it is
# still inactive, and `active=true` follows about half a second later, or once
# the keyboard counter reads 1.5 s if a key went down just before (the guard
# waits for the keyboard to be quiet; don't type while it runs).
#
# Usage: packaging/bin/sample-sudo-review-activation.sh [seconds]
#   Requires packaging/bin/build-sudo-review.sh to have run. The live fixed
#   fixture entry is available only in the debug helper, never the installed one.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
build_directory="$repo_root/packaging/build/sudo-review"
wire_probe="$build_directory/csec-sudo-review-wire-probe"
sampler_source="$repo_root/packaging/sudo/sample-review-activation.swift"
sampler="$build_directory/sample-review-activation"
seconds="${1:-2.5}"

[[ -x "$wire_probe" ]] || {
  echo "missing $wire_probe; run packaging/bin/build-sudo-review.sh first" >&2
  exit 1
}

swift build --package-path "$repo_root/agent" --product csec-sudo-review
debug_directory="$(swift build --package-path "$repo_root/agent" --show-bin-path)"
helper="$debug_directory/csec-sudo-review"

if [[ ! -x "$sampler" || "$sampler_source" -nt "$sampler" ]]; then
  swiftc -O "$sampler_source" -o "$sampler"
fi

"$wire_probe" sudo /usr/bin/true --api-key synthetic-short-value safe |
  "$sampler" "$helper" "$seconds"
