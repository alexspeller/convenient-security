#!/usr/bin/env bash
set -euo pipefail

# Build and verify the contextual sudo PAM module. This script does
# not install the module or alter /etc/pam.d/sudo_local.

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_file="$here/sudo/pam_csec_sudo.c"
heuristics_source="$here/../agent/Sources/CSECSecretHeuristics/CSECSecretHeuristics.c"
heuristics_include="$here/../agent/Sources/CSECSecretHeuristics/include"
output_dir="$here/build/sudo-pam"
module="$output_dir/pam_csec_sudo.so"
preview="$output_dir/pam-csec-sudo-prompt-preview"
redactor_probe="$output_dir/pam-csec-sudo-redactor-probe"
sdk="$(xcrun --sdk macosx --show-sdk-path)"
module_arm64="$output_dir/pam_csec_sudo.arm64.so"
module_arm64e="$output_dir/pam_csec_sudo.arm64e.so"
module_x86_64="$output_dir/pam_csec_sudo.x86_64.so"

mkdir -p "$output_dir"
rm -f \
  "$module" \
  "$module_arm64" \
  "$module_arm64e" \
  "$module_x86_64" \
  "$preview" \
  "$redactor_probe"

common_flags=(
  -isysroot "$sdk"
  -mmacosx-version-min=12.0
  -Os
  -Wall
  -Wextra
  -Werror
  -fstack-protector-strong
  -I "$heuristics_include"
)

build_module_arch() {
  local architecture="$1"
  local output="$2"
  xcrun clang "${common_flags[@]}" \
    -arch "$architecture" \
    -dynamiclib \
    -Wl,-install_name,/usr/local/lib/pam/pam_csec_sudo.so \
    "$source_file" \
    "$heuristics_source" \
    -framework CoreFoundation \
    -framework Security \
    -lpam \
    -o "$output"
}

build_module_arch arm64 "$module_arm64"
build_module_arch arm64e "$module_arm64e"
build_module_arch x86_64 "$module_x86_64"
lipo -create \
  "$module_arm64" \
  "$module_arm64e" \
  "$module_x86_64" \
  -output "$module"

xcrun clang "${common_flags[@]}" \
  -DCSEC_PAM_PROMPT_PREVIEW=1 \
  "$source_file" \
  "$heuristics_source" \
  -framework CoreFoundation \
  -framework Security \
  -lpam \
  -o "$preview"

xcrun clang "${common_flags[@]}" \
  -DCSEC_PAM_REDACTOR_PROBE=1 \
  "$source_file" \
  "$heuristics_source" \
  -framework CoreFoundation \
  -framework Security \
  -lpam \
  -o "$redactor_probe"

codesign --force --sign - "$module"

context_suffix=$'\nworking directory: /Users/example/project\nterminal: /dev/ttys001\narguments were filtered by the active csec secret catalog'

check_preview() {
  local description="$1"
  local expected="$2"
  shift 2
  local actual
  actual="$("$preview" "$@")"
  if [[ "$actual" != "$expected" ]]; then
    echo "$description preview mismatch" >&2
    echo "expected: $expected" >&2
    echo "actual:   $actual" >&2
    exit 1
  fi
}

check_preview \
  "complete argv" \
  $'approve this sudo invocation:\n  sudo /usr/bin/id -un'"$context_suffix" \
  sudo /usr/bin/id -un

check_preview \
  "sudo options" \
  $'approve this sudo invocation:\n  sudo -u root -- /usr/bin/id -un'"$context_suffix" \
  sudo -u root -- /usr/bin/id -un

check_preview \
  "safe environment assignment" \
  $'approve this sudo invocation:\n  sudo CSEC_SYNTHETIC_MODE=test /usr/bin/env'"$context_suffix" \
  sudo CSEC_SYNTHETIC_MODE=test /usr/bin/env

check_preview \
  "passwordless URL" \
  $'approve this sudo invocation:\n  sudo /usr/bin/tool http://192.0.2.140:8123'"$context_suffix" \
  sudo /usr/bin/tool http://192.0.2.140:8123

check_preview \
  "password-bearing URL" \
  $'approve this sudo invocation:\n  sudo /usr/bin/tool "[csec:secret-like]"'"$context_suffix" \
  sudo /usr/bin/tool http://synthetic-user:synthetic-password@example.test

check_preview \
  "secret-named environment assignment" \
  $'approve this sudo invocation:\n  sudo "DATABASE_URL=[csec:secret-like]" /usr/bin/env'"$context_suffix" \
  sudo DATABASE_URL=synthetic-short /usr/bin/env

check_preview \
  "secret-named option value" \
  $'approve this sudo invocation:\n  sudo /usr/bin/tool --api-key "[csec:secret-like]" safe'"$context_suffix" \
  sudo /usr/bin/tool --api-key synthetic-short-value safe

check_preview \
  "known secret prefix" \
  $'approve this sudo invocation:\n  sudo /usr/bin/tool "[csec:secret-like]"'"$context_suffix" \
  sudo /usr/bin/tool github_pat_SYNTHETIC_0123456789abcdef

check_preview \
  "active-catalog label" \
  $'approve this sudo invocation:\n  sudo /usr/bin/tool "--token=[csec:secret-1]"'"$context_suffix" \
  sudo /usr/bin/tool '--token=[csec:secret-1]'

check_preview \
  "control-character escaping" \
  $'approve this sudo invocation:\n  sudo /usr/bin/tool "line\\x0Abreak"'"$context_suffix" \
  sudo /usr/bin/tool $'line\nbreak'

check_preview \
  "redactor unavailable" \
  'authorize a submitted sudo request from [/Users/example/project] on [/dev/ttys001]; arguments are withheld because the authenticated csec redactor is unavailable or the invocation exceeds safe review bounds' \
  sudo --redactor-unavailable-preview

echo "built: $module"
echo "preview checks: pass"
