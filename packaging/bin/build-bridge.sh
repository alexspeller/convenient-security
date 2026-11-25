#!/usr/bin/env bash
set -euo pipefail

# Build csec-op-bridge: the process that holds one authorized 1Password SDK
# client per account.
#
# It must be built with CGO for the target architecture. The SDK reaches the
# desktop app through 1Password's own dylib, which ships arm64-only, and a
# Rosetta Go toolchain would produce a binary that cannot load it.
#
# Usage: packaging/bin/build-bridge.sh <output-path> [<notices-dir>]
#
# With <notices-dir>, it also collects the licence and NOTICE files of Go and
# of every module linked into the binary, for the app bundle to ship.

out="${1:?usage: build-bridge.sh <output-path> [<notices-dir>]}"
notices="${2:-}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # packaging/
root="$(cd "$here/.." && pwd)"                            # repo root

go_bin="$(command -v go || true)"
for candidate in "$HOME"/.local/share/mise/installs/go/*/bin/go; do
  [ -x "$candidate" ] || continue
  go_bin="$candidate"
done
: "${go_bin:?no Go toolchain found; install one with: mise install go@1.24}"

arch="$(uname -m)"
case "$arch" in
  arm64) goarch=arm64 ;;
  x86_64) goarch=amd64 ;;
  *) echo "unsupported architecture: $arch" >&2; exit 2 ;;
esac

toolchain_arch="$("$go_bin" env GOHOSTARCH)"
if [ "$toolchain_arch" != "$goarch" ]; then
  echo "error: Go toolchain is $toolchain_arch but this Mac is $goarch." >&2
  echo "       CGO cannot cross-compile the 1Password integration here." >&2
  echo "       Install a native toolchain: mise install go@1.24" >&2
  exit 2
fi

echo "--- building csec-op-bridge ($goarch) ---"
CGO_ENABLED=1 GOARCH="$goarch" "$go_bin" build \
  -C "$root/bridge" \
  -trimpath \
  -o "$out" \
  .

[ -n "$notices" ] || exit 0
echo "--- collecting csec-op-bridge licence notices ---"
rm -rf "$notices"
mkdir -p "$notices/go"
cp "$("$go_bin" env GOROOT)/LICENSE" "$notices/go/LICENSE"
# The binary's own build info names exactly the modules linked into it, so a
# dependency that stops being linked stops being listed.
"$go_bin" version -m "$out" | awk '$1 == "dep" { print $2 }' | while read -r module; do
  dir="$("$go_bin" list -C "$root/bridge" -m -f '{{.Dir}}' "$module")"
  dest="$notices/$module"
  mkdir -p "$dest"
  found=0
  for file in "$dir"/LICENSE* "$dir"/LICENCE* "$dir"/COPYING* "$dir"/NOTICE*; do
    [ -f "$file" ] || continue
    cp "$file" "$dest/"
    found=1
  done
  if [ "$found" -eq 0 ]; then
    echo "error: $module has no licence file in $dir" >&2
    exit 1
  fi
done
