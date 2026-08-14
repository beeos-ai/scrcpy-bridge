#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:?usage: verify-release-assets.sh <asset-directory>}"
targets=(
  x86_64-unknown-linux-gnu
  aarch64-unknown-linux-gnu
  x86_64-unknown-linux-musl
  aarch64-unknown-linux-musl
  x86_64-apple-darwin
  aarch64-apple-darwin
  x86_64-pc-windows-msvc
)

for target in "${targets[@]}"; do
  suffix=tar.gz
  [[ "$target" != *windows* ]] || suffix=zip
  archive="$ROOT/scrcpy-bridge-${target}.${suffix}"
  test -s "$archive"
  test -s "${archive}.sha256"
  (cd "$ROOT" && sha256sum -c "$(basename "${archive}.sha256")")
done

test "$(find "$ROOT" -maxdepth 1 -type f \( -name '*.tar.gz' -o -name '*.zip' \) | wc -l | tr -d ' ')" = 7
