#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:?usage: package-target.sh <target-triple>}"
BIN="scrcpy-bridge"
[[ "$TARGET" != *windows* ]] || BIN="scrcpy-bridge.exe"
SOURCE="${CARGO_TARGET_DIR:-target}/${TARGET}/dist/${BIN}"
STAGE="scrcpy-bridge-${TARGET}"
test -f "$SOURCE"
rm -rf "$STAGE"
mkdir -p "$STAGE"
install -m 0755 "$SOURCE" "$STAGE/$BIN"
cp README.md "$STAGE/"

if [[ "$TARGET" == *windows* ]]; then
  7z a -bd "${STAGE}.zip" "$STAGE" >/dev/null
  archive="${STAGE}.zip"
else
  tar -czf "${STAGE}.tar.gz" "$STAGE"
  archive="${STAGE}.tar.gz"
fi

if command -v sha256sum >/dev/null; then
  sha256sum "$archive" > "${archive}.sha256"
else
  shasum -a 256 "$archive" > "${archive}.sha256"
fi
printf '%s\n' "$archive"
