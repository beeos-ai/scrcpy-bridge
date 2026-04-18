#!/usr/bin/env bash
#
# fetch-scrcpy-server.sh — download + sha256-verify the scrcpy-server JAR
# that `build.rs` embeds via `include_bytes!`.
#
# Primary use case: local dev on an air-gapped / offline-ish machine where
# `cargo build` cannot reach github.com, or CI jobs that want to cache the
# jar across runs. On a plain workstation `cargo build --release` does this
# same dance inline — you only need this script if you want the jar
# materialised before invoking cargo.
#
# Version + checksum MUST stay in lock-step with `build.rs`
# (`SCRCPY_VERSION` / `SHA256`). When bumping, update BOTH files in the
# same commit and rerun `shasum -a 256 scrcpy-server-vX.Y`.

set -euo pipefail

# ── Pinned, MUST match build.rs ──────────────────────────────────────────
SCRCPY_VERSION="3.1"
SCRCPY_SHA256="958f0944a62f23b1f33a16e9eb14844c1a04b882ca175a738c16d23cb22b86c0"
MIN_JAR_SIZE=50000

# ── Paths ────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR_DEFAULT="$CRATE_DIR/assets"
OUT_DIR="${OUT_DIR:-$OUT_DIR_DEFAULT}"
OUT_FILE="$OUT_DIR/scrcpy-server.jar"

URL="https://github.com/Genymobile/scrcpy/releases/download/v${SCRCPY_VERSION}/scrcpy-server-v${SCRCPY_VERSION}"
MIRROR="${SCRCPY_MIRROR_URL:-}"

# ── Helpers ──────────────────────────────────────────────────────────────
log() { printf '[fetch-scrcpy-server] %s\n' "$*" >&2; }

compute_sha256() {
    local file="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$file" | awk '{print $1}'
    else
        log "ERROR: neither sha256sum nor shasum available"
        exit 1
    fi
}

file_matches() {
    [[ -f "$OUT_FILE" ]] || return 1
    local size
    size=$(wc -c < "$OUT_FILE" | tr -d ' ')
    [[ "$size" -ge "$MIN_JAR_SIZE" ]] || return 1
    local actual
    actual=$(compute_sha256 "$OUT_FILE")
    [[ "$actual" == "$SCRCPY_SHA256" ]]
}

download() {
    local url="$1"
    log "downloading $url"
    if command -v curl >/dev/null 2>&1; then
        curl -fSL --retry 3 --retry-delay 2 -o "$OUT_FILE.tmp" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$OUT_FILE.tmp" "$url"
    else
        log "ERROR: neither curl nor wget available"
        return 1
    fi
    mv "$OUT_FILE.tmp" "$OUT_FILE"
}

# ── Main ─────────────────────────────────────────────────────────────────
mkdir -p "$OUT_DIR"

if file_matches; then
    log "already present and sha256 OK: $OUT_FILE"
    exit 0
fi

[[ -f "$OUT_FILE" ]] && {
    log "existing jar failed sha256 / size check — re-downloading"
    rm -f "$OUT_FILE"
}

if [[ -n "$MIRROR" ]]; then
    download "${MIRROR%/}/scrcpy-server-v${SCRCPY_VERSION}" || true
fi

if ! file_matches; then
    download "$URL"
fi

actual=$(compute_sha256 "$OUT_FILE")
size=$(wc -c < "$OUT_FILE" | tr -d ' ')

if [[ "$size" -lt "$MIN_JAR_SIZE" ]]; then
    log "ERROR: downloaded file size $size < MIN_JAR_SIZE $MIN_JAR_SIZE"
    log "       this usually means GitHub returned an HTML error page"
    rm -f "$OUT_FILE"
    exit 1
fi

if [[ "$actual" != "$SCRCPY_SHA256" ]]; then
    log "ERROR: sha256 mismatch"
    log "  expected $SCRCPY_SHA256"
    log "  actual   $actual"
    log ""
    log "  This either means:"
    log "    (a) the upstream release was re-uploaded → verify with Genymobile"
    log "        and update SCRCPY_SHA256 in BOTH build.rs and this script, or"
    log "    (b) a MITM/proxy is injecting a different JAR."
    rm -f "$OUT_FILE"
    exit 1
fi

log "OK: $OUT_FILE (v$SCRCPY_VERSION, sha256 verified)"
log ""
log "Build tip: set SCRCPY_SKIP_DOWNLOAD=1 on cargo to reuse the cached jar:"
log "  SCRCPY_SKIP_DOWNLOAD=1 cargo build --release"
