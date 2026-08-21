#!/usr/bin/env bash
# shellcheck disable=SC2016 # Contract assertions intentionally match literal workflow expressions.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
workflow="$root/.github/workflows/release.yml"
cross_config="$root/.github/cross-shared-cache.toml"

grep -Fq 'CROSS_CONFIG: .github/cross-shared-cache.toml' "$workflow"
grep -Fq 'test "$RUSTC_WRAPPER" = /usr/local/bin/shared-ci-sccache' "$workflow"
grep -Fq 'case "$SCCACHE_DIR" in */organizations/beeos-ai/rust-sccache)' "$workflow"
grep -Fq 'sccache --show-stats' "$workflow"
grep -Fq 'passthrough = ["RUSTC_WRAPPER", "SCCACHE_DIR", "SCCACHE_CACHE_SIZE"]' "$cross_config"
grep -Fq '"SCCACHE_BINARY=/usr/local/bin/sccache"' "$cross_config"
grep -Fq '"SCCACHE_WRAPPER=/usr/local/bin/shared-ci-sccache"' "$cross_config"
grep -Fq '"SCCACHE_DIR"' "$cross_config"

# Quality stays on shared-ci. Tag `cross` builds run on GitHub-hosted
# ubuntu because the OCI slot cannot docker-pull musl cross-rs layers.
# macOS/Windows stay hosted.
test "$(grep -Fc 'runs-on: [self-hosted, linux, x64, oci, shared-ci, shared-ci-heavy]' "$workflow")" = 2
grep -Fq 'SCCACHE_DIR: /var/lib/shared-ci/organizations/beeos-ai/rust-sccache' "$workflow"
grep -Fq 'runs-on: ubuntu-24.04' "$workflow"
grep -Fq 'needs: [linux-dist, macos, windows]' "$workflow"
grep -Fq 'cross build --target "$target" --profile dist --locked' "$workflow"
if grep -Fq 'if (( ${#pids[@]} == 2 ))' "$workflow"; then
  echo "parallel cross is forbidden: it hung 0.1.38 with Compile requests=0" >&2
  exit 1
fi
grep -Fq 'runs-on: macos-14' "$workflow"
grep -Fq 'runs-on: windows-2022' "$workflow"
