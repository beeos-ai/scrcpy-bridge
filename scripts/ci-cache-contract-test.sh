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

# Linux stays on shared-ci with two-way bounded target builds; macOS and
# Windows retain their platform-native hosted runners.
test "$(grep -Fc 'runs-on: [self-hosted, linux, x64, oci, shared-ci, shared-ci-heavy]' "$workflow")" = 2
grep -Fq 'if (( ${#pids[@]} == 2 ))' "$workflow"
grep -Fq 'runs-on: macos-14' "$workflow"
grep -Fq 'runs-on: windows-2022' "$workflow"
