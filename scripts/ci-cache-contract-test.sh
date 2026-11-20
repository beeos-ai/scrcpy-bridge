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

# PRs run Linux quality on GitHub-hosted Ubuntu. Release quality and staging
# use shared-ci, with tag cross builds on hosted Ubuntu for musl image access.
job_definition() {
  awk -v job="$1" '$0 == "  " job ":" { in_job = 1; next }
    in_job && /^  [^ ]/ { exit }
    in_job { print }' "$workflow"
}

pr_quality="$(job_definition linux-pr)"
grep -Fxq "    if: github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name == github.repository" <<< "$pr_quality"
grep -Fxq '    runs-on: ubuntu-24.04' <<< "$pr_quality"
grep -Fxq '          toolchain: ${{ env.RUST_RELEASE_TOOLCHAIN }}' <<< "$pr_quality"
grep -Fxq '          scripts/ci-cache-contract-test.sh' <<< "$pr_quality"
grep -Fxq '          cargo clippy --all-targets --locked' <<< "$pr_quality"
grep -Fxq '          cargo test --locked' <<< "$pr_quality"
for release_job in linux linux-dist macos windows staging; do
  grep -Fxq "    if: github.event_name == 'push'" <<< "$(job_definition "$release_job")"
done
production="$(job_definition production)"
grep -Fxq '    needs: staging' <<< "$production"
test "$(grep -c '^    if:' <<< "$production" || true)" = 0
for shared_job in linux staging; do
  grep -Fxq '    runs-on: [self-hosted, linux, x64, oci, shared-ci, shared-ci-heavy]' <<< "$(job_definition "$shared_job")"
done
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
