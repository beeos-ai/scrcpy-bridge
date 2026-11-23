#!/usr/bin/env bash
# shellcheck disable=SC2016 # Contract assertions intentionally match literal workflow expressions.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
workflow="$root/.github/workflows/release.yml"

# A public repository: every job runs on GitHub-hosted runners, none on self-hosted ones.
if grep -rFq 'self-hosted' "$root/.github/workflows"; then
  echo "self-hosted runners are not allowed in this public repository" >&2
  exit 1
fi

# PRs and tags run Linux quality on GitHub-hosted Ubuntu.
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
for hosted_job in linux linux-dist staging production; do
  grep -Fxq '    runs-on: ubuntu-24.04' <<< "$(job_definition "$hosted_job")"
done
grep -Fq 'needs: [linux-dist, macos, windows]' "$workflow"
grep -Fq 'cross build --target "$target" --profile dist --locked' "$workflow"
if grep -Fq 'if (( ${#pids[@]} == 2 ))' "$workflow"; then
  echo "parallel cross is forbidden: it hung 0.1.38 with Compile requests=0" >&2
  exit 1
fi
grep -Fq 'runs-on: macos-14' "$workflow"
grep -Fq 'runs-on: windows-2022' "$workflow"
