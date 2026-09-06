#!/usr/bin/env bash
set -euo pipefail

iterations="${ITERATIONS:-1}"
delay_seconds="${DELAY_SECONDS:-5}"
full="${FULL:-0}"
no_clippy="${NO_CLIPPY:-0}"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

phase6_filters=(
  "hardening_tests"
  "storage::tests::outbox"
  "storage::tests::sync"
  "storage::tests::own_device"
  "storage::tests::device_revocation"
  "storage::tests::duplicate"
  "crdt::tests"
  "discovery_tests"
)

run_cmd() {
  echo
  printf '>>>'
  printf ' %q' "$@"
  echo
  "$@"
}

count=0
while [[ "$iterations" == "0" || "$count" -lt "$iterations" ]]; do
  count=$((count + 1))
  echo
  echo "=== Phase 6 validation pass $count ==="
  date -u +"Started: %Y-%m-%dT%H:%M:%SZ"

  run_cmd cargo fmt --check

  for filter in "${phase6_filters[@]}"; do
    run_cmd cargo test "$filter"
  done

  if [[ "$full" == "1" ]]; then
    run_cmd cargo test
  fi

  run_cmd cargo run -- phase6-lan-smoke

  if [[ "$no_clippy" != "1" ]]; then
    run_cmd cargo clippy --all-targets --all-features -- -D warnings
  fi

  date -u +"Finished: %Y-%m-%dT%H:%M:%SZ"

  if [[ "$iterations" == "0" || "$count" -lt "$iterations" ]]; then
    sleep "$delay_seconds"
  fi
done
