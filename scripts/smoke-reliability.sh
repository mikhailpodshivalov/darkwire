#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

tests=(
  "e2e::tests::late_message_from_gap_is_accepted_once"
  "e2e::tests::bulk_out_of_order_delivery_is_reassembled_without_loss"
  "e2e::tests::out_of_order_beyond_forward_gap_does_not_advance_recv_counter"
  "runtime::recovery::tests::recovery_request_is_limited_to_one_attempt_per_session"
  "runtime::recovery::tests::recovery_request_is_allowed_for_new_session_after_prior_attempt"
)

echo "[reliability] running targeted client reliability regressions"
for test_name in "${tests[@]}"; do
  echo "[reliability] cargo test -p darkwire-client ${test_name}"
  cargo test -p darkwire-client "${test_name}" -- --nocapture
done

echo "[reliability] OK"
