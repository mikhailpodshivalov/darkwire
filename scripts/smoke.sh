#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[smoke] cargo check --workspace"
cargo check --workspace

echo "[smoke] cargo test --workspace"
cargo test --workspace

echo "[smoke] relay integration: chat/disconnect"
cargo test -p darkwire-relay integration_two_clients_can_chat_and_disconnect_ends_session -- --nocapture

echo "[smoke] relay integration: invite.use backoff"
cargo test -p darkwire-relay integration_invite_use_backoff_emits_rate_limited_after_failed_attempts -- --nocapture

echo "[smoke] OK"
