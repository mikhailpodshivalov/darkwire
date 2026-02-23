#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${DARKWIRE_INSTALL_DIR:-$HOME/.local/bin}"

if command -v darkwire-relay >/dev/null 2>&1; then
  RELAY_BIN="$(command -v darkwire-relay)"
elif [[ -x "$INSTALL_DIR/darkwire-relay" ]]; then
  RELAY_BIN="$INSTALL_DIR/darkwire-relay"
else
  echo "error: darkwire-relay not found. Run ./scripts/install.sh first." >&2
  exit 1
fi

LISTEN_ADDR="${DARKWIRE_RELAY_ADDR:-127.0.0.1:7000}"
HAS_LISTEN_FLAG=false

for arg in "$@"; do
  if [[ "$arg" == "--listen" ]]; then
    HAS_LISTEN_FLAG=true
    break
  fi
done

if $HAS_LISTEN_FLAG; then
  exec "$RELAY_BIN" "$@"
fi

exec "$RELAY_BIN" --listen "$LISTEN_ADDR" "$@"
