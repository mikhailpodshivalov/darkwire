#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${DARKWIRE_INSTALL_DIR:-$HOME/.local/bin}"

if command -v darkwire >/dev/null 2>&1; then
  CLIENT_BIN="$(command -v darkwire)"
elif [[ -x "$INSTALL_DIR/darkwire" ]]; then
  CLIENT_BIN="$INSTALL_DIR/darkwire"
else
  echo "error: darkwire client not found. Run ./scripts/install.sh first." >&2
  exit 1
fi

DEFAULT_RELAY="${DARKWIRE_RELAY_WS:-wss://srv1418428.hstgr.cloud/ws}"
HAS_RELAY_FLAG=false

for arg in "$@"; do
  if [[ "$arg" == "--relay" ]]; then
    HAS_RELAY_FLAG=true
    break
  fi
done

if $HAS_RELAY_FLAG; then
  exec "$CLIENT_BIN" "$@"
fi

exec "$CLIENT_BIN" --relay "$DEFAULT_RELAY" "$@"
