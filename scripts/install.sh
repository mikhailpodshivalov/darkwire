#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_DIR="${DARKWIRE_INSTALL_DIR:-$HOME/.local/bin}"
INSTALL_CLIENT=true
INSTALL_RELAY=true
SKIP_BUILD=false

usage() {
  cat <<'EOF'
Usage: ./scripts/install.sh [options]

Build and install darkwire binaries into ~/.local/bin by default.

Options:
  --client-only         Install only darkwire client binary.
  --relay-only          Install only darkwire-relay binary.
  --install-dir <dir>   Custom destination directory.
  --skip-build          Skip cargo build step (use existing target/release binaries).
  -h, --help            Show this help.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --client-only)
      INSTALL_CLIENT=true
      INSTALL_RELAY=false
      shift
      ;;
    --relay-only)
      INSTALL_CLIENT=false
      INSTALL_RELAY=true
      shift
      ;;
    --install-dir)
      if [[ $# -lt 2 ]]; then
        echo "error: --install-dir requires a value" >&2
        exit 1
      fi
      INSTALL_DIR="$2"
      shift 2
      ;;
    --skip-build)
      SKIP_BUILD=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if ! $INSTALL_CLIENT && ! $INSTALL_RELAY; then
  echo "error: nothing selected for installation" >&2
  exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "error: cargo is required. Install Rust first: https://rustup.rs/" >&2
  exit 1
fi

cd "$ROOT_DIR"

if ! $SKIP_BUILD; then
  if $INSTALL_CLIENT; then
    echo "[install] building darkwire client (release)"
    cargo build --release -p darkwire-client --bin darkwire
  fi

  if $INSTALL_RELAY; then
    echo "[install] building darkwire relay (release)"
    cargo build --release -p darkwire-relay --bin darkwire-relay
  fi
fi

if ! mkdir -p "$INSTALL_DIR"; then
  echo "error: cannot create install dir: $INSTALL_DIR" >&2
  echo "hint: use --install-dir /path/you/can/write" >&2
  exit 1
fi

if $INSTALL_CLIENT; then
  SRC="$ROOT_DIR/target/release/darkwire"
  if [[ ! -x "$SRC" ]]; then
    echo "error: missing binary $SRC (build failed or use without --skip-build)" >&2
    exit 1
  fi
  install -m 0755 "$SRC" "$INSTALL_DIR/darkwire"
  echo "[install] installed: $INSTALL_DIR/darkwire"
fi

if $INSTALL_RELAY; then
  SRC="$ROOT_DIR/target/release/darkwire-relay"
  if [[ ! -x "$SRC" ]]; then
    echo "error: missing binary $SRC (build failed or use without --skip-build)" >&2
    exit 1
  fi
  install -m 0755 "$SRC" "$INSTALL_DIR/darkwire-relay"
  echo "[install] installed: $INSTALL_DIR/darkwire-relay"
fi

case ":$PATH:" in
  *":$INSTALL_DIR:"*)
    ;;
  *)
    echo "[install] add to PATH:"
    echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
    ;;
esac

echo "[install] done"
