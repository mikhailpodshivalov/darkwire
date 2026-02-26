# Darkwire

Darkwire is an MVP terminal chat in "walkie-talkie" mode:
- relay-only transport over WebSocket
- no message persistence
- if peer is offline, delivery is dropped
- relay logs metadata only (no plaintext/ciphertext, no invite codes)

## Security docs
- Phase 2 security baseline (frozen): `docs/phase2_security_spec_freeze.md`
- Phase 2 protocol v2 design (frozen): `docs/phase2_protocol_v2_spec.md`

## MVP status
Implemented phases 1-7:
- workspace + protocol
- relay lifecycle and idle timeout
- invite TTL/one-time + rate limits/backoff
- session pairing + message relay
- line-based CLI client
- integration/security/logging tests
- release polish (docs + smoke script + CLI flags)

## Requirements
- Rust 1.76+
- Cargo

## Easy install (no cargo run every time)
### 1. Install binaries once
```bash
./scripts/install.sh
```
If needed, set custom destination:
```bash
./scripts/install.sh --install-dir /tmp/darkwire-bin
```

This installs:
- `darkwire` to `~/.local/bin/darkwire`
- `darkwire-relay` to `~/.local/bin/darkwire-relay`

### 2. Start relay
```bash
./scripts/start-relay.sh
```
or (custom install dir):
```bash
DARKWIRE_INSTALL_DIR=/tmp/darkwire-bin ./scripts/start-relay.sh
```
or directly:
```bash
darkwire-relay --listen 127.0.0.1:7000
```

### 3. Start client
```bash
./scripts/start-client.sh
```
or (custom install dir):
```bash
DARKWIRE_INSTALL_DIR=/tmp/darkwire-bin ./scripts/start-client.sh
```
or directly:
```bash
darkwire
```
Override relay when needed:
```bash
darkwire --relay ws://127.0.0.1:7000/ws
```
or:
```bash
DARKWIRE_RELAY_WS=ws://127.0.0.1:7000/ws darkwire
```

## Prebuilt client binaries for friends
Use GitHub Actions matrix build to get client binaries for different OS targets.

1. Open GitHub Actions and run workflow `Build Client Binaries`.
2. Wait for all matrix jobs to finish.
3. Download artifacts:
   - `darkwire-linux-x64`
   - `darkwire-windows-x64` (`darkwire.exe`)
   - `darkwire-macos-arm64`
4. Send the correct binary to each friend:
   - Windows: `darkwire.exe`
   - macOS ARM/Linux: `chmod +x ./darkwire && ./darkwire`

### Publish binaries to GitHub Release
1. Push a tag `client-v*` (example: `client-v20260223-02`).
2. Workflow `Build Client Binaries` runs matrix build and then publishes release assets.
3. In release page you get:
   - `darkwire-linux-x64`
   - `darkwire-windows-x64.exe`
   - `darkwire-macos-arm64`
   - `SHA256SUMS.txt`

## Quickstart
### 1. Run relay
```bash
cargo run -p darkwire-relay --bin darkwire-relay -- --listen 127.0.0.1:7000
```

### 2. Run inviter client (terminal A)
```bash
cargo run -p darkwire-client --bin darkwire -- --relay ws://127.0.0.1:7000/ws
```

Client A auto-creates invite on startup.
Copy generated invite string from `[invite:...]`.

### 3. Run joiner client (terminal B)
```bash
cargo run -p darkwire-client --bin darkwire -- --relay ws://127.0.0.1:7000/ws
```

In client B:
```text
/c DL1:...
```

After `session.started` on both sides, type text lines to chat.
Client now auto-runs session bootstrap (`prekey.get` -> `handshake.init/accept`) after pairing.
Wait for `[e2e] secure session established ...` before sending messages.

## Client commands
- `/help` show basic commands
- `/help all` show full command list
- `/new` create/rotate invite (invalidates previous invite for this client)
- `/i` legacy alias for `/new`
- `/c CODE` connect by invite
- `/me @name` set/change your username (recommended UX path)
- `/accept-key` accept peer key change and continue messaging
- `/keys` show local key status (fingerprint, signed prekey id/expiry, OPK count)
- `/keys rotate` rotate signed prekey and publish new bundle
- `/keys refill` refill OPK pool to target and publish new bundle
- `/keys revoke` revoke local identity (regenerate identity + prekeys) and publish new bundle
- `/trust` show active peer trust state + fingerprint/safety number
- `/trust verify` mark active peer identity as verified (advanced/manual flow)
- `/trust unverify` remove active peer verification
- `/trust list` list verified contacts
- `/login` show local login binding status (and request fresh relay lookup)
- `/login set @name` legacy alias for `/me @name`
- `/login lookup @name` resolve login to identity key fingerprint
- `/q` quit (sends `session.leave` when session is active)
- any other non-empty line sends chat message to active secure session

## Configuration
### Relay (`darkwire-relay`)
- `--listen <ip:port>` (`DARKWIRE_RELAY_ADDR`), default `127.0.0.1:7000`
- `--log-filter <filter>` (`DARKWIRE_LOG_FILTER`), default `darkwire_relay=info,tower_http=warn`

### Client (`darkwire`)
- `--relay <ws://.../ws|wss://.../ws>` (`DARKWIRE_RELAY_WS`), default `wss://srv1418428.hstgr.cloud/ws`
- `--invite-relay <ws://.../ws>` (`DARKWIRE_INVITE_RELAY`), default = value of `--relay`
- `--invite-ttl <seconds>` (`DARKWIRE_INVITE_TTL`), default `600` (range `1..=86400`)
- `--demo-incoming-ms <ms>` (`DARKWIRE_DEMO_INCOMING_MS`), optional simulated incoming events for terminal UI stress test (range `50..=60000`)
- `--key-file <path>` (`DARKWIRE_KEY_FILE`), optional keystore file path (default `~/.darkwire/keys.json`)

### Client key lifecycle (Phase 2.6 baseline)
- On first launch, client generates local identity key (Ed25519), signed prekey, and one-time prekeys.
- Client stores key material locally in keystore file with restricted permissions (`0700` dir, `0600` file on Unix).
- Signed prekey auto-rotates on expiry; OPK pool auto-refills when low.
- Client auto-publishes prekey bundle on startup and after `/keys rotate|refill|revoke`.

### Secure session persistence (Phase 2.11 baseline)
- Client stores encrypted-session checkpoints locally in `~/.darkwire/sessions.json` (restricted permissions on Unix).
- On `/c CODE`, client attempts secure auto-resume from local checkpoint when invite contains peer identity hint.
- If auto-resume is not possible, client falls back to normal `prekey.get -> handshake.init/accept` flow.
- On local identity revoke (`/keys revoke`), stored session checkpoints are cleared.

## Demo scenario (manual)
1. Start relay.
2. Start client A and copy startup invite code.
3. Start client B and run `/c <invite>`.
4. Exchange messages both ways.
5. Close client B (`/q` or Ctrl+C): client A receives `session.ended` with `peer_disconnect`.
6. To rotate compromised invite, run `/new` in client A and share new code.
7. To reconnect, use `/c` again with a fresh invite.

## Terminal input stress demo
To verify incoming events do not break your current input line:
```bash
darkwire --relay ws://127.0.0.1:7000/ws --demo-incoming-ms 200
```
Then type a long line while demo messages are arriving.

## Smoke test
Run end-to-end smoke checks:
```bash
./scripts/smoke.sh
```

The script runs workspace checks and key relay integration tests.

## No-store and security notes
- Relay state is in-memory only.
- `invite.create`: `5/min/IP` + `20/hour/IP`
- `invite.use`: `20/min/IP`, backoff after 5 failed attempts
- messages: `~1/sec/connection`, max size `8KB`
- handshake control events: `30/min/IP`
- idle timeout: `15 min`
- logs are metadata-only; payload content and secrets are not logged.

## Transport notes
- Use `ws://` for local dev.
- Use `wss://` via reverse proxy (nginx/caddy) in deployment.

## Production WSS (Caddy)
1. Point a public DNS record (for example `relay.example.com`) to your VPS IP.
2. Install Caddy config from `deploy/caddy/Caddyfile.example` and replace host with your real domain.
3. Validate and reload Caddy:
```bash
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
sudo systemctl status caddy --no-pager
```
4. Use secure relay URL in client:
```bash
cargo run -p darkwire-client --bin darkwire -- --relay wss://relay.example.com/ws
```
