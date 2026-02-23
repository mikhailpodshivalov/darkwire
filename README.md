# Darkwire

Darkwire is an MVP terminal chat in "walkie-talkie" mode:
- relay-only transport over WebSocket
- no message persistence
- if peer is offline, delivery is dropped
- relay logs metadata only (no plaintext/ciphertext, no invite codes)

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

## Quickstart
### 1. Run relay
```bash
cargo run -p darkwire-relay --bin darkwire-relay -- --listen 127.0.0.1:7000
```

### 2. Run inviter client (terminal A)
```bash
cargo run -p darkwire-client --bin darkwire -- --relay ws://127.0.0.1:7000/ws
```

In client A:
```text
/i
```
Copy generated invite string.

### 3. Run joiner client (terminal B)
```bash
cargo run -p darkwire-client --bin darkwire -- --relay ws://127.0.0.1:7000/ws
```

In client B:
```text
/c DL1:...
```

After `session.started` on both sides, type text lines to chat.

## Client commands
- `/i` create invite
- `/c CODE` connect by invite
- `/q` quit (sends `session.leave` when session is active)
- any other non-empty line sends chat message to active session

## Configuration
### Relay (`darkwire-relay`)
- `--listen <ip:port>` (`DARKWIRE_RELAY_ADDR`), default `127.0.0.1:7000`
- `--log-filter <filter>` (`DARKWIRE_LOG_FILTER`), default `darkwire_relay=info,tower_http=warn`

### Client (`darkwire`)
- `--relay <ws://.../ws>` (`DARKWIRE_RELAY_WS`), default `ws://127.0.0.1:7000/ws`
- `--invite-relay <ws://.../ws>` (`DARKWIRE_INVITE_RELAY`), default = value of `--relay`
- `--invite-ttl <seconds>` (`DARKWIRE_INVITE_TTL`), default `600` (range `1..=86400`)

## Demo scenario (manual)
1. Start relay.
2. Start client A and run `/i`.
3. Start client B and run `/c <invite>`.
4. Exchange messages both ways.
5. Close client B (`/q` or Ctrl+C): client A receives `session.ended` with `peer_disconnect`.
6. To reconnect, use `/c` again with a fresh invite.

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
- idle timeout: `15 min`
- logs are metadata-only; payload content and secrets are not logged.

## Transport notes
- Use `ws://` for local dev.
- Use `wss://` via reverse proxy (nginx/caddy) in deployment.
