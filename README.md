# Darkwire

Darkwire is a simple terminal chat for 1:1 conversations.

What you get:
- end-to-end encrypted messages between clients
- relay transport over WebSocket (`ws://` or `wss://`)
- no message history on relay (offline peer = message is dropped)
- metadata-only logging on relay

## Start Here (5 Minutes)

### Option A: Just chat on existing relay (no Rust needed)
1. Download a client binary from GitHub Releases.
2. Run it:
```bash
./darkwire
```
3. Set your username:
```text
/login @your_name
```
4. Create invite and copy it:
```text
/my invite copy
```
5. Send invite to a friend.
6. Friend runs:
```text
/invite DL1:...
```
7. Both sides wait for `secure session established`, then type normal text.

### Option B: Run your own relay + clients locally
Requirements:
- Rust + Cargo

Install once:
```bash
./scripts/install.sh
```

Start relay:
```bash
./scripts/start-relay.sh
```

Start client (Terminal A):
```bash
./scripts/start-client.sh --relay ws://127.0.0.1:7000/ws
```

Start client (Terminal B):
```bash
./scripts/start-client.sh --relay ws://127.0.0.1:7000/ws
```

Then use the same flow:
- A: `/login @name`, `/my invite copy`
- B: `/invite DL1:...`

## Commands (Current Minimal Set)

Default UI mode is `clean` (reduced system noise). Use `/details` (or `+`) to show full technical events.

1. `/help` - show command list
2. `/my invite copy` - create invite and copy it to clipboard
3. `/invite CODE` - join by invite code
4. `/login @name` - set or change your username
5. `/trust` - show trust state and safety number of active peer
6. `/accept-key` - accept peer key change and continue
7. `/details` (or `+`) - toggle verbose system diagnostics on/off
8. `/q` - quit
9. `<text>` - send encrypted message in active secure session

## Security Notes (Practical)

- If peer key changes, client warns and blocks sending until `/accept-key`.
- Before `/accept-key`, verify safety number with peer out-of-band.
- Relay cannot read plaintext messages.

Security specs:
- `docs/phase2_security_spec_freeze.md`
- `docs/phase2_protocol_v2_spec.md`

## Binaries for Friends (GitHub Actions)

Workflow: `Build Client Binaries`

Current matrix builds:
- `darkwire-linux-x64`
- `darkwire-linux-arm64`
- `darkwire-windows-x64.exe`
- `darkwire-macos-arm64`

Publish release assets:
1. Push tag like `client-v20260226-01`
2. Workflow builds binaries and publishes release with `SHA256SUMS.txt`

## Relay Deploy to VPS

Workflow: `.github/workflows/deploy-relay.yml`

It builds `darkwire-relay`, uploads binary, restarts `darkwire-relay` systemd unit, and shows status.

Required repo secrets:
- `VPS_HOST`
- `VPS_USER`
- `VPS_SSH_KEY_B64`

## Configuration (`.env`)

Both client and relay auto-load `.env` from current working directory.

Start from template:
```bash
cp .env.example .env
```

Common vars:
- `DARKWIRE_RELAY_WS` (client relay URL)
- `DARKWIRE_INVITE_RELAY` (optional invite relay URL)
- `DARKWIRE_INVITE_TTL` (invite lifetime in seconds)
- `DARKWIRE_RELAY_ADDR` (relay listen address)
- `DARKWIRE_LOG_FILTER` (relay log filter)

Precedence:
1. CLI flags
2. environment / `.env`
3. built-in defaults

## Troubleshooting

- `No active session`:
  run `/my invite copy` on one side and `/invite CODE` on the other.
- `clipboard copy not confirmed`:
  client prints `[invite] code DL1:...` as fallback for manual copy.
- Need input-race test UI mode:
```bash
darkwire --demo-incoming-ms 200
```

## Smoke Test

```bash
./scripts/smoke.sh
```

Targeted client reliability regressions:

```bash
./scripts/smoke-reliability.sh
```
