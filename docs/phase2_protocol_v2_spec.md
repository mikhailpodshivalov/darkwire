# Darkwire Phase 2 Protocol v2 Spec

Status: frozen for implementation  
Version: 1.0  
Date: 2026-02-25  
Depends on: `docs/phase2_security_spec_freeze.md`

## 1. Scope
This document defines wire-level `protocol v2` for E2E support.

Included:
1. Envelope and versioning rules.
2. Prekey bundle publish/fetch events.
3. Handshake control events.
4. Encrypted message envelope.
5. Validation and error mapping.
6. Client/relay state machines.

Not included:
1. UX details for login and trust screens (separate UX stages).
2. Multi-device and group-chat protocol.
3. Post-quantum hybrid mode.

## 2. Terms
1. `IK`: long-term identity key pair (Ed25519).
2. `SPK`: signed prekey (X25519 + Ed25519 signature).
3. `OPK`: one-time prekey (X25519).
4. `HS`: handshake.
5. `DR`: Double Ratchet.

## 3. Envelope
All v2 messages use JSON envelope:

```json
{
  "pv": 2,
  "t": "event.name",
  "rid": "cli-123",
  "d": {}
}
```

Rules:
1. `pv` is required and MUST be `2` for all v2 events.
2. `t` is required event type string.
3. `rid` is optional for async events; required for direct request/response correlation.
4. `d` is required object payload.
5. Unknown critical fields MUST cause rejection (`error` with `bad_request`).

Compatibility:
1. `pv=1` and old no-`pv` flow are legacy mode.
2. v2-capable clients MUST refuse plaintext messaging once v2 mode is selected for a session.

## 4. Binary Encoding Conventions
1. `b64u`: Base64URL without padding.
2. Ed25519 public key: 32 bytes -> `b64u`.
3. Ed25519 signature: 64 bytes -> `b64u`.
4. X25519 public key: 32 bytes -> `b64u`.
5. AEAD nonce: 12 bytes -> `b64u`.
6. Ciphertext includes AEAD tag and is encoded as `b64u`.

## 5. Event Catalog (v2)

### 5.1 Prekey Publish
Client -> Relay:

`t = "e2e.prekey.publish"`

```json
{
  "ik_ed25519": "b64u(32)",
  "spk": {
    "id": 1,
    "x25519": "b64u(32)",
    "sig_ed25519": "b64u(64)",
    "exp_unix": 1770000000
  },
  "opks": [
    { "id": 1001, "x25519": "b64u(32)" },
    { "id": 1002, "x25519": "b64u(32)" }
  ]
}
```

Relay -> Client:

`t = "e2e.prekey.published"`

```json
{
  "spk_id": 1,
  "opk_count": 64
}
```

Validation:
1. `spk.sig_ed25519` MUST verify `spk.x25519 || spk.id || exp_unix` by `ik_ed25519`.
2. `opks` MAY be empty, but relay should warn with `opk_count=0`.
3. Relay stores public material only.

### 5.2 Prekey Fetch (By Session)
Client -> Relay:

`t = "e2e.prekey.get"`

```json
{
  "session_id": "uuid"
}
```

Relay -> Client:

`t = "e2e.prekey.bundle"`

```json
{
  "session_id": "uuid",
  "peer": {
    "ik_ed25519": "b64u(32)",
    "spk": {
      "id": 7,
      "x25519": "b64u(32)",
      "sig_ed25519": "b64u(64)",
      "exp_unix": 1770000000
    },
    "opk": {
      "id": 9021,
      "x25519": "b64u(32)"
    }
  }
}
```

Rules:
1. Relay consumes one OPK for each successful bundle fetch/handshake start.
2. If OPKs are depleted, relay returns bundle with `"opk": null` and client continues with no-OPK path.

### 5.3 Handshake Init
Initiator Client -> Relay:

`t = "e2e.handshake.init"`

```json
{
  "session_id": "uuid",
  "hs_id": "uuid",
  "sender_ik_ed25519": "b64u(32)",
  "sender_eph_x25519": "b64u(32)",
  "peer_spk_id": 7,
  "peer_opk_id": 9021,
  "sig_ed25519": "b64u(64)",
  "ts_unix": 1770000100
}
```

Relay routes to peer as:

`t = "e2e.handshake.init.recv"` (same payload + relay metadata)

Validation:
1. `sig_ed25519` signs canonical transcript:
   `session_id || hs_id || sender_eph_x25519 || peer_spk_id || peer_opk_id || ts_unix`.
2. `peer_spk_id` must match bundle selected by initiator.
3. `peer_opk_id` may be null when OPKs are depleted.

### 5.4 Handshake Accept
Responder Client -> Relay:

`t = "e2e.handshake.accept"`

```json
{
  "session_id": "uuid",
  "hs_id": "uuid",
  "responder_ik_ed25519": "b64u(32)",
  "responder_eph_x25519": "b64u(32)",
  "sig_ed25519": "b64u(64)",
  "kc": "b64u(16)"
}
```

Relay routes to initiator as:

`t = "e2e.handshake.accept.recv"`

Notes:
1. `kc` is key-confirmation tag derived from handshake secret.
2. Both peers switch to DR state only after key-confirmation passes.

### 5.5 Encrypted Message
Client -> Relay:

`t = "e2e.msg.send"`

```json
{
  "session_id": "uuid",
  "n": 15,
  "pn": 9,
  "dh_x25519": "b64u(32)",
  "nonce": "b64u(12)",
  "ct": "b64u(..)",
  "ad": {
    "pv": 2,
    "session_id": "uuid",
    "n": 15,
    "pn": 9
  }
}
```

Relay -> Peer:

`t = "e2e.msg.recv"` (same payload, relay-routed)

Rules:
1. Relay MUST not inspect/transform `ct`.
2. Client MUST verify AEAD auth tag and associated data before plaintext release.
3. On decrypt/auth failure: drop message and emit local warning.

## 6. Required Validation Rules
1. `session_id`, `hs_id` must be valid UUID.
2. All numeric counters are unsigned and monotonic where applicable.
3. `n` must be strictly increasing per sending chain.
4. Replay of `(session_id, sender_chain, n)` is rejected.
5. `ts_unix` must be within acceptable clock skew window (default: 5 minutes).
6. Any malformed key length or invalid `b64u` => `error.bad_request`.

## 7. Error Codes (v2 additions)
Extend `error.code` with:
1. `unsupported_protocol`
2. `e2e_required`
3. `prekey_not_found`
4. `prekey_depleted`
5. `handshake_invalid`
6. `handshake_timeout`
7. `decrypt_failed`
8. `replay_detected`
9. `identity_key_changed`
10. `state_conflict`

Mapping guidance:
1. Relay-side schema errors -> `bad_request`.
2. Missing/invalid peer bundle -> `prekey_not_found`.
3. OPK unavailable -> `prekey_depleted` (non-fatal if no-OPK path enabled).
4. Signature/transcript mismatch -> `handshake_invalid`.
5. Client decrypt/auth failure is local first, optionally signaled as `decrypt_failed`.

## 8. State Machines

### 8.1 Client Connection State
1. `connected`
2. `session_paired` (after invite/session flow)
3. `bundle_ready` (peer bundle fetched)
4. `handshake_pending`
5. `secure_active` (DR established)
6. `ended`

Transitions:
1. `session_paired -> bundle_ready` via `e2e.prekey.bundle`.
2. `bundle_ready -> handshake_pending` via `e2e.handshake.init`.
3. `handshake_pending -> secure_active` via valid accept + key confirmation.
4. Any fatal validation/decrypt failure -> `ended` (or explicit recover path).

### 8.2 Relay Session State
1. Relay tracks transport session and route only.
2. Relay stores public prekey material and OPK consumption state.
3. Relay never stores plaintext keys or message plaintext.

## 9. Downgrade Policy (Fail Closed)
1. If one side is in v2 mode, plaintext `msg.send/msg.recv` MUST be rejected.
2. If peer/relay cannot satisfy v2 requirements, client must surface explicit error and refuse silent fallback.
3. Any compatibility fallback requires explicit user action (not automatic).

## 10. Size and Rate Constraints (v2 payloads)
1. Existing global limits remain: `~1 msg/sec/conn`, max payload 8KB.
2. Encrypted payload (`ct` + envelope) must stay within max size.
3. Handshake events are control-plane and should be rate-limited separately if abused.

## 11. Logging Policy (v2-specific)
1. Do not log `ct`, `nonce`, handshake secrets, signatures, invite codes, or private key material.
2. Log event type, request id, session id, and failure class only.

## 12. Implementation Notes
1. Keep existing invite/session lifecycle from MVP; v2 builds on it.
2. Use existing `session.started/session.ended` events to bracket secure state.
3. v2 event names are additive and do not require immediate removal of v1 names.

## 13. Test Vectors and Compliance
Before coding complete v2 runtime:
1. Add canonical transcript serialization fixtures.
2. Add handshake KATs (known-answer tests).
3. Add decrypt-fail/replay/MITM negative tests.
4. Verify strict rejection of malformed envelopes/keys.
