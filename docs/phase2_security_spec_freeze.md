# Darkwire Phase 2 Security Spec Freeze

Status: frozen for implementation  
Version: 1.0  
Date: 2026-02-25

## 1. Purpose
This document freezes the security requirements for Darkwire Phase 2 before protocol implementation.
It is the baseline for `protocol v2` and E2E development.

Any behavior that conflicts with this document must be treated as a bug or a planned spec change.

## 2. System Model
1. Two clients communicate through a relay over WebSocket (`ws`/`wss`).
2. Relay can route messages and store limited public handshake material.
3. Relay must not have decryption capability for message content.
4. Client identity is long-lived per device install.

## 3. Assets to Protect
1. Message plaintext.
2. Message authenticity and integrity.
3. Private keys and ratchet/session state.
4. Contact trust state (key continuity).

## 4. Adversary Model
1. Network attacker: can observe, delay, replay, drop, and modify packets.
2. Relay attacker: relay may be honest-but-curious and must be considered untrusted for content.
3. Active MITM: can attempt key substitution during handshake.
4. Endpoint compromise is out of cryptographic scope (malware/keylogger/screen capture).

## 5. Security Goals (Mandatory)
1. End-to-end confidentiality: only endpoints can decrypt messages.
2. End-to-end integrity/authentication: tampering is detected.
3. Forward secrecy: compromise of current keys must not reveal old messages.
4. Key continuity: client detects peer identity key changes.
5. No silent downgrade to insecure/plaintext mode.
6. Metadata minimization: relay logs metadata only per existing policy.

## 6. Trust Boundaries
1. Trusted boundary: local client process + local private key store.
2. Untrusted boundary: relay, network path, hosting provider.
3. TLS (`wss`) is defense-in-depth for transport only; it does not replace E2E.

## 7. Frozen Crypto Profile (Phase 2)
1. Identity key: Ed25519 (long-lived).
2. Key agreement: X25519.
3. KDF: HKDF-SHA256.
4. Message AEAD: ChaCha20-Poly1305.
5. Session evolution: Double Ratchet.
6. Randomness: OS CSPRNG only.

Notes:
1. Hybrid post-quantum extension is future work and not required for Phase 2.
2. Alternative algorithms are out of scope unless this document is revised.

## 8. Key and Session Rules
1. Private keys are generated and stored only on client devices.
2. Relay may store only public bundle material needed for handshake.
3. One-time prekeys are consumed once.
4. Identity key changes must trigger explicit trust warning in client UX.
5. Session resume must not require relay-side storage of decryptable secrets.

## 9. Downgrade and Failure Policy
1. If peer does not support `protocol v2` E2E, client must fail closed by default.
2. Handshake signature/prekey validation failure must abort session establishment.
3. Decryption/authentication failure must drop the message and surface a warning.
4. Unknown critical fields in secure envelopes must cause rejection (not ignore-and-continue).
5. Any fallback to insecure mode must require explicit user opt-in and visible warning.

## 10. Logging and Data Handling
1. Never log message plaintext/ciphertext, invite codes, keys, or shared secrets.
2. Never log full E2E envelopes if they contain sensitive payload bytes.
3. Log only operational metadata needed for debugging/rate-limits/connection lifecycle.

## 11. Verification Gate Before Protocol Coding
Before starting `Phase 2 protocol v2` implementation:
1. This spec is reviewed and accepted.
2. Event-level protocol design references this spec explicitly.
3. Negative security test plan is prepared (MITM/replay/key-change/decrypt-fail).

## 12. Acceptance Criteria for Phase 2 Security
1. Relay cannot decrypt message content in normal operation.
2. MITM attempts produce detectable identity/fingerprint mismatch signals.
3. Key change warning is shown and trust state becomes unverified until user action.
4. Tests cover happy path and adversarial cases for handshake and message flow.

## 13. Change Control
1. Security-impacting changes require updating this document version.
2. Document updates must include reason, scope, and migration impact.
