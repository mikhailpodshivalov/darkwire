use crate::keys::{HandshakeRole, SecureSessionMaterial};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use darkwire_protocol::events::{E2eMsgAd, E2eMsgRecvEvent, E2eMsgSendRequest};
use ring::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey},
    digest::{digest, SHA256},
};
use std::{error::Error, fmt};
use uuid::Uuid;

const PV_V2: u8 = 2;
const DIR_INITIATOR_TO_RESPONDER: &[u8] = b"darkwire-e2e-dir-init->resp-v1";
const DIR_RESPONDER_TO_INITIATOR: &[u8] = b"darkwire-e2e-dir-resp->init-v1";
const CHAIN_PUBLIC_CONTEXT: &[u8] = b"darkwire-e2e-chain-public-v1";
const MESSAGE_KEY_CONTEXT: &[u8] = b"darkwire-e2e-msg-key-v1";
const MESSAGE_NONCE_CONTEXT: &[u8] = b"darkwire-e2e-msg-nonce-v1";
const MAX_FORWARD_GAP: u64 = 1024;

#[derive(Debug, Default)]
pub struct SecureMessenger {
    session: Option<SecureMessagingSession>,
}

#[derive(Debug)]
struct SecureMessagingSession {
    session_id: Uuid,
    role: HandshakeRole,
    root_key_b64u: String,
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_dh_x25519_b64u: String,
    send_n: u64,
    recv_n: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureSessionSnapshot {
    pub session_id: Uuid,
    pub role: HandshakeRole,
    pub root_key_b64u: String,
    pub send_n: u64,
    pub recv_n: u64,
}

#[derive(Debug)]
pub enum SecureMessagingError {
    NotActive,
    SessionMismatch,
    ReplayDetected(u64),
    OutOfOrder { expected: u64, got: u64 },
    InvalidAssociatedData,
    InvalidCounter,
    InvalidNonce,
    NonceMismatch,
    DecryptFailed,
    InvalidUtf8,
    InvalidRootKey,
    CryptoInit,
}

impl fmt::Display for SecureMessagingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecureMessagingError::NotActive => write!(f, "secure session is not active"),
            SecureMessagingError::SessionMismatch => write!(f, "session id mismatch"),
            SecureMessagingError::ReplayDetected(n) => write!(f, "replay detected for n={n}"),
            SecureMessagingError::OutOfOrder { expected, got } => {
                write!(
                    f,
                    "out-of-order message: expected n={expected}, got n={got}"
                )
            }
            SecureMessagingError::InvalidAssociatedData => write!(f, "invalid associated data"),
            SecureMessagingError::InvalidCounter => write!(f, "invalid message counter"),
            SecureMessagingError::InvalidNonce => write!(f, "invalid message nonce"),
            SecureMessagingError::NonceMismatch => write!(f, "nonce mismatch"),
            SecureMessagingError::DecryptFailed => write!(f, "message decryption failed"),
            SecureMessagingError::InvalidUtf8 => write!(f, "decrypted message is not utf-8"),
            SecureMessagingError::InvalidRootKey => write!(f, "invalid handshake root key"),
            SecureMessagingError::CryptoInit => write!(f, "failed to initialize cipher"),
        }
    }
}

impl Error for SecureMessagingError {}

impl SecureMessenger {
    pub fn clear(&mut self) {
        self.session = None;
    }

    pub fn activate(
        &mut self,
        material: &SecureSessionMaterial,
    ) -> Result<(), SecureMessagingError> {
        self.activate_with_root_key(
            material.session_id,
            material.role,
            &material.root_key_b64u,
            0,
            0,
        )
    }

    pub fn activate_resumed(
        &mut self,
        session_id: Uuid,
        role: HandshakeRole,
        root_key_b64u: &str,
        send_n: u64,
        recv_n: u64,
    ) -> Result<(), SecureMessagingError> {
        self.activate_with_root_key(session_id, role, root_key_b64u, send_n, recv_n)
    }

    pub fn snapshot(&self) -> Option<SecureSessionSnapshot> {
        self.session.as_ref().map(|session| SecureSessionSnapshot {
            session_id: session.session_id,
            role: session.role,
            root_key_b64u: session.root_key_b64u.clone(),
            send_n: session.send_n,
            recv_n: session.recv_n,
        })
    }

    pub fn encrypt_outgoing(
        &mut self,
        plaintext: &str,
    ) -> Result<E2eMsgSendRequest, SecureMessagingError> {
        let session = self
            .session
            .as_mut()
            .ok_or(SecureMessagingError::NotActive)?;
        session.send_n = session.send_n.saturating_add(1);

        let n = session.send_n;
        let pn = 0_u64;
        let ad = E2eMsgAd {
            pv: PV_V2,
            session_id: session.session_id,
            n,
            pn,
        };
        let aad =
            associated_data_bytes(&ad).map_err(|_| SecureMessagingError::InvalidAssociatedData)?;
        let key_bytes = derive_32(MESSAGE_KEY_CONTEXT, &session.send_key, Some(n));
        let nonce_bytes = derive_nonce(&session.send_key, n);

        let mut ciphertext = plaintext.as_bytes().to_vec();
        let key = LessSafeKey::new(
            UnboundKey::new(&aead::CHACHA20_POLY1305, &key_bytes)
                .map_err(|_| SecureMessagingError::CryptoInit)?,
        );
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(aad.as_slice()),
            &mut ciphertext,
        )
        .map_err(|_| SecureMessagingError::CryptoInit)?;

        Ok(E2eMsgSendRequest {
            session_id: session.session_id,
            n,
            pn,
            dh_x25519: session.send_dh_x25519_b64u.clone(),
            nonce: encode_b64u(&nonce_bytes),
            ct: encode_b64u(&ciphertext),
            ad,
        })
    }

    pub fn decrypt_incoming(
        &mut self,
        event: &E2eMsgRecvEvent,
    ) -> Result<String, SecureMessagingError> {
        let session = self
            .session
            .as_mut()
            .ok_or(SecureMessagingError::NotActive)?;

        if event.session_id != session.session_id || event.ad.session_id != session.session_id {
            return Err(SecureMessagingError::SessionMismatch);
        }
        if event.ad.pv != PV_V2 || event.ad.n != event.n || event.ad.pn != event.pn {
            return Err(SecureMessagingError::InvalidAssociatedData);
        }
        if event.n == 0 {
            return Err(SecureMessagingError::InvalidCounter);
        }

        let expected = session.recv_n.saturating_add(1);
        if event.n < expected {
            return Err(SecureMessagingError::ReplayDetected(event.n));
        }
        if event.n.saturating_sub(expected) > MAX_FORWARD_GAP {
            return Err(SecureMessagingError::OutOfOrder {
                expected,
                got: event.n,
            });
        }

        let nonce =
            decode_b64u_fixed_12(&event.nonce).map_err(|_| SecureMessagingError::InvalidNonce)?;
        let expected_nonce = derive_nonce(&session.recv_key, event.n);
        if nonce != expected_nonce {
            return Err(SecureMessagingError::NonceMismatch);
        }

        let key_bytes = derive_32(MESSAGE_KEY_CONTEXT, &session.recv_key, Some(event.n));
        let key = LessSafeKey::new(
            UnboundKey::new(&aead::CHACHA20_POLY1305, &key_bytes)
                .map_err(|_| SecureMessagingError::CryptoInit)?,
        );
        let mut ciphertext =
            decode_b64u(&event.ct).map_err(|_| SecureMessagingError::DecryptFailed)?;
        let aad = associated_data_bytes(&event.ad)
            .map_err(|_| SecureMessagingError::InvalidAssociatedData)?;
        let plaintext = key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad.as_slice()),
                &mut ciphertext,
            )
            .map_err(|_| SecureMessagingError::DecryptFailed)?;

        let message =
            String::from_utf8(plaintext.to_vec()).map_err(|_| SecureMessagingError::InvalidUtf8)?;
        session.recv_n = event.n;
        Ok(message)
    }

    fn activate_with_root_key(
        &mut self,
        session_id: Uuid,
        role: HandshakeRole,
        root_key_b64u: &str,
        send_n: u64,
        recv_n: u64,
    ) -> Result<(), SecureMessagingError> {
        let root_key = decode_b64u_fixed_32(root_key_b64u)
            .map_err(|_| SecureMessagingError::InvalidRootKey)?;
        let (send_context, recv_context) = match role {
            HandshakeRole::Initiator => (DIR_INITIATOR_TO_RESPONDER, DIR_RESPONDER_TO_INITIATOR),
            HandshakeRole::Responder => (DIR_RESPONDER_TO_INITIATOR, DIR_INITIATOR_TO_RESPONDER),
        };

        let send_key = derive_32(send_context, &root_key, None);
        let recv_key = derive_32(recv_context, &root_key, None);
        let send_dh_x25519_b64u = encode_b64u(&derive_32(CHAIN_PUBLIC_CONTEXT, &send_key, None));

        self.session = Some(SecureMessagingSession {
            session_id,
            role,
            root_key_b64u: root_key_b64u.to_string(),
            send_key,
            recv_key,
            send_dh_x25519_b64u,
            send_n,
            recv_n,
        });

        Ok(())
    }
}

fn associated_data_bytes(ad: &E2eMsgAd) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(ad)
}

fn derive_nonce(key: &[u8; 32], n: u64) -> [u8; 12] {
    let full = derive_32(MESSAGE_NONCE_CONTEXT, key, Some(n));
    let mut nonce = [0_u8; 12];
    nonce.copy_from_slice(&full[..12]);
    nonce
}

fn derive_32(context: &[u8], key: &[u8; 32], n: Option<u64>) -> [u8; 32] {
    let mut material = Vec::with_capacity(context.len() + 32 + 8);
    material.extend_from_slice(context);
    material.extend_from_slice(key);
    if let Some(n) = n {
        material.extend_from_slice(&n.to_be_bytes());
    }

    let hash = digest(&SHA256, &material);
    let mut out = [0_u8; 32];
    out.copy_from_slice(hash.as_ref());
    out
}

fn encode_b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_b64u(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(value.as_bytes())
}

fn decode_b64u_fixed_32(value: &str) -> Result<[u8; 32], base64::DecodeError> {
    let bytes = decode_b64u(value)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| base64::DecodeError::InvalidLength(bytes.len()))
}

fn decode_b64u_fixed_12(value: &str) -> Result<[u8; 12], base64::DecodeError> {
    let bytes = decode_b64u(value)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| base64::DecodeError::InvalidLength(bytes.len()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::HandshakeRole;

    fn material_for(role: HandshakeRole) -> SecureSessionMaterial {
        SecureSessionMaterial {
            session_id: Uuid::new_v4(),
            hs_id: Uuid::new_v4(),
            peer_ik_ed25519: "peer".to_string(),
            role,
            established_unix: 1,
            root_key_b64u: encode_b64u(&[7_u8; 32]),
        }
    }

    #[test]
    fn encrypt_decrypt_roundtrip_between_peers() {
        let init_material = material_for(HandshakeRole::Initiator);
        let mut resp_material = material_for(HandshakeRole::Responder);
        resp_material.session_id = init_material.session_id;
        resp_material.hs_id = init_material.hs_id;
        resp_material.root_key_b64u = init_material.root_key_b64u.clone();

        let mut initiator = SecureMessenger::default();
        let mut responder = SecureMessenger::default();
        initiator
            .activate(&init_material)
            .expect("activate initiator");
        responder
            .activate(&resp_material)
            .expect("activate responder");

        let encrypted = initiator
            .encrypt_outgoing("hello encrypted")
            .expect("encrypt");
        let decrypted = responder.decrypt_incoming(&encrypted).expect("decrypt");
        assert_eq!(decrypted, "hello encrypted");
    }

    #[test]
    fn replay_is_rejected() {
        let init_material = material_for(HandshakeRole::Initiator);
        let mut resp_material = material_for(HandshakeRole::Responder);
        resp_material.session_id = init_material.session_id;
        resp_material.hs_id = init_material.hs_id;
        resp_material.root_key_b64u = init_material.root_key_b64u.clone();

        let mut initiator = SecureMessenger::default();
        let mut responder = SecureMessenger::default();
        initiator
            .activate(&init_material)
            .expect("activate initiator");
        responder
            .activate(&resp_material)
            .expect("activate responder");

        let encrypted = initiator.encrypt_outgoing("once").expect("encrypt");
        let _ = responder
            .decrypt_incoming(&encrypted)
            .expect("first decrypt");
        let replay = responder
            .decrypt_incoming(&encrypted)
            .expect_err("replay must fail");
        assert!(matches!(replay, SecureMessagingError::ReplayDetected(1)));
    }

    #[test]
    fn missing_counter_gap_is_accepted() {
        let init_material = material_for(HandshakeRole::Initiator);
        let mut resp_material = material_for(HandshakeRole::Responder);
        resp_material.session_id = init_material.session_id;
        resp_material.hs_id = init_material.hs_id;
        resp_material.root_key_b64u = init_material.root_key_b64u.clone();

        let mut initiator = SecureMessenger::default();
        let mut responder = SecureMessenger::default();
        initiator
            .activate(&init_material)
            .expect("activate initiator");
        responder
            .activate(&resp_material)
            .expect("activate responder");

        let first = initiator.encrypt_outgoing("m1").expect("encrypt m1");
        let second = initiator.encrypt_outgoing("m2").expect("encrypt m2");
        let third = initiator.encrypt_outgoing("m3").expect("encrypt m3");

        let first_plain = responder.decrypt_incoming(&first).expect("decrypt m1");
        assert_eq!(first_plain, "m1");
        let third_plain = responder.decrypt_incoming(&third).expect("decrypt m3");
        assert_eq!(third_plain, "m3");

        let late_second = responder
            .decrypt_incoming(&second)
            .expect_err("late m2 should be rejected after moving recv counter");
        assert!(matches!(
            late_second,
            SecureMessagingError::ReplayDetected(2)
        ));
    }

    #[test]
    fn resume_restores_counters_for_new_transport_session() {
        let init_material = material_for(HandshakeRole::Initiator);
        let mut resp_material = material_for(HandshakeRole::Responder);
        resp_material.session_id = init_material.session_id;
        resp_material.hs_id = init_material.hs_id;
        resp_material.root_key_b64u = init_material.root_key_b64u.clone();

        let mut initiator = SecureMessenger::default();
        let mut responder = SecureMessenger::default();
        initiator
            .activate(&init_material)
            .expect("activate initiator");
        responder
            .activate(&resp_material)
            .expect("activate responder");

        let first = initiator.encrypt_outgoing("first").expect("encrypt first");
        let _ = responder.decrypt_incoming(&first).expect("decrypt first");

        let second = responder
            .encrypt_outgoing("second")
            .expect("encrypt second");
        let _ = initiator.decrypt_incoming(&second).expect("decrypt second");

        let init_snapshot = initiator.snapshot().expect("initiator snapshot");
        let resp_snapshot = responder.snapshot().expect("responder snapshot");
        let resumed_session_id = Uuid::new_v4();

        let mut resumed_initiator = SecureMessenger::default();
        let mut resumed_responder = SecureMessenger::default();
        resumed_initiator
            .activate_resumed(
                resumed_session_id,
                HandshakeRole::Initiator,
                &init_snapshot.root_key_b64u,
                init_snapshot.send_n,
                init_snapshot.recv_n,
            )
            .expect("resume initiator");
        resumed_responder
            .activate_resumed(
                resumed_session_id,
                HandshakeRole::Responder,
                &resp_snapshot.root_key_b64u,
                resp_snapshot.send_n,
                resp_snapshot.recv_n,
            )
            .expect("resume responder");

        let resumed_message = resumed_initiator
            .encrypt_outgoing("after-resume")
            .expect("encrypt after resume");
        assert_eq!(resumed_message.n, init_snapshot.send_n + 1);
        let decrypted = resumed_responder
            .decrypt_incoming(&resumed_message)
            .expect("decrypt after resume");
        assert_eq!(decrypted, "after-resume");
    }
}
