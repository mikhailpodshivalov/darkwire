use super::*;
use darkwire_protocol::events::{HandshakeAcceptRequest, HandshakeInitRequest, PublicPrekeyBundle};
use ring::signature::{Ed25519KeyPair, UnparsedPublicKey, ED25519};
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

const HANDSHAKE_INIT_SIG_CONTEXT: &[u8] = b"darkwire-hs-init-v1";
const HANDSHAKE_ACCEPT_SIG_CONTEXT: &[u8] = b"darkwire-hs-accept-v1";
const HANDSHAKE_SECRET_CONTEXT: &[u8] = b"darkwire-hs-secret-v1";
const HANDSHAKE_KC_CONTEXT: &[u8] = b"darkwire-hs-kc-v1";
const MAX_CLOCK_SKEW_SECS: u64 = 5 * 60;

impl KeyManager {
    pub fn start_initiator_handshake(
        &self,
        session_id: Uuid,
        peer_bundle: &PublicPrekeyBundle,
    ) -> Result<(HandshakeInitRequest, InitiatorHandshakeContext), Box<dyn Error>> {
        verify_signed_prekey_bundle(peer_bundle)?;

        if peer_bundle.spk.exp_unix <= now_unix() {
            return Err("peer signed prekey is expired".into());
        }

        let (initiator_eph_private_x25519_b64u, initiator_eph_public_x25519_b64u) =
            generate_x25519_keypair()?;
        let hs_id = Uuid::new_v4();
        let ts_unix = now_unix();

        let signature = sign_handshake_init(
            &self.store.identity.pkcs8_ed25519_b64u,
            session_id,
            hs_id,
            &initiator_eph_public_x25519_b64u,
            peer_bundle.spk.id,
            peer_bundle.opk.as_ref().map(|opk| opk.id),
            ts_unix,
        )?;

        let request = HandshakeInitRequest {
            session_id,
            hs_id,
            sender_ik_ed25519: self.store.identity.public_ed25519_b64u.clone(),
            sender_eph_x25519: initiator_eph_public_x25519_b64u.clone(),
            peer_spk_id: peer_bundle.spk.id,
            peer_opk_id: peer_bundle.opk.as_ref().map(|opk| opk.id),
            sig_ed25519: signature,
            ts_unix,
        };

        let context = InitiatorHandshakeContext {
            session_id,
            hs_id,
            started_unix: ts_unix,
            peer_ik_ed25519: peer_bundle.ik_ed25519.clone(),
            initiator_eph_private_x25519_b64u,
            peer_spk_x25519_b64u: peer_bundle.spk.x25519.clone(),
            peer_opk_x25519_b64u: peer_bundle.opk.as_ref().map(|opk| opk.x25519.clone()),
        };

        Ok((request, context))
    }

    pub fn respond_to_handshake_init(
        &mut self,
        init: &HandshakeInitRequest,
    ) -> Result<(HandshakeAcceptRequest, SecureSessionMaterial), Box<dyn Error>> {
        verify_handshake_init_signature(init)?;
        if !is_timestamp_within_skew(init.ts_unix, MAX_CLOCK_SKEW_SECS) {
            return Err("handshake init timestamp is outside allowed skew".into());
        }

        if init.peer_spk_id != self.store.signed_prekey.id {
            return Err("handshake init peer_spk_id does not match local signed prekey".into());
        }

        let sender_eph = decode_b64u_fixed_32(&init.sender_eph_x25519)?;
        let local_spk_private =
            decode_b64u_fixed_32(&self.store.signed_prekey.private_x25519_b64u)?;

        let mut dh_parts = Vec::with_capacity(3);
        dh_parts.push(x25519_shared_secret(local_spk_private, sender_eph));

        if let Some(opk_id) = init.peer_opk_id {
            let opk = self
                .store
                .take_one_time_prekey(opk_id)
                .ok_or("handshake init referenced unknown one-time prekey")?;
            let opk_private = decode_b64u_fixed_32(&opk.private_x25519_b64u)?;
            dh_parts.push(x25519_shared_secret(opk_private, sender_eph));
        }

        let (responder_eph_private, responder_eph_public) = generate_x25519_keypair()?;
        let responder_eph_private = decode_b64u_fixed_32(&responder_eph_private)?;
        dh_parts.push(x25519_shared_secret(responder_eph_private, sender_eph));

        let root_key = derive_handshake_secret(init.session_id, init.hs_id, &dh_parts);
        let kc = derive_key_confirmation_tag(&root_key);
        let kc_b64u = encode_b64u(&kc);

        let signature = sign_handshake_accept(
            &self.store.identity.pkcs8_ed25519_b64u,
            init.session_id,
            init.hs_id,
            &responder_eph_public,
            &kc_b64u,
        )?;

        let now = now_unix();
        if self.store.one_time_prekeys.len() < LOW_WATERMARK_OPK_COUNT {
            self.store.refill_opks_to_target(now)?;
        }
        self.store.updated_unix = now;
        self.persist()?;

        let accept = HandshakeAcceptRequest {
            session_id: init.session_id,
            hs_id: init.hs_id,
            responder_ik_ed25519: self.store.identity.public_ed25519_b64u.clone(),
            responder_eph_x25519: responder_eph_public,
            sig_ed25519: signature,
            kc: kc_b64u.clone(),
        };

        let material = SecureSessionMaterial {
            session_id: init.session_id,
            hs_id: init.hs_id,
            peer_ik_ed25519: init.sender_ik_ed25519.clone(),
            role: HandshakeRole::Responder,
            established_unix: now,
            root_key_b64u: encode_b64u(&root_key),
        };

        Ok((accept, material))
    }

    pub fn finalize_initiator_handshake(
        &self,
        context: &InitiatorHandshakeContext,
        accept: &HandshakeAcceptRequest,
    ) -> Result<SecureSessionMaterial, Box<dyn Error>> {
        if accept.session_id != context.session_id || accept.hs_id != context.hs_id {
            return Err("handshake accept does not match pending context".into());
        }

        if accept.responder_ik_ed25519 != context.peer_ik_ed25519 {
            return Err("handshake accept identity key does not match expected peer".into());
        }

        verify_handshake_accept_signature(accept)?;

        let initiator_eph_private =
            decode_b64u_fixed_32(&context.initiator_eph_private_x25519_b64u)?;
        let peer_spk_public = decode_b64u_fixed_32(&context.peer_spk_x25519_b64u)?;
        let mut dh_parts = Vec::with_capacity(3);
        dh_parts.push(x25519_shared_secret(initiator_eph_private, peer_spk_public));

        if let Some(peer_opk_public) = context.peer_opk_x25519_b64u.as_deref() {
            let peer_opk_public = decode_b64u_fixed_32(peer_opk_public)?;
            dh_parts.push(x25519_shared_secret(initiator_eph_private, peer_opk_public));
        }

        let responder_eph_public = decode_b64u_fixed_32(&accept.responder_eph_x25519)?;
        dh_parts.push(x25519_shared_secret(
            initiator_eph_private,
            responder_eph_public,
        ));

        let root_key = derive_handshake_secret(context.session_id, context.hs_id, &dh_parts);
        let expected_kc = derive_key_confirmation_tag(&root_key);
        let received_kc = decode_b64u_fixed_16(&accept.kc)?;
        if received_kc != expected_kc {
            return Err("handshake key confirmation mismatch".into());
        }

        Ok(SecureSessionMaterial {
            session_id: context.session_id,
            hs_id: context.hs_id,
            peer_ik_ed25519: accept.responder_ik_ed25519.clone(),
            role: HandshakeRole::Initiator,
            established_unix: now_unix(),
            root_key_b64u: encode_b64u(&root_key),
        })
    }
}

fn verify_signed_prekey_bundle(peer_bundle: &PublicPrekeyBundle) -> Result<(), Box<dyn Error>> {
    let ik_public = decode_b64u_fixed_32(&peer_bundle.ik_ed25519)?;
    let spk_public = decode_b64u_fixed_32(&peer_bundle.spk.x25519)?;
    let signature = decode_b64u(&peer_bundle.spk.sig_ed25519)?;
    if signature.len() != 64 {
        return Err("signed prekey signature length must be 64 bytes".into());
    }

    let transcript =
        signed_prekey_transcript_bytes(&spk_public, peer_bundle.spk.id, peer_bundle.spk.exp_unix);
    UnparsedPublicKey::new(&ED25519, ik_public.as_slice())
        .verify(&transcript, &signature)
        .map_err(|_| "signed prekey signature verification failed".into())
}

fn sign_handshake_init(
    identity_pkcs8_b64u: &str,
    session_id: Uuid,
    hs_id: Uuid,
    sender_eph_x25519_b64u: &str,
    peer_spk_id: u32,
    peer_opk_id: Option<u32>,
    ts_unix: u64,
) -> Result<String, Box<dyn Error>> {
    let sender_eph = decode_b64u_fixed_32(sender_eph_x25519_b64u)?;
    let transcript = handshake_init_transcript_bytes(
        session_id,
        hs_id,
        &sender_eph,
        peer_spk_id,
        peer_opk_id,
        ts_unix,
    );
    let signature = sign_message(identity_pkcs8_b64u, &transcript)?;
    Ok(encode_b64u(signature.as_ref()))
}

fn verify_handshake_init_signature(req: &HandshakeInitRequest) -> Result<(), Box<dyn Error>> {
    let sender_ik = decode_b64u_fixed_32(&req.sender_ik_ed25519)?;
    let sender_eph = decode_b64u_fixed_32(&req.sender_eph_x25519)?;
    let signature = decode_b64u(&req.sig_ed25519)?;
    if signature.len() != 64 {
        return Err("handshake init signature length must be 64 bytes".into());
    }

    let transcript = handshake_init_transcript_bytes(
        req.session_id,
        req.hs_id,
        &sender_eph,
        req.peer_spk_id,
        req.peer_opk_id,
        req.ts_unix,
    );

    UnparsedPublicKey::new(&ED25519, sender_ik.as_slice())
        .verify(&transcript, &signature)
        .map_err(|_| "handshake init signature verification failed".into())
}

fn sign_handshake_accept(
    identity_pkcs8_b64u: &str,
    session_id: Uuid,
    hs_id: Uuid,
    responder_eph_x25519_b64u: &str,
    kc_b64u: &str,
) -> Result<String, Box<dyn Error>> {
    let responder_eph = decode_b64u_fixed_32(responder_eph_x25519_b64u)?;
    let kc = decode_b64u_fixed_16(kc_b64u)?;
    let transcript = handshake_accept_transcript_bytes(session_id, hs_id, &responder_eph, &kc);
    let signature = sign_message(identity_pkcs8_b64u, &transcript)?;
    Ok(encode_b64u(signature.as_ref()))
}

fn verify_handshake_accept_signature(req: &HandshakeAcceptRequest) -> Result<(), Box<dyn Error>> {
    let responder_ik = decode_b64u_fixed_32(&req.responder_ik_ed25519)?;
    let responder_eph = decode_b64u_fixed_32(&req.responder_eph_x25519)?;
    let signature = decode_b64u(&req.sig_ed25519)?;
    if signature.len() != 64 {
        return Err("handshake accept signature length must be 64 bytes".into());
    }

    let kc = decode_b64u_fixed_16(&req.kc)?;
    let transcript =
        handshake_accept_transcript_bytes(req.session_id, req.hs_id, &responder_eph, &kc);

    UnparsedPublicKey::new(&ED25519, responder_ik.as_slice())
        .verify(&transcript, &signature)
        .map_err(|_| "handshake accept signature verification failed".into())
}

fn sign_message(
    identity_pkcs8_b64u: &str,
    message: &[u8],
) -> Result<ring::signature::Signature, Box<dyn Error>> {
    let pkcs8 = decode_b64u(identity_pkcs8_b64u)?;
    let keypair = Ed25519KeyPair::from_pkcs8(&pkcs8)
        .map_err(|_| "failed to decode identity key for signing")?;
    Ok(keypair.sign(message))
}

fn signed_prekey_transcript_bytes(spk_public: &[u8; 32], spk_id: u32, exp_unix: u64) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(spk_public.len() + 4 + 8);
    transcript.extend_from_slice(spk_public);
    transcript.extend_from_slice(&spk_id.to_be_bytes());
    transcript.extend_from_slice(&exp_unix.to_be_bytes());
    transcript
}

fn handshake_init_transcript_bytes(
    session_id: Uuid,
    hs_id: Uuid,
    sender_eph: &[u8; 32],
    peer_spk_id: u32,
    peer_opk_id: Option<u32>,
    ts_unix: u64,
) -> Vec<u8> {
    let mut transcript =
        Vec::with_capacity(16 + 16 + 32 + 4 + 1 + 4 + 8 + HANDSHAKE_INIT_SIG_CONTEXT.len());
    transcript.extend_from_slice(HANDSHAKE_INIT_SIG_CONTEXT);
    transcript.extend_from_slice(session_id.as_bytes());
    transcript.extend_from_slice(hs_id.as_bytes());
    transcript.extend_from_slice(sender_eph);
    transcript.extend_from_slice(&peer_spk_id.to_be_bytes());
    match peer_opk_id {
        Some(opk_id) => {
            transcript.push(1);
            transcript.extend_from_slice(&opk_id.to_be_bytes());
        }
        None => {
            transcript.push(0);
            transcript.extend_from_slice(&0_u32.to_be_bytes());
        }
    }
    transcript.extend_from_slice(&ts_unix.to_be_bytes());
    transcript
}

fn handshake_accept_transcript_bytes(
    session_id: Uuid,
    hs_id: Uuid,
    responder_eph: &[u8; 32],
    kc: &[u8; 16],
) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(16 + 16 + 32 + 16 + HANDSHAKE_ACCEPT_SIG_CONTEXT.len());
    transcript.extend_from_slice(HANDSHAKE_ACCEPT_SIG_CONTEXT);
    transcript.extend_from_slice(session_id.as_bytes());
    transcript.extend_from_slice(hs_id.as_bytes());
    transcript.extend_from_slice(responder_eph);
    transcript.extend_from_slice(kc);
    transcript
}

fn derive_handshake_secret(session_id: Uuid, hs_id: Uuid, parts: &[Vec<u8>]) -> [u8; 32] {
    let mut material = Vec::with_capacity(64 + parts.iter().map(|part| part.len()).sum::<usize>());
    material.extend_from_slice(HANDSHAKE_SECRET_CONTEXT);
    material.extend_from_slice(session_id.as_bytes());
    material.extend_from_slice(hs_id.as_bytes());
    for part in parts {
        material.extend_from_slice(&(part.len() as u16).to_be_bytes());
        material.extend_from_slice(part);
    }

    let digest = digest(&SHA256, &material);
    let mut out = [0_u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

fn derive_key_confirmation_tag(root_key: &[u8; 32]) -> [u8; 16] {
    let mut material = Vec::with_capacity(HANDSHAKE_KC_CONTEXT.len() + root_key.len());
    material.extend_from_slice(HANDSHAKE_KC_CONTEXT);
    material.extend_from_slice(root_key);
    let digest = digest(&SHA256, &material);
    let mut out = [0_u8; 16];
    out.copy_from_slice(&digest.as_ref()[..16]);
    out
}

fn x25519_shared_secret(private: [u8; 32], peer_public: [u8; 32]) -> Vec<u8> {
    let private = StaticSecret::from(private);
    let peer_public = X25519PublicKey::from(peer_public);
    private.diffie_hellman(&peer_public).as_bytes().to_vec()
}

fn decode_b64u_fixed_32(value: &str) -> Result<[u8; 32], Box<dyn Error>> {
    let bytes = decode_b64u(value)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| "expected 32-byte base64url value".into())
}

fn decode_b64u_fixed_16(value: &str) -> Result<[u8; 16], Box<dyn Error>> {
    let bytes = decode_b64u(value)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| "expected 16-byte base64url value".into())
}

fn is_timestamp_within_skew(ts_unix: u64, skew_secs: u64) -> bool {
    let now = now_unix();
    let lower = now.saturating_sub(skew_secs);
    let upper = now.saturating_add(skew_secs);
    (lower..=upper).contains(&ts_unix)
}
