mod handshake;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use darkwire_protocol::events::{OneTimePrekey, PrekeyPublishRequest, SignedPrekey};
use ring::{
    digest::{digest, SHA256},
    rand::{SecureRandom, SystemRandom},
    signature::{Ed25519KeyPair, KeyPair},
};
use serde::{Deserialize, Serialize};
use std::{
    env,
    error::Error,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

const KEYSTORE_VERSION: u32 = 1;
const SIGNED_PREKEY_TTL_SECS: u64 = 7 * 24 * 60 * 60;
const TARGET_OPK_COUNT: usize = 64;
const LOW_WATERMARK_OPK_COUNT: usize = 8;
const DEFAULT_KEY_SUBDIR: &str = ".darkwire";
const DEFAULT_KEY_FILE: &str = "keys.json";

#[derive(Debug, Clone)]
pub struct KeyStatus {
    pub fingerprint_short: String,
    pub identity_key_short: String,
    pub signed_prekey_id: u32,
    pub signed_prekey_expires_unix: u64,
    pub one_time_prekeys: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeRole {
    Initiator,
    Responder,
}

#[derive(Debug, Clone)]
pub struct InitiatorHandshakeContext {
    pub session_id: Uuid,
    pub hs_id: Uuid,
    pub started_unix: u64,
    peer_ik_ed25519: String,
    initiator_eph_private_x25519_b64u: String,
    peer_spk_x25519_b64u: String,
    peer_opk_x25519_b64u: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SecureSessionMaterial {
    pub session_id: Uuid,
    pub hs_id: Uuid,
    pub peer_ik_ed25519: String,
    pub role: HandshakeRole,
    pub established_unix: u64,
    pub root_key_b64u: String,
}

#[derive(Debug, Clone)]
pub struct KeyManager {
    key_file: PathBuf,
    store: KeyStoreFile,
}

impl KeyManager {
    pub fn load_or_init(key_file: PathBuf) -> Result<Self, Box<dyn Error>> {
        ensure_parent_dir(&key_file)?;

        let mut manager = if key_file.exists() {
            let raw = fs::read_to_string(&key_file)?;
            let store: KeyStoreFile = serde_json::from_str(&raw)?;
            Self { key_file, store }
        } else {
            Self {
                key_file,
                store: KeyStoreFile::new(generate_identity()?, now_unix())?,
            }
        };

        manager.enforce_runtime_invariants()?;
        manager.persist()?;
        Ok(manager)
    }

    pub fn key_file(&self) -> &Path {
        &self.key_file
    }

    pub fn status(&self) -> KeyStatus {
        let identity_pub_bytes = decode_b64u(&self.store.identity.public_ed25519_b64u);
        let fingerprint = identity_pub_bytes
            .ok()
            .map(|bytes| short_fingerprint(&bytes))
            .unwrap_or_else(|| "unknown".to_string());

        KeyStatus {
            fingerprint_short: fingerprint,
            identity_key_short: shorten_b64u(&self.store.identity.public_ed25519_b64u),
            signed_prekey_id: self.store.signed_prekey.id,
            signed_prekey_expires_unix: self.store.signed_prekey.exp_unix,
            one_time_prekeys: self.store.one_time_prekeys.len(),
        }
    }

    pub fn status_line(&self) -> String {
        let status = self.status();
        format!(
            "fp={} ik={} spk_id={} spk_exp={} opk_available={}",
            status.fingerprint_short,
            status.identity_key_short,
            status.signed_prekey_id,
            status.signed_prekey_expires_unix,
            status.one_time_prekeys
        )
    }

    pub fn build_prekey_publish_request(&self) -> PrekeyPublishRequest {
        PrekeyPublishRequest {
            ik_ed25519: self.store.identity.public_ed25519_b64u.clone(),
            spk: SignedPrekey {
                id: self.store.signed_prekey.id,
                x25519: self.store.signed_prekey.public_x25519_b64u.clone(),
                sig_ed25519: self.store.signed_prekey.signature_ed25519_b64u.clone(),
                exp_unix: self.store.signed_prekey.exp_unix,
            },
            opks: self
                .store
                .one_time_prekeys
                .iter()
                .map(|opk| OneTimePrekey {
                    id: opk.id,
                    x25519: opk.public_x25519_b64u.clone(),
                })
                .collect(),
        }
    }

    pub fn rotate_signed_prekey(&mut self) -> Result<(), Box<dyn Error>> {
        let now = now_unix();
        self.store.rotate_signed_prekey(now)?;
        self.store.updated_unix = now;
        self.persist()?;
        Ok(())
    }

    pub fn refill_one_time_prekeys(&mut self) -> Result<usize, Box<dyn Error>> {
        let now = now_unix();
        let before = self.store.one_time_prekeys.len();
        self.store.refill_opks_to_target(now)?;
        let added = self.store.one_time_prekeys.len().saturating_sub(before);
        if added > 0 {
            self.store.updated_unix = now;
            self.persist()?;
        }
        Ok(added)
    }

    pub fn revoke_and_regenerate(&mut self) -> Result<(), Box<dyn Error>> {
        let now = now_unix();
        let identity = generate_identity()?;
        self.store = KeyStoreFile::new(identity, now)?;
        self.persist()?;
        Ok(())
    }

    fn enforce_runtime_invariants(&mut self) -> Result<(), Box<dyn Error>> {
        if self.store.version != KEYSTORE_VERSION {
            return Err(format!("unsupported keystore version: {}", self.store.version).into());
        }

        let now = now_unix();
        let mut changed = false;
        if self.store.signed_prekey.exp_unix <= now {
            self.store.rotate_signed_prekey(now)?;
            changed = true;
        }

        if self.store.one_time_prekeys.len() < LOW_WATERMARK_OPK_COUNT {
            self.store.refill_opks_to_target(now)?;
            changed = true;
        }

        if changed {
            self.store.updated_unix = now;
        }

        Ok(())
    }

    fn persist(&self) -> Result<(), Box<dyn Error>> {
        write_keystore_file(&self.key_file, &self.store)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyStoreFile {
    version: u32,
    created_unix: u64,
    updated_unix: u64,
    next_signed_prekey_id: u32,
    next_one_time_prekey_id: u32,
    identity: IdentityRecord,
    signed_prekey: SignedPrekeyRecord,
    one_time_prekeys: Vec<OneTimePrekeyRecord>,
}

impl KeyStoreFile {
    fn new(identity: IdentityRecord, now: u64) -> Result<Self, Box<dyn Error>> {
        let mut file = Self {
            version: KEYSTORE_VERSION,
            created_unix: now,
            updated_unix: now,
            next_signed_prekey_id: 1,
            next_one_time_prekey_id: 1,
            identity,
            signed_prekey: SignedPrekeyRecord::placeholder(),
            one_time_prekeys: Vec::new(),
        };

        file.rotate_signed_prekey(now)?;
        file.refill_opks_to_target(now)?;
        Ok(file)
    }

    fn rotate_signed_prekey(&mut self, now: u64) -> Result<(), Box<dyn Error>> {
        let id = self.next_signed_prekey_id;
        self.next_signed_prekey_id = self.next_signed_prekey_id.saturating_add(1);

        let (private_x25519_b64u, public_x25519_b64u) = generate_x25519_keypair()?;
        let exp_unix = now.saturating_add(SIGNED_PREKEY_TTL_SECS);
        let signature = sign_spk(
            &self.identity.pkcs8_ed25519_b64u,
            &public_x25519_b64u,
            id,
            exp_unix,
        )?;

        self.signed_prekey = SignedPrekeyRecord {
            id,
            private_x25519_b64u,
            public_x25519_b64u,
            signature_ed25519_b64u: signature,
            generated_unix: now,
            exp_unix,
        };

        Ok(())
    }

    fn refill_opks_to_target(&mut self, now: u64) -> Result<(), Box<dyn Error>> {
        if self.one_time_prekeys.len() >= TARGET_OPK_COUNT {
            return Ok(());
        }

        let missing = TARGET_OPK_COUNT - self.one_time_prekeys.len();
        for _ in 0..missing {
            let id = self.next_one_time_prekey_id;
            self.next_one_time_prekey_id = self.next_one_time_prekey_id.saturating_add(1);

            let (private_x25519_b64u, public_x25519_b64u) = generate_x25519_keypair()?;
            self.one_time_prekeys.push(OneTimePrekeyRecord {
                id,
                private_x25519_b64u,
                public_x25519_b64u,
                generated_unix: now,
            });
        }

        Ok(())
    }

    fn take_one_time_prekey(&mut self, id: u32) -> Option<OneTimePrekeyRecord> {
        let index = self.one_time_prekeys.iter().position(|opk| opk.id == id)?;
        Some(self.one_time_prekeys.remove(index))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IdentityRecord {
    pkcs8_ed25519_b64u: String,
    public_ed25519_b64u: String,
    generated_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedPrekeyRecord {
    id: u32,
    private_x25519_b64u: String,
    public_x25519_b64u: String,
    signature_ed25519_b64u: String,
    generated_unix: u64,
    exp_unix: u64,
}

impl SignedPrekeyRecord {
    fn placeholder() -> Self {
        Self {
            id: 0,
            private_x25519_b64u: String::new(),
            public_x25519_b64u: String::new(),
            signature_ed25519_b64u: String::new(),
            generated_unix: 0,
            exp_unix: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OneTimePrekeyRecord {
    id: u32,
    private_x25519_b64u: String,
    public_x25519_b64u: String,
    generated_unix: u64,
}

pub fn default_key_file_path() -> PathBuf {
    let base = env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("USERPROFILE").map(PathBuf::from))
        .unwrap_or_else(|| env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    base.join(DEFAULT_KEY_SUBDIR).join(DEFAULT_KEY_FILE)
}

fn generate_identity() -> Result<IdentityRecord, Box<dyn Error>> {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|_| "failed to generate ed25519 pkcs8 identity key")?;
    let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .map_err(|_| "failed to decode generated ed25519 identity key")?;

    Ok(IdentityRecord {
        pkcs8_ed25519_b64u: encode_b64u(pkcs8.as_ref()),
        public_ed25519_b64u: encode_b64u(keypair.public_key().as_ref()),
        generated_unix: now_unix(),
    })
}

fn generate_x25519_keypair() -> Result<(String, String), Box<dyn Error>> {
    let mut private_bytes = [0_u8; 32];
    SystemRandom::new()
        .fill(&mut private_bytes)
        .map_err(|_| "failed to generate x25519 private key bytes")?;

    let private = StaticSecret::from(private_bytes);
    let public = X25519PublicKey::from(&private);

    Ok((
        encode_b64u(&private.to_bytes()),
        encode_b64u(public.as_bytes()),
    ))
}

fn sign_spk(
    identity_pkcs8_b64u: &str,
    spk_public_x25519_b64u: &str,
    spk_id: u32,
    exp_unix: u64,
) -> Result<String, Box<dyn Error>> {
    let pkcs8 = decode_b64u(identity_pkcs8_b64u)?;
    let spk_public = decode_b64u(spk_public_x25519_b64u)?;

    let keypair = Ed25519KeyPair::from_pkcs8(&pkcs8)
        .map_err(|_| "failed to decode identity key for prekey signing")?;

    let mut transcript = Vec::with_capacity(spk_public.len() + 4 + 8);
    transcript.extend_from_slice(&spk_public);
    transcript.extend_from_slice(&spk_id.to_be_bytes());
    transcript.extend_from_slice(&exp_unix.to_be_bytes());

    let signature = keypair.sign(&transcript);
    Ok(encode_b64u(signature.as_ref()))
}

fn ensure_parent_dir(path: &Path) -> Result<(), Box<dyn Error>> {
    let Some(parent) = path.parent() else {
        return Err("key file path has no parent directory".into());
    };

    fs::create_dir_all(parent)?;
    secure_dir_permissions(parent)?;
    Ok(())
}

fn write_keystore_file(path: &Path, store: &KeyStoreFile) -> Result<(), Box<dyn Error>> {
    let raw = serde_json::to_string_pretty(store)?;
    let tmp = path.with_extension("tmp");

    {
        let mut file = open_secure_file_for_write(&tmp)?;
        file.write_all(raw.as_bytes())?;
        file.flush()?;
        file.sync_all()?;
    }

    fs::rename(&tmp, path)?;
    secure_file_permissions(path)?;
    Ok(())
}

fn encode_b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_b64u(value: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|err| format!("invalid base64url payload: {err}").into())
}

fn shorten_b64u(value: &str) -> String {
    if value.len() <= 12 {
        return value.to_string();
    }
    format!("{}...{}", &value[..6], &value[value.len() - 5..])
}

fn short_fingerprint(bytes: &[u8]) -> String {
    let digest = digest(&SHA256, bytes);
    digest
        .as_ref()
        .iter()
        .take(6)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(unix)]
fn open_secure_file_for_write(path: &Path) -> Result<std::fs::File, Box<dyn Error>> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|err| err.into())
}

#[cfg(not(unix))]
fn open_secure_file_for_write(path: &Path) -> Result<std::fs::File, Box<dyn Error>> {
    OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .map_err(|err| err.into())
}

#[cfg(unix)]
fn secure_dir_permissions(path: &Path) -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn secure_dir_permissions(_path: &Path) -> Result<(), Box<dyn Error>> {
    Ok(())
}

#[cfg(unix)]
fn secure_file_permissions(path: &Path) -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn secure_file_permissions(_path: &Path) -> Result<(), Box<dyn Error>> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use darkwire_protocol::events::PublicPrekeyBundle;
    use std::process;

    fn temp_key_file() -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = env::temp_dir().join(format!("darkwire-keys-test-{}-{}", process::id(), nanos));
        dir.join("keys.json")
    }

    #[test]
    fn load_or_init_creates_new_keystore_when_missing() {
        let key_file = temp_key_file();
        let manager = KeyManager::load_or_init(key_file.clone()).expect("key manager should init");

        assert!(key_file.exists());
        assert_eq!(manager.status().one_time_prekeys, TARGET_OPK_COUNT);
        assert!(manager.status().signed_prekey_id >= 1);

        let _ = fs::remove_dir_all(
            key_file
                .parent()
                .expect("temp key file should always have a parent"),
        );
    }

    #[test]
    fn key_lifecycle_rotate_refill_and_revoke() {
        let key_file = temp_key_file();
        let mut manager = KeyManager::load_or_init(key_file.clone()).expect("init should pass");

        let before_rotate = manager.status();
        manager
            .rotate_signed_prekey()
            .expect("rotate signed prekey should pass");
        let after_rotate = manager.status();
        assert!(after_rotate.signed_prekey_id > before_rotate.signed_prekey_id);

        let added = manager
            .refill_one_time_prekeys()
            .expect("refill should pass");
        assert_eq!(added, 0);
        assert_eq!(manager.status().one_time_prekeys, TARGET_OPK_COUNT);

        manager
            .revoke_and_regenerate()
            .expect("revoke+regenerate should pass");
        let after_revoke = manager.status();
        assert_eq!(after_revoke.one_time_prekeys, TARGET_OPK_COUNT);
        assert_ne!(
            after_revoke.fingerprint_short,
            before_rotate.fingerprint_short
        );

        let _ = fs::remove_dir_all(
            key_file
                .parent()
                .expect("temp key file should always have a parent"),
        );
    }

    #[test]
    fn prekey_publish_request_contains_public_material_only() {
        let key_file = temp_key_file();
        let manager = KeyManager::load_or_init(key_file.clone()).expect("init should pass");
        let publish = manager.build_prekey_publish_request();

        assert!(!publish.ik_ed25519.is_empty());
        assert!(publish.spk.id >= 1);
        assert!(!publish.spk.x25519.is_empty());
        assert!(!publish.spk.sig_ed25519.is_empty());
        assert_eq!(publish.opks.len(), TARGET_OPK_COUNT);
        assert!(publish.opks.iter().all(|opk| !opk.x25519.is_empty()));

        let _ = fs::remove_dir_all(
            key_file
                .parent()
                .expect("temp key file should always have a parent"),
        );
    }

    #[test]
    fn initiator_and_responder_derive_same_handshake_root_key() {
        let key_file_a = temp_key_file();
        let key_file_b = temp_key_file();
        let initiator = KeyManager::load_or_init(key_file_a.clone()).expect("init A");
        let mut responder = KeyManager::load_or_init(key_file_b.clone()).expect("init B");

        let session_id = Uuid::new_v4();
        let responder_publish = responder.build_prekey_publish_request();
        let responder_bundle = PublicPrekeyBundle {
            ik_ed25519: responder_publish.ik_ed25519.clone(),
            spk: responder_publish.spk.clone(),
            opk: responder_publish.opks.first().cloned(),
        };

        let responder_opk_before = responder.status().one_time_prekeys;
        let (init_request, context) = initiator
            .start_initiator_handshake(session_id, &responder_bundle)
            .expect("initiator handshake start should pass");
        let (accept_request, responder_material) = responder
            .respond_to_handshake_init(&init_request)
            .expect("responder should accept handshake init");
        let initiator_material = initiator
            .finalize_initiator_handshake(&context, &accept_request)
            .expect("initiator should finalize handshake");

        assert_eq!(initiator_material.session_id, session_id);
        assert_eq!(initiator_material.hs_id, init_request.hs_id);
        assert_eq!(
            initiator_material.root_key_b64u,
            responder_material.root_key_b64u
        );
        assert_eq!(initiator_material.role, HandshakeRole::Initiator);
        assert_eq!(responder_material.role, HandshakeRole::Responder);
        assert_eq!(
            responder.status().one_time_prekeys + 1,
            responder_opk_before,
            "responder should consume exactly one one-time prekey"
        );

        let _ = fs::remove_dir_all(
            key_file_a
                .parent()
                .expect("temp key file should always have a parent"),
        );
        let _ = fs::remove_dir_all(
            key_file_b
                .parent()
                .expect("temp key file should always have a parent"),
        );
    }

    #[test]
    fn start_initiator_handshake_rejects_tampered_signed_prekey_signature() {
        let key_file_a = temp_key_file();
        let key_file_b = temp_key_file();
        let initiator = KeyManager::load_or_init(key_file_a.clone()).expect("init A");
        let responder = KeyManager::load_or_init(key_file_b.clone()).expect("init B");

        let publish = responder.build_prekey_publish_request();
        let mut tampered_bundle = PublicPrekeyBundle {
            ik_ed25519: publish.ik_ed25519.clone(),
            spk: publish.spk.clone(),
            opk: publish.opks.first().cloned(),
        };

        let mut sig_bytes = decode_b64u(&tampered_bundle.spk.sig_ed25519)
            .expect("signature in generated bundle should decode");
        sig_bytes[0] ^= 0x01;
        tampered_bundle.spk.sig_ed25519 = encode_b64u(&sig_bytes);

        let err = initiator
            .start_initiator_handshake(Uuid::new_v4(), &tampered_bundle)
            .expect_err("tampered signed prekey must be rejected");
        assert!(err.to_string().contains("verification failed"));

        let _ = fs::remove_dir_all(
            key_file_a
                .parent()
                .expect("temp key file should always have a parent"),
        );
        let _ = fs::remove_dir_all(
            key_file_b
                .parent()
                .expect("temp key file should always have a parent"),
        );
    }
}
