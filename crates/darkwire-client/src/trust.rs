use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::digest::{digest, SHA256};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    error::Error,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const TRUSTSTORE_VERSION: u32 = 1;
const DEFAULT_TRUST_FILE: &str = "trust.json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionTrustState {
    Verified,
    Unverified,
    KeyChanged,
}

impl SessionTrustState {
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionTrustState::Verified => "verified",
            SessionTrustState::Unverified => "unverified",
            SessionTrustState::KeyChanged => "unverified_key_changed",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ActivePeerTrust {
    pub peer_ik_ed25519: String,
    pub fingerprint_short: String,
    pub safety_number: String,
    pub state: SessionTrustState,
    pub previous_fingerprint_short: Option<String>,
}

#[derive(Debug, Clone)]
pub struct VerifiedContact {
    pub fingerprint_short: String,
    pub safety_number: String,
}

#[derive(Debug, Clone)]
pub struct TrustManager {
    trust_file: PathBuf,
    store: TrustStoreFile,
}

impl TrustManager {
    pub fn load_or_init(trust_file: PathBuf) -> Result<Self, Box<dyn Error>> {
        ensure_parent_dir(&trust_file)?;

        let mut manager = if trust_file.exists() {
            let raw = fs::read_to_string(&trust_file)?;
            let store: TrustStoreFile = serde_json::from_str(&raw)?;
            Self { trust_file, store }
        } else {
            Self {
                trust_file,
                store: TrustStoreFile::new(now_unix()),
            }
        };

        manager.enforce_invariants()?;
        manager.persist()?;
        Ok(manager)
    }

    pub fn trust_file(&self) -> &Path {
        &self.trust_file
    }

    pub fn verified_count(&self) -> usize {
        self.store.verified_peer_ik_ed25519.len()
    }

    pub fn list_verified(&self) -> Vec<VerifiedContact> {
        self.store
            .verified_peer_ik_ed25519
            .iter()
            .map(|ik| VerifiedContact {
                fingerprint_short: fingerprint_short(ik),
                safety_number: safety_number(ik),
            })
            .collect()
    }

    pub fn evaluate_peer(
        &mut self,
        peer_ik_ed25519: &str,
    ) -> Result<ActivePeerTrust, Box<dyn Error>> {
        let previous = self.store.last_seen_peer_ik_ed25519.clone();
        let mut state = if self
            .store
            .verified_peer_ik_ed25519
            .contains(peer_ik_ed25519)
        {
            SessionTrustState::Verified
        } else {
            SessionTrustState::Unverified
        };
        let mut previous_fingerprint_short = None;

        if let Some(previous_ik) = previous {
            if previous_ik != peer_ik_ed25519 {
                state = SessionTrustState::KeyChanged;
                previous_fingerprint_short = Some(fingerprint_short(&previous_ik));
                // Require explicit re-trust after key change.
                self.store.verified_peer_ik_ed25519.remove(peer_ik_ed25519);
            }
        } else if state == SessionTrustState::Unverified {
            // TOFU: first seen identity key is auto-trusted.
            self.store
                .verified_peer_ik_ed25519
                .insert(peer_ik_ed25519.to_string());
            state = SessionTrustState::Verified;
        }

        self.store.last_seen_peer_ik_ed25519 = Some(peer_ik_ed25519.to_string());
        self.store.updated_unix = now_unix();
        self.persist()?;

        Ok(ActivePeerTrust {
            peer_ik_ed25519: peer_ik_ed25519.to_string(),
            fingerprint_short: fingerprint_short(peer_ik_ed25519),
            safety_number: safety_number(peer_ik_ed25519),
            state,
            previous_fingerprint_short,
        })
    }

    pub fn verify_peer(&mut self, peer_ik_ed25519: &str) -> Result<(), Box<dyn Error>> {
        self.store
            .verified_peer_ik_ed25519
            .insert(peer_ik_ed25519.to_string());
        self.store.updated_unix = now_unix();
        self.persist()
    }

    pub fn unverify_peer(&mut self, peer_ik_ed25519: &str) -> Result<(), Box<dyn Error>> {
        self.store.verified_peer_ik_ed25519.remove(peer_ik_ed25519);
        self.store.updated_unix = now_unix();
        self.persist()
    }

    fn enforce_invariants(&mut self) -> Result<(), Box<dyn Error>> {
        if self.store.version != TRUSTSTORE_VERSION {
            return Err(format!("unsupported trust store version: {}", self.store.version).into());
        }
        Ok(())
    }

    fn persist(&self) -> Result<(), Box<dyn Error>> {
        write_truststore_file(&self.trust_file, &self.store)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TrustStoreFile {
    version: u32,
    created_unix: u64,
    updated_unix: u64,
    verified_peer_ik_ed25519: BTreeSet<String>,
    last_seen_peer_ik_ed25519: Option<String>,
}

impl TrustStoreFile {
    fn new(now_unix: u64) -> Self {
        Self {
            version: TRUSTSTORE_VERSION,
            created_unix: now_unix,
            updated_unix: now_unix,
            verified_peer_ik_ed25519: BTreeSet::new(),
            last_seen_peer_ik_ed25519: None,
        }
    }
}

pub fn default_trust_file_path(key_file: &Path) -> PathBuf {
    key_file
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(DEFAULT_TRUST_FILE)
}

pub fn fingerprint_short_for_ik(ik_ed25519_b64u: &str) -> String {
    fingerprint_short(ik_ed25519_b64u)
}

fn fingerprint_short(ik_ed25519_b64u: &str) -> String {
    let source = decode_peer_key(ik_ed25519_b64u);
    let hash = digest(&SHA256, &source);
    hash.as_ref()
        .iter()
        .take(6)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn safety_number(ik_ed25519_b64u: &str) -> String {
    let source = decode_peer_key(ik_ed25519_b64u);
    let hash = digest(&SHA256, &source);
    let mut groups = Vec::with_capacity(4);
    for chunk in hash.as_ref().chunks(2).take(4) {
        let value = u16::from_be_bytes([chunk[0], chunk[1]]);
        groups.push(format!("{value:05}"));
    }
    groups.join("-")
}

fn decode_peer_key(ik_ed25519_b64u: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD
        .decode(ik_ed25519_b64u.as_bytes())
        .unwrap_or_else(|_| ik_ed25519_b64u.as_bytes().to_vec())
}

fn ensure_parent_dir(path: &Path) -> Result<(), Box<dyn Error>> {
    let Some(parent) = path.parent() else {
        return Err("trust file path has no parent directory".into());
    };

    fs::create_dir_all(parent)?;
    secure_dir_permissions(parent)?;
    Ok(())
}

fn write_truststore_file(path: &Path, store: &TrustStoreFile) -> Result<(), Box<dyn Error>> {
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
    use std::{env, process};

    fn temp_trust_file() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = env::temp_dir().join(format!("darkwire-trust-test-{}-{}", process::id(), nanos));
        dir.join("trust.json")
    }

    fn peer_ik(seed: u8) -> String {
        URL_SAFE_NO_PAD.encode([seed; 32])
    }

    #[test]
    fn trust_store_verify_and_list_roundtrip() {
        let trust_file = temp_trust_file();
        let mut trust = TrustManager::load_or_init(trust_file.clone()).expect("init trust store");

        trust.verify_peer(&peer_ik(7)).expect("verify");
        let list = trust.list_verified();
        assert_eq!(list.len(), 1);
        assert!(!list[0].fingerprint_short.is_empty());
        assert!(list[0].safety_number.contains('-'));

        let _ = fs::remove_dir_all(
            trust_file
                .parent()
                .expect("temp trust file should have a parent"),
        );
    }

    #[test]
    fn evaluate_peer_reports_key_change_and_downgrades_to_unverified() {
        let trust_file = temp_trust_file();
        let mut trust = TrustManager::load_or_init(trust_file.clone()).expect("init trust store");
        let first = peer_ik(1);
        let second = peer_ik(2);

        trust.verify_peer(&first).expect("verify first");
        let first_state = trust.evaluate_peer(&first).expect("evaluate first");
        assert_eq!(first_state.state, SessionTrustState::Verified);

        trust.verify_peer(&second).expect("verify second");
        let changed = trust.evaluate_peer(&second).expect("evaluate second");
        assert_eq!(changed.state, SessionTrustState::KeyChanged);
        assert!(changed.previous_fingerprint_short.is_some());

        let after = trust.evaluate_peer(&second).expect("evaluate second again");
        assert_eq!(after.state, SessionTrustState::Unverified);

        let _ = fs::remove_dir_all(
            trust_file
                .parent()
                .expect("temp trust file should have a parent"),
        );
    }

    #[test]
    fn evaluate_peer_first_seen_is_auto_verified_by_tofu() {
        let trust_file = temp_trust_file();
        let mut trust = TrustManager::load_or_init(trust_file.clone()).expect("init trust store");
        let first = peer_ik(9);

        let first_state = trust.evaluate_peer(&first).expect("evaluate first");
        assert_eq!(first_state.state, SessionTrustState::Verified);
        assert_eq!(trust.verified_count(), 1);

        let _ = fs::remove_dir_all(
            trust_file
                .parent()
                .expect("temp trust file should have a parent"),
        );
    }
}
