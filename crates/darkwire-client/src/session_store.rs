use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    error::Error,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const SESSION_STORE_VERSION: u32 = 1;
const DEFAULT_SESSION_FILE: &str = "sessions.json";

#[derive(Debug, Clone)]
pub struct StoredSession {
    pub peer_ik_ed25519: String,
    pub root_key_b64u: String,
    pub send_n: u64,
    pub recv_n: u64,
    pub updated_unix: u64,
}

#[derive(Debug, Clone)]
pub struct SessionStore {
    session_file: PathBuf,
    store: SessionStoreFile,
}

impl SessionStore {
    pub fn load_or_init(
        session_file: PathBuf,
        local_ik_ed25519: &str,
    ) -> Result<Self, Box<dyn Error>> {
        ensure_parent_dir(&session_file)?;

        let mut manager = if session_file.exists() {
            match fs::read_to_string(&session_file)
                .ok()
                .and_then(|raw| serde_json::from_str::<SessionStoreFile>(&raw).ok())
            {
                Some(store) => Self {
                    session_file,
                    store,
                },
                None => Self {
                    session_file,
                    store: SessionStoreFile::new(local_ik_ed25519.to_string(), now_unix()),
                },
            }
        } else {
            Self {
                session_file,
                store: SessionStoreFile::new(local_ik_ed25519.to_string(), now_unix()),
            }
        };

        manager.enforce_invariants(local_ik_ed25519)?;
        manager.persist()?;
        Ok(manager)
    }

    pub fn session_file(&self) -> &Path {
        &self.session_file
    }

    pub fn session_count(&self) -> usize {
        self.store.sessions_by_peer_ik.len()
    }

    pub fn load_peer(&self, peer_ik_ed25519: &str) -> Option<StoredSession> {
        self.store
            .sessions_by_peer_ik
            .get(peer_ik_ed25519)
            .map(SessionRecord::to_public)
    }

    pub fn list(&self) -> Vec<StoredSession> {
        let mut sessions = self
            .store
            .sessions_by_peer_ik
            .values()
            .map(SessionRecord::to_public)
            .collect::<Vec<_>>();
        sessions.sort_by(|a, b| b.updated_unix.cmp(&a.updated_unix));
        sessions
    }

    pub fn upsert(
        &mut self,
        peer_ik_ed25519: &str,
        root_key_b64u: &str,
        send_n: u64,
        recv_n: u64,
        established_unix: u64,
    ) -> Result<(), Box<dyn Error>> {
        let now = now_unix();
        let record = SessionRecord {
            peer_ik_ed25519: peer_ik_ed25519.to_string(),
            root_key_b64u: root_key_b64u.to_string(),
            send_n,
            recv_n,
            established_unix,
            updated_unix: now,
        };

        self.store
            .sessions_by_peer_ik
            .insert(peer_ik_ed25519.to_string(), record);
        self.store.updated_unix = now;
        self.persist()
    }

    pub fn update_counters(
        &mut self,
        peer_ik_ed25519: &str,
        send_n: u64,
        recv_n: u64,
    ) -> Result<(), Box<dyn Error>> {
        let Some(record) = self.store.sessions_by_peer_ik.get_mut(peer_ik_ed25519) else {
            return Ok(());
        };

        record.send_n = send_n;
        record.recv_n = recv_n;
        record.updated_unix = now_unix();
        self.store.updated_unix = record.updated_unix;
        self.persist()
    }

    #[allow(dead_code)]
    pub fn remove_peer(&mut self, peer_ik_ed25519: &str) -> Result<(), Box<dyn Error>> {
        if self
            .store
            .sessions_by_peer_ik
            .remove(peer_ik_ed25519)
            .is_some()
        {
            self.store.updated_unix = now_unix();
            self.persist()?;
        }

        Ok(())
    }

    pub fn reset_for_local_identity(
        &mut self,
        local_ik_ed25519: &str,
    ) -> Result<(), Box<dyn Error>> {
        self.store.local_ik_ed25519 = local_ik_ed25519.to_string();
        self.store.sessions_by_peer_ik.clear();
        self.store.updated_unix = now_unix();
        self.persist()
    }

    fn enforce_invariants(&mut self, local_ik_ed25519: &str) -> Result<(), Box<dyn Error>> {
        if self.store.version != SESSION_STORE_VERSION {
            self.store = SessionStoreFile::new(local_ik_ed25519.to_string(), now_unix());
            return Ok(());
        }

        if self.store.local_ik_ed25519 != local_ik_ed25519 {
            self.store.local_ik_ed25519 = local_ik_ed25519.to_string();
            self.store.sessions_by_peer_ik.clear();
            self.store.updated_unix = now_unix();
        }

        Ok(())
    }

    fn persist(&self) -> Result<(), Box<dyn Error>> {
        write_session_store_file(&self.session_file, &self.store)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionStoreFile {
    version: u32,
    created_unix: u64,
    updated_unix: u64,
    local_ik_ed25519: String,
    sessions_by_peer_ik: BTreeMap<String, SessionRecord>,
}

impl SessionStoreFile {
    fn new(local_ik_ed25519: String, now_unix: u64) -> Self {
        Self {
            version: SESSION_STORE_VERSION,
            created_unix: now_unix,
            updated_unix: now_unix,
            local_ik_ed25519,
            sessions_by_peer_ik: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionRecord {
    peer_ik_ed25519: String,
    root_key_b64u: String,
    send_n: u64,
    recv_n: u64,
    established_unix: u64,
    updated_unix: u64,
}

impl SessionRecord {
    fn to_public(&self) -> StoredSession {
        StoredSession {
            peer_ik_ed25519: self.peer_ik_ed25519.clone(),
            root_key_b64u: self.root_key_b64u.clone(),
            send_n: self.send_n,
            recv_n: self.recv_n,
            updated_unix: self.updated_unix,
        }
    }
}

pub fn default_session_store_path(key_file: &Path) -> PathBuf {
    key_file
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(DEFAULT_SESSION_FILE)
}

fn ensure_parent_dir(path: &Path) -> Result<(), Box<dyn Error>> {
    let Some(parent) = path.parent() else {
        return Err("session store path has no parent directory".into());
    };

    fs::create_dir_all(parent)?;
    secure_dir_permissions(parent)?;
    Ok(())
}

fn write_session_store_file(path: &Path, store: &SessionStoreFile) -> Result<(), Box<dyn Error>> {
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

    fn temp_session_file() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = env::temp_dir().join(format!(
            "darkwire-session-store-test-{}-{}",
            process::id(),
            nanos
        ));
        dir.join("sessions.json")
    }

    fn peer_ik(seed: u8) -> String {
        format!("peer-{seed}")
    }

    #[test]
    fn upsert_roundtrip_and_counter_update() {
        let session_file = temp_session_file();
        let mut store = SessionStore::load_or_init(session_file.clone(), "local-ik")
            .expect("session store init should pass");

        store
            .upsert(&peer_ik(1), "rk-1", 3, 2, 100)
            .expect("upsert should pass");
        let loaded = store
            .load_peer(&peer_ik(1))
            .expect("stored peer session should exist");
        assert_eq!(loaded.root_key_b64u, "rk-1");
        assert_eq!(loaded.send_n, 3);
        assert_eq!(loaded.recv_n, 2);

        store
            .update_counters(&peer_ik(1), 7, 6)
            .expect("counter update should pass");
        let updated = store
            .load_peer(&peer_ik(1))
            .expect("stored peer session should exist");
        assert_eq!(updated.send_n, 7);
        assert_eq!(updated.recv_n, 6);

        let _ = fs::remove_dir_all(
            session_file
                .parent()
                .expect("temp session file should have a parent"),
        );
    }

    #[test]
    fn identity_change_clears_sessions() {
        let session_file = temp_session_file();
        let mut store = SessionStore::load_or_init(session_file.clone(), "local-ik-a")
            .expect("session store init should pass");
        store
            .upsert(&peer_ik(2), "rk-2", 1, 1, 100)
            .expect("upsert should pass");
        assert_eq!(store.session_count(), 1);

        let reloaded = SessionStore::load_or_init(session_file.clone(), "local-ik-b")
            .expect("reload should pass");
        assert_eq!(reloaded.session_count(), 0);

        let _ = fs::remove_dir_all(
            session_file
                .parent()
                .expect("temp session file should have a parent"),
        );
    }

    #[test]
    fn corrupted_json_recovers_with_empty_store() {
        let session_file = temp_session_file();
        let parent = session_file
            .parent()
            .expect("temp session file should have a parent");
        fs::create_dir_all(parent).expect("create temp dir");
        fs::write(&session_file, "{broken-json").expect("write corrupted store");

        let store = SessionStore::load_or_init(session_file.clone(), "local-ik")
            .expect("corrupted session store should recover");
        assert_eq!(store.session_count(), 0);

        let raw = fs::read_to_string(&session_file).expect("repaired store should be persisted");
        let persisted: serde_json::Value =
            serde_json::from_str(&raw).expect("repaired store must be valid json");
        assert_eq!(
            persisted
                .get("local_ik_ed25519")
                .and_then(serde_json::Value::as_str),
            Some("local-ik")
        );

        let _ = fs::remove_dir_all(parent);
    }

    #[test]
    fn unsupported_version_resets_store() {
        let session_file = temp_session_file();
        let mut store = SessionStore::load_or_init(session_file.clone(), "local-ik")
            .expect("session store init should pass");
        store
            .upsert(&peer_ik(7), "rk-7", 1, 1, 100)
            .expect("upsert should pass");
        assert_eq!(store.session_count(), 1);

        let mut json: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&session_file).expect("session store should exist"),
        )
        .expect("session store json should parse");
        json["version"] = serde_json::json!(999);
        fs::write(
            &session_file,
            serde_json::to_string(&json).expect("serialize mutated json"),
        )
        .expect("write mutated store");

        let reloaded = SessionStore::load_or_init(session_file.clone(), "local-ik")
            .expect("unsupported version should reset");
        assert_eq!(reloaded.session_count(), 0);

        let _ = fs::remove_dir_all(
            session_file
                .parent()
                .expect("temp session file should have a parent"),
        );
    }
}
