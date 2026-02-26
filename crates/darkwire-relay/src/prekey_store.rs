use std::collections::{HashMap, VecDeque};
use uuid::Uuid;

pub type ConnId = Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpkRecord {
    pub id: u32,
    pub x25519: String,
    pub sig_ed25519: String,
    pub exp_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpkRecord {
    pub id: u32,
    pub x25519: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicBundleRecord {
    pub ik_ed25519: String,
    pub spk: SpkRecord,
    pub opks: VecDeque<OpkRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerBundleSnapshot {
    pub ik_ed25519: String,
    pub spk: SpkRecord,
    pub opk: Option<OpkRecord>,
}

#[derive(Debug, Default)]
pub struct PrekeyStore {
    by_conn: HashMap<ConnId, PublicBundleRecord>,
}

impl PrekeyStore {
    pub fn new() -> Self {
        Self {
            by_conn: HashMap::new(),
        }
    }

    pub fn upsert_bundle(
        &mut self,
        conn_id: ConnId,
        ik_ed25519: String,
        spk: SpkRecord,
        opks: Vec<OpkRecord>,
    ) -> u32 {
        let opk_count = opks.len() as u32;
        let record = PublicBundleRecord {
            ik_ed25519,
            spk,
            opks: VecDeque::from(opks),
        };
        self.by_conn.insert(conn_id, record);
        opk_count
    }

    pub fn take_peer_bundle(&mut self, conn_id: ConnId) -> Option<PeerBundleSnapshot> {
        let record = self.by_conn.get_mut(&conn_id)?;
        let opk = record.opks.pop_front();

        Some(PeerBundleSnapshot {
            ik_ed25519: record.ik_ed25519.clone(),
            spk: record.spk.clone(),
            opk,
        })
    }

    pub fn identity_key_for_conn(&self, conn_id: ConnId) -> Option<&str> {
        self.by_conn
            .get(&conn_id)
            .map(|record| record.ik_ed25519.as_str())
    }

    pub fn remove_bundle(&mut self, conn_id: ConnId) -> bool {
        self.by_conn.remove(&conn_id).is_some()
    }

    #[cfg(test)]
    pub fn opk_count_for_conn(&self, conn_id: ConnId) -> Option<usize> {
        self.by_conn.get(&conn_id).map(|record| record.opks.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_spk() -> SpkRecord {
        SpkRecord {
            id: 7,
            x25519: "spk_x25519_b64u".to_string(),
            sig_ed25519: "spk_sig_b64u".to_string(),
            exp_unix: 1_770_000_000,
        }
    }

    fn sample_opk(id: u32) -> OpkRecord {
        OpkRecord {
            id,
            x25519: format!("opk_{id}_b64u"),
        }
    }

    #[test]
    fn upsert_replaces_existing_bundle() {
        let mut store = PrekeyStore::new();
        let conn_id = Uuid::new_v4();

        let first_count = store.upsert_bundle(
            conn_id,
            "ik_a".to_string(),
            sample_spk(),
            vec![sample_opk(1), sample_opk(2)],
        );
        assert_eq!(first_count, 2);

        let second_count = store.upsert_bundle(
            conn_id,
            "ik_b".to_string(),
            sample_spk(),
            vec![sample_opk(9)],
        );
        assert_eq!(second_count, 1);
        assert_eq!(store.opk_count_for_conn(conn_id), Some(1));
    }

    #[test]
    fn take_peer_bundle_consumes_single_opk_per_call() {
        let mut store = PrekeyStore::new();
        let conn_id = Uuid::new_v4();

        store.upsert_bundle(
            conn_id,
            "ik_a".to_string(),
            sample_spk(),
            vec![sample_opk(10), sample_opk(11)],
        );

        let first = store
            .take_peer_bundle(conn_id)
            .expect("bundle should exist");
        assert_eq!(first.opk.expect("first opk").id, 10);

        let second = store
            .take_peer_bundle(conn_id)
            .expect("bundle should still exist");
        assert_eq!(second.opk.expect("second opk").id, 11);

        let third = store
            .take_peer_bundle(conn_id)
            .expect("bundle remains with depleted opks");
        assert!(third.opk.is_none());
    }

    #[test]
    fn remove_bundle_cleans_peer_material() {
        let mut store = PrekeyStore::new();
        let conn_id = Uuid::new_v4();

        store.upsert_bundle(conn_id, "ik_a".to_string(), sample_spk(), vec![]);
        assert!(store.remove_bundle(conn_id));
        assert!(store.take_peer_bundle(conn_id).is_none());
    }
}
