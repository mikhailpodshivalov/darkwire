use darkwire_protocol::invite::InvitePayloadV1;
use std::{collections::HashMap, time::Instant};
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct InviteRecord {
    pub token: String,
    pub creator_conn: Uuid,
    pub relay_urls: Vec<String>,
    pub ttl_seconds: u32,
    pub one_time: bool,
    pub used: bool,
    pub expires_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteConsumeResult {
    pub creator_conn: Uuid,
    pub token: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InviteConsumeError {
    NotFound,
    Expired,
    Used,
    PayloadMismatch,
}

#[derive(Debug, Default)]
pub struct InviteStore {
    invites: RwLock<HashMap<String, InviteRecord>>,
}

impl InviteStore {
    pub fn new() -> Self {
        Self {
            invites: RwLock::new(HashMap::new()),
        }
    }

    pub async fn contains_token(&self, token: &str) -> bool {
        self.invites.read().await.contains_key(token)
    }

    pub async fn insert(&self, record: InviteRecord) {
        let now = Instant::now();
        let mut invites = self.invites.write().await;
        prune_expired_locked(&mut invites, now);
        invites.insert(record.token.clone(), record);
    }

    pub async fn consume(
        &self,
        payload: &InvitePayloadV1,
    ) -> Result<InviteConsumeResult, InviteConsumeError> {
        self.consume_at(payload, Instant::now()).await
    }

    pub async fn consume_at(
        &self,
        payload: &InvitePayloadV1,
        now: Instant,
    ) -> Result<InviteConsumeResult, InviteConsumeError> {
        let mut invites = self.invites.write().await;

        let Some(record) = invites.get_mut(&payload.c) else {
            prune_expired_locked(&mut invites, now);
            return Err(InviteConsumeError::NotFound);
        };

        if record.expires_at <= now {
            invites.remove(&payload.c);
            return Err(InviteConsumeError::Expired);
        }

        if record.relay_urls != payload.r
            || record.one_time != payload.o
            || record.ttl_seconds != payload.e
        {
            return Err(InviteConsumeError::PayloadMismatch);
        }

        if record.one_time && record.used {
            return Err(InviteConsumeError::Used);
        }

        if record.one_time {
            record.used = true;
        }

        Ok(InviteConsumeResult {
            creator_conn: record.creator_conn,
            token: record.token.clone(),
        })
    }

    pub async fn rollback_use(&self, token: &str) {
        let mut invites = self.invites.write().await;
        if let Some(record) = invites.get_mut(token) {
            if record.one_time {
                record.used = false;
            }
        }
    }

    #[cfg(test)]
    pub async fn invite_count(&self) -> usize {
        self.invites.read().await.len()
    }
}

fn prune_expired_locked(invites: &mut HashMap<String, InviteRecord>, now: Instant) {
    invites.retain(|_, record| record.expires_at > now);
}

#[cfg(test)]
mod tests {
    use super::*;
    use darkwire_protocol::invite::INVITE_VERSION;
    use std::time::Duration;

    fn payload(token: &str) -> InvitePayloadV1 {
        InvitePayloadV1 {
            v: INVITE_VERSION,
            r: vec!["ws://127.0.0.1:7000".to_string()],
            c: token.to_string(),
            e: 600,
            o: true,
            k: None,
        }
    }

    fn record(token: &str, now: Instant) -> InviteRecord {
        InviteRecord {
            token: token.to_string(),
            creator_conn: Uuid::new_v4(),
            relay_urls: vec!["ws://127.0.0.1:7000".to_string()],
            ttl_seconds: 600,
            one_time: true,
            used: false,
            expires_at: now + Duration::from_secs(600),
        }
    }

    #[tokio::test]
    async fn one_time_invite_can_be_consumed_only_once() {
        let store = InviteStore::new();
        let now = Instant::now();
        let token = "ABCDEFGHJKLMNPQR";

        store.insert(record(token, now)).await;

        let first = store
            .consume_at(&payload(token), now + Duration::from_secs(1))
            .await
            .expect("first consume should pass");
        assert_eq!(first.token, token);

        let second = store
            .consume_at(&payload(token), now + Duration::from_secs(2))
            .await
            .expect_err("second consume must fail");
        assert_eq!(second, InviteConsumeError::Used);
    }

    #[tokio::test]
    async fn expired_invite_is_rejected_and_removed() {
        let store = InviteStore::new();
        let now = Instant::now();
        let token = "BCDEFGHJKLMNPQRS";
        let mut rec = record(token, now);
        rec.expires_at = now + Duration::from_secs(1);

        store.insert(rec).await;

        let err = store
            .consume_at(&payload(token), now + Duration::from_secs(2))
            .await
            .expect_err("expired invite should fail");
        assert_eq!(err, InviteConsumeError::Expired);
        assert_eq!(store.invite_count().await, 0);
    }

    #[tokio::test]
    async fn payload_mismatch_is_rejected() {
        let store = InviteStore::new();
        let now = Instant::now();
        let token = "CDEFGHJKLMNPQRST";
        store.insert(record(token, now)).await;

        let mut altered = payload(token);
        altered.r = vec!["ws://example.com:7000".to_string()];

        let err = store
            .consume_at(&altered, now + Duration::from_secs(1))
            .await
            .expect_err("mismatched payload should fail");
        assert_eq!(err, InviteConsumeError::PayloadMismatch);
    }
}
