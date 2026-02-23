use crate::{
    invite_store::{InviteConsumeError, InviteRecord, InviteStore},
    rate_limit::{RateLimitHit, RateLimitStore},
};
use darkwire_protocol::{
    config::LimitsConfig,
    events::{InviteCreateRequest, InviteUseRequest},
    invite::{decode_invite, encode_invite, InvitePayloadV1, INVITE_VERSION, TOKEN_MAX_LEN},
};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;
use uuid::Uuid;

pub type ConnId = Uuid;
pub type SharedState = Arc<AppState>;

const TOKEN_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

#[derive(Debug, Clone)]
pub struct ConnectionRecord {
    pub id: ConnId,
    pub ip: IpAddr,
    pub connected_at: Instant,
    pub last_activity: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteCreated {
    pub invite: String,
    pub expires_in: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteUsed {
    pub creator_conn: ConnId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InviteCreateError {
    RateLimited(RateLimitHit),
    InvalidRequest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InviteUseError {
    RateLimited(RateLimitHit),
    InvalidInvite,
    InviteExpired,
    InviteUsed,
}

#[derive(Debug)]
pub struct AppState {
    limits: LimitsConfig,
    connections: RwLock<HashMap<ConnId, ConnectionRecord>>,
    invites: InviteStore,
    rate_limits: RateLimitStore,
}

impl AppState {
    pub fn new(limits: LimitsConfig) -> Self {
        Self {
            limits,
            connections: RwLock::new(HashMap::new()),
            invites: InviteStore::new(),
            rate_limits: RateLimitStore::new(),
        }
    }

    pub fn limits(&self) -> &LimitsConfig {
        &self.limits
    }

    pub async fn register_connection(&self, ip: IpAddr) -> ConnId {
        let now = Instant::now();
        let id = Uuid::new_v4();
        let record = ConnectionRecord {
            id,
            ip,
            connected_at: now,
            last_activity: now,
        };

        self.connections.write().await.insert(id, record);
        id
    }

    pub async fn touch_connection(&self, id: ConnId) -> bool {
        let mut connections = self.connections.write().await;
        match connections.get_mut(&id) {
            Some(record) => {
                record.last_activity = Instant::now();
                true
            }
            None => false,
        }
    }

    pub async fn get_connection(&self, id: ConnId) -> Option<ConnectionRecord> {
        self.connections.read().await.get(&id).cloned()
    }

    pub async fn unregister_connection(&self, id: ConnId) -> Option<ConnectionRecord> {
        self.connections.write().await.remove(&id)
    }

    pub async fn active_connection_count(&self) -> usize {
        self.connections.read().await.len()
    }

    pub async fn create_invite(
        &self,
        creator_conn: ConnId,
        ip: IpAddr,
        req: InviteCreateRequest,
    ) -> Result<InviteCreated, InviteCreateError> {
        self.rate_limits
            .check_invite_create(ip, &self.limits)
            .await
            .map_err(InviteCreateError::RateLimited)?;

        let token = self.generate_unique_token().await;
        let payload = InvitePayloadV1 {
            v: INVITE_VERSION,
            r: req.r,
            c: token.clone(),
            e: req.e,
            o: req.o,
            k: None,
        };

        let invite = encode_invite(&payload).map_err(|_| InviteCreateError::InvalidRequest)?;
        let now = Instant::now();
        let record = InviteRecord {
            token,
            creator_conn,
            relay_urls: payload.r.clone(),
            ttl_seconds: payload.e,
            one_time: payload.o,
            used: false,
            expires_at: now + Duration::from_secs(u64::from(payload.e)),
        };
        self.invites.insert(record).await;

        Ok(InviteCreated {
            invite,
            expires_in: payload.e,
        })
    }

    pub async fn use_invite(
        &self,
        ip: IpAddr,
        req: InviteUseRequest,
    ) -> Result<InviteUsed, InviteUseError> {
        self.rate_limits
            .check_invite_use(ip, &self.limits)
            .await
            .map_err(InviteUseError::RateLimited)?;

        let payload = match decode_invite(&req.invite) {
            Ok(payload) => payload,
            Err(_) => {
                self.rate_limits
                    .record_invite_use_result(ip, false, &self.limits)
                    .await;
                return Err(InviteUseError::InvalidInvite);
            }
        };

        let consumed = self.invites.consume(&payload).await;

        match consumed {
            Ok(ok) => {
                self.rate_limits
                    .record_invite_use_result(ip, true, &self.limits)
                    .await;
                Ok(InviteUsed {
                    creator_conn: ok.creator_conn,
                })
            }
            Err(err) => {
                self.rate_limits
                    .record_invite_use_result(ip, false, &self.limits)
                    .await;
                Err(map_invite_error(err))
            }
        }
    }

    async fn generate_unique_token(&self) -> String {
        for _ in 0..8 {
            let token = generate_token(TOKEN_MAX_LEN);
            if !self.invites.contains_token(&token).await {
                return token;
            }
        }

        generate_token(TOKEN_MAX_LEN)
    }
}

fn map_invite_error(err: InviteConsumeError) -> InviteUseError {
    match err {
        InviteConsumeError::NotFound | InviteConsumeError::PayloadMismatch => {
            InviteUseError::InvalidInvite
        }
        InviteConsumeError::Expired => InviteUseError::InviteExpired,
        InviteConsumeError::Used => InviteUseError::InviteUsed,
    }
}

fn generate_token(len: usize) -> String {
    let mut value = Uuid::new_v4().as_u128();
    let mut token = String::with_capacity(len);

    for _ in 0..len {
        let idx = (value & 0x1f) as usize;
        token.push(TOKEN_ALPHABET[idx] as char);
        value >>= 5;
    }

    token
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::{IpAddr, Ipv4Addr},
        time::Duration,
    };

    #[tokio::test]
    async fn connection_lifecycle_updates_and_cleans_up() {
        let state = AppState::new(LimitsConfig::default());
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let conn_id = state.register_connection(ip).await;
        assert_eq!(state.active_connection_count().await, 1);

        let before_touch = state
            .get_connection(conn_id)
            .await
            .expect("connection should exist");
        assert_eq!(before_touch.id, conn_id);
        assert_eq!(before_touch.ip, ip);

        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(state.touch_connection(conn_id).await);

        let after_touch = state
            .get_connection(conn_id)
            .await
            .expect("connection should still exist");
        assert!(after_touch.last_activity > before_touch.last_activity);

        let removed = state
            .unregister_connection(conn_id)
            .await
            .expect("connection should be removed");
        assert_eq!(removed.id, conn_id);
        assert_eq!(state.active_connection_count().await, 0);
    }

    #[tokio::test]
    async fn one_time_invite_cannot_be_reused() {
        let state = AppState::new(LimitsConfig::default());
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
        let conn = state.register_connection(ip).await;

        let created = state
            .create_invite(
                conn,
                ip,
                InviteCreateRequest {
                    r: vec!["ws://127.0.0.1:7000".to_string()],
                    e: 600,
                    o: true,
                },
            )
            .await
            .expect("invite should be created");

        state
            .use_invite(
                ip,
                InviteUseRequest {
                    invite: created.invite.clone(),
                },
            )
            .await
            .expect("first use should pass");

        let second = state
            .use_invite(
                ip,
                InviteUseRequest {
                    invite: created.invite,
                },
            )
            .await
            .expect_err("second use should fail");
        assert_eq!(second, InviteUseError::InviteUsed);
    }

    #[tokio::test]
    async fn invite_create_rejects_invalid_payload() {
        let state = AppState::new(LimitsConfig::default());
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
        let conn = state.register_connection(ip).await;

        let err = state
            .create_invite(
                conn,
                ip,
                InviteCreateRequest {
                    r: vec![],
                    e: 600,
                    o: true,
                },
            )
            .await
            .expect_err("empty relay list should fail");

        assert_eq!(err, InviteCreateError::InvalidRequest);
    }

    #[test]
    fn token_generation_matches_base32_contract() {
        let token = generate_token(TOKEN_MAX_LEN);
        assert_eq!(token.len(), TOKEN_MAX_LEN);
        assert!(token.chars().all(|c| matches!(c, 'A'..='Z' | '2'..='7')));
    }
}
