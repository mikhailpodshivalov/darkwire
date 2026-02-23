use crate::{
    invite_store::{InviteConsumeError, InviteRecord, InviteStore},
    rate_limit::{RateLimitHit, RateLimitStore},
    session_store::{SessionCreateError, SessionId, SessionStore},
};
use darkwire_protocol::{
    config::LimitsConfig,
    events::{InviteCreateRequest, InviteUseRequest, SessionEndReason},
    invite::{decode_invite, encode_invite, InvitePayloadV1, INVITE_VERSION, TOKEN_MAX_LEN},
};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, RwLock};
use uuid::Uuid;

pub type ConnId = Uuid;
pub type SharedState = Arc<AppState>;
pub type OutboundSender = mpsc::Sender<String>;

const TOKEN_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

#[derive(Debug, Clone)]
pub struct ConnectionRecord {
    pub id: ConnId,
    pub ip: IpAddr,
    pub connected_at: Instant,
    pub last_activity: Instant,
    pub last_msg_at: Option<Instant>,
}

#[derive(Debug)]
struct ConnectionEntry {
    record: ConnectionRecord,
    outbound_tx: OutboundSender,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteCreated {
    pub invite: String,
    pub expires_in: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteUseSuccess {
    pub session_id: SessionId,
    pub creator_conn: ConnId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTermination {
    pub session_id: SessionId,
    pub peer_conn: ConnId,
    pub reason: SessionEndReason,
}

#[derive(Debug, Clone)]
pub struct DisconnectOutcome {
    pub connection: Option<ConnectionRecord>,
    pub peer_ended: Option<SessionTermination>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageRoute {
    pub session_id: SessionId,
    pub peer_conn: ConnId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InviteCreateError {
    RateLimited(RateLimitHit),
    InvalidRequest,
    PeerOffline,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InviteUseError {
    RateLimited(RateLimitHit),
    InvalidInvite,
    InviteExpired,
    InviteUsed,
    PeerOffline,
    SessionBusy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MsgSendError {
    NoActiveSession,
    MessageTooLarge,
    RateLimited(Duration),
}

#[derive(Debug)]
pub struct AppState {
    limits: LimitsConfig,
    connections: RwLock<HashMap<ConnId, ConnectionEntry>>,
    invites: InviteStore,
    rate_limits: RateLimitStore,
    sessions: RwLock<SessionStore>,
}

impl AppState {
    pub fn new(limits: LimitsConfig) -> Self {
        Self {
            limits,
            connections: RwLock::new(HashMap::new()),
            invites: InviteStore::new(),
            rate_limits: RateLimitStore::new(),
            sessions: RwLock::new(SessionStore::new()),
        }
    }

    pub fn limits(&self) -> &LimitsConfig {
        &self.limits
    }

    pub async fn register_connection(&self, ip: IpAddr, outbound_tx: OutboundSender) -> ConnId {
        let now = Instant::now();
        let id = Uuid::new_v4();
        let entry = ConnectionEntry {
            record: ConnectionRecord {
                id,
                ip,
                connected_at: now,
                last_activity: now,
                last_msg_at: None,
            },
            outbound_tx,
        };

        self.connections.write().await.insert(id, entry);
        id
    }

    pub async fn touch_connection(&self, id: ConnId) -> bool {
        let mut connections = self.connections.write().await;
        match connections.get_mut(&id) {
            Some(entry) => {
                entry.record.last_activity = Instant::now();
                true
            }
            None => false,
        }
    }

    pub async fn get_connection(&self, id: ConnId) -> Option<ConnectionRecord> {
        self.connections
            .read()
            .await
            .get(&id)
            .map(|entry| entry.record.clone())
    }

    pub async fn unregister_connection(
        &self,
        id: ConnId,
        reason: SessionEndReason,
    ) -> DisconnectOutcome {
        let removed = self
            .connections
            .write()
            .await
            .remove(&id)
            .map(|entry| entry.record);

        let peer_ended = self
            .sessions
            .write()
            .await
            .close_for_conn(id)
            .map(|closed| SessionTermination {
                session_id: closed.session_id,
                peer_conn: closed.peer_conn,
                reason,
            });

        DisconnectOutcome {
            connection: removed,
            peer_ended,
        }
    }

    pub async fn active_connection_count(&self) -> usize {
        self.connections.read().await.len()
    }

    pub async fn send_to_connection(&self, conn_id: ConnId, payload: String) -> bool {
        let sender = self
            .connections
            .read()
            .await
            .get(&conn_id)
            .map(|entry| entry.outbound_tx.clone());

        let Some(sender) = sender else {
            return false;
        };

        sender.send(payload).await.is_ok()
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

        if !self.connection_exists(creator_conn).await {
            return Err(InviteCreateError::PeerOffline);
        }

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
        joiner_conn: ConnId,
        ip: IpAddr,
        req: InviteUseRequest,
    ) -> Result<InviteUseSuccess, InviteUseError> {
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

        let consumed = match self.invites.consume(&payload).await {
            Ok(consumed) => consumed,
            Err(err) => {
                self.rate_limits
                    .record_invite_use_result(ip, false, &self.limits)
                    .await;
                return Err(map_invite_error(err));
            }
        };

        let creator_conn = consumed.creator_conn;
        let session_result = self
            .create_session(joiner_conn, creator_conn, consumed.token.clone())
            .await;

        match session_result {
            Ok(session_id) => {
                self.rate_limits
                    .record_invite_use_result(ip, true, &self.limits)
                    .await;
                Ok(InviteUseSuccess {
                    session_id,
                    creator_conn,
                })
            }
            Err(err) => {
                self.invites.rollback_use(&consumed.token).await;
                self.rate_limits
                    .record_invite_use_result(ip, false, &self.limits)
                    .await;
                Err(err)
            }
        }
    }

    pub async fn route_message(
        &self,
        sender_conn: ConnId,
        text_bytes: usize,
    ) -> Result<MessageRoute, MsgSendError> {
        if text_bytes > self.limits.max_msg_bytes {
            return Err(MsgSendError::MessageTooLarge);
        }

        let now = Instant::now();
        self.enforce_message_rate_limit(sender_conn, now).await?;

        let mut sessions = self.sessions.write().await;
        let (session_id, peer_conn) = sessions
            .peer_for_conn(sender_conn)
            .ok_or(MsgSendError::NoActiveSession)?;

        sessions.touch_conn(sender_conn, now);

        Ok(MessageRoute {
            session_id,
            peer_conn,
        })
    }

    pub async fn end_session_for_conn(
        &self,
        conn_id: ConnId,
        reason: SessionEndReason,
    ) -> Option<SessionTermination> {
        self.sessions
            .write()
            .await
            .close_for_conn(conn_id)
            .map(|closed| SessionTermination {
                session_id: closed.session_id,
                peer_conn: closed.peer_conn,
                reason,
            })
    }

    async fn create_session(
        &self,
        joiner_conn: ConnId,
        creator_conn: ConnId,
        _token: String,
    ) -> Result<SessionId, InviteUseError> {
        let both_online = {
            let connections = self.connections.read().await;
            connections.contains_key(&joiner_conn) && connections.contains_key(&creator_conn)
        };

        if !both_online {
            return Err(InviteUseError::PeerOffline);
        }

        let now = Instant::now();
        let session = self
            .sessions
            .write()
            .await
            .create(joiner_conn, creator_conn, now)
            .map_err(map_session_create_error)?;

        Ok(session.id)
    }

    async fn enforce_message_rate_limit(
        &self,
        sender_conn: ConnId,
        now: Instant,
    ) -> Result<(), MsgSendError> {
        let mut connections = self.connections.write().await;
        let Some(entry) = connections.get_mut(&sender_conn) else {
            return Err(MsgSendError::NoActiveSession);
        };

        let min_interval = min_interval_for_rate(self.limits.msg_per_sec);
        if min_interval > Duration::ZERO {
            if let Some(last_msg_at) = entry.record.last_msg_at {
                let elapsed = now.saturating_duration_since(last_msg_at);
                if elapsed < min_interval {
                    return Err(MsgSendError::RateLimited(min_interval - elapsed));
                }
            }
        }

        entry.record.last_msg_at = Some(now);
        entry.record.last_activity = now;

        Ok(())
    }

    async fn connection_exists(&self, conn_id: ConnId) -> bool {
        self.connections.read().await.contains_key(&conn_id)
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

fn map_session_create_error(err: SessionCreateError) -> InviteUseError {
    match err {
        SessionCreateError::ConnectionBusy | SessionCreateError::SamePeer => {
            InviteUseError::SessionBusy
        }
    }
}

fn min_interval_for_rate(rate_per_sec: u32) -> Duration {
    if rate_per_sec == 0 {
        return Duration::ZERO;
    }

    Duration::from_secs_f64(1.0 / f64::from(rate_per_sec))
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
    use darkwire_protocol::events::InviteCreateRequest;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::sync::mpsc;

    fn test_ip(a: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, a))
    }

    fn channel() -> (OutboundSender, mpsc::Receiver<String>) {
        mpsc::channel(8)
    }

    #[tokio::test]
    async fn connection_lifecycle_updates_and_cleans_up() {
        let state = AppState::new(LimitsConfig::default());
        let (tx, _rx) = channel();

        let conn_id = state.register_connection(test_ip(1), tx).await;
        assert_eq!(state.active_connection_count().await, 1);

        let before_touch = state
            .get_connection(conn_id)
            .await
            .expect("connection should exist");
        assert_eq!(before_touch.id, conn_id);
        assert_eq!(before_touch.ip, test_ip(1));

        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(state.touch_connection(conn_id).await);

        let after_touch = state
            .get_connection(conn_id)
            .await
            .expect("connection should still exist");
        assert!(after_touch.last_activity > before_touch.last_activity);

        let removed = state
            .unregister_connection(conn_id, SessionEndReason::PeerDisconnect)
            .await;
        assert_eq!(removed.connection.expect("removed").id, conn_id);
        assert!(removed.peer_ended.is_none());
        assert_eq!(state.active_connection_count().await, 0);
    }

    #[tokio::test]
    async fn invite_use_creates_session_and_rejects_reuse() {
        let state = AppState::new(LimitsConfig::default());

        let (tx_a, _rx_a) = channel();
        let (tx_b, _rx_b) = channel();
        let inviter = state.register_connection(test_ip(2), tx_a).await;
        let joiner = state.register_connection(test_ip(3), tx_b).await;

        let created = state
            .create_invite(
                inviter,
                test_ip(2),
                InviteCreateRequest {
                    r: vec!["ws://127.0.0.1:7000".to_string()],
                    e: 600,
                    o: true,
                },
            )
            .await
            .expect("invite create should pass");

        let joined = state
            .use_invite(
                joiner,
                test_ip(3),
                InviteUseRequest {
                    invite: created.invite.clone(),
                },
            )
            .await
            .expect("invite use should pass");
        assert_eq!(joined.creator_conn, inviter);

        let err = state
            .use_invite(
                joiner,
                test_ip(3),
                InviteUseRequest {
                    invite: created.invite,
                },
            )
            .await
            .expect_err("reusing invite should fail");
        assert_eq!(err, InviteUseError::InviteUsed);
    }

    #[tokio::test]
    async fn invite_use_rejects_expired_invite() {
        let state = AppState::new(LimitsConfig::default());

        let (tx_a, _rx_a) = channel();
        let (tx_b, _rx_b) = channel();
        let inviter = state.register_connection(test_ip(10), tx_a).await;
        let joiner = state.register_connection(test_ip(11), tx_b).await;

        let created = state
            .create_invite(
                inviter,
                test_ip(10),
                InviteCreateRequest {
                    r: vec!["ws://127.0.0.1:7000".to_string()],
                    e: 1,
                    o: true,
                },
            )
            .await
            .expect("invite create should pass");

        tokio::time::sleep(Duration::from_secs(2)).await;

        let err = state
            .use_invite(
                joiner,
                test_ip(11),
                InviteUseRequest {
                    invite: created.invite,
                },
            )
            .await
            .expect_err("expired invite should fail");
        assert_eq!(err, InviteUseError::InviteExpired);
    }

    #[tokio::test]
    async fn route_message_enforces_active_session_and_rate_limit() {
        let mut limits = LimitsConfig::default();
        limits.msg_per_sec = 1;

        let state = AppState::new(limits);
        let (tx_a, _rx_a) = channel();
        let (tx_b, _rx_b) = channel();

        let inviter = state.register_connection(test_ip(4), tx_a).await;
        let joiner = state.register_connection(test_ip(5), tx_b).await;

        let created = state
            .create_invite(
                inviter,
                test_ip(4),
                InviteCreateRequest {
                    r: vec!["ws://127.0.0.1:7000".to_string()],
                    e: 600,
                    o: true,
                },
            )
            .await
            .expect("invite create should pass");

        state
            .use_invite(
                joiner,
                test_ip(5),
                InviteUseRequest {
                    invite: created.invite,
                },
            )
            .await
            .expect("invite use should pass");

        let first = state
            .route_message(inviter, "hello".len())
            .await
            .expect("first message should pass");
        assert_eq!(first.peer_conn, joiner);

        let second = state
            .route_message(inviter, "again".len())
            .await
            .expect_err("second message too soon should fail");
        assert!(matches!(second, MsgSendError::RateLimited(_)));

        tokio::time::sleep(Duration::from_secs(1)).await;
        state
            .route_message(inviter, "ok".len())
            .await
            .expect("message should pass after interval");
    }

    #[tokio::test]
    async fn route_message_rejects_oversized_payload() {
        let mut limits = LimitsConfig::default();
        limits.max_msg_bytes = 8;

        let state = AppState::new(limits);
        let (tx_a, _rx_a) = channel();
        let (tx_b, _rx_b) = channel();

        let inviter = state.register_connection(test_ip(8), tx_a).await;
        let joiner = state.register_connection(test_ip(9), tx_b).await;

        let created = state
            .create_invite(
                inviter,
                test_ip(8),
                InviteCreateRequest {
                    r: vec!["ws://127.0.0.1:7000".to_string()],
                    e: 600,
                    o: true,
                },
            )
            .await
            .expect("invite create should pass");

        state
            .use_invite(
                joiner,
                test_ip(9),
                InviteUseRequest {
                    invite: created.invite,
                },
            )
            .await
            .expect("invite use should pass");

        let err = state
            .route_message(inviter, 9)
            .await
            .expect_err("payload over max bytes should fail");
        assert_eq!(err, MsgSendError::MessageTooLarge);
    }

    #[tokio::test]
    async fn unregister_notifies_peer_session_end() {
        let state = AppState::new(LimitsConfig::default());
        let (tx_a, _rx_a) = channel();
        let (tx_b, _rx_b) = channel();

        let inviter = state.register_connection(test_ip(6), tx_a).await;
        let joiner = state.register_connection(test_ip(7), tx_b).await;

        let created = state
            .create_invite(
                inviter,
                test_ip(6),
                InviteCreateRequest {
                    r: vec!["ws://127.0.0.1:7000".to_string()],
                    e: 600,
                    o: true,
                },
            )
            .await
            .expect("invite create should pass");

        let joined = state
            .use_invite(
                joiner,
                test_ip(7),
                InviteUseRequest {
                    invite: created.invite,
                },
            )
            .await
            .expect("invite use should pass");

        let outcome = state
            .unregister_connection(inviter, SessionEndReason::PeerDisconnect)
            .await;
        let peer_ended = outcome.peer_ended.expect("peer should be notified");
        assert_eq!(peer_ended.session_id, joined.session_id);
        assert_eq!(peer_ended.peer_conn, joiner);
        assert_eq!(peer_ended.reason, SessionEndReason::PeerDisconnect);
    }

    #[test]
    fn token_generation_matches_base32_contract() {
        let token = generate_token(TOKEN_MAX_LEN);
        assert_eq!(token.len(), TOKEN_MAX_LEN);
        assert!(token.chars().all(|c| matches!(c, 'A'..='Z' | '2'..='7')));
    }
}
