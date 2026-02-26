use crate::{
    handshake_store::{
        ConsumeSelectionError, HandshakeStore, PendingHandshake, PrekeySelection,
        TakeHandshakeError,
    },
    invite_store::{InviteConsumeError, InviteRecord, InviteStore},
    login_store::{BindError, LoginStore},
    prekey_store::{OpkRecord, PrekeyStore, SpkRecord},
    rate_limit::{RateLimitHit, RateLimitStore},
    session_store::{SessionCreateError, SessionId, SessionStore},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use darkwire_protocol::{
    config::LimitsConfig,
    events::{
        HandshakeAcceptRecvEvent, HandshakeAcceptRequest, HandshakeInitRecvEvent,
        HandshakeInitRequest, InviteCreateRequest, InviteUseRequest, LoginBindRequest,
        LoginLookupRequest, OneTimePrekey, PrekeyGetRequest, PrekeyPublishRequest,
        PublicPrekeyBundle, SessionEndReason, SignedPrekey,
    },
    invite::{decode_invite, encode_invite, InvitePayloadV1, INVITE_VERSION, TOKEN_MAX_LEN},
    login::{login_bind_transcript, normalize_login},
};
use ring::signature::{self, UnparsedPublicKey};
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{mpsc, RwLock};
use uuid::Uuid;

pub type ConnId = Uuid;
pub type SharedState = Arc<AppState>;
pub type OutboundSender = mpsc::Sender<String>;

const TOKEN_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const MAX_OPKS_PER_PUBLISH: usize = 256;

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
pub struct LoginBinding {
    pub login: String,
    pub ik_ed25519: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HandshakeFailureReason {
    InvalidPayload,
    NoActiveSession,
    SessionMismatch,
    PrekeyNotFound,
    StateConflict,
    HandshakeInvalid,
    HandshakeTimeout,
    UnsupportedEvent,
}

impl HandshakeFailureReason {
    pub fn as_str(self) -> &'static str {
        match self {
            HandshakeFailureReason::InvalidPayload => "invalid_payload",
            HandshakeFailureReason::NoActiveSession => "no_active_session",
            HandshakeFailureReason::SessionMismatch => "session_mismatch",
            HandshakeFailureReason::PrekeyNotFound => "prekey_not_found",
            HandshakeFailureReason::StateConflict => "state_conflict",
            HandshakeFailureReason::HandshakeInvalid => "handshake_invalid",
            HandshakeFailureReason::HandshakeTimeout => "handshake_timeout",
            HandshakeFailureReason::UnsupportedEvent => "unsupported_event",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrekeyPublished {
    pub spk_id: u32,
    pub opk_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrekeyBundleRoute {
    pub session_id: SessionId,
    pub peer: PublicPrekeyBundle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeInitRoute {
    pub session_id: SessionId,
    pub peer_conn: ConnId,
    pub event: HandshakeInitRecvEvent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeAcceptRoute {
    pub session_id: SessionId,
    pub peer_conn: ConnId,
    pub event: HandshakeAcceptRecvEvent,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum E2eMsgSendError {
    NoActiveSession,
    SessionMismatch,
    MessageTooLarge,
    RateLimited(Duration),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrekeyPublishError {
    RateLimited(RateLimitHit),
    PeerOffline,
    InvalidRequest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrekeyGetError {
    RateLimited(RateLimitHit),
    NoActiveSession,
    SessionMismatch,
    PrekeyNotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginBindError {
    InvalidRequest,
    LoginTaken,
    KeyMismatch,
    PeerOffline,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginLookupError {
    InvalidRequest,
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeInitError {
    RateLimited(RateLimitHit),
    InvalidRequest,
    NoActiveSession,
    SessionMismatch,
    PrekeySelectionMissing,
    StateConflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeAcceptError {
    RateLimited(RateLimitHit),
    InvalidRequest,
    NoActiveSession,
    SessionMismatch,
    StateConflict,
}

#[derive(Debug)]
pub struct AppState {
    limits: LimitsConfig,
    connections: RwLock<HashMap<ConnId, ConnectionEntry>>,
    invites: InviteStore,
    rate_limits: RateLimitStore,
    logins: RwLock<LoginStore>,
    prekeys: RwLock<PrekeyStore>,
    handshakes: RwLock<HandshakeStore>,
    sessions: RwLock<SessionStore>,
    handshake_failures: RwLock<HashMap<HandshakeFailureReason, u64>>,
}

impl AppState {
    pub fn new(limits: LimitsConfig) -> Self {
        Self {
            limits,
            connections: RwLock::new(HashMap::new()),
            invites: InviteStore::new(),
            rate_limits: RateLimitStore::new(),
            logins: RwLock::new(LoginStore::new()),
            prekeys: RwLock::new(PrekeyStore::new()),
            handshakes: RwLock::new(HandshakeStore::new()),
            sessions: RwLock::new(SessionStore::new()),
            handshake_failures: RwLock::new(HashMap::new()),
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

        self.prekeys.write().await.remove_bundle(id);
        self.handshakes.write().await.cleanup_for_conn(id);
        if let Some(ended) = peer_ended.as_ref() {
            self.handshakes
                .write()
                .await
                .cleanup_for_session(ended.session_id);
        }

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
            k: req.k,
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
        self.invites.invalidate_for_creator(creator_conn).await;
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

    pub async fn route_encrypted_message(
        &self,
        sender_conn: ConnId,
        session_id: SessionId,
        payload_bytes: usize,
    ) -> Result<MessageRoute, E2eMsgSendError> {
        if payload_bytes > self.limits.max_msg_bytes {
            return Err(E2eMsgSendError::MessageTooLarge);
        }

        {
            let sessions = self.sessions.read().await;
            let (active_session_id, _) = sessions
                .peer_for_conn(sender_conn)
                .ok_or(E2eMsgSendError::NoActiveSession)?;
            if active_session_id != session_id {
                return Err(E2eMsgSendError::SessionMismatch);
            }
        }

        let now = Instant::now();
        self.enforce_message_rate_limit(sender_conn, now)
            .await
            .map_err(map_msg_send_error)?;

        let mut sessions = self.sessions.write().await;
        let (active_session_id, peer_conn) = sessions
            .peer_for_conn(sender_conn)
            .ok_or(E2eMsgSendError::NoActiveSession)?;
        if active_session_id != session_id {
            return Err(E2eMsgSendError::SessionMismatch);
        }

        sessions.touch_conn(sender_conn, now);

        Ok(MessageRoute {
            session_id,
            peer_conn,
        })
    }

    pub async fn publish_prekeys(
        &self,
        conn_id: ConnId,
        ip: IpAddr,
        req: PrekeyPublishRequest,
    ) -> Result<PrekeyPublished, PrekeyPublishError> {
        self.rate_limits
            .check_prekey_publish(ip, &self.limits)
            .await
            .map_err(PrekeyPublishError::RateLimited)?;

        if !self.connection_exists(conn_id).await {
            return Err(PrekeyPublishError::PeerOffline);
        }

        validate_prekey_publish(&req).map_err(|_| PrekeyPublishError::InvalidRequest)?;

        let spk = SpkRecord {
            id: req.spk.id,
            x25519: req.spk.x25519,
            sig_ed25519: req.spk.sig_ed25519,
            exp_unix: req.spk.exp_unix,
        };

        let opks = req
            .opks
            .into_iter()
            .map(|opk| OpkRecord {
                id: opk.id,
                x25519: opk.x25519,
            })
            .collect::<Vec<_>>();

        let opk_count =
            self.prekeys
                .write()
                .await
                .upsert_bundle(conn_id, req.ik_ed25519, spk.clone(), opks);

        Ok(PrekeyPublished {
            spk_id: spk.id,
            opk_count,
        })
    }

    pub async fn get_peer_prekey_bundle(
        &self,
        conn_id: ConnId,
        ip: IpAddr,
        req: PrekeyGetRequest,
    ) -> Result<PrekeyBundleRoute, PrekeyGetError> {
        self.rate_limits
            .check_prekey_get(ip, &self.limits)
            .await
            .map_err(PrekeyGetError::RateLimited)?;

        let (session_id, peer_conn) = {
            let sessions = self.sessions.read().await;
            let (active_session_id, peer_conn) = sessions
                .peer_for_conn(conn_id)
                .ok_or(PrekeyGetError::NoActiveSession)?;
            if active_session_id != req.session_id {
                return Err(PrekeyGetError::SessionMismatch);
            }
            (active_session_id, peer_conn)
        };

        let peer_bundle = self
            .prekeys
            .write()
            .await
            .take_peer_bundle(peer_conn)
            .ok_or(PrekeyGetError::PrekeyNotFound)?;

        self.handshakes
            .write()
            .await
            .note_prekey_selection(PrekeySelection {
                session_id,
                initiator_conn: conn_id,
                responder_conn: peer_conn,
                peer_spk_id: peer_bundle.spk.id,
                peer_opk_id: peer_bundle.opk.as_ref().map(|opk| opk.id),
                selected_at: Instant::now(),
            });

        Ok(PrekeyBundleRoute {
            session_id,
            peer: PublicPrekeyBundle {
                ik_ed25519: peer_bundle.ik_ed25519,
                spk: SignedPrekey {
                    id: peer_bundle.spk.id,
                    x25519: peer_bundle.spk.x25519,
                    sig_ed25519: peer_bundle.spk.sig_ed25519,
                    exp_unix: peer_bundle.spk.exp_unix,
                },
                opk: peer_bundle.opk.map(|opk| OneTimePrekey {
                    id: opk.id,
                    x25519: opk.x25519,
                }),
            },
        })
    }

    pub async fn bind_login(
        &self,
        conn_id: ConnId,
        req: LoginBindRequest,
    ) -> Result<LoginBinding, LoginBindError> {
        if !self.connection_exists(conn_id).await {
            return Err(LoginBindError::PeerOffline);
        }

        let normalized = normalize_login(&req.login).ok_or(LoginBindError::InvalidRequest)?;
        validate_login_bind_request(&normalized, &req).map_err(map_login_validation_error)?;

        let conn_ik = self
            .prekeys
            .read()
            .await
            .identity_key_for_conn(conn_id)
            .map(str::to_string)
            .ok_or(LoginBindError::KeyMismatch)?;

        if conn_ik != req.ik_ed25519 {
            return Err(LoginBindError::KeyMismatch);
        }

        let binding = self
            .logins
            .write()
            .await
            .bind(normalized, req.ik_ed25519)
            .map_err(map_login_bind_store_error)?;

        Ok(LoginBinding {
            login: binding.login,
            ik_ed25519: binding.ik_ed25519,
        })
    }

    pub async fn lookup_login(
        &self,
        req: LoginLookupRequest,
    ) -> Result<LoginBinding, LoginLookupError> {
        let binding = match (req.login, req.ik_ed25519) {
            (Some(login), None) => {
                let normalized = normalize_login(&login).ok_or(LoginLookupError::InvalidRequest)?;
                self.logins.read().await.get_by_login(&normalized)
            }
            (None, Some(ik_ed25519)) => {
                if ik_ed25519.trim().is_empty() {
                    return Err(LoginLookupError::InvalidRequest);
                }
                self.logins.read().await.get_by_ik(ik_ed25519.trim())
            }
            _ => return Err(LoginLookupError::InvalidRequest),
        };

        let Some(binding) = binding else {
            return Err(LoginLookupError::NotFound);
        };

        Ok(LoginBinding {
            login: binding.login,
            ik_ed25519: binding.ik_ed25519,
        })
    }

    pub async fn route_handshake_init(
        &self,
        initiator_conn: ConnId,
        ip: IpAddr,
        req: HandshakeInitRequest,
    ) -> Result<HandshakeInitRoute, HandshakeInitError> {
        self.rate_limits
            .check_handshake(ip, &self.limits)
            .await
            .map_err(HandshakeInitError::RateLimited)?;

        validate_handshake_init_request(&req).map_err(|_| HandshakeInitError::InvalidRequest)?;

        let (session_id, responder_conn) = {
            let sessions = self.sessions.read().await;
            let (active_session_id, peer_conn) = sessions
                .peer_for_conn(initiator_conn)
                .ok_or(HandshakeInitError::NoActiveSession)?;
            if active_session_id != req.session_id {
                return Err(HandshakeInitError::SessionMismatch);
            }
            (active_session_id, peer_conn)
        };

        let mut handshakes = self.handshakes.write().await;
        let _ = handshakes
            .consume_prekey_selection(
                session_id,
                initiator_conn,
                responder_conn,
                req.peer_spk_id,
                req.peer_opk_id,
            )
            .map_err(map_prekey_selection_error)?;

        let inserted = handshakes.register_pending_handshake(PendingHandshake {
            session_id,
            hs_id: req.hs_id,
            initiator_conn,
            responder_conn,
            peer_spk_id: req.peer_spk_id,
            peer_opk_id: req.peer_opk_id,
            created_at: Instant::now(),
        });

        if !inserted {
            return Err(HandshakeInitError::StateConflict);
        }

        Ok(HandshakeInitRoute {
            session_id,
            peer_conn: responder_conn,
            event: req,
        })
    }

    pub async fn route_handshake_accept(
        &self,
        responder_conn: ConnId,
        ip: IpAddr,
        req: HandshakeAcceptRequest,
    ) -> Result<HandshakeAcceptRoute, HandshakeAcceptError> {
        self.rate_limits
            .check_handshake(ip, &self.limits)
            .await
            .map_err(HandshakeAcceptError::RateLimited)?;

        validate_handshake_accept_request(&req)
            .map_err(|_| HandshakeAcceptError::InvalidRequest)?;

        let (session_id, peer_conn) = {
            let sessions = self.sessions.read().await;
            let (active_session_id, peer_conn) = sessions
                .peer_for_conn(responder_conn)
                .ok_or(HandshakeAcceptError::NoActiveSession)?;
            if active_session_id != req.session_id {
                return Err(HandshakeAcceptError::SessionMismatch);
            }
            (active_session_id, peer_conn)
        };

        let pending = self
            .handshakes
            .write()
            .await
            .take_pending_for_accept(req.hs_id, session_id, responder_conn)
            .map_err(map_take_handshake_error)?;

        if pending.initiator_conn != peer_conn {
            return Err(HandshakeAcceptError::StateConflict);
        }

        Ok(HandshakeAcceptRoute {
            session_id,
            peer_conn: pending.initiator_conn,
            event: req,
        })
    }

    pub async fn end_session_for_conn(
        &self,
        conn_id: ConnId,
        reason: SessionEndReason,
    ) -> Option<SessionTermination> {
        let ended = self
            .sessions
            .write()
            .await
            .close_for_conn(conn_id)
            .map(|closed| SessionTermination {
                session_id: closed.session_id,
                peer_conn: closed.peer_conn,
                reason,
            });

        if let Some(session) = ended.as_ref() {
            self.handshakes
                .write()
                .await
                .cleanup_for_session(session.session_id);
        }

        self.handshakes.write().await.cleanup_for_conn(conn_id);
        ended
    }

    pub async fn record_handshake_failure(&self, reason: HandshakeFailureReason) {
        let mut failures = self.handshake_failures.write().await;
        let count = failures.entry(reason).or_insert(0);
        *count = count.saturating_add(1);
    }

    #[cfg(test)]
    pub async fn handshake_failure_count(&self, reason: HandshakeFailureReason) -> u64 {
        self.handshake_failures
            .read()
            .await
            .get(&reason)
            .copied()
            .unwrap_or(0)
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

fn map_prekey_selection_error(err: ConsumeSelectionError) -> HandshakeInitError {
    match err {
        ConsumeSelectionError::NotFound => HandshakeInitError::PrekeySelectionMissing,
        ConsumeSelectionError::PeerMismatch
        | ConsumeSelectionError::SpkMismatch
        | ConsumeSelectionError::OpkMismatch => HandshakeInitError::StateConflict,
    }
}

fn map_take_handshake_error(err: TakeHandshakeError) -> HandshakeAcceptError {
    match err {
        TakeHandshakeError::NotFound => HandshakeAcceptError::StateConflict,
        TakeHandshakeError::SessionMismatch | TakeHandshakeError::ResponderMismatch => {
            HandshakeAcceptError::StateConflict
        }
    }
}

fn map_msg_send_error(err: MsgSendError) -> E2eMsgSendError {
    match err {
        MsgSendError::NoActiveSession => E2eMsgSendError::NoActiveSession,
        MsgSendError::MessageTooLarge => E2eMsgSendError::MessageTooLarge,
        MsgSendError::RateLimited(retry_after) => E2eMsgSendError::RateLimited(retry_after),
    }
}

fn map_login_bind_store_error(err: BindError) -> LoginBindError {
    match err {
        BindError::LoginTaken => LoginBindError::LoginTaken,
    }
}

fn map_login_validation_error(err: LoginValidationError) -> LoginBindError {
    match err {
        LoginValidationError::MissingIdentityKey
        | LoginValidationError::MissingSignature
        | LoginValidationError::InvalidLogin => LoginBindError::InvalidRequest,
        LoginValidationError::KeyMismatch | LoginValidationError::InvalidSignature => {
            LoginBindError::KeyMismatch
        }
    }
}

fn validate_login_bind_request(
    normalized_login: &str,
    req: &LoginBindRequest,
) -> Result<(), LoginValidationError> {
    if normalized_login.is_empty() {
        return Err(LoginValidationError::InvalidLogin);
    }
    if req.ik_ed25519.trim().is_empty() {
        return Err(LoginValidationError::MissingIdentityKey);
    }
    if req.sig_ed25519.trim().is_empty() {
        return Err(LoginValidationError::MissingSignature);
    }

    verify_login_bind_signature(normalized_login, &req.ik_ed25519, &req.sig_ed25519)
        .map_err(|_| LoginValidationError::InvalidSignature)?;
    Ok(())
}

fn verify_login_bind_signature(
    login: &str,
    ik_ed25519: &str,
    sig_ed25519: &str,
) -> Result<(), LoginValidationError> {
    let key_bytes = URL_SAFE_NO_PAD
        .decode(ik_ed25519.as_bytes())
        .map_err(|_| LoginValidationError::KeyMismatch)?;
    if key_bytes.len() != 32 {
        return Err(LoginValidationError::KeyMismatch);
    }

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_ed25519.as_bytes())
        .map_err(|_| LoginValidationError::InvalidSignature)?;
    if sig_bytes.len() != 64 {
        return Err(LoginValidationError::InvalidSignature);
    }

    let transcript = login_bind_transcript(login, ik_ed25519);
    let verifier = UnparsedPublicKey::new(&signature::ED25519, key_bytes);
    verifier
        .verify(&transcript, &sig_bytes)
        .map_err(|_| LoginValidationError::InvalidSignature)
}

fn validate_prekey_publish(req: &PrekeyPublishRequest) -> Result<(), PrekeyValidationError> {
    if req.ik_ed25519.trim().is_empty() {
        return Err(PrekeyValidationError::MissingIdentityKey);
    }

    if req.spk.x25519.trim().is_empty() || req.spk.sig_ed25519.trim().is_empty() {
        return Err(PrekeyValidationError::MissingSignedPrekey);
    }

    if req.opks.len() > MAX_OPKS_PER_PUBLISH {
        return Err(PrekeyValidationError::TooManyOpks);
    }

    let mut seen_ids = HashSet::with_capacity(req.opks.len());
    for opk in &req.opks {
        if opk.x25519.trim().is_empty() {
            return Err(PrekeyValidationError::InvalidOpk);
        }
        if !seen_ids.insert(opk.id) {
            return Err(PrekeyValidationError::DuplicateOpkId);
        }
    }

    Ok(())
}

fn validate_handshake_init_request(
    req: &HandshakeInitRequest,
) -> Result<(), HandshakeValidationError> {
    if req.sender_ik_ed25519.trim().is_empty()
        || req.sender_eph_x25519.trim().is_empty()
        || req.sig_ed25519.trim().is_empty()
    {
        return Err(HandshakeValidationError::MissingFields);
    }

    if !is_timestamp_within_skew(req.ts_unix, 5 * 60) {
        return Err(HandshakeValidationError::TimestampOutOfSkew);
    }

    Ok(())
}

fn validate_handshake_accept_request(
    req: &HandshakeAcceptRequest,
) -> Result<(), HandshakeValidationError> {
    if req.responder_ik_ed25519.trim().is_empty()
        || req.responder_eph_x25519.trim().is_empty()
        || req.sig_ed25519.trim().is_empty()
        || req.kc.trim().is_empty()
    {
        return Err(HandshakeValidationError::MissingFields);
    }

    Ok(())
}

fn is_timestamp_within_skew(ts_unix: u64, skew_secs: u64) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let lower = now.saturating_sub(skew_secs);
    let upper = now.saturating_add(skew_secs);
    (lower..=upper).contains(&ts_unix)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrekeyValidationError {
    MissingIdentityKey,
    MissingSignedPrekey,
    InvalidOpk,
    DuplicateOpkId,
    TooManyOpks,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandshakeValidationError {
    MissingFields,
    TimestampOutOfSkew,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoginValidationError {
    InvalidLogin,
    MissingIdentityKey,
    MissingSignature,
    KeyMismatch,
    InvalidSignature,
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
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use darkwire_protocol::events::{
        HandshakeAcceptRequest, HandshakeInitRequest, InviteCreateRequest, LoginBindRequest,
        LoginLookupRequest, OneTimePrekey, PrekeyGetRequest, PrekeyPublishRequest, SignedPrekey,
    };
    use ring::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::sync::mpsc;

    fn test_ip(a: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, a))
    }

    fn channel() -> (OutboundSender, mpsc::Receiver<String>) {
        mpsc::channel(8)
    }

    fn now_unix() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn sample_prekey_publish(opk_ids: &[u32]) -> PrekeyPublishRequest {
        sample_prekey_publish_with_ik("ik_ed25519_b64u".to_string(), opk_ids)
    }

    fn sample_prekey_publish_with_ik(ik_ed25519: String, opk_ids: &[u32]) -> PrekeyPublishRequest {
        PrekeyPublishRequest {
            ik_ed25519,
            spk: SignedPrekey {
                id: 7,
                x25519: "spk_x25519_b64u".to_string(),
                sig_ed25519: "spk_sig_b64u".to_string(),
                exp_unix: 1_770_000_000,
            },
            opks: opk_ids
                .iter()
                .copied()
                .map(|id| OneTimePrekey {
                    id,
                    x25519: format!("opk_{id}_b64u"),
                })
                .collect(),
        }
    }

    fn generate_identity_keypair() -> Ed25519KeyPair {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate identity key");
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("decode generated identity key")
    }

    fn keypair_public_b64u(keypair: &Ed25519KeyPair) -> String {
        URL_SAFE_NO_PAD.encode(keypair.public_key().as_ref())
    }

    fn signed_login_bind_request(login: &str, keypair: &Ed25519KeyPair) -> LoginBindRequest {
        let ik_ed25519 = keypair_public_b64u(keypair);
        let normalized = normalize_login(login).expect("login must normalize");
        let transcript = login_bind_transcript(&normalized, &ik_ed25519);
        let signature = keypair.sign(&transcript);

        LoginBindRequest {
            login: login.to_string(),
            ik_ed25519,
            sig_ed25519: URL_SAFE_NO_PAD.encode(signature.as_ref()),
        }
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
                    k: None,
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
    async fn invite_create_embeds_identity_hint_when_provided() {
        let state = AppState::new(LimitsConfig::default());
        let (tx, _rx) = channel();
        let inviter = state.register_connection(test_ip(9), tx).await;
        let ik_hint = "ik_hint_test_value";

        let created = state
            .create_invite(
                inviter,
                test_ip(9),
                InviteCreateRequest {
                    r: vec!["ws://127.0.0.1:7000".to_string()],
                    e: 600,
                    o: true,
                    k: Some(ik_hint.to_string()),
                },
            )
            .await
            .expect("invite create should pass");

        let decoded = decode_invite(&created.invite).expect("created invite should decode");
        assert_eq!(decoded.k.as_deref(), Some(ik_hint));
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
                    k: None,
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
    async fn create_invite_invalidates_previous_invites_for_creator() {
        let state = AppState::new(LimitsConfig::default());
        let (tx_a, _rx_a) = channel();
        let (tx_b, _rx_b) = channel();
        let inviter = state.register_connection(test_ip(12), tx_a).await;
        let joiner = state.register_connection(test_ip(13), tx_b).await;

        let first = state
            .create_invite(
                inviter,
                test_ip(12),
                InviteCreateRequest {
                    r: vec!["ws://127.0.0.1:7000".to_string()],
                    e: 600,
                    o: true,
                    k: None,
                },
            )
            .await
            .expect("first invite should pass");

        let second = state
            .create_invite(
                inviter,
                test_ip(12),
                InviteCreateRequest {
                    r: vec!["ws://127.0.0.1:7000".to_string()],
                    e: 600,
                    o: true,
                    k: None,
                },
            )
            .await
            .expect("second invite should pass");

        let first_err = state
            .use_invite(
                joiner,
                test_ip(13),
                InviteUseRequest {
                    invite: first.invite,
                },
            )
            .await
            .expect_err("old invite should be invalidated");
        assert_eq!(first_err, InviteUseError::InvalidInvite);

        state
            .use_invite(
                joiner,
                test_ip(13),
                InviteUseRequest {
                    invite: second.invite,
                },
            )
            .await
            .expect("new invite should remain valid");
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
                    k: None,
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
                    k: None,
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
    async fn route_encrypted_message_validates_session_and_size() {
        let mut limits = LimitsConfig::default();
        limits.max_msg_bytes = 16;
        limits.msg_per_sec = 100;

        let state = AppState::new(limits);
        let (tx_a, _rx_a) = channel();
        let (tx_b, _rx_b) = channel();

        let inviter = state.register_connection(test_ip(40), tx_a).await;
        let joiner = state.register_connection(test_ip(41), tx_b).await;

        let created = state
            .create_invite(
                inviter,
                test_ip(40),
                InviteCreateRequest {
                    r: vec!["ws://127.0.0.1:7000".to_string()],
                    e: 600,
                    o: true,
                    k: None,
                },
            )
            .await
            .expect("invite create should pass");

        let session_id = state
            .use_invite(
                joiner,
                test_ip(41),
                InviteUseRequest {
                    invite: created.invite,
                },
            )
            .await
            .expect("invite use should pass")
            .session_id;

        let route = state
            .route_encrypted_message(inviter, session_id, 12)
            .await
            .expect("e2e payload should route");
        assert_eq!(route.session_id, session_id);
        assert_eq!(route.peer_conn, joiner);

        let mismatch = state
            .route_encrypted_message(inviter, Uuid::new_v4(), 12)
            .await
            .expect_err("session mismatch should fail");
        assert_eq!(mismatch, E2eMsgSendError::SessionMismatch);

        let too_large = state
            .route_encrypted_message(inviter, session_id, 17)
            .await
            .expect_err("oversized encrypted payload should fail");
        assert_eq!(too_large, E2eMsgSendError::MessageTooLarge);
    }

    #[tokio::test]
    async fn prekey_publish_and_get_consumes_one_opk_per_fetch() {
        let state = AppState::new(LimitsConfig::default());
        let (tx_a, _rx_a) = channel();
        let (tx_b, _rx_b) = channel();
        let inviter = state.register_connection(test_ip(20), tx_a).await;
        let joiner = state.register_connection(test_ip(21), tx_b).await;

        let created = state
            .create_invite(
                inviter,
                test_ip(20),
                InviteCreateRequest {
                    r: vec!["ws://127.0.0.1:7000".to_string()],
                    e: 600,
                    o: true,
                    k: None,
                },
            )
            .await
            .expect("invite create should pass");

        let session_id = state
            .use_invite(
                joiner,
                test_ip(21),
                InviteUseRequest {
                    invite: created.invite,
                },
            )
            .await
            .expect("invite use should pass")
            .session_id;

        let published = state
            .publish_prekeys(inviter, test_ip(20), sample_prekey_publish(&[10, 11]))
            .await
            .expect("prekey publish should pass");
        assert_eq!(published.spk_id, 7);
        assert_eq!(published.opk_count, 2);

        let first = state
            .get_peer_prekey_bundle(joiner, test_ip(21), PrekeyGetRequest { session_id })
            .await
            .expect("first bundle fetch should pass");
        assert_eq!(first.session_id, session_id);
        assert_eq!(first.peer.opk.expect("first opk").id, 10);

        let second = state
            .get_peer_prekey_bundle(joiner, test_ip(21), PrekeyGetRequest { session_id })
            .await
            .expect("second bundle fetch should pass");
        assert_eq!(second.peer.opk.expect("second opk").id, 11);

        let third = state
            .get_peer_prekey_bundle(joiner, test_ip(21), PrekeyGetRequest { session_id })
            .await
            .expect("fetch should still pass without opk");
        assert!(third.peer.opk.is_none());
    }

    #[tokio::test]
    async fn prekey_get_rejects_session_mismatch() {
        let state = AppState::new(LimitsConfig::default());
        let (tx_a, _rx_a) = channel();
        let (tx_b, _rx_b) = channel();
        let inviter = state.register_connection(test_ip(30), tx_a).await;
        let joiner = state.register_connection(test_ip(31), tx_b).await;

        let created = state
            .create_invite(
                inviter,
                test_ip(30),
                InviteCreateRequest {
                    r: vec!["ws://127.0.0.1:7000".to_string()],
                    e: 600,
                    o: true,
                    k: None,
                },
            )
            .await
            .expect("invite create should pass");

        state
            .use_invite(
                joiner,
                test_ip(31),
                InviteUseRequest {
                    invite: created.invite,
                },
            )
            .await
            .expect("invite use should pass");

        state
            .publish_prekeys(inviter, test_ip(30), sample_prekey_publish(&[1]))
            .await
            .expect("prekey publish should pass");

        let err = state
            .get_peer_prekey_bundle(
                joiner,
                test_ip(31),
                PrekeyGetRequest {
                    session_id: Uuid::new_v4(),
                },
            )
            .await
            .expect_err("wrong session id should fail");
        assert_eq!(err, PrekeyGetError::SessionMismatch);
    }

    #[tokio::test]
    async fn prekey_publish_rejects_duplicate_opk_ids() {
        let state = AppState::new(LimitsConfig::default());
        let (tx_a, _rx_a) = channel();
        let inviter = state.register_connection(test_ip(40), tx_a).await;

        let err = state
            .publish_prekeys(inviter, test_ip(40), sample_prekey_publish(&[1, 1]))
            .await
            .expect_err("duplicate opk ids should fail");
        assert_eq!(err, PrekeyPublishError::InvalidRequest);
    }

    #[tokio::test]
    async fn handshake_init_and_accept_route_between_session_peers() {
        let state = AppState::new(LimitsConfig::default());
        let (tx_a, _rx_a) = channel();
        let (tx_b, _rx_b) = channel();
        let inviter = state.register_connection(test_ip(50), tx_a).await;
        let joiner = state.register_connection(test_ip(51), tx_b).await;

        let created = state
            .create_invite(
                inviter,
                test_ip(50),
                InviteCreateRequest {
                    r: vec!["ws://127.0.0.1:7000".to_string()],
                    e: 600,
                    o: true,
                    k: None,
                },
            )
            .await
            .expect("invite create should pass");

        let session_id = state
            .use_invite(
                joiner,
                test_ip(51),
                InviteUseRequest {
                    invite: created.invite,
                },
            )
            .await
            .expect("invite use should pass")
            .session_id;

        state
            .publish_prekeys(inviter, test_ip(50), sample_prekey_publish(&[777]))
            .await
            .expect("prekey publish should pass");

        let bundle = state
            .get_peer_prekey_bundle(joiner, test_ip(51), PrekeyGetRequest { session_id })
            .await
            .expect("bundle fetch should pass");

        let hs_id = Uuid::new_v4();
        let init = HandshakeInitRequest {
            session_id,
            hs_id,
            sender_ik_ed25519: "sender_ik".to_string(),
            sender_eph_x25519: "sender_eph".to_string(),
            peer_spk_id: bundle.peer.spk.id,
            peer_opk_id: bundle.peer.opk.as_ref().map(|opk| opk.id),
            sig_ed25519: "sender_sig".to_string(),
            ts_unix: now_unix(),
        };

        let routed_init = state
            .route_handshake_init(joiner, test_ip(51), init)
            .await
            .expect("handshake init should route");
        assert_eq!(routed_init.session_id, session_id);
        assert_eq!(routed_init.peer_conn, inviter);

        let accept = HandshakeAcceptRequest {
            session_id,
            hs_id,
            responder_ik_ed25519: "responder_ik".to_string(),
            responder_eph_x25519: "responder_eph".to_string(),
            sig_ed25519: "responder_sig".to_string(),
            kc: "kc_value".to_string(),
        };

        let routed_accept = state
            .route_handshake_accept(inviter, test_ip(50), accept.clone())
            .await
            .expect("handshake accept should route");
        assert_eq!(routed_accept.session_id, session_id);
        assert_eq!(routed_accept.peer_conn, joiner);
        assert_eq!(routed_accept.event.hs_id, hs_id);

        let second_accept = state
            .route_handshake_accept(inviter, test_ip(50), accept)
            .await
            .expect_err("second accept for same hs_id should fail");
        assert_eq!(second_accept, HandshakeAcceptError::StateConflict);
    }

    #[tokio::test]
    async fn handshake_init_requires_prekey_selection_first() {
        let state = AppState::new(LimitsConfig::default());
        let (tx_a, _rx_a) = channel();
        let (tx_b, _rx_b) = channel();
        let inviter = state.register_connection(test_ip(60), tx_a).await;
        let joiner = state.register_connection(test_ip(61), tx_b).await;

        let created = state
            .create_invite(
                inviter,
                test_ip(60),
                InviteCreateRequest {
                    r: vec!["ws://127.0.0.1:7000".to_string()],
                    e: 600,
                    o: true,
                    k: None,
                },
            )
            .await
            .expect("invite create should pass");

        let session_id = state
            .use_invite(
                joiner,
                test_ip(61),
                InviteUseRequest {
                    invite: created.invite,
                },
            )
            .await
            .expect("invite use should pass")
            .session_id;

        let err = state
            .route_handshake_init(
                joiner,
                test_ip(61),
                HandshakeInitRequest {
                    session_id,
                    hs_id: Uuid::new_v4(),
                    sender_ik_ed25519: "sender_ik".to_string(),
                    sender_eph_x25519: "sender_eph".to_string(),
                    peer_spk_id: 7,
                    peer_opk_id: None,
                    sig_ed25519: "sender_sig".to_string(),
                    ts_unix: now_unix(),
                },
            )
            .await
            .expect_err("handshake init without prekey.get should fail");

        assert_eq!(err, HandshakeInitError::PrekeySelectionMissing);
    }

    #[tokio::test]
    async fn handshake_failure_metrics_increment_by_reason() {
        let state = AppState::new(LimitsConfig::default());

        state
            .record_handshake_failure(HandshakeFailureReason::UnsupportedEvent)
            .await;
        state
            .record_handshake_failure(HandshakeFailureReason::UnsupportedEvent)
            .await;
        state
            .record_handshake_failure(HandshakeFailureReason::PrekeyNotFound)
            .await;

        assert_eq!(
            state
                .handshake_failure_count(HandshakeFailureReason::UnsupportedEvent)
                .await,
            2
        );
        assert_eq!(
            state
                .handshake_failure_count(HandshakeFailureReason::PrekeyNotFound)
                .await,
            1
        );
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
                    k: None,
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

    #[tokio::test]
    async fn login_bind_and_lookup_roundtrip() {
        let state = AppState::new(LimitsConfig::default());
        let (tx, _rx) = channel();
        let conn = state.register_connection(test_ip(70), tx).await;
        let keypair = generate_identity_keypair();
        let ik_ed25519 = keypair_public_b64u(&keypair);

        state
            .publish_prekeys(
                conn,
                test_ip(70),
                sample_prekey_publish_with_ik(ik_ed25519.clone(), &[1]),
            )
            .await
            .expect("prekey publish should pass");

        let bound = state
            .bind_login(conn, signed_login_bind_request("@Mike", &keypair))
            .await
            .expect("login bind should pass");
        assert_eq!(bound.login, "mike");
        assert_eq!(bound.ik_ed25519, ik_ed25519);

        let by_login = state
            .lookup_login(LoginLookupRequest {
                login: Some("mike".to_string()),
                ik_ed25519: None,
            })
            .await
            .expect("lookup by login should pass");
        assert_eq!(by_login.login, "mike");

        let by_ik = state
            .lookup_login(LoginLookupRequest {
                login: None,
                ik_ed25519: Some(bound.ik_ed25519),
            })
            .await
            .expect("lookup by ik should pass");
        assert_eq!(by_ik.login, "mike");
    }

    #[tokio::test]
    async fn login_bind_rejects_taken_login() {
        let state = AppState::new(LimitsConfig::default());
        let (tx_a, _rx_a) = channel();
        let (tx_b, _rx_b) = channel();
        let conn_a = state.register_connection(test_ip(71), tx_a).await;
        let conn_b = state.register_connection(test_ip(72), tx_b).await;
        let key_a = generate_identity_keypair();
        let key_b = generate_identity_keypair();

        state
            .publish_prekeys(
                conn_a,
                test_ip(71),
                sample_prekey_publish_with_ik(keypair_public_b64u(&key_a), &[1]),
            )
            .await
            .expect("prekey publish A should pass");
        state
            .publish_prekeys(
                conn_b,
                test_ip(72),
                sample_prekey_publish_with_ik(keypair_public_b64u(&key_b), &[2]),
            )
            .await
            .expect("prekey publish B should pass");

        state
            .bind_login(conn_a, signed_login_bind_request("mike", &key_a))
            .await
            .expect("first bind should pass");

        let err = state
            .bind_login(conn_b, signed_login_bind_request("mike", &key_b))
            .await
            .expect_err("second bind should fail");
        assert_eq!(err, LoginBindError::LoginTaken);
    }

    #[tokio::test]
    async fn login_bind_rejects_signature_mismatch() {
        let state = AppState::new(LimitsConfig::default());
        let (tx, _rx) = channel();
        let conn = state.register_connection(test_ip(73), tx).await;
        let legit = generate_identity_keypair();
        let attacker = generate_identity_keypair();
        let legit_ik = keypair_public_b64u(&legit);

        state
            .publish_prekeys(
                conn,
                test_ip(73),
                sample_prekey_publish_with_ik(legit_ik.clone(), &[1]),
            )
            .await
            .expect("prekey publish should pass");

        let mut forged = signed_login_bind_request("mike", &attacker);
        forged.ik_ed25519 = legit_ik;

        let err = state
            .bind_login(conn, forged)
            .await
            .expect_err("forged signature should fail");
        assert_eq!(err, LoginBindError::KeyMismatch);
    }

    #[test]
    fn token_generation_matches_base32_contract() {
        let token = generate_token(TOKEN_MAX_LEN);
        assert_eq!(token.len(), TOKEN_MAX_LEN);
        assert!(token.chars().all(|c| matches!(c, 'A'..='Z' | '2'..='7')));
    }
}
