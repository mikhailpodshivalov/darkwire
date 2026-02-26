use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub mod names {
    pub const INVITE_CREATE: &str = "invite.create";
    pub const INVITE_USE: &str = "invite.use";
    pub const LOGIN_BIND: &str = "login.bind";
    pub const LOGIN_LOOKUP: &str = "login.lookup";
    pub const MSG_SEND: &str = "msg.send";
    pub const E2E_MSG_SEND: &str = "e2e.msg.send";
    pub const SESSION_LEAVE: &str = "session.leave";
    pub const PING: &str = "ping";
    pub const E2E_PREKEY_PUBLISH: &str = "e2e.prekey.publish";
    pub const E2E_PREKEY_GET: &str = "e2e.prekey.get";
    pub const E2E_HANDSHAKE_INIT: &str = "e2e.handshake.init";
    pub const E2E_HANDSHAKE_ACCEPT: &str = "e2e.handshake.accept";

    pub const READY: &str = "ready";
    pub const INVITE_CREATED: &str = "invite.created";
    pub const INVITE_USED: &str = "invite.used";
    pub const LOGIN_BOUND: &str = "login.bound";
    pub const LOGIN_BINDING: &str = "login.binding";
    pub const SESSION_STARTED: &str = "session.started";
    pub const MSG_RECV: &str = "msg.recv";
    pub const E2E_MSG_RECV: &str = "e2e.msg.recv";
    pub const SESSION_ENDED: &str = "session.ended";
    pub const E2E_PREKEY_PUBLISHED: &str = "e2e.prekey.published";
    pub const E2E_PREKEY_BUNDLE: &str = "e2e.prekey.bundle";
    pub const E2E_HANDSHAKE_INIT_RECV: &str = "e2e.handshake.init.recv";
    pub const E2E_HANDSHAKE_ACCEPT_RECV: &str = "e2e.handshake.accept.recv";
    pub const RATE_LIMITED: &str = "rate.limited";
    pub const ERROR: &str = "error";
    pub const PONG: &str = "pong";
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Envelope<T> {
    #[serde(rename = "t")]
    pub event_type: String,
    #[serde(rename = "rid", skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(rename = "d")]
    pub data: T,
}

impl<T> Envelope<T> {
    pub fn new(event_type: impl Into<String>, data: T) -> Self {
        Self {
            event_type: event_type.into(),
            request_id: None,
            data,
        }
    }

    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InviteCreateRequest {
    pub r: Vec<String>,
    pub e: u32,
    pub o: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub k: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InviteUseRequest {
    pub invite: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoginBindRequest {
    pub login: String,
    pub ik_ed25519: String,
    pub sig_ed25519: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoginLookupRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ik_ed25519: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MsgSendRequest {
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct E2eMsgAd {
    pub pv: u8,
    pub session_id: Uuid,
    pub n: u64,
    pub pn: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct E2eMsgSendRequest {
    pub session_id: Uuid,
    pub n: u64,
    pub pn: u64,
    pub dh_x25519: String,
    pub nonce: String,
    pub ct: String,
    pub ad: E2eMsgAd,
}

pub type E2eMsgRecvEvent = E2eMsgSendRequest;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SessionLeaveRequest {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PingRequest {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedPrekey {
    pub id: u32,
    pub x25519: String,
    pub sig_ed25519: String,
    pub exp_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OneTimePrekey {
    pub id: u32,
    pub x25519: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrekeyPublishRequest {
    pub ik_ed25519: String,
    pub spk: SignedPrekey,
    pub opks: Vec<OneTimePrekey>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrekeyGetRequest {
    pub session_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HandshakeInitRequest {
    pub session_id: Uuid,
    pub hs_id: Uuid,
    pub sender_ik_ed25519: String,
    pub sender_eph_x25519: String,
    pub peer_spk_id: u32,
    pub peer_opk_id: Option<u32>,
    pub sig_ed25519: String,
    pub ts_unix: u64,
}

pub type HandshakeInitRecvEvent = HandshakeInitRequest;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HandshakeAcceptRequest {
    pub session_id: Uuid,
    pub hs_id: Uuid,
    pub responder_ik_ed25519: String,
    pub responder_eph_x25519: String,
    pub sig_ed25519: String,
    pub kc: String,
}

pub type HandshakeAcceptRecvEvent = HandshakeAcceptRequest;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReadyEvent {
    pub server_time: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InviteCreatedEvent {
    pub invite: String,
    pub expires_in: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct InviteUsedEvent {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoginBindingEvent {
    pub login: String,
    pub ik_ed25519: String,
}

pub type LoginBoundEvent = LoginBindingEvent;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionStartedEvent {
    pub session_id: Uuid,
    pub peer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MsgRecvEvent {
    pub session_id: Uuid,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionEndReason {
    PeerDisconnect,
    IdleTimeout,
    PeerQuit,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionEndedEvent {
    pub session_id: Uuid,
    pub reason: SessionEndReason,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrekeyPublishedEvent {
    pub spk_id: u32,
    pub opk_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicPrekeyBundle {
    pub ik_ed25519: String,
    pub spk: SignedPrekey,
    pub opk: Option<OneTimePrekey>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrekeyBundleEvent {
    pub session_id: Uuid,
    pub peer: PublicPrekeyBundle,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitScope {
    InviteCreate,
    InviteUse,
    MsgSend,
    PrekeyPublish,
    PrekeyGet,
    Handshake,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RateLimitedEvent {
    pub scope: RateLimitScope,
    pub retry_after_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    BadRequest,
    InvalidInvite,
    InviteExpired,
    InviteUsed,
    LoginInvalid,
    LoginTaken,
    LoginNotFound,
    LoginKeyMismatch,
    NoActiveSession,
    MessageTooLarge,
    UnsupportedProtocol,
    E2eRequired,
    PrekeyNotFound,
    PrekeyDepleted,
    HandshakeInvalid,
    HandshakeTimeout,
    DecryptFailed,
    ReplayDetected,
    IdentityKeyChanged,
    StateConflict,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorEvent {
    pub code: ErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PongEvent {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_serializes_as_wire_shape() {
        let msg = Envelope::new(
            names::INVITE_USE,
            InviteUseRequest {
                invite: "DL1:abc.def".to_string(),
            },
        )
        .with_request_id("req-1");

        let raw = serde_json::to_value(&msg).expect("serialize envelope");

        assert_eq!(raw["t"], names::INVITE_USE);
        assert_eq!(raw["rid"], "req-1");
        assert_eq!(raw["d"]["invite"], "DL1:abc.def");
    }

    #[test]
    fn e2e_msg_envelope_serializes_expected_fields() {
        let session_id = Uuid::new_v4();
        let msg = Envelope::new(
            names::E2E_MSG_SEND,
            E2eMsgSendRequest {
                session_id,
                n: 1,
                pn: 0,
                dh_x25519: "a".repeat(43),
                nonce: "b".repeat(16),
                ct: "c".repeat(24),
                ad: E2eMsgAd {
                    pv: 2,
                    session_id,
                    n: 1,
                    pn: 0,
                },
            },
        )
        .with_request_id("req-e2e");

        let raw = serde_json::to_value(&msg).expect("serialize envelope");
        assert_eq!(raw["t"], names::E2E_MSG_SEND);
        assert_eq!(raw["rid"], "req-e2e");
        assert_eq!(raw["d"]["session_id"], session_id.to_string());
        assert_eq!(raw["d"]["ad"]["pv"], 2);
    }
}
