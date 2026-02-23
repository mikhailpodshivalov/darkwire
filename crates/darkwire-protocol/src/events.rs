use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub mod names {
    pub const INVITE_CREATE: &str = "invite.create";
    pub const INVITE_USE: &str = "invite.use";
    pub const MSG_SEND: &str = "msg.send";
    pub const SESSION_LEAVE: &str = "session.leave";
    pub const PING: &str = "ping";

    pub const READY: &str = "ready";
    pub const INVITE_CREATED: &str = "invite.created";
    pub const SESSION_STARTED: &str = "session.started";
    pub const MSG_RECV: &str = "msg.recv";
    pub const SESSION_ENDED: &str = "session.ended";
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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InviteUseRequest {
    pub invite: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MsgSendRequest {
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SessionLeaveRequest {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PingRequest {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReadyEvent {
    pub server_time: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InviteCreatedEvent {
    pub invite: String,
    pub expires_in: u32,
}

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
#[serde(rename_all = "snake_case")]
pub enum RateLimitScope {
    InviteCreate,
    InviteUse,
    MsgSend,
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
    NoActiveSession,
    MessageTooLarge,
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
}
