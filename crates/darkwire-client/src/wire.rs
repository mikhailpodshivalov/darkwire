use darkwire_protocol::events::{
    self, ErrorEvent, InviteCreatedEvent, MsgRecvEvent, RateLimitedEvent, ReadyEvent,
    SessionEndReason, SessionEndedEvent, SessionStartedEvent,
};
use serde::Deserialize;

#[derive(Debug, Default)]
pub struct ClientState {
    pub active_session: bool,
}

#[derive(Debug, Deserialize)]
struct IncomingEnvelope {
    #[serde(rename = "t")]
    event_type: String,
    #[serde(rename = "rid")]
    request_id: Option<String>,
    #[serde(rename = "d", default)]
    data: serde_json::Value,
}

pub fn handle_server_text(raw: &str, state: &mut ClientState) -> Option<String> {
    let envelope: IncomingEnvelope = match serde_json::from_str(raw) {
        Ok(envelope) => envelope,
        Err(_) => {
            return Some("Received invalid JSON from server".to_string());
        }
    };

    let rid = envelope.request_id.as_deref().unwrap_or("-");

    match envelope.event_type.as_str() {
        events::names::READY => {
            if let Ok(event) = serde_json::from_value::<ReadyEvent>(envelope.data) {
                return Some(format!("[ready:{rid}] server_time={}", event.server_time));
            }
        }
        events::names::INVITE_CREATED => {
            if let Ok(event) = serde_json::from_value::<InviteCreatedEvent>(envelope.data) {
                return Some(format!("[invite:{rid}] {}", event.invite));
            }
        }
        events::names::INVITE_USED => {
            return Some(format!("[invite:{rid}] accepted"));
        }
        events::names::SESSION_STARTED => {
            if let Ok(event) = serde_json::from_value::<SessionStartedEvent>(envelope.data) {
                state.active_session = true;
                return Some(format!("[session:{rid}] started id={}", event.session_id));
            }
        }
        events::names::MSG_RECV => {
            if let Ok(event) = serde_json::from_value::<MsgRecvEvent>(envelope.data) {
                return Some(format!("peer> {}", event.text));
            }
        }
        events::names::SESSION_ENDED => {
            if let Ok(event) = serde_json::from_value::<SessionEndedEvent>(envelope.data) {
                state.active_session = false;
                return Some(format!(
                    "[session:{rid}] ended reason={}",
                    session_end_reason_name(event.reason)
                ));
            }
        }
        events::names::RATE_LIMITED => {
            if let Ok(event) = serde_json::from_value::<RateLimitedEvent>(envelope.data) {
                return Some(format!(
                    "[rate:{rid}] scope={} retry_after_ms={}",
                    rate_limit_scope_name(event.scope),
                    event.retry_after_ms
                ));
            }
        }
        events::names::ERROR => {
            if let Ok(event) = serde_json::from_value::<ErrorEvent>(envelope.data) {
                return Some(format!(
                    "[error:{rid}] code={:?} message={}",
                    event.code, event.message
                ));
            }
        }
        events::names::PONG => {
            let _ = envelope.data;
        }
        _ => {
            return Some(format!("[event:{rid}] {}", envelope.event_type));
        }
    }

    None
}

fn session_end_reason_name(reason: SessionEndReason) -> &'static str {
    match reason {
        SessionEndReason::PeerDisconnect => "peer_disconnect",
        SessionEndReason::IdleTimeout => "idle_timeout",
        SessionEndReason::PeerQuit => "peer_quit",
    }
}

fn rate_limit_scope_name(scope: darkwire_protocol::events::RateLimitScope) -> &'static str {
    match scope {
        darkwire_protocol::events::RateLimitScope::InviteCreate => "invite_create",
        darkwire_protocol::events::RateLimitScope::InviteUse => "invite_use",
        darkwire_protocol::events::RateLimitScope::MsgSend => "msg_send",
        darkwire_protocol::events::RateLimitScope::PrekeyPublish => "prekey_publish",
        darkwire_protocol::events::RateLimitScope::PrekeyGet => "prekey_get",
        darkwire_protocol::events::RateLimitScope::Handshake => "handshake",
    }
}
