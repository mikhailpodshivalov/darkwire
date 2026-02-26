use darkwire_protocol::events::{
    self, E2eMsgRecvEvent, ErrorCode, ErrorEvent, HandshakeAcceptRequest, HandshakeInitRequest,
    InviteCreatedEvent, LoginBindingEvent, MsgRecvEvent, PrekeyBundleEvent, PrekeyPublishedEvent,
    RateLimitedEvent, ReadyEvent, SessionEndReason, SessionEndedEvent, SessionStartedEvent,
};
use serde::Deserialize;
use uuid::Uuid;

#[derive(Debug, Default)]
pub struct ClientState {
    pub active_session: bool,
    pub active_session_id: Option<Uuid>,
    pub secure_active: bool,
    pub should_initiate_handshake: bool,
}

#[derive(Debug, Clone)]
pub enum WireAction {
    SessionStarted { session_id: Uuid },
    SessionEnded,
    PrekeyBundle(PrekeyBundleEvent),
    HandshakeInitRecv(HandshakeInitRequest),
    HandshakeAcceptRecv(HandshakeAcceptRequest),
    EncryptedMessage(E2eMsgRecvEvent),
    LoginBound(LoginBindingEvent),
    LoginBinding(LoginBindingEvent),
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

pub fn extract_wire_action(raw: &str) -> Option<WireAction> {
    let envelope: IncomingEnvelope = serde_json::from_str(raw).ok()?;
    match envelope.event_type.as_str() {
        events::names::SESSION_STARTED => {
            serde_json::from_value::<SessionStartedEvent>(envelope.data)
                .ok()
                .map(|event| WireAction::SessionStarted {
                    session_id: event.session_id,
                })
        }
        events::names::SESSION_ENDED => Some(WireAction::SessionEnded),
        events::names::E2E_PREKEY_BUNDLE => {
            serde_json::from_value::<PrekeyBundleEvent>(envelope.data)
                .ok()
                .map(WireAction::PrekeyBundle)
        }
        events::names::E2E_HANDSHAKE_INIT_RECV => {
            serde_json::from_value::<HandshakeInitRequest>(envelope.data)
                .ok()
                .map(WireAction::HandshakeInitRecv)
        }
        events::names::E2E_HANDSHAKE_ACCEPT_RECV => {
            serde_json::from_value::<HandshakeAcceptRequest>(envelope.data)
                .ok()
                .map(WireAction::HandshakeAcceptRecv)
        }
        events::names::E2E_MSG_RECV => serde_json::from_value::<E2eMsgRecvEvent>(envelope.data)
            .ok()
            .map(WireAction::EncryptedMessage),
        events::names::LOGIN_BOUND => serde_json::from_value::<LoginBindingEvent>(envelope.data)
            .ok()
            .map(WireAction::LoginBound),
        events::names::LOGIN_BINDING => serde_json::from_value::<LoginBindingEvent>(envelope.data)
            .ok()
            .map(WireAction::LoginBinding),
        _ => None,
    }
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
                state.active_session_id = Some(event.session_id);
                state.secure_active = false;
                state.should_initiate_handshake = envelope.request_id.is_some();
                return Some(format!("[session:{rid}] started id={}", event.session_id));
            }
        }
        events::names::E2E_PREKEY_PUBLISHED => {
            if let Ok(event) = serde_json::from_value::<PrekeyPublishedEvent>(envelope.data) {
                return Some(format!(
                    "[keys:{rid}] published spk_id={} opk_count={}",
                    event.spk_id, event.opk_count
                ));
            }
        }
        events::names::E2E_PREKEY_BUNDLE => {
            if let Ok(event) = serde_json::from_value::<PrekeyBundleEvent>(envelope.data) {
                return Some(format!(
                    "[e2e:{rid}] peer_bundle session_id={} opk={}",
                    event.session_id,
                    if event.peer.opk.is_some() {
                        "present"
                    } else {
                        "none"
                    }
                ));
            }
        }
        events::names::E2E_HANDSHAKE_INIT_RECV => {
            if let Ok(event) = serde_json::from_value::<HandshakeInitRequest>(envelope.data) {
                return Some(format!(
                    "[e2e:{rid}] handshake.init.recv session_id={} hs_id={}",
                    event.session_id, event.hs_id
                ));
            }
        }
        events::names::E2E_HANDSHAKE_ACCEPT_RECV => {
            if let Ok(event) = serde_json::from_value::<HandshakeAcceptRequest>(envelope.data) {
                return Some(format!(
                    "[e2e:{rid}] handshake.accept.recv session_id={} hs_id={}",
                    event.session_id, event.hs_id
                ));
            }
        }
        events::names::MSG_RECV => {
            if let Ok(event) = serde_json::from_value::<MsgRecvEvent>(envelope.data) {
                return Some(format!("peer> {}", event.text));
            }
        }
        events::names::E2E_MSG_RECV => {
            return None;
        }
        events::names::LOGIN_BOUND | events::names::LOGIN_BINDING => {
            let _ = envelope.data;
            return None;
        }
        events::names::SESSION_ENDED => {
            if let Ok(event) = serde_json::from_value::<SessionEndedEvent>(envelope.data) {
                state.active_session = false;
                state.active_session_id = None;
                state.secure_active = false;
                state.should_initiate_handshake = false;
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
                return Some(match event.code {
                    ErrorCode::LoginNotFound => {
                        "[login] who am i? set your login with /login set @name".to_string()
                    }
                    ErrorCode::LoginTaken => {
                        "[login] this login is already taken by another identity key".to_string()
                    }
                    ErrorCode::LoginInvalid => {
                        "[login] invalid login request. Use /login set @name".to_string()
                    }
                    ErrorCode::LoginKeyMismatch => {
                        "[login] signature or identity mismatch. Try /keys and /login set again"
                            .to_string()
                    }
                    _ => format!(
                        "[error:{rid}] code={:?} message={}",
                        event.code, event.message
                    ),
                });
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

#[cfg(test)]
mod tests {
    use super::*;
    use darkwire_protocol::events::{Envelope, LoginBindingEvent, SessionStartedEvent};

    #[test]
    fn session_started_with_request_id_marks_local_initiator() {
        let mut state = ClientState::default();
        let raw = serde_json::to_string(
            &Envelope::new(
                events::names::SESSION_STARTED,
                SessionStartedEvent {
                    session_id: Uuid::new_v4(),
                    peer: "anon".to_string(),
                },
            )
            .with_request_id("cli-3"),
        )
        .expect("serialize envelope");

        let _ = handle_server_text(&raw, &mut state);
        assert!(state.should_initiate_handshake);
    }

    #[test]
    fn session_started_without_request_id_waits_for_peer_handshake() {
        let mut state = ClientState::default();
        let raw = serde_json::to_string(&Envelope::new(
            events::names::SESSION_STARTED,
            SessionStartedEvent {
                session_id: Uuid::new_v4(),
                peer: "anon".to_string(),
            },
        ))
        .expect("serialize envelope");

        let _ = handle_server_text(&raw, &mut state);
        assert!(!state.should_initiate_handshake);
    }

    #[test]
    fn login_binding_extracts_action_and_avoids_generic_output() {
        let raw = serde_json::to_string(&Envelope::new(
            events::names::LOGIN_BINDING,
            LoginBindingEvent {
                login: "mike".to_string(),
                ik_ed25519: "ik_b64u".to_string(),
            },
        ))
        .expect("serialize login.binding envelope");

        assert!(matches!(
            extract_wire_action(&raw),
            Some(WireAction::LoginBinding(_))
        ));

        let mut state = ClientState::default();
        assert!(handle_server_text(&raw, &mut state).is_none());
    }
}
