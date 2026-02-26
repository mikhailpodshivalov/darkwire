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
    InviteCreated {
        request_id: Option<String>,
        invite: String,
    },
    SessionStarted {
        session_id: Uuid,
    },
    SessionEnded,
    PrekeyBundle(PrekeyBundleEvent),
    HandshakeInitRecv(HandshakeInitRequest),
    HandshakeAcceptRecv(HandshakeAcceptRequest),
    EncryptedMessage(E2eMsgRecvEvent),
    LoginBound {
        request_id: Option<String>,
        event: LoginBindingEvent,
    },
    LoginBinding {
        request_id: Option<String>,
        event: LoginBindingEvent,
    },
    Error {
        request_id: Option<String>,
        event: ErrorEvent,
    },
    RateLimited {
        request_id: Option<String>,
        event: RateLimitedEvent,
    },
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
    let request_id = envelope.request_id.clone();
    match envelope.event_type.as_str() {
        events::names::INVITE_CREATED => {
            serde_json::from_value::<InviteCreatedEvent>(envelope.data)
                .ok()
                .map(|event| WireAction::InviteCreated {
                    request_id,
                    invite: event.invite,
                })
        }
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
            .map(|event| WireAction::LoginBound { request_id, event }),
        events::names::LOGIN_BINDING => serde_json::from_value::<LoginBindingEvent>(envelope.data)
            .ok()
            .map(|event| WireAction::LoginBinding { request_id, event }),
        events::names::ERROR => serde_json::from_value::<ErrorEvent>(envelope.data)
            .ok()
            .map(|event| WireAction::Error { request_id, event }),
        events::names::RATE_LIMITED => serde_json::from_value::<RateLimitedEvent>(envelope.data)
            .ok()
            .map(|event| WireAction::RateLimited { request_id, event }),
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
            if serde_json::from_value::<E2eMsgRecvEvent>(envelope.data).is_err() {
                return Some(format!("[e2e:{rid}] invalid encrypted payload from server"));
            }
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
                if matches!(
                    event.code,
                    ErrorCode::LoginNotFound
                        | ErrorCode::LoginTaken
                        | ErrorCode::LoginInvalid
                        | ErrorCode::LoginKeyMismatch
                ) {
                    return None;
                }

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

#[cfg(test)]
mod tests {
    use super::*;
    use darkwire_protocol::events::{
        Envelope, ErrorEvent, InviteCreatedEvent, LoginBindingEvent, RateLimitScope,
        RateLimitedEvent, SessionStartedEvent,
    };

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
    fn extract_wire_action_invite_created_contains_invite_code() {
        let raw = serde_json::to_string(
            &Envelope::new(
                events::names::INVITE_CREATED,
                InviteCreatedEvent {
                    invite: "DL1:abc.def".to_string(),
                    expires_in: 600,
                },
            )
            .with_request_id("cli-9".to_string()),
        )
        .expect("serialize");

        match extract_wire_action(&raw) {
            Some(WireAction::InviteCreated { request_id, invite }) => {
                assert_eq!(request_id.as_deref(), Some("cli-9"));
                assert_eq!(invite, "DL1:abc.def");
            }
            other => panic!("unexpected action: {other:?}"),
        }
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
    fn extract_wire_action_rate_limited_parses_scope_and_retry() {
        let raw = serde_json::to_string(
            &Envelope::new(
                events::names::RATE_LIMITED,
                RateLimitedEvent {
                    scope: RateLimitScope::MsgSend,
                    retry_after_ms: 34,
                },
            )
            .with_request_id("cli-77"),
        )
        .expect("serialize");

        match extract_wire_action(&raw) {
            Some(WireAction::RateLimited { request_id, event }) => {
                assert_eq!(request_id.as_deref(), Some("cli-77"));
                assert_eq!(event.scope, RateLimitScope::MsgSend);
                assert_eq!(event.retry_after_ms, 34);
            }
            other => panic!("unexpected action: {other:?}"),
        }
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
            Some(WireAction::LoginBinding { .. })
        ));

        let mut state = ClientState::default();
        assert!(handle_server_text(&raw, &mut state).is_none());
    }

    #[test]
    fn login_errors_are_suppressed_for_runtime_handling() {
        let raw = serde_json::to_string(
            &Envelope::new(
                events::names::ERROR,
                ErrorEvent {
                    code: ErrorCode::LoginNotFound,
                    message: "login binding not found".to_string(),
                },
            )
            .with_request_id("cli-3"),
        )
        .expect("serialize error envelope");

        let mut state = ClientState::default();
        assert!(handle_server_text(&raw, &mut state).is_none());
        assert!(matches!(
            extract_wire_action(&raw),
            Some(WireAction::Error { .. })
        ));
    }

    #[test]
    fn malformed_e2e_payload_surfaces_warning_line() {
        let raw = serde_json::json!({
            "pv": 2,
            "t": events::names::E2E_MSG_RECV,
            "rid": "srv-7",
            "d": {
                "session_id": Uuid::new_v4(),
                "n": 1,
                "pn": 0
            }
        })
        .to_string();

        let mut state = ClientState::default();
        let line = handle_server_text(&raw, &mut state).expect("warning line");
        assert!(line.contains("invalid encrypted payload"));
    }
}
