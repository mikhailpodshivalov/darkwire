mod e2e;
mod login;
mod outgoing;
mod parse;

use crate::app_state::{ConnId, InviteCreateError, InviteUseError, SharedState};
use crate::logging;
use axum::{
    extract::{
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, State,
    },
    response::IntoResponse,
};
use darkwire_protocol::events::{
    self, ErrorCode, InviteCreateRequest, InviteUseRequest, RateLimitScope, SessionEndReason,
    SessionLeaveRequest, SessionStartedEvent,
};
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::{
    sync::mpsc,
    time::{self, MissedTickBehavior},
};
use tracing::{debug, info, warn};

use outgoing::{
    encode_event, queue_session_ended, send_error, send_invite_created, send_invite_used,
    send_pong, send_rate_limited, send_ready, send_session_ended, send_session_started,
};
use parse::parse_incoming_envelope;

const OUTBOUND_BUFFER: usize = 64;

pub async fn ws_upgrade(
    State(state): State<SharedState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    let ip = peer_addr.ip();
    ws.on_upgrade(move |socket| handle_socket(socket, state, ip))
}

async fn handle_socket(mut socket: WebSocket, state: SharedState, ip: IpAddr) {
    let (outbound_tx, mut outbound_rx) = mpsc::channel(OUTBOUND_BUFFER);
    let conn_id = state.register_connection(ip, outbound_tx).await;
    info!(%conn_id, %ip, "connection.opened");

    if let Err(err) = send_ready(&mut socket).await {
        warn!(%conn_id, %ip, err = %err, "connection.ready_send_failed");
        state
            .unregister_connection(conn_id, SessionEndReason::PeerDisconnect)
            .await;
        return;
    }

    let mut disconnect_reason = SessionEndReason::PeerDisconnect;
    let idle_timeout = state.limits().idle_timeout();
    let mut idle_tick = time::interval(Duration::from_secs(5));
    idle_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = idle_tick.tick() => {
                let snapshot = match state.get_connection(conn_id).await {
                    Some(snapshot) => snapshot,
                    None => break,
                };

                if snapshot.last_activity.elapsed() >= idle_timeout {
                    disconnect_reason = SessionEndReason::IdleTimeout;
                    info!(
                        %conn_id,
                        ip = %snapshot.ip,
                        connected_for_secs = snapshot.connected_at.elapsed().as_secs(),
                        idle_timeout_secs = idle_timeout.as_secs(),
                        "connection.idle_timeout"
                    );
                    let _ = socket
                        .send(Message::Close(Some(CloseFrame {
                            code: 1000,
                            reason: "idle_timeout".into(),
                        })))
                        .await;
                    break;
                }
            }
            outbound = outbound_rx.recv() => {
                match outbound {
                    Some(payload) => {
                        if let Err(err) = socket.send(Message::Text(payload.into())).await {
                            warn!(%conn_id, err = %err, "connection.outbound_send_failed");
                            break;
                        }
                    }
                    None => break,
                }
            }
            frame = socket.recv() => {
                match frame {
                    Some(Ok(message)) => {
                        if !handle_message(&mut socket, &state, conn_id, ip, message).await {
                            break;
                        }
                    }
                    Some(Err(err)) => {
                        warn!(%conn_id, err = %err, "connection.read_failed");
                        break;
                    }
                    None => break,
                }
            }
        }
    }

    let outcome = state
        .unregister_connection(conn_id, disconnect_reason.clone())
        .await;
    let total = state.active_connection_count().await;

    if let Some(peer_ended) = outcome.peer_ended {
        let _ = queue_session_ended(&state, peer_ended).await;
    }

    if let Some(removed) = outcome.connection {
        info!(
            conn_id = %removed.id,
            ip = %removed.ip,
            connected_for_secs = removed.connected_at.elapsed().as_secs(),
            active_connections = total,
            "connection.closed"
        );
    } else {
        debug!(%conn_id, "connection.already_removed");
    }
}

async fn handle_message(
    socket: &mut WebSocket,
    state: &SharedState,
    conn_id: ConnId,
    ip: IpAddr,
    message: Message,
) -> bool {
    let _ = state.touch_connection(conn_id).await;

    match message {
        Message::Text(raw) => handle_text_message(socket, state, conn_id, ip, &raw).await,
        Message::Binary(_) => true,
        Message::Ping(payload) => {
            if let Err(err) = socket.send(Message::Pong(payload)).await {
                warn!(%conn_id, err = %err, "connection.ws_pong_send_failed");
                return false;
            }
            true
        }
        Message::Pong(_) => true,
        Message::Close(_) => false,
    }
}

async fn handle_text_message(
    socket: &mut WebSocket,
    state: &SharedState,
    conn_id: ConnId,
    ip: IpAddr,
    raw: &str,
) -> bool {
    let payload_bytes = raw.len();
    let incoming = match parse_incoming_envelope(raw) {
        Some(incoming) => {
            logging::log_inbound_event(
                conn_id,
                &incoming.event_type,
                incoming.request_id.as_deref(),
                payload_bytes,
            );
            incoming
        }
        None => {
            logging::log_invalid_json(conn_id, payload_bytes);
            return send_error(
                socket,
                None,
                ErrorCode::BadRequest,
                "invalid JSON envelope",
                conn_id,
            )
            .await;
        }
    };

    let request_id = incoming.request_id;
    if let Some(violation) = protocol_violation(&incoming.event_type, incoming.protocol_version) {
        return send_error(
            socket,
            request_id,
            violation.code(),
            violation.message(),
            conn_id,
        )
        .await;
    }

    match incoming.event_type.as_str() {
        events::names::PING => send_pong(socket, request_id, conn_id).await,
        events::names::INVITE_CREATE => {
            let request: InviteCreateRequest = match serde_json::from_value(incoming.data) {
                Ok(request) => request,
                Err(_) => {
                    return send_error(
                        socket,
                        request_id,
                        ErrorCode::BadRequest,
                        "invalid invite.create payload",
                        conn_id,
                    )
                    .await;
                }
            };

            match state.create_invite(conn_id, ip, request).await {
                Ok(created) => send_invite_created(socket, request_id, created, conn_id).await,
                Err(InviteCreateError::RateLimited(hit)) => {
                    send_rate_limited(
                        socket,
                        request_id,
                        RateLimitScope::InviteCreate,
                        hit.retry_after,
                        conn_id,
                    )
                    .await
                }
                Err(InviteCreateError::InvalidRequest) => {
                    send_error(
                        socket,
                        request_id,
                        ErrorCode::BadRequest,
                        "invalid invite.create payload",
                        conn_id,
                    )
                    .await
                }
                Err(InviteCreateError::PeerOffline) => {
                    send_error(
                        socket,
                        request_id,
                        ErrorCode::BadRequest,
                        "connection is offline",
                        conn_id,
                    )
                    .await
                }
            }
        }
        events::names::INVITE_USE => {
            let request: InviteUseRequest = match serde_json::from_value(incoming.data) {
                Ok(request) => request,
                Err(_) => {
                    return send_error(
                        socket,
                        request_id,
                        ErrorCode::BadRequest,
                        "invalid invite.use payload",
                        conn_id,
                    )
                    .await;
                }
            };

            match state.use_invite(conn_id, ip, request).await {
                Ok(joined) => {
                    if !send_invite_used(socket, request_id.clone(), conn_id).await {
                        return false;
                    }

                    if !send_session_started(socket, request_id, joined.session_id, conn_id).await {
                        return false;
                    }

                    let peer_started = encode_event(
                        events::names::SESSION_STARTED,
                        None,
                        SessionStartedEvent {
                            session_id: joined.session_id,
                            peer: "anon".to_string(),
                        },
                    );

                    if !state
                        .send_to_connection(joined.creator_conn, peer_started)
                        .await
                    {
                        if let Some(ended) = state
                            .end_session_for_conn(conn_id, SessionEndReason::PeerDisconnect)
                            .await
                        {
                            let _ = send_session_ended(
                                socket,
                                None,
                                ended.session_id,
                                SessionEndReason::PeerDisconnect,
                                conn_id,
                            )
                            .await;
                        }
                    }

                    true
                }
                Err(InviteUseError::RateLimited(hit)) => {
                    send_rate_limited(
                        socket,
                        request_id,
                        RateLimitScope::InviteUse,
                        hit.retry_after,
                        conn_id,
                    )
                    .await
                }
                Err(InviteUseError::InvalidInvite) => {
                    send_error(
                        socket,
                        request_id,
                        ErrorCode::InvalidInvite,
                        "invite is invalid or unknown",
                        conn_id,
                    )
                    .await
                }
                Err(InviteUseError::InviteExpired) => {
                    send_error(
                        socket,
                        request_id,
                        ErrorCode::InviteExpired,
                        "invite has expired",
                        conn_id,
                    )
                    .await
                }
                Err(InviteUseError::InviteUsed) => {
                    send_error(
                        socket,
                        request_id,
                        ErrorCode::InviteUsed,
                        "invite was already used",
                        conn_id,
                    )
                    .await
                }
                Err(InviteUseError::PeerOffline) => {
                    send_error(
                        socket,
                        request_id,
                        ErrorCode::InvalidInvite,
                        "invite peer is offline",
                        conn_id,
                    )
                    .await
                }
                Err(InviteUseError::SessionBusy) => {
                    send_error(
                        socket,
                        request_id,
                        ErrorCode::BadRequest,
                        "session already active",
                        conn_id,
                    )
                    .await
                }
            }
        }
        events::names::LOGIN_BIND => {
            login::handle_login_bind(socket, state, conn_id, request_id, incoming.data).await
        }
        events::names::LOGIN_LOOKUP => {
            login::handle_login_lookup(socket, state, conn_id, request_id, incoming.data).await
        }
        events::names::E2E_PREKEY_PUBLISH => {
            e2e::handle_prekey_publish(socket, state, conn_id, ip, request_id, incoming.data).await
        }
        events::names::E2E_PREKEY_GET => {
            e2e::handle_prekey_get(socket, state, conn_id, ip, request_id, incoming.data).await
        }
        events::names::E2E_HANDSHAKE_INIT => {
            e2e::handle_handshake_init(socket, state, conn_id, ip, request_id, incoming.data).await
        }
        events::names::E2E_HANDSHAKE_ACCEPT => {
            e2e::handle_handshake_accept(socket, state, conn_id, ip, request_id, incoming.data)
                .await
        }
        events::names::E2E_MSG_SEND => {
            e2e::handle_encrypted_message(socket, state, conn_id, ip, request_id, incoming.data)
                .await
        }
        events::names::SESSION_LEAVE => {
            let _: SessionLeaveRequest = match serde_json::from_value(incoming.data) {
                Ok(request) => request,
                Err(_) => {
                    return send_error(
                        socket,
                        request_id,
                        ErrorCode::BadRequest,
                        "invalid session.leave payload",
                        conn_id,
                    )
                    .await;
                }
            };

            match state
                .end_session_for_conn(conn_id, SessionEndReason::PeerQuit)
                .await
            {
                Some(ended) => {
                    if !send_session_ended(
                        socket,
                        request_id,
                        ended.session_id,
                        SessionEndReason::PeerQuit,
                        conn_id,
                    )
                    .await
                    {
                        return false;
                    }

                    let _ = queue_session_ended(state, ended).await;
                    true
                }
                None => {
                    send_error(
                        socket,
                        request_id,
                        ErrorCode::NoActiveSession,
                        "no active session",
                        conn_id,
                    )
                    .await
                }
            }
        }
        _ => {
            send_error(
                socket,
                request_id,
                ErrorCode::BadRequest,
                "unsupported event type",
                conn_id,
            )
            .await
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProtocolViolation {
    UnsupportedE2eVersion,
    PlaintextDisabled,
}

impl ProtocolViolation {
    fn code(self) -> ErrorCode {
        match self {
            Self::UnsupportedE2eVersion => ErrorCode::UnsupportedProtocol,
            Self::PlaintextDisabled => ErrorCode::E2eRequired,
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::UnsupportedE2eVersion => {
                "unsupported protocol version for e2e event; expected pv=2"
            }
            Self::PlaintextDisabled => "plaintext messaging disabled; use e2e.msg.send",
        }
    }
}

fn protocol_violation(event_type: &str, protocol_version: Option<u8>) -> Option<ProtocolViolation> {
    if event_type.starts_with("e2e.") && protocol_version != Some(2) {
        return Some(ProtocolViolation::UnsupportedE2eVersion);
    }

    if event_type == events::names::MSG_SEND {
        return Some(ProtocolViolation::PlaintextDisabled);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_violation_rejects_e2e_without_v2() {
        assert_eq!(
            protocol_violation(events::names::E2E_PREKEY_GET, None),
            Some(ProtocolViolation::UnsupportedE2eVersion)
        );
        assert_eq!(
            protocol_violation(events::names::E2E_PREKEY_GET, Some(1)),
            Some(ProtocolViolation::UnsupportedE2eVersion)
        );
    }

    #[test]
    fn protocol_violation_rejects_plaintext_event() {
        assert_eq!(
            protocol_violation(events::names::MSG_SEND, Some(2)),
            Some(ProtocolViolation::PlaintextDisabled)
        );
    }

    #[test]
    fn protocol_violation_accepts_v2_e2e_and_non_e2e_events() {
        assert_eq!(
            protocol_violation(events::names::E2E_PREKEY_GET, Some(2)),
            None
        );
        assert_eq!(protocol_violation(events::names::PING, None), None);
    }
}
