use crate::app_state::{ConnId, InviteCreateError, InviteUseError, SharedState};
use axum::{
    extract::{
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, State,
    },
    response::IntoResponse,
};
use darkwire_protocol::events::{
    self, Envelope, ErrorCode, ErrorEvent, InviteCreateRequest, InviteCreatedEvent,
    InviteUseRequest, InviteUsedEvent, PongEvent, RateLimitScope, RateLimitedEvent, ReadyEvent,
};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, SocketAddr},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::{self, MissedTickBehavior};
use tracing::{debug, info, warn};

pub async fn ws_upgrade(
    State(state): State<SharedState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    let ip = peer_addr.ip();
    ws.on_upgrade(move |socket| handle_socket(socket, state, ip))
}

async fn handle_socket(mut socket: WebSocket, state: SharedState, ip: IpAddr) {
    let conn_id = state.register_connection(ip).await;
    info!(%conn_id, %ip, "connection.opened");

    if let Err(err) = send_ready(&mut socket).await {
        warn!(%conn_id, %ip, err = %err, "connection.ready_send_failed");
        state.unregister_connection(conn_id).await;
        return;
    }

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

    let removed = state.unregister_connection(conn_id).await;
    let total = state.active_connection_count().await;

    if let Some(removed) = removed {
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
    let incoming = match parse_incoming_envelope(raw) {
        Some(incoming) => incoming,
        None => {
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

            match state.use_invite(ip, request).await {
                Ok(_) => send_invite_used(socket, request_id, conn_id).await,
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

async fn send_ready(socket: &mut WebSocket) -> Result<(), axum::Error> {
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let ready = ReadyEvent {
        server_time: now_unix,
    };
    send_event(socket, events::names::READY, None, ready).await
}

async fn send_pong(socket: &mut WebSocket, request_id: Option<String>, conn_id: ConnId) -> bool {
    match send_event(
        socket,
        events::names::PONG,
        request_id,
        PongEvent::default(),
    )
    .await
    {
        Ok(()) => true,
        Err(err) => {
            warn!(%conn_id, err = %err, "connection.pong_send_failed");
            false
        }
    }
}

async fn send_invite_created(
    socket: &mut WebSocket,
    request_id: Option<String>,
    created: crate::app_state::InviteCreated,
    conn_id: ConnId,
) -> bool {
    let event = InviteCreatedEvent {
        invite: created.invite,
        expires_in: created.expires_in,
    };

    match send_event(socket, events::names::INVITE_CREATED, request_id, event).await {
        Ok(()) => true,
        Err(err) => {
            warn!(%conn_id, err = %err, "connection.invite_created_send_failed");
            false
        }
    }
}

async fn send_invite_used(
    socket: &mut WebSocket,
    request_id: Option<String>,
    conn_id: ConnId,
) -> bool {
    match send_event(
        socket,
        events::names::INVITE_USED,
        request_id,
        InviteUsedEvent::default(),
    )
    .await
    {
        Ok(()) => true,
        Err(err) => {
            warn!(%conn_id, err = %err, "connection.invite_used_send_failed");
            false
        }
    }
}

async fn send_rate_limited(
    socket: &mut WebSocket,
    request_id: Option<String>,
    scope: RateLimitScope,
    retry_after: Duration,
    conn_id: ConnId,
) -> bool {
    let event = RateLimitedEvent {
        scope,
        retry_after_ms: duration_to_ms(retry_after),
    };

    match send_event(socket, events::names::RATE_LIMITED, request_id, event).await {
        Ok(()) => true,
        Err(err) => {
            warn!(%conn_id, err = %err, "connection.rate_limited_send_failed");
            false
        }
    }
}

async fn send_error(
    socket: &mut WebSocket,
    request_id: Option<String>,
    code: ErrorCode,
    message: &str,
    conn_id: ConnId,
) -> bool {
    let event = ErrorEvent {
        code,
        message: message.to_string(),
    };

    match send_event(socket, events::names::ERROR, request_id, event).await {
        Ok(()) => true,
        Err(err) => {
            warn!(%conn_id, err = %err, "connection.error_send_failed");
            false
        }
    }
}

async fn send_event<T: Serialize>(
    socket: &mut WebSocket,
    event_type: &str,
    request_id: Option<String>,
    data: T,
) -> Result<(), axum::Error> {
    let mut envelope = Envelope::new(event_type, data);
    envelope.request_id = request_id;

    let raw = serde_json::to_string(&envelope).expect("serializing event should not fail");
    socket.send(Message::Text(raw.into())).await
}

fn duration_to_ms(duration: Duration) -> u64 {
    let millis = duration.as_millis();
    let millis = millis.clamp(1, u128::from(u64::MAX));
    millis as u64
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

fn parse_incoming_envelope(raw: &str) -> Option<IncomingEnvelope> {
    serde_json::from_str(raw).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_incoming_envelope_extracts_fields() {
        let raw = r#"{"t":"invite.use","rid":"req-42","d":{"invite":"DL1:abc.def"}}"#;
        let envelope = parse_incoming_envelope(raw).expect("envelope should parse");

        assert_eq!(envelope.event_type, events::names::INVITE_USE);
        assert_eq!(envelope.request_id.as_deref(), Some("req-42"));
        assert_eq!(envelope.data["invite"], "DL1:abc.def");
    }

    #[test]
    fn parse_incoming_envelope_returns_none_for_invalid_json() {
        assert!(parse_incoming_envelope("not-json").is_none());
    }

    #[test]
    fn duration_to_ms_never_returns_zero() {
        assert_eq!(duration_to_ms(Duration::from_millis(0)), 1);
        assert_eq!(duration_to_ms(Duration::from_millis(7)), 7);
    }
}
