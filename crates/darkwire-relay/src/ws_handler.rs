use crate::app_state::{ConnId, SharedState};
use axum::{
    extract::{
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, State,
    },
    response::IntoResponse,
};
use darkwire_protocol::events::{self, Envelope, PongEvent, ReadyEvent};
use serde::Deserialize;
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
                    let _ = socket.send(Message::Close(Some(CloseFrame {
                        code: 1000,
                        reason: "idle_timeout".into(),
                    }))).await;
                    break;
                }
            }
            frame = socket.recv() => {
                match frame {
                    Some(Ok(message)) => {
                        if !handle_message(&mut socket, &state, conn_id, message).await {
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
    message: Message,
) -> bool {
    let _ = state.touch_connection(conn_id).await;

    match message {
        Message::Text(raw) => {
            let maybe_event = parse_event_header(&raw);
            if maybe_event.as_ref().map(|h| h.event_type.as_str()) == Some(events::names::PING) {
                if let Err(err) = send_pong(socket, maybe_event.and_then(|h| h.request_id)).await {
                    warn!(%conn_id, err = %err, "connection.pong_send_failed");
                    return false;
                }
            }
            true
        }
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

async fn send_ready(socket: &mut WebSocket) -> Result<(), axum::Error> {
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let ready = Envelope::new(
        events::names::READY,
        ReadyEvent {
            server_time: now_unix,
        },
    );
    let raw = serde_json::to_string(&ready).expect("serializing ready event should not fail");
    socket.send(Message::Text(raw.into())).await
}

async fn send_pong(socket: &mut WebSocket, request_id: Option<String>) -> Result<(), axum::Error> {
    let mut pong = Envelope::new(events::names::PONG, PongEvent::default());
    pong.request_id = request_id;

    let raw = serde_json::to_string(&pong).expect("serializing pong event should not fail");
    socket.send(Message::Text(raw.into())).await
}

#[derive(Debug, Deserialize)]
struct EventHeader {
    #[serde(rename = "t")]
    event_type: String,
    #[serde(rename = "rid")]
    request_id: Option<String>,
}

fn parse_event_header(raw: &str) -> Option<EventHeader> {
    serde_json::from_str(raw).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_event_header_extracts_type_and_request_id() {
        let raw = r#"{"t":"ping","rid":"req-42","d":{}}"#;
        let header = parse_event_header(raw).expect("header should parse");
        assert_eq!(header.event_type, events::names::PING);
        assert_eq!(header.request_id.as_deref(), Some("req-42"));
    }

    #[test]
    fn parse_event_header_returns_none_for_invalid_json() {
        assert!(parse_event_header("not-json").is_none());
    }
}
