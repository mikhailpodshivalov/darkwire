use crate::app_state::{
    ConnId, InviteCreated, PrekeyBundleRoute, PrekeyPublished, SessionTermination, SharedState,
};
use axum::extract::ws::{Message, WebSocket};
use darkwire_protocol::events::{
    self, Envelope, ErrorCode, ErrorEvent, InviteCreatedEvent, InviteUsedEvent, PongEvent,
    PrekeyBundleEvent, PrekeyPublishedEvent, RateLimitScope, RateLimitedEvent, ReadyEvent,
    SessionEndReason, SessionEndedEvent, SessionStartedEvent,
};
use serde::Serialize;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::warn;

pub(super) async fn send_ready(socket: &mut WebSocket) -> Result<(), axum::Error> {
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    send_event(
        socket,
        events::names::READY,
        None,
        ReadyEvent {
            server_time: now_unix,
        },
    )
    .await
}

pub(super) async fn send_pong(
    socket: &mut WebSocket,
    request_id: Option<String>,
    conn_id: ConnId,
) -> bool {
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

pub(super) async fn send_invite_created(
    socket: &mut WebSocket,
    request_id: Option<String>,
    created: InviteCreated,
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

pub(super) async fn send_invite_used(
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

pub(super) async fn send_session_started(
    socket: &mut WebSocket,
    request_id: Option<String>,
    session_id: uuid::Uuid,
    conn_id: ConnId,
) -> bool {
    let event = SessionStartedEvent {
        session_id,
        peer: "anon".to_string(),
    };

    match send_event(socket, events::names::SESSION_STARTED, request_id, event).await {
        Ok(()) => true,
        Err(err) => {
            warn!(%conn_id, err = %err, "connection.session_started_send_failed");
            false
        }
    }
}

pub(super) async fn queue_session_ended(state: &SharedState, ended: SessionTermination) -> bool {
    let payload = encode_event(
        events::names::SESSION_ENDED,
        None,
        SessionEndedEvent {
            session_id: ended.session_id,
            reason: ended.reason,
        },
    );

    state.send_to_connection(ended.peer_conn, payload).await
}

pub(super) async fn send_session_ended(
    socket: &mut WebSocket,
    request_id: Option<String>,
    session_id: uuid::Uuid,
    reason: SessionEndReason,
    conn_id: ConnId,
) -> bool {
    let event = SessionEndedEvent { session_id, reason };

    match send_event(socket, events::names::SESSION_ENDED, request_id, event).await {
        Ok(()) => true,
        Err(err) => {
            warn!(%conn_id, err = %err, "connection.session_ended_send_failed");
            false
        }
    }
}

pub(super) async fn send_rate_limited(
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

pub(super) async fn send_prekey_published(
    socket: &mut WebSocket,
    request_id: Option<String>,
    published: PrekeyPublished,
    conn_id: ConnId,
) -> bool {
    let event = PrekeyPublishedEvent {
        spk_id: published.spk_id,
        opk_count: published.opk_count,
    };

    match send_event(
        socket,
        events::names::E2E_PREKEY_PUBLISHED,
        request_id,
        event,
    )
    .await
    {
        Ok(()) => true,
        Err(err) => {
            warn!(%conn_id, err = %err, "connection.prekey_published_send_failed");
            false
        }
    }
}

pub(super) async fn send_prekey_bundle(
    socket: &mut WebSocket,
    request_id: Option<String>,
    bundle: PrekeyBundleRoute,
    conn_id: ConnId,
) -> bool {
    let event = PrekeyBundleEvent {
        session_id: bundle.session_id,
        peer: bundle.peer,
    };

    match send_event(socket, events::names::E2E_PREKEY_BUNDLE, request_id, event).await {
        Ok(()) => true,
        Err(err) => {
            warn!(%conn_id, err = %err, "connection.prekey_bundle_send_failed");
            false
        }
    }
}

pub(super) async fn send_error(
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
    let raw = encode_event(event_type, request_id, data);
    socket.send(Message::Text(raw.into())).await
}

pub(super) fn encode_event<T: Serialize>(
    event_type: &str,
    request_id: Option<String>,
    data: T,
) -> String {
    let mut envelope = Envelope::new(event_type, data);
    envelope.request_id = request_id;

    serde_json::to_string(&envelope).expect("serializing event should not fail")
}

pub(super) fn duration_to_ms(duration: Duration) -> u64 {
    let millis = duration.as_millis();
    let millis = millis.clamp(1, u128::from(u64::MAX));
    millis as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_to_ms_never_returns_zero() {
        assert_eq!(duration_to_ms(Duration::from_millis(0)), 1);
        assert_eq!(duration_to_ms(Duration::from_millis(7)), 7);
    }

    #[test]
    fn encode_event_uses_wire_shape() {
        let raw = encode_event(
            events::names::ERROR,
            Some("req-1".to_string()),
            ErrorEvent {
                code: ErrorCode::BadRequest,
                message: "oops".to_string(),
            },
        );

        let envelope: serde_json::Value =
            serde_json::from_str(&raw).expect("encoded event must be valid JSON");
        assert_eq!(envelope["t"], events::names::ERROR);
        assert_eq!(envelope["rid"], "req-1");
        assert_eq!(envelope["d"]["message"], "oops");
    }
}
