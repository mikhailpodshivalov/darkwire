use crate::app_state::{
    ConnId, HandshakeAcceptError, HandshakeFailureReason, HandshakeInitError, PrekeyGetError,
    PrekeyPublishError, SharedState,
};
use crate::logging;
use axum::extract::ws::WebSocket;
use darkwire_protocol::events::{
    self, ErrorCode, HandshakeAcceptRequest, HandshakeInitRequest, PrekeyGetRequest,
    PrekeyPublishRequest, RateLimitScope,
};
use std::net::IpAddr;

use super::outgoing::{
    encode_event, send_error, send_prekey_bundle, send_prekey_published, send_rate_limited,
};

pub(super) async fn handle_prekey_publish(
    socket: &mut WebSocket,
    state: &SharedState,
    conn_id: ConnId,
    ip: IpAddr,
    request_id: Option<String>,
    data: serde_json::Value,
) -> bool {
    let request: PrekeyPublishRequest = match serde_json::from_value(data) {
        Ok(request) => request,
        Err(_) => {
            record_handshake_failure(
                state,
                conn_id,
                events::names::E2E_PREKEY_PUBLISH,
                HandshakeFailureReason::InvalidPayload,
            )
            .await;
            return send_error(
                socket,
                request_id,
                ErrorCode::BadRequest,
                "invalid e2e.prekey.publish payload",
                conn_id,
            )
            .await;
        }
    };

    match state.publish_prekeys(conn_id, ip, request).await {
        Ok(published) => send_prekey_published(socket, request_id, published, conn_id).await,
        Err(PrekeyPublishError::RateLimited(hit)) => {
            send_rate_limited(
                socket,
                request_id,
                RateLimitScope::PrekeyPublish,
                hit.retry_after,
                conn_id,
            )
            .await
        }
        Err(PrekeyPublishError::PeerOffline) => {
            send_error(
                socket,
                request_id,
                ErrorCode::BadRequest,
                "connection is offline",
                conn_id,
            )
            .await
        }
        Err(PrekeyPublishError::InvalidRequest) => {
            record_handshake_failure(
                state,
                conn_id,
                events::names::E2E_PREKEY_PUBLISH,
                HandshakeFailureReason::InvalidPayload,
            )
            .await;
            send_error(
                socket,
                request_id,
                ErrorCode::BadRequest,
                "invalid e2e.prekey.publish payload",
                conn_id,
            )
            .await
        }
    }
}

pub(super) async fn handle_prekey_get(
    socket: &mut WebSocket,
    state: &SharedState,
    conn_id: ConnId,
    ip: IpAddr,
    request_id: Option<String>,
    data: serde_json::Value,
) -> bool {
    let request: PrekeyGetRequest = match serde_json::from_value(data) {
        Ok(request) => request,
        Err(_) => {
            record_handshake_failure(
                state,
                conn_id,
                events::names::E2E_PREKEY_GET,
                HandshakeFailureReason::InvalidPayload,
            )
            .await;
            return send_error(
                socket,
                request_id,
                ErrorCode::BadRequest,
                "invalid e2e.prekey.get payload",
                conn_id,
            )
            .await;
        }
    };

    match state.get_peer_prekey_bundle(conn_id, ip, request).await {
        Ok(bundle) => send_prekey_bundle(socket, request_id, bundle, conn_id).await,
        Err(PrekeyGetError::RateLimited(hit)) => {
            send_rate_limited(
                socket,
                request_id,
                RateLimitScope::PrekeyGet,
                hit.retry_after,
                conn_id,
            )
            .await
        }
        Err(PrekeyGetError::NoActiveSession) => {
            record_handshake_failure(
                state,
                conn_id,
                events::names::E2E_PREKEY_GET,
                HandshakeFailureReason::NoActiveSession,
            )
            .await;
            send_error(
                socket,
                request_id,
                ErrorCode::NoActiveSession,
                "no active session",
                conn_id,
            )
            .await
        }
        Err(PrekeyGetError::SessionMismatch) => {
            record_handshake_failure(
                state,
                conn_id,
                events::names::E2E_PREKEY_GET,
                HandshakeFailureReason::SessionMismatch,
            )
            .await;
            send_error(
                socket,
                request_id,
                ErrorCode::StateConflict,
                "session mismatch for e2e.prekey.get",
                conn_id,
            )
            .await
        }
        Err(PrekeyGetError::PrekeyNotFound) => {
            record_handshake_failure(
                state,
                conn_id,
                events::names::E2E_PREKEY_GET,
                HandshakeFailureReason::PrekeyNotFound,
            )
            .await;
            send_error(
                socket,
                request_id,
                ErrorCode::PrekeyNotFound,
                "peer prekey bundle not found",
                conn_id,
            )
            .await
        }
    }
}

pub(super) async fn handle_handshake_init(
    socket: &mut WebSocket,
    state: &SharedState,
    conn_id: ConnId,
    ip: IpAddr,
    request_id: Option<String>,
    data: serde_json::Value,
) -> bool {
    let request: HandshakeInitRequest = match serde_json::from_value(data) {
        Ok(request) => request,
        Err(_) => {
            record_handshake_failure(
                state,
                conn_id,
                events::names::E2E_HANDSHAKE_INIT,
                HandshakeFailureReason::InvalidPayload,
            )
            .await;
            return send_error(
                socket,
                request_id,
                ErrorCode::BadRequest,
                "invalid e2e.handshake.init payload",
                conn_id,
            )
            .await;
        }
    };

    match state.route_handshake_init(conn_id, ip, request).await {
        Ok(route) => {
            let payload = encode_event(events::names::E2E_HANDSHAKE_INIT_RECV, None, route.event);
            if !state.send_to_connection(route.peer_conn, payload).await {
                record_handshake_failure(
                    state,
                    conn_id,
                    events::names::E2E_HANDSHAKE_INIT,
                    HandshakeFailureReason::HandshakeTimeout,
                )
                .await;
                return send_error(
                    socket,
                    request_id,
                    ErrorCode::HandshakeTimeout,
                    "peer is unavailable for handshake",
                    conn_id,
                )
                .await;
            }

            true
        }
        Err(HandshakeInitError::RateLimited(hit)) => {
            send_rate_limited(
                socket,
                request_id,
                RateLimitScope::Handshake,
                hit.retry_after,
                conn_id,
            )
            .await
        }
        Err(HandshakeInitError::InvalidRequest) => {
            record_handshake_failure(
                state,
                conn_id,
                events::names::E2E_HANDSHAKE_INIT,
                HandshakeFailureReason::HandshakeInvalid,
            )
            .await;
            send_error(
                socket,
                request_id,
                ErrorCode::BadRequest,
                "invalid e2e.handshake.init payload",
                conn_id,
            )
            .await
        }
        Err(HandshakeInitError::NoActiveSession) => {
            record_handshake_failure(
                state,
                conn_id,
                events::names::E2E_HANDSHAKE_INIT,
                HandshakeFailureReason::NoActiveSession,
            )
            .await;
            send_error(
                socket,
                request_id,
                ErrorCode::NoActiveSession,
                "no active session",
                conn_id,
            )
            .await
        }
        Err(HandshakeInitError::SessionMismatch) => {
            record_handshake_failure(
                state,
                conn_id,
                events::names::E2E_HANDSHAKE_INIT,
                HandshakeFailureReason::SessionMismatch,
            )
            .await;
            send_error(
                socket,
                request_id,
                ErrorCode::StateConflict,
                "session mismatch for e2e.handshake.init",
                conn_id,
            )
            .await
        }
        Err(HandshakeInitError::PrekeySelectionMissing) => {
            record_handshake_failure(
                state,
                conn_id,
                events::names::E2E_HANDSHAKE_INIT,
                HandshakeFailureReason::PrekeyNotFound,
            )
            .await;
            send_error(
                socket,
                request_id,
                ErrorCode::PrekeyNotFound,
                "prekey selection is missing; call e2e.prekey.get first",
                conn_id,
            )
            .await
        }
        Err(HandshakeInitError::StateConflict) => {
            record_handshake_failure(
                state,
                conn_id,
                events::names::E2E_HANDSHAKE_INIT,
                HandshakeFailureReason::StateConflict,
            )
            .await;
            send_error(
                socket,
                request_id,
                ErrorCode::StateConflict,
                "handshake state conflict",
                conn_id,
            )
            .await
        }
    }
}

pub(super) async fn handle_handshake_accept(
    socket: &mut WebSocket,
    state: &SharedState,
    conn_id: ConnId,
    ip: IpAddr,
    request_id: Option<String>,
    data: serde_json::Value,
) -> bool {
    let request: HandshakeAcceptRequest = match serde_json::from_value(data) {
        Ok(request) => request,
        Err(_) => {
            record_handshake_failure(
                state,
                conn_id,
                events::names::E2E_HANDSHAKE_ACCEPT,
                HandshakeFailureReason::InvalidPayload,
            )
            .await;
            return send_error(
                socket,
                request_id,
                ErrorCode::BadRequest,
                "invalid e2e.handshake.accept payload",
                conn_id,
            )
            .await;
        }
    };

    match state.route_handshake_accept(conn_id, ip, request).await {
        Ok(route) => {
            let payload = encode_event(events::names::E2E_HANDSHAKE_ACCEPT_RECV, None, route.event);
            if !state.send_to_connection(route.peer_conn, payload).await {
                record_handshake_failure(
                    state,
                    conn_id,
                    events::names::E2E_HANDSHAKE_ACCEPT,
                    HandshakeFailureReason::HandshakeTimeout,
                )
                .await;
                return send_error(
                    socket,
                    request_id,
                    ErrorCode::HandshakeTimeout,
                    "peer is unavailable for handshake accept",
                    conn_id,
                )
                .await;
            }

            true
        }
        Err(HandshakeAcceptError::RateLimited(hit)) => {
            send_rate_limited(
                socket,
                request_id,
                RateLimitScope::Handshake,
                hit.retry_after,
                conn_id,
            )
            .await
        }
        Err(HandshakeAcceptError::InvalidRequest) => {
            record_handshake_failure(
                state,
                conn_id,
                events::names::E2E_HANDSHAKE_ACCEPT,
                HandshakeFailureReason::HandshakeInvalid,
            )
            .await;
            send_error(
                socket,
                request_id,
                ErrorCode::BadRequest,
                "invalid e2e.handshake.accept payload",
                conn_id,
            )
            .await
        }
        Err(HandshakeAcceptError::NoActiveSession) => {
            record_handshake_failure(
                state,
                conn_id,
                events::names::E2E_HANDSHAKE_ACCEPT,
                HandshakeFailureReason::NoActiveSession,
            )
            .await;
            send_error(
                socket,
                request_id,
                ErrorCode::NoActiveSession,
                "no active session",
                conn_id,
            )
            .await
        }
        Err(HandshakeAcceptError::SessionMismatch) => {
            record_handshake_failure(
                state,
                conn_id,
                events::names::E2E_HANDSHAKE_ACCEPT,
                HandshakeFailureReason::SessionMismatch,
            )
            .await;
            send_error(
                socket,
                request_id,
                ErrorCode::StateConflict,
                "session mismatch for e2e.handshake.accept",
                conn_id,
            )
            .await
        }
        Err(HandshakeAcceptError::StateConflict) => {
            record_handshake_failure(
                state,
                conn_id,
                events::names::E2E_HANDSHAKE_ACCEPT,
                HandshakeFailureReason::StateConflict,
            )
            .await;
            send_error(
                socket,
                request_id,
                ErrorCode::StateConflict,
                "handshake state conflict",
                conn_id,
            )
            .await
        }
    }
}

async fn record_handshake_failure(
    state: &SharedState,
    conn_id: ConnId,
    event_type: &str,
    reason: HandshakeFailureReason,
) {
    state.record_handshake_failure(reason).await;
    logging::log_handshake_failure(conn_id, event_type, reason.as_str());
}
