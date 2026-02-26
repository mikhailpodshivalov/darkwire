use crate::app_state::{
    ConnId, E2eMsgSendError, HandshakeAcceptError, HandshakeFailureReason, HandshakeInitError,
    PrekeyGetError, PrekeyPublishError, SharedState,
};
use crate::logging;
use axum::extract::ws::WebSocket;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use darkwire_protocol::events::{
    self, E2eMsgSendRequest, ErrorCode, HandshakeAcceptRequest, HandshakeInitRequest,
    PrekeyGetRequest, PrekeyPublishRequest, RateLimitScope, SessionEndReason,
};
use std::net::IpAddr;

use super::outgoing::{
    encode_event, send_error, send_prekey_bundle, send_prekey_published, send_rate_limited,
    send_session_ended,
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
                ErrorCode::HandshakeInvalid,
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
                ErrorCode::HandshakeInvalid,
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

pub(super) async fn handle_encrypted_message(
    socket: &mut WebSocket,
    state: &SharedState,
    conn_id: ConnId,
    _ip: IpAddr,
    request_id: Option<String>,
    data: serde_json::Value,
) -> bool {
    let request: E2eMsgSendRequest = match serde_json::from_value(data) {
        Ok(request) if is_valid_e2e_message_payload(&request) => request,
        _ => {
            return send_error(
                socket,
                request_id,
                ErrorCode::BadRequest,
                "invalid e2e.msg.send payload",
                conn_id,
            )
            .await;
        }
    };

    let payload_bytes = serde_json::to_vec(&request)
        .map(|raw| raw.len())
        .unwrap_or(usize::MAX);

    match state
        .route_encrypted_message(conn_id, request.session_id, payload_bytes)
        .await
    {
        Ok(route) => {
            let payload = encode_event(events::names::E2E_MSG_RECV, None, request);
            if !state.send_to_connection(route.peer_conn, payload).await {
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
        Err(E2eMsgSendError::NoActiveSession) => {
            send_error(
                socket,
                request_id,
                ErrorCode::NoActiveSession,
                "no active session",
                conn_id,
            )
            .await
        }
        Err(E2eMsgSendError::SessionMismatch) => {
            send_error(
                socket,
                request_id,
                ErrorCode::StateConflict,
                "session mismatch for e2e.msg.send",
                conn_id,
            )
            .await
        }
        Err(E2eMsgSendError::MessageTooLarge) => {
            send_error(
                socket,
                request_id,
                ErrorCode::MessageTooLarge,
                "encrypted message exceeds max size",
                conn_id,
            )
            .await
        }
        Err(E2eMsgSendError::RateLimited(retry_after)) => {
            send_rate_limited(
                socket,
                request_id,
                RateLimitScope::MsgSend,
                retry_after,
                conn_id,
            )
            .await
        }
    }
}

fn is_valid_e2e_message_payload(request: &E2eMsgSendRequest) -> bool {
    if request.n == 0 {
        return false;
    }
    if request.nonce.trim().is_empty()
        || request.ct.trim().is_empty()
        || request.dh_x25519.trim().is_empty()
    {
        return false;
    }

    if !is_b64u_with_len(&request.dh_x25519, 32) {
        return false;
    }
    if !is_b64u_with_len(&request.nonce, 12) {
        return false;
    }
    if !is_non_empty_b64u(&request.ct) {
        return false;
    }

    request.ad.pv == 2
        && request.ad.session_id == request.session_id
        && request.ad.n == request.n
        && request.ad.pn == request.pn
}

fn is_b64u_with_len(value: &str, expected_len: usize) -> bool {
    match URL_SAFE_NO_PAD.decode(value.as_bytes()) {
        Ok(bytes) => bytes.len() == expected_len,
        Err(_) => false,
    }
}

fn is_non_empty_b64u(value: &str) -> bool {
    match URL_SAFE_NO_PAD.decode(value.as_bytes()) {
        Ok(bytes) => !bytes.is_empty(),
        Err(_) => false,
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

#[cfg(test)]
mod tests {
    use super::*;
    use darkwire_protocol::events::E2eMsgAd;
    use uuid::Uuid;

    fn sample_payload() -> E2eMsgSendRequest {
        let session_id = Uuid::new_v4();
        E2eMsgSendRequest {
            session_id,
            n: 1,
            pn: 0,
            dh_x25519: URL_SAFE_NO_PAD.encode([1_u8; 32]),
            nonce: URL_SAFE_NO_PAD.encode([2_u8; 12]),
            ct: URL_SAFE_NO_PAD.encode([3_u8; 24]),
            ad: E2eMsgAd {
                pv: 2,
                session_id,
                n: 1,
                pn: 0,
            },
        }
    }

    #[test]
    fn e2e_payload_validation_accepts_expected_shape() {
        assert!(is_valid_e2e_message_payload(&sample_payload()));
    }

    #[test]
    fn e2e_payload_validation_rejects_bad_nonce_length() {
        let mut payload = sample_payload();
        payload.nonce = URL_SAFE_NO_PAD.encode([0_u8; 8]);
        assert!(!is_valid_e2e_message_payload(&payload));
    }

    #[test]
    fn e2e_payload_validation_rejects_bad_dh_length() {
        let mut payload = sample_payload();
        payload.dh_x25519 = URL_SAFE_NO_PAD.encode([0_u8; 31]);
        assert!(!is_valid_e2e_message_payload(&payload));
    }

    #[test]
    fn e2e_payload_validation_rejects_non_base64_ciphertext() {
        let mut payload = sample_payload();
        payload.ct = "!not-base64".to_string();
        assert!(!is_valid_e2e_message_payload(&payload));
    }
}
