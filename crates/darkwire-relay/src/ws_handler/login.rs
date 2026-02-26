use crate::app_state::{ConnId, LoginBindError, LoginLookupError, SharedState};
use axum::extract::ws::WebSocket;
use darkwire_protocol::events::{ErrorCode, LoginBindRequest, LoginLookupRequest};

use super::outgoing::{send_error, send_login_binding, send_login_bound};

pub(super) async fn handle_login_bind(
    socket: &mut WebSocket,
    state: &SharedState,
    conn_id: ConnId,
    request_id: Option<String>,
    data: serde_json::Value,
) -> bool {
    let request: LoginBindRequest = match serde_json::from_value(data) {
        Ok(request) => request,
        Err(_) => {
            return send_error(
                socket,
                request_id,
                ErrorCode::LoginInvalid,
                "invalid login.bind payload",
                conn_id,
            )
            .await;
        }
    };

    match state.bind_login(conn_id, request).await {
        Ok(binding) => send_login_bound(socket, request_id, binding, conn_id).await,
        Err(LoginBindError::InvalidRequest) => {
            send_error(
                socket,
                request_id,
                ErrorCode::LoginInvalid,
                "invalid login or signature",
                conn_id,
            )
            .await
        }
        Err(LoginBindError::LoginTaken) => {
            send_error(
                socket,
                request_id,
                ErrorCode::LoginTaken,
                "login is already bound to another identity key",
                conn_id,
            )
            .await
        }
        Err(LoginBindError::KeyMismatch) => {
            send_error(
                socket,
                request_id,
                ErrorCode::LoginKeyMismatch,
                "login binding signature or identity key mismatch",
                conn_id,
            )
            .await
        }
        Err(LoginBindError::PeerOffline) => {
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

pub(super) async fn handle_login_lookup(
    socket: &mut WebSocket,
    state: &SharedState,
    conn_id: ConnId,
    request_id: Option<String>,
    data: serde_json::Value,
) -> bool {
    let request: LoginLookupRequest = match serde_json::from_value(data) {
        Ok(request) => request,
        Err(_) => {
            return send_error(
                socket,
                request_id,
                ErrorCode::LoginInvalid,
                "invalid login.lookup payload",
                conn_id,
            )
            .await;
        }
    };

    match state.lookup_login(request).await {
        Ok(binding) => send_login_binding(socket, request_id, binding, conn_id).await,
        Err(LoginLookupError::InvalidRequest) => {
            send_error(
                socket,
                request_id,
                ErrorCode::LoginInvalid,
                "invalid login.lookup payload",
                conn_id,
            )
            .await
        }
        Err(LoginLookupError::NotFound) => {
            send_error(
                socket,
                request_id,
                ErrorCode::LoginNotFound,
                "login binding not found",
                conn_id,
            )
            .await
        }
    }
}
