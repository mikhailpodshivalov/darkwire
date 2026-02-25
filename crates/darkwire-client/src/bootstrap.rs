use crate::{
    keys::{HandshakeRole, InitiatorHandshakeContext, KeyManager, SecureSessionMaterial},
    ui::TerminalUi,
    wire::{ClientState, WireAction},
    WsWriter,
};
use darkwire_protocol::events::{self, PrekeyGetRequest, SessionLeaveRequest};
use std::{
    error::Error,
    time::{SystemTime, UNIX_EPOCH},
};

pub const HANDSHAKE_TIMEOUT_SECS: u64 = 20;

#[derive(Debug, Default)]
pub struct BootstrapState {
    pending_initiator: Option<InitiatorHandshakeContext>,
    secure_session: Option<SecureSessionMaterial>,
}

impl BootstrapState {
    pub fn clear(&mut self) {
        self.pending_initiator = None;
        self.secure_session = None;
    }

    pub fn handshake_timeout_message(&self, now_unix: u64) -> Option<String> {
        let pending = self.pending_initiator.as_ref()?;
        if now_unix.saturating_sub(pending.started_unix) > HANDSHAKE_TIMEOUT_SECS {
            return Some(format!(
                "[e2e] handshake timeout for session {} hs_id={}, aborting session",
                pending.session_id, pending.hs_id
            ));
        }

        None
    }
}

pub async fn handle_wire_action(
    action: WireAction,
    ws_writer: &mut WsWriter,
    state: &mut ClientState,
    bootstrap: &mut BootstrapState,
    keys: &mut KeyManager,
    ui: &mut TerminalUi,
    request_counter: &mut u64,
) -> Result<(), Box<dyn Error>> {
    match action {
        WireAction::SessionStarted { session_id } => {
            bootstrap.clear();
            request_prekey_bundle(ws_writer, session_id, request_counter).await?;
            ui.print_line(&format!(
                "[e2e] session {} paired; requesting peer prekey bundle",
                session_id
            ));
        }
        WireAction::SessionEnded => {
            bootstrap.clear();
        }
        WireAction::PrekeyBundle(bundle) => {
            if state.active_session_id != Some(bundle.session_id) {
                return Ok(());
            }

            match keys.start_initiator_handshake(bundle.session_id, &bundle.peer) {
                Ok((request, context)) => {
                    let hs_id = request.hs_id;
                    bootstrap.pending_initiator = Some(context);
                    super::send_request(
                        ws_writer,
                        events::names::E2E_HANDSHAKE_INIT,
                        request,
                        request_counter,
                    )
                    .await?;
                    ui.print_line(&format!(
                        "[e2e] handshake.init sent for session {} hs_id={}",
                        bundle.session_id, hs_id
                    ));
                }
                Err(err) => {
                    ui.print_error(&format!("[e2e] prekey bundle verification failed: {err}"));
                    abort_handshake_session(ws_writer, state, bootstrap, request_counter).await?;
                }
            }
        }
        WireAction::HandshakeInitRecv(init) => {
            if state.active_session_id != Some(init.session_id) {
                return Ok(());
            }

            match keys.respond_to_handshake_init(&init) {
                Ok((accept, material)) => {
                    super::send_request(
                        ws_writer,
                        events::names::E2E_HANDSHAKE_ACCEPT,
                        accept,
                        request_counter,
                    )
                    .await?;
                    state.secure_active = true;
                    bootstrap.secure_session = Some(material.clone());
                    ui.print_line(&format!(
                        "[e2e] secure session established {}",
                        secure_material_summary(&material)
                    ));
                }
                Err(err) => {
                    ui.print_error(&format!("[e2e] handshake.init validation failed: {err}"));
                    abort_handshake_session(ws_writer, state, bootstrap, request_counter).await?;
                }
            }
        }
        WireAction::HandshakeAcceptRecv(accept) => {
            let Some(context) = bootstrap.pending_initiator.clone() else {
                return Ok(());
            };

            match keys.finalize_initiator_handshake(&context, &accept) {
                Ok(material) => {
                    state.secure_active = true;
                    bootstrap.pending_initiator = None;
                    bootstrap.secure_session = Some(material.clone());
                    ui.print_line(&format!(
                        "[e2e] secure session established {}",
                        secure_material_summary(&material)
                    ));
                }
                Err(err) => {
                    ui.print_error(&format!(
                        "[e2e] handshake.accept verification failed: {err}"
                    ));
                    abort_handshake_session(ws_writer, state, bootstrap, request_counter).await?;
                }
            }
        }
    }

    Ok(())
}

pub async fn abort_handshake_session(
    ws_writer: &mut WsWriter,
    state: &mut ClientState,
    bootstrap: &mut BootstrapState,
    request_counter: &mut u64,
) -> Result<(), Box<dyn Error>> {
    bootstrap.clear();
    state.secure_active = false;
    if state.active_session {
        super::send_request(
            ws_writer,
            events::names::SESSION_LEAVE,
            SessionLeaveRequest::default(),
            request_counter,
        )
        .await?;
    }
    Ok(())
}

async fn request_prekey_bundle(
    ws_writer: &mut WsWriter,
    session_id: uuid::Uuid,
    request_counter: &mut u64,
) -> Result<(), Box<dyn Error>> {
    super::send_request(
        ws_writer,
        events::names::E2E_PREKEY_GET,
        PrekeyGetRequest { session_id },
        request_counter,
    )
    .await
}

fn shorten_b64u(value: &str) -> String {
    if value.len() <= 12 {
        return value.to_string();
    }
    format!("{}...{}", &value[..6], &value[value.len() - 5..])
}

fn secure_material_summary(material: &SecureSessionMaterial) -> String {
    let role = match material.role {
        HandshakeRole::Initiator => "initiator",
        HandshakeRole::Responder => "responder",
    };

    format!(
        "role={} session={} hs_id={} peer_ik={} rk={} at={}",
        role,
        material.session_id,
        material.hs_id,
        shorten_b64u(&material.peer_ik_ed25519),
        shorten_b64u(&material.root_key_b64u),
        material.established_unix
    )
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
