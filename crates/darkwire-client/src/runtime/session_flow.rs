use super::{
    recovery::{should_fail_closed_on_decrypt_error, RecoveryRequestState},
    ClientRuntime, WsWriter,
};
use crate::{
    bootstrap::{
        abort_handshake_session as abort_bootstrap_handshake_session, handle_wire_action, now_unix,
        should_use_initiator_branch,
    },
    keys::{HandshakeRole, KeyManager},
    ui::TerminalUi,
    wire::WireAction,
};
use darkwire_protocol::events::{self, E2eMsgRecvEvent, PrekeyGetRequest};
use std::error::Error;

pub(super) async fn handle_session_started(
    runtime: &mut ClientRuntime,
    session_id: uuid::Uuid,
    ws_writer: &mut WsWriter,
    keys: &mut KeyManager,
    ui: &mut TerminalUi,
) -> Result<(), Box<dyn Error>> {
    reset_secure_runtime_state(runtime, false);
    runtime.bootstrap.clear();
    apply_session_start_handshake_tie_break(runtime, keys, ui);

    let resumed = try_auto_resume_on_session_start(runtime, session_id, ws_writer, ui).await?;
    runtime.pending_resume_peer_ik = None;

    if !resumed {
        forward_wire_action(
            runtime,
            WireAction::SessionStarted { session_id },
            ws_writer,
            keys,
            ui,
        )
        .await?;
    }

    Ok(())
}

pub(super) async fn handle_encrypted_message(
    runtime: &mut ClientRuntime,
    event: E2eMsgRecvEvent,
    ws_writer: &mut WsWriter,
    ui: &mut TerminalUi,
) -> Result<(), Box<dyn Error>> {
    if !runtime.state.secure_active {
        if let Some(message) = try_auto_resume_from_incoming(runtime, &event, ws_writer, ui).await?
        {
            print_incoming_message(runtime, ui, &message);
            persist_active_session_checkpoint(runtime)?;
            return Ok(());
        }

        match maybe_request_recovery_handshake(runtime, ws_writer, ui).await? {
            RecoveryRequestState::Requested => {
                ui.print_error("[e2e] secure session unavailable; waiting for recovery handshake");
            }
            RecoveryRequestState::AlreadyRequested => {
                if runtime.recovery.is_request_in_flight() {
                    ui.print_error(
                        "[e2e] secure session unavailable; recovery in progress (send is blocked)",
                    );
                } else {
                    ui.print_error(
                        "[e2e] secure session desynchronized; reconnect with /q then /invite CODE",
                    );
                }
            }
            RecoveryRequestState::Unavailable => {
                if runtime.recovery.is_send_blocked() {
                    ui.print_error(
                        "[e2e] secure session desynchronized; reconnect with /q then /invite CODE",
                    );
                } else {
                    ui.print_error("[e2e] secure session unavailable");
                }
            }
        }
        return Ok(());
    }

    match runtime.secure_messenger.decrypt_incoming(&event) {
        Ok(message) => {
            print_incoming_message(runtime, ui, &message);
            persist_active_session_checkpoint(runtime)?;
            runtime.maybe_refresh_active_peer_login(ws_writer).await?;
        }
        Err(err) => {
            if should_fail_closed_on_decrypt_error(&err) {
                enter_fail_closed_recovery(runtime, ws_writer, ui, &err).await?;
            } else {
                ui.print_error(&format!("[e2e] drop inbound message: {err}"));
            }
        }
    }

    Ok(())
}

pub(super) async fn activate_secure_material_if_ready(
    runtime: &mut ClientRuntime,
    ws_writer: &mut WsWriter,
    keys: &mut KeyManager,
    ui: &mut TerminalUi,
) -> Result<(), Box<dyn Error>> {
    let Some(material) = runtime.bootstrap.take_secure_session_material() else {
        return Ok(());
    };

    if let Err(err) = runtime.secure_messenger.activate(&material) {
        ui.print_error(&format!("[e2e] failed to activate secure messaging: {err}"));
        runtime.state.secure_active = false;
        return Ok(());
    }

    let trust = runtime.trust.evaluate_peer(&material.peer_ik_ed25519)?;
    runtime.recovery.reset();
    runtime.active_peer_login = None;
    runtime.print_active_trust(ui, &trust);

    if trust.state == crate::trust::SessionTrustState::KeyChanged {
        runtime
            .session_store
            .reset_for_local_identity(keys.identity_public_ed25519())?;
        let previous = trust
            .previous_fingerprint_short
            .as_deref()
            .unwrap_or("unknown");
        runtime.print_key_changed_warning(ui, previous, &trust.fingerprint_short, None);
    } else {
        runtime.session_store.upsert(
            &material.peer_ik_ed25519,
            &material.root_key_b64u,
            0,
            0,
            material.established_unix,
        )?;
    }

    runtime
        .request_login_lookup_by_ik(ws_writer, &material.peer_ik_ed25519, false)
        .await?;
    runtime.active_peer_trust = Some(trust);

    Ok(())
}

pub(super) async fn forward_wire_action(
    runtime: &mut ClientRuntime,
    action: WireAction,
    ws_writer: &mut WsWriter,
    keys: &mut KeyManager,
    ui: &mut TerminalUi,
) -> Result<(), Box<dyn Error>> {
    handle_wire_action(
        action,
        ws_writer,
        &mut runtime.state,
        &mut runtime.bootstrap,
        keys,
        ui,
        &mut runtime.request_counter,
    )
    .await
}

pub(super) fn apply_session_start_handshake_tie_break(
    runtime: &mut ClientRuntime,
    keys: &KeyManager,
    ui: &mut TerminalUi,
) {
    if !runtime.state.should_initiate_handshake {
        return;
    }

    let Some(peer_ik) = runtime.pending_resume_peer_ik.as_deref() else {
        return;
    };

    if should_use_initiator_branch(keys.identity_public_ed25519(), peer_ik) {
        return;
    }

    runtime.state.should_initiate_handshake = false;
    ui.print_line("[e2e] simultaneous connect resolved: waiting for peer handshake.init");
}

pub(super) async fn enter_fail_closed_recovery(
    runtime: &mut ClientRuntime,
    ws_writer: &mut WsWriter,
    ui: &mut TerminalUi,
    err: &crate::e2e::SecureMessagingError,
) -> Result<(), Box<dyn Error>> {
    ui.print_error(&format!(
        "[e2e] decrypt failed ({err}); entering fail-closed recovery mode",
    ));

    runtime.recovery.block_send();
    runtime.state.secure_active = false;
    runtime.secure_messenger.clear();
    runtime.recovery.clear_request_in_flight();

    match maybe_request_recovery_handshake(runtime, ws_writer, ui).await? {
        RecoveryRequestState::Requested => {}
        RecoveryRequestState::AlreadyRequested | RecoveryRequestState::Unavailable => {
            ui.print_error(
                "[e2e] recovery unavailable for this session; reconnect with /q then /invite CODE",
            );
        }
    }

    Ok(())
}

pub(super) fn print_incoming_message(runtime: &ClientRuntime, ui: &mut TerminalUi, message: &str) {
    let sender_label = runtime.incoming_sender_label();
    ui.print_line(&format!("{sender_label} {message}"));
}

pub(super) fn reset_secure_runtime_state(
    runtime: &mut ClientRuntime,
    clear_pending_resume_peer: bool,
) {
    runtime.secure_messenger.clear();
    runtime.active_peer_trust = None;
    runtime.active_peer_login = None;
    runtime.recovery.reset();
    runtime.peer_login_missing_notified = false;
    runtime.last_peer_login_lookup_unix = 0;
    if clear_pending_resume_peer {
        runtime.pending_resume_peer_ik = None;
    }
}

pub(super) async fn on_handshake_tick(
    runtime: &mut ClientRuntime,
    ws_writer: &mut WsWriter,
    ui: &mut TerminalUi,
) -> Result<(), Box<dyn Error>> {
    runtime.maybe_refresh_active_peer_login(ws_writer).await?;

    if let Some(message) = runtime.bootstrap.handshake_timeout_message(now_unix()) {
        ui.print_error(&message);
        abort_handshake_session(runtime, ws_writer).await?;
    }

    Ok(())
}

pub(super) async fn abort_handshake_session(
    runtime: &mut ClientRuntime,
    ws_writer: &mut WsWriter,
) -> Result<(), Box<dyn Error>> {
    abort_bootstrap_handshake_session(
        ws_writer,
        &mut runtime.state,
        &mut runtime.bootstrap,
        &mut runtime.request_counter,
    )
    .await?;
    reset_secure_runtime_state(runtime, false);
    Ok(())
}

pub(super) async fn try_auto_resume_on_session_start(
    runtime: &mut ClientRuntime,
    session_id: uuid::Uuid,
    ws_writer: &mut WsWriter,
    ui: &mut TerminalUi,
) -> Result<bool, Box<dyn Error>> {
    if !runtime.state.should_initiate_handshake {
        return Ok(false);
    }

    let Some(peer_ik_ed25519) = runtime.pending_resume_peer_ik.clone() else {
        return Ok(false);
    };

    if !runtime.trust.is_verified(&peer_ik_ed25519) {
        return Ok(false);
    }

    let Some(stored) = runtime.session_store.load_peer(&peer_ik_ed25519) else {
        return Ok(false);
    };

    let mut resumed = crate::e2e::SecureMessenger::default();
    if resumed
        .activate_resumed(
            session_id,
            HandshakeRole::Initiator,
            &stored.root_key_b64u,
            stored.send_n,
            stored.recv_n,
        )
        .is_err()
    {
        return Ok(false);
    }

    runtime.secure_messenger = resumed;
    runtime.state.secure_active = true;
    runtime.recovery.reset();

    let trust = runtime.trust.evaluate_peer(&peer_ik_ed25519)?;
    runtime.active_peer_login = None;
    runtime.active_peer_trust = Some(trust.clone());
    runtime.print_active_trust(ui, &trust);
    runtime
        .request_login_lookup_by_ik(ws_writer, &peer_ik_ed25519, false)
        .await?;

    if trust.state != crate::trust::SessionTrustState::Verified {
        runtime.state.secure_active = false;
        runtime.secure_messenger.clear();
        return Ok(false);
    }

    persist_active_session_checkpoint(runtime)?;
    ui.print_line(&format!(
        "[e2e] secure session resumed role=initiator session={} peer_fp={}",
        session_id, trust.fingerprint_short
    ));
    Ok(true)
}

pub(super) async fn try_auto_resume_from_incoming(
    runtime: &mut ClientRuntime,
    event: &E2eMsgRecvEvent,
    ws_writer: &mut WsWriter,
    ui: &mut TerminalUi,
) -> Result<Option<String>, Box<dyn Error>> {
    let role = if runtime.state.should_initiate_handshake {
        HandshakeRole::Initiator
    } else {
        HandshakeRole::Responder
    };

    for stored in runtime.session_store.list() {
        if !runtime.trust.is_verified(&stored.peer_ik_ed25519) {
            continue;
        }

        let mut resumed = crate::e2e::SecureMessenger::default();
        if resumed
            .activate_resumed(
                event.session_id,
                role,
                &stored.root_key_b64u,
                stored.send_n,
                stored.recv_n,
            )
            .is_err()
        {
            continue;
        }

        let Ok(message) = resumed.decrypt_incoming(event) else {
            continue;
        };

        let trust = runtime.trust.evaluate_peer(&stored.peer_ik_ed25519)?;
        if trust.state != crate::trust::SessionTrustState::Verified {
            continue;
        }

        runtime.secure_messenger = resumed;
        runtime.state.secure_active = true;
        runtime.recovery.reset();
        runtime.active_peer_login = None;
        runtime.active_peer_trust = Some(trust.clone());
        runtime.print_active_trust(ui, &trust);
        runtime
            .request_login_lookup_by_ik(ws_writer, &stored.peer_ik_ed25519, false)
            .await?;
        ui.print_line(&format!(
            "[e2e] secure session resumed role={} session={} peer_fp={}",
            if role == HandshakeRole::Initiator {
                "initiator"
            } else {
                "responder"
            },
            event.session_id,
            trust.fingerprint_short
        ));

        return Ok(Some(message));
    }

    Ok(None)
}

pub(super) fn persist_active_session_checkpoint(
    runtime: &mut ClientRuntime,
) -> Result<(), Box<dyn Error>> {
    if runtime.recovery.is_send_blocked() {
        return Ok(());
    }

    let Some(active_peer) = runtime.active_peer_trust.as_ref() else {
        return Ok(());
    };
    let Some(snapshot) = runtime.secure_messenger.snapshot() else {
        return Ok(());
    };

    let now = now_unix();
    let existing = runtime
        .session_store
        .load_peer(&active_peer.peer_ik_ed25519);
    match existing {
        Some(existing) if existing.root_key_b64u == snapshot.root_key_b64u => {
            runtime.session_store.update_counters(
                &active_peer.peer_ik_ed25519,
                snapshot.send_n,
                snapshot.recv_n,
            )
        }
        _ => runtime.session_store.upsert(
            &active_peer.peer_ik_ed25519,
            &snapshot.root_key_b64u,
            snapshot.send_n,
            snapshot.recv_n,
            now,
        ),
    }
}

pub(super) async fn maybe_request_recovery_handshake(
    runtime: &mut ClientRuntime,
    ws_writer: &mut WsWriter,
    ui: &mut TerminalUi,
) -> Result<RecoveryRequestState, Box<dyn Error>> {
    let state = runtime.recovery.request_state_for(&runtime.state);
    if state != RecoveryRequestState::Requested {
        return Ok(state);
    }

    let Some(session_id) = runtime.state.active_session_id else {
        return Ok(RecoveryRequestState::Unavailable);
    };

    let _ = runtime
        .send_request(
            ws_writer,
            events::names::E2E_PREKEY_GET,
            PrekeyGetRequest { session_id },
        )
        .await?;
    runtime.recovery.mark_recovery_requested(session_id);
    ui.print_line("[e2e] resume unavailable, requesting prekey bundle for recovery");
    Ok(RecoveryRequestState::Requested)
}
