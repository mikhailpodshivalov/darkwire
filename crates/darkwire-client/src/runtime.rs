use crate::{
    bootstrap::{abort_handshake_session, handle_wire_action, now_unix, BootstrapState},
    commands::{command_help_all_lines, command_help_basic_lines, parse_user_command, UserCommand},
    e2e::SecureMessenger,
    keys::KeyManager,
    trust::{fingerprint_short_for_ik, ActivePeerTrust, SessionTrustState, TrustManager},
    ui::TerminalUi,
    wire::{extract_wire_action, handle_server_text, ClientState, WireAction},
};
use darkwire_protocol::events::{
    self, Envelope, InviteCreateRequest, InviteUseRequest, LoginBindRequest, LoginLookupRequest,
    SessionLeaveRequest,
};
use darkwire_protocol::login::{format_login, normalize_login};
use futures_util::{stream::SplitSink, SinkExt};
use serde::Serialize;
use std::error::Error;
use tokio::net::TcpStream;
use tokio_tungstenite::{tungstenite::Message, MaybeTlsStream, WebSocketStream};

pub type WsWriter = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;

pub struct ClientRuntime {
    state: ClientState,
    bootstrap: BootstrapState,
    secure_messenger: SecureMessenger,
    trust: TrustManager,
    active_peer_trust: Option<ActivePeerTrust>,
    active_peer_login: Option<String>,
    local_login: Option<String>,
    request_counter: u64,
}

impl ClientRuntime {
    pub fn new(trust: TrustManager) -> Self {
        Self {
            state: ClientState::default(),
            bootstrap: BootstrapState::default(),
            secure_messenger: SecureMessenger::default(),
            trust,
            active_peer_trust: None,
            active_peer_login: None,
            local_login: None,
            request_counter: 1,
        }
    }

    pub fn trust_overview_line(&self) -> String {
        format!(
            "[trust] verified_contacts={} file={}",
            self.trust.verified_count(),
            self.trust.trust_file().display()
        )
    }

    pub async fn initialize_session(
        &mut self,
        ws_writer: &mut WsWriter,
        keys: &KeyManager,
        invite_relay: &str,
        invite_ttl: u32,
    ) -> Result<(), Box<dyn Error>> {
        self.publish_prekeys(ws_writer, keys).await?;
        self.request_invite(ws_writer, invite_relay, invite_ttl)
            .await?;
        Ok(())
    }

    pub async fn process_user_line(
        &mut self,
        line: &str,
        ws_writer: &mut WsWriter,
        ui: &mut TerminalUi,
        invite_relay: &str,
        invite_ttl: u32,
        keys: &mut KeyManager,
    ) -> Result<bool, Box<dyn Error>> {
        match parse_user_command(line) {
            UserCommand::Ignore => Ok(true),
            UserCommand::Help => {
                ui.print_line("Commands (basic):");
                for line in command_help_basic_lines() {
                    ui.print_line(line);
                }
                Ok(true)
            }
            UserCommand::HelpAll => {
                ui.print_line("Commands (all):");
                for line in command_help_all_lines() {
                    ui.print_line(line);
                }
                Ok(true)
            }
            UserCommand::Unknown => {
                ui.print_line("Unknown command. Use /help or /help all");
                Ok(true)
            }
            UserCommand::KeyStatus => {
                ui.print_line(&format!("[keys] {}", keys.status_line()));
                Ok(true)
            }
            UserCommand::KeyRotate => {
                keys.rotate_signed_prekey()?;
                self.publish_prekeys(ws_writer, keys).await?;
                ui.print_line(&format!(
                    "[keys] rotated + published {}",
                    keys.status_line()
                ));
                Ok(true)
            }
            UserCommand::KeyRefill => {
                let added = keys.refill_one_time_prekeys()?;
                self.publish_prekeys(ws_writer, keys).await?;
                ui.print_line(&format!(
                    "[keys] refill added={} + published {}",
                    added,
                    keys.status_line()
                ));
                Ok(true)
            }
            UserCommand::KeyRevoke => {
                keys.revoke_and_regenerate()?;
                self.publish_prekeys(ws_writer, keys).await?;
                if self.state.active_session {
                    self.abort_handshake_session(ws_writer).await?;
                }
                ui.print_line(&format!(
                    "[keys] identity revoked/regenerated + published {}",
                    keys.status_line()
                ));
                Ok(true)
            }
            UserCommand::Quit => {
                if self.state.active_session {
                    self.send_request(
                        ws_writer,
                        events::names::SESSION_LEAVE,
                        SessionLeaveRequest::default(),
                    )
                    .await?;
                }
                ui.print_line("Bye");
                Ok(false)
            }
            UserCommand::CreateInvite => {
                self.request_invite(ws_writer, invite_relay, invite_ttl)
                    .await?;
                Ok(true)
            }
            UserCommand::ConnectInvite(invite) => {
                self.send_request(
                    ws_writer,
                    events::names::INVITE_USE,
                    InviteUseRequest { invite },
                )
                .await?;
                Ok(true)
            }
            UserCommand::TrustStatus => {
                self.print_trust_status(ui);
                Ok(true)
            }
            UserCommand::TrustVerify => {
                let Some(active) = self.active_peer_trust.as_ref() else {
                    ui.print_line(
                        "[trust] no active secure peer; establish session first, then /trust verify",
                    );
                    return Ok(true);
                };

                self.trust.verify_peer(&active.peer_ik_ed25519)?;
                let refreshed = self.trust.evaluate_peer(&active.peer_ik_ed25519)?;
                self.active_peer_trust = Some(refreshed.clone());
                ui.print_line(&format!(
                    "[trust] verified peer fp={} safety={}",
                    refreshed.fingerprint_short, refreshed.safety_number
                ));
                Ok(true)
            }
            UserCommand::TrustUnverify => {
                let Some(active) = self.active_peer_trust.as_ref() else {
                    ui.print_line(
                        "[trust] no active secure peer; establish session first, then /trust unverify",
                    );
                    return Ok(true);
                };

                self.trust.unverify_peer(&active.peer_ik_ed25519)?;
                let refreshed = self.trust.evaluate_peer(&active.peer_ik_ed25519)?;
                self.active_peer_trust = Some(refreshed.clone());
                ui.print_line(&format!(
                    "[trust] unverified peer fp={} safety={}",
                    refreshed.fingerprint_short, refreshed.safety_number
                ));
                Ok(true)
            }
            UserCommand::TrustList => {
                let verified = self.trust.list_verified();
                if verified.is_empty() {
                    ui.print_line("[trust] verified contacts: none");
                    return Ok(true);
                }
                ui.print_line(&format!("[trust] verified contacts: {}", verified.len()));
                for entry in verified {
                    ui.print_line(&format!(
                        "[trust] fp={} safety={}",
                        entry.fingerprint_short, entry.safety_number
                    ));
                }
                Ok(true)
            }
            UserCommand::LoginStatus => {
                let local_fp = keys.status().fingerprint_short;
                if let Some(login) = self.local_login.as_ref() {
                    ui.print_line(&format!(
                        "[login] local {} fp={}",
                        format_login(login),
                        local_fp
                    ));
                } else {
                    ui.print_line(&format!("[login] local unbound fp={local_fp}"));
                }
                self.request_login_lookup_by_ik(ws_writer, keys.identity_public_ed25519())
                    .await?;
                Ok(true)
            }
            UserCommand::LoginSet(raw_login) => {
                let Some(login) = normalize_login(&raw_login) else {
                    ui.print_error(
                        "[login] invalid login format; use 3-24 chars [a-z0-9_.-], optional @ prefix",
                    );
                    return Ok(true);
                };

                let signature = match keys.sign_login_binding(&login) {
                    Ok(signature) => signature,
                    Err(err) => {
                        ui.print_error(&format!("[login] failed to sign bind request: {err}"));
                        return Ok(true);
                    }
                };

                self.send_request(
                    ws_writer,
                    events::names::LOGIN_BIND,
                    LoginBindRequest {
                        login: login.clone(),
                        ik_ed25519: keys.identity_public_ed25519().to_string(),
                        sig_ed25519: signature,
                    },
                )
                .await?;
                ui.print_line(&format!("[login] binding {} ...", format_login(&login)));
                Ok(true)
            }
            UserCommand::LoginLookup(raw_login) => {
                let Some(login) = normalize_login(&raw_login) else {
                    ui.print_error(
                        "[login] invalid login format; use 3-24 chars [a-z0-9_.-], optional @ prefix",
                    );
                    return Ok(true);
                };
                self.request_login_lookup_by_login(ws_writer, &login)
                    .await?;
                ui.print_line(&format!("[login] resolving {} ...", format_login(&login)));
                Ok(true)
            }
            UserCommand::SendMessage(text) => {
                if !self.state.active_session {
                    ui.print_line("No active session. Use /new or /c CODE");
                    return Ok(true);
                }
                if !self.state.secure_active {
                    ui.print_line(
                        "Secure handshake is in progress. Wait for '[e2e] secure session established'.",
                    );
                    return Ok(true);
                }

                let payload = match self.secure_messenger.encrypt_outgoing(&text) {
                    Ok(payload) => payload,
                    Err(err) => {
                        ui.print_error(&format!("[e2e] encrypt failed: {err}"));
                        return Ok(true);
                    }
                };

                self.send_request(ws_writer, events::names::E2E_MSG_SEND, payload)
                    .await?;
                Ok(true)
            }
        }
    }

    pub async fn process_server_text(
        &mut self,
        raw: &str,
        ws_writer: &mut WsWriter,
        keys: &mut KeyManager,
        ui: &mut TerminalUi,
    ) -> Result<(), Box<dyn Error>> {
        let action = extract_wire_action(raw);
        if let Some(line) = handle_server_text(raw, &mut self.state) {
            ui.print_line(&line);
        }

        let Some(action) = action else {
            return Ok(());
        };

        match action {
            WireAction::EncryptedMessage(event) => {
                match self.secure_messenger.decrypt_incoming(&event) {
                    Ok(message) => ui.print_line(&format!("peer> {message}")),
                    Err(err) => ui.print_error(&format!("[e2e] drop inbound message: {err}")),
                }
            }
            WireAction::LoginBound(binding) | WireAction::LoginBinding(binding) => {
                self.handle_login_binding(binding.login, binding.ik_ed25519, keys, ui);
            }
            action => {
                if matches!(
                    action,
                    WireAction::SessionStarted { .. } | WireAction::SessionEnded
                ) {
                    self.secure_messenger.clear();
                    self.active_peer_trust = None;
                    self.active_peer_login = None;
                }

                handle_wire_action(
                    action,
                    ws_writer,
                    &mut self.state,
                    &mut self.bootstrap,
                    keys,
                    ui,
                    &mut self.request_counter,
                )
                .await?;

                if let Some(material) = self.bootstrap.take_secure_session_material() {
                    if let Err(err) = self.secure_messenger.activate(&material) {
                        ui.print_error(&format!(
                            "[e2e] failed to activate secure messaging: {err}"
                        ));
                        self.state.secure_active = false;
                    } else {
                        let trust = self.trust.evaluate_peer(&material.peer_ik_ed25519)?;
                        self.active_peer_login = None;
                        self.print_active_trust(ui, &trust);
                        if trust.state == SessionTrustState::KeyChanged {
                            let previous = trust
                                .previous_fingerprint_short
                                .as_deref()
                                .unwrap_or("unknown");
                            ui.print_error(&format!(
                                "[trust] WARNING: peer identity key changed (prev_fp={previous} new_fp={}); re-verify with /trust verify",
                                trust.fingerprint_short
                            ));
                        }
                        self.request_login_lookup_by_ik(ws_writer, &material.peer_ik_ed25519)
                            .await?;
                        self.active_peer_trust = Some(trust);
                    }
                }
            }
        }

        Ok(())
    }

    pub async fn on_handshake_tick(
        &mut self,
        ws_writer: &mut WsWriter,
        ui: &mut TerminalUi,
    ) -> Result<(), Box<dyn Error>> {
        if let Some(message) = self.bootstrap.handshake_timeout_message(now_unix()) {
            ui.print_error(&message);
            self.abort_handshake_session(ws_writer).await?;
        }

        Ok(())
    }

    async fn abort_handshake_session(
        &mut self,
        ws_writer: &mut WsWriter,
    ) -> Result<(), Box<dyn Error>> {
        abort_handshake_session(
            ws_writer,
            &mut self.state,
            &mut self.bootstrap,
            &mut self.request_counter,
        )
        .await?;
        self.secure_messenger.clear();
        self.active_peer_trust = None;
        self.active_peer_login = None;
        Ok(())
    }

    async fn request_invite(
        &mut self,
        ws_writer: &mut WsWriter,
        invite_relay: &str,
        invite_ttl: u32,
    ) -> Result<(), Box<dyn Error>> {
        let payload = InviteCreateRequest {
            r: vec![invite_relay.to_string()],
            e: invite_ttl,
            o: true,
        };

        self.send_request(ws_writer, events::names::INVITE_CREATE, payload)
            .await
    }

    async fn publish_prekeys(
        &mut self,
        ws_writer: &mut WsWriter,
        keys: &KeyManager,
    ) -> Result<(), Box<dyn Error>> {
        let payload = keys.build_prekey_publish_request();
        self.send_request(ws_writer, events::names::E2E_PREKEY_PUBLISH, payload)
            .await
    }

    async fn request_login_lookup_by_login(
        &mut self,
        ws_writer: &mut WsWriter,
        login: &str,
    ) -> Result<(), Box<dyn Error>> {
        self.send_request(
            ws_writer,
            events::names::LOGIN_LOOKUP,
            LoginLookupRequest {
                login: Some(login.to_string()),
                ik_ed25519: None,
            },
        )
        .await
    }

    async fn request_login_lookup_by_ik(
        &mut self,
        ws_writer: &mut WsWriter,
        ik_ed25519: &str,
    ) -> Result<(), Box<dyn Error>> {
        self.send_request(
            ws_writer,
            events::names::LOGIN_LOOKUP,
            LoginLookupRequest {
                login: None,
                ik_ed25519: Some(ik_ed25519.to_string()),
            },
        )
        .await
    }

    async fn send_request<T: Serialize>(
        &mut self,
        ws_writer: &mut WsWriter,
        event_type: &str,
        data: T,
    ) -> Result<(), Box<dyn Error>> {
        let request_id = format!("cli-{}", self.request_counter);
        self.request_counter = self.request_counter.saturating_add(1);

        let envelope = Envelope::new(event_type, data).with_request_id(request_id);
        let raw = serde_json::to_string(&envelope)?;
        ws_writer.send(Message::Text(raw.into())).await?;
        Ok(())
    }

    fn print_trust_status(&self, ui: &mut TerminalUi) {
        if let Some(active) = self.active_peer_trust.as_ref() {
            self.print_active_trust(ui, active);
        } else {
            ui.print_line(&format!(
                "[trust] no active secure peer; verified_contacts={}",
                self.trust.verified_count()
            ));
        }
    }

    fn print_active_trust(&self, ui: &mut TerminalUi, active: &ActivePeerTrust) {
        let login = self
            .active_peer_login
            .as_ref()
            .map(|value| format!(" login={}", format_login(value)))
            .unwrap_or_default();
        ui.print_line(&format!(
            "[trust] state={}{} fp={} safety={}",
            active.state.as_str(),
            login,
            active.fingerprint_short,
            active.safety_number
        ));
    }

    fn handle_login_binding(
        &mut self,
        login: String,
        ik_ed25519: String,
        keys: &KeyManager,
        ui: &mut TerminalUi,
    ) {
        let fp = fingerprint_short_for_ik(&ik_ed25519);
        let formatted = format_login(&login);
        if ik_ed25519 == keys.identity_public_ed25519() {
            self.local_login = Some(login);
            ui.print_line(&format!("[login] local {formatted} fp={fp}"));
            return;
        }

        if let Some(active) = self.active_peer_trust.clone() {
            if active.peer_ik_ed25519 == ik_ed25519 {
                self.active_peer_login = Some(login.clone());
                self.print_active_trust(ui, &active);
                if active.state == SessionTrustState::KeyChanged {
                    let previous = active
                        .previous_fingerprint_short
                        .as_deref()
                        .unwrap_or("unknown");
                    ui.print_error(&format!(
                        "[trust] WARNING: login {formatted} key changed (prev_fp={previous} new_fp={}); re-verify with /trust verify",
                        active.fingerprint_short
                    ));
                }
                return;
            }
        }

        ui.print_line(&format!("[login] {formatted} fp={fp}"));
    }
}
