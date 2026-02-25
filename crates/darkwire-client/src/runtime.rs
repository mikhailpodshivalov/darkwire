use crate::{
    bootstrap::{abort_handshake_session, handle_wire_action, now_unix, BootstrapState},
    commands::{parse_user_command, UserCommand},
    e2e::SecureMessenger,
    keys::KeyManager,
    ui::TerminalUi,
    wire::{extract_wire_action, handle_server_text, ClientState, WireAction},
};
use darkwire_protocol::events::{
    self, Envelope, InviteCreateRequest, InviteUseRequest, SessionLeaveRequest,
};
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
    request_counter: u64,
}

impl ClientRuntime {
    pub fn new() -> Self {
        Self {
            state: ClientState::default(),
            bootstrap: BootstrapState::default(),
            secure_messenger: SecureMessenger::default(),
            request_counter: 1,
        }
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
            UserCommand::Unknown => {
                ui.print_line(
                    "Unknown command. Use /new, /c CODE, /keys, /keys rotate, /keys refill, /keys revoke, /q",
                );
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
            action => {
                if matches!(
                    action,
                    WireAction::SessionStarted { .. } | WireAction::SessionEnded
                ) {
                    self.secure_messenger.clear();
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
}
