mod recovery;
mod session_flow;

use crate::{
    bootstrap::{now_unix, BootstrapState},
    commands::{command_help_basic_lines, parse_user_command, UserCommand},
    e2e::SecureMessenger,
    keys::KeyManager,
    session_store::SessionStore,
    trust::{fingerprint_short_for_ik, ActivePeerTrust, SessionTrustState, TrustManager},
    ui::TerminalUi,
    wire::{extract_wire_action, handle_server_text, ClientState, WireAction},
};
use darkwire_protocol::events::{
    self, E2eMsgRecvEvent, E2eMsgSendRequest, Envelope, ErrorCode, ErrorEvent, InviteCreateRequest,
    InviteUseRequest, LoginBindRequest, LoginLookupRequest, RateLimitScope, RateLimitedEvent,
    SessionLeaveRequest,
};
use darkwire_protocol::invite::decode_invite;
use darkwire_protocol::login::{format_login, normalize_login};
use futures_util::{stream::SplitSink, SinkExt};
use recovery::RecoveryState;
use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::error::Error;
use tokio::net::TcpStream;
use tokio::time::{Duration, Instant};
use tokio_tungstenite::{tungstenite::Message, MaybeTlsStream, WebSocketStream};

pub type WsWriter = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;

const USERNAME_PROMPT: &str = "Who are you? enter your username:";
const LOGIN_FORMAT_ERROR: &str =
    "[login] invalid login format; use 3-24 chars [a-z0-9_.-], optional @ prefix";
const CLIENT_SEND_INTERVAL: Duration = Duration::from_millis(1050);
const RATE_RETRY_SAFETY_BUFFER: Duration = Duration::from_millis(25);
const OUTBOUND_INFLIGHT_TTL: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
struct QueuedOutboundMessage {
    payload: E2eMsgSendRequest,
    next_attempt_at: Instant,
    retry_count: u32,
}

pub struct ClientRuntime {
    state: ClientState,
    bootstrap: BootstrapState,
    secure_messenger: SecureMessenger,
    trust: TrustManager,
    session_store: SessionStore,
    active_peer_trust: Option<ActivePeerTrust>,
    active_peer_login: Option<String>,
    pending_resume_peer_ik: Option<String>,
    recovery: RecoveryState,
    local_login: Option<String>,
    pending_local_login_lookup: HashSet<String>,
    pending_peer_login_lookup: HashSet<String>,
    peer_login_missing_notified: bool,
    last_peer_login_lookup_unix: u64,
    awaiting_username_entry: bool,
    pending_invite_copy_request_id: Option<String>,
    outbound_queue: VecDeque<QueuedOutboundMessage>,
    outbound_inflight: HashMap<String, (QueuedOutboundMessage, Instant)>,
    next_send_allowed_at: Instant,
    request_counter: u64,
}

impl ClientRuntime {
    pub fn new(trust: TrustManager, session_store: SessionStore) -> Self {
        Self {
            state: ClientState::default(),
            bootstrap: BootstrapState::default(),
            secure_messenger: SecureMessenger::default(),
            trust,
            session_store,
            active_peer_trust: None,
            active_peer_login: None,
            pending_resume_peer_ik: None,
            recovery: RecoveryState::default(),
            local_login: None,
            pending_local_login_lookup: HashSet::new(),
            pending_peer_login_lookup: HashSet::new(),
            peer_login_missing_notified: false,
            last_peer_login_lookup_unix: 0,
            awaiting_username_entry: false,
            pending_invite_copy_request_id: None,
            outbound_queue: VecDeque::new(),
            outbound_inflight: HashMap::new(),
            next_send_allowed_at: Instant::now(),
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

    pub fn session_resume_overview_line(&self) -> String {
        format!(
            "[resume] stored_sessions={} file={}",
            self.session_store.session_count(),
            self.session_store.session_file().display()
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
        let _ = self
            .request_invite(ws_writer, keys, invite_relay, invite_ttl)
            .await?;
        self.request_login_lookup_by_ik(ws_writer, keys.identity_public_ed25519(), true)
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
        if self.awaiting_username_entry && !line.trim().starts_with('/') {
            let Some(login) = self.normalize_login_or_print_error(line, ui) else {
                self.print_username_prompt(ui);
                return Ok(true);
            };

            self.bind_local_login(ws_writer, keys, &login, ui).await?;
            return Ok(true);
        }

        self.execute_user_command(
            parse_user_command(line),
            ws_writer,
            ui,
            invite_relay,
            invite_ttl,
            keys,
        )
        .await
    }

    async fn execute_user_command(
        &mut self,
        command: UserCommand,
        ws_writer: &mut WsWriter,
        ui: &mut TerminalUi,
        invite_relay: &str,
        invite_ttl: u32,
        keys: &mut KeyManager,
    ) -> Result<bool, Box<dyn Error>> {
        match command {
            UserCommand::Ignore => Ok(true),
            UserCommand::Help => {
                ui.print_line("Commands:");
                for line in command_help_basic_lines() {
                    ui.print_line(line);
                }
                Ok(true)
            }
            UserCommand::Unknown => {
                ui.print_line("Unknown command. Use /help");
                Ok(true)
            }
            UserCommand::Quit => {
                if self.state.active_session {
                    let _ = self
                        .send_request(
                            ws_writer,
                            events::names::SESSION_LEAVE,
                            SessionLeaveRequest::default(),
                        )
                        .await?;
                }
                ui.print_line("Bye");
                Ok(false)
            }
            UserCommand::CreateInviteAndCopy => {
                let request_id = self
                    .request_invite(ws_writer, keys, invite_relay, invite_ttl)
                    .await?;
                self.pending_invite_copy_request_id = Some(request_id);
                ui.print_line("[invite] creating invite; will copy to clipboard on receive");
                Ok(true)
            }
            UserCommand::ConnectInvite(invite) => {
                self.pending_resume_peer_ik = decode_invite(&invite)
                    .ok()
                    .and_then(|payload| payload.k)
                    .filter(|ik| !ik.trim().is_empty());

                if let Some(peer_ik) = self.pending_resume_peer_ik.as_deref() {
                    if self.session_store.load_peer(peer_ik).is_some() {
                        ui.print_line(
                            "[resume] found saved secure state for this contact; attempting auto-resume",
                        );
                    }
                }

                let _ = self
                    .send_request(
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
            UserCommand::ToggleDetails => {
                let enabled = ui.toggle_details();
                if enabled {
                    ui.print_line("[ui] details enabled");
                } else {
                    ui.print_line("[ui] clean mode enabled");
                }
                Ok(true)
            }
            UserCommand::SetUsername(raw_login) => {
                let Some(login) = self.normalize_login_or_print_error(&raw_login, ui) else {
                    return Ok(true);
                };
                self.bind_local_login(ws_writer, keys, &login, ui).await?;
                Ok(true)
            }
            UserCommand::AcceptKey => {
                self.verify_or_accept_active_peer(true, ui)?;
                Ok(true)
            }
            UserCommand::SendMessage(text) => {
                if !self.state.active_session {
                    ui.print_line("No active session. Use /my invite copy or /invite CODE");
                    return Ok(true);
                }
                if self.recovery.is_send_blocked() {
                    ui.print_error(
                        "[e2e] secure session recovery required; wait for recovery or reconnect with /q then /invite CODE",
                    );
                    return Ok(true);
                }
                if !self.state.secure_active {
                    ui.print_line(
                        "Secure handshake is in progress. Wait for '[e2e] secure session established'.",
                    );
                    return Ok(true);
                }
                if self
                    .active_peer_trust
                    .as_ref()
                    .is_some_and(|trust| trust.state == SessionTrustState::KeyChanged)
                {
                    ui.print_error(
                        "[trust] peer key changed; use /accept-key before sending messages",
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

                self.enqueue_outbound_message(payload);
                self.flush_outbound_queue(ws_writer).await?;
                self.persist_active_session_checkpoint()?;
                ui.print_line(&format!("you> {}", text));
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

        self.handle_wire_action_event(action, ws_writer, keys, ui)
            .await
    }

    async fn handle_wire_action_event(
        &mut self,
        action: WireAction,
        ws_writer: &mut WsWriter,
        keys: &mut KeyManager,
        ui: &mut TerminalUi,
    ) -> Result<(), Box<dyn Error>> {
        match action {
            WireAction::InviteCreated { request_id, invite } => {
                if self.pending_invite_copy_request_id.as_deref() == request_id.as_deref() {
                    self.pending_invite_copy_request_id = None;
                    self.copy_invite_or_print(ui, &invite);
                }
            }
            WireAction::SessionStarted { session_id } => {
                self.handle_session_started(session_id, ws_writer, keys, ui)
                    .await?;
            }
            WireAction::SessionEnded => {
                self.reset_secure_runtime_state(true);
                self.forward_wire_action(WireAction::SessionEnded, ws_writer, keys, ui)
                    .await?;
            }
            WireAction::EncryptedMessage(event) => {
                self.handle_encrypted_message(event, ws_writer, ui).await?;
            }
            WireAction::LoginBound { request_id, event }
            | WireAction::LoginBinding { request_id, event } => {
                self.handle_login_binding(request_id, event.login, event.ik_ed25519, keys, ui);
            }
            WireAction::RateLimited { request_id, event } => {
                self.handle_rate_limited_event(request_id, event, ui);
                self.flush_outbound_queue(ws_writer).await?;
            }
            WireAction::Error { request_id, event } => {
                self.handle_error_event(request_id, event, ui);
            }
            action => {
                self.forward_wire_action(action, ws_writer, keys, ui)
                    .await?;
                self.activate_secure_material_if_ready(ws_writer, keys, ui)
                    .await?;
            }
        }

        Ok(())
    }

    async fn handle_session_started(
        &mut self,
        session_id: uuid::Uuid,
        ws_writer: &mut WsWriter,
        keys: &mut KeyManager,
        ui: &mut TerminalUi,
    ) -> Result<(), Box<dyn Error>> {
        session_flow::handle_session_started(self, session_id, ws_writer, keys, ui).await
    }

    async fn handle_encrypted_message(
        &mut self,
        event: E2eMsgRecvEvent,
        ws_writer: &mut WsWriter,
        ui: &mut TerminalUi,
    ) -> Result<(), Box<dyn Error>> {
        session_flow::handle_encrypted_message(self, event, ws_writer, ui).await
    }

    async fn activate_secure_material_if_ready(
        &mut self,
        ws_writer: &mut WsWriter,
        keys: &mut KeyManager,
        ui: &mut TerminalUi,
    ) -> Result<(), Box<dyn Error>> {
        session_flow::activate_secure_material_if_ready(self, ws_writer, keys, ui).await
    }

    async fn forward_wire_action(
        &mut self,
        action: WireAction,
        ws_writer: &mut WsWriter,
        keys: &mut KeyManager,
        ui: &mut TerminalUi,
    ) -> Result<(), Box<dyn Error>> {
        session_flow::forward_wire_action(self, action, ws_writer, keys, ui).await
    }

    fn reset_secure_runtime_state(&mut self, clear_pending_resume_peer: bool) {
        session_flow::reset_secure_runtime_state(self, clear_pending_resume_peer);
    }

    pub async fn on_handshake_tick(
        &mut self,
        ws_writer: &mut WsWriter,
        ui: &mut TerminalUi,
    ) -> Result<(), Box<dyn Error>> {
        session_flow::on_handshake_tick(self, ws_writer, ui).await
    }

    pub async fn on_outbox_tick(&mut self, ws_writer: &mut WsWriter) -> Result<(), Box<dyn Error>> {
        self.prune_outbound_inflight();
        self.flush_outbound_queue(ws_writer).await
    }

    async fn request_invite(
        &mut self,
        ws_writer: &mut WsWriter,
        keys: &KeyManager,
        invite_relay: &str,
        invite_ttl: u32,
    ) -> Result<String, Box<dyn Error>> {
        let payload = InviteCreateRequest {
            r: vec![invite_relay.to_string()],
            e: invite_ttl,
            o: true,
            k: Some(keys.identity_public_ed25519().to_string()),
        };

        let request_id = self
            .send_request(ws_writer, events::names::INVITE_CREATE, payload)
            .await?;
        Ok(request_id)
    }

    async fn publish_prekeys(
        &mut self,
        ws_writer: &mut WsWriter,
        keys: &KeyManager,
    ) -> Result<(), Box<dyn Error>> {
        let payload = keys.build_prekey_publish_request();
        let _ = self
            .send_request(ws_writer, events::names::E2E_PREKEY_PUBLISH, payload)
            .await?;
        Ok(())
    }

    async fn request_login_lookup_by_ik(
        &mut self,
        ws_writer: &mut WsWriter,
        ik_ed25519: &str,
        is_local: bool,
    ) -> Result<(), Box<dyn Error>> {
        let request_id = self
            .send_request(
                ws_writer,
                events::names::LOGIN_LOOKUP,
                LoginLookupRequest {
                    login: None,
                    ik_ed25519: Some(ik_ed25519.to_string()),
                },
            )
            .await?;
        if is_local {
            self.pending_local_login_lookup.insert(request_id);
        } else {
            self.pending_peer_login_lookup.insert(request_id);
            self.last_peer_login_lookup_unix = now_unix();
        }
        Ok(())
    }

    async fn send_request<T: Serialize>(
        &mut self,
        ws_writer: &mut WsWriter,
        event_type: &str,
        data: T,
    ) -> Result<String, Box<dyn Error>> {
        let request_id = format!("cli-{}", self.request_counter);
        self.request_counter = self.request_counter.saturating_add(1);

        let envelope = Envelope::new(event_type, data).with_request_id(request_id.clone());
        let raw = serde_json::to_string(&envelope)?;
        ws_writer.send(Message::Text(raw.into())).await?;
        Ok(request_id)
    }

    fn enqueue_outbound_message(&mut self, payload: E2eMsgSendRequest) {
        self.outbound_queue.push_back(QueuedOutboundMessage {
            payload,
            next_attempt_at: Instant::now(),
            retry_count: 0,
        });
    }

    async fn flush_outbound_queue(
        &mut self,
        ws_writer: &mut WsWriter,
    ) -> Result<(), Box<dyn Error>> {
        if !self.state.active_session
            || !self.state.secure_active
            || self.recovery.is_send_blocked()
        {
            return Ok(());
        }
        if self
            .active_peer_trust
            .as_ref()
            .is_some_and(|trust| trust.state == SessionTrustState::KeyChanged)
        {
            return Ok(());
        }

        let now = Instant::now();
        if now < self.next_send_allowed_at {
            return Ok(());
        }

        let Some(front) = self.outbound_queue.front() else {
            return Ok(());
        };
        if front.next_attempt_at > now {
            return Ok(());
        }

        let mut message = self
            .outbound_queue
            .pop_front()
            .expect("front exists because we just checked");
        let request_id = self
            .send_request(
                ws_writer,
                events::names::E2E_MSG_SEND,
                message.payload.clone(),
            )
            .await?;

        let sent_at = Instant::now();
        self.next_send_allowed_at = sent_at + CLIENT_SEND_INTERVAL;
        message.next_attempt_at = self.next_send_allowed_at;
        self.outbound_inflight
            .insert(request_id, (message, sent_at));
        Ok(())
    }

    fn handle_rate_limited_event(
        &mut self,
        request_id: Option<String>,
        event: RateLimitedEvent,
        ui: &mut TerminalUi,
    ) {
        if event.scope != RateLimitScope::MsgSend {
            return;
        }

        let Some(request_id) = request_id else {
            return;
        };

        let Some((mut message, _sent_at)) = self.outbound_inflight.remove(&request_id) else {
            return;
        };

        let retry_delay = retry_delay_for_rate_limit(event.retry_after_ms);
        message.next_attempt_at = Instant::now() + retry_delay;
        message.retry_count = message.retry_count.saturating_add(1);
        self.outbound_queue.push_front(message);
        self.next_send_allowed_at = Instant::now() + retry_delay;
        ui.print_line(&format!(
            "[rate] queued resend after {}ms",
            retry_delay.as_millis()
        ));
    }

    fn prune_outbound_inflight(&mut self) {
        let now = Instant::now();
        self.outbound_inflight.retain(|_, (_, sent_at)| {
            now.saturating_duration_since(*sent_at) <= OUTBOUND_INFLIGHT_TTL
        });
    }

    fn clear_outbound_delivery_state(&mut self) {
        self.outbound_queue.clear();
        self.outbound_inflight.clear();
        self.next_send_allowed_at = Instant::now();
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

    fn persist_active_session_checkpoint(&mut self) -> Result<(), Box<dyn Error>> {
        session_flow::persist_active_session_checkpoint(self)
    }

    async fn maybe_refresh_active_peer_login(
        &mut self,
        ws_writer: &mut WsWriter,
    ) -> Result<(), Box<dyn Error>> {
        if !self.state.active_session || self.active_peer_login.is_some() {
            return Ok(());
        }
        if !self.pending_peer_login_lookup.is_empty() {
            return Ok(());
        }

        let Some(active) = self.active_peer_trust.as_ref() else {
            return Ok(());
        };

        let now = now_unix();
        if now.saturating_sub(self.last_peer_login_lookup_unix) < 10 {
            return Ok(());
        }

        let peer_ik = active.peer_ik_ed25519.clone();
        self.request_login_lookup_by_ik(ws_writer, &peer_ik, false)
            .await?;
        Ok(())
    }

    fn verify_or_accept_active_peer(
        &mut self,
        require_key_changed: bool,
        ui: &mut TerminalUi,
    ) -> Result<(), Box<dyn Error>> {
        let Some(active) = self.active_peer_trust.as_ref() else {
            ui.print_line("[trust] no active secure peer");
            return Ok(());
        };

        if require_key_changed && active.state != SessionTrustState::KeyChanged {
            ui.print_line("[trust] no pending key change");
            return Ok(());
        }

        self.trust.verify_peer(&active.peer_ik_ed25519)?;
        let refreshed = self.trust.evaluate_peer(&active.peer_ik_ed25519)?;
        self.active_peer_trust = Some(refreshed.clone());
        self.print_active_trust(ui, &refreshed);

        if require_key_changed {
            ui.print_line("[trust] key change accepted");
        } else {
            ui.print_line("[trust] peer verified");
        }

        Ok(())
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

    fn incoming_sender_label(&self) -> String {
        if let Some(login) = self.active_peer_login.as_ref() {
            return format!("{}>", format_login(login));
        }

        "peer>".to_string()
    }

    fn handle_login_binding(
        &mut self,
        request_id: Option<String>,
        login: String,
        ik_ed25519: String,
        keys: &KeyManager,
        ui: &mut TerminalUi,
    ) {
        if let Some(request_id) = request_id {
            self.pending_local_login_lookup.remove(&request_id);
            self.pending_peer_login_lookup.remove(&request_id);
        }

        let fp = fingerprint_short_for_ik(&ik_ed25519);
        let formatted = format_login(&login);
        let is_local = ik_ed25519 == keys.identity_public_ed25519();
        let mut is_active_peer = false;

        if let Some(active) = self.active_peer_trust.clone() {
            if active.peer_ik_ed25519 == ik_ed25519 {
                is_active_peer = true;
                self.active_peer_login = Some(login.clone());
                self.peer_login_missing_notified = false;
                if active.state == SessionTrustState::KeyChanged {
                    self.print_active_trust(ui, &active);
                    let previous = active
                        .previous_fingerprint_short
                        .as_deref()
                        .unwrap_or("unknown");
                    self.print_key_changed_warning(
                        ui,
                        previous,
                        &active.fingerprint_short,
                        Some(&login),
                    );
                }
            }
        }

        if is_local {
            self.local_login = Some(login);
            self.awaiting_username_entry = false;
            ui.print_line(&format!("[login] local {formatted} fp={fp}"));
            return;
        }

        if !is_active_peer {
            ui.print_line(&format!("[login] {formatted} fp={fp}"));
        }
    }

    fn handle_error_event(
        &mut self,
        request_id: Option<String>,
        event: ErrorEvent,
        ui: &mut TerminalUi,
    ) {
        let request_id = request_id.unwrap_or_default();

        if self.recovery.is_send_blocked()
            && matches!(
                &event.code,
                ErrorCode::PrekeyNotFound
                    | ErrorCode::StateConflict
                    | ErrorCode::HandshakeInvalid
                    | ErrorCode::HandshakeTimeout
                    | ErrorCode::NoActiveSession
            )
        {
            self.recovery.clear_request_in_flight();
        }

        if self.pending_invite_copy_request_id.as_deref() == Some(request_id.as_str()) {
            self.pending_invite_copy_request_id = None;
        }

        if self.pending_local_login_lookup.remove(&request_id)
            && event.code == ErrorCode::LoginNotFound
            && self.local_login.is_none()
        {
            self.awaiting_username_entry = true;
            self.print_username_prompt(ui);
            return;
        }

        if self.pending_peer_login_lookup.remove(&request_id)
            && event.code == ErrorCode::LoginNotFound
        {
            if !self.peer_login_missing_notified {
                ui.print_line("[login] peer has no username yet");
                self.peer_login_missing_notified = true;
            }
            return;
        }

        match event.code {
            ErrorCode::LoginTaken => ui.print_error("[login] this username is already taken"),
            ErrorCode::LoginInvalid => {
                ui.print_error("[login] invalid username/signature; use /login @name")
            }
            ErrorCode::LoginKeyMismatch => {
                ui.print_error("[login] signature or identity mismatch; retry /login @name")
            }
            ErrorCode::LoginNotFound => ui.print_line("[login] username not found"),
            _ => {}
        }
    }

    async fn bind_local_login(
        &mut self,
        ws_writer: &mut WsWriter,
        keys: &KeyManager,
        login: &str,
        ui: &mut TerminalUi,
    ) -> Result<(), Box<dyn Error>> {
        let signature = keys.sign_login_binding(login)?;
        let _ = self
            .send_request(
                ws_writer,
                events::names::LOGIN_BIND,
                LoginBindRequest {
                    login: login.to_string(),
                    ik_ed25519: keys.identity_public_ed25519().to_string(),
                    sig_ed25519: signature,
                },
            )
            .await?;
        self.awaiting_username_entry = false;
        ui.print_line(&format!("[login] binding {} ...", format_login(login)));
        Ok(())
    }

    fn normalize_login_or_print_error(
        &self,
        raw_login: &str,
        ui: &mut TerminalUi,
    ) -> Option<String> {
        let Some(login) = normalize_login(raw_login) else {
            ui.print_error(LOGIN_FORMAT_ERROR);
            return None;
        };

        Some(login)
    }

    fn copy_invite_or_print(&self, ui: &mut TerminalUi, invite: &str) {
        match ui.copy_to_clipboard(invite) {
            Ok(()) => ui.print_line("[invite] copied to clipboard"),
            Err(err) => {
                ui.print_error(&format!("[invite] clipboard copy not confirmed: {err}"));
                ui.print_line(&format!("[invite] code {invite}"));
            }
        }
    }

    fn print_username_prompt(&self, ui: &mut TerminalUi) {
        ui.print_line(USERNAME_PROMPT);
    }

    fn print_key_changed_warning(
        &self,
        ui: &mut TerminalUi,
        previous_fingerprint: &str,
        new_fingerprint: &str,
        login: Option<&str>,
    ) {
        if let Some(login) = login {
            ui.print_error(&format!(
                "[trust] WARNING: login {} key changed (prev_fp={previous_fingerprint} new_fp={new_fingerprint}); use /accept-key to continue",
                format_login(login)
            ));
            return;
        }

        ui.print_error(&format!(
            "[trust] WARNING: peer identity key changed (prev_fp={previous_fingerprint} new_fp={new_fingerprint}); use /accept-key to continue",
        ));
    }
}

fn retry_delay_for_rate_limit(retry_after_ms: u64) -> Duration {
    Duration::from_millis(retry_after_ms.max(1)).saturating_add(RATE_RETRY_SAFETY_BUFFER)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_delay_has_minimum_and_safety_buffer() {
        assert_eq!(
            retry_delay_for_rate_limit(0),
            Duration::from_millis(1).saturating_add(RATE_RETRY_SAFETY_BUFFER)
        );
        assert_eq!(
            retry_delay_for_rate_limit(34),
            Duration::from_millis(34).saturating_add(RATE_RETRY_SAFETY_BUFFER)
        );
    }
}
