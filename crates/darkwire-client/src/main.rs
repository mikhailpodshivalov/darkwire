use clap::Parser;
use crossterm::{
    event::{Event, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    terminal::{disable_raw_mode, enable_raw_mode},
};
use darkwire_protocol::events::{
    self, Envelope, ErrorEvent, InviteCreateRequest, InviteCreatedEvent, InviteUseRequest,
    MsgRecvEvent, MsgSendRequest, RateLimitedEvent, ReadyEvent, SessionEndReason,
    SessionEndedEvent, SessionLeaveRequest, SessionStartedEvent,
};
use futures_util::{stream::SplitSink, SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    io::{self, IsTerminal, Write},
};
use tokio::{
    io::AsyncBufReadExt,
    io::BufReader,
    net::TcpStream,
    sync::mpsc,
    time::{self, Duration, MissedTickBehavior},
};
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};

const DEFAULT_RELAY_WS: &str = "wss://srv1418428.hstgr.cloud/ws";
const DEFAULT_INVITE_TTL: u32 = 10 * 60;

type WsWriter = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;

#[derive(Debug, Parser)]
#[command(name = "darkwire", version, about = "Darkwire terminal chat client")]
struct ClientArgs {
    #[arg(long, env = "DARKWIRE_RELAY_WS", default_value = DEFAULT_RELAY_WS)]
    relay: String,
    #[arg(long, env = "DARKWIRE_INVITE_RELAY")]
    invite_relay: Option<String>,
    #[arg(
        long,
        env = "DARKWIRE_INVITE_TTL",
        default_value_t = DEFAULT_INVITE_TTL,
        value_parser = clap::value_parser!(u32).range(1..=86_400)
    )]
    invite_ttl: u32,
    #[arg(
        long,
        env = "DARKWIRE_DEMO_INCOMING_MS",
        value_parser = clap::value_parser!(u64).range(50..=60_000)
    )]
    demo_incoming_ms: Option<u64>,
}

#[derive(Debug, Default)]
struct ClientState {
    active_session: bool,
}

#[derive(Debug, Deserialize)]
struct IncomingEnvelope {
    #[serde(rename = "t")]
    event_type: String,
    #[serde(rename = "rid")]
    request_id: Option<String>,
    #[serde(rename = "d", default)]
    data: serde_json::Value,
}

#[derive(Debug, PartialEq, Eq)]
enum UserCommand {
    CreateInvite,
    ConnectInvite(String),
    Quit,
    SendMessage(String),
    Ignore,
    Unknown,
}

#[derive(Debug)]
struct TerminalUi {
    interactive: bool,
    input_buffer: String,
}

impl TerminalUi {
    fn new(interactive: bool) -> Self {
        Self {
            interactive,
            input_buffer: String::new(),
        }
    }

    fn print_line(&mut self, line: &str) {
        if self.interactive {
            self.clear_line();
            println!("{line}");
            self.redraw_prompt();
            return;
        }

        println!("{line}");
    }

    fn print_error(&mut self, line: &str) {
        if self.interactive {
            self.clear_line();
            eprintln!("{line}");
            self.redraw_prompt();
            return;
        }

        eprintln!("{line}");
    }

    fn redraw_prompt(&self) {
        if !self.interactive {
            return;
        }

        print!("\r\x1b[2K> {}", self.input_buffer);
        let _ = io::stdout().flush();
    }

    fn clear_line(&self) {
        if !self.interactive {
            return;
        }

        print!("\r\x1b[2K");
        let _ = io::stdout().flush();
    }

    fn handle_key_event(&mut self, key: KeyEvent) -> Option<String> {
        if key.kind == KeyEventKind::Release {
            return None;
        }

        match key.code {
            KeyCode::Enter => {
                let submitted = std::mem::take(&mut self.input_buffer);
                self.clear_line();
                println!();
                self.redraw_prompt();
                Some(submitted)
            }
            KeyCode::Backspace => {
                self.input_buffer.pop();
                self.redraw_prompt();
                None
            }
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                Some("/q".to_string())
            }
            KeyCode::Char(ch) => {
                if key.modifiers.contains(KeyModifiers::CONTROL) {
                    return None;
                }

                self.input_buffer.push(ch);
                self.redraw_prompt();
                None
            }
            _ => None,
        }
    }
}

struct RawModeGuard;

impl RawModeGuard {
    fn activate(enabled: bool) -> io::Result<Option<Self>> {
        if !enabled {
            return Ok(None);
        }

        enable_raw_mode()?;
        Ok(Some(Self))
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        print!("\r\x1b[2K");
        let _ = io::stdout().flush();
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    install_rustls_crypto_provider();

    let args = ClientArgs::parse();
    let relay_ws = args.relay.clone();
    let invite_relay = resolve_invite_relay(&args);
    let invite_ttl = args.invite_ttl;
    let interactive_stdin = io::stdin().is_terminal() && io::stdout().is_terminal();
    let _raw_mode_guard = RawModeGuard::activate(interactive_stdin)?;
    let mut ui = TerminalUi::new(interactive_stdin);
    let demo_enabled = args.demo_incoming_ms.is_some();
    let mut demo_rx = spawn_demo_incoming(args.demo_incoming_ms);

    ui.print_line(&format!("Connecting to {relay_ws} ..."));
    let (ws_stream, _) = connect_async(relay_ws.as_str()).await?;
    ui.print_line("Connected. Commands: /new, /c CODE, /q (/i alias)");

    let (mut ws_writer, mut ws_reader) = ws_stream.split();
    let mut stdin_lines = BufReader::new(tokio::io::stdin()).lines();
    let mut key_events = EventStream::new();

    let mut state = ClientState::default();
    let mut request_counter = 1_u64;
    request_invite(
        &mut ws_writer,
        &invite_relay,
        invite_ttl,
        &mut request_counter,
    )
    .await?;
    ui.redraw_prompt();

    loop {
        tokio::select! {
            line = stdin_lines.next_line(), if !interactive_stdin => {
                let Some(line) = line? else {
                    break;
                };

                let keep_running = handle_user_input(
                    &line,
                    &mut ws_writer,
                    &mut state,
                    &mut ui,
                    &invite_relay,
                    invite_ttl,
                    &mut request_counter,
                ).await?;

                if !keep_running {
                    break;
                }
            }
            maybe_key_event = key_events.next(), if interactive_stdin => {
                let Some(Ok(Event::Key(key))) = maybe_key_event else {
                    continue;
                };

                let Some(line) = ui.handle_key_event(key) else {
                    continue;
                };

                let keep_running = handle_user_input(
                    &line,
                    &mut ws_writer,
                    &mut state,
                    &mut ui,
                    &invite_relay,
                    invite_ttl,
                    &mut request_counter,
                ).await?;

                if !keep_running {
                    break;
                }
            }
            incoming = ws_reader.next() => {
                match incoming {
                    Some(Ok(Message::Text(raw))) => {
                        if let Some(line) = handle_server_text(raw.as_ref(), &mut state) {
                            ui.print_line(&line);
                        }
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        ws_writer.send(Message::Pong(payload)).await?;
                    }
                    Some(Ok(Message::Close(frame))) => {
                        if let Some(frame) = frame {
                            ui.print_line(&format!("Server closed connection: {}", frame.reason));
                        } else {
                            ui.print_line("Server closed connection");
                        }
                        break;
                    }
                    Some(Ok(_)) => {}
                    Some(Err(err)) => {
                        ui.print_error(&format!("WebSocket error: {err}"));
                        break;
                    }
                    None => {
                        ui.print_line("Connection closed");
                        break;
                    }
                }
            }
            Some(simulated) = demo_rx.recv(), if demo_enabled => {
                ui.print_line(&simulated);
            }
        }
    }

    ui.clear_line();
    let _ = ws_writer.send(Message::Close(None)).await;
    Ok(())
}

fn spawn_demo_incoming(interval_ms: Option<u64>) -> mpsc::UnboundedReceiver<String> {
    let (tx, rx) = mpsc::unbounded_channel();
    let Some(interval_ms) = interval_ms else {
        return rx;
    };

    tokio::spawn(async move {
        let mut counter = 1_u64;
        let mut interval = time::interval(Duration::from_millis(interval_ms));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            interval.tick().await;
            let line = format!("[demo] simulated incoming message #{counter}");
            if tx.send(line).is_err() {
                break;
            }
            counter = counter.saturating_add(1);
        }
    });

    rx
}

fn install_rustls_crypto_provider() {
    // rustls 0.23 requires selecting a process-level provider before TLS handshakes.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

async fn handle_user_input(
    line: &str,
    ws_writer: &mut WsWriter,
    state: &mut ClientState,
    ui: &mut TerminalUi,
    invite_relay: &str,
    invite_ttl: u32,
    request_counter: &mut u64,
) -> Result<bool, Box<dyn Error>> {
    match parse_user_command(line) {
        UserCommand::Ignore => Ok(true),
        UserCommand::Unknown => {
            ui.print_line("Unknown command. Use /new, /c CODE, /q");
            Ok(true)
        }
        UserCommand::Quit => {
            if state.active_session {
                send_request(
                    ws_writer,
                    events::names::SESSION_LEAVE,
                    SessionLeaveRequest::default(),
                    request_counter,
                )
                .await?;
            }
            ui.print_line("Bye");
            Ok(false)
        }
        UserCommand::CreateInvite => {
            request_invite(ws_writer, invite_relay, invite_ttl, request_counter).await?;
            Ok(true)
        }
        UserCommand::ConnectInvite(invite) => {
            let payload = InviteUseRequest { invite };
            send_request(
                ws_writer,
                events::names::INVITE_USE,
                payload,
                request_counter,
            )
            .await?;
            Ok(true)
        }
        UserCommand::SendMessage(text) => {
            if !state.active_session {
                ui.print_line("No active session. Use /new or /c CODE");
                return Ok(true);
            }

            let payload = MsgSendRequest { text };
            send_request(ws_writer, events::names::MSG_SEND, payload, request_counter).await?;
            Ok(true)
        }
    }
}

async fn request_invite(
    ws_writer: &mut WsWriter,
    invite_relay: &str,
    invite_ttl: u32,
    request_counter: &mut u64,
) -> Result<(), Box<dyn Error>> {
    let payload = InviteCreateRequest {
        r: vec![invite_relay.to_string()],
        e: invite_ttl,
        o: true,
    };

    send_request(
        ws_writer,
        events::names::INVITE_CREATE,
        payload,
        request_counter,
    )
    .await
}

async fn send_request<T: Serialize>(
    ws_writer: &mut WsWriter,
    event_type: &str,
    data: T,
    request_counter: &mut u64,
) -> Result<(), Box<dyn Error>> {
    let request_id = format!("cli-{}", *request_counter);
    *request_counter = request_counter.saturating_add(1);

    let envelope = Envelope::new(event_type, data).with_request_id(request_id);
    let raw = serde_json::to_string(&envelope)?;
    ws_writer.send(Message::Text(raw.into())).await?;
    Ok(())
}

fn handle_server_text(raw: &str, state: &mut ClientState) -> Option<String> {
    let envelope: IncomingEnvelope = match serde_json::from_str(raw) {
        Ok(envelope) => envelope,
        Err(_) => {
            return Some("Received invalid JSON from server".to_string());
        }
    };

    let rid = envelope.request_id.as_deref().unwrap_or("-");

    match envelope.event_type.as_str() {
        events::names::READY => {
            if let Ok(event) = serde_json::from_value::<ReadyEvent>(envelope.data) {
                return Some(format!("[ready:{rid}] server_time={}", event.server_time));
            }
        }
        events::names::INVITE_CREATED => {
            if let Ok(event) = serde_json::from_value::<InviteCreatedEvent>(envelope.data) {
                return Some(format!("[invite:{rid}] {}", event.invite));
            }
        }
        events::names::INVITE_USED => {
            return Some(format!("[invite:{rid}] accepted"));
        }
        events::names::SESSION_STARTED => {
            if let Ok(event) = serde_json::from_value::<SessionStartedEvent>(envelope.data) {
                state.active_session = true;
                return Some(format!("[session:{rid}] started id={}", event.session_id));
            }
        }
        events::names::MSG_RECV => {
            if let Ok(event) = serde_json::from_value::<MsgRecvEvent>(envelope.data) {
                return Some(format!("peer> {}", event.text));
            }
        }
        events::names::SESSION_ENDED => {
            if let Ok(event) = serde_json::from_value::<SessionEndedEvent>(envelope.data) {
                state.active_session = false;
                return Some(format!(
                    "[session:{rid}] ended reason={}",
                    session_end_reason_name(event.reason)
                ));
            }
        }
        events::names::RATE_LIMITED => {
            if let Ok(event) = serde_json::from_value::<RateLimitedEvent>(envelope.data) {
                return Some(format!(
                    "[rate:{rid}] scope={} retry_after_ms={}",
                    rate_limit_scope_name(event.scope),
                    event.retry_after_ms
                ));
            }
        }
        events::names::ERROR => {
            if let Ok(event) = serde_json::from_value::<ErrorEvent>(envelope.data) {
                return Some(format!(
                    "[error:{rid}] code={:?} message={}",
                    event.code, event.message
                ));
            }
        }
        events::names::PONG => {
            let _ = envelope.data;
        }
        _ => {
            return Some(format!("[event:{rid}] {}", envelope.event_type));
        }
    }

    None
}

fn parse_user_command(line: &str) -> UserCommand {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return UserCommand::Ignore;
    }

    if trimmed == "/new" || trimmed == "/i" {
        return UserCommand::CreateInvite;
    }

    if trimmed == "/q" {
        return UserCommand::Quit;
    }

    if trimmed.starts_with("/c") {
        let mut parts = trimmed.split_whitespace();
        let command = parts.next();
        let invite = parts.next();

        if command == Some("/c") {
            if let Some(invite) = invite {
                return UserCommand::ConnectInvite(invite.to_string());
            }
            return UserCommand::Unknown;
        }
    }

    if trimmed.starts_with('/') {
        return UserCommand::Unknown;
    }

    UserCommand::SendMessage(line.to_string())
}

fn session_end_reason_name(reason: SessionEndReason) -> &'static str {
    match reason {
        SessionEndReason::PeerDisconnect => "peer_disconnect",
        SessionEndReason::IdleTimeout => "idle_timeout",
        SessionEndReason::PeerQuit => "peer_quit",
    }
}

fn resolve_invite_relay(args: &ClientArgs) -> String {
    args.invite_relay
        .clone()
        .unwrap_or_else(|| args.relay.clone())
}

fn rate_limit_scope_name(scope: darkwire_protocol::events::RateLimitScope) -> &'static str {
    match scope {
        darkwire_protocol::events::RateLimitScope::InviteCreate => "invite_create",
        darkwire_protocol::events::RateLimitScope::InviteUse => "invite_use",
        darkwire_protocol::events::RateLimitScope::MsgSend => "msg_send",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_command_invite_create() {
        assert_eq!(parse_user_command("/new"), UserCommand::CreateInvite);
    }

    #[test]
    fn parse_command_invite_create_legacy_alias() {
        assert_eq!(parse_user_command("/i"), UserCommand::CreateInvite);
    }

    #[test]
    fn parse_command_invite_connect() {
        assert_eq!(
            parse_user_command("/c DL1:abc.def"),
            UserCommand::ConnectInvite("DL1:abc.def".to_string())
        );
    }

    #[test]
    fn parse_command_quit() {
        assert_eq!(parse_user_command("/q"), UserCommand::Quit);
    }

    #[test]
    fn parse_command_message() {
        assert_eq!(
            parse_user_command("hello"),
            UserCommand::SendMessage("hello".to_string())
        );
    }

    #[test]
    fn parse_command_unknown_for_bad_connect() {
        assert_eq!(parse_user_command("/c"), UserCommand::Unknown);
    }

    #[test]
    fn cli_defaults_match_contract() {
        let args = ClientArgs::parse_from(["darkwire"]);
        assert_eq!(args.relay, DEFAULT_RELAY_WS);
        assert_eq!(args.invite_relay, None);
        assert_eq!(args.invite_ttl, DEFAULT_INVITE_TTL);
        assert_eq!(args.demo_incoming_ms, None);
    }

    #[test]
    fn invite_relay_falls_back_to_relay_when_not_set() {
        let args = ClientArgs::parse_from(["darkwire", "--relay", "ws://127.0.0.1:7777/ws"]);
        assert_eq!(resolve_invite_relay(&args), "ws://127.0.0.1:7777/ws");
    }

    #[test]
    fn invite_relay_uses_explicit_value_when_set() {
        let args = ClientArgs::parse_from([
            "darkwire",
            "--relay",
            "ws://127.0.0.1:7777/ws",
            "--invite-relay",
            "ws://127.0.0.1:8888/ws",
        ]);
        assert_eq!(resolve_invite_relay(&args), "ws://127.0.0.1:8888/ws");
    }

    #[test]
    fn cli_demo_incoming_ms_uses_flag_value() {
        let args = ClientArgs::parse_from(["darkwire", "--demo-incoming-ms", "200"]);
        assert_eq!(args.demo_incoming_ms, Some(200));
    }
}
