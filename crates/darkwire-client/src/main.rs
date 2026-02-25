mod bootstrap;
mod commands;
mod config;
mod e2e;
mod keys;
mod ui;
mod wire;

use bootstrap::{abort_handshake_session, handle_wire_action, now_unix, BootstrapState};
use clap::Parser;
use commands::{parse_user_command, UserCommand};
use config::{resolve_invite_relay, ClientArgs};
use crossterm::event::{Event, EventStream};
use darkwire_protocol::events::{
    self, Envelope, InviteCreateRequest, InviteUseRequest, SessionLeaveRequest,
};
use e2e::SecureMessenger;
use futures_util::{stream::SplitSink, SinkExt, StreamExt};
use keys::{default_key_file_path, KeyManager};
use serde::Serialize;
use std::{error::Error, io::IsTerminal};
use tokio::{
    io::AsyncBufReadExt,
    io::BufReader,
    net::TcpStream,
    sync::mpsc,
    time::{self, Duration, MissedTickBehavior},
};
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};
use ui::{RawModeGuard, TerminalUi};
use wire::{extract_wire_action, handle_server_text, ClientState, WireAction};

type WsWriter = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    install_rustls_crypto_provider();

    let args = ClientArgs::parse();
    let relay_ws = args.relay.clone();
    let invite_relay = resolve_invite_relay(&args);
    let invite_ttl = args.invite_ttl;
    let key_file = args.key_file.clone().unwrap_or_else(default_key_file_path);
    let interactive_stdin = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let _raw_mode_guard = RawModeGuard::activate(interactive_stdin)?;
    let mut ui = TerminalUi::new(interactive_stdin);
    let demo_enabled = args.demo_incoming_ms.is_some();
    let mut demo_rx = spawn_demo_incoming(args.demo_incoming_ms);
    let mut keys = KeyManager::load_or_init(key_file)?;

    ui.print_line(&format!("Connecting to {relay_ws} ..."));
    let (ws_stream, _) = connect_async(relay_ws.as_str()).await?;
    ui.print_line("Connected. Commands: /new, /c CODE, /keys, /keys rotate, /keys refill, /keys revoke, /q (/i alias)");
    ui.print_line(&format!(
        "[keys] {} file={}",
        keys.status_line(),
        keys.key_file().display()
    ));

    let (mut ws_writer, mut ws_reader) = ws_stream.split();
    let mut stdin_lines = BufReader::new(tokio::io::stdin()).lines();
    let mut key_events = EventStream::new();
    let mut handshake_tick = time::interval(Duration::from_secs(1));
    handshake_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut state = ClientState::default();
    let mut bootstrap = BootstrapState::default();
    let mut secure_messenger = SecureMessenger::default();
    let mut request_counter = 1_u64;
    publish_prekeys(&mut ws_writer, &keys, &mut request_counter).await?;
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
                    &mut keys,
                    &mut bootstrap,
                    &mut secure_messenger,
                    &mut request_counter,
                ).await?;

                if !keep_running {
                    break;
                }
            }
            maybe_key_event = key_events.next(), if interactive_stdin => {
                let Some(Ok(event)) = maybe_key_event else {
                    continue;
                };

                let maybe_line = match event {
                    Event::Key(key) => ui.handle_key_event(key),
                    Event::Paste(text) => {
                        ui.handle_paste(&text);
                        None
                    }
                    _ => None,
                };

                let Some(line) = maybe_line else {
                    continue;
                };

                let keep_running = handle_user_input(
                    &line,
                    &mut ws_writer,
                    &mut state,
                    &mut ui,
                    &invite_relay,
                    invite_ttl,
                    &mut keys,
                    &mut bootstrap,
                    &mut secure_messenger,
                    &mut request_counter,
                ).await?;

                if !keep_running {
                    break;
                }
            }
            incoming = ws_reader.next() => {
                match incoming {
                    Some(Ok(Message::Text(raw))) => {
                        let action = extract_wire_action(raw.as_ref());
                        if let Some(line) = handle_server_text(raw.as_ref(), &mut state) {
                            ui.print_line(&line);
                        }
                        if let Some(action) = action {
                            match action {
                                WireAction::EncryptedMessage(event) => {
                                    match secure_messenger.decrypt_incoming(&event) {
                                        Ok(message) => ui.print_line(&format!("peer> {message}")),
                                        Err(err) => ui.print_error(&format!("[e2e] drop inbound message: {err}")),
                                    }
                                }
                                action => {
                                    if matches!(action, WireAction::SessionStarted { .. } | WireAction::SessionEnded) {
                                        secure_messenger.clear();
                                    }

                                    handle_wire_action(
                                        action,
                                        &mut ws_writer,
                                        &mut state,
                                        &mut bootstrap,
                                        &mut keys,
                                        &mut ui,
                                        &mut request_counter,
                                    ).await?;

                                    if let Some(material) = bootstrap.take_secure_session_material() {
                                        if let Err(err) = secure_messenger.activate(&material) {
                                            ui.print_error(&format!("[e2e] failed to activate secure messaging: {err}"));
                                            state.secure_active = false;
                                        }
                                    }
                                }
                            }
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
            _ = handshake_tick.tick() => {
                if let Some(message) = bootstrap.handshake_timeout_message(now_unix()) {
                    ui.print_error(&message);
                    abort_handshake_session(
                        &mut ws_writer,
                        &mut state,
                        &mut bootstrap,
                        &mut request_counter,
                    ).await?;
                    secure_messenger.clear();
                }
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
    keys: &mut KeyManager,
    bootstrap: &mut BootstrapState,
    secure_messenger: &mut SecureMessenger,
    request_counter: &mut u64,
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
            publish_prekeys(ws_writer, keys, request_counter).await?;
            ui.print_line(&format!(
                "[keys] rotated + published {}",
                keys.status_line()
            ));
            Ok(true)
        }
        UserCommand::KeyRefill => {
            let added = keys.refill_one_time_prekeys()?;
            publish_prekeys(ws_writer, keys, request_counter).await?;
            ui.print_line(&format!(
                "[keys] refill added={} + published {}",
                added,
                keys.status_line()
            ));
            Ok(true)
        }
        UserCommand::KeyRevoke => {
            keys.revoke_and_regenerate()?;
            publish_prekeys(ws_writer, keys, request_counter).await?;
            if state.active_session {
                abort_handshake_session(ws_writer, state, bootstrap, request_counter).await?;
                secure_messenger.clear();
            }
            ui.print_line(&format!(
                "[keys] identity revoked/regenerated + published {}",
                keys.status_line()
            ));
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
            if !state.secure_active {
                ui.print_line(
                    "Secure handshake is in progress. Wait for '[e2e] secure session established'.",
                );
                return Ok(true);
            }
            let payload = match secure_messenger.encrypt_outgoing(&text) {
                Ok(payload) => payload,
                Err(err) => {
                    ui.print_error(&format!("[e2e] encrypt failed: {err}"));
                    return Ok(true);
                }
            };
            send_request(
                ws_writer,
                events::names::E2E_MSG_SEND,
                payload,
                request_counter,
            )
            .await?;
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

async fn publish_prekeys(
    ws_writer: &mut WsWriter,
    keys: &KeyManager,
    request_counter: &mut u64,
) -> Result<(), Box<dyn Error>> {
    let payload = keys.build_prekey_publish_request();
    send_request(
        ws_writer,
        events::names::E2E_PREKEY_PUBLISH,
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
