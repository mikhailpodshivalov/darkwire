mod bootstrap;
mod commands;
mod config;
mod e2e;
mod keys;
mod runtime;
mod session_store;
mod trust;
mod ui;
mod wire;

use clap::Parser;
use config::{load_dotenv, resolve_invite_relay, ClientArgs};
use crossterm::event::{Event, EventStream};
use darkwire_protocol::events::Envelope;
use futures_util::{SinkExt, StreamExt};
use keys::{default_key_file_path, KeyManager};
use runtime::ClientRuntime;
use serde::Serialize;
use session_store::{default_session_store_path, SessionStore};
use std::{error::Error, io::IsTerminal};
use tokio::{
    io::AsyncBufReadExt,
    io::BufReader,
    sync::mpsc,
    time::{self, Duration, MissedTickBehavior},
};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use trust::{default_trust_file_path, TrustManager};
use ui::{RawModeGuard, TerminalUi};

pub(crate) use runtime::WsWriter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    install_rustls_crypto_provider();
    load_dotenv();

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
    ui.print_line("Connected. Use /help for basic commands.");
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

    let trust_file = default_trust_file_path(keys.key_file());
    let trust = TrustManager::load_or_init(trust_file)?;
    let session_store_file = default_session_store_path(keys.key_file());
    let session_store =
        SessionStore::load_or_init(session_store_file, keys.identity_public_ed25519())?;
    let mut runtime = ClientRuntime::new(trust, session_store);
    ui.print_line(&runtime.trust_overview_line());
    ui.print_line(&runtime.session_resume_overview_line());
    runtime
        .initialize_session(&mut ws_writer, &keys, &invite_relay, invite_ttl)
        .await?;
    ui.redraw_prompt();

    loop {
        tokio::select! {
            line = stdin_lines.next_line(), if !interactive_stdin => {
                let Some(line) = line? else {
                    break;
                };

                let keep_running = handle_user_input(
                    &line, &mut ws_writer, &mut runtime, &mut ui, &invite_relay, invite_ttl,
                    &mut keys,
                )
                .await?;

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
                    Event::Resize(_, _) => {
                        ui.redraw_prompt();
                        None
                    }
                    _ => None,
                };

                let Some(line) = maybe_line else {
                    continue;
                };

                let keep_running = handle_user_input(
                    &line, &mut ws_writer, &mut runtime, &mut ui, &invite_relay, invite_ttl,
                    &mut keys,
                )
                .await?;

                if !keep_running {
                    break;
                }
            }
            incoming = ws_reader.next() => {
                match incoming {
                    Some(Ok(Message::Text(raw))) => {
                        runtime
                            .process_server_text(raw.as_ref(), &mut ws_writer, &mut keys, &mut ui)
                            .await?;
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
                runtime.on_handshake_tick(&mut ws_writer, &mut ui).await?;
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
    runtime: &mut ClientRuntime,
    ui: &mut TerminalUi,
    invite_relay: &str,
    invite_ttl: u32,
    keys: &mut KeyManager,
) -> Result<bool, Box<dyn Error>> {
    runtime
        .process_user_line(line, ws_writer, ui, invite_relay, invite_ttl, keys)
        .await
}

pub(crate) async fn send_request<T: Serialize>(
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
