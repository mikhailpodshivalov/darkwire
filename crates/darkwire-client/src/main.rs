use darkwire_protocol::events::{
    self, Envelope, ErrorEvent, InviteCreateRequest, InviteCreatedEvent, InviteUseRequest,
    MsgRecvEvent, MsgSendRequest, RateLimitedEvent, ReadyEvent, SessionEndReason,
    SessionEndedEvent, SessionLeaveRequest, SessionStartedEvent,
};
use futures_util::{stream::SplitSink, SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::{env, error::Error};
use tokio::{io::AsyncBufReadExt, io::BufReader, net::TcpStream};
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};

const DEFAULT_RELAY_WS: &str = "ws://127.0.0.1:7000/ws";
const DEFAULT_INVITE_TTL: u32 = 10 * 60;

type WsWriter = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let relay_ws = env::var("DARKWIRE_RELAY_WS").unwrap_or_else(|_| DEFAULT_RELAY_WS.to_string());
    let invite_relay = env::var("DARKWIRE_INVITE_RELAY").unwrap_or_else(|_| relay_ws.clone());

    println!("Connecting to {relay_ws} ...");
    let (ws_stream, _) = connect_async(relay_ws.as_str()).await?;
    println!("Connected. Commands: /i, /c CODE, /q");

    let (mut ws_writer, mut ws_reader) = ws_stream.split();
    let mut stdin_lines = BufReader::new(tokio::io::stdin()).lines();

    let mut state = ClientState::default();
    let mut request_counter = 1_u64;

    loop {
        tokio::select! {
            line = stdin_lines.next_line() => {
                let Some(line) = line? else {
                    break;
                };

                let keep_running = handle_user_input(
                    &line,
                    &mut ws_writer,
                    &mut state,
                    &invite_relay,
                    &mut request_counter,
                ).await?;

                if !keep_running {
                    break;
                }
            }
            incoming = ws_reader.next() => {
                match incoming {
                    Some(Ok(Message::Text(raw))) => {
                        handle_server_text(raw.as_ref(), &mut state);
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        ws_writer.send(Message::Pong(payload)).await?;
                    }
                    Some(Ok(Message::Close(frame))) => {
                        if let Some(frame) = frame {
                            println!("Server closed connection: {}", frame.reason);
                        } else {
                            println!("Server closed connection");
                        }
                        break;
                    }
                    Some(Ok(_)) => {}
                    Some(Err(err)) => {
                        eprintln!("WebSocket error: {err}");
                        break;
                    }
                    None => {
                        println!("Connection closed");
                        break;
                    }
                }
            }
        }
    }

    let _ = ws_writer.send(Message::Close(None)).await;
    Ok(())
}

async fn handle_user_input(
    line: &str,
    ws_writer: &mut WsWriter,
    state: &mut ClientState,
    invite_relay: &str,
    request_counter: &mut u64,
) -> Result<bool, Box<dyn Error>> {
    match parse_user_command(line) {
        UserCommand::Ignore => Ok(true),
        UserCommand::Unknown => {
            println!("Unknown command. Use /i, /c CODE, /q");
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
            println!("Bye");
            Ok(false)
        }
        UserCommand::CreateInvite => {
            let payload = InviteCreateRequest {
                r: vec![invite_relay.to_string()],
                e: DEFAULT_INVITE_TTL,
                o: true,
            };

            send_request(
                ws_writer,
                events::names::INVITE_CREATE,
                payload,
                request_counter,
            )
            .await?;
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
                println!("No active session. Use /i or /c CODE");
                return Ok(true);
            }

            let payload = MsgSendRequest { text };
            send_request(ws_writer, events::names::MSG_SEND, payload, request_counter).await?;
            Ok(true)
        }
    }
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

fn handle_server_text(raw: &str, state: &mut ClientState) {
    let envelope: IncomingEnvelope = match serde_json::from_str(raw) {
        Ok(envelope) => envelope,
        Err(_) => {
            eprintln!("Received invalid JSON from server");
            return;
        }
    };

    let rid = envelope.request_id.as_deref().unwrap_or("-");

    match envelope.event_type.as_str() {
        events::names::READY => {
            if let Ok(event) = serde_json::from_value::<ReadyEvent>(envelope.data) {
                println!("[ready:{rid}] server_time={}", event.server_time);
            }
        }
        events::names::INVITE_CREATED => {
            if let Ok(event) = serde_json::from_value::<InviteCreatedEvent>(envelope.data) {
                println!("[invite:{rid}] {}", event.invite);
            }
        }
        events::names::INVITE_USED => {
            println!("[invite:{rid}] accepted");
        }
        events::names::SESSION_STARTED => {
            if let Ok(event) = serde_json::from_value::<SessionStartedEvent>(envelope.data) {
                state.active_session = true;
                println!("[session:{rid}] started id={}", event.session_id);
            }
        }
        events::names::MSG_RECV => {
            if let Ok(event) = serde_json::from_value::<MsgRecvEvent>(envelope.data) {
                println!("peer> {}", event.text);
            }
        }
        events::names::SESSION_ENDED => {
            if let Ok(event) = serde_json::from_value::<SessionEndedEvent>(envelope.data) {
                state.active_session = false;
                println!(
                    "[session:{rid}] ended reason={}",
                    session_end_reason_name(event.reason)
                );
            }
        }
        events::names::RATE_LIMITED => {
            if let Ok(event) = serde_json::from_value::<RateLimitedEvent>(envelope.data) {
                println!(
                    "[rate:{rid}] scope={} retry_after_ms={}",
                    rate_limit_scope_name(event.scope),
                    event.retry_after_ms
                );
            }
        }
        events::names::ERROR => {
            if let Ok(event) = serde_json::from_value::<ErrorEvent>(envelope.data) {
                println!(
                    "[error:{rid}] code={:?} message={}",
                    event.code, event.message
                );
            }
        }
        events::names::PONG => {
            let _ = envelope.data;
        }
        _ => {
            println!("[event:{rid}] {}", envelope.event_type);
        }
    }
}

fn parse_user_command(line: &str) -> UserCommand {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return UserCommand::Ignore;
    }

    if trimmed == "/i" {
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
}
