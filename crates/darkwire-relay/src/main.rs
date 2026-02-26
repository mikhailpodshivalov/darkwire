mod app_state;
mod handshake_store;
mod invite_store;
mod logging;
mod login_store;
mod prekey_store;
mod rate_limit;
mod session_store;
mod ws_handler;

use app_state::AppState;
use axum::{routing::get, Router};
use clap::Parser;
use darkwire_protocol::config::LimitsConfig;
use std::{net::SocketAddr, sync::Arc};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, Clone, Parser)]
#[command(name = "darkwire-relay", version, about = "Darkwire websocket relay")]
struct RelayArgs {
    #[arg(long, env = "DARKWIRE_RELAY_ADDR", default_value = "127.0.0.1:7000")]
    listen: SocketAddr,
    #[arg(
        long,
        env = "DARKWIRE_LOG_FILTER",
        default_value = "darkwire_relay=info,tower_http=warn"
    )]
    log_filter: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    load_dotenv();
    let args = RelayArgs::parse();
    init_tracing(&args.log_filter);

    let bind_addr = args.listen;
    let limits = LimitsConfig::default();
    let state = Arc::new(AppState::new(limits.clone()));

    let app = build_app(state);

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    info!(%bind_addr, idle_timeout_secs = limits.idle_timeout_secs, "relay.listening");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

fn load_dotenv() {
    let _ = dotenvy::dotenv();
}

fn build_app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/ws", get(ws_handler::ws_upgrade))
        .with_state(state)
}

fn init_tracing(log_filter: &str) {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(log_filter.to_string()))
        .with(tracing_subscriber::fmt::layer())
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use darkwire_protocol::events::{
        self, E2eMsgAd, E2eMsgSendRequest, Envelope, ErrorCode, ErrorEvent, HandshakeAcceptRequest,
        HandshakeInitRequest, InviteCreateRequest, InviteCreatedEvent, InviteUseRequest,
        LoginBindRequest, LoginBindingEvent, LoginLookupRequest, MsgSendRequest, OneTimePrekey,
        PrekeyBundleEvent, PrekeyGetRequest, PrekeyPublishRequest, PrekeyPublishedEvent,
        RateLimitScope, RateLimitedEvent, SessionEndReason, SessionEndedEvent, SessionStartedEvent,
        SignedPrekey,
    };
    use darkwire_protocol::login::login_bind_transcript;
    use futures_util::{SinkExt, StreamExt};
    use ring::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };
    use serde::{Deserialize, Serialize};
    use std::{
        env,
        sync::{Mutex, MutexGuard, OnceLock},
        time::Duration,
    };
    use tokio::{
        net::TcpStream,
        sync::oneshot,
        time::{sleep, timeout},
    };
    use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};
    use uuid::Uuid;

    type WsClient = WebSocketStream<MaybeTlsStream<TcpStream>>;

    fn env_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock")
    }

    struct EnvOverrideGuard {
        previous: Vec<(&'static str, Option<String>)>,
    }

    impl Drop for EnvOverrideGuard {
        fn drop(&mut self) {
            for (key, value) in self.previous.iter().rev() {
                if let Some(value) = value {
                    env::set_var(key, value);
                } else {
                    env::remove_var(key);
                }
            }
        }
    }

    fn override_env(values: &[(&'static str, Option<&str>)]) -> EnvOverrideGuard {
        let mut previous = Vec::with_capacity(values.len());
        for (key, value) in values {
            previous.push((*key, env::var(key).ok()));
            if let Some(value) = value {
                env::set_var(key, value);
            } else {
                env::remove_var(key);
            }
        }
        EnvOverrideGuard { previous }
    }

    fn clear_relay_env() -> EnvOverrideGuard {
        override_env(&[("DARKWIRE_RELAY_ADDR", None), ("DARKWIRE_LOG_FILTER", None)])
    }

    #[derive(Debug, Deserialize)]
    struct TestEnvelope {
        #[serde(rename = "t")]
        event_type: String,
        #[serde(rename = "rid")]
        request_id: Option<String>,
        #[serde(rename = "d", default)]
        data: serde_json::Value,
    }

    #[test]
    fn relay_addr_defaults_when_not_provided() {
        let _lock = env_lock();
        let _env = clear_relay_env();
        let addr = RelayArgs::parse_from(["darkwire-relay"]).listen;
        assert_eq!(addr.to_string(), "127.0.0.1:7000");
    }

    #[test]
    fn relay_addr_uses_listen_flag() {
        let _lock = env_lock();
        let _env = clear_relay_env();
        let addr = RelayArgs::parse_from(["darkwire-relay", "--listen", "127.0.0.1:7011"]).listen;
        assert_eq!(addr.to_string(), "127.0.0.1:7011");
    }

    #[test]
    fn relay_log_filter_defaults_when_not_provided() {
        let _lock = env_lock();
        let _env = clear_relay_env();
        let filter = RelayArgs::parse_from(["darkwire-relay"]).log_filter;
        assert_eq!(filter, "darkwire_relay=info,tower_http=warn");
    }

    #[test]
    fn relay_log_filter_uses_flag_value() {
        let _lock = env_lock();
        let _env = clear_relay_env();
        let filter =
            RelayArgs::parse_from(["darkwire-relay", "--log-filter", "debug,axum=warn"]).log_filter;
        assert_eq!(filter, "debug,axum=warn");
    }

    #[test]
    fn relay_uses_env_values_when_flags_missing() {
        let _lock = env_lock();
        let _clean = clear_relay_env();
        let _env = override_env(&[
            ("DARKWIRE_RELAY_ADDR", Some("127.0.0.1:7444")),
            ("DARKWIRE_LOG_FILTER", Some("info,axum=warn")),
        ]);

        let args = RelayArgs::parse_from(["darkwire-relay"]);
        assert_eq!(args.listen.to_string(), "127.0.0.1:7444");
        assert_eq!(args.log_filter, "info,axum=warn");
    }

    #[test]
    fn relay_flags_override_env_values() {
        let _lock = env_lock();
        let _clean = clear_relay_env();
        let _env = override_env(&[
            ("DARKWIRE_RELAY_ADDR", Some("127.0.0.1:7444")),
            ("DARKWIRE_LOG_FILTER", Some("info,axum=warn")),
        ]);

        let args = RelayArgs::parse_from([
            "darkwire-relay",
            "--listen",
            "127.0.0.1:7555",
            "--log-filter",
            "debug,axum=error",
        ]);
        assert_eq!(args.listen.to_string(), "127.0.0.1:7555");
        assert_eq!(args.log_filter, "debug,axum=error");
    }

    #[tokio::test]
    async fn integration_plaintext_msg_send_is_rejected_with_e2e_required() {
        let (addr, shutdown_tx, server_task) = spawn_test_relay(LimitsConfig::default()).await;

        let mut inviter = connect_client(addr).await;
        let mut joiner = connect_client(addr).await;

        assert_eq!(
            recv_with_timeout(&mut inviter).await.event_type,
            events::names::READY
        );
        assert_eq!(
            recv_with_timeout(&mut joiner).await.event_type,
            events::names::READY
        );

        send_event(
            &mut inviter,
            events::names::INVITE_CREATE,
            "req-create",
            InviteCreateRequest {
                r: vec![relay_url(addr)],
                e: 600,
                o: true,
                k: None,
            },
        )
        .await;

        let invite_created = recv_until(&mut inviter, events::names::INVITE_CREATED).await;
        assert_eq!(invite_created.request_id.as_deref(), Some("req-create"));
        let invite = serde_json::from_value::<InviteCreatedEvent>(invite_created.data)
            .expect("invite.created payload should parse")
            .invite;

        send_event(
            &mut joiner,
            events::names::INVITE_USE,
            "req-join",
            InviteUseRequest { invite },
        )
        .await;

        assert_eq!(
            recv_until(&mut joiner, events::names::INVITE_USED)
                .await
                .request_id
                .as_deref(),
            Some("req-join")
        );

        let joiner_started = recv_until(&mut joiner, events::names::SESSION_STARTED).await;
        let joiner_session = serde_json::from_value::<SessionStartedEvent>(joiner_started.data)
            .expect("joiner session.started should parse")
            .session_id;

        let inviter_started = recv_until(&mut inviter, events::names::SESSION_STARTED).await;
        let inviter_session = serde_json::from_value::<SessionStartedEvent>(inviter_started.data)
            .expect("inviter session.started should parse")
            .session_id;

        assert_eq!(inviter_session, joiner_session);

        send_event(
            &mut inviter,
            events::names::MSG_SEND,
            "req-msg",
            MsgSendRequest {
                text: "hello from inviter".to_string(),
            },
        )
        .await;

        let plaintext_err = recv_until(&mut inviter, events::names::ERROR).await;
        assert_eq!(plaintext_err.request_id.as_deref(), Some("req-msg"));
        let payload = serde_json::from_value::<ErrorEvent>(plaintext_err.data)
            .expect("error payload should parse");
        assert_eq!(payload.code, ErrorCode::E2eRequired);

        joiner
            .send(Message::Close(None))
            .await
            .expect("joiner should close connection");

        let ended = recv_until(&mut inviter, events::names::SESSION_ENDED).await;
        let ended_payload = serde_json::from_value::<SessionEndedEvent>(ended.data)
            .expect("session.ended payload should parse");
        assert_eq!(ended_payload.session_id, inviter_session);
        assert_eq!(ended_payload.reason, SessionEndReason::PeerDisconnect);

        let _ = shutdown_tx.send(());
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn integration_e2e_msg_send_routes_ciphertext_without_transform() {
        let (addr, shutdown_tx, server_task) = spawn_test_relay(LimitsConfig::default()).await;

        let mut inviter = connect_client(addr).await;
        let mut joiner = connect_client(addr).await;

        assert_eq!(
            recv_with_timeout(&mut inviter).await.event_type,
            events::names::READY
        );
        assert_eq!(
            recv_with_timeout(&mut joiner).await.event_type,
            events::names::READY
        );

        send_event(
            &mut inviter,
            events::names::INVITE_CREATE,
            "req-create",
            InviteCreateRequest {
                r: vec![relay_url(addr)],
                e: 600,
                o: true,
                k: None,
            },
        )
        .await;

        let invite_created = recv_until(&mut inviter, events::names::INVITE_CREATED).await;
        let invite = serde_json::from_value::<InviteCreatedEvent>(invite_created.data)
            .expect("invite.created payload should parse")
            .invite;

        send_event(
            &mut joiner,
            events::names::INVITE_USE,
            "req-join",
            InviteUseRequest { invite },
        )
        .await;

        let _ = recv_until(&mut joiner, events::names::INVITE_USED).await;
        let joiner_started = recv_until(&mut joiner, events::names::SESSION_STARTED).await;
        let session_id = serde_json::from_value::<SessionStartedEvent>(joiner_started.data)
            .expect("joiner session.started should parse")
            .session_id;
        let _ = recv_until(&mut inviter, events::names::SESSION_STARTED).await;

        let outbound = E2eMsgSendRequest {
            session_id,
            n: 1,
            pn: 0,
            dh_x25519: URL_SAFE_NO_PAD.encode([7_u8; 32]),
            nonce: URL_SAFE_NO_PAD.encode([9_u8; 12]),
            ct: URL_SAFE_NO_PAD.encode([11_u8; 24]),
            ad: E2eMsgAd {
                pv: 2,
                session_id,
                n: 1,
                pn: 0,
            },
        };

        send_event(
            &mut inviter,
            events::names::E2E_MSG_SEND,
            "req-e2e-msg",
            outbound.clone(),
        )
        .await;

        let routed = recv_until(&mut joiner, events::names::E2E_MSG_RECV).await;
        let inbound = serde_json::from_value::<E2eMsgSendRequest>(routed.data)
            .expect("e2e.msg.recv payload should parse");
        assert_eq!(inbound.session_id, session_id);
        assert_eq!(inbound.n, 1);
        assert_eq!(inbound.ct, outbound.ct);
        assert_eq!(inbound.nonce, outbound.nonce);
        assert_eq!(inbound.ad, outbound.ad);

        let _ = shutdown_tx.send(());
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn integration_e2e_event_without_pv_is_rejected() {
        let (addr, shutdown_tx, server_task) = spawn_test_relay(LimitsConfig::default()).await;
        let mut client = connect_client(addr).await;

        assert_eq!(
            recv_with_timeout(&mut client).await.event_type,
            events::names::READY
        );

        let session_id = Uuid::new_v4();
        let raw = format!(
            r#"{{"t":"{}","rid":"req-pv","d":{{"session_id":"{}"}}}}"#,
            events::names::E2E_PREKEY_GET,
            session_id
        );
        send_raw_event(&mut client, raw).await;

        let error = recv_until(&mut client, events::names::ERROR).await;
        assert_eq!(error.request_id.as_deref(), Some("req-pv"));
        let payload =
            serde_json::from_value::<ErrorEvent>(error.data).expect("error payload should parse");
        assert_eq!(payload.code, ErrorCode::UnsupportedProtocol);

        let _ = shutdown_tx.send(());
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn integration_e2e_msg_send_with_unknown_field_is_rejected() {
        let (addr, shutdown_tx, server_task) = spawn_test_relay(LimitsConfig::default()).await;
        let mut client = connect_client(addr).await;

        assert_eq!(
            recv_with_timeout(&mut client).await.event_type,
            events::names::READY
        );

        let session_id = Uuid::new_v4();
        let payload = serde_json::json!({
            "session_id": session_id,
            "n": 1,
            "pn": 0,
            "dh_x25519": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "nonce": "BBBBBBBBBBBBBBBB",
            "ct": "Q0NDQw",
            "ad": {
                "pv": 2,
                "session_id": session_id,
                "n": 1,
                "pn": 0
            },
            "unexpected": 1
        });
        let raw = serde_json::json!({
            "pv": 2,
            "t": events::names::E2E_MSG_SEND,
            "rid": "req-unknown-field",
            "d": payload
        })
        .to_string();
        send_raw_event(&mut client, raw).await;

        let error = recv_until(&mut client, events::names::ERROR).await;
        assert_eq!(error.request_id.as_deref(), Some("req-unknown-field"));
        let payload =
            serde_json::from_value::<ErrorEvent>(error.data).expect("error payload should parse");
        assert_eq!(payload.code, ErrorCode::BadRequest);

        let _ = shutdown_tx.send(());
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn integration_invite_use_backoff_emits_rate_limited_after_failed_attempts() {
        let (addr, shutdown_tx, server_task) = spawn_test_relay(LimitsConfig::default()).await;

        let mut client = connect_client(addr).await;
        assert_eq!(
            recv_with_timeout(&mut client).await.event_type,
            events::names::READY
        );

        for attempt in 1..=5 {
            send_event(
                &mut client,
                events::names::INVITE_USE,
                &format!("req-fail-{attempt}"),
                InviteUseRequest {
                    invite: "DL1:INVALID.INVALID".to_string(),
                },
            )
            .await;

            let envelope = recv_with_timeout(&mut client).await;
            assert_eq!(envelope.event_type, events::names::ERROR);
            let payload = serde_json::from_value::<ErrorEvent>(envelope.data)
                .expect("error payload should parse");
            assert_eq!(payload.code, ErrorCode::InvalidInvite);
        }

        send_event(
            &mut client,
            events::names::INVITE_USE,
            "req-rate-limit",
            InviteUseRequest {
                invite: "DL1:INVALID.INVALID".to_string(),
            },
        )
        .await;

        let envelope = recv_with_timeout(&mut client).await;
        assert_eq!(envelope.event_type, events::names::RATE_LIMITED);
        let payload = serde_json::from_value::<RateLimitedEvent>(envelope.data)
            .expect("rate.limited payload should parse");
        assert_eq!(payload.scope, RateLimitScope::InviteUse);
        assert!(payload.retry_after_ms >= 1);

        let _ = shutdown_tx.send(());
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn integration_prekey_publish_and_get_consumes_opk() {
        let (addr, shutdown_tx, server_task) = spawn_test_relay(LimitsConfig::default()).await;

        let mut inviter = connect_client(addr).await;
        let mut joiner = connect_client(addr).await;

        assert_eq!(
            recv_with_timeout(&mut inviter).await.event_type,
            events::names::READY
        );
        assert_eq!(
            recv_with_timeout(&mut joiner).await.event_type,
            events::names::READY
        );

        send_event(
            &mut inviter,
            events::names::INVITE_CREATE,
            "req-create",
            InviteCreateRequest {
                r: vec![relay_url(addr)],
                e: 600,
                o: true,
                k: None,
            },
        )
        .await;

        let invite_created = recv_until(&mut inviter, events::names::INVITE_CREATED).await;
        let invite = serde_json::from_value::<InviteCreatedEvent>(invite_created.data)
            .expect("invite.created payload should parse")
            .invite;

        send_event(
            &mut joiner,
            events::names::INVITE_USE,
            "req-join",
            InviteUseRequest { invite },
        )
        .await;
        let joiner_started = recv_until(&mut joiner, events::names::SESSION_STARTED).await;
        let session_id = serde_json::from_value::<SessionStartedEvent>(joiner_started.data)
            .expect("joiner session.started should parse")
            .session_id;
        let _ = recv_until(&mut inviter, events::names::SESSION_STARTED).await;

        send_event(
            &mut inviter,
            events::names::E2E_PREKEY_PUBLISH,
            "req-publish",
            sample_prekey_publish(7, &[1001]),
        )
        .await;

        let published = recv_until(&mut inviter, events::names::E2E_PREKEY_PUBLISHED).await;
        let published_payload = serde_json::from_value::<PrekeyPublishedEvent>(published.data)
            .expect("e2e.prekey.published payload should parse");
        assert_eq!(published_payload.spk_id, 7);
        assert_eq!(published_payload.opk_count, 1);

        send_event(
            &mut joiner,
            events::names::E2E_PREKEY_GET,
            "req-get-1",
            PrekeyGetRequest { session_id },
        )
        .await;
        let bundle1 = recv_until(&mut joiner, events::names::E2E_PREKEY_BUNDLE).await;
        let bundle1_payload = serde_json::from_value::<PrekeyBundleEvent>(bundle1.data)
            .expect("e2e.prekey.bundle payload should parse");
        assert_eq!(bundle1_payload.session_id, session_id);
        assert_eq!(bundle1_payload.peer.opk.expect("first opk").id, 1001);

        send_event(
            &mut joiner,
            events::names::E2E_PREKEY_GET,
            "req-get-2",
            PrekeyGetRequest { session_id },
        )
        .await;
        let bundle2 = recv_until(&mut joiner, events::names::E2E_PREKEY_BUNDLE).await;
        let bundle2_payload = serde_json::from_value::<PrekeyBundleEvent>(bundle2.data)
            .expect("second e2e.prekey.bundle payload should parse");
        assert_eq!(bundle2_payload.session_id, session_id);
        assert!(bundle2_payload.peer.opk.is_none());

        let _ = shutdown_tx.send(());
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn integration_prekey_publish_rate_limit_uses_prekey_scope() {
        let mut limits = LimitsConfig::default();
        limits.prekey_publish_per_min = 1;

        let (addr, shutdown_tx, server_task) = spawn_test_relay(limits).await;
        let mut client = connect_client(addr).await;

        assert_eq!(
            recv_with_timeout(&mut client).await.event_type,
            events::names::READY
        );

        send_event(
            &mut client,
            events::names::E2E_PREKEY_PUBLISH,
            "req-publish-1",
            sample_prekey_publish(1, &[1]),
        )
        .await;
        assert_eq!(
            recv_with_timeout(&mut client).await.event_type,
            events::names::E2E_PREKEY_PUBLISHED
        );

        send_event(
            &mut client,
            events::names::E2E_PREKEY_PUBLISH,
            "req-publish-2",
            sample_prekey_publish(2, &[2]),
        )
        .await;
        let limited = recv_with_timeout(&mut client).await;
        assert_eq!(limited.event_type, events::names::RATE_LIMITED);
        let payload = serde_json::from_value::<RateLimitedEvent>(limited.data)
            .expect("rate.limited payload should parse");
        assert_eq!(payload.scope, RateLimitScope::PrekeyPublish);
        assert!(payload.retry_after_ms >= 1);

        let _ = shutdown_tx.send(());
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn integration_handshake_routes_init_and_accept_between_peers() {
        let (addr, shutdown_tx, server_task) = spawn_test_relay(LimitsConfig::default()).await;

        let mut inviter = connect_client(addr).await;
        let mut joiner = connect_client(addr).await;

        assert_eq!(
            recv_with_timeout(&mut inviter).await.event_type,
            events::names::READY
        );
        assert_eq!(
            recv_with_timeout(&mut joiner).await.event_type,
            events::names::READY
        );

        send_event(
            &mut inviter,
            events::names::INVITE_CREATE,
            "req-create",
            InviteCreateRequest {
                r: vec![relay_url(addr)],
                e: 600,
                o: true,
                k: None,
            },
        )
        .await;
        let invite_created = recv_until(&mut inviter, events::names::INVITE_CREATED).await;
        let invite = serde_json::from_value::<InviteCreatedEvent>(invite_created.data)
            .expect("invite.created payload should parse")
            .invite;

        send_event(
            &mut joiner,
            events::names::INVITE_USE,
            "req-join",
            InviteUseRequest { invite },
        )
        .await;
        let joiner_started = recv_until(&mut joiner, events::names::SESSION_STARTED).await;
        let session_id = serde_json::from_value::<SessionStartedEvent>(joiner_started.data)
            .expect("session.started payload should parse")
            .session_id;
        let _ = recv_until(&mut inviter, events::names::SESSION_STARTED).await;

        send_event(
            &mut inviter,
            events::names::E2E_PREKEY_PUBLISH,
            "req-publish",
            sample_prekey_publish(7, &[5001]),
        )
        .await;
        let _ = recv_until(&mut inviter, events::names::E2E_PREKEY_PUBLISHED).await;

        send_event(
            &mut joiner,
            events::names::E2E_PREKEY_GET,
            "req-prekey-get",
            PrekeyGetRequest { session_id },
        )
        .await;
        let bundle = recv_until(&mut joiner, events::names::E2E_PREKEY_BUNDLE).await;
        let bundle_payload = serde_json::from_value::<PrekeyBundleEvent>(bundle.data)
            .expect("prekey.bundle payload should parse");

        let hs_id = uuid::Uuid::new_v4();
        send_event(
            &mut joiner,
            events::names::E2E_HANDSHAKE_INIT,
            "req-hs-init",
            HandshakeInitRequest {
                session_id,
                hs_id,
                sender_ik_ed25519: "sender_ik".to_string(),
                sender_eph_x25519: "sender_eph".to_string(),
                peer_spk_id: bundle_payload.peer.spk.id,
                peer_opk_id: bundle_payload.peer.opk.as_ref().map(|opk| opk.id),
                sig_ed25519: "sender_sig".to_string(),
                ts_unix: now_unix(),
            },
        )
        .await;

        let routed_init = recv_until(&mut inviter, events::names::E2E_HANDSHAKE_INIT_RECV).await;
        let routed_init_payload = serde_json::from_value::<HandshakeInitRequest>(routed_init.data)
            .expect("handshake.init.recv payload should parse");
        assert_eq!(routed_init_payload.session_id, session_id);
        assert_eq!(routed_init_payload.hs_id, hs_id);

        send_event(
            &mut inviter,
            events::names::E2E_HANDSHAKE_ACCEPT,
            "req-hs-accept",
            HandshakeAcceptRequest {
                session_id,
                hs_id,
                responder_ik_ed25519: "responder_ik".to_string(),
                responder_eph_x25519: "responder_eph".to_string(),
                sig_ed25519: "responder_sig".to_string(),
                kc: "kc_value".to_string(),
            },
        )
        .await;

        let routed_accept = recv_until(&mut joiner, events::names::E2E_HANDSHAKE_ACCEPT_RECV).await;
        let routed_accept_payload =
            serde_json::from_value::<HandshakeAcceptRequest>(routed_accept.data)
                .expect("handshake.accept.recv payload should parse");
        assert_eq!(routed_accept_payload.session_id, session_id);
        assert_eq!(routed_accept_payload.hs_id, hs_id);

        let _ = shutdown_tx.send(());
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn integration_handshake_without_prekey_selection_emits_prekey_not_found_metric() {
        let (state, addr, shutdown_tx, server_task) =
            spawn_test_relay_with_state(LimitsConfig::default()).await;

        let mut inviter = connect_client(addr).await;
        let mut joiner = connect_client(addr).await;

        assert_eq!(
            recv_with_timeout(&mut inviter).await.event_type,
            events::names::READY
        );
        assert_eq!(
            recv_with_timeout(&mut joiner).await.event_type,
            events::names::READY
        );

        send_event(
            &mut inviter,
            events::names::INVITE_CREATE,
            "req-create",
            InviteCreateRequest {
                r: vec![relay_url(addr)],
                e: 600,
                o: true,
                k: None,
            },
        )
        .await;
        let invite_created = recv_until(&mut inviter, events::names::INVITE_CREATED).await;
        let invite = serde_json::from_value::<InviteCreatedEvent>(invite_created.data)
            .expect("invite.created payload should parse")
            .invite;

        send_event(
            &mut joiner,
            events::names::INVITE_USE,
            "req-join",
            InviteUseRequest { invite },
        )
        .await;
        let started = recv_until(&mut joiner, events::names::SESSION_STARTED).await;
        let session_id = serde_json::from_value::<SessionStartedEvent>(started.data)
            .expect("session.started payload should parse")
            .session_id;
        let _ = recv_until(&mut inviter, events::names::SESSION_STARTED).await;

        send_event(
            &mut joiner,
            events::names::E2E_HANDSHAKE_INIT,
            "req-hs",
            HandshakeInitRequest {
                session_id,
                hs_id: uuid::Uuid::new_v4(),
                sender_ik_ed25519: "sender_ik".to_string(),
                sender_eph_x25519: "sender_eph".to_string(),
                peer_spk_id: 7,
                peer_opk_id: None,
                sig_ed25519: "sender_sig".to_string(),
                ts_unix: now_unix(),
            },
        )
        .await;

        let envelope = recv_with_timeout(&mut joiner).await;
        assert_eq!(envelope.event_type, events::names::ERROR);
        let payload = serde_json::from_value::<ErrorEvent>(envelope.data)
            .expect("error payload should parse");
        assert_eq!(payload.code, ErrorCode::PrekeyNotFound);

        let failures = state
            .handshake_failure_count(app_state::HandshakeFailureReason::PrekeyNotFound)
            .await;
        assert_eq!(failures, 1);

        let _ = shutdown_tx.send(());
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn integration_login_bind_lookup_and_hijack_rejection() {
        let (addr, shutdown_tx, server_task) = spawn_test_relay(LimitsConfig::default()).await;

        let mut owner = connect_client(addr).await;
        let mut attacker = connect_client(addr).await;
        assert_eq!(
            recv_with_timeout(&mut owner).await.event_type,
            events::names::READY
        );
        assert_eq!(
            recv_with_timeout(&mut attacker).await.event_type,
            events::names::READY
        );

        let owner_key = generate_identity_keypair();
        let owner_ik = keypair_public_b64u(&owner_key);
        send_event(
            &mut owner,
            events::names::E2E_PREKEY_PUBLISH,
            "req-owner-publish",
            sample_prekey_publish_with_ik(&owner_ik, 1, &[1]),
        )
        .await;
        let _ = recv_until(&mut owner, events::names::E2E_PREKEY_PUBLISHED).await;

        send_event(
            &mut owner,
            events::names::LOGIN_BIND,
            "req-owner-bind",
            LoginBindRequest {
                login: "@mike".to_string(),
                ik_ed25519: owner_ik.clone(),
                sig_ed25519: sign_login_bind("@mike", &owner_ik, &owner_key),
            },
        )
        .await;

        let bound = recv_until(&mut owner, events::names::LOGIN_BOUND).await;
        let bound_payload = serde_json::from_value::<LoginBindingEvent>(bound.data)
            .expect("login.bound payload should parse");
        assert_eq!(bound_payload.login, "mike");
        assert_eq!(bound_payload.ik_ed25519, owner_ik);

        let attacker_key = generate_identity_keypair();
        let attacker_ik = keypair_public_b64u(&attacker_key);
        send_event(
            &mut attacker,
            events::names::E2E_PREKEY_PUBLISH,
            "req-attacker-publish",
            sample_prekey_publish_with_ik(&attacker_ik, 2, &[2]),
        )
        .await;
        let _ = recv_until(&mut attacker, events::names::E2E_PREKEY_PUBLISHED).await;

        send_event(
            &mut attacker,
            events::names::LOGIN_BIND,
            "req-attacker-bind",
            LoginBindRequest {
                login: "mike".to_string(),
                ik_ed25519: attacker_ik.clone(),
                sig_ed25519: sign_login_bind("mike", &attacker_ik, &attacker_key),
            },
        )
        .await;
        let taken = recv_until(&mut attacker, events::names::ERROR).await;
        let taken_payload = serde_json::from_value::<ErrorEvent>(taken.data)
            .expect("login taken error payload should parse");
        assert_eq!(taken_payload.code, ErrorCode::LoginTaken);

        send_event(
            &mut attacker,
            events::names::LOGIN_LOOKUP,
            "req-lookup",
            LoginLookupRequest {
                login: Some("mike".to_string()),
                ik_ed25519: None,
            },
        )
        .await;
        let lookup = recv_until(&mut attacker, events::names::LOGIN_BINDING).await;
        let lookup_payload = serde_json::from_value::<LoginBindingEvent>(lookup.data)
            .expect("login.binding payload should parse");
        assert_eq!(lookup_payload.login, "mike");
        assert_eq!(lookup_payload.ik_ed25519, keypair_public_b64u(&owner_key));

        let _ = shutdown_tx.send(());
        let _ = server_task.await;
    }

    async fn spawn_test_relay(
        limits: LimitsConfig,
    ) -> (SocketAddr, oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
        let (_state, addr, shutdown_tx, task) = spawn_test_relay_with_state(limits).await;
        (addr, shutdown_tx, task)
    }

    async fn spawn_test_relay_with_state(
        limits: LimitsConfig,
    ) -> (
        Arc<AppState>,
        SocketAddr,
        oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let state = Arc::new(AppState::new(limits));
        let app = build_app(Arc::clone(&state));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test relay listener");
        let addr = listener.local_addr().expect("listener local addr");

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let server = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async {
            let _ = shutdown_rx.await;
        });

        let task = tokio::spawn(async move {
            let _ = server.await;
        });

        // Give the server a short moment to start accepting sockets.
        sleep(Duration::from_millis(20)).await;

        (state, addr, shutdown_tx, task)
    }

    async fn connect_client(addr: SocketAddr) -> WsClient {
        let url = format!("ws://{addr}/ws");
        let (client, _) = connect_async(url)
            .await
            .expect("websocket client should connect");
        client
    }

    async fn send_event<T: Serialize>(
        client: &mut WsClient,
        event_type: &str,
        request_id: &str,
        data: T,
    ) {
        let raw = serde_json::to_string(
            &Envelope::new(event_type, data).with_request_id(request_id.to_string()),
        )
        .expect("serialize outbound event");

        client
            .send(Message::Text(raw.into()))
            .await
            .expect("send websocket text event");
    }

    async fn send_raw_event(client: &mut WsClient, raw: String) {
        client
            .send(Message::Text(raw.into()))
            .await
            .expect("send websocket text event");
    }

    async fn recv_with_timeout(client: &mut WsClient) -> TestEnvelope {
        timeout(Duration::from_secs(5), recv_envelope(client))
            .await
            .expect("timed out waiting for websocket event")
    }

    async fn recv_until(client: &mut WsClient, event_type: &str) -> TestEnvelope {
        for _ in 0..16 {
            let envelope = recv_with_timeout(client).await;
            if envelope.event_type == event_type {
                return envelope;
            }
        }

        panic!("did not receive expected event: {event_type}");
    }

    async fn recv_envelope(client: &mut WsClient) -> TestEnvelope {
        loop {
            match client.next().await {
                Some(Ok(Message::Text(raw))) => {
                    return serde_json::from_str::<TestEnvelope>(raw.as_ref())
                        .expect("incoming envelope should be valid JSON");
                }
                Some(Ok(Message::Ping(payload))) => {
                    client
                        .send(Message::Pong(payload))
                        .await
                        .expect("pong response should be sent");
                }
                Some(Ok(Message::Close(frame))) => {
                    if let Some(frame) = frame {
                        panic!("unexpected close frame: {}", frame.reason);
                    }
                    panic!("unexpected close frame");
                }
                Some(Ok(_)) => {}
                Some(Err(err)) => panic!("websocket error: {err}"),
                None => panic!("websocket stream ended unexpectedly"),
            }
        }
    }

    fn relay_url(addr: SocketAddr) -> String {
        format!("ws://{addr}/ws")
    }

    fn now_unix() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn sample_prekey_publish(spk_id: u32, opk_ids: &[u32]) -> PrekeyPublishRequest {
        sample_prekey_publish_with_ik("ik_ed25519_b64u", spk_id, opk_ids)
    }

    fn sample_prekey_publish_with_ik(
        ik_ed25519: &str,
        spk_id: u32,
        opk_ids: &[u32],
    ) -> PrekeyPublishRequest {
        PrekeyPublishRequest {
            ik_ed25519: ik_ed25519.to_string(),
            spk: SignedPrekey {
                id: spk_id,
                x25519: "spk_x25519_b64u".to_string(),
                sig_ed25519: "spk_sig_b64u".to_string(),
                exp_unix: 1_770_000_000,
            },
            opks: opk_ids
                .iter()
                .copied()
                .map(|id| OneTimePrekey {
                    id,
                    x25519: format!("opk_{id}_x25519_b64u"),
                })
                .collect(),
        }
    }

    fn generate_identity_keypair() -> Ed25519KeyPair {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate test identity key");
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("decode test identity key")
    }

    fn keypair_public_b64u(keypair: &Ed25519KeyPair) -> String {
        URL_SAFE_NO_PAD.encode(keypair.public_key().as_ref())
    }

    fn sign_login_bind(login: &str, ik_ed25519: &str, keypair: &Ed25519KeyPair) -> String {
        let transcript = login_bind_transcript(login, ik_ed25519);
        let signature = keypair.sign(&transcript);
        URL_SAFE_NO_PAD.encode(signature.as_ref())
    }
}
