mod app_state;
mod ws_handler;

use app_state::AppState;
use axum::{routing::get, Router};
use darkwire_protocol::config::LimitsConfig;
use std::{env, net::SocketAddr, sync::Arc};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();

    let bind_addr = relay_addr_from_env();
    let limits = LimitsConfig::default();
    let state = Arc::new(AppState::new(limits.clone()));

    let app = Router::new()
        .route("/ws", get(ws_handler::ws_upgrade))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    info!(%bind_addr, idle_timeout_secs = limits.idle_timeout_secs, "relay.listening");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

fn relay_addr_from_env() -> SocketAddr {
    let env_value = env::var("DARKWIRE_RELAY_ADDR").ok();
    relay_addr_from_value(env_value.as_deref())
}

fn relay_addr_from_value(value: Option<&str>) -> SocketAddr {
    const DEFAULT_ADDR: &str = "127.0.0.1:7000";

    value
        .and_then(|raw| raw.parse::<SocketAddr>().ok())
        .unwrap_or_else(|| {
            DEFAULT_ADDR
                .parse()
                .expect("default relay address is valid")
        })
}

fn init_tracing() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "darkwire_relay=info,tower_http=warn".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_addr_defaults_when_value_missing() {
        let addr = relay_addr_from_value(None);
        assert_eq!(addr.to_string(), "127.0.0.1:7000");
    }

    #[test]
    fn relay_addr_uses_value_when_valid() {
        let addr = relay_addr_from_value(Some("127.0.0.1:7011"));
        assert_eq!(addr.to_string(), "127.0.0.1:7011");
    }

    #[test]
    fn relay_addr_falls_back_for_invalid_value() {
        let addr = relay_addr_from_value(Some("invalid-addr"));
        assert_eq!(addr.to_string(), "127.0.0.1:7000");
    }
}
