use clap::Parser;
use std::path::PathBuf;

pub const DEFAULT_RELAY_WS: &str = "wss://srv1418428.hstgr.cloud/ws";
pub const DEFAULT_INVITE_TTL: u32 = 10 * 60;

#[derive(Debug, Parser)]
#[command(name = "darkwire", version, about = "Darkwire terminal chat client")]
pub struct ClientArgs {
    #[arg(long, env = "DARKWIRE_RELAY_WS", default_value = DEFAULT_RELAY_WS)]
    pub relay: String,
    #[arg(long, env = "DARKWIRE_INVITE_RELAY")]
    pub invite_relay: Option<String>,
    #[arg(
        long,
        env = "DARKWIRE_INVITE_TTL",
        default_value_t = DEFAULT_INVITE_TTL,
        value_parser = clap::value_parser!(u32).range(1..=86_400)
    )]
    pub invite_ttl: u32,
    #[arg(
        long,
        env = "DARKWIRE_DEMO_INCOMING_MS",
        value_parser = clap::value_parser!(u64).range(50..=60_000)
    )]
    pub demo_incoming_ms: Option<u64>,
    #[arg(long, env = "DARKWIRE_KEY_FILE")]
    pub key_file: Option<PathBuf>,
}

pub fn resolve_invite_relay(args: &ClientArgs) -> String {
    args.invite_relay
        .clone()
        .unwrap_or_else(|| args.relay.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_defaults_match_contract() {
        let args = ClientArgs::parse_from(["darkwire"]);
        assert_eq!(args.relay, DEFAULT_RELAY_WS);
        assert_eq!(args.invite_relay, None);
        assert_eq!(args.invite_ttl, DEFAULT_INVITE_TTL);
        assert_eq!(args.demo_incoming_ms, None);
        assert_eq!(args.key_file, None);
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

    #[test]
    fn cli_key_file_uses_flag_value() {
        let args = ClientArgs::parse_from(["darkwire", "--key-file", "/tmp/darkwire-keys.json"]);
        assert_eq!(
            args.key_file.as_deref(),
            Some(std::path::Path::new("/tmp/darkwire-keys.json"))
        );
    }
}
