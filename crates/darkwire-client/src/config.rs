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

pub fn load_dotenv() {
    let _ = dotenvy::dotenv();
}

pub fn resolve_invite_relay(args: &ClientArgs) -> String {
    args.invite_relay
        .clone()
        .unwrap_or_else(|| args.relay.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        env,
        sync::{Mutex, MutexGuard, OnceLock},
    };

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

    fn clear_client_env() -> EnvOverrideGuard {
        override_env(&[
            ("DARKWIRE_RELAY_WS", None),
            ("DARKWIRE_INVITE_RELAY", None),
            ("DARKWIRE_INVITE_TTL", None),
            ("DARKWIRE_DEMO_INCOMING_MS", None),
            ("DARKWIRE_KEY_FILE", None),
        ])
    }

    #[test]
    fn cli_defaults_match_contract() {
        let _lock = env_lock();
        let _env = clear_client_env();
        let args = ClientArgs::parse_from(["darkwire"]);
        assert_eq!(args.relay, DEFAULT_RELAY_WS);
        assert_eq!(args.invite_relay, None);
        assert_eq!(args.invite_ttl, DEFAULT_INVITE_TTL);
        assert_eq!(args.demo_incoming_ms, None);
        assert_eq!(args.key_file, None);
    }

    #[test]
    fn invite_relay_falls_back_to_relay_when_not_set() {
        let _lock = env_lock();
        let _env = clear_client_env();
        let args = ClientArgs::parse_from(["darkwire", "--relay", "ws://127.0.0.1:7777/ws"]);
        assert_eq!(resolve_invite_relay(&args), "ws://127.0.0.1:7777/ws");
    }

    #[test]
    fn invite_relay_uses_explicit_value_when_set() {
        let _lock = env_lock();
        let _env = clear_client_env();
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
        let _lock = env_lock();
        let _env = clear_client_env();
        let args = ClientArgs::parse_from(["darkwire", "--demo-incoming-ms", "200"]);
        assert_eq!(args.demo_incoming_ms, Some(200));
    }

    #[test]
    fn cli_key_file_uses_flag_value() {
        let _lock = env_lock();
        let _env = clear_client_env();
        let args = ClientArgs::parse_from(["darkwire", "--key-file", "/tmp/darkwire-keys.json"]);
        assert_eq!(
            args.key_file.as_deref(),
            Some(std::path::Path::new("/tmp/darkwire-keys.json"))
        );
    }

    #[test]
    fn cli_uses_env_values_when_flags_missing() {
        let _lock = env_lock();
        let _clean = clear_client_env();
        let _env = override_env(&[
            ("DARKWIRE_RELAY_WS", Some("ws://127.0.0.1:7900/ws")),
            ("DARKWIRE_INVITE_RELAY", Some("ws://127.0.0.1:7901/ws")),
            ("DARKWIRE_INVITE_TTL", Some("123")),
            ("DARKWIRE_DEMO_INCOMING_MS", Some("250")),
            ("DARKWIRE_KEY_FILE", Some("/tmp/from-env-keys.json")),
        ]);

        let args = ClientArgs::parse_from(["darkwire"]);
        assert_eq!(args.relay, "ws://127.0.0.1:7900/ws");
        assert_eq!(args.invite_relay.as_deref(), Some("ws://127.0.0.1:7901/ws"));
        assert_eq!(args.invite_ttl, 123);
        assert_eq!(args.demo_incoming_ms, Some(250));
        assert_eq!(
            args.key_file.as_deref(),
            Some(std::path::Path::new("/tmp/from-env-keys.json"))
        );
        assert_eq!(resolve_invite_relay(&args), "ws://127.0.0.1:7901/ws");
    }

    #[test]
    fn cli_flags_override_env_values() {
        let _lock = env_lock();
        let _clean = clear_client_env();
        let _env = override_env(&[
            ("DARKWIRE_RELAY_WS", Some("ws://127.0.0.1:7900/ws")),
            ("DARKWIRE_INVITE_RELAY", Some("ws://127.0.0.1:7901/ws")),
            ("DARKWIRE_INVITE_TTL", Some("321")),
            ("DARKWIRE_DEMO_INCOMING_MS", Some("250")),
            ("DARKWIRE_KEY_FILE", Some("/tmp/from-env-keys.json")),
        ]);

        let args = ClientArgs::parse_from([
            "darkwire",
            "--relay",
            "ws://127.0.0.1:8000/ws",
            "--invite-relay",
            "ws://127.0.0.1:8001/ws",
            "--invite-ttl",
            "600",
            "--demo-incoming-ms",
            "500",
            "--key-file",
            "/tmp/from-cli-keys.json",
        ]);
        assert_eq!(args.relay, "ws://127.0.0.1:8000/ws");
        assert_eq!(args.invite_relay.as_deref(), Some("ws://127.0.0.1:8001/ws"));
        assert_eq!(args.invite_ttl, 600);
        assert_eq!(args.demo_incoming_ms, Some(500));
        assert_eq!(
            args.key_file.as_deref(),
            Some(std::path::Path::new("/tmp/from-cli-keys.json"))
        );
    }
}
