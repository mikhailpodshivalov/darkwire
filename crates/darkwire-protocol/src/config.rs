use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LimitsConfig {
    pub invite_create_per_min: u32,
    pub invite_create_per_hour: u32,
    pub invite_use_per_min: u32,
    pub invite_use_backoff_after_failures: u32,
    pub msg_per_sec: u32,
    pub max_msg_bytes: usize,
    pub prekey_publish_per_min: u32,
    pub prekey_get_per_min: u32,
    pub handshake_per_min: u32,
    pub idle_timeout_secs: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            invite_create_per_min: 5,
            invite_create_per_hour: 20,
            invite_use_per_min: 20,
            invite_use_backoff_after_failures: 5,
            msg_per_sec: 1,
            max_msg_bytes: 8 * 1024,
            prekey_publish_per_min: 10,
            prekey_get_per_min: 60,
            handshake_per_min: 30,
            idle_timeout_secs: 15 * 60,
        }
    }
}

impl LimitsConfig {
    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.idle_timeout_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_values_match_mvp_contract() {
        let cfg = LimitsConfig::default();
        assert_eq!(cfg.invite_create_per_min, 5);
        assert_eq!(cfg.invite_create_per_hour, 20);
        assert_eq!(cfg.invite_use_per_min, 20);
        assert_eq!(cfg.invite_use_backoff_after_failures, 5);
        assert_eq!(cfg.msg_per_sec, 1);
        assert_eq!(cfg.max_msg_bytes, 8192);
        assert_eq!(cfg.prekey_publish_per_min, 10);
        assert_eq!(cfg.prekey_get_per_min, 60);
        assert_eq!(cfg.handshake_per_min, 30);
        assert_eq!(cfg.idle_timeout(), Duration::from_secs(900));
    }
}
