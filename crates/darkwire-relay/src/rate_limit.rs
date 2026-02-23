use darkwire_protocol::config::LimitsConfig;
use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitHit {
    pub retry_after: Duration,
}

#[derive(Debug, Default)]
struct IpRateState {
    create_min: VecDeque<Instant>,
    create_hour: VecDeque<Instant>,
    use_min: VecDeque<Instant>,
    failed_invite_uses: u32,
    backoff_until: Option<Instant>,
}

#[derive(Debug, Default)]
pub struct RateLimitStore {
    by_ip: Mutex<HashMap<IpAddr, IpRateState>>,
}

impl RateLimitStore {
    pub fn new() -> Self {
        Self {
            by_ip: Mutex::new(HashMap::new()),
        }
    }

    pub async fn check_invite_create(
        &self,
        ip: IpAddr,
        limits: &LimitsConfig,
    ) -> Result<(), RateLimitHit> {
        self.check_invite_create_at(ip, limits, Instant::now())
            .await
    }

    pub async fn check_invite_use(
        &self,
        ip: IpAddr,
        limits: &LimitsConfig,
    ) -> Result<(), RateLimitHit> {
        self.check_invite_use_at(ip, limits, Instant::now()).await
    }

    pub async fn record_invite_use_result(&self, ip: IpAddr, success: bool, limits: &LimitsConfig) {
        self.record_invite_use_result_at(ip, success, limits, Instant::now())
            .await;
    }

    async fn check_invite_create_at(
        &self,
        ip: IpAddr,
        limits: &LimitsConfig,
        now: Instant,
    ) -> Result<(), RateLimitHit> {
        let mut by_ip = self.by_ip.lock().await;
        let state = by_ip.entry(ip).or_default();

        prune_window(&mut state.create_min, Duration::from_secs(60), now);
        prune_window(&mut state.create_hour, Duration::from_secs(60 * 60), now);

        let min_retry = retry_after_window(
            &state.create_min,
            limits.invite_create_per_min,
            Duration::from_secs(60),
            now,
        );
        let hour_retry = retry_after_window(
            &state.create_hour,
            limits.invite_create_per_hour,
            Duration::from_secs(60 * 60),
            now,
        );

        if let Some(retry_after) = max_retry(min_retry, hour_retry) {
            return Err(RateLimitHit { retry_after });
        }

        state.create_min.push_back(now);
        state.create_hour.push_back(now);
        Ok(())
    }

    async fn check_invite_use_at(
        &self,
        ip: IpAddr,
        limits: &LimitsConfig,
        now: Instant,
    ) -> Result<(), RateLimitHit> {
        let mut by_ip = self.by_ip.lock().await;
        let state = by_ip.entry(ip).or_default();

        if let Some(backoff_until) = state.backoff_until {
            if backoff_until > now {
                return Err(RateLimitHit {
                    retry_after: backoff_until.saturating_duration_since(now),
                });
            }
            state.backoff_until = None;
        }

        prune_window(&mut state.use_min, Duration::from_secs(60), now);

        if let Some(retry_after) = retry_after_window(
            &state.use_min,
            limits.invite_use_per_min,
            Duration::from_secs(60),
            now,
        ) {
            return Err(RateLimitHit { retry_after });
        }

        state.use_min.push_back(now);
        Ok(())
    }

    async fn record_invite_use_result_at(
        &self,
        ip: IpAddr,
        success: bool,
        limits: &LimitsConfig,
        now: Instant,
    ) {
        let mut by_ip = self.by_ip.lock().await;
        let state = by_ip.entry(ip).or_default();

        if success {
            state.failed_invite_uses = 0;
            state.backoff_until = None;
            return;
        }

        state.failed_invite_uses = state.failed_invite_uses.saturating_add(1);

        let threshold = limits.invite_use_backoff_after_failures.max(1);
        if state.failed_invite_uses >= threshold {
            let step = state.failed_invite_uses.saturating_sub(threshold) + 1;
            let backoff_secs = (u64::from(step) * 5).min(60);
            state.backoff_until = Some(now + Duration::from_secs(backoff_secs));
        }
    }
}

fn prune_window(events: &mut VecDeque<Instant>, window: Duration, now: Instant) {
    while let Some(front) = events.front().copied() {
        if now.saturating_duration_since(front) >= window {
            events.pop_front();
        } else {
            break;
        }
    }
}

fn retry_after_window(
    events: &VecDeque<Instant>,
    limit: u32,
    window: Duration,
    now: Instant,
) -> Option<Duration> {
    if events.len() < limit as usize {
        return None;
    }

    let oldest = events.front().copied()?;
    let retry_after = (oldest + window).saturating_duration_since(now);
    Some(retry_after.max(Duration::from_millis(1)))
}

fn max_retry(a: Option<Duration>, b: Option<Duration>) -> Option<Duration> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.max(y)),
        (Some(x), None) => Some(x),
        (None, Some(y)) => Some(y),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    #[tokio::test]
    async fn invite_create_respects_minute_limit() {
        let limits = LimitsConfig::default();
        let store = RateLimitStore::new();
        let now = Instant::now();

        for i in 0..limits.invite_create_per_min {
            store
                .check_invite_create_at(ip(), &limits, now + Duration::from_millis(u64::from(i)))
                .await
                .expect("within minute limit should pass");
        }

        let err = store
            .check_invite_create_at(ip(), &limits, now + Duration::from_secs(1))
            .await
            .expect_err("request over minute limit should fail");
        assert!(err.retry_after >= Duration::from_secs(58));
    }

    #[tokio::test]
    async fn invite_create_respects_hour_limit() {
        let limits = LimitsConfig::default();
        let store = RateLimitStore::new();
        let now = Instant::now();

        for i in 0..limits.invite_create_per_hour {
            let at = now + Duration::from_secs(u64::from(i) * 180);
            store
                .check_invite_create_at(ip(), &limits, at)
                .await
                .expect("within hour limit should pass");
        }

        let err = store
            .check_invite_create_at(ip(), &limits, now + Duration::from_secs(59 * 60))
            .await
            .expect_err("request over hour limit should fail");
        assert!(err.retry_after >= Duration::from_secs(50));
    }

    #[tokio::test]
    async fn invite_use_backoff_starts_after_failed_threshold() {
        let limits = LimitsConfig::default();
        let store = RateLimitStore::new();
        let now = Instant::now();

        for attempt in 0..limits.invite_use_backoff_after_failures {
            let at = now + Duration::from_secs(u64::from(attempt) * 2);
            store
                .check_invite_use_at(ip(), &limits, at)
                .await
                .expect("check should pass before backoff is applied");
            store
                .record_invite_use_result_at(ip(), false, &limits, at)
                .await;
        }

        let blocked = store
            .check_invite_use_at(ip(), &limits, now + Duration::from_secs(10))
            .await
            .expect_err("backoff should block immediately after threshold failure");
        assert!(blocked.retry_after >= Duration::from_secs(2));
    }

    #[tokio::test]
    async fn invite_use_success_resets_backoff_counter() {
        let limits = LimitsConfig::default();
        let store = RateLimitStore::new();
        let now = Instant::now();

        for attempt in 0..limits.invite_use_backoff_after_failures {
            let at = now + Duration::from_secs(u64::from(attempt));
            store
                .check_invite_use_at(ip(), &limits, at)
                .await
                .expect("pre-backoff check should pass");
            store
                .record_invite_use_result_at(ip(), false, &limits, at)
                .await;
        }

        let after_backoff = now + Duration::from_secs(10);
        store
            .check_invite_use_at(ip(), &limits, after_backoff)
            .await
            .expect("backoff should have elapsed");
        store
            .record_invite_use_result_at(ip(), true, &limits, after_backoff)
            .await;

        let next_attempt = after_backoff + Duration::from_secs(1);
        store
            .check_invite_use_at(ip(), &limits, next_attempt)
            .await
            .expect("counter should reset after success");
    }
}
