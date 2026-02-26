use super::{ClientRuntime, WsWriter};
use crate::ui::TerminalUi;
use darkwire_protocol::events::{self, E2eMsgSendRequest, RateLimitScope, RateLimitedEvent};
use std::collections::{HashMap, VecDeque};
use std::error::Error;
use tokio::time::{Duration, Instant};

const CLIENT_SEND_INTERVAL: Duration = Duration::from_millis(1050);
const RATE_RETRY_SAFETY_BUFFER: Duration = Duration::from_millis(25);
const OUTBOUND_INFLIGHT_TTL: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
struct QueuedOutboundMessage {
    payload: E2eMsgSendRequest,
    next_attempt_at: Instant,
    retry_count: u32,
}

#[derive(Debug)]
pub(super) struct OutboxState {
    queue: VecDeque<QueuedOutboundMessage>,
    inflight: HashMap<String, (QueuedOutboundMessage, Instant)>,
    next_send_allowed_at: Instant,
}

impl OutboxState {
    pub(super) fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            inflight: HashMap::new(),
            next_send_allowed_at: Instant::now(),
        }
    }
}

impl ClientRuntime {
    pub(super) fn enqueue_outbound_message(&mut self, payload: E2eMsgSendRequest) {
        self.outbox.queue.push_back(QueuedOutboundMessage {
            payload,
            next_attempt_at: Instant::now(),
            retry_count: 0,
        });
    }

    pub(super) async fn flush_outbound_queue(
        &mut self,
        ws_writer: &mut WsWriter,
    ) -> Result<(), Box<dyn Error>> {
        if !self.state.active_session
            || !self.state.secure_active
            || self.recovery.is_send_blocked()
        {
            return Ok(());
        }
        if self
            .active_peer_trust
            .as_ref()
            .is_some_and(|trust| trust.state == crate::trust::SessionTrustState::KeyChanged)
        {
            return Ok(());
        }

        let now = Instant::now();
        if now < self.outbox.next_send_allowed_at {
            return Ok(());
        }

        let Some(front) = self.outbox.queue.front() else {
            return Ok(());
        };
        if front.next_attempt_at > now {
            return Ok(());
        }

        let mut message = self
            .outbox
            .queue
            .pop_front()
            .expect("front exists because we just checked");
        let request_id = self
            .send_request(
                ws_writer,
                events::names::E2E_MSG_SEND,
                message.payload.clone(),
            )
            .await?;

        let sent_at = Instant::now();
        self.outbox.next_send_allowed_at = sent_at + CLIENT_SEND_INTERVAL;
        message.next_attempt_at = self.outbox.next_send_allowed_at;
        self.outbox.inflight.insert(request_id, (message, sent_at));
        Ok(())
    }

    pub(super) fn handle_rate_limited_event(
        &mut self,
        request_id: Option<String>,
        event: RateLimitedEvent,
        ui: &mut TerminalUi,
    ) {
        if event.scope != RateLimitScope::MsgSend {
            return;
        }

        let Some(request_id) = request_id else {
            return;
        };

        let Some((mut message, _sent_at)) = self.outbox.inflight.remove(&request_id) else {
            return;
        };

        let retry_delay = retry_delay_for_rate_limit(event.retry_after_ms);
        message.next_attempt_at = Instant::now() + retry_delay;
        message.retry_count = message.retry_count.saturating_add(1);
        self.outbox.queue.push_front(message);
        self.outbox.next_send_allowed_at = Instant::now() + retry_delay;
        ui.print_line(&format!(
            "[rate] queued resend after {}ms",
            retry_delay.as_millis()
        ));
    }

    pub(super) fn prune_outbound_inflight(&mut self) {
        let now = Instant::now();
        self.outbox.inflight.retain(|_, (_, sent_at)| {
            now.saturating_duration_since(*sent_at) <= OUTBOUND_INFLIGHT_TTL
        });
    }

    pub(super) fn clear_outbound_delivery_state(&mut self) {
        self.outbox.queue.clear();
        self.outbox.inflight.clear();
        self.outbox.next_send_allowed_at = Instant::now();
    }
}

fn retry_delay_for_rate_limit(retry_after_ms: u64) -> Duration {
    Duration::from_millis(retry_after_ms.max(1)).saturating_add(RATE_RETRY_SAFETY_BUFFER)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_delay_has_minimum_and_safety_buffer() {
        assert_eq!(
            retry_delay_for_rate_limit(0),
            Duration::from_millis(1).saturating_add(RATE_RETRY_SAFETY_BUFFER)
        );
        assert_eq!(
            retry_delay_for_rate_limit(34),
            Duration::from_millis(34).saturating_add(RATE_RETRY_SAFETY_BUFFER)
        );
    }
}
