use crate::{e2e::SecureMessagingError, wire::ClientState};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RecoveryRequestState {
    Requested,
    AlreadyRequested,
    Unavailable,
}

#[derive(Debug, Clone, Default)]
pub(super) struct RecoveryState {
    send_blocked: bool,
    request_in_flight: bool,
    attempted_session_id: Option<Uuid>,
}

impl RecoveryState {
    pub(super) fn is_send_blocked(&self) -> bool {
        self.send_blocked
    }

    pub(super) fn block_send(&mut self) {
        self.send_blocked = true;
    }

    pub(super) fn is_request_in_flight(&self) -> bool {
        self.request_in_flight
    }

    pub(super) fn reset(&mut self) {
        self.send_blocked = false;
        self.request_in_flight = false;
        self.attempted_session_id = None;
    }

    pub(super) fn clear_request_in_flight(&mut self) {
        self.request_in_flight = false;
    }

    pub(super) fn mark_recovery_requested(&mut self, session_id: Uuid) {
        self.request_in_flight = true;
        self.attempted_session_id = Some(session_id);
    }

    pub(super) fn request_state_for(&self, state: &ClientState) -> RecoveryRequestState {
        if !state.active_session || state.active_session_id.is_none() || state.secure_active {
            return RecoveryRequestState::Unavailable;
        }

        let session_id = state.active_session_id.expect("checked is_some above");
        if self.request_in_flight || self.attempted_session_id == Some(session_id) {
            return RecoveryRequestState::AlreadyRequested;
        }

        RecoveryRequestState::Requested
    }
}

pub(super) fn should_fail_closed_on_decrypt_error(err: &SecureMessagingError) -> bool {
    !matches!(err, SecureMessagingError::ReplayDetected(_))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_state_true_for_unsecured_active_session() {
        let state = ClientState {
            active_session: true,
            active_session_id: Some(Uuid::new_v4()),
            secure_active: false,
            should_initiate_handshake: false,
        };
        let recovery = RecoveryState::default();

        assert_eq!(
            recovery.request_state_for(&state),
            RecoveryRequestState::Requested
        );
    }

    #[test]
    fn request_state_false_when_already_requested() {
        let session_id = Uuid::new_v4();
        let state = ClientState {
            active_session: true,
            active_session_id: Some(session_id),
            secure_active: false,
            should_initiate_handshake: false,
        };
        let mut recovery = RecoveryState::default();
        recovery.mark_recovery_requested(session_id);

        assert_eq!(
            recovery.request_state_for(&state),
            RecoveryRequestState::AlreadyRequested
        );
    }

    #[test]
    fn recovery_request_is_limited_to_one_attempt_per_session() {
        let session_id = Uuid::new_v4();
        let state = ClientState {
            active_session: true,
            active_session_id: Some(session_id),
            secure_active: false,
            should_initiate_handshake: false,
        };
        let mut recovery = RecoveryState::default();

        assert_eq!(
            recovery.request_state_for(&state),
            RecoveryRequestState::Requested
        );
        recovery.mark_recovery_requested(session_id);
        recovery.clear_request_in_flight();
        assert_eq!(
            recovery.request_state_for(&state),
            RecoveryRequestState::AlreadyRequested
        );
    }

    #[test]
    fn recovery_request_is_allowed_for_new_session_after_prior_attempt() {
        let first_session = Uuid::new_v4();
        let second_session = Uuid::new_v4();
        let mut recovery = RecoveryState::default();
        recovery.mark_recovery_requested(first_session);
        recovery.clear_request_in_flight();

        let second_state = ClientState {
            active_session: true,
            active_session_id: Some(second_session),
            secure_active: false,
            should_initiate_handshake: false,
        };
        assert_eq!(
            recovery.request_state_for(&second_state),
            RecoveryRequestState::Requested
        );
    }

    #[test]
    fn request_state_false_when_secure_is_active() {
        let state = ClientState {
            active_session: true,
            active_session_id: Some(Uuid::new_v4()),
            secure_active: true,
            should_initiate_handshake: false,
        };
        let recovery = RecoveryState::default();

        assert_eq!(
            recovery.request_state_for(&state),
            RecoveryRequestState::Unavailable
        );
    }

    #[test]
    fn fail_closed_filter_allows_replay_without_degrade() {
        assert!(!should_fail_closed_on_decrypt_error(
            &SecureMessagingError::ReplayDetected(3)
        ));
    }

    #[test]
    fn fail_closed_filter_triggers_for_nonce_and_gap_errors() {
        assert!(should_fail_closed_on_decrypt_error(
            &SecureMessagingError::NonceMismatch
        ));
        assert!(should_fail_closed_on_decrypt_error(
            &SecureMessagingError::SkippedWindowOverflow {
                limit: 10,
                pending: 9
            }
        ));
        assert!(should_fail_closed_on_decrypt_error(
            &SecureMessagingError::OutOfOrder {
                expected: 1,
                got: 2048
            }
        ));
    }
}
