use std::collections::HashMap;
use std::time::Instant;
use uuid::Uuid;

pub type ConnId = Uuid;
pub type SessionId = Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrekeySelection {
    pub session_id: SessionId,
    pub initiator_conn: ConnId,
    pub responder_conn: ConnId,
    pub peer_spk_id: u32,
    pub peer_opk_id: Option<u32>,
    pub selected_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingHandshake {
    pub session_id: SessionId,
    pub hs_id: Uuid,
    pub initiator_conn: ConnId,
    pub responder_conn: ConnId,
    pub peer_spk_id: u32,
    pub peer_opk_id: Option<u32>,
    pub created_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsumeSelectionError {
    NotFound,
    PeerMismatch,
    SpkMismatch,
    OpkMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TakeHandshakeError {
    NotFound,
    SessionMismatch,
    ResponderMismatch,
}

#[derive(Debug, Default)]
pub struct HandshakeStore {
    prekey_by_initiator: HashMap<(SessionId, ConnId), PrekeySelection>,
    pending_by_hs_id: HashMap<Uuid, PendingHandshake>,
}

impl HandshakeStore {
    pub fn new() -> Self {
        Self {
            prekey_by_initiator: HashMap::new(),
            pending_by_hs_id: HashMap::new(),
        }
    }

    pub fn note_prekey_selection(&mut self, selection: PrekeySelection) {
        self.prekey_by_initiator
            .insert((selection.session_id, selection.initiator_conn), selection);
    }

    pub fn consume_prekey_selection(
        &mut self,
        session_id: SessionId,
        initiator_conn: ConnId,
        responder_conn: ConnId,
        peer_spk_id: u32,
        peer_opk_id: Option<u32>,
    ) -> Result<PrekeySelection, ConsumeSelectionError> {
        let key = (session_id, initiator_conn);
        let selection = self
            .prekey_by_initiator
            .get(&key)
            .cloned()
            .ok_or(ConsumeSelectionError::NotFound)?;

        if selection.responder_conn != responder_conn {
            return Err(ConsumeSelectionError::PeerMismatch);
        }

        if selection.peer_spk_id != peer_spk_id {
            return Err(ConsumeSelectionError::SpkMismatch);
        }

        if selection.peer_opk_id != peer_opk_id {
            return Err(ConsumeSelectionError::OpkMismatch);
        }

        self.prekey_by_initiator.remove(&key);
        Ok(selection)
    }

    pub fn register_pending_handshake(&mut self, pending: PendingHandshake) -> bool {
        if self.pending_by_hs_id.contains_key(&pending.hs_id) {
            return false;
        }

        self.pending_by_hs_id.insert(pending.hs_id, pending);
        true
    }

    pub fn take_pending_for_accept(
        &mut self,
        hs_id: Uuid,
        session_id: SessionId,
        responder_conn: ConnId,
    ) -> Result<PendingHandshake, TakeHandshakeError> {
        let pending = self
            .pending_by_hs_id
            .get(&hs_id)
            .cloned()
            .ok_or(TakeHandshakeError::NotFound)?;

        if pending.session_id != session_id {
            return Err(TakeHandshakeError::SessionMismatch);
        }

        if pending.responder_conn != responder_conn {
            return Err(TakeHandshakeError::ResponderMismatch);
        }

        self.pending_by_hs_id.remove(&hs_id);
        Ok(pending)
    }

    pub fn cleanup_for_conn(&mut self, conn_id: ConnId) {
        self.prekey_by_initiator
            .retain(|_, value| value.initiator_conn != conn_id && value.responder_conn != conn_id);
        self.pending_by_hs_id
            .retain(|_, value| value.initiator_conn != conn_id && value.responder_conn != conn_id);
    }

    pub fn cleanup_for_session(&mut self, session_id: SessionId) {
        self.prekey_by_initiator
            .retain(|(sid, _), _| *sid != session_id);
        self.pending_by_hs_id
            .retain(|_, value| value.session_id != session_id);
    }

    #[cfg(test)]
    pub fn pending_count(&self) -> usize {
        self.pending_by_hs_id.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_selection(
        session_id: SessionId,
        initiator_conn: ConnId,
        responder_conn: ConnId,
    ) -> PrekeySelection {
        PrekeySelection {
            session_id,
            initiator_conn,
            responder_conn,
            peer_spk_id: 7,
            peer_opk_id: Some(55),
            selected_at: Instant::now(),
        }
    }

    #[test]
    fn consume_prekey_selection_validates_peer_and_ids() {
        let mut store = HandshakeStore::new();
        let session_id = Uuid::new_v4();
        let initiator = Uuid::new_v4();
        let responder = Uuid::new_v4();
        store.note_prekey_selection(sample_selection(session_id, initiator, responder));

        let mismatch =
            store.consume_prekey_selection(session_id, initiator, responder, 8, Some(55));
        assert_eq!(mismatch, Err(ConsumeSelectionError::SpkMismatch));

        let consumed = store
            .consume_prekey_selection(session_id, initiator, responder, 7, Some(55))
            .expect("matching selection should be consumed");
        assert_eq!(consumed.peer_spk_id, 7);
    }

    #[test]
    fn pending_handshake_take_requires_matching_responder_and_session() {
        let mut store = HandshakeStore::new();
        let pending = PendingHandshake {
            session_id: Uuid::new_v4(),
            hs_id: Uuid::new_v4(),
            initiator_conn: Uuid::new_v4(),
            responder_conn: Uuid::new_v4(),
            peer_spk_id: 7,
            peer_opk_id: None,
            created_at: Instant::now(),
        };

        assert!(store.register_pending_handshake(pending.clone()));

        let wrong_responder =
            store.take_pending_for_accept(pending.hs_id, pending.session_id, Uuid::new_v4());
        assert_eq!(wrong_responder, Err(TakeHandshakeError::ResponderMismatch));

        let taken = store
            .take_pending_for_accept(pending.hs_id, pending.session_id, pending.responder_conn)
            .expect("matching pending handshake should be removed");
        assert_eq!(taken.initiator_conn, pending.initiator_conn);
        assert_eq!(store.pending_count(), 0);
    }

    #[test]
    fn cleanup_for_conn_removes_related_entries() {
        let mut store = HandshakeStore::new();
        let session_id = Uuid::new_v4();
        let initiator = Uuid::new_v4();
        let responder = Uuid::new_v4();
        store.note_prekey_selection(sample_selection(session_id, initiator, responder));
        assert!(store.register_pending_handshake(PendingHandshake {
            session_id,
            hs_id: Uuid::new_v4(),
            initiator_conn: initiator,
            responder_conn: responder,
            peer_spk_id: 7,
            peer_opk_id: Some(55),
            created_at: Instant::now(),
        }));

        store.cleanup_for_conn(initiator);
        assert_eq!(store.pending_count(), 0);
        let err = store.consume_prekey_selection(session_id, initiator, responder, 7, Some(55));
        assert_eq!(err, Err(ConsumeSelectionError::NotFound));
    }
}
