use std::collections::HashMap;
use std::time::Instant;
use uuid::Uuid;

pub type ConnId = Uuid;
pub type SessionId = Uuid;

#[derive(Debug, Clone)]
pub struct SessionRecord {
    pub id: SessionId,
    pub a: ConnId,
    pub b: ConnId,
    #[allow(dead_code)]
    pub started_at: Instant,
    pub last_activity: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionClosed {
    pub session_id: SessionId,
    pub peer_conn: ConnId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionCreateError {
    ConnectionBusy,
    SamePeer,
}

#[derive(Debug, Default)]
pub struct SessionStore {
    by_id: HashMap<SessionId, SessionRecord>,
    by_conn: HashMap<ConnId, SessionId>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            by_id: HashMap::new(),
            by_conn: HashMap::new(),
        }
    }

    pub fn create(
        &mut self,
        a: ConnId,
        b: ConnId,
        now: Instant,
    ) -> Result<SessionRecord, SessionCreateError> {
        if a == b {
            return Err(SessionCreateError::SamePeer);
        }

        if self.by_conn.contains_key(&a) || self.by_conn.contains_key(&b) {
            return Err(SessionCreateError::ConnectionBusy);
        }

        let id = Uuid::new_v4();
        let session = SessionRecord {
            id,
            a,
            b,
            started_at: now,
            last_activity: now,
        };

        self.by_conn.insert(a, id);
        self.by_conn.insert(b, id);
        self.by_id.insert(id, session.clone());

        Ok(session)
    }

    pub fn session_for_conn(&self, conn: ConnId) -> Option<&SessionRecord> {
        let session_id = self.by_conn.get(&conn)?;
        self.by_id.get(session_id)
    }

    pub fn session_for_conn_mut(&mut self, conn: ConnId) -> Option<&mut SessionRecord> {
        let session_id = *self.by_conn.get(&conn)?;
        self.by_id.get_mut(&session_id)
    }

    pub fn close_for_conn(&mut self, conn: ConnId) -> Option<SessionClosed> {
        let session_id = self.by_conn.remove(&conn)?;
        let session = self.by_id.remove(&session_id)?;

        let peer_conn = if session.a == conn {
            session.b
        } else {
            session.a
        };
        self.by_conn.remove(&peer_conn);

        Some(SessionClosed {
            session_id,
            peer_conn,
        })
    }

    pub fn peer_for_conn(&self, conn: ConnId) -> Option<(SessionId, ConnId)> {
        let session = self.session_for_conn(conn)?;
        let peer = if session.a == conn {
            session.b
        } else {
            session.a
        };
        Some((session.id, peer))
    }

    pub fn touch_conn(&mut self, conn: ConnId, now: Instant) {
        if let Some(session) = self.session_for_conn_mut(conn) {
            session.last_activity = now;
        }
    }

    #[cfg(test)]
    pub fn session_count(&self) -> usize {
        self.by_id.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn create_and_close_lifecycle() {
        let mut store = SessionStore::new();
        let now = Instant::now();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();

        let session = store.create(a, b, now).expect("session should be created");
        assert_eq!(store.session_count(), 1);
        assert_eq!(store.peer_for_conn(a), Some((session.id, b)));

        let closed = store.close_for_conn(a).expect("session should close");
        assert_eq!(closed.session_id, session.id);
        assert_eq!(closed.peer_conn, b);
        assert_eq!(store.session_count(), 0);
    }

    #[test]
    fn create_rejects_busy_connection() {
        let mut store = SessionStore::new();
        let now = Instant::now();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let c = Uuid::new_v4();

        store.create(a, b, now).expect("first session should pass");
        let err = store
            .create(a, c, now + Duration::from_secs(1))
            .expect_err("second session with same conn should fail");
        assert_eq!(err, SessionCreateError::ConnectionBusy);
    }

    #[test]
    fn touch_updates_last_activity() {
        let mut store = SessionStore::new();
        let now = Instant::now();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();

        let created = store.create(a, b, now).expect("session should be created");
        store.touch_conn(a, now + Duration::from_secs(5));

        let session = store
            .session_for_conn(a)
            .expect("session should still exist after touch");
        assert_eq!(session.started_at, created.started_at);
        assert!(session.last_activity > created.last_activity);
    }
}
