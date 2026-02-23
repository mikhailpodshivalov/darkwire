use darkwire_protocol::config::LimitsConfig;
use std::{collections::HashMap, net::IpAddr, sync::Arc, time::Instant};
use tokio::sync::RwLock;
use uuid::Uuid;

pub type ConnId = Uuid;
pub type SharedState = Arc<AppState>;

#[derive(Debug, Clone)]
pub struct ConnectionRecord {
    pub id: ConnId,
    pub ip: IpAddr,
    pub connected_at: Instant,
    pub last_activity: Instant,
}

#[derive(Debug)]
pub struct AppState {
    limits: LimitsConfig,
    connections: RwLock<HashMap<ConnId, ConnectionRecord>>,
}

impl AppState {
    pub fn new(limits: LimitsConfig) -> Self {
        Self {
            limits,
            connections: RwLock::new(HashMap::new()),
        }
    }

    pub fn limits(&self) -> &LimitsConfig {
        &self.limits
    }

    pub async fn register_connection(&self, ip: IpAddr) -> ConnId {
        let now = Instant::now();
        let id = Uuid::new_v4();
        let record = ConnectionRecord {
            id,
            ip,
            connected_at: now,
            last_activity: now,
        };

        self.connections.write().await.insert(id, record);
        id
    }

    pub async fn touch_connection(&self, id: ConnId) -> bool {
        let mut connections = self.connections.write().await;
        match connections.get_mut(&id) {
            Some(record) => {
                record.last_activity = Instant::now();
                true
            }
            None => false,
        }
    }

    pub async fn get_connection(&self, id: ConnId) -> Option<ConnectionRecord> {
        self.connections.read().await.get(&id).cloned()
    }

    pub async fn unregister_connection(&self, id: ConnId) -> Option<ConnectionRecord> {
        self.connections.write().await.remove(&id)
    }

    pub async fn active_connection_count(&self) -> usize {
        self.connections.read().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::{IpAddr, Ipv4Addr},
        time::Duration,
    };

    #[tokio::test]
    async fn connection_lifecycle_updates_and_cleans_up() {
        let state = AppState::new(LimitsConfig::default());
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let conn_id = state.register_connection(ip).await;
        assert_eq!(state.active_connection_count().await, 1);

        let before_touch = state
            .get_connection(conn_id)
            .await
            .expect("connection should exist");
        assert_eq!(before_touch.id, conn_id);
        assert_eq!(before_touch.ip, ip);

        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(state.touch_connection(conn_id).await);

        let after_touch = state
            .get_connection(conn_id)
            .await
            .expect("connection should still exist");
        assert!(after_touch.last_activity > before_touch.last_activity);

        let removed = state
            .unregister_connection(conn_id)
            .await
            .expect("connection should be removed");
        assert_eq!(removed.id, conn_id);
        assert_eq!(state.active_connection_count().await, 0);
    }
}
