use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use parking_lot::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Dead,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeHealthRecord {
    pub node_id: u64,
    pub status: HealthStatus,
    pub consecutive_failures: u32,
    pub last_heartbeat_unix: u64,
    pub latency_ms: f64,
}

pub struct HealthSupervisor {
    nodes: RwLock<HashMap<u64, (NodeHealthRecord, Instant)>>,
    failure_threshold: u32,
    heartbeat_timeout: Duration,
}

impl HealthSupervisor {
    pub fn new(failure_threshold: u32, heartbeat_timeout: Duration) -> Self {
        Self {
            nodes: RwLock::new(HashMap::new()),
            failure_threshold,
            heartbeat_timeout,
        }
    }

    pub fn register_node(&self, node_id: u64) {
        let mut guard = self.nodes.write();
        let record = NodeHealthRecord {
            node_id,
            status: HealthStatus::Unknown,
            consecutive_failures: 0,
            last_heartbeat_unix: 0,
            latency_ms: 0.0,
        };
        guard.insert(node_id, (record, Instant::now()));
    }

    pub fn record_heartbeat(&self, node_id: u64, latency_ms: f64) {
        let mut guard = self.nodes.write();
        let now = Instant::now();
        let unix_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if let Some((rec, last_seen)) = guard.get_mut(&node_id) {
            rec.status = HealthStatus::Healthy;
            rec.consecutive_failures = 0;
            rec.last_heartbeat_unix = unix_now;
            rec.latency_ms = latency_ms;
            *last_seen = now;
        }
    }

    pub fn record_failure(&self, node_id: u64) {
        let mut guard = self.nodes.write();
        if let Some((rec, _)) = guard.get_mut(&node_id) {
            rec.consecutive_failures += 1;
            if rec.consecutive_failures >= self.failure_threshold {
                rec.status = HealthStatus::Dead;
            } else {
                rec.status = HealthStatus::Degraded;
            }
        }
    }

    pub fn evaluate_dead_nodes(&self) -> Vec<u64> {
        let mut guard = self.nodes.write();
        let now = Instant::now();
        let mut dead = Vec::new();

        for (&node_id, (rec, last_seen)) in guard.iter_mut() {
            if now.duration_since(*last_seen) > self.heartbeat_timeout {
                rec.status = HealthStatus::Dead;
                dead.push(node_id);
            }
        }

        dead
    }
}
