use crate::proto::ClusterNodeInfo;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

pub trait LoadBalancer: Send + Sync {
    fn select_node(&self) -> Option<ClusterNodeInfo>;
    fn update_nodes(&self, nodes: Vec<ClusterNodeInfo>);
}

pub struct RoundRobinBalancer {
    nodes: RwLock<Vec<ClusterNodeInfo>>,
    counter: AtomicUsize,
}

impl RoundRobinBalancer {
    pub fn new(initial_nodes: Vec<ClusterNodeInfo>) -> Self {
        Self {
            nodes: RwLock::new(initial_nodes),
            counter: AtomicUsize::new(0),
        }
    }
}

impl LoadBalancer for RoundRobinBalancer {
    fn select_node(&self) -> Option<ClusterNodeInfo> {
        let guard = self.nodes.read();
        if guard.is_empty() {
            return None;
        }
        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % guard.len();
        Some(guard[idx].clone())
    }

    fn update_nodes(&self, new_nodes: Vec<ClusterNodeInfo>) {
        let mut guard = self.nodes.write();
        *guard = new_nodes;
    }
}

pub struct ConsistentHashingRing {
    ring: RwLock<Vec<(u32, ClusterNodeInfo)>>,
}

impl ConsistentHashingRing {
    pub fn new(nodes: Vec<ClusterNodeInfo>, virtual_nodes: usize) -> Self {
        let mut ring = Vec::new();
        for node in nodes {
            for v in 0..virtual_nodes {
                let v_key = format!("{}:{}:{}", node.node_id, node.address, v);
                let hash = crc32fast::hash(v_key.as_bytes());
                ring.push((hash, node.clone()));
            }
        }
        ring.sort_by_key(|&(h, _)| h);
        Self {
            ring: RwLock::new(ring),
        }
    }

    pub fn get_node_for_key(&self, key: &[u8]) -> Option<ClusterNodeInfo> {
        let guard = self.ring.read();
        if guard.is_empty() {
            return None;
        }
        let hash = crc32fast::hash(key);

        match guard.binary_search_by_key(&hash, |&(h, _)| h) {
            Ok(idx) => Some(guard[idx].1.clone()),
            Err(idx) => {
                if idx < guard.len() {
                    Some(guard[idx].1.clone())
                } else {
                    Some(guard[0].1.clone())
                }
            }
        }
    }
}
