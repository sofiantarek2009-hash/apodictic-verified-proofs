use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterNodeSpec {
    pub node_id: u64,
    pub rack: String,
    pub ip_address: String,
    pub port: u16,
    pub is_raft_voter: bool,
    pub microvm_enclave_capacity: usize,
}

pub struct TopologyMap {
    pub nodes: HashMap<u64, ClusterNodeSpec>,
}

impl TopologyMap {
    pub fn generate_10k_cluster_spec() -> Self {
        let mut nodes = HashMap::with_capacity(10_000);
        for i in 1..=10_000 {
            let rack_id = (i % 100) + 1;
            let node_spec = ClusterNodeSpec {
                node_id: i as u64,
                rack: format!("rack-{:03}", rack_id),
                ip_address: format!("10.{}.{}.{}", (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF),
                port: 5432,
                is_raft_voter: i <= 7, // 7-node consensus core
                microvm_enclave_capacity: 100, // 100 warm Firecracker VMs per host
            };
            nodes.insert(i as u64, node_spec);
        }
        Self { nodes }
    }

    pub fn total_nodes(&self) -> usize {
        self.nodes.len()
    }

    pub fn total_enclaves_capacity(&self) -> usize {
        self.nodes.values().map(|n| n.microvm_enclave_capacity).sum()
    }
}
