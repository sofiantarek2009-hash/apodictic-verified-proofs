use crate::health::HealthSupervisor;
use std::collections::HashSet;
use std::sync::Arc;
use parking_lot::Mutex;

#[derive(Debug, Clone, PartialEq)]
pub enum FailoverAction {
    PromoteReplica { new_leader_id: u64, old_leader_id: u64 },
    IsolateNode { node_id: u64 },
    RebalanceShards { source_node_id: u64, target_node_ids: Vec<u64> },
}

pub struct FailoverCoordinator {
    health: Arc<HealthSupervisor>,
    current_leader: Mutex<Option<u64>>,
    cluster_nodes: Mutex<Vec<u64>>,
}

impl FailoverCoordinator {
    pub fn new(health: Arc<HealthSupervisor>, initial_leader: u64, nodes: Vec<u64>) -> Self {
        Self {
            health,
            current_leader: Mutex::new(Some(initial_leader)),
            cluster_nodes: Mutex::new(nodes),
        }
    }

    pub fn check_and_execute_failover(&self) -> Option<FailoverAction> {
        let dead_nodes: HashSet<u64> = self.health.evaluate_dead_nodes().into_iter().collect();
        let mut leader_guard = self.current_leader.lock();

        if let Some(leader) = *leader_guard {
            if dead_nodes.contains(&leader) {
                // Leader is dead, elect candidate from surviving nodes
                let nodes = self.cluster_nodes.lock();
                let candidate = nodes.iter().find(|&&n| !dead_nodes.contains(&n)).cloned();

                if let Some(new_leader) = candidate {
                    *leader_guard = Some(new_leader);
                    return Some(FailoverAction::PromoteReplica {
                        new_leader_id: new_leader,
                        old_leader_id: leader,
                    });
                } else {
                    *leader_guard = None; // Total cluster partition
                    return None;
                }
            }
        }

        // Check for degraded follower nodes needing rebalance
        if let Some(&first_dead) = dead_nodes.iter().next() {
            let nodes = self.cluster_nodes.lock();
            let targets: Vec<u64> = nodes.iter().filter(|&&n| !dead_nodes.contains(&n)).cloned().collect();
            if !targets.is_empty() {
                return Some(FailoverAction::RebalanceShards {
                    source_node_id: first_dead,
                    target_node_ids: targets,
                });
            }
        }

        None
    }
}
