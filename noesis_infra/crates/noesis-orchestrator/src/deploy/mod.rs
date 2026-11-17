use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use parking_lot::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpgradePhase {
    Pending,
    DrainingTraffic,
    UpdatingBinary,
    RunningHealthChecks,
    RestoringTraffic,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollingUpgradeSpec {
    pub target_version: String,
    pub max_unavailable_nodes: usize,
    pub health_check_timeout_secs: u64,
}

pub struct RollingUpgradeManager {
    spec: RollingUpgradeSpec,
    pending_nodes: Mutex<VecDeque<u64>>,
    in_progress: Mutex<Option<(u64, UpgradePhase)>>,
    upgraded_nodes: Mutex<Vec<u64>>,
}

impl RollingUpgradeManager {
    pub fn new(spec: RollingUpgradeSpec, nodes: Vec<u64>) -> Self {
        Self {
            spec,
            pending_nodes: Mutex::new(VecDeque::from(nodes)),
            in_progress: Mutex::new(None),
            upgraded_nodes: Mutex::new(Vec::new()),
        }
    }

    pub fn advance_step(&self, is_healthy: bool) -> Option<(u64, UpgradePhase)> {
        let mut in_prog = self.in_progress.lock();

        if let Some((node_id, phase)) = *in_prog {
            let next_phase = match phase {
                UpgradePhase::DrainingTraffic => UpgradePhase::UpdatingBinary,
                UpgradePhase::UpdatingBinary => UpgradePhase::RunningHealthChecks,
                UpgradePhase::RunningHealthChecks => {
                    if is_healthy {
                        UpgradePhase::RestoringTraffic
                    } else {
                        UpgradePhase::Failed
                    }
                }
                UpgradePhase::RestoringTraffic => {
                    self.upgraded_nodes.lock().push(node_id);
                    UpgradePhase::Completed
                }
                UpgradePhase::Completed | UpgradePhase::Failed => {
                    *in_prog = None;
                    return None;
                }
                _ => UpgradePhase::Failed,
            };

            if next_phase == UpgradePhase::Completed || next_phase == UpgradePhase::Failed {
                *in_prog = None;
                Some((node_id, next_phase))
            } else {
                *in_prog = Some((node_id, next_phase));
                Some((node_id, next_phase))
            }
        } else {
            // Pick next pending node
            let mut pending = self.pending_nodes.lock();
            if let Some(next_node) = pending.pop_front() {
                let initial = UpgradePhase::DrainingTraffic;
                *in_prog = Some((next_node, initial));
                Some((next_node, initial))
            } else {
                None // All nodes completed
            }
        }
    }
}
