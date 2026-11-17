use std::collections::HashSet;
use rand::Rng;

#[derive(Debug, Clone, PartialEq)]
pub enum PartitionTopology {
    FullyConnected,
    IsolatedNodes(HashSet<u64>),
    MajorityMinoritySplit {
        majority: HashSet<u64>,
        minority: HashSet<u64>,
    },
    BridgePartition {
        group_a: HashSet<u64>,
        bridge: u64,
        group_b: HashSet<u64>,
    },
}

pub struct PartitionMatrix {
    topology: PartitionTopology,
    drop_probability: f64,
}

impl PartitionMatrix {
    pub fn new(topology: PartitionTopology, drop_probability: f64) -> Self {
        Self {
            topology,
            drop_probability,
        }
    }

    pub fn can_deliver(&self, from: u64, to: u64) -> bool {
        if self.drop_probability > 0.0 {
            let mut rng = rand::thread_rng();
            if rng.gen::<f64>() < self.drop_probability {
                return false;
            }
        }

        match &self.topology {
            PartitionTopology::FullyConnected => true,
            PartitionTopology::IsolatedNodes(isolated) => {
                !isolated.contains(&from) && !isolated.contains(&to)
            }
            PartitionTopology::MajorityMinoritySplit { majority, minority } => {
                if majority.contains(&from) && majority.contains(&to) {
                    true
                } else if minority.contains(&from) && minority.contains(&to) {
                    true
                } else {
                    false // Cross-partition network dropped
                }
            }
            PartitionTopology::BridgePartition { group_a, bridge, group_b } => {
                if group_a.contains(&from) && group_b.contains(&to) {
                    false
                } else if group_b.contains(&from) && group_a.contains(&to) {
                    false
                } else {
                    true // Bridge can communicate with both
                }
            }
        }
    }
}
