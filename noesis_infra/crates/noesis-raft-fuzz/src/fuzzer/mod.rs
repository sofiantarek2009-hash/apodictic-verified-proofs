use crate::network_sim::VirtualNetworkSimulator;
use crate::partition::{PartitionMatrix, PartitionTopology};
use std::collections::HashSet;

pub struct JepsenRaftFuzzer {
    simulator: VirtualNetworkSimulator,
    cluster_nodes: Vec<u64>,
}

impl JepsenRaftFuzzer {
    pub fn new(nodes: Vec<u64>) -> Self {
        let sim = VirtualNetworkSimulator::new(PartitionMatrix::new(PartitionTopology::FullyConnected, 0.0));
        Self {
            simulator: sim,
            cluster_nodes: nodes,
        }
    }

    pub fn inject_split_brain_partition(&self) {
        let n = self.cluster_nodes.len();
        let split_idx = (n / 2) + 1;
        let majority: HashSet<u64> = self.cluster_nodes[0..split_idx].iter().cloned().collect();
        let minority: HashSet<u64> = self.cluster_nodes[split_idx..n].iter().cloned().collect();

        self.simulator.set_partition(PartitionMatrix::new(
            PartitionTopology::MajorityMinoritySplit { majority, minority },
            0.0,
        ));
    }

    pub fn heal_network(&self) {
        self.simulator.set_partition(PartitionMatrix::new(PartitionTopology::FullyConnected, 0.0));
    }

    pub fn run_chaos_cycle(&self, ticks: usize) -> usize {
        let mut packets_delivered = 0;
        for _ in 0..ticks {
            let delivered = self.simulator.advance_tick();
            packets_delivered += delivered.len();
        }
        packets_delivered
    }
}
