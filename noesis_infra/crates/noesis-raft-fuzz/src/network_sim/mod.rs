use crate::partition::PartitionMatrix;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use parking_lot::Mutex;

#[derive(Debug, Clone)]
pub struct SimulatedPacket {
    pub from: u64,
    pub to: u64,
    pub payload: Vec<u8>,
    pub deliver_at_tick: u64,
}

pub struct VirtualNetworkSimulator {
    matrix: Arc<Mutex<PartitionMatrix>>,
    queues: Mutex<HashMap<u64, VecDeque<SimulatedPacket>>>,
    current_tick: Mutex<u64>,
}

impl VirtualNetworkSimulator {
    pub fn new(matrix: PartitionMatrix) -> Self {
        Self {
            matrix: Arc::new(Mutex::new(matrix)),
            queues: Mutex::new(HashMap::new()),
            current_tick: Mutex::new(0),
        }
    }

    pub fn set_partition(&self, new_matrix: PartitionMatrix) {
        let mut guard = self.matrix.lock();
        *guard = new_matrix;
    }

    pub fn send(&self, from: u64, to: u64, payload: Vec<u8>, latency_ticks: u64) {
        let matrix = self.matrix.lock();
        if !matrix.can_deliver(from, to) {
            return; // Dropped by partition or chaos fault
        }

        let tick = *self.current_tick.lock();
        let packet = SimulatedPacket {
            from,
            to,
            payload,
            deliver_at_tick: tick + latency_ticks,
        };

        let mut queues = self.queues.lock();
        queues.entry(to).or_insert_with(VecDeque::new).push_back(packet);
    }

    pub fn advance_tick(&self) -> Vec<SimulatedPacket> {
        let mut tick = self.current_tick.lock();
        *tick += 1;
        let current = *tick;

        let mut ready = Vec::new();
        let mut queues = self.queues.lock();

        for queue in queues.values_mut() {
            let mut remaining = VecDeque::new();
            while let Some(packet) = queue.pop_front() {
                if packet.deliver_at_tick <= current {
                    ready.push(packet);
                } else {
                    remaining.push_back(packet);
                }
            }
            *queue = remaining;
        }

        ready
    }
}
