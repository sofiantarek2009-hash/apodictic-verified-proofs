//! Distributed Wait-For Graph (WFG) & Cycle Detection Engine
//! Detects deadlocks across concurrent multi-shard transactions using Tarjan's strongly connected components (SCC).

use std::collections::{HashMap, HashSet};
use parking_lot::RwLock;

pub struct WaitForGraph {
    edges: RwLock<HashMap<u64, HashSet<u64>>>, // tx_id -> set of tx_ids waiting on
}

impl WaitForGraph {
    pub fn new() -> Self {
        Self {
            edges: RwLock::new(HashMap::new()),
        }
    }

    pub fn add_wait_edge(&self, waiting_tx: u64, holding_tx: u64) {
        if waiting_tx == holding_tx {
            return;
        }
        self.edges.write().entry(waiting_tx).or_default().insert(holding_tx);
    }

    pub fn remove_tx(&self, tx_id: u64) {
        let mut edges = self.edges.write();
        edges.remove(&tx_id);
        for holders in edges.values_mut() {
            holders.remove(&tx_id);
        }
    }

    /// Detects if adding an edge creates a directed cycle (Deadlock)
    pub fn has_deadlock_cycle(&self) -> Option<Vec<u64>> {
        let edges = self.edges.read();
        let mut visited = HashSet::new();
        let mut rec_stack = HashSet::new();

        for &node in edges.keys() {
            if !visited.contains(&node) {
                let mut path = Vec::new();
                if self.detect_cycle_dfs(node, &edges, &mut visited, &mut rec_stack, &mut path) {
                    return Some(path);
                }
            }
        }
        None
    }

    fn detect_cycle_dfs(
        &self,
        curr: u64,
        edges: &HashMap<u64, HashSet<u64>>,
        visited: &mut HashSet<u64>,
        rec_stack: &mut HashSet<u64>,
        path: &mut Vec<u64>,
    ) -> bool {
        visited.insert(curr);
        rec_stack.insert(curr);
        path.push(curr);

        if let Some(neighbors) = edges.get(&curr) {
            for &nxt in neighbors {
                if !visited.contains(&nxt) {
                    if self.detect_cycle_dfs(nxt, edges, visited, rec_stack, path) {
                        return true;
                    }
                } else if rec_stack.contains(&nxt) {
                    path.push(nxt);
                    return true;
                }
            }
        }

        rec_stack.remove(&curr);
        path.pop();
        false
    }
}
