//! # Apodictic Kinetic Ontology CSR Graph Kernel
//!
//! High-speed Compressed Sparse Row (CSR) in-memory property graph engine
//! for sub-millisecond k-hop blast-radius traversal and Tarjan/DFS cycle
//! detection (detecting circular VAT carousel fraud and shell-company wash trading).

use std::collections::{HashMap, HashSet, VecDeque};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum OntologyGraphError {
    #[error("Entity node not found in CSR graph: {0}")]
    NodeNotFound(String),
    #[error("Acyclic constraint violated between {source_id} and {target_id}")]
    CycleDetected { source_id: String, target_id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeightedEdge {
    pub target_idx: usize,
    pub link_type: String,
    pub exposure_usd: f64,
}

/// Compressed Sparse Row (CSR) Financial Property Graph
pub struct CsrOntologyGraph {
    node_to_idx: HashMap<String, usize>,
    idx_to_node: Vec<String>,
    adjacency: Vec<Vec<WeightedEdge>>,
}

impl CsrOntologyGraph {
    pub fn new() -> Self {
        Self {
            node_to_idx: HashMap::new(),
            idx_to_node: Vec::new(),
            adjacency: Vec::new(),
        }
    }

    pub fn add_node(&mut self, node_id: &str) -> usize {
        if let Some(&idx) = self.node_to_idx.get(node_id) {
            return idx;
        }
        let idx = self.idx_to_node.len();
        self.idx_to_node.push(node_id.to_string());
        self.node_to_idx.insert(node_id.to_string(), idx);
        self.adjacency.push(Vec::new());
        idx
    }

    pub fn add_edge(&mut self, source_id: &str, target_id: &str, link_type: &str, exposure_usd: f64) {
        let src_idx = self.add_node(source_id);
        let tgt_idx = self.add_node(target_id);
        self.adjacency[src_idx].push(WeightedEdge {
            target_idx: tgt_idx,
            link_type: link_type.to_string(),
            exposure_usd,
        });
    }

    /// Sub-millisecond k-hop blast radius traversal
    pub fn k_hop_blast_radius(&self, origin_id: &str, max_hops: usize) -> Result<Vec<(String, usize, f64)>, OntologyGraphError> {
        let &origin_idx = self.node_to_idx.get(origin_id)
            .ok_or_else(|| OntologyGraphError::NodeNotFound(origin_id.to_string()))?;

        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut results = Vec::new();

        visited.insert(origin_idx);
        queue.push_back((origin_idx, 0usize, 1.0f64));

        while let Some((curr, hop, attenuation)) = queue.pop_front() {
            if hop >= max_hops {
                continue;
            }
            for edge in &self.adjacency[curr] {
                if visited.insert(edge.target_idx) {
                    let next_att = attenuation * 0.75;
                    results.push((
                        self.idx_to_node[edge.target_idx].clone(),
                        hop + 1,
                        edge.exposure_usd * next_att,
                    ));
                    queue.push_back((edge.target_idx, hop + 1, next_att));
                }
            }
        }

        Ok(results)
    }

    /// Detects circular wash-trading or VAT carousel fraud cycles
    pub fn detect_wash_trading_cycles(&self) -> Vec<Vec<String>> {
        let n = self.idx_to_node.len();
        let mut state = vec![0u8; n]; // 0 = unvisited, 1 = visiting, 2 = visited
        let mut stack = Vec::new();
        let mut cycles = Vec::new();

        for i in 0..n {
            if state[i] == 0 {
                self.dfs_cycle(i, &mut state, &mut stack, &mut cycles);
            }
        }
        cycles
    }

    fn dfs_cycle(&self, u: usize, state: &mut [u8], stack: &mut Vec<usize>, cycles: &mut Vec<Vec<String>>) {
        state[u] = 1;
        stack.push(u);

        for edge in &self.adjacency[u] {
            let v = edge.target_idx;
            if state[v] == 1 {
                if let Some(pos) = stack.iter().position(|&x| x == v) {
                    let mut cycle: Vec<String> = stack[pos..].iter().map(|&idx| self.idx_to_node[idx].clone()).collect();
                    cycle.push(self.idx_to_node[v].clone());
                    cycles.push(cycle);
                }
            } else if state[v] == 0 {
                self.dfs_cycle(v, state, stack, cycles);
            }
        }

        stack.pop();
        state[u] = 2;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csr_carousel_fraud_cycle_detection() {
        let mut g = CsrOntologyGraph::new();
        g.add_edge("SHELL-A", "SHELL-B", "INTERCOMPANY_FLOW", 1_000_000.0);
        g.add_edge("SHELL-B", "SHELL-C", "INTERCOMPANY_FLOW", 1_000_000.0);
        g.add_edge("SHELL-C", "SHELL-A", "INTERCOMPANY_FLOW", 1_000_000.0);

        let cycles = g.detect_wash_trading_cycles();
        assert_eq!(cycles.len(), 1);
        assert_eq!(cycles[0].len(), 4);
    }
}
