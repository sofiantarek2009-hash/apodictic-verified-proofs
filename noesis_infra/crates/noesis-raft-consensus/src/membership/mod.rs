use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ConfigurationState {
    Stable(HashSet<u64>),
    Joint {
        old_nodes: HashSet<u64>,
        new_nodes: HashSet<u64>,
    },
}

impl ConfigurationState {
    pub fn is_joint(&self) -> bool {
        matches!(self, ConfigurationState::Joint { .. })
    }

    pub fn has_quorum(&self, votes: &HashSet<u64>) -> bool {
        match self {
            ConfigurationState::Stable(nodes) => {
                let count = nodes.intersection(votes).count();
                count > nodes.len() / 2
            }
            ConfigurationState::Joint { old_nodes, new_nodes } => {
                let old_count = old_nodes.intersection(votes).count();
                let new_count = new_nodes.intersection(votes).count();
                (old_count > old_nodes.len() / 2) && (new_count > new_nodes.len() / 2)
            }
        }
    }

    pub fn enter_joint(&mut self, next_nodes: HashSet<u64>) -> Result<(), &'static str> {
        match self {
            ConfigurationState::Stable(current) => {
                *self = ConfigurationState::Joint {
                    old_nodes: current.clone(),
                    new_nodes: next_nodes,
                };
                Ok(())
            }
            ConfigurationState::Joint { .. } => Err("Already in joint consensus transition"),
        }
    }

    pub fn finalize_joint(&mut self) -> Result<(), &'static str> {
        match self {
            ConfigurationState::Joint { new_nodes, .. } => {
                *self = ConfigurationState::Stable(new_nodes.clone());
                Ok(())
            }
            ConfigurationState::Stable(_) => Err("Not in joint consensus"),
        }
    }

    pub fn all_nodes(&self) -> HashSet<u64> {
        match self {
            ConfigurationState::Stable(nodes) => nodes.clone(),
            ConfigurationState::Joint { old_nodes, new_nodes } => {
                old_nodes.union(new_nodes).cloned().collect()
            }
        }
    }
}
