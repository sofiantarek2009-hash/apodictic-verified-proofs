use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum MigrationError {
    #[error("Cyclic dependency detected in migrations: {0}")]
    CyclicDependency(String),
    #[error("Checksum mismatch for migration {version}: expected {expected}, got {computed}")]
    ChecksumMismatch { version: u64, expected: String, computed: String },
    #[error("Missing prerequisite migration: {0}")]
    MissingPrerequisite(u64),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MigrationStep {
    pub version: u64,
    pub description: String,
    pub up_sql: String,
    pub down_sql: String,
    pub dependencies: Vec<u64>,
    pub checksum: String,
}

impl MigrationStep {
    pub fn new(version: u64, description: &str, up_sql: &str, down_sql: &str, dependencies: Vec<u64>) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(up_sql.as_bytes());
        hasher.update(down_sql.as_bytes());
        let hash = hasher.finalize();
        let checksum = hex::encode(hash);

        Self {
            version,
            description: description.to_string(),
            up_sql: up_sql.to_string(),
            down_sql: down_sql.to_string(),
            dependencies,
            checksum,
        }
    }
}

pub struct MigrationDag {
    steps: HashMap<u64, MigrationStep>,
}

impl MigrationDag {
    pub fn new() -> Self {
        Self {
            steps: HashMap::new(),
        }
    }

    pub fn add_migration(&mut self, step: MigrationStep) -> Result<(), MigrationError> {
        self.steps.insert(step.version, step);
        Ok(())
    }

    pub fn resolve_execution_order(&self) -> Result<Vec<MigrationStep>, MigrationError> {
        let mut in_degree: HashMap<u64, usize> = HashMap::new();
        let mut adj: HashMap<u64, Vec<u64>> = HashMap::new();

        for &v in self.steps.keys() {
            in_degree.insert(v, 0);
            adj.insert(v, Vec::new());
        }

        for step in self.steps.values() {
            for &dep in &step.dependencies {
                if !self.steps.contains_key(&dep) {
                    return Err(MigrationError::MissingPrerequisite(dep));
                }
                adj.get_mut(&dep).unwrap().push(step.version);
                *in_degree.get_mut(&step.version).unwrap() += 1;
            }
        }

        let mut queue: VecDeque<u64> = in_degree.iter()
            .filter(|&(_, &deg)| deg == 0)
            .map(|(&v, _)| v)
            .collect();

        let mut ordered_versions = Vec::new();

        while let Some(v) = queue.pop_front() {
            ordered_versions.push(v);
            if let Some(neighbors) = adj.get(&v) {
                for &neighbor in neighbors {
                    let deg = in_degree.get_mut(&neighbor).unwrap();
                    *deg -= 1;
                    if *deg == 0 {
                        queue.push_back(neighbor);
                    }
                }
            }
        }

        if ordered_versions.len() != self.steps.len() {
            return Err(MigrationError::CyclicDependency("Cycle detected in migration graph".into()));
        }

        let ordered_steps = ordered_versions.into_iter()
            .map(|v| self.steps.get(&v).cloned().unwrap())
            .collect();

        Ok(ordered_steps)
    }
}

mod hex {
    pub fn encode(data: impl AsRef<[u8]>) -> String {
        let mut s = String::new();
        for b in data.as_ref() {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }
}
