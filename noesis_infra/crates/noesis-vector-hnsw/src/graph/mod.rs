use crate::distance::DistanceCalculator;
use parking_lot::RwLock;
use rand::Rng;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::cmp::Ordering;

#[derive(Debug, Clone)]
struct Candidate {
    id: usize,
    distance: f32,
}

impl PartialEq for Candidate {
    fn eq(&self, other: &Self) -> bool {
        self.distance == other.distance
    }
}
impl Eq for Candidate {}

impl PartialOrd for Candidate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.distance.partial_cmp(&other.distance)
    }
}

impl Ord for Candidate {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap_or(Ordering::Equal)
    }
}

pub struct HnswConfig {
    pub max_connections_layer0: usize,
    pub max_connections: usize,
    pub ef_construction: usize,
    pub ef_search: usize,
    pub level_multiplier: f64,
}

impl Default for HnswConfig {
    fn default() -> Self {
        Self {
            max_connections_layer0: 32,
            max_connections: 16,
            ef_construction: 64,
            ef_search: 32,
            level_multiplier: 1.0 / (16.0f64.ln()),
        }
    }
}

pub struct HnswIndex {
    config: HnswConfig,
    vectors: RwLock<Vec<Vec<f32>>>,
    // layers[level][node_id] = list of neighbor node_ids
    layers: RwLock<Vec<HashMap<usize, Vec<usize>>>>,
    entry_point: RwLock<Option<(usize, usize)>>, // (node_id, level)
}

impl HnswIndex {
    pub fn new(config: HnswConfig) -> Self {
        Self {
            config,
            vectors: RwLock::new(Vec::new()),
            layers: RwLock::new(Vec::new()),
            entry_point: RwLock::new(None),
        }
    }

    fn sample_level(&self) -> usize {
        let mut rng = rand::thread_rng();
        let r: f64 = rng.gen();
        (-r.ln() * self.config.level_multiplier) as usize
    }

    pub fn insert(&self, vector: Vec<f32>) -> usize {
        let mut vectors_guard = self.vectors.write();
        let node_id = vectors_guard.len();
        vectors_guard.push(vector.clone());
        drop(vectors_guard);

        let insert_level = self.sample_level();
        let mut layers_guard = self.layers.write();

        while layers_guard.len() <= insert_level {
            layers_guard.push(HashMap::new());
        }

        let mut ep_guard = self.entry_point.write();
        let current_ep = *ep_guard;

        if let Some((mut curr_obj, top_level)) = current_ep {
            let vectors = self.vectors.read();
            let mut curr_dist = 1.0 - DistanceCalculator::cosine_similarity(&vector, &vectors[curr_obj]);

            // Greedy search down to insert_level
            for level in (insert_level + 1..=top_level).rev() {
                let mut changed = true;
                while changed {
                    changed = false;
                    if let Some(neighbors) = layers_guard[level].get(&curr_obj) {
                        for &n in neighbors {
                            let d = 1.0 - DistanceCalculator::cosine_similarity(&vector, &vectors[n]);
                            if d < curr_dist {
                                curr_dist = d;
                                curr_obj = n;
                                changed = true;
                            }
                        }
                    }
                }
            }

            // Connect at levels from min(insert_level, top_level) down to 0
            for level in (0..=insert_level.min(top_level)).rev() {
                let neighbors_entry = layers_guard[level].entry(node_id).or_insert_with(Vec::new);
                neighbors_entry.push(curr_obj);

                let target_neighbors = layers_guard[level].entry(curr_obj).or_insert_with(Vec::new);
                target_neighbors.push(node_id);
            }

            if insert_level > top_level {
                *ep_guard = Some((node_id, insert_level));
            }
        } else {
            for level in 0..=insert_level {
                layers_guard[level].insert(node_id, Vec::new());
            }
            *ep_guard = Some((node_id, insert_level));
        }

        node_id
    }

    pub fn search_knn(&self, query: &[f32], k: usize) -> Vec<(usize, f32)> {
        let ep = *self.entry_point.read();
        let (mut curr_obj, top_level) = match ep {
            Some(p) => p,
            None => return Vec::new(),
        };

        let vectors = self.vectors.read();
        let layers = self.layers.read();
        let mut curr_dist = 1.0 - DistanceCalculator::cosine_similarity(query, &vectors[curr_obj]);

        // Search down layers to layer 0
        for level in (1..=top_level).rev() {
            let mut changed = true;
            while changed {
                changed = false;
                if let Some(neighbors) = layers[level].get(&curr_obj) {
                    for &n in neighbors {
                        let d = 1.0 - DistanceCalculator::cosine_similarity(query, &vectors[n]);
                        if d < curr_dist {
                            curr_dist = d;
                            curr_obj = n;
                            changed = true;
                        }
                    }
                }
            }
        }

        // Layer 0 beam search
        let mut visited = HashSet::new();
        visited.insert(curr_obj);
        let mut candidates = BinaryHeap::new();
        candidates.push(Candidate { id: curr_obj, distance: curr_dist });

        let mut results = Vec::new();
        while let Some(candidate) = candidates.pop() {
            results.push((candidate.id, 1.0 - candidate.distance));
            if results.len() >= k {
                break;
            }

            if let Some(neighbors) = layers[0].get(&candidate.id) {
                for &neighbor in neighbors {
                    if !visited.contains(&neighbor) {
                        visited.insert(neighbor);
                        let d = 1.0 - DistanceCalculator::cosine_similarity(query, &vectors[neighbor]);
                        candidates.push(Candidate { id: neighbor, distance: d });
                    }
                }
            }
        }

        results
    }
}
