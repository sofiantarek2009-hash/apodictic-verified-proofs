#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MetricType {
    Cosine,
    Euclidean,
    DotProduct,
}

pub struct DistanceCalculator;

impl DistanceCalculator {
    pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
        let mut dot = 0.0f32;
        let mut norm_a = 0.0f32;
        let mut norm_b = 0.0f32;

        for i in 0..a.len() {
            dot += a[i] * b[i];
            norm_a += a[i] * a[i];
            norm_b += b[i] * b[i];
        }

        if norm_a == 0.0 || norm_b == 0.0 {
            return 0.0;
        }

        dot / (norm_a.sqrt() * norm_b.sqrt())
    }

    pub fn euclidean_distance_sq(a: &[f32], b: &[f32]) -> f32 {
        let mut sum = 0.0f32;
        for i in 0..a.len() {
            let diff = a[i] - b[i];
            sum += diff * diff;
        }
        sum
    }

    pub fn dot_product(a: &[f32], b: &[f32]) -> f32 {
        let mut dot = 0.0f32;
        for i in 0..a.len() {
            dot += a[i] * b[i];
        }
        dot
    }
}
