use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkReport {
    pub concurrency: usize,
    pub total_transactions: u64,
    pub successful_transactions: u64,
    pub rejected_solvency_violations: u64,
    pub duration_secs: f64,
    pub throughput_tps: f64,
    pub latency_p50_ms: f64,
    pub latency_p95_ms: f64,
    pub latency_p99_ms: f64,
    pub latency_p999_ms: f64,
}

pub struct LatencyHistogram {
    latencies_micros: Vec<u64>,
}

impl LatencyHistogram {
    pub fn new() -> Self {
        Self {
            latencies_micros: Vec::with_capacity(100_000),
        }
    }

    pub fn record(&mut self, dur: Duration) {
        self.latencies_micros.push(dur.as_micros() as u64);
    }

    pub fn compute_percentiles(&mut self) -> (f64, f64, f64, f64) {
        if self.latencies_micros.is_empty() {
            return (0.0, 0.0, 0.0, 0.0);
        }

        self.latencies_micros.sort_unstable();
        let n = self.latencies_micros.len();

        let p50 = self.latencies_micros[n * 50 / 100] as f64 / 1000.0;
        let p95 = self.latencies_micros[n * 95 / 100] as f64 / 1000.0;
        let p99 = self.latencies_micros[n * 99 / 100] as f64 / 1000.0;
        let p999 = self.latencies_micros[n * 999 / 1000] as f64 / 1000.0;

        (p50, p95, p99, p999)
    }
}
