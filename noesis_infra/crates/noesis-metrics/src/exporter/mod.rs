use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;

pub struct Counter {
    name: String,
    help: String,
    value: AtomicU64,
}

impl Counter {
    pub fn new(name: &str, help: &str) -> Self {
        Self {
            name: name.to_string(),
            help: help.to_string(),
            value: AtomicU64::new(0),
        }
    }

    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_by(&self, val: u64) {
        self.value.fetch_add(val, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

pub struct Gauge {
    name: String,
    help: String,
    value: AtomicI64,
}

impl Gauge {
    pub fn new(name: &str, help: &str) -> Self {
        Self {
            name: name.to_string(),
            help: help.to_string(),
            value: AtomicI64::new(0),
        }
    }

    pub fn set(&self, val: i64) {
        self.value.store(val, Ordering::Relaxed);
    }

    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec(&self) {
        self.value.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn get(&self) -> i64 {
        self.value.load(Ordering::Relaxed)
    }
}

pub struct Histogram {
    name: String,
    help: String,
    buckets: Vec<f64>,
    counts: Vec<AtomicU64>,
    sum: AtomicU64, // scaled by 1e6 for microsecond precision
}

impl Histogram {
    pub fn new(name: &str, help: &str, buckets: Vec<f64>) -> Self {
        let mut sorted_buckets = buckets;
        sorted_buckets.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let counts = (0..=sorted_buckets.len()).map(|_| AtomicU64::new(0)).collect();

        Self {
            name: name.to_string(),
            help: help.to_string(),
            buckets: sorted_buckets,
            counts,
            sum: AtomicU64::new(0),
        }
    }

    pub fn observe(&self, val: f64) {
        let val_scaled = (val * 1_000_000.0) as u64;
        self.sum.fetch_add(val_scaled, Ordering::Relaxed);

        let mut bucket_idx = self.buckets.len();
        for (i, &b) in self.buckets.iter().enumerate() {
            if val <= b {
                bucket_idx = i;
                break;
            }
        }
        self.counts[bucket_idx].fetch_add(1, Ordering::Relaxed);
    }
}

pub struct MetricsRegistry {
    counters: RwLock<HashMap<String, Arc<Counter>>>,
    gauges: RwLock<HashMap<String, Arc<Gauge>>>,
    histograms: RwLock<HashMap<String, Arc<Histogram>>>,
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self {
            counters: RwLock::new(HashMap::new()),
            gauges: RwLock::new(HashMap::new()),
            histograms: RwLock::new(HashMap::new()),
        }
    }

    pub fn register_counter(&self, name: &str, help: &str) -> Arc<Counter> {
        let mut guard = self.counters.write();
        guard.entry(name.to_string()).or_insert_with(|| Arc::new(Counter::new(name, help))).clone()
    }

    pub fn register_gauge(&self, name: &str, help: &str) -> Arc<Gauge> {
        let mut guard = self.gauges.write();
        guard.entry(name.to_string()).or_insert_with(|| Arc::new(Gauge::new(name, help))).clone()
    }

    pub fn register_histogram(&self, name: &str, help: &str, buckets: Vec<f64>) -> Arc<Histogram> {
        let mut guard = self.histograms.write();
        guard.entry(name.to_string()).or_insert_with(|| Arc::new(Histogram::new(name, help, buckets))).clone()
    }

    pub fn export_prometheus(&self) -> String {
        let mut out = String::new();

        {
            let counters = self.counters.read();
            for (name, c) in counters.iter() {
                out.push_str(&format!("# HELP {} {}\n", name, c.help));
                out.push_str(&format!("# TYPE {} counter\n", name));
                out.push_str(&format!("{} {}\n", name, c.get()));
            }
        }

        {
            let gauges = self.gauges.read();
            for (name, g) in gauges.iter() {
                out.push_str(&format!("# HELP {} {}\n", name, g.help));
                out.push_str(&format!("# TYPE {} gauge\n", name));
                out.push_str(&format!("{} {}\n", name, g.get()));
            }
        }

        out
    }
}
