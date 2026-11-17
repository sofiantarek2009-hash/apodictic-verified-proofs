use parking_lot::Mutex;
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct TokenBucket {
    capacity: f64,
    refill_rate_per_sec: f64,
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    pub fn new(capacity: f64, refill_rate_per_sec: f64) -> Self {
        Self {
            capacity,
            refill_rate_per_sec,
            tokens: capacity,
            last_refill: Instant::now(),
        }
    }

    pub fn try_acquire(&mut self, tokens_requested: f64) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate_per_sec).min(self.capacity);
        self.last_refill = now;

        if self.tokens >= tokens_requested {
            self.tokens -= tokens_requested;
            true
        } else {
            false
        }
    }
}

pub struct MultiTenantTokenBucketLimiter {
    buckets: Mutex<HashMap<String, TokenBucket>>,
    default_capacity: f64,
    default_refill_rate: f64,
}

impl MultiTenantTokenBucketLimiter {
    pub fn new(default_capacity: f64, default_refill_rate: f64) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            default_capacity,
            default_refill_rate,
        }
    }

    pub fn check_rate_limit(&self, tenant_id: &str, cost: f64) -> bool {
        let mut guard = self.buckets.lock();
        let bucket = guard.entry(tenant_id.to_string()).or_insert_with(|| {
            TokenBucket::new(self.default_capacity, self.default_refill_rate)
        });
        bucket.try_acquire(cost)
    }
}
