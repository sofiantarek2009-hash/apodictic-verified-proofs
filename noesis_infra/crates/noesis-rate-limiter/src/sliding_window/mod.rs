use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

pub struct SlidingWindowLimiter {
    windows: Mutex<HashMap<String, VecDeque<Instant>>>,
    max_requests: usize,
    window_duration: Duration,
}

impl SlidingWindowLimiter {
    pub fn new(max_requests: usize, window_duration: Duration) -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
            max_requests,
            window_duration,
        }
    }

    pub fn allow_request(&self, client_key: &str) -> bool {
        let now = Instant::now();
        let cutoff = now.checked_sub(self.window_duration).unwrap_or(now);

        let mut guard = self.windows.lock();
        let timestamps = guard.entry(client_key.to_string()).or_insert_with(VecDeque::new);

        // Prune entries older than sliding window
        while let Some(&front) = timestamps.front() {
            if front < cutoff {
                timestamps.pop_front();
            } else {
                break;
            }
        }

        if timestamps.len() < self.max_requests {
            timestamps.push_back(now);
            true
        } else {
            false
        }
    }
}
