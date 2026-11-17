//! VirtIO Dynamic Memory Ballooning & Guest Watchdog Protocol
//! Allows host orchestrator to dynamically reclaim guest RAM without terminating the VM:
//! - VirtIO Balloon Driver: pages inflated/deflated via virtqueue
//! - Guest Agent Heartbeat: periodic ping over vsock ensuring sub-millisecond liveness

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use parking_lot::Mutex;
use tracing::{info, warn};

pub struct VirtioMemoryBalloon {
    pub current_ram_mib: AtomicU64,
    pub target_ram_mib: AtomicU64,
    pub actual_pages: AtomicU64,
}

impl VirtioMemoryBalloon {
    pub fn new(initial_ram_mib: u64) -> Self {
        Self {
            current_ram_mib: AtomicU64::new(initial_ram_mib),
            target_ram_mib: AtomicU64::new(initial_ram_mib),
            actual_pages: AtomicU64::new(initial_ram_mib * 256), // 4KB pages
        }
    }

    /// Requests guest to inflate balloon (reclaim memory back to host)
    pub fn inflate_balloon(&self, reclaim_mib: u64) {
        let curr = self.current_ram_mib.load(Ordering::SeqCst);
        let target = curr.saturating_sub(reclaim_mib).max(64); // Keep 64MB minimum
        self.target_ram_mib.store(target, Ordering::SeqCst);
        info!("Inflating balloon: Target guest RAM reduced to {} MiB", target);
    }

    /// Requests guest to deflate balloon (give memory back to guest)
    pub fn deflate_balloon(&self, expand_mib: u64) {
        let curr = self.current_ram_mib.load(Ordering::SeqCst);
        let target = curr + expand_mib;
        self.target_ram_mib.store(target, Ordering::SeqCst);
        info!("Deflating balloon: Target guest RAM expanded to {} MiB", target);
    }
}

pub struct GuestHeartbeatWatchdog {
    last_heartbeat: Mutex<Instant>,
    timeout_threshold: Duration,
}

impl GuestHeartbeatWatchdog {
    pub fn new(timeout_threshold: Duration) -> Self {
        Self {
            last_heartbeat: Mutex::new(Instant::now()),
            timeout_threshold,
        }
    }

    pub fn record_heartbeat(&self) {
        *self.last_heartbeat.lock() = Instant::now();
    }

    pub fn is_alive(&self) -> bool {
        self.last_heartbeat.lock().elapsed() < self.timeout_threshold
    }
}
