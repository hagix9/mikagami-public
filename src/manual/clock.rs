//! Time source used by polling loops, injectable for deterministic tests.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub(crate) trait Clock {
    /// Monotonic milliseconds since an arbitrary origin.
    fn now_ms(&self) -> u64;
    fn sleep(&self, duration: Duration);
    /// Wall-clock seconds. The controller uses it for records and evidence
    /// only. The Witness agent's own wall clock does take two decisions (see
    /// `lease.rs`): whether an operation that has not mutated anything may be
    /// taken over after its TTL, and whether a mutating operation has been
    /// silent long enough for `reconcile --abandon-op`. Both are liveness /
    /// plausibility aids; a clock step cannot make a mutating operation
    /// expire, and the operator's explicit decision is always required.
    fn unix_secs(&self) -> u64;
}

pub(crate) struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    pub(crate) fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }

    fn unix_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }
}
