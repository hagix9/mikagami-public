use std::fmt;
use std::time::{Duration, Instant};

/// Local peer communication observation; `Unreachable` does not prove peer death.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerLiveness {
    Healthy,
    Suspect,
    Unreachable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LivenessThresholds {
    suspect_after: Duration,
    unreachable_after: Duration,
}

impl LivenessThresholds {
    pub fn new(
        suspect_after: Duration,
        unreachable_after: Duration,
    ) -> Result<Self, LivenessConfigError> {
        if suspect_after.is_zero() {
            return Err(LivenessConfigError::ZeroSuspectThreshold);
        }
        if unreachable_after.is_zero() {
            return Err(LivenessConfigError::ZeroUnreachableThreshold);
        }
        if suspect_after >= unreachable_after {
            return Err(LivenessConfigError::InvalidThresholdOrder);
        }
        Ok(Self {
            suspect_after,
            unreachable_after,
        })
    }

    pub const fn suspect_after(&self) -> Duration {
        self.suspect_after
    }

    pub const fn unreachable_after(&self) -> Duration {
        self.unreachable_after
    }

    pub fn classify(&self, elapsed: Duration) -> PeerLiveness {
        if elapsed >= self.unreachable_after {
            PeerLiveness::Unreachable
        } else if elapsed >= self.suspect_after {
            PeerLiveness::Suspect
        } else {
            PeerLiveness::Healthy
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LivenessConfigError {
    ZeroSuspectThreshold,
    ZeroUnreachableThreshold,
    InvalidThresholdOrder,
}

impl fmt::Display for LivenessConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ZeroSuspectThreshold => "suspect threshold must be greater than zero",
            Self::ZeroUnreachableThreshold => "unreachable threshold must be greater than zero",
            Self::InvalidThresholdOrder => {
                "suspect threshold must be less than unreachable threshold"
            }
        };
        write!(f, "{message}")
    }
}

impl std::error::Error for LivenessConfigError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerLivenessObservation {
    NotObservedYet,
    Observed(PeerLiveness),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LivenessTrackerError {
    TimeWentBackwards,
}

impl fmt::Display for LivenessTrackerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TimeWentBackwards => write!(f, "liveness observation time moved backwards"),
        }
    }
}

impl std::error::Error for LivenessTrackerError {}

#[derive(Debug, Default)]
pub struct PeerLivenessTracker {
    last_success: Option<Instant>,
}

impl PeerLivenessTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn last_success(&self) -> Option<Instant> {
        self.last_success
    }

    pub fn record_success(&mut self, now: Instant) -> Result<(), LivenessTrackerError> {
        if self.last_success.is_some_and(|last| now < last) {
            return Err(LivenessTrackerError::TimeWentBackwards);
        }
        self.last_success = Some(now);
        Ok(())
    }

    pub fn observe(
        &self,
        now: Instant,
        thresholds: &LivenessThresholds,
    ) -> Result<PeerLivenessObservation, LivenessTrackerError> {
        let Some(last_success) = self.last_success else {
            return Ok(PeerLivenessObservation::NotObservedYet);
        };
        let elapsed = now
            .checked_duration_since(last_success)
            .ok_or(LivenessTrackerError::TimeWentBackwards)?;
        Ok(PeerLivenessObservation::Observed(
            thresholds.classify(elapsed),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn thresholds() -> LivenessThresholds {
        LivenessThresholds::new(Duration::from_secs(3), Duration::from_secs(10)).unwrap()
    }

    #[test]
    fn classifies_elapsed_boundaries() {
        let thresholds = thresholds();
        for elapsed in [
            Duration::ZERO,
            Duration::from_secs(1),
            Duration::from_millis(2999),
        ] {
            assert_eq!(thresholds.classify(elapsed), PeerLiveness::Healthy);
        }
        for elapsed in [
            Duration::from_secs(3),
            Duration::from_secs(5),
            Duration::from_millis(9999),
        ] {
            assert_eq!(thresholds.classify(elapsed), PeerLiveness::Suspect);
        }
        for elapsed in [Duration::from_secs(10), Duration::from_secs(20)] {
            assert_eq!(thresholds.classify(elapsed), PeerLiveness::Unreachable);
        }
    }

    #[test]
    fn rejects_invalid_thresholds() {
        assert_eq!(
            LivenessThresholds::new(Duration::ZERO, Duration::from_secs(10)),
            Err(LivenessConfigError::ZeroSuspectThreshold)
        );
        assert_eq!(
            LivenessThresholds::new(Duration::from_secs(3), Duration::ZERO),
            Err(LivenessConfigError::ZeroUnreachableThreshold)
        );
        assert_eq!(
            LivenessThresholds::new(Duration::from_secs(3), Duration::from_secs(3)),
            Err(LivenessConfigError::InvalidThresholdOrder)
        );
        assert_eq!(
            LivenessThresholds::new(Duration::from_secs(4), Duration::from_secs(3)),
            Err(LivenessConfigError::InvalidThresholdOrder)
        );
    }

    #[test]
    fn classifies_large_elapsed_duration_as_unreachable() {
        assert_eq!(
            thresholds().classify(Duration::MAX),
            PeerLiveness::Unreachable
        );
    }

    #[test]
    fn classification_is_deterministic() {
        let thresholds = thresholds();
        let elapsed = Duration::from_millis(7500);
        assert_eq!(thresholds.classify(elapsed), thresholds.classify(elapsed));
        assert_eq!(thresholds.suspect_after(), Duration::from_secs(3));
        assert_eq!(thresholds.unreachable_after(), Duration::from_secs(10));
    }

    #[test]
    fn tracker_starts_without_an_observation() {
        let now = Instant::now();
        let tracker = PeerLivenessTracker::new();
        let observation = tracker.observe(now, &thresholds()).unwrap();
        assert_eq!(observation, PeerLivenessObservation::NotObservedYet);
        assert_ne!(
            observation,
            PeerLivenessObservation::Observed(PeerLiveness::Healthy)
        );
    }

    #[test]
    fn tracker_records_success_as_healthy() {
        let t0 = Instant::now();
        let mut tracker = PeerLivenessTracker::new();
        tracker.record_success(t0).unwrap();
        assert_eq!(
            tracker.observe(t0, &thresholds()).unwrap(),
            PeerLivenessObservation::Observed(PeerLiveness::Healthy)
        );
    }

    #[test]
    fn tracker_classifies_boundaries() {
        let t0 = Instant::now();
        let mut tracker = PeerLivenessTracker::new();
        tracker.record_success(t0).unwrap();
        for (elapsed, expected) in [
            (Duration::from_millis(2999), PeerLiveness::Healthy),
            (Duration::from_millis(3000), PeerLiveness::Suspect),
            (Duration::from_millis(9999), PeerLiveness::Suspect),
            (Duration::from_millis(10000), PeerLiveness::Unreachable),
        ] {
            assert_eq!(
                tracker.observe(t0 + elapsed, &thresholds()).unwrap(),
                PeerLivenessObservation::Observed(expected)
            );
        }
    }

    #[test]
    fn newer_success_refreshes_liveness() {
        let t0 = Instant::now();
        let mut tracker = PeerLivenessTracker::new();
        tracker.record_success(t0).unwrap();
        assert_eq!(
            tracker
                .observe(t0 + Duration::from_secs(5), &thresholds())
                .unwrap(),
            PeerLivenessObservation::Observed(PeerLiveness::Suspect)
        );
        let refreshed = t0 + Duration::from_secs(5);
        tracker.record_success(refreshed).unwrap();
        assert_eq!(
            tracker
                .observe(t0 + Duration::from_secs(6), &thresholds())
                .unwrap(),
            PeerLivenessObservation::Observed(PeerLiveness::Healthy)
        );
    }

    #[test]
    fn repeated_success_uses_newest_time() {
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(2);
        let mut tracker = PeerLivenessTracker::new();
        tracker.record_success(t0).unwrap();
        tracker.record_success(t1).unwrap();
        assert_eq!(tracker.last_success(), Some(t1));
        assert_eq!(
            tracker
                .observe(t1 + Duration::from_secs(2), &thresholds())
                .unwrap(),
            PeerLivenessObservation::Observed(PeerLiveness::Healthy)
        );
    }

    #[test]
    fn backwards_record_is_rejected_without_changing_state() {
        let t0 = Instant::now();
        let mut tracker = PeerLivenessTracker::new();
        tracker.record_success(t0).unwrap();
        assert_eq!(
            tracker.record_success(t0 - Duration::from_secs(1)),
            Err(LivenessTrackerError::TimeWentBackwards)
        );
        assert_eq!(tracker.last_success(), Some(t0));
    }

    #[test]
    fn backwards_observation_is_rejected_without_changing_state() {
        let t0 = Instant::now();
        let mut tracker = PeerLivenessTracker::new();
        tracker.record_success(t0).unwrap();
        assert_eq!(
            tracker.observe(t0 - Duration::from_secs(1), &thresholds()),
            Err(LivenessTrackerError::TimeWentBackwards)
        );
        assert_eq!(tracker.last_success(), Some(t0));
    }

    #[test]
    fn same_success_time_is_accepted() {
        let t0 = Instant::now();
        let mut tracker = PeerLivenessTracker::new();
        tracker.record_success(t0).unwrap();
        tracker.record_success(t0).unwrap();
        assert_eq!(
            tracker.observe(t0, &thresholds()).unwrap(),
            PeerLivenessObservation::Observed(PeerLiveness::Healthy)
        );
    }

    #[test]
    fn tracker_observation_is_deterministic() {
        let t0 = Instant::now();
        let mut tracker = PeerLivenessTracker::new();
        tracker.record_success(t0).unwrap();
        let now = t0 + Duration::from_secs(7);
        assert_eq!(
            tracker.observe(now, &thresholds()).unwrap(),
            tracker.observe(now, &thresholds()).unwrap()
        );
    }
}
