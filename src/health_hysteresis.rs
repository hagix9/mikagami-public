//! Health observation hysteresis (contract A-6 `[health] failure_threshold` /
//! `success_threshold`).
//!
//! The configured health command is run on every ordinary observation; this
//! pure filter turns its raw results into the stable state the node reports.
//! A definite failure streak shorter than `failure_threshold` does not flip a
//! healthy service, a success streak shorter than `success_threshold` does not
//! flip an unhealthy one, and an observation that could not be made at all
//! (`Unknown`) neither counts as a success nor a failure. The filter is
//! advisory: it feeds status and logging and is never evidence for a safety
//! decision (the promotion workflow reads the raw health check itself).

/// One raw observation of the health command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RawHealth {
    Healthy,
    Unhealthy,
    /// The check could not be run or its result is unusable.
    Unknown,
}

/// The stable reported state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StableHealth {
    /// No threshold has been met yet.
    Unknown,
    Healthy,
    Unhealthy,
}

/// A change of the stable state (for transition-only logging).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HealthTransition {
    BecameUnhealthy { consecutive_failures: u32 },
    Recovered,
}

#[derive(Debug, Clone)]
pub(crate) struct HealthHysteresis {
    failure_threshold: u32,
    success_threshold: u32,
    failures: u32,
    successes: u32,
    stable: StableHealth,
}

impl HealthHysteresis {
    /// Thresholds below 1 are treated as 1 (configuration validation rejects
    /// them earlier; this keeps the filter total).
    pub(crate) fn new(failure_threshold: u32, success_threshold: u32) -> Self {
        Self {
            failure_threshold: failure_threshold.max(1),
            success_threshold: success_threshold.max(1),
            failures: 0,
            successes: 0,
            stable: StableHealth::Unknown,
        }
    }

    pub(crate) const fn stable(&self) -> StableHealth {
        self.stable
    }

    /// The current consecutive failures and successes (for a status display).
    pub(crate) const fn counts(&self) -> (u32, u32) {
        (self.failures, self.successes)
    }

    /// Feed one raw observation; returns the transition it caused, if any.
    pub(crate) fn observe(&mut self, raw: RawHealth) -> Option<HealthTransition> {
        match raw {
            RawHealth::Unknown => None,
            RawHealth::Healthy => {
                self.failures = 0;
                self.successes = self.successes.saturating_add(1);
                if self.successes >= self.success_threshold && self.stable != StableHealth::Healthy
                {
                    let was_unhealthy = self.stable == StableHealth::Unhealthy;
                    self.stable = StableHealth::Healthy;
                    return was_unhealthy.then_some(HealthTransition::Recovered);
                }
                None
            }
            RawHealth::Unhealthy => {
                self.successes = 0;
                self.failures = self.failures.saturating_add(1);
                if self.failures >= self.failure_threshold && self.stable != StableHealth::Unhealthy
                {
                    self.stable = StableHealth::Unhealthy;
                    return Some(HealthTransition::BecameUnhealthy {
                        consecutive_failures: self.failures,
                    });
                }
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use RawHealth::{Healthy, Unhealthy, Unknown};

    fn run(filter: &mut HealthHysteresis, sequence: &[RawHealth]) -> Vec<StableHealth> {
        sequence
            .iter()
            .map(|raw| {
                filter.observe(*raw);
                filter.stable()
            })
            .collect()
    }

    #[test]
    fn starts_unknown_and_needs_the_success_threshold_for_healthy() {
        let mut filter = HealthHysteresis::new(3, 2);
        assert_eq!(filter.stable(), StableHealth::Unknown);
        assert_eq!(
            run(&mut filter, &[Healthy, Healthy]),
            [StableHealth::Unknown, StableHealth::Healthy]
        );
    }

    #[test]
    fn failure_streak_below_threshold_does_not_flip_a_healthy_service() {
        let mut filter = HealthHysteresis::new(3, 1);
        run(&mut filter, &[Healthy]);
        assert_eq!(
            run(
                &mut filter,
                &[Unhealthy, Unhealthy, Healthy, Unhealthy, Unhealthy]
            ),
            [StableHealth::Healthy; 5],
            "the streak restarts after a success"
        );
        assert_eq!(run(&mut filter, &[Unhealthy]), [StableHealth::Unhealthy]);
    }

    #[test]
    fn boundary_exactly_at_the_failure_threshold_flips_and_logs_once() {
        let mut filter = HealthHysteresis::new(3, 2);
        run(&mut filter, &[Healthy, Healthy]);
        assert_eq!(filter.observe(Unhealthy), None);
        assert_eq!(filter.observe(Unhealthy), None);
        assert_eq!(
            filter.observe(Unhealthy),
            Some(HealthTransition::BecameUnhealthy {
                consecutive_failures: 3
            })
        );
        // Further failures are not new transitions.
        assert_eq!(filter.observe(Unhealthy), None);
        assert_eq!(filter.observe(Unhealthy), None);
    }

    #[test]
    fn recovery_needs_the_success_threshold_and_logs_once() {
        let mut filter = HealthHysteresis::new(1, 3);
        run(&mut filter, &[Healthy, Healthy, Healthy, Unhealthy]);
        assert_eq!(filter.stable(), StableHealth::Unhealthy);
        assert_eq!(filter.observe(Healthy), None);
        assert_eq!(filter.observe(Healthy), None);
        assert_eq!(filter.stable(), StableHealth::Unhealthy);
        assert_eq!(filter.observe(Healthy), Some(HealthTransition::Recovered));
        assert_eq!(filter.observe(Healthy), None);
    }

    #[test]
    fn a_failure_resets_the_success_streak() {
        let mut filter = HealthHysteresis::new(1, 3);
        run(&mut filter, &[Healthy, Healthy, Healthy, Unhealthy]);
        run(
            &mut filter,
            &[Healthy, Healthy, Unhealthy, Healthy, Healthy],
        );
        assert_eq!(filter.stable(), StableHealth::Unhealthy);
        assert_eq!(filter.observe(Healthy), Some(HealthTransition::Recovered));
    }

    #[test]
    fn unknown_observations_count_for_neither_side() {
        let mut filter = HealthHysteresis::new(2, 2);
        run(&mut filter, &[Healthy, Healthy]);
        assert_eq!(
            run(&mut filter, &[Unhealthy, Unknown, Unknown, Unknown]),
            [StableHealth::Healthy; 4]
        );
        // The failure streak survived the unknowns: one more flips it.
        assert_eq!(
            filter.observe(Unhealthy),
            Some(HealthTransition::BecameUnhealthy {
                consecutive_failures: 2
            })
        );
        // Never observed anything definite: stays unknown.
        let mut fresh = HealthHysteresis::new(1, 1);
        assert_eq!(run(&mut fresh, &[Unknown; 5]), [StableHealth::Unknown; 5]);
    }

    #[test]
    fn first_failures_from_unknown_reach_unhealthy_at_the_threshold() {
        let mut filter = HealthHysteresis::new(2, 1);
        assert_eq!(filter.observe(Unhealthy), None);
        assert_eq!(
            filter.observe(Unhealthy),
            Some(HealthTransition::BecameUnhealthy {
                consecutive_failures: 2
            })
        );
    }

    #[test]
    fn thresholds_below_one_are_treated_as_one() {
        let mut filter = HealthHysteresis::new(0, 0);
        assert_eq!(filter.observe(Healthy), None);
        assert_eq!(filter.stable(), StableHealth::Healthy);
        assert!(filter.observe(Unhealthy).is_some());
    }

    #[test]
    fn module_is_pure() {
        let source = include_str!("health_hysteresis.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for forbidden in [
            "Instant",
            "Duration",
            "std::fs",
            "std::process",
            "thread",
            "operator_log",
        ] {
            assert!(!production.contains(forbidden), "{forbidden}");
        }
    }
}
