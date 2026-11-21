//! Runtime driver for Witness-local lease expiry maintenance.

use crate::witness_authority::{LeaseExpiryResult, WitnessAuthorityError, expire_lease_if_needed};
use crate::witness_state::{
    BootIdProvider, LeaseState, MonotonicClock, WitnessReadiness, WitnessStateStore,
};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

const DEFAULT_RETRY_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerStep {
    Idle,
    Wait(Duration),
    Expired,
    NotExpired,
    Retry,
}

#[derive(Debug)]
pub enum WitnessExpirySchedulerError {
    AuthorityLockPoisoned,
    Authority(WitnessAuthorityError),
}

impl std::fmt::Display for WitnessExpirySchedulerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthorityLockPoisoned => write!(f, "authority mutation lock is poisoned"),
            Self::Authority(error) => write!(f, "expiry scheduler authority error: {error}"),
        }
    }
}

impl std::error::Error for WitnessExpirySchedulerError {}

#[derive(Clone, Default)]
pub struct SchedulerCancellation {
    state: Arc<(Mutex<bool>, Condvar)>,
}

impl SchedulerCancellation {
    pub fn cancel(&self) {
        let (lock, wake) = &*self.state;
        if let Ok(mut cancelled) = lock.lock() {
            *cancelled = true;
            wake.notify_all();
        }
    }

    fn is_cancelled(&self) -> bool {
        self.state.0.lock().map(|value| *value).unwrap_or(true)
    }

    fn wait(&self, duration: Duration) -> bool {
        let (lock, wake) = &*self.state;
        let Ok(cancelled) = lock.lock() else {
            return true;
        };
        if *cancelled {
            return true;
        }
        let (cancelled, _) = wake
            .wait_timeout_while(cancelled, duration, |value| !*value)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *cancelled
    }
}

pub struct WitnessExpiryScheduler {
    retry_interval: Duration,
}

impl Default for WitnessExpiryScheduler {
    fn default() -> Self {
        Self::new(DEFAULT_RETRY_INTERVAL)
    }
}

impl WitnessExpiryScheduler {
    pub fn new(retry_interval: Duration) -> Self {
        Self {
            retry_interval: retry_interval.max(Duration::from_millis(1)),
        }
    }

    pub fn retry_interval(&self) -> Duration {
        self.retry_interval
    }

    pub fn cancellation(&self) -> SchedulerCancellation {
        SchedulerCancellation::default()
    }

    pub fn schedule_once<B, C>(
        &self,
        store: &WitnessStateStore<B, C>,
    ) -> Result<SchedulerStep, WitnessExpirySchedulerError>
    where
        B: BootIdProvider,
        C: MonotonicClock,
    {
        let recovery = store.load();
        if recovery.readiness != WitnessReadiness::Ready {
            return Ok(SchedulerStep::Retry);
        }
        let Some(state) = recovery.state else {
            return Ok(SchedulerStep::Retry);
        };
        match state.lease_state {
            LeaseState::None => Ok(SchedulerStep::Idle),
            LeaseState::Unknown => Ok(SchedulerStep::Retry),
            LeaseState::Active => {
                let Some(deadline) = state.lease_deadline_monotonic_ms else {
                    return Ok(SchedulerStep::Retry);
                };
                let now = match store.current_monotonic_ms() {
                    Ok(now) => now,
                    Err(_) => return Ok(SchedulerStep::Retry),
                };
                if now < deadline {
                    return Ok(SchedulerStep::Wait(Duration::from_millis(deadline - now)));
                }
                match expire_lease_if_needed(store) {
                    Ok(LeaseExpiryResult::Expired) => Ok(SchedulerStep::Expired),
                    Ok(LeaseExpiryResult::NotExpired) => Ok(SchedulerStep::NotExpired),
                    Err(WitnessAuthorityError::AuthorityLockPoisoned) => {
                        Err(WitnessExpirySchedulerError::AuthorityLockPoisoned)
                    }
                    Err(error) => {
                        let _ = error;
                        Ok(SchedulerStep::Retry)
                    }
                }
            }
        }
    }

    pub fn run_until_cancelled<B, C>(
        &self,
        store: &WitnessStateStore<B, C>,
        cancellation: &SchedulerCancellation,
    ) -> Result<(), WitnessExpirySchedulerError>
    where
        B: BootIdProvider,
        C: MonotonicClock,
    {
        while !cancellation.is_cancelled() {
            let step = self.schedule_once(store)?;
            let wait = match step {
                SchedulerStep::Wait(duration) => duration,
                SchedulerStep::Idle
                | SchedulerStep::Retry
                | SchedulerStep::Expired
                | SchedulerStep::NotExpired => self.retry_interval,
            };
            if cancellation.wait(wait) {
                break;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        ClusterId, CommonFields, DurationMs, LeaseId, LeaseReleasePayload, LeaseRequestPayload,
        NodeId, PROTOCOL_VERSION, ProtocolMessage, RequestId, Sequence, SessionId, Term,
        UnsignedEnvelope,
    };
    use crate::witness_authority::{
        prepare_lease_release_authority, prepare_lease_renew_authority,
        prepare_lease_request_authority,
    };
    use crate::witness_state::{BootId, WitnessPersistentState};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::thread;

    #[derive(Clone)]
    struct Boot;
    impl BootIdProvider for Boot {
        fn current_boot_id(&self) -> Result<BootId, crate::witness_state::WitnessStateError> {
            Ok(BootId::new("boot-a"))
        }
    }

    #[derive(Clone)]
    struct OtherBoot;
    impl BootIdProvider for OtherBoot {
        fn current_boot_id(&self) -> Result<BootId, crate::witness_state::WitnessStateError> {
            Ok(BootId::new("boot-b"))
        }
    }

    #[derive(Clone, Copy)]
    struct Clock(u64);
    impl MonotonicClock for Clock {
        fn now_ms(&self) -> Result<u64, crate::witness_state::WitnessStateError> {
            Ok(self.0)
        }
    }

    struct FailedClock;
    impl MonotonicClock for FailedClock {
        fn now_ms(&self) -> Result<u64, crate::witness_state::WitnessStateError> {
            Err(crate::witness_state::WitnessStateError::Clock(
                std::io::Error::other("test clock failure"),
            ))
        }
    }

    fn path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("mikagami-stage8-{name}-{}", std::process::id()))
    }

    fn store(path: &Path, clock: Clock) -> WitnessStateStore<Boot, Clock> {
        WitnessStateStore::with_providers(path, ClusterId::new("cluster"), Boot, clock)
    }

    fn other_boot_store(path: &Path, clock: Clock) -> WitnessStateStore<OtherBoot, Clock> {
        WitnessStateStore::with_providers(path, ClusterId::new("cluster"), OtherBoot, clock)
    }

    fn failed_clock_store(path: &Path) -> WitnessStateStore<Boot, FailedClock> {
        WitnessStateStore::with_providers(path, ClusterId::new("cluster"), Boot, FailedClock)
    }

    fn active(deadline: u64) -> WitnessPersistentState {
        WitnessPersistentState {
            state_format_version: 2,
            cluster_id: ClusterId::new("cluster"),
            current_term: Term(7),
            active_lease_id: Some(LeaseId::new("lease-1")),
            holder_node_id: Some(crate::protocol::NodeId::new("node-a")),
            lease_ttl_ms: Some(crate::protocol::DurationMs(10_000)),
            lease_deadline_monotonic_ms: Some(deadline),
            lease_state: LeaseState::Active,
            boot_id: BootId::new("boot-a"),
            journal: Vec::new(),
            generation_watermarks: std::collections::BTreeMap::new(),
        }
    }

    fn lease_request(
        request_id: &str,
        generation: u64,
        observed_term: u64,
    ) -> (
        UnsignedEnvelope,
        crate::witness_runtime::WitnessRequestObservation,
    ) {
        let request_id = RequestId::new(request_id);
        let payload = LeaseRequestPayload {
            mutation_generation: generation,
            observed_term: Term(observed_term),
            priority: 100,
            requested_ttl: DurationMs(10_000),
        };
        (
            UnsignedEnvelope {
                common: CommonFields {
                    protocol_version: PROTOCOL_VERSION,
                    cluster_id: ClusterId::new("cluster"),
                    sender_node_id: NodeId::new("node-a"),
                    receiver_node_id: NodeId::new("witness"),
                    session_id: SessionId::new("session-a"),
                    sequence: Sequence(1),
                    term: Term(0),
                    lease_id: None,
                    request_id: Some(request_id.clone()),
                    operation_id: None,
                },
                message: ProtocolMessage::LeaseRequest(payload.clone()),
            },
            crate::witness_runtime::WitnessRequestObservation::LeaseRequest {
                request_id,
                sender_node_id: NodeId::new("node-a"),
                term: Term(0),
                lease_id: None,
                payload,
            },
        )
    }

    fn lease_renew(
        request_id: &str,
        generation: u64,
    ) -> (
        UnsignedEnvelope,
        crate::witness_runtime::WitnessRequestObservation,
    ) {
        let request_id = RequestId::new(request_id);
        let payload = crate::protocol::LeaseRenewPayload {
            mutation_generation: generation,
            term: Term(7),
            lease_id: LeaseId::new("lease-1"),
        };
        (
            UnsignedEnvelope {
                common: CommonFields {
                    protocol_version: PROTOCOL_VERSION,
                    cluster_id: ClusterId::new("cluster"),
                    sender_node_id: NodeId::new("node-a"),
                    receiver_node_id: NodeId::new("witness"),
                    session_id: SessionId::new("session-a"),
                    sequence: Sequence(1),
                    term: Term(0),
                    lease_id: None,
                    request_id: Some(request_id.clone()),
                    operation_id: None,
                },
                message: ProtocolMessage::LeaseRenew(payload.clone()),
            },
            crate::witness_runtime::WitnessRequestObservation::LeaseRenew {
                request_id,
                sender_node_id: NodeId::new("node-a"),
                term: Term(0),
                lease_id: None,
                payload,
            },
        )
    }

    fn lease_release(
        request_id: &str,
        generation: u64,
    ) -> (
        UnsignedEnvelope,
        crate::witness_runtime::WitnessRequestObservation,
    ) {
        let request_id = RequestId::new(request_id);
        let payload = LeaseReleasePayload {
            mutation_generation: generation,
            term: Term(7),
            lease_id: LeaseId::new("lease-1"),
            reason: "test release".to_string(),
        };
        (
            UnsignedEnvelope {
                common: CommonFields {
                    protocol_version: PROTOCOL_VERSION,
                    cluster_id: ClusterId::new("cluster"),
                    sender_node_id: NodeId::new("node-a"),
                    receiver_node_id: NodeId::new("witness"),
                    session_id: SessionId::new("session-a"),
                    sequence: Sequence(1),
                    term: Term(0),
                    lease_id: None,
                    request_id: Some(request_id.clone()),
                    operation_id: None,
                },
                message: ProtocolMessage::LeaseRelease(payload.clone()),
            },
            crate::witness_runtime::WitnessRequestObservation::LeaseRelease {
                request_id,
                sender_node_id: NodeId::new("node-a"),
                term: Term(0),
                lease_id: None,
                payload,
            },
        )
    }

    #[test]
    fn early_wake_waits_and_exact_deadline_expires() {
        let file = path("boundary");
        let before = store(&file, Clock(9_999));
        before.save(&active(10_000)).unwrap();
        let scheduler = WitnessExpiryScheduler::default();
        assert!(matches!(
            scheduler.schedule_once(&before),
            Ok(SchedulerStep::Wait(duration)) if duration == Duration::from_millis(1)
        ));

        let at = store(&file, Clock(10_000));
        assert_eq!(
            scheduler.schedule_once(&at).unwrap(),
            SchedulerStep::Expired
        );
        assert_eq!(at.load().state.unwrap().lease_state, LeaseState::None);
        let _ = std::fs::remove_file(file);
    }

    #[test]
    fn none_is_idle_and_scheduler_can_be_cancelled() {
        let file = path("cancel");
        let store = store(&file, Clock(1_000));
        store
            .save(&WitnessPersistentState::new(
                ClusterId::new("cluster"),
                BootId::new("boot-a"),
            ))
            .unwrap();
        let scheduler = WitnessExpiryScheduler::new(Duration::from_millis(10));
        assert_eq!(
            scheduler.schedule_once(&store).unwrap(),
            SchedulerStep::Idle
        );
        let cancellation = scheduler.cancellation();
        let worker_cancel = cancellation.clone();
        let worker = thread::spawn(move || worker_cancel.wait(Duration::from_secs(30)));
        cancellation.cancel();
        assert!(worker.join().unwrap());
        let _ = std::fs::remove_file(file);
    }

    #[test]
    fn scheduler_wait_does_not_hold_authority_lock() {
        let file = path("lock-scope");
        let initial_store = store(&file, Clock(1_000));
        initial_store.save(&active(10_000)).unwrap();
        let scheduler = WitnessExpiryScheduler::default();
        assert!(matches!(
            scheduler.schedule_once(&initial_store),
            Ok(SchedulerStep::Wait(_))
        ));
        let cancellation = scheduler.cancellation();
        let worker_cancel = cancellation.clone();
        let worker_store = store(&file, Clock(10_000));
        let worker = thread::spawn(move || {
            let scheduler = WitnessExpiryScheduler::default();
            scheduler.run_until_cancelled(&worker_store, &worker_cancel)
        });
        let expiry_store = store(&file, Clock(10_000));
        assert!(matches!(
            expire_lease_if_needed(&expiry_store).unwrap(),
            LeaseExpiryResult::Expired | LeaseExpiryResult::NotExpired
        ));
        assert_eq!(
            expiry_store.load().state.unwrap().lease_state,
            LeaseState::None
        );
        cancellation.cancel();
        assert!(worker.join().unwrap().is_ok());
        let _ = std::fs::remove_file(file);
    }

    #[test]
    fn scheduler_error_paths_retry_without_inventing_expiry() {
        let file = path("retry");
        let store = store(&file, Clock(1_000));
        let unknown = WitnessPersistentState {
            lease_state: LeaseState::Unknown,
            ..WitnessPersistentState::new(ClusterId::new("cluster"), BootId::new("boot-a"))
        };
        store.save(&unknown).unwrap();
        assert_eq!(
            WitnessExpiryScheduler::default()
                .schedule_once(&store)
                .unwrap(),
            SchedulerStep::Retry
        );
        assert_eq!(store.load().state.unwrap().lease_state, LeaseState::Unknown);
        let _ = std::fs::remove_file(file);
    }

    #[test]
    fn cancellation_is_safe_to_clone() {
        let cancellation = SchedulerCancellation::default();
        let clone = Arc::new(cancellation.clone());
        let worker = Arc::clone(&clone);
        let handle = thread::spawn(move || worker.wait(Duration::from_secs(30)));
        cancellation.cancel();
        assert!(handle.join().unwrap());
    }

    #[test]
    fn cancellation_mutex_poison_stops_waiting_safely() {
        let cancellation = SchedulerCancellation::default();
        let state = Arc::clone(&cancellation.state);
        let poisoned = thread::spawn(move || {
            let _guard = state.0.lock().unwrap();
            panic!("poison cancellation mutex for test");
        });
        assert!(poisoned.join().is_err());
        assert!(cancellation.is_cancelled());
        assert!(cancellation.wait(Duration::from_millis(1)));
    }

    #[test]
    fn renew_after_scheduler_observation_does_not_expire_from_old_deadline() {
        let file = path("renew-after-observation");
        let observed = store(&file, Clock(9_000));
        observed.save(&active(10_000)).unwrap();
        let scheduler = WitnessExpiryScheduler::default();
        assert!(matches!(
            scheduler.schedule_once(&observed),
            Ok(SchedulerStep::Wait(duration)) if duration == Duration::from_secs(1)
        ));

        let renewed = store(&file, Clock(5_000));
        let (request, observation) = lease_renew("00000000-0000-4000-8000-000000000101", 1);
        prepare_lease_renew_authority(&renewed, &observation, &request).unwrap();

        let old_wake = store(&file, Clock(11_000));
        assert!(matches!(
            scheduler.schedule_once(&old_wake),
            Ok(SchedulerStep::Wait(duration)) if duration == Duration::from_secs(4)
        ));
        let current = old_wake.load().state.unwrap();
        assert_eq!(current.lease_state, LeaseState::Active);
        assert_eq!(current.current_term, Term(7));
        assert_eq!(current.active_lease_id, Some(LeaseId::new("lease-1")));
        assert_eq!(current.holder_node_id, Some(NodeId::new("node-a")));
        assert_eq!(current.lease_deadline_monotonic_ms, Some(15_000));
        assert_eq!(current.journal.len(), 1);
        assert_eq!(current.generation_watermarks.get("node-a"), Some(&1));
        let _ = std::fs::remove_file(file);
    }

    #[test]
    fn release_after_scheduler_observation_leaves_none_and_old_timer_idle() {
        let file = path("release-after-observation");
        let observed = store(&file, Clock(9_000));
        observed.save(&active(10_000)).unwrap();
        let scheduler = WitnessExpiryScheduler::default();
        assert!(matches!(
            scheduler.schedule_once(&observed),
            Ok(SchedulerStep::Wait(_))
        ));

        let released = store(&file, Clock(5_000));
        let (request, observation) = lease_release("00000000-0000-4000-8000-000000000102", 1);
        prepare_lease_release_authority(&released, &observation, &request).unwrap();

        let old_wake = store(&file, Clock(11_000));
        assert_eq!(
            scheduler.schedule_once(&old_wake).unwrap(),
            SchedulerStep::Idle
        );
        let current = old_wake.load().state.unwrap();
        assert_eq!(current.lease_state, LeaseState::None);
        assert_eq!(current.current_term, Term(7));
        assert_eq!(current.active_lease_id, None);
        assert_eq!(current.holder_node_id, None);
        assert_eq!(current.lease_ttl_ms, None);
        assert_eq!(current.lease_deadline_monotonic_ms, None);
        assert_eq!(current.journal.len(), 1);
        assert_eq!(current.generation_watermarks.get("node-a"), Some(&1));
        let _ = std::fs::remove_file(file);
    }

    #[test]
    fn old_l1_timer_does_not_clear_new_l2_after_aba_transition() {
        let file = path("aba-old-timer");
        let initial = store(&file, Clock(10_000));
        initial.save(&active(10_000)).unwrap();
        let scheduler = WitnessExpiryScheduler::default();
        assert_eq!(
            scheduler.schedule_once(&initial).unwrap(),
            SchedulerStep::Expired
        );

        let grant_store = store(&file, Clock(10_001));
        let (request, observation) = lease_request("00000000-0000-4000-8000-000000000103", 1, 7);
        prepare_lease_request_authority(&grant_store, &observation, &request).unwrap();

        let old_wake = store(&file, Clock(11_000));
        assert!(matches!(
            scheduler.schedule_once(&old_wake),
            Ok(SchedulerStep::Wait(_))
        ));
        let current = old_wake.load().state.unwrap();
        assert_eq!(current.current_term, Term(8));
        assert_eq!(current.lease_state, LeaseState::Active);
        assert_eq!(current.holder_node_id, Some(NodeId::new("node-a")));
        assert_eq!(current.lease_deadline_monotonic_ms, Some(20_001));
        assert_eq!(current.journal.len(), 1);
        assert_eq!(current.generation_watermarks.get("node-a"), Some(&1));
        let _ = std::fs::remove_file(file);
    }

    #[test]
    fn not_ready_and_clock_failure_retry_without_mutation() {
        let file = path("not-ready");
        let ready = store(&file, Clock(1_000));
        ready.save(&active(10_000)).unwrap();
        let not_ready = other_boot_store(&file, Clock(1_000));
        assert_eq!(
            WitnessExpiryScheduler::default()
                .schedule_once(&not_ready)
                .unwrap(),
            SchedulerStep::Retry
        );
        let unchanged = ready.load().state.unwrap();
        assert_eq!(unchanged.lease_state, LeaseState::Active);
        assert_eq!(unchanged.lease_deadline_monotonic_ms, Some(10_000));
        let _ = std::fs::remove_file(file);

        let file = path("clock-failure");
        let save_store = store(&file, Clock(1_000));
        save_store.save(&active(10_000)).unwrap();
        let failed = failed_clock_store(&file);
        assert_eq!(
            WitnessExpiryScheduler::default()
                .schedule_once(&failed)
                .unwrap(),
            SchedulerStep::Retry
        );
        let unchanged = save_store.load().state.unwrap();
        assert_eq!(unchanged.lease_state, LeaseState::Active);
        assert_eq!(unchanged.current_term, Term(7));
        assert_eq!(unchanged.lease_deadline_monotonic_ms, Some(10_000));
        let _ = std::fs::remove_file(file);
    }

    #[test]
    fn late_wake_expires_current_active_without_extending_or_incrementing_term() {
        let file = path("late-wake");
        let store = store(&file, Clock(12_345));
        store.save(&active(10_000)).unwrap();
        assert_eq!(
            WitnessExpiryScheduler::default()
                .schedule_once(&store)
                .unwrap(),
            SchedulerStep::Expired
        );
        let current = store.load().state.unwrap();
        assert_eq!(current.lease_state, LeaseState::None);
        assert_eq!(current.current_term, Term(7));
        assert_eq!(current.lease_deadline_monotonic_ms, None);
        let _ = std::fs::remove_file(file);
    }

    #[test]
    fn new_scheduler_reobserves_durable_deadline_without_timer_persistence() {
        let file = path("restart-reobserve");
        let first = store(&file, Clock(9_000));
        first.save(&active(10_000)).unwrap();
        let first_scheduler = WitnessExpiryScheduler::default();
        assert!(matches!(
            first_scheduler.schedule_once(&first),
            Ok(SchedulerStep::Wait(_))
        ));

        let restarted = store(&file, Clock(9_500));
        let second_scheduler = WitnessExpiryScheduler::default();
        assert!(matches!(
            second_scheduler.schedule_once(&restarted),
            Ok(SchedulerStep::Wait(duration)) if duration == Duration::from_millis(500)
        ));
        assert_eq!(
            restarted.load().state.unwrap().lease_state,
            LeaseState::Active
        );
        let _ = std::fs::remove_file(file);
    }
}
