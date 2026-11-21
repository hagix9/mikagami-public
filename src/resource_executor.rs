//! Trusted boundary between raw resource backends and the HA controller.
//!
//! This module deliberately contains no operating-system resource operations.
//! Backends report raw results, while `ResourceExecutor` is the only place
//! that creates trusted runtime observations.

#![allow(dead_code)]

pub(crate) mod sealed {
    pub trait NetworkBackend {}
    pub trait ServiceBackend {}
}

#[path = "linux_network.rs"]
mod linux_network;

#[cfg(target_os = "linux")]
#[allow(unused_imports)]
pub(crate) use linux_network::{LinuxNetworkBackend, LinuxNetworkConfig};

#[path = "systemd_service.rs"]
mod systemd_service;

#[path = "command_service.rs"]
mod command_service;

#[cfg(target_os = "linux")]
#[allow(unused_imports)]
pub(crate) use systemd_service::LinuxSystemdServiceBackend;

#[allow(unused_imports)]
pub(crate) use command_service::ExternalServiceBackend;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ActionDiagnostic {
    Success,
    Error(String),
    Timeout,
    Interrupted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RawVipObservation {
    Present,
    Absent,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RawServiceObservation {
    Running,
    Stopped,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RawHealthObservation {
    Healthy,
    Unhealthy,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RawGarpOutcome {
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VipObservationKind {
    Present,
    Absent,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServiceObservationKind {
    Running,
    Stopped,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HealthObservationKind {
    Healthy,
    Unhealthy,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TrustedObservation;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VipObservation {
    kind: VipObservationKind,
    _provenance: TrustedObservation,
}

impl VipObservation {
    fn from_raw(raw: RawVipObservation) -> Self {
        let kind = match raw {
            RawVipObservation::Present => VipObservationKind::Present,
            RawVipObservation::Absent => VipObservationKind::Absent,
            RawVipObservation::Unavailable => VipObservationKind::Unknown,
        };
        Self {
            kind,
            _provenance: TrustedObservation,
        }
    }

    pub(crate) const fn is_present(self) -> bool {
        matches!(self.kind, VipObservationKind::Present)
    }

    pub(crate) const fn is_absent(self) -> bool {
        matches!(self.kind, VipObservationKind::Absent)
    }

    pub(crate) const fn is_unknown(self) -> bool {
        matches!(self.kind, VipObservationKind::Unknown)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ServiceObservation {
    kind: ServiceObservationKind,
    _provenance: TrustedObservation,
}

impl ServiceObservation {
    fn from_raw(raw: RawServiceObservation) -> Self {
        let kind = match raw {
            RawServiceObservation::Running => ServiceObservationKind::Running,
            RawServiceObservation::Stopped => ServiceObservationKind::Stopped,
            RawServiceObservation::Unavailable => ServiceObservationKind::Unknown,
        };
        Self {
            kind,
            _provenance: TrustedObservation,
        }
    }

    pub(crate) const fn is_running(self) -> bool {
        matches!(self.kind, ServiceObservationKind::Running)
    }

    pub(crate) const fn is_stopped(self) -> bool {
        matches!(self.kind, ServiceObservationKind::Stopped)
    }

    pub(crate) const fn is_unknown(self) -> bool {
        matches!(self.kind, ServiceObservationKind::Unknown)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HealthObservation {
    kind: HealthObservationKind,
    _provenance: TrustedObservation,
}

impl HealthObservation {
    fn from_raw(raw: RawHealthObservation) -> Self {
        let kind = match raw {
            RawHealthObservation::Healthy => HealthObservationKind::Healthy,
            RawHealthObservation::Unhealthy => HealthObservationKind::Unhealthy,
            RawHealthObservation::Unavailable => HealthObservationKind::Unknown,
        };
        Self {
            kind,
            _provenance: TrustedObservation,
        }
    }

    pub(crate) const fn is_healthy(self) -> bool {
        matches!(self.kind, HealthObservationKind::Healthy)
    }

    pub(crate) const fn is_unhealthy(self) -> bool {
        matches!(self.kind, HealthObservationKind::Unhealthy)
    }

    pub(crate) const fn is_unknown(self) -> bool {
        matches!(self.kind, HealthObservationKind::Unknown)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GarpOutcome {
    Succeeded,
    Failed,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct GarpResult {
    diagnostic: ActionDiagnostic,
    outcome: GarpOutcome,
}

impl GarpResult {
    pub(crate) const fn outcome(&self) -> GarpOutcome {
        self.outcome
    }

    pub(crate) const fn diagnostic(&self) -> &ActionDiagnostic {
        &self.diagnostic
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct VipTransitionResult {
    diagnostic: ActionDiagnostic,
    observation: VipObservation,
}

impl VipTransitionResult {
    pub(crate) const fn observation(&self) -> VipObservation {
        self.observation
    }

    pub(crate) const fn diagnostic(&self) -> &ActionDiagnostic {
        &self.diagnostic
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ServiceTransitionResult {
    diagnostic: ActionDiagnostic,
    observation: ServiceObservation,
}

impl ServiceTransitionResult {
    pub(crate) const fn observation(&self) -> ServiceObservation {
        self.observation
    }

    pub(crate) const fn diagnostic(&self) -> &ActionDiagnostic {
        &self.diagnostic
    }
}

pub(crate) trait NetworkBackend: sealed::NetworkBackend {
    fn request_vip_acquire(&mut self) -> ActionDiagnostic;
    fn observe_vip(&mut self) -> RawVipObservation;
    fn request_vip_release(&mut self) -> ActionDiagnostic;
    fn send_garp(&mut self) -> (ActionDiagnostic, RawGarpOutcome);
}

pub(crate) trait ServiceBackend: sealed::ServiceBackend {
    fn request_service_start(&mut self) -> ActionDiagnostic;
    fn observe_service(&mut self) -> RawServiceObservation;
    fn request_service_stop(&mut self) -> ActionDiagnostic;
    fn observe_health(&mut self) -> RawHealthObservation;
}

/// The two v1.0 service managers behind the one sealed service boundary
/// (contract K-6, plan WU-6). The workflow above this type is identical for
/// both: it never learns which manager is configured.
pub(crate) enum ServiceAdapter {
    #[cfg(target_os = "linux")]
    Systemd(LinuxSystemdServiceBackend),
    External(ExternalServiceBackend),
}

impl sealed::ServiceBackend for ServiceAdapter {}

impl ServiceBackend for ServiceAdapter {
    fn request_service_start(&mut self) -> ActionDiagnostic {
        match self {
            #[cfg(target_os = "linux")]
            Self::Systemd(backend) => backend.request_service_start(),
            Self::External(backend) => backend.request_service_start(),
        }
    }

    fn observe_service(&mut self) -> RawServiceObservation {
        match self {
            #[cfg(target_os = "linux")]
            Self::Systemd(backend) => backend.observe_service(),
            Self::External(backend) => backend.observe_service(),
        }
    }

    fn request_service_stop(&mut self) -> ActionDiagnostic {
        match self {
            #[cfg(target_os = "linux")]
            Self::Systemd(backend) => backend.request_service_stop(),
            Self::External(backend) => backend.request_service_stop(),
        }
    }

    fn observe_health(&mut self) -> RawHealthObservation {
        match self {
            #[cfg(target_os = "linux")]
            Self::Systemd(backend) => backend.observe_health(),
            Self::External(backend) => backend.observe_health(),
        }
    }
}

pub(crate) struct ResourceExecutor<N, S> {
    network: N,
    service: S,
}

impl<N, S> ResourceExecutor<N, S> {
    pub(crate) const fn new(network: N, service: S) -> Self {
        Self { network, service }
    }
}

impl<N: NetworkBackend, S: ServiceBackend> ResourceExecutor<N, S> {
    pub(crate) fn observe_vip(&mut self) -> VipObservation {
        VipObservation::from_raw(self.network.observe_vip())
    }

    pub(crate) fn observe_service(&mut self) -> ServiceObservation {
        ServiceObservation::from_raw(self.service.observe_service())
    }

    pub(crate) fn observe_health(&mut self) -> HealthObservation {
        HealthObservation::from_raw(self.service.observe_health())
    }

    pub(crate) fn acquire_vip(&mut self) -> VipTransitionResult {
        let diagnostic = self.network.request_vip_acquire();
        let observation = VipObservation::from_raw(self.network.observe_vip());
        VipTransitionResult {
            diagnostic,
            observation,
        }
    }

    pub(crate) fn release_vip(&mut self) -> VipTransitionResult {
        let diagnostic = self.network.request_vip_release();
        let observation = VipObservation::from_raw(self.network.observe_vip());
        VipTransitionResult {
            diagnostic,
            observation,
        }
    }

    pub(crate) fn start_service(&mut self) -> ServiceTransitionResult {
        let diagnostic = self.service.request_service_start();
        let observation = ServiceObservation::from_raw(self.service.observe_service());
        ServiceTransitionResult {
            diagnostic,
            observation,
        }
    }

    pub(crate) fn stop_service(&mut self) -> ServiceTransitionResult {
        let diagnostic = self.service.request_service_stop();
        let observation = ServiceObservation::from_raw(self.service.observe_service());
        ServiceTransitionResult {
            diagnostic,
            observation,
        }
    }

    pub(crate) fn send_garp(&mut self) -> GarpResult {
        let (diagnostic, outcome) = self.network.send_garp();
        GarpResult {
            diagnostic,
            outcome: match outcome {
                RawGarpOutcome::Succeeded => GarpOutcome::Succeeded,
                RawGarpOutcome::Failed => GarpOutcome::Failed,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_lease_authority::{
        AuthorityMode, ClockError, LEASE_TTL_MS, MonotonicClock, MonotonicTime,
        NodeAuthorityController, RENEW_AFTER_MS,
    };
    use crate::node_mutation::{NodeMutationError, NodeMutationStore};
    use crate::protocol::{ClusterId, DurationMs, LeaseGrantPayload, LeaseId, NodeId, Term};
    use crate::resource_workflow::{
        CleanupWorkflowOutcome, PromotionWorkflowOutcome, ResourceWorkflow,
    };
    use crate::state_machine::{NodeState, StateMachine};
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::rc::Rc;

    #[derive(Debug)]
    struct FakeNetwork {
        acquire: ActionDiagnostic,
        release: ActionDiagnostic,
        vip_observation: RawVipObservation,
        garp: (ActionDiagnostic, RawGarpOutcome),
    }

    impl sealed::NetworkBackend for FakeNetwork {}

    impl NetworkBackend for FakeNetwork {
        fn request_vip_acquire(&mut self) -> ActionDiagnostic {
            self.acquire.clone()
        }

        fn observe_vip(&mut self) -> RawVipObservation {
            self.vip_observation
        }

        fn request_vip_release(&mut self) -> ActionDiagnostic {
            self.release.clone()
        }

        fn send_garp(&mut self) -> (ActionDiagnostic, RawGarpOutcome) {
            self.garp.clone()
        }
    }

    #[derive(Debug)]
    struct FakeService {
        start: ActionDiagnostic,
        stop: ActionDiagnostic,
        service_observation: RawServiceObservation,
        health: RawHealthObservation,
    }

    impl sealed::ServiceBackend for FakeService {}

    impl ServiceBackend for FakeService {
        fn request_service_start(&mut self) -> ActionDiagnostic {
            self.start.clone()
        }

        fn observe_service(&mut self) -> RawServiceObservation {
            self.service_observation
        }

        fn request_service_stop(&mut self) -> ActionDiagnostic {
            self.stop.clone()
        }

        fn observe_health(&mut self) -> RawHealthObservation {
            self.health
        }
    }

    #[derive(Debug, Clone)]
    struct WorkflowClock {
        now: Rc<Cell<u64>>,
        advance_after_now: Rc<Cell<Option<(u32, u64)>>>,
    }

    impl WorkflowClock {
        fn at(value: u64) -> Self {
            Self {
                now: Rc::new(Cell::new(value)),
                advance_after_now: Rc::new(Cell::new(None)),
            }
        }

        fn set(&self, value: u64) {
            self.now.set(value);
        }

        fn advance_after_nows(&self, count: u32, value: u64) {
            self.advance_after_now.set(Some((count, value)));
        }
    }

    impl MonotonicClock for WorkflowClock {
        fn now(&self) -> Result<MonotonicTime, ClockError> {
            if let Some((remaining, value)) = self.advance_after_now.get() {
                if remaining == 0 {
                    self.now.set(value);
                    self.advance_after_now.set(None);
                } else {
                    self.advance_after_now
                        .set(Some((remaining.saturating_sub(1), value)));
                }
            }
            Ok(MonotonicTime::from_millis(self.now.get()))
        }
    }

    #[derive(Debug)]
    struct WorkflowNetwork {
        acquire_diagnostics: VecDeque<ActionDiagnostic>,
        acquire_observations: VecDeque<RawVipObservation>,
        release_diagnostics: VecDeque<ActionDiagnostic>,
        release_observations: VecDeque<RawVipObservation>,
        garp_results: VecDeque<(ActionDiagnostic, RawGarpOutcome)>,
        actions: Rc<RefCell<Vec<&'static str>>>,
        clock_on_first_observation: Option<WorkflowClock>,
        clock_after_garp: Option<WorkflowClock>,
        observation_count: usize,
    }

    impl WorkflowNetwork {
        fn new(
            acquire: (ActionDiagnostic, RawVipObservation),
            release: (ActionDiagnostic, RawVipObservation),
            garp: (ActionDiagnostic, RawGarpOutcome),
            actions: Rc<RefCell<Vec<&'static str>>>,
        ) -> Self {
            Self {
                acquire_diagnostics: VecDeque::from([acquire.0]),
                acquire_observations: VecDeque::from([acquire.1]),
                release_diagnostics: VecDeque::from([release.0]),
                release_observations: VecDeque::from([release.1]),
                garp_results: VecDeque::from([garp]),
                actions,
                clock_on_first_observation: None,
                clock_after_garp: None,
                observation_count: 0,
            }
        }

        fn fail_completion_after_vip_observation(&mut self, clock: WorkflowClock) {
            self.clock_on_first_observation = Some(clock);
        }

        fn fail_completion_before_active_commit(&mut self, clock: WorkflowClock) {
            self.clock_after_garp = Some(clock);
        }
    }

    impl sealed::NetworkBackend for WorkflowNetwork {}

    impl NetworkBackend for WorkflowNetwork {
        fn request_vip_acquire(&mut self) -> ActionDiagnostic {
            self.actions.borrow_mut().push("vip_acquire");
            self.acquire_diagnostics
                .pop_front()
                .unwrap_or(ActionDiagnostic::Success)
        }

        fn observe_vip(&mut self) -> RawVipObservation {
            self.observation_count += 1;
            if self.observation_count == 1
                && let Some(clock) = &self.clock_on_first_observation
            {
                clock.set(9_000);
            }
            self.acquire_observations
                .pop_front()
                .or_else(|| self.release_observations.pop_front())
                .unwrap_or(RawVipObservation::Unavailable)
        }

        fn request_vip_release(&mut self) -> ActionDiagnostic {
            self.actions.borrow_mut().push("vip_release");
            self.release_diagnostics
                .pop_front()
                .unwrap_or(ActionDiagnostic::Success)
        }

        fn send_garp(&mut self) -> (ActionDiagnostic, RawGarpOutcome) {
            self.actions.borrow_mut().push("garp");
            if let Some(clock) = &self.clock_after_garp {
                // Let GARP completion observe the old authority, then expire
                // it for the fresh BeforeActiveCommit checkpoint.
                clock.advance_after_nows(1, 9_000);
            }
            self.garp_results
                .pop_front()
                .unwrap_or((ActionDiagnostic::Success, RawGarpOutcome::Succeeded))
        }
    }

    #[derive(Debug)]
    struct WorkflowService {
        start_diagnostics: VecDeque<ActionDiagnostic>,
        stop_diagnostics: VecDeque<ActionDiagnostic>,
        service_observations: VecDeque<RawServiceObservation>,
        health_observations: VecDeque<RawHealthObservation>,
        actions: Rc<RefCell<Vec<&'static str>>>,
        clock_on_first_observation: Option<WorkflowClock>,
        observation_count: usize,
    }

    impl WorkflowService {
        fn new(
            start: (ActionDiagnostic, RawServiceObservation),
            stop: (ActionDiagnostic, RawServiceObservation),
            health: RawHealthObservation,
            actions: Rc<RefCell<Vec<&'static str>>>,
        ) -> Self {
            Self {
                start_diagnostics: VecDeque::from([start.0]),
                stop_diagnostics: VecDeque::from([stop.0]),
                service_observations: VecDeque::from([start.1, stop.1]),
                health_observations: VecDeque::from([health]),
                actions,
                clock_on_first_observation: None,
                observation_count: 0,
            }
        }

        fn fail_completion_after_service_observation(&mut self, clock: WorkflowClock) {
            self.clock_on_first_observation = Some(clock);
        }
    }

    impl sealed::ServiceBackend for WorkflowService {}

    impl ServiceBackend for WorkflowService {
        fn request_service_start(&mut self) -> ActionDiagnostic {
            self.actions.borrow_mut().push("service_start");
            self.start_diagnostics
                .pop_front()
                .unwrap_or(ActionDiagnostic::Success)
        }

        fn observe_service(&mut self) -> RawServiceObservation {
            self.observation_count += 1;
            if self.observation_count == 1
                && let Some(clock) = &self.clock_on_first_observation
            {
                clock.set(9_000);
            }
            self.service_observations
                .pop_front()
                .unwrap_or(RawServiceObservation::Unavailable)
        }

        fn request_service_stop(&mut self) -> ActionDiagnostic {
            self.actions.borrow_mut().push("service_stop");
            self.stop_diagnostics
                .pop_front()
                .unwrap_or(ActionDiagnostic::Success)
        }

        fn observe_health(&mut self) -> RawHealthObservation {
            self.actions.borrow_mut().push("health");
            self.health_observations
                .pop_front()
                .unwrap_or(RawHealthObservation::Unavailable)
        }
    }

    /// The state files of the workflow tests share one directory (the temp
    /// directory) with every other test, thread and process. A name made only
    /// from the clock collides when two tests start within one clock tick
    /// (macOS reads the clock in microseconds): `initialize_new` then fails
    /// with `AlreadyExists`. A name is `pid`, a per-process sequence number
    /// that is never repeated, and the clock: the sequence keeps threads of one
    /// process apart whatever the clock says, the pid keeps live processes
    /// apart (the clock only separates a later process that reuses a pid). An
    /// existing path is never reused and never removed: `initialize_new`
    /// refuses it and the next name is tried, a bounded number of times.
    static WORKFLOW_STATE_SEQUENCE: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(0);
    const WORKFLOW_STATE_ATTEMPTS: u32 = 16;

    /// The next sequence number; a counter that would wrap is a test failure,
    /// never a repeated number.
    fn next_workflow_sequence(counter: &std::sync::atomic::AtomicU64) -> u64 {
        use std::sync::atomic::Ordering;
        counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .expect("the workflow state-name counter is exhausted")
    }

    fn workflow_state_name(pid: u32, sequence: u64, nanos: u128) -> String {
        format!("mikagami-stage11-5-{pid}-{sequence}-{nanos}")
    }

    /// A fresh state path for the clock value `nanos` (a parameter so a test can
    /// make every caller read the same clock value).
    fn workflow_state_path(nanos: u128) -> std::path::PathBuf {
        std::env::temp_dir().join(workflow_state_name(
            std::process::id(),
            next_workflow_sequence(&WORKFLOW_STATE_SEQUENCE),
            nanos,
        ))
    }

    fn workflow_clock_nanos() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }

    fn workflow_controller(
        clock: WorkflowClock,
        mode: AuthorityMode,
        install_authority: bool,
    ) -> (NodeAuthorityController<WorkflowClock>, std::path::PathBuf) {
        workflow_controller_at(
            || workflow_state_path(workflow_clock_nanos()),
            clock,
            mode,
            install_authority,
        )
    }

    fn workflow_controller_at(
        mut next_path: impl FnMut() -> std::path::PathBuf,
        clock: WorkflowClock,
        mode: AuthorityMode,
        install_authority: bool,
    ) -> (NodeAuthorityController<WorkflowClock>, std::path::PathBuf) {
        let mut attempts = 0;
        let (store, path) = loop {
            attempts += 1;
            assert!(
                attempts <= WORKFLOW_STATE_ATTEMPTS,
                "no unused workflow state path after {WORKFLOW_STATE_ATTEMPTS} attempts"
            );
            let path = next_path();
            let store =
                NodeMutationStore::new(&path, ClusterId::new("cluster"), NodeId::new("node-a"));
            match store.initialize_new() {
                Ok(_) => break (store, path),
                // Somebody else's path: leave it alone and take another name.
                Err(NodeMutationError::AlreadyExists) => {}
                Err(other) => panic!("cannot initialize {}: {other:?}", path.display()),
            }
        };
        let mut controller = NodeAuthorityController::new_for_resource_workflow_test(
            clock,
            NodeId::new("node-a"),
            store,
            mode,
        );
        if install_authority {
            controller
                .install_test_grant_for_resource_workflow(
                    &LeaseGrantPayload {
                        term: Term(7),
                        lease_id: LeaseId::new("lease-1"),
                        holder_node_id: NodeId::new("node-a"),
                        lease_ttl_ms: DurationMs(LEASE_TTL_MS),
                        renew_after_ms: DurationMs(RENEW_AFTER_MS),
                        lease_remaining_ms: DurationMs(LEASE_TTL_MS),
                    },
                    MonotonicTime::from_millis(0),
                )
                .unwrap();
        }
        (controller, path)
    }

    fn workflow_executor(
        network: WorkflowNetwork,
        service: WorkflowService,
    ) -> ResourceExecutor<WorkflowNetwork, WorkflowService> {
        ResourceExecutor::new(network, service)
    }

    /// C-3 exhaustive sweep: the lease passes its safe deadline after exactly `n`
    /// reads of B's monotonic clock inside `ResourceWorkflow::promote`, for every
    /// `n`. Invariants asserted for every `n`:
    ///  (I1) `ReadyForActiveCommit` only if the expiry never happened;
    ///  (I2) if the expiry happened and any resource action was already taken,
    ///       the controller has latched cleanup (`demotion_required`);
    ///  (I3) once expired, NO further protected action is taken after the
    ///       checkpoint that observed it (no action follows a failed checkpoint).
    /// The table is printed (run with --nocapture) as evidence.
    #[test]
    fn ba_c3_lease_expiry_sweep_over_every_clock_read_in_promote() {
        let mut rows = Vec::new();
        for n in 0u32..16 {
            let clock = WorkflowClock::at(0);
            let (mut controller, path) =
                workflow_controller(clock.clone(), AuthorityMode::Conservative, true);
            let actions = Rc::new(RefCell::new(Vec::new()));
            let network = WorkflowNetwork::new(
                (ActionDiagnostic::Success, RawVipObservation::Present),
                (ActionDiagnostic::Success, RawVipObservation::Absent),
                (ActionDiagnostic::Success, RawGarpOutcome::Succeeded),
                actions.clone(),
            );
            let service = WorkflowService::new(
                (ActionDiagnostic::Success, RawServiceObservation::Running),
                (ActionDiagnostic::Success, RawServiceObservation::Stopped),
                RawHealthObservation::Healthy,
                actions.clone(),
            );
            let mut executor = workflow_executor(network, service);
            // safe deadline is 8_000 (10_000 - 2_000 margin); jump to 9_000.
            clock.advance_after_nows(n, 9_000);
            let outcome = ResourceWorkflow::new(&mut controller, &mut executor).promote();
            let taken = actions.borrow().clone();
            let expired = clock.now.get() >= 8_000;
            if outcome == PromotionWorkflowOutcome::ReadyForActiveCommit {
                assert!(!expired, "I1 violated at n={n}");
            }
            if expired && !taken.is_empty() {
                assert!(controller.demotion_required(), "I2 violated at n={n}");
            }
            rows.push((n, expired, outcome, taken, controller.demotion_required()));
            let _ = std::fs::remove_file(path);
        }
        eprintln!("n | expired | outcome | protected actions taken | demotion_required");
        for (n, expired, outcome, taken, demotion) in &rows {
            eprintln!("{n} | {expired} | {outcome:?} | {taken:?} | {demotion}");
        }
        // The expiry-free rows must complete normally (positive control).
        assert!(
            rows.iter()
                .any(|row| !row.1 && row.2 == PromotionWorkflowOutcome::ReadyForActiveCommit)
        );
        // I3 (precise): a protected action is taken only if the checkpoint read
        // that precedes it happened BEFORE the expiry. Read indices inside
        // `promote`: 0 = checkpoint(vip) [action vip_acquire], 1 = complete(vip),
        // 2 = checkpoint(service) [service_start], 3 = complete(service),
        // 4 = checkpoint(health) [health], 5 = complete(health),
        // 6 = checkpoint(garp) [garp], 7 = complete(garp), 8/9 = active commit.
        for (n, _expired, _outcome, taken, _demotion) in &rows {
            for action in taken {
                let preceding_read = match *action {
                    "vip_acquire" => 0u32,
                    "service_start" => 2,
                    "health" => 4,
                    "garp" => 6,
                    other => panic!("unexpected action {other}"),
                };
                assert!(
                    preceding_read < *n,
                    "I3 violated at n={n}: `{action}` ran after a checkpoint that saw the expiry"
                );
            }
        }
    }

    /// Finding F-MODE: in `AuthorityMode::Availability` the lease gates are not
    /// applied at all (`ensure_usable_for_step` returns Ok when `!conservative`),
    /// so an expired grant crosses every protected checkpoint. The production
    /// attempt path does not refuse `cluster.mode = availability` when a Witness
    /// is configured. Bootstrap Admission MUST therefore be admitted only in
    /// conservative mode (a guard the BA wiring has to add).
    #[test]
    fn ba_f_mode_availability_mode_applies_no_lease_gate() {
        let clock = WorkflowClock::at(0);
        let (mut controller, path) =
            workflow_controller(clock.clone(), AuthorityMode::Availability, true);
        clock.set(9_000); // long past the 8_000 safe deadline
        let actions = Rc::new(RefCell::new(Vec::new()));
        let network = WorkflowNetwork::new(
            (ActionDiagnostic::Success, RawVipObservation::Present),
            (ActionDiagnostic::Success, RawVipObservation::Absent),
            (ActionDiagnostic::Success, RawGarpOutcome::Succeeded),
            actions.clone(),
        );
        let service = WorkflowService::new(
            (ActionDiagnostic::Success, RawServiceObservation::Running),
            (ActionDiagnostic::Success, RawServiceObservation::Stopped),
            RawHealthObservation::Healthy,
            actions.clone(),
        );
        let mut executor = workflow_executor(network, service);
        assert_eq!(
            ResourceWorkflow::new(&mut controller, &mut executor).promote(),
            PromotionWorkflowOutcome::ReadyForActiveCommit
        );
        assert_eq!(actions.borrow().len(), 4);
        let _ = std::fs::remove_file(path);
    }

    fn executor(
        acquire: ActionDiagnostic,
        release: ActionDiagnostic,
        vip: RawVipObservation,
        start: ActionDiagnostic,
        stop: ActionDiagnostic,
        service: RawServiceObservation,
        health: RawHealthObservation,
    ) -> ResourceExecutor<FakeNetwork, FakeService> {
        ResourceExecutor::new(
            FakeNetwork {
                acquire,
                release,
                vip_observation: vip,
                garp: (ActionDiagnostic::Success, RawGarpOutcome::Succeeded),
            },
            FakeService {
                start,
                stop,
                service_observation: service,
                health,
            },
        )
    }

    fn assert_vip(result: &VipTransitionResult, diagnostic: &ActionDiagnostic, present: bool) {
        assert_eq!(result.diagnostic(), diagnostic);
        assert_eq!(result.observation().is_present(), present);
    }

    fn assert_service(
        result: &ServiceTransitionResult,
        diagnostic: &ActionDiagnostic,
        running: bool,
        stopped: bool,
    ) {
        assert_eq!(result.diagnostic(), diagnostic);
        assert_eq!(result.observation().is_running(), running);
        assert_eq!(result.observation().is_stopped(), stopped);
    }

    #[test]
    fn vip_acquire_preserves_timeout_and_present() {
        let mut first_executor = executor(
            ActionDiagnostic::Timeout,
            ActionDiagnostic::Success,
            RawVipObservation::Present,
            ActionDiagnostic::Success,
            ActionDiagnostic::Success,
            RawServiceObservation::Stopped,
            RawHealthObservation::Unhealthy,
        );
        assert_vip(
            &first_executor.acquire_vip(),
            &ActionDiagnostic::Timeout,
            true,
        );
    }

    #[test]
    fn vip_acquire_preserves_error_and_present() {
        let mut executor = executor(
            ActionDiagnostic::Error("acquire failed".into()),
            ActionDiagnostic::Success,
            RawVipObservation::Present,
            ActionDiagnostic::Success,
            ActionDiagnostic::Success,
            RawServiceObservation::Stopped,
            RawHealthObservation::Unhealthy,
        );
        assert_vip(
            &executor.acquire_vip(),
            &ActionDiagnostic::Error("acquire failed".into()),
            true,
        );
    }

    #[test]
    fn vip_acquire_success_does_not_fabricate_present() {
        let mut executor = executor(
            ActionDiagnostic::Success,
            ActionDiagnostic::Success,
            RawVipObservation::Absent,
            ActionDiagnostic::Success,
            ActionDiagnostic::Success,
            RawServiceObservation::Stopped,
            RawHealthObservation::Unhealthy,
        );
        let result = executor.acquire_vip();
        assert_eq!(result.diagnostic(), &ActionDiagnostic::Success);
        assert!(result.observation().is_absent());
        assert!(!result.observation().is_present());
    }

    #[test]
    fn vip_acquire_success_with_unavailable_observation_is_unknown() {
        let mut executor = executor(
            ActionDiagnostic::Success,
            ActionDiagnostic::Success,
            RawVipObservation::Unavailable,
            ActionDiagnostic::Success,
            ActionDiagnostic::Success,
            RawServiceObservation::Stopped,
            RawHealthObservation::Unhealthy,
        );
        assert!(executor.acquire_vip().observation().is_unknown());
    }

    #[test]
    fn service_start_preserves_error_and_running() {
        let mut executor = executor(
            ActionDiagnostic::Success,
            ActionDiagnostic::Success,
            RawVipObservation::Absent,
            ActionDiagnostic::Error("start failed".into()),
            ActionDiagnostic::Success,
            RawServiceObservation::Running,
            RawHealthObservation::Unhealthy,
        );
        assert_service(
            &executor.start_service(),
            &ActionDiagnostic::Error("start failed".into()),
            true,
            false,
        );
    }

    #[test]
    fn service_start_success_does_not_fabricate_running() {
        let mut executor = executor(
            ActionDiagnostic::Success,
            ActionDiagnostic::Success,
            RawVipObservation::Absent,
            ActionDiagnostic::Success,
            ActionDiagnostic::Success,
            RawServiceObservation::Stopped,
            RawHealthObservation::Unhealthy,
        );
        assert!(executor.start_service().observation().is_stopped());
    }

    #[test]
    fn service_stop_preserves_success_and_running() {
        let mut executor = executor(
            ActionDiagnostic::Success,
            ActionDiagnostic::Success,
            RawVipObservation::Absent,
            ActionDiagnostic::Success,
            ActionDiagnostic::Success,
            RawServiceObservation::Running,
            RawHealthObservation::Unhealthy,
        );
        assert_service(
            &executor.stop_service(),
            &ActionDiagnostic::Success,
            true,
            false,
        );
    }

    #[test]
    fn service_stop_preserves_error_and_stopped() {
        let mut executor = executor(
            ActionDiagnostic::Success,
            ActionDiagnostic::Success,
            RawVipObservation::Absent,
            ActionDiagnostic::Success,
            ActionDiagnostic::Error("stop failed".into()),
            RawServiceObservation::Stopped,
            RawHealthObservation::Unhealthy,
        );
        assert_service(
            &executor.stop_service(),
            &ActionDiagnostic::Error("stop failed".into()),
            false,
            true,
        );
    }

    #[test]
    fn service_stop_preserves_timeout_and_stopped() {
        let mut executor = executor(
            ActionDiagnostic::Success,
            ActionDiagnostic::Success,
            RawVipObservation::Absent,
            ActionDiagnostic::Success,
            ActionDiagnostic::Timeout,
            RawServiceObservation::Stopped,
            RawHealthObservation::Unhealthy,
        );
        assert_service(
            &executor.stop_service(),
            &ActionDiagnostic::Timeout,
            false,
            true,
        );
    }

    #[test]
    fn service_stop_success_with_unavailable_observation_is_unknown() {
        let mut executor = executor(
            ActionDiagnostic::Success,
            ActionDiagnostic::Success,
            RawVipObservation::Absent,
            ActionDiagnostic::Success,
            ActionDiagnostic::Success,
            RawServiceObservation::Unavailable,
            RawHealthObservation::Unhealthy,
        );
        assert!(executor.stop_service().observation().is_unknown());
    }

    #[test]
    fn vip_release_preserves_success_and_present() {
        let mut executor = executor(
            ActionDiagnostic::Success,
            ActionDiagnostic::Success,
            RawVipObservation::Present,
            ActionDiagnostic::Success,
            ActionDiagnostic::Success,
            RawServiceObservation::Stopped,
            RawHealthObservation::Unhealthy,
        );
        assert_vip(&executor.release_vip(), &ActionDiagnostic::Success, true);
    }

    #[test]
    fn vip_release_preserves_error_and_absent() {
        let mut executor = executor(
            ActionDiagnostic::Success,
            ActionDiagnostic::Error("release failed".into()),
            RawVipObservation::Absent,
            ActionDiagnostic::Success,
            ActionDiagnostic::Success,
            RawServiceObservation::Stopped,
            RawHealthObservation::Unhealthy,
        );
        let result = executor.release_vip();
        assert_eq!(
            result.diagnostic(),
            &ActionDiagnostic::Error("release failed".into())
        );
        assert!(result.observation().is_absent());
    }

    #[test]
    fn vip_release_preserves_timeout_and_absent() {
        let mut executor = executor(
            ActionDiagnostic::Success,
            ActionDiagnostic::Timeout,
            RawVipObservation::Absent,
            ActionDiagnostic::Success,
            ActionDiagnostic::Success,
            RawServiceObservation::Stopped,
            RawHealthObservation::Unhealthy,
        );
        let result = executor.release_vip();
        assert_eq!(result.diagnostic(), &ActionDiagnostic::Timeout);
        assert!(result.observation().is_absent());
        assert!(!result.observation().is_unknown());
    }

    #[test]
    fn vip_release_success_with_unavailable_observation_is_unknown() {
        let mut executor = executor(
            ActionDiagnostic::Success,
            ActionDiagnostic::Success,
            RawVipObservation::Unavailable,
            ActionDiagnostic::Success,
            ActionDiagnostic::Success,
            RawServiceObservation::Stopped,
            RawHealthObservation::Unhealthy,
        );
        assert!(executor.release_vip().observation().is_unknown());
    }

    #[test]
    fn health_unhealthy_does_not_create_stopped_service() {
        let mut executor = executor(
            ActionDiagnostic::Success,
            ActionDiagnostic::Success,
            RawVipObservation::Present,
            ActionDiagnostic::Success,
            ActionDiagnostic::Success,
            RawServiceObservation::Running,
            RawHealthObservation::Unhealthy,
        );
        assert!(executor.observe_health().is_unhealthy());
        assert!(executor.stop_service().observation().is_running());
    }

    #[test]
    fn garp_failure_does_not_create_absent_vip() {
        let mut executor = ResourceExecutor::new(
            FakeNetwork {
                acquire: ActionDiagnostic::Success,
                release: ActionDiagnostic::Success,
                vip_observation: RawVipObservation::Present,
                garp: (ActionDiagnostic::Timeout, RawGarpOutcome::Failed),
            },
            FakeService {
                start: ActionDiagnostic::Success,
                stop: ActionDiagnostic::Success,
                service_observation: RawServiceObservation::Running,
                health: RawHealthObservation::Unhealthy,
            },
        );
        let result = executor.send_garp();
        assert_eq!(result.diagnostic(), &ActionDiagnostic::Timeout);
        assert_eq!(result.outcome(), GarpOutcome::Failed);
        assert!(executor.acquire_vip().observation().is_present());
    }

    #[test]
    fn executor_api_has_no_node_state_or_controller_mutation_capability() {
        let machine = StateMachine::new();
        assert_eq!(machine.node_state(), NodeState::Init);
        let mut first_executor = executor(
            ActionDiagnostic::Success,
            ActionDiagnostic::Success,
            RawVipObservation::Present,
            ActionDiagnostic::Success,
            ActionDiagnostic::Success,
            RawServiceObservation::Running,
            RawHealthObservation::Healthy,
        );
        let _ = first_executor.acquire_vip();
        let _ = first_executor.start_service();
        assert_eq!(machine.node_state(), NodeState::Init);
    }

    #[test]
    fn cleanup_primitives_have_no_authority_parameter() {
        let mut executor = executor(
            ActionDiagnostic::Success,
            ActionDiagnostic::Success,
            RawVipObservation::Absent,
            ActionDiagnostic::Success,
            ActionDiagnostic::Success,
            RawServiceObservation::Stopped,
            RawHealthObservation::Unhealthy,
        );
        assert!(executor.stop_service().observation().is_stopped());
        assert!(executor.release_vip().observation().is_absent());
    }

    #[test]
    fn new_executor_does_not_receive_prior_runtime_observations() {
        let mut first_executor = executor(
            ActionDiagnostic::Success,
            ActionDiagnostic::Success,
            RawVipObservation::Present,
            ActionDiagnostic::Success,
            ActionDiagnostic::Success,
            RawServiceObservation::Running,
            RawHealthObservation::Healthy,
        );
        let result = first_executor.acquire_vip();
        assert!(result.observation().is_present());
        drop(result);
        let mut restarted = executor(
            ActionDiagnostic::Success,
            ActionDiagnostic::Success,
            RawVipObservation::Unavailable,
            ActionDiagnostic::Success,
            ActionDiagnostic::Success,
            RawServiceObservation::Unavailable,
            RawHealthObservation::Unavailable,
        );
        assert!(restarted.acquire_vip().observation().is_unknown());
    }

    #[test]
    fn trusted_observation_is_only_obtained_through_executor_conversion() {
        let mut executor = executor(
            ActionDiagnostic::Success,
            ActionDiagnostic::Success,
            RawVipObservation::Present,
            ActionDiagnostic::Success,
            ActionDiagnostic::Success,
            RawServiceObservation::Running,
            RawHealthObservation::Healthy,
        );
        let observation = executor.acquire_vip().observation();
        assert!(observation.is_present());
        assert!(!observation.is_unknown());
    }

    #[test]
    fn workflow_happy_promotion_requires_each_authority_checkpoint() {
        let clock = WorkflowClock::at(0);
        let (mut controller, path) =
            workflow_controller(clock.clone(), AuthorityMode::Conservative, true);
        let actions = Rc::new(RefCell::new(Vec::new()));
        let network = WorkflowNetwork::new(
            (ActionDiagnostic::Success, RawVipObservation::Present),
            (ActionDiagnostic::Success, RawVipObservation::Absent),
            (ActionDiagnostic::Success, RawGarpOutcome::Succeeded),
            actions.clone(),
        );
        let service = WorkflowService::new(
            (ActionDiagnostic::Success, RawServiceObservation::Running),
            (ActionDiagnostic::Success, RawServiceObservation::Stopped),
            RawHealthObservation::Healthy,
            actions.clone(),
        );
        let mut executor = workflow_executor(network, service);
        let outcome = ResourceWorkflow::new(&mut controller, &mut executor).promote();
        assert_eq!(outcome, PromotionWorkflowOutcome::ReadyForActiveCommit);
        assert_eq!(
            actions.borrow().as_slice(),
            &["vip_acquire", "service_start", "health", "garp"]
        );
        assert!(!controller.demotion_required());
        assert!(controller.resource_owning());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn workflow_blocks_before_vip_without_authority_or_vip_action() {
        let (mut controller, path) =
            workflow_controller(WorkflowClock::at(0), AuthorityMode::Conservative, false);
        let actions = Rc::new(RefCell::new(Vec::new()));
        let mut executor = workflow_executor(
            WorkflowNetwork::new(
                (ActionDiagnostic::Success, RawVipObservation::Present),
                (ActionDiagnostic::Success, RawVipObservation::Absent),
                (ActionDiagnostic::Success, RawGarpOutcome::Succeeded),
                actions.clone(),
            ),
            WorkflowService::new(
                (ActionDiagnostic::Success, RawServiceObservation::Running),
                (ActionDiagnostic::Success, RawServiceObservation::Stopped),
                RawHealthObservation::Healthy,
                actions.clone(),
            ),
        );
        assert_eq!(
            ResourceWorkflow::new(&mut controller, &mut executor).promote(),
            PromotionWorkflowOutcome::PromotionBlocked
        );
        assert!(actions.borrow().is_empty());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn workflow_completion_loss_after_vip_preserves_cleanup_obligation() {
        let clock = WorkflowClock::at(0);
        let (mut controller, path) =
            workflow_controller(clock.clone(), AuthorityMode::Conservative, true);
        let actions = Rc::new(RefCell::new(Vec::new()));
        let mut network = WorkflowNetwork::new(
            (ActionDiagnostic::Success, RawVipObservation::Present),
            (ActionDiagnostic::Success, RawVipObservation::Absent),
            (ActionDiagnostic::Success, RawGarpOutcome::Succeeded),
            actions.clone(),
        );
        network.fail_completion_after_vip_observation(clock);
        let service = WorkflowService::new(
            (ActionDiagnostic::Success, RawServiceObservation::Running),
            (ActionDiagnostic::Success, RawServiceObservation::Stopped),
            RawHealthObservation::Healthy,
            actions.clone(),
        );
        let mut executor = workflow_executor(network, service);
        assert_eq!(
            ResourceWorkflow::new(&mut controller, &mut executor).promote(),
            PromotionWorkflowOutcome::CleanupRequired
        );
        assert_eq!(actions.borrow().as_slice(), &["vip_acquire"]);
        assert!(controller.demotion_required());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn workflow_service_error_with_running_observation_cannot_continue() {
        let (mut controller, path) =
            workflow_controller(WorkflowClock::at(0), AuthorityMode::Conservative, true);
        let actions = Rc::new(RefCell::new(Vec::new()));
        let mut executor = workflow_executor(
            WorkflowNetwork::new(
                (ActionDiagnostic::Success, RawVipObservation::Present),
                (ActionDiagnostic::Success, RawVipObservation::Absent),
                (ActionDiagnostic::Success, RawGarpOutcome::Succeeded),
                actions.clone(),
            ),
            WorkflowService::new(
                (
                    ActionDiagnostic::Error("start failed".into()),
                    RawServiceObservation::Running,
                ),
                (ActionDiagnostic::Success, RawServiceObservation::Stopped),
                RawHealthObservation::Healthy,
                actions.clone(),
            ),
        );
        assert_eq!(
            ResourceWorkflow::new(&mut controller, &mut executor).promote(),
            PromotionWorkflowOutcome::CleanupRequired
        );
        assert_eq!(
            actions.borrow().as_slice(),
            &["vip_acquire", "service_start"]
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn workflow_completion_loss_after_service_keeps_cleanup_obligation() {
        let clock = WorkflowClock::at(0);
        let (mut controller, path) =
            workflow_controller(clock.clone(), AuthorityMode::Conservative, true);
        let actions = Rc::new(RefCell::new(Vec::new()));
        let network = WorkflowNetwork::new(
            (ActionDiagnostic::Success, RawVipObservation::Present),
            (ActionDiagnostic::Success, RawVipObservation::Absent),
            (ActionDiagnostic::Success, RawGarpOutcome::Succeeded),
            actions.clone(),
        );
        let mut service = WorkflowService::new(
            (ActionDiagnostic::Success, RawServiceObservation::Running),
            (ActionDiagnostic::Success, RawServiceObservation::Stopped),
            RawHealthObservation::Healthy,
            actions.clone(),
        );
        service.fail_completion_after_service_observation(clock);
        let mut executor = workflow_executor(network, service);
        assert_eq!(
            ResourceWorkflow::new(&mut controller, &mut executor).promote(),
            PromotionWorkflowOutcome::CleanupRequired
        );
        assert_eq!(
            actions.borrow().as_slice(),
            &["vip_acquire", "service_start"]
        );
        assert!(controller.demotion_required());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn workflow_unknown_vip_or_service_never_reports_ready() {
        for (vip, service) in [
            (
                RawVipObservation::Unavailable,
                RawServiceObservation::Running,
            ),
            (
                RawVipObservation::Present,
                RawServiceObservation::Unavailable,
            ),
        ] {
            let (mut controller, path) =
                workflow_controller(WorkflowClock::at(0), AuthorityMode::Conservative, true);
            let actions = Rc::new(RefCell::new(Vec::new()));
            let mut executor = workflow_executor(
                WorkflowNetwork::new(
                    (ActionDiagnostic::Success, vip),
                    (ActionDiagnostic::Success, RawVipObservation::Absent),
                    (ActionDiagnostic::Success, RawGarpOutcome::Succeeded),
                    actions.clone(),
                ),
                WorkflowService::new(
                    (ActionDiagnostic::Success, service),
                    (ActionDiagnostic::Success, RawServiceObservation::Stopped),
                    RawHealthObservation::Healthy,
                    actions.clone(),
                ),
            );
            assert_ne!(
                ResourceWorkflow::new(&mut controller, &mut executor).promote(),
                PromotionWorkflowOutcome::ReadyForActiveCommit
            );
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn workflow_timeout_vip_present_follows_resource_truth_not_diagnostic() {
        let (mut controller, path) =
            workflow_controller(WorkflowClock::at(0), AuthorityMode::Conservative, true);
        let actions = Rc::new(RefCell::new(Vec::new()));
        let mut executor = workflow_executor(
            WorkflowNetwork::new(
                (ActionDiagnostic::Timeout, RawVipObservation::Present),
                (ActionDiagnostic::Success, RawVipObservation::Absent),
                (ActionDiagnostic::Success, RawGarpOutcome::Succeeded),
                actions.clone(),
            ),
            WorkflowService::new(
                (ActionDiagnostic::Success, RawServiceObservation::Running),
                (ActionDiagnostic::Success, RawServiceObservation::Stopped),
                RawHealthObservation::Healthy,
                actions.clone(),
            ),
        );
        assert_eq!(
            ResourceWorkflow::new(&mut controller, &mut executor).promote(),
            PromotionWorkflowOutcome::ReadyForActiveCommit
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn workflow_error_vip_present_follows_resource_truth_not_diagnostic() {
        let (mut controller, path) =
            workflow_controller(WorkflowClock::at(0), AuthorityMode::Conservative, true);
        let actions = Rc::new(RefCell::new(Vec::new()));
        let mut executor = workflow_executor(
            WorkflowNetwork::new(
                (
                    ActionDiagnostic::Error("acquire uncertain".into()),
                    RawVipObservation::Present,
                ),
                (ActionDiagnostic::Success, RawVipObservation::Absent),
                (ActionDiagnostic::Success, RawGarpOutcome::Succeeded),
                actions.clone(),
            ),
            WorkflowService::new(
                (ActionDiagnostic::Success, RawServiceObservation::Running),
                (ActionDiagnostic::Success, RawServiceObservation::Stopped),
                RawHealthObservation::Healthy,
                actions,
            ),
        );
        assert_eq!(
            ResourceWorkflow::new(&mut controller, &mut executor).promote(),
            PromotionWorkflowOutcome::ReadyForActiveCommit
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn workflow_interrupted_vip_present_requires_cleanup() {
        let (mut controller, path) =
            workflow_controller(WorkflowClock::at(0), AuthorityMode::Conservative, true);
        let actions = Rc::new(RefCell::new(Vec::new()));
        let mut executor = workflow_executor(
            WorkflowNetwork::new(
                (ActionDiagnostic::Interrupted, RawVipObservation::Present),
                (ActionDiagnostic::Success, RawVipObservation::Absent),
                (ActionDiagnostic::Success, RawGarpOutcome::Succeeded),
                actions.clone(),
            ),
            WorkflowService::new(
                (ActionDiagnostic::Success, RawServiceObservation::Running),
                (ActionDiagnostic::Success, RawServiceObservation::Stopped),
                RawHealthObservation::Healthy,
                actions,
            ),
        );
        assert_eq!(
            ResourceWorkflow::new(&mut controller, &mut executor).promote(),
            PromotionWorkflowOutcome::CleanupRequired
        );
        assert!(controller.ownership_is_unknown_for_test());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn workflow_service_timeout_and_interrupted_running_require_cleanup() {
        for diagnostic in [ActionDiagnostic::Timeout, ActionDiagnostic::Interrupted] {
            let (mut controller, path) =
                workflow_controller(WorkflowClock::at(0), AuthorityMode::Conservative, true);
            let actions = Rc::new(RefCell::new(Vec::new()));
            let mut executor = workflow_executor(
                WorkflowNetwork::new(
                    (ActionDiagnostic::Success, RawVipObservation::Present),
                    (ActionDiagnostic::Success, RawVipObservation::Absent),
                    (ActionDiagnostic::Success, RawGarpOutcome::Succeeded),
                    actions.clone(),
                ),
                WorkflowService::new(
                    (diagnostic, RawServiceObservation::Running),
                    (ActionDiagnostic::Success, RawServiceObservation::Stopped),
                    RawHealthObservation::Healthy,
                    actions,
                ),
            );
            assert_eq!(
                ResourceWorkflow::new(&mut controller, &mut executor).promote(),
                PromotionWorkflowOutcome::CleanupRequired
            );
            assert!(controller.ownership_is_unknown_for_test());
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn workflow_unknown_health_requires_cleanup() {
        let (mut controller, path) =
            workflow_controller(WorkflowClock::at(0), AuthorityMode::Conservative, true);
        let actions = Rc::new(RefCell::new(Vec::new()));
        let mut executor = workflow_executor(
            WorkflowNetwork::new(
                (ActionDiagnostic::Success, RawVipObservation::Present),
                (ActionDiagnostic::Success, RawVipObservation::Absent),
                (ActionDiagnostic::Success, RawGarpOutcome::Succeeded),
                actions.clone(),
            ),
            WorkflowService::new(
                (ActionDiagnostic::Success, RawServiceObservation::Running),
                (ActionDiagnostic::Success, RawServiceObservation::Stopped),
                RawHealthObservation::Unavailable,
                actions,
            ),
        );
        assert_eq!(
            ResourceWorkflow::new(&mut controller, &mut executor).promote(),
            PromotionWorkflowOutcome::CleanupRequired
        );
        assert!(controller.resource_owning());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn workflow_garp_completion_failure_requires_cleanup() {
        let clock = WorkflowClock::at(0);
        let (mut controller, path) =
            workflow_controller(clock.clone(), AuthorityMode::Conservative, true);
        let actions = Rc::new(RefCell::new(Vec::new()));
        let mut network = WorkflowNetwork::new(
            (ActionDiagnostic::Success, RawVipObservation::Present),
            (ActionDiagnostic::Success, RawVipObservation::Absent),
            (ActionDiagnostic::Success, RawGarpOutcome::Succeeded),
            actions.clone(),
        );
        network.fail_completion_before_active_commit(clock);
        let service = WorkflowService::new(
            (ActionDiagnostic::Success, RawServiceObservation::Running),
            (ActionDiagnostic::Success, RawServiceObservation::Stopped),
            RawHealthObservation::Healthy,
            actions,
        );
        let mut executor = workflow_executor(network, service);
        assert_eq!(
            ResourceWorkflow::new(&mut controller, &mut executor).promote(),
            PromotionWorkflowOutcome::CleanupRequired
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn workflow_before_active_commit_failure_requires_cleanup() {
        let clock = WorkflowClock::at(0);
        let (mut controller, path) =
            workflow_controller(clock.clone(), AuthorityMode::Conservative, true);
        let actions = Rc::new(RefCell::new(Vec::new()));
        let mut network = WorkflowNetwork::new(
            (ActionDiagnostic::Success, RawVipObservation::Present),
            (ActionDiagnostic::Success, RawVipObservation::Absent),
            (ActionDiagnostic::Success, RawGarpOutcome::Succeeded),
            actions.clone(),
        );
        network.fail_completion_before_active_commit(clock);
        let service = WorkflowService::new(
            (ActionDiagnostic::Success, RawServiceObservation::Running),
            (ActionDiagnostic::Success, RawServiceObservation::Stopped),
            RawHealthObservation::Healthy,
            actions,
        );
        let mut executor = workflow_executor(network, service);
        assert_eq!(
            ResourceWorkflow::new(&mut controller, &mut executor).promote(),
            PromotionWorkflowOutcome::CleanupRequired
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn workflow_health_or_garp_failure_requires_cleanup() {
        for (health, garp) in [
            (RawHealthObservation::Unhealthy, RawGarpOutcome::Succeeded),
            (RawHealthObservation::Healthy, RawGarpOutcome::Failed),
        ] {
            let (mut controller, path) =
                workflow_controller(WorkflowClock::at(0), AuthorityMode::Conservative, true);
            let actions = Rc::new(RefCell::new(Vec::new()));
            let mut executor = workflow_executor(
                WorkflowNetwork::new(
                    (ActionDiagnostic::Success, RawVipObservation::Present),
                    (ActionDiagnostic::Success, RawVipObservation::Absent),
                    (ActionDiagnostic::Success, garp),
                    actions.clone(),
                ),
                WorkflowService::new(
                    (ActionDiagnostic::Success, RawServiceObservation::Running),
                    (ActionDiagnostic::Success, RawServiceObservation::Stopped),
                    health,
                    actions.clone(),
                ),
            );
            assert_eq!(
                ResourceWorkflow::new(&mut controller, &mut executor).promote(),
                PromotionWorkflowOutcome::CleanupRequired
            );
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn workflow_cleanup_is_authority_free_and_preserves_diagnostics() {
        let clock = WorkflowClock::at(0);
        let (mut controller, path) =
            workflow_controller(clock.clone(), AuthorityMode::Conservative, true);
        controller.arm_current_obligation_for_test();
        clock.set(9_000);
        controller.mark_resource_ownership_started();
        controller.request_demotion();
        let actions = Rc::new(RefCell::new(Vec::new()));
        let mut network = WorkflowNetwork::new(
            (ActionDiagnostic::Success, RawVipObservation::Unavailable),
            (
                ActionDiagnostic::Error("delete uncertain".into()),
                RawVipObservation::Absent,
            ),
            (ActionDiagnostic::Success, RawGarpOutcome::Succeeded),
            actions.clone(),
        );
        network.acquire_observations.clear();
        let mut service = WorkflowService::new(
            (ActionDiagnostic::Success, RawServiceObservation::Running),
            (ActionDiagnostic::Timeout, RawServiceObservation::Stopped),
            RawHealthObservation::Unavailable,
            actions.clone(),
        );
        service.service_observations.pop_front();
        let mut executor = workflow_executor(network, service);
        let outcome = ResourceWorkflow::new(&mut controller, &mut executor)
            .cleanup("resource workflow cleanup")
            .unwrap();
        assert!(matches!(
            outcome,
            CleanupWorkflowOutcome::LeaseReleasePending(_)
        ));
        assert_eq!(
            actions.borrow().as_slice(),
            &["service_stop", "vip_release"]
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn workflow_cleanup_does_not_release_vip_without_stopped_confirmation() {
        let (mut controller, path) =
            workflow_controller(WorkflowClock::at(0), AuthorityMode::Availability, false);
        controller.mark_resource_ownership_started();
        let actions = Rc::new(RefCell::new(Vec::new()));
        let mut network = WorkflowNetwork::new(
            (ActionDiagnostic::Success, RawVipObservation::Unavailable),
            (ActionDiagnostic::Success, RawVipObservation::Absent),
            (ActionDiagnostic::Success, RawGarpOutcome::Succeeded),
            actions.clone(),
        );
        network.acquire_observations.clear();
        let mut service = WorkflowService::new(
            (ActionDiagnostic::Success, RawServiceObservation::Running),
            (ActionDiagnostic::Success, RawServiceObservation::Running),
            RawHealthObservation::Unavailable,
            actions.clone(),
        );
        service.service_observations.pop_front();
        let mut executor = workflow_executor(network, service);
        assert_eq!(
            ResourceWorkflow::new(&mut controller, &mut executor)
                .cleanup("not stopped")
                .unwrap(),
            CleanupWorkflowOutcome::CleanupRequired
        );
        assert_eq!(actions.borrow().as_slice(), &["service_stop"]);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn workflow_cleanup_from_zero_classifies_running_or_unknown_service() {
        for observation in [
            RawServiceObservation::Running,
            RawServiceObservation::Unavailable,
        ] {
            let (mut controller, path) =
                workflow_controller(WorkflowClock::at(0), AuthorityMode::Availability, false);
            let actions = Rc::new(RefCell::new(Vec::new()));
            let mut network = WorkflowNetwork::new(
                (ActionDiagnostic::Success, RawVipObservation::Unavailable),
                (ActionDiagnostic::Success, RawVipObservation::Absent),
                (ActionDiagnostic::Success, RawGarpOutcome::Succeeded),
                actions.clone(),
            );
            network.acquire_observations.clear();
            let service = WorkflowService::new(
                (ActionDiagnostic::Success, observation),
                (ActionDiagnostic::Success, RawServiceObservation::Stopped),
                RawHealthObservation::Unavailable,
                actions,
            );
            let mut executor = workflow_executor(network, service);
            assert_eq!(
                ResourceWorkflow::new(&mut controller, &mut executor)
                    .cleanup("zero-resource service observation")
                    .unwrap(),
                CleanupWorkflowOutcome::CleanupRequired
            );
            if observation == RawServiceObservation::Running {
                assert!(controller.resource_owning());
            } else {
                assert!(controller.ownership_is_unknown_for_test());
            }
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn workflow_cleanup_from_zero_classifies_present_or_unknown_vip() {
        for observation in [RawVipObservation::Present, RawVipObservation::Unavailable] {
            let (mut controller, path) =
                workflow_controller(WorkflowClock::at(0), AuthorityMode::Availability, false);
            let actions = Rc::new(RefCell::new(Vec::new()));
            let mut network = WorkflowNetwork::new(
                (ActionDiagnostic::Success, RawVipObservation::Unavailable),
                (ActionDiagnostic::Success, observation),
                (ActionDiagnostic::Success, RawGarpOutcome::Succeeded),
                actions.clone(),
            );
            network.acquire_observations.clear();
            let service = WorkflowService::new(
                (ActionDiagnostic::Success, RawServiceObservation::Stopped),
                (ActionDiagnostic::Success, RawServiceObservation::Stopped),
                RawHealthObservation::Unavailable,
                actions,
            );
            let mut executor = workflow_executor(network, service);
            assert_eq!(
                ResourceWorkflow::new(&mut controller, &mut executor)
                    .cleanup("zero-resource VIP observation")
                    .unwrap(),
                CleanupWorkflowOutcome::CleanupRequired
            );
            if observation == RawVipObservation::Present {
                assert!(controller.resource_owning());
            } else {
                assert!(controller.ownership_is_unknown_for_test());
            }
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn workflow_cleanup_reaches_lease_release_only_after_stopped_and_absent() {
        let (mut controller, path) =
            workflow_controller(WorkflowClock::at(0), AuthorityMode::Conservative, true);
        controller.arm_current_obligation_for_test();
        let actions = Rc::new(RefCell::new(Vec::new()));
        let mut network = WorkflowNetwork::new(
            (ActionDiagnostic::Success, RawVipObservation::Unavailable),
            (
                ActionDiagnostic::Error("release delayed".into()),
                RawVipObservation::Absent,
            ),
            (ActionDiagnostic::Success, RawGarpOutcome::Succeeded),
            actions.clone(),
        );
        network.acquire_observations.clear();
        let mut service = WorkflowService::new(
            (ActionDiagnostic::Success, RawServiceObservation::Stopped),
            (ActionDiagnostic::Timeout, RawServiceObservation::Stopped),
            RawHealthObservation::Unavailable,
            actions,
        );
        service.service_observations.pop_front();
        let mut executor = workflow_executor(network, service);
        assert!(matches!(
            ResourceWorkflow::new(&mut controller, &mut executor)
                .cleanup("ordered lease release")
                .unwrap(),
            CleanupWorkflowOutcome::LeaseReleasePending(_)
        ));
        assert!(!controller.resource_owning());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn workflow_cleanup_release_present_or_unknown_never_starts_lease_release() {
        for observation in [RawVipObservation::Present, RawVipObservation::Unavailable] {
            let (mut controller, path) =
                workflow_controller(WorkflowClock::at(0), AuthorityMode::Conservative, true);
            let actions = Rc::new(RefCell::new(Vec::new()));
            let mut network = WorkflowNetwork::new(
                (ActionDiagnostic::Success, RawVipObservation::Unavailable),
                (ActionDiagnostic::Success, observation),
                (ActionDiagnostic::Success, RawGarpOutcome::Succeeded),
                actions.clone(),
            );
            network.acquire_observations.clear();
            let mut service = WorkflowService::new(
                (ActionDiagnostic::Success, RawServiceObservation::Stopped),
                (ActionDiagnostic::Success, RawServiceObservation::Stopped),
                RawHealthObservation::Unavailable,
                actions,
            );
            service.service_observations.pop_front();
            let mut executor = workflow_executor(network, service);
            assert_eq!(
                ResourceWorkflow::new(&mut controller, &mut executor)
                    .cleanup("release not absent")
                    .unwrap(),
                CleanupWorkflowOutcome::CleanupRequired
            );
            if observation == RawVipObservation::Present {
                assert!(controller.resource_owning());
            } else {
                assert!(controller.ownership_is_unknown_for_test());
            }
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn availability_cleanup_can_be_clean_without_witness_lease() {
        let (mut controller, path) =
            workflow_controller(WorkflowClock::at(0), AuthorityMode::Availability, false);
        controller.mark_resource_ownership_started();
        let actions = Rc::new(RefCell::new(Vec::new()));
        let mut network = WorkflowNetwork::new(
            (ActionDiagnostic::Success, RawVipObservation::Unavailable),
            (ActionDiagnostic::Timeout, RawVipObservation::Absent),
            (ActionDiagnostic::Success, RawGarpOutcome::Succeeded),
            actions.clone(),
        );
        network.acquire_observations.clear();
        let mut service = WorkflowService::new(
            (ActionDiagnostic::Success, RawServiceObservation::Running),
            (
                ActionDiagnostic::Error("stop delayed".into()),
                RawServiceObservation::Stopped,
            ),
            RawHealthObservation::Unavailable,
            actions.clone(),
        );
        service.service_observations.pop_front();
        let mut executor = workflow_executor(network, service);
        assert_eq!(
            ResourceWorkflow::new(&mut controller, &mut executor)
                .cleanup("availability cleanup")
                .unwrap(),
            CleanupWorkflowOutcome::CleanStandbyEligible
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn recovery_cleanup_local_resources_proves_zero_resource_without_lease() {
        let (mut controller, path) =
            workflow_controller(WorkflowClock::at(0), AuthorityMode::Availability, false);
        controller.mark_resource_ownership_started();
        let actions = Rc::new(RefCell::new(Vec::new()));
        let mut network = WorkflowNetwork::new(
            (ActionDiagnostic::Success, RawVipObservation::Present),
            (ActionDiagnostic::Success, RawVipObservation::Absent),
            (ActionDiagnostic::Success, RawGarpOutcome::Succeeded),
            actions.clone(),
        );
        network.acquire_observations.clear();
        let mut service = WorkflowService::new(
            (ActionDiagnostic::Success, RawServiceObservation::Running),
            (ActionDiagnostic::Success, RawServiceObservation::Stopped),
            RawHealthObservation::Unavailable,
            actions.clone(),
        );
        service.service_observations.pop_front();
        let mut executor = workflow_executor(network, service);
        assert_eq!(
            ResourceWorkflow::new(&mut controller, &mut executor).cleanup_local_resources(),
            CleanupWorkflowOutcome::CleanStandbyEligible
        );
        assert!(!controller.resource_owning());
        assert_eq!(
            actions.borrow().as_slice(),
            &["service_stop", "vip_release"]
        );
        let _ = std::fs::remove_file(path);
    }

    // ---- NF-6: workflow state paths never collide ----------------------------------------

    /// Remove a state file and the recovery siblings a test left beside it.
    fn remove_workflow_state(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        if let (Some(dir), Some(name)) = (path.parent(), path.file_name()) {
            let prefix = format!("{}.", name.to_string_lossy());
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    if entry.file_name().to_string_lossy().starts_with(&prefix) {
                        let _ = std::fs::remove_file(entry.path());
                    }
                }
            }
        }
    }

    /// Every caller reads the same clock value and the same pid: only the
    /// sequence tells the names apart, from 32 threads at once.
    #[test]
    fn workflow_state_names_are_distinct_when_the_clock_and_pid_are_equal() {
        let counter = std::sync::atomic::AtomicU64::new(0);
        let names = std::sync::Mutex::new(Vec::new());
        std::thread::scope(|scope| {
            for _ in 0..32 {
                scope.spawn(|| {
                    for _ in 0..200 {
                        let name =
                            workflow_state_name(4242, next_workflow_sequence(&counter), 1_000);
                        names.lock().unwrap().push(name);
                    }
                });
            }
        });
        let names = names.into_inner().unwrap();
        let distinct: std::collections::HashSet<_> = names.iter().collect();
        assert_eq!(names.len(), 6_400);
        assert_eq!(distinct.len(), names.len(), "a name was handed out twice");
    }

    /// The real controller helper, 32 threads, every call reading one and the
    /// same clock value: no `AlreadyExists`, every path distinct and created.
    #[test]
    fn workflow_controllers_do_not_collide_when_every_call_reads_one_clock_value() {
        let paths = std::sync::Mutex::new(Vec::new());
        std::thread::scope(|scope| {
            for _ in 0..32 {
                scope.spawn(|| {
                    for _ in 0..3 {
                        let (_controller, path) = workflow_controller_at(
                            || workflow_state_path(1_000),
                            WorkflowClock::at(0),
                            AuthorityMode::Conservative,
                            false,
                        );
                        assert!(path.exists(), "the state was not created");
                        paths.lock().unwrap().push(path);
                    }
                });
            }
        });
        let paths = paths.into_inner().unwrap();
        let distinct: std::collections::HashSet<_> = paths.iter().collect();
        assert_eq!(distinct.len(), 96, "a path was handed out twice");
        for path in &paths {
            remove_workflow_state(path);
        }
    }

    const NF6_CHILD_ENV: &str = "MKM_TEST_NF6_CHILD";
    const NF6_CHILD_TEST: &str =
        "resource_executor::tests::workflow_state_child_process_creates_paths_at_a_fixed_clock";

    /// Does nothing unless the parent test below started this binary: it then
    /// creates controllers at a fixed clock value (every process has the same
    /// sequence numbers and the same clock) and prints the paths.
    #[test]
    fn workflow_state_child_process_creates_paths_at_a_fixed_clock() {
        if std::env::var_os(NF6_CHILD_ENV).is_none() {
            return;
        }
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    for _ in 0..4 {
                        let (_controller, path) = workflow_controller_at(
                            || workflow_state_path(1_000),
                            WorkflowClock::at(0),
                            AuthorityMode::Conservative,
                            false,
                        );
                        println!("NF6-PATH {}", path.display());
                    }
                });
            }
        });
    }

    /// Four processes at once, sharing one temp directory, identical sequences
    /// and an identical clock value: no process fails, no path is shared.
    #[test]
    fn workflow_state_paths_do_not_collide_across_concurrent_processes() {
        let exe = std::env::current_exe().unwrap();
        let children: Vec<_> = (0..4)
            .map(|_| {
                std::process::Command::new(&exe)
                    .args(["--exact", NF6_CHILD_TEST, "--nocapture", "--test-threads=1"])
                    .env(NF6_CHILD_ENV, "1")
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .unwrap()
            })
            .collect();
        let mut paths = Vec::new();
        for child in children {
            let output = child.wait_with_output().unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                output.status.success(),
                "a child failed: {}\n{stdout}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
            paths.extend(
                stdout
                    .lines()
                    // libtest may print its own text before the first line.
                    .filter_map(|line| line.split_once("NF6-PATH ").map(|(_, path)| path))
                    .map(std::path::PathBuf::from),
            );
        }
        let distinct: std::collections::HashSet<_> = paths.iter().collect();
        assert_eq!(paths.len(), 4 * 8 * 4, "a child did not run");
        assert_eq!(distinct.len(), paths.len(), "a path was handed out twice");
        for path in &paths {
            remove_workflow_state(path);
        }
    }

    /// A path that already exists is skipped: its content survives, it is not
    /// reused, and exactly the names up to the first free one are asked for.
    #[test]
    fn an_existing_workflow_state_path_is_skipped_never_reused_or_removed() {
        let taken: Vec<_> = (0..2)
            .map(|_| workflow_state_path(workflow_clock_nanos()))
            .collect();
        for path in &taken {
            std::fs::write(path, "someone else's state").unwrap();
        }
        let free = workflow_state_path(workflow_clock_nanos());
        let mut offered = vec![taken[0].clone(), taken[1].clone(), free.clone()].into_iter();
        let mut calls = 0;
        let (_controller, path) = workflow_controller_at(
            || {
                calls += 1;
                offered.next().expect("more names asked for than offered")
            },
            WorkflowClock::at(0),
            AuthorityMode::Conservative,
            false,
        );
        assert_eq!(path, free, "an existing path was reused");
        assert_eq!(calls, 3);
        for path in &taken {
            assert_eq!(
                std::fs::read_to_string(path).unwrap(),
                "someone else's state",
                "an existing file was touched"
            );
            std::fs::remove_file(path).unwrap();
        }
        remove_workflow_state(&free);
    }

    /// The search for a free path is bounded, and gives up without touching
    /// what it found.
    #[test]
    fn the_workflow_state_path_search_is_bounded() {
        let taken = workflow_state_path(workflow_clock_nanos());
        std::fs::write(&taken, "someone else's state").unwrap();
        let mut calls = 0u32;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            workflow_controller_at(
                || {
                    calls += 1;
                    assert!(
                        calls <= 4 * WORKFLOW_STATE_ATTEMPTS,
                        "the search is unbounded"
                    );
                    taken.clone()
                },
                WorkflowClock::at(0),
                AuthorityMode::Conservative,
                false,
            )
        }));
        let message = match result {
            Ok(_) => panic!("a taken path was accepted"),
            Err(payload) => payload
                .downcast_ref::<String>()
                .cloned()
                .unwrap_or_default(),
        };
        assert!(
            message.contains("no unused workflow state path"),
            "{message}"
        );
        assert_eq!(calls, WORKFLOW_STATE_ATTEMPTS);
        assert_eq!(
            std::fs::read_to_string(&taken).unwrap(),
            "someone else's state"
        );
        std::fs::remove_file(&taken).unwrap();
    }

    /// Only a taken path is retried: any other initialization failure is a
    /// failure of the test, reported at once with its cause.
    #[test]
    fn an_unrelated_initialization_error_is_not_retried() {
        let missing_dir = workflow_state_path(workflow_clock_nanos());
        assert!(!missing_dir.exists());
        let mut calls = 0u32;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            workflow_controller_at(
                || {
                    calls += 1;
                    missing_dir.join("state")
                },
                WorkflowClock::at(0),
                AuthorityMode::Conservative,
                false,
            )
        }));
        let message = match result {
            Ok(_) => panic!("an unusable path was accepted"),
            Err(payload) => payload
                .downcast_ref::<String>()
                .cloned()
                .unwrap_or_default(),
        };
        assert!(message.contains("cannot initialize"), "{message}");
        assert_eq!(calls, 1, "a non-collision error was retried");
    }

    /// A counter at its end is an error, never a wrap to an old number.
    #[test]
    fn the_workflow_state_counter_refuses_to_wrap() {
        let counter = std::sync::atomic::AtomicU64::new(u64::MAX - 1);
        assert_eq!(next_workflow_sequence(&counter), u64::MAX - 1);
        let wrapped = std::panic::catch_unwind(|| next_workflow_sequence(&counter));
        assert!(wrapped.is_err(), "the counter wrapped around");
        assert_eq!(
            counter.load(std::sync::atomic::Ordering::Relaxed),
            u64::MAX,
            "a refused step must not move the counter"
        );
    }
}
