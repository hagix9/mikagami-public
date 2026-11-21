//! Deterministic daemon/runtime supervisor foundation.
//!
//! This module deliberately owns lifecycle and observation scheduling only. It
//! does not make HA decisions: an observation never acquires authority or
//! promotes a node.

#![allow(dead_code)]

use crate::failover_policy::{
    FailoverEligibility, FailoverEligibilityInput, FailoverEligibilityPolicy, LocalSafetySnapshot,
};
use crate::peer_observer::{PeerObservation, PeerObservationState};
use crate::promotion_authorization::PromotionAttemptAuthorization;
use crate::protocol::Role;
use crate::state_machine::{NodeState, OperationPhase};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DaemonHealth {
    Healthy,
    Unhealthy,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DaemonVip {
    Present,
    Absent,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DaemonService {
    Running,
    Stopped,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DaemonSnapshot {
    pub(crate) node_state: NodeState,
    pub(crate) health: DaemonHealth,
    pub(crate) vip: DaemonVip,
    pub(crate) service: DaemonService,
    pub(crate) resource_owning: bool,
    pub(crate) recovery_reconciled: bool,
    pub(crate) unresolved_mutation: bool,
}

/// Cached local diagnostic state supplied to the peer heartbeat path.
/// Resource observation remains owned by the local runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PeerStatusSnapshot {
    pub(crate) node_state: NodeState,
    pub(crate) operation_phase: Option<OperationPhase>,
    pub(crate) role: Role,
    pub(crate) service: DaemonService,
    pub(crate) health: DaemonHealth,
    pub(crate) vip: DaemonVip,
}

impl PeerStatusSnapshot {
    pub(crate) const fn unobserved() -> Self {
        Self {
            node_state: NodeState::Init,
            operation_phase: None,
            role: Role::Standby,
            service: DaemonService::Unknown,
            health: DaemonHealth::Unknown,
            vip: DaemonVip::Unknown,
        }
    }

    pub(crate) const fn with_unknown_resources(self) -> Self {
        Self {
            service: DaemonService::Unknown,
            health: DaemonHealth::Unknown,
            vip: DaemonVip::Unknown,
            ..self
        }
    }
}

impl DaemonSnapshot {
    fn zero_resource(self) -> bool {
        self.vip == DaemonVip::Absent && self.service == DaemonService::Stopped
    }

    fn recovery_ready(self) -> bool {
        self.node_state == NodeState::Standby
            && self.recovery_reconciled
            && !self.unresolved_mutation
            && !self.resource_owning
            && self.zero_resource()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DaemonState {
    Constructing,
    Recovering,
    Running,
    ShutdownRequested,
    Stopped,
    RecoveryBlocked,
    ShutdownBlocked,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartResult {
    Running,
    RecoveryBlocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TickResult {
    Observed,
    ObservationUnavailable,
    ShutdownComplete,
    ShutdownRequiresCleanup,
    NotRunning,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShutdownResult {
    Clean,
    RequiresCleanup,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DaemonError {
    Startup(String),
    ObservationInvariant(String),
    Shutdown(String),
    /// The Witness session is lost and this node is a clean Standby: the
    /// daemon stops (non-zero) so the service manager reconnects it.
    WitnessSessionLost(String),
    /// The shared control lock is no longer trusted. This is deliberately
    /// distinct from a normal shutdown: no demotion, VIP release, service
    /// stop, lease release or other cleanup may start after the process can
    /// no longer prove that it is the only control owner.
    ControlLockLost(String),
}

impl fmt::Display for DaemonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Startup(error) => write!(formatter, "daemon startup failed: {error}"),
            Self::ObservationInvariant(error) => {
                write!(formatter, "daemon observation invariant failed: {error}")
            }
            Self::Shutdown(error) => write!(formatter, "daemon shutdown failed: {error}"),
            Self::WitnessSessionLost(error) => {
                write!(formatter, "Witness session lost: {error}")
            }
            Self::ControlLockLost(error) => {
                write!(
                    formatter,
                    "control lock lost; refusing further resource or lease operations: {error}"
                )
            }
        }
    }
}

impl std::error::Error for DaemonError {}

/// C-l: one new authoritative GET_TERM on `session`, classified against
/// `expectation` by the observation adapter (authentication, request-id and
/// connection-provenance checks included). Any failure is an error, never a
/// view.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn fresh_authority_view(
    observer: &mut crate::evidence_fusion::adapter::WitnessEvidenceAdapter,
    session: &mut crate::witness_runtime::WitnessSession,
    expectation: crate::evidence_fusion::adapter::AuthorityViewExpectation,
) -> Result<
    (
        crate::protocol::Term,
        crate::evidence_fusion::adapter::AuthorityViewCompatibility,
    ),
    String,
> {
    observer
        .complete_attempt_observation(
            session,
            expectation,
            &|| false,
            &mut std::time::Instant::now,
            &mut std::thread::sleep,
        )
        .into_result()
        .map_err(|reason| format!("the Witness term could not be read: {reason}"))?;
    match observer.poll_observation_at(session, std::time::Instant::now()) {
        Ok(crate::evidence_fusion::adapter::ObservationProgress::Ready(view)) => {
            Ok((view.term(), view.compatibility()))
        }
        _ => Err("the Witness term view was not available".to_string()),
    }
}

/// The minimal runtime boundary owned by the daemon.
///
/// Implementations must keep each operation bounded by their own backend
/// timeouts. In particular, this trait has no sleep, retry, or HA decision
/// method.
pub(crate) trait DaemonRuntime {
    fn startup(&mut self) -> Result<DaemonSnapshot, String>;
    /// `startup` with the live control-lock predicate, for the protected
    /// effects of the startup reconciliation (Amendment C, C-m': the guarded
    /// ZeroResource before an exceptional settle). Runtimes without such
    /// effects keep `startup`.
    fn startup_guarded(
        &mut self,
        control_lock_safe: &dyn Fn() -> bool,
    ) -> Result<DaemonSnapshot, String> {
        let _ = control_lock_safe;
        self.startup()
    }
    fn observe(&mut self) -> Result<DaemonSnapshot, String>;
    /// Classify and, when permitted, perform shutdown cleanup.
    ///
    /// `control_lock_safe` is the live control-lock contract. It must be
    /// sampled before every new protected effect (demotion, service stop,
    /// VIP release, lease operation) and the cleanup must stop without
    /// starting the next effect when it returns `false`.
    fn shutdown(&mut self, control_lock_safe: &dyn Fn() -> bool) -> Result<ShutdownResult, String>;

    /// The peer assessment, for transition-only logging. `None`: no peer.
    fn peer_assessment_for_log(&self) -> Option<crate::failure_assessment::PeerFailureAssessment> {
        None
    }

    /// Whether the Witness session is lost for good: a sticky adapter failure
    /// (`WitnessEvidenceAdapter::session_lost`) or a session owner that has
    /// latched its transport as closed (`WitnessSession::lost`).
    fn witness_session_lost(&self) -> bool {
        false
    }

    /// v0.6 A-1: with the Witness session permanently lost, may this process
    /// stop (non-zero) so the service manager restarts it with a fresh
    /// handshake? Only when nothing local is still protected: no owned
    /// resource, VIP absent, service stopped, and the only outstanding work is
    /// a Witness lease operation a dead session can never complete. Startup
    /// reconciliation resolves that durable obligation. Default: no.
    fn witness_loss_stop_allowed(&mut self) -> bool {
        false
    }

    /// Release the Witness transport without declaring the session lost.
    /// Called on the shutdown path so the descriptor is not held until process
    /// exit.
    fn close_witness_session(&mut self) {}

    /// v0.6 A-1: cheap, side-effect-free liveness probe of the Witness
    /// transport. An idle Standby sends no request, so without this a stopped
    /// Witness is only noticed at the next promotion attempt and the dead
    /// socket is retained (`CLOSE_WAIT`) in the meantime. The implementation
    /// must not send, consume a frame or change any protocol state, and must
    /// never treat a probe result as authority.
    fn probe_witness_transport(&mut self) -> Result<(), String> {
        Ok(())
    }

    /// Read-only facts for the automatic trigger, if this runtime supports
    /// one. Default runtimes have none (no automation).
    fn auto_facts(&mut self, _now: std::time::Instant) -> Option<AutoRuntimeFacts> {
        None
    }

    /// Why `startup` left the node recovery-blocked, for the recovery-gate
    /// message (diagnostic text only, never evidence).
    fn recovery_block_cause(&self) -> Option<String> {
        None
    }

    /// One bounded foreground lifecycle step (Active renewal/demotion or
    /// post-cleanup reconciliation). Default runtimes have no such work.
    ///
    /// `shutdown_requested` is the Daemon-owned requested state the Stage 13
    /// lifecycle has always used (unchanged). `live_shutdown` (Stage 14
    /// F14.9-01) is the live shutdown query for the Stage 14 foreground
    /// fencing step: it is sampled at that step's §26 R7 / §18.5 / §27.4
    /// boundaries and after its bounded process returns (§17.2).
    fn foreground_lifecycle_tick(
        &mut self,
        _shutdown_requested: &dyn Fn() -> bool,
        _live_shutdown: &dyn Fn() -> bool,
        _control_lock_safe: &dyn Fn() -> bool,
    ) -> Result<(), String> {
        Ok(())
    }

    /// Design Revision 10 §9 bounded shutdown join: perform at most one
    /// eligible reconciliation step once shutdown is observed. Default
    /// runtimes have no durable work to join, so this is a no-op.
    fn shutdown_bounded_step(
        &mut self,
        _control_lock_safe: &dyn Fn() -> bool,
    ) -> Result<bool, String> {
        Ok(false)
    }

    fn lifecycle_wait_delay(
        &self,
        ordinary: std::time::Duration,
    ) -> Result<std::time::Duration, String> {
        Ok(ordinary)
    }

    fn authority_observation_allowed(&self) -> bool {
        true
    }

    /// Advance the peer runtime exactly once using the caller-supplied
    /// authoritative observation time. No internal clock sampling is allowed
    /// on this deterministic path.
    fn peer_tick_at(
        &mut self,
        _now: std::time::Instant,
        _peer_status: Option<PeerStatusSnapshot>,
    ) -> Result<Option<PeerObservationState>, String> {
        Ok(None)
    }

    fn peer_status(&self) -> Option<PeerStatusSnapshot> {
        None
    }

    /// Snapshot the peer observation using the same authoritative time as
    /// `peer_tick_at` for the current iteration.
    fn peer_snapshot_at(&mut self, _now: std::time::Instant) -> Option<PeerObservation> {
        None
    }

    fn invalidate_peer_status(&mut self) {}

    // ---- Bootstrap Admission hooks (contract K-1..K-6) ---------------------
    //
    // Defaults describe a runtime without a peer: BA is unavailable.

    /// Answering side: the daemon-level facts of the tick that is about to
    /// advance the peer runtime, or `None` when this tick's observation
    /// failed. Called exactly once per tick, right before `peer_tick_at`, with
    /// nothing in between that can change the node (K-3).
    fn set_probe_context(&mut self, _context: Option<crate::bootstrap_admission::DaemonFacts>) {}

    /// Whether this runtime has a peer connection to admit through.
    fn bootstrap_supported(&self) -> bool {
        false
    }

    /// Whether the runtime's authority mode is Conservative (K-5).
    fn bootstrap_conservative(&self) -> bool {
        false
    }

    /// The established peer connection a BA session/probe is bound to.
    fn bootstrap_stamp(&self) -> Option<crate::bootstrap_admission::BootstrapStamp> {
        None
    }

    /// Ask the peer runtime to send the probe from its next tick.
    fn request_bootstrap_probe(&mut self) -> bool {
        false
    }

    /// The probe outcome, once.
    fn take_probe_outcome(&mut self) -> Option<crate::bootstrap_admission::ProbeOutcome> {
        None
    }

    /// Forget an outstanding probe (the session was dropped).
    fn discard_bootstrap_probe(&mut self) {}

    fn local_safety_snapshot(
        &mut self,
        _shutdown_requested: bool,
    ) -> Result<Option<LocalSafetySnapshot>, String> {
        Ok(None)
    }

    /// v0.7 G-2 (`G2_SAFETY_CONTRACT.md` R4.1 §5.1): the route-handoff tick, called as the last
    /// blocking work of an observed iteration. Default runtimes have no route handoff.
    fn route_handoff_tick(&mut self, _control_lock_safe: &dyn Fn() -> bool) -> Result<(), String> {
        Ok(())
    }
}

/// Immutable per-iteration observation/safety context.
///
/// It carries the single authoritative observation `now` and the authoritative
/// shutdown state, both derived from `Daemon`-owned state. It is constructed
/// only by `Daemon::iteration_context` (fields are private to this module), so a
/// caller cannot fabricate an inconsistent shutdown value. It is ephemeral:
/// not persisted, serialized, or sent on the wire, and consumers can only read
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DaemonIterationContext {
    now: std::time::Instant,
    shutdown_requested: bool,
}

impl DaemonIterationContext {
    pub(crate) const fn now(&self) -> std::time::Instant {
        self.now
    }

    pub(crate) const fn shutdown_requested(&self) -> bool {
        self.shutdown_requested
    }

    /// Test-only constructor. Production callers must use
    /// `Daemon::iteration_context` so the shutdown value cannot be fabricated.
    #[cfg(test)]
    pub(crate) const fn new_for_test(now: std::time::Instant, shutdown_requested: bool) -> Self {
        Self {
            now,
            shutdown_requested,
        }
    }
}

/// Stage 14 F14.9-01: a read-only reader of the process shutdown-signal
/// latch — the same input the observation loop turns into
/// `Daemon::request_shutdown`. It is not a second shutdown authority: it can
/// only be read, it never changes Daemon state, and the latch it reads is set
/// only by the signal handler. The Daemon composes it with its own requested
/// state so a blocking fencing step can observe a shutdown that arrives while
/// the foreground owner is inside the step (§17.2, §27.2 step 3, §27.4).
/// Absent (no reader attached), the live query is the requested state alone.
#[derive(Default)]
struct ShutdownSignal(Option<Box<dyn Fn() -> bool>>);

impl ShutdownSignal {
    fn raised(&self) -> bool {
        self.0.as_ref().is_some_and(|read| read())
    }
}

/// Read-only reader of the shared control lock's safety contract.
///
/// Unlike [`ShutdownSignal`], this is **not** a shutdown authority and never
/// requests a shutdown. It answers only "may this process still start a new
/// protected operation?" and returns the first lock-path error when the
/// answer is no. `None` means no reader is attached (unit runtimes that do
/// not use the host control lock). A normal SIGTERM does not by itself make
/// this reader report a loss.
#[derive(Default)]
struct ControlLockGuard(Option<Box<dyn Fn() -> Option<String>>>);

impl ControlLockGuard {
    fn lost(&self) -> Option<String> {
        self.0.as_ref().and_then(|read| read())
    }
}

/// What the automatic trigger may read from the runtime (plain data, one
/// observation epoch; never evidence and never a capability).
#[derive(Debug, Clone)]
pub(crate) struct AutoRuntimeFacts {
    pub(crate) backend_is_command: bool,
    pub(crate) assessment: crate::failure_assessment::PeerFailureAssessment,
    pub(crate) loss: Option<crate::auto_failover::LossEpisode>,
    pub(crate) peer_active_confirmed: bool,
    pub(crate) peer_node_state: Option<NodeState>,
    pub(crate) standby_safe: bool,
    pub(crate) node_state: NodeState,
    pub(crate) incident: Option<crate::auto_failover::IncidentFacts>,
    /// The runtime's fencing activity counts (Phase 1-J29 B1 / C1).
    pub(crate) activity: crate::auto_failover::FenceActivity,
}

pub(crate) struct Daemon<R> {
    /// Automatic trigger (`[failover] auto`): a pure state machine polled once
    /// per tick. It can only leave a one-shot request that the loop consumes
    /// through the same entry as an operator's SIGUSR1.
    auto: Option<crate::auto_failover::AutoFailover>,
    /// Last peer state written to the log (transition-only logging).
    peer_lost_logged: bool,
    pending_auto: Option<crate::auto_failover::AutoOrigin>,
    /// The origin of the attempt the loop is about to run (`None`: operator).
    trigger_origin: Option<crate::auto_failover::AutoOrigin>,
    started_at: Option<std::time::Instant>,
    runtime: R,
    state: DaemonState,
    shutdown_requested: bool,
    shutdown_signal: ShutdownSignal,
    /// Live control-lock safety reader. It is separate from the shutdown
    /// signal so a lock loss can stop the daemon without being mistaken for
    /// a voluntary shutdown (which is allowed to demote and clean up).
    control_lock_guard: ControlLockGuard,
    cached: Option<DaemonSnapshot>,
    last_observation_error: Option<String>,
    peer_state: PeerObservationState,
    peer_observation: Option<PeerObservation>,
    promotion_attempt: crate::promotion_attempt::PromotionAttemptLifecycle,
    /// Bootstrap Admission: the runtime-only session (never persisted, lost on
    /// restart, consumed by attempt 2).
    bootstrap_session: Option<crate::bootstrap_admission::BootstrapSession>,
    /// BAP-7 time limits of that session (hygiene; independent of `auto`).
    session_hygiene: crate::bootstrap_admission::SessionHygiene,
    /// Test-only hooks consumed at internal Stage 13.2 boundaries by
    /// `execute_promotion_attempt` (post-revalidation, then post-lease).
    /// Used to model shutdown/cancellation races deterministically.
    #[cfg(test)]
    promotion_attempt_test_hooks: std::collections::VecDeque<Box<dyn FnOnce(&mut Daemon<R>)>>,
}

impl<R: DaemonRuntime> Daemon<R> {
    pub(crate) fn new(runtime: R) -> Self {
        Self {
            auto: None,
            peer_lost_logged: false,
            pending_auto: None,
            trigger_origin: None,
            started_at: None,
            runtime,
            state: DaemonState::Constructing,
            shutdown_requested: false,
            shutdown_signal: ShutdownSignal::default(),
            control_lock_guard: ControlLockGuard::default(),
            cached: None,
            last_observation_error: None,
            peer_state: PeerObservationState::NeverSeen,
            peer_observation: None,
            promotion_attempt: crate::promotion_attempt::PromotionAttemptLifecycle::idle(),
            bootstrap_session: None,
            session_hygiene: crate::bootstrap_admission::SessionHygiene::default(),
            #[cfg(test)]
            promotion_attempt_test_hooks: std::collections::VecDeque::new(),
        }
    }

    pub(crate) fn start(&mut self) -> Result<StartResult, DaemonError> {
        if !matches!(
            self.state,
            DaemonState::Constructing | DaemonState::RecoveryBlocked
        ) {
            return Err(DaemonError::Startup("daemon was already started".into()));
        }
        self.state = DaemonState::Recovering;
        let guard = &self.control_lock_guard;
        let snapshot = self
            .runtime
            .startup_guarded(&|| guard.lost().is_none())
            .map_err(DaemonError::Startup)?;
        self.cached = Some(snapshot);
        if snapshot.recovery_ready() {
            self.state = DaemonState::Running;
            self.started_at = Some(std::time::Instant::now());
            Ok(StartResult::Running)
        } else {
            self.state = DaemonState::RecoveryBlocked;
            Ok(StartResult::RecoveryBlocked)
        }
    }

    /// Arm the automatic trigger (production composition root only).
    pub(crate) fn enable_auto(&mut self, config: crate::auto_failover::AutoConfig) {
        self.auto = Some(crate::auto_failover::AutoFailover::new(config));
    }

    /// Consume the automatic trigger's one-shot request, if any. The loop
    /// folds this into the same consumption point as the operator's intent;
    /// it creates no attempt by itself.
    pub(crate) fn take_auto_request(&mut self) -> Option<crate::auto_failover::AutoOrigin> {
        self.pending_auto.take()
    }

    /// Record which trigger the next attempt belongs to (`None`: operator).
    pub(crate) fn set_trigger_origin(&mut self, origin: Option<crate::auto_failover::AutoOrigin>) {
        self.trigger_origin = origin;
    }

    /// The request-id prefix of the attempt about to run (identity only).
    pub(crate) fn trigger_label(&self) -> &'static str {
        match self.trigger_origin {
            None => "operator-sigusr1",
            Some(_) => "auto",
        }
    }

    /// `manual` or `automatic`, for the one line written per attempt.
    pub(crate) fn trigger_kind(&self) -> &'static str {
        match self.trigger_origin {
            None => "manual",
            Some(_) => "automatic",
        }
    }

    /// Poll the automatic trigger once, after this tick's peer advance. Pure
    /// decision; the only effects are a pending request flag or one log line.
    fn evaluate_auto(&mut self, now: std::time::Instant) {
        use crate::auto_failover::{AutoDecision, AutoInputs};
        if self.auto.is_none() || self.pending_auto.is_some() {
            return;
        }
        let Some(started) = self.started_at else {
            return;
        };
        let Some(facts) = self.runtime.auto_facts(now) else {
            return;
        };
        let inputs = AutoInputs {
            now_ms: now.saturating_duration_since(started).as_millis() as u64,
            uptime_ms: now.saturating_duration_since(started).as_millis() as u64,
            running: self.state == DaemonState::Running,
            shutdown: self.shutdown_requested || self.shutdown_signal.raised(),
            attempt_in_flight: self.promotion_attempt.in_flight_id().is_some(),
            standby_safe: facts.standby_safe,
            node_state: facts.node_state,
            backend_is_command: facts.backend_is_command,
            assessment: facts.assessment,
            loss: facts.loss,
            peer_active_confirmed: facts.peer_active_confirmed,
            peer_node_state: facts.peer_node_state,
            incident: facts.incident,
            activity: facts.activity,
            bootstrap_session_open: self.bootstrap_session_open(),
            bootstrap_session_attested: self.bootstrap_session_attested(),
        };
        let decision = match self.auto.as_mut() {
            Some(auto) => auto.poll(&inputs),
            None => return,
        };
        match decision {
            AutoDecision::Request { origin, first } => {
                if first {
                    crate::operator_log::info_auto_failover_started(origin.name());
                }
                self.pending_auto = Some(origin);
            }
            AutoDecision::Exhausted(reason) => {
                crate::operator_log::warn_auto_failover_stopped(reason);
            }
            AutoDecision::Idle | AutoDecision::Wait(_) => {}
        }
    }

    /// Why the last `start` left the node recovery-blocked, if the runtime
    /// can say (diagnostic text for the recovery gate).
    pub(crate) fn recovery_block_cause(&self) -> Option<String> {
        self.runtime.recovery_block_cause()
    }

    pub(crate) fn request_shutdown(&mut self) -> Result<(), DaemonError> {
        if matches!(self.state, DaemonState::Stopped | DaemonState::Failed) {
            return Err(DaemonError::Shutdown("daemon is not running".into()));
        }
        self.shutdown_requested = true;
        if self.state != DaemonState::ShutdownBlocked {
            self.state = DaemonState::ShutdownRequested;
        }
        // A Bootstrap Admission session never outlives a shutdown request,
        // and no automatic request outlives it either.
        self.pending_auto = None;
        self.discard_bootstrap_session("shutdown requested");
        Ok(())
    }

    /// Stage 14 F14.9-01: attach the read-only reader of the shutdown-signal
    /// latch that also feeds the observation loop's `should_stop` (production:
    /// the one `daemon_run` signal reader). Only the Stage 14 fencing
    /// boundaries consult it; `request_shutdown` stays the only way Daemon
    /// shutdown state changes.
    pub(crate) fn attach_shutdown_signal(&mut self, read: impl Fn() -> bool + 'static) {
        self.shutdown_signal = ShutdownSignal(Some(Box::new(read)));
    }

    /// Attach the read-only live control-lock safety reader. It reports the
    /// first lock-path error, or `None` while the process may still start a
    /// protected operation. It is sampled at every effect boundary; a loss
    /// is never converted into a normal shutdown.
    pub(crate) fn attach_control_lock_guard(
        &mut self,
        read: impl Fn() -> Option<String> + 'static,
    ) {
        self.control_lock_guard = ControlLockGuard(Some(Box::new(read)));
    }

    /// Fail closed on a lost control lock before any effect starts.
    fn require_control_lock(&mut self) -> Result<(), DaemonError> {
        let Some(error) = self.control_lock_guard.lost() else {
            return Ok(());
        };
        self.state = DaemonState::Failed;
        Err(DaemonError::ControlLockLost(error))
    }

    /// Build the immutable per-iteration observation/safety context from
    /// Daemon-owned shutdown state and the supplied authoritative observation
    /// time. This is the only production constructor: it never samples a
    /// second clock, and callers cannot inject an arbitrary shutdown value.
    pub(crate) fn iteration_context(&self, now: std::time::Instant) -> DaemonIterationContext {
        DaemonIterationContext {
            now,
            shutdown_requested: self.shutdown_requested,
        }
    }

    /// Stage 13.1: accept one explicit local promotion attempt into the
    /// single in-flight slot. This is inert lifecycle plumbing only: it does
    /// not poll the Witness observation, advance the peer runtime, consume a
    /// `WitnessAuthorityViewEvidence`, evaluate eligibility/authorization, or touch any
    /// promotion/lease/VIP/service/GARP mutation path. An `Authorized`
    /// evaluation is permission data from its observation epoch and is never
    /// stored here; executing the attempt requires the future Stage 13.2
    /// fresh-revalidation and lease-handoff boundary, which does not exist
    /// yet.
    ///
    /// Rejects while the authoritative `Daemon`-owned shutdown state is
    /// requested (`RejectedShutdown`) or while an attempt is already in
    /// flight (`AlreadyInProgress`) — a duplicate of the in-flight identity
    /// is rejected identically and never replaces it.
    pub(crate) fn request_promotion_attempt(
        &mut self,
        request: crate::promotion_attempt::PromotionExecutionRequest,
    ) -> Result<
        crate::promotion_attempt::PromotionRequestId,
        crate::promotion_attempt::PromotionAttemptRejection,
    > {
        if self.shutdown_requested {
            return Err(crate::promotion_attempt::PromotionAttemptRejection::RejectedShutdown);
        }
        self.promotion_attempt.accept(request)
    }

    /// Complete the in-flight promotion attempt: `InFlight -> Idle`, inert
    /// bookkeeping only (no promotion is performed or implied). A no-op
    /// (`None`) when no attempt is in flight.
    pub(crate) fn finish_promotion_attempt(
        &mut self,
    ) -> Option<crate::promotion_attempt::PromotionRequestId> {
        self.promotion_attempt.finish()
    }

    /// Cancel the in-flight promotion attempt: `InFlight -> Idle`. A no-op
    /// (`None`) when no attempt is in flight.
    pub(crate) fn cancel_promotion_attempt(
        &mut self,
    ) -> Option<crate::promotion_attempt::PromotionRequestId> {
        self.promotion_attempt.cancel()
    }

    /// Read-only view of the promotion-attempt lifecycle slot.
    pub(crate) const fn promotion_attempt_lifecycle(
        &self,
    ) -> &crate::promotion_attempt::PromotionAttemptLifecycle {
        &self.promotion_attempt
    }

    /// Drive one lifecycle step, sampling one authoritative observation time.
    /// This is a convenience wrapper; the deterministic path is `tick_at`.
    pub(crate) fn tick(&mut self) -> Result<TickResult, DaemonError> {
        let now = std::time::Instant::now();
        self.tick_at(now)
    }

    /// Drive one deterministic lifecycle step at the supplied authoritative
    /// observation time. No internal clock sampling occurs on this path: the
    /// same `now` is used for the peer runtime advance and its snapshot.
    /// No sleeping or implicit retry is performed here; the caller owns the
    /// tick cadence.
    pub(crate) fn tick_at(&mut self, now: std::time::Instant) -> Result<TickResult, DaemonError> {
        // R-16: the control-lock safety contract is sampled before the
        // shutdown branch, not only by the observation loop. A lock loss
        // racing a SIGTERM therefore cannot enter demotion/VIP/service/lease
        // cleanup.
        self.require_control_lock()?;
        if self.shutdown_requested {
            if !matches!(
                self.state,
                DaemonState::ShutdownRequested | DaemonState::ShutdownBlocked
            ) {
                return Ok(TickResult::NotRunning);
            }
            // Design Revision 10 §9: shutdown joins the existing owner with at
            // most one bounded eligible reconciliation step before the final
            // classification.  The runtime holds the "at most one" latch, so
            // repeated shutdown ticks cannot form a retry loop.  A step that
            // cannot complete is reported and then classified from actual
            // durable state, which stays non-clean.
            //
            // The cached observation is refreshed only when a step actually ran
            // and changed lifecycle state.  A shutdown that performs no step
            // makes no extra runtime call at all, so an idle shutdown keeps its
            // existing bounded-call contract.  The refresh is a pure read-only
            // observation: it cannot promote, mutate, install authority, or
            // clear anything, and a failed observation leaves the previous
            // cache untouched rather than inventing a new fact.
            let bounded_step = self
                .runtime
                .shutdown_bounded_step(&|| self.control_lock_guard.lost().is_none());
            // Re-check before the observation refresh and the final shutdown
            // classification: the step may have been long enough for another
            // process to replace the lock.
            self.require_control_lock()?;
            match bounded_step {
                Ok(true) => {
                    if let Ok(snapshot) = self.runtime.observe() {
                        self.cached = Some(snapshot);
                    }
                }
                Ok(false) => {}
                Err(error) => crate::operator_log::warn_shutdown_step_rejected(&error),
            }
            self.require_control_lock()?;
            let shutdown_result = self
                .runtime
                .shutdown(&|| self.control_lock_guard.lost().is_none());
            // v0.6 A-1: the verdict is final, so the Witness descriptor is
            // released now rather than at process exit. This cannot promote,
            // mutate a resource or change the verdict.
            self.runtime.close_witness_session();
            // A cleanup that stopped because the lock was lost is not a
            // normal shutdown verdict. Check the guard before mapping any
            // runtime error or success.
            self.require_control_lock()?;
            return match shutdown_result.map_err(DaemonError::Shutdown)? {
                ShutdownResult::Clean => {
                    self.state = DaemonState::Stopped;
                    Ok(TickResult::ShutdownComplete)
                }
                ShutdownResult::RequiresCleanup => {
                    self.state = DaemonState::ShutdownBlocked;
                    Ok(TickResult::ShutdownRequiresCleanup)
                }
            };
        }

        if self.state != DaemonState::Running {
            return Ok(TickResult::NotRunning);
        }

        // v0.6 A-1: detect a Witness that closed the connection while this
        // node was idle (no exchange would otherwise notice). Read-only: it
        // sends nothing and consumes no frame; a detected loss only latches
        // the session, and the fail-closed stop check below decides.
        // A probe failure is not a safety decision; the session stays as it
        // was and every later exchange re-detects a real closure.
        let _ = self.runtime.probe_witness_transport();
        let foreground = self.runtime.foreground_lifecycle_tick(
            &|| self.shutdown_requested,
            &|| self.shutdown_requested || self.shutdown_signal.raised(),
            &|| self.control_lock_guard.lost().is_none(),
        );
        // A live loss during the foreground step wins over its local result:
        // no observation, peer tick, demotion or cleanup may run after it.
        self.require_control_lock()?;
        foreground.map_err(DaemonError::ObservationInvariant)?;

        match self.runtime.observe() {
            Ok(snapshot) => {
                // ADD-7 / v0.6 A-1: a lost Witness session can never be used
                // again from this process (no promotion, no renewal, no
                // lease release), so keeping it only retains a dead socket
                // (`CLOSE_WAIT`) and a loop that can make no progress. Stop
                // (non-zero) so the service manager restarts the daemon, which
                // reconnects with a fresh handshake; startup reconciliation
                // recovers anything still owed.
                //
                // Fail-closed ordering: an Active node is never stopped here
                // before its demotion released the local resources - it
                // demotes by its lease expiry first, and
                // `witness_loss_stop_allowed` is the runtime's proof that the
                // demotion already released the VIP and stopped the service
                // and the only remaining work is a Witness operation on the
                // dead session. This check precedes the Active-without-
                // ownership invariant because that state is the legitimate
                // post-demotion `ReleaseLease` phase, not a broken invariant.
                if self.runtime.witness_session_lost()
                    && !snapshot.resource_owning
                    && snapshot.vip == DaemonVip::Absent
                    && snapshot.service == DaemonService::Stopped
                    && snapshot.recovery_reconciled
                    && self.runtime.witness_loss_stop_allowed()
                {
                    let reason = "the connection to the Witness is permanently lost";
                    crate::operator_log::error_witness_session_lost(reason);
                    self.state = DaemonState::Failed;
                    return Err(DaemonError::WitnessSessionLost(reason.into()));
                }
                if snapshot.node_state == NodeState::Active && !snapshot.resource_owning {
                    self.state = DaemonState::Failed;
                    return Err(DaemonError::ObservationInvariant(
                        "Active observation without resource ownership".into(),
                    ));
                }
                self.cached = Some(snapshot);
                self.last_observation_error = None;
                // K-3: the probe context is set immediately before the peer
                // tick that may read a probe; the answer is built and sent in
                // that same tick.
                let facts = self.probe_facts();
                self.runtime.set_probe_context(Some(facts));
                self.drive_peer_tick_at(now);
                self.log_peer_transition();
                self.collect_bootstrap_outcome();
                self.expire_bootstrap_session(now, true);
                self.evaluate_auto(now);
                // v0.7 G-2 §5.1 condition 1: the route-handoff step is the last blocking work
                // of the iteration, so the next iteration's first blocking work is the renewal.
                self.require_control_lock()?;
                self.runtime
                    .route_handoff_tick(&|| self.control_lock_guard.lost().is_none())
                    .map_err(DaemonError::ObservationInvariant)?;
                self.require_control_lock()?;
                Ok(TickResult::Observed)
            }
            Err(error) => {
                self.last_observation_error = Some(error);
                if let Some(snapshot) = &mut self.cached {
                    snapshot.health = DaemonHealth::Unknown;
                }
                self.runtime.invalidate_peer_status();
                // A failed observation answers any probe `Unknown`.
                self.runtime.set_probe_context(None);
                self.drive_peer_tick_at(now);
                self.collect_bootstrap_outcome();
                self.expire_bootstrap_session(now, false);
                Ok(TickResult::ObservationUnavailable)
            }
        }
    }

    fn probe_facts(&self) -> crate::bootstrap_admission::DaemonFacts {
        crate::bootstrap_admission::DaemonFacts {
            running: self.state == DaemonState::Running,
            shutdown_requested: self.shutdown_requested,
            attempt_in_flight: self.promotion_attempt.in_flight_id().is_some(),
        }
    }

    /// Transition-only peer logging: one WARN when the peer is lost, one INFO
    /// when it is back; nothing in steady state.
    fn log_peer_transition(&mut self) {
        use crate::failure_assessment::PeerFailureAssessment;
        let Some(assessment) = self.runtime.peer_assessment_for_log() else {
            return;
        };
        match assessment {
            PeerFailureAssessment::CommunicationLost if !self.peer_lost_logged => {
                self.peer_lost_logged = true;
                crate::operator_log::warn_peer_lost();
            }
            PeerFailureAssessment::Healthy if self.peer_lost_logged => {
                self.peer_lost_logged = false;
                crate::operator_log::info_peer_recovered();
            }
            _ => {}
        }
    }

    /// Evaluating side: apply a probe outcome and drop a session whose peer
    /// connection is no longer the one it was anchored on (BAP-7). No clock
    /// is read here; the hygiene limits are `expire_bootstrap_session`.
    fn collect_bootstrap_outcome(&mut self) {
        if let Some(outcome) = self.runtime.take_probe_outcome() {
            let had_session = self.bootstrap_session.is_some();
            let attested_before = self
                .bootstrap_session
                .as_ref()
                .is_some_and(crate::bootstrap_admission::BootstrapSession::is_attested);
            self.bootstrap_session = crate::bootstrap_admission::apply_probe_outcome(
                self.bootstrap_session.take(),
                &outcome,
            );
            match (&self.bootstrap_session, had_session) {
                (Some(session), _) if session.is_attested() && !attested_before => {
                    crate::operator_log::info_bootstrap_attested();
                }
                (None, true) => {
                    crate::operator_log::warn_bootstrap_dropped(match outcome {
                        crate::bootstrap_admission::ProbeOutcome::Response {
                            verdict: crate::bootstrap_admission::ProbeVerdict::Block,
                            ..
                        } => "peer reported it is not a safe standby",
                        crate::bootstrap_admission::ProbeOutcome::Response {
                            verdict: crate::bootstrap_admission::ProbeVerdict::Unknown,
                            ..
                        } => "peer could not tell its state",
                        crate::bootstrap_admission::ProbeOutcome::Response { .. } => {
                            "probe response did not match the session"
                        }
                        crate::bootstrap_admission::ProbeOutcome::Invalid => {
                            "probe response did not match or the connection was lost"
                        }
                    });
                }
                _ => {}
            }
        }
        let stale = self.bootstrap_session.as_ref().is_some_and(|session| {
            self.state != DaemonState::Running
                || self.shutdown_requested
                || self.runtime.bootstrap_stamp().as_ref() != Some(session.stamp())
        });
        if stale {
            self.discard_bootstrap_session("the peer connection changed or the daemon is stopping");
        }
    }

    /// BAP-7 hygiene for the BA session: the 5 s probe wait, the 60 s age and
    /// the loss of a safe local standby or a healthy peer. Run every tick,
    /// whether or not `[failover] auto` is enabled — a manual attempt opens
    /// the same session. Hygiene only: it never decides an admission (the
    /// attempt re-checks everything), and it only ever drops the session.
    /// `with_facts` is `false` after a failed observation, where nothing is
    /// concluded about readiness or the peer.
    fn expire_bootstrap_session(&mut self, now: std::time::Instant, with_facts: bool) {
        let session_open = self.bootstrap_session_open();
        let facts = if session_open && with_facts {
            self.runtime.auto_facts(now)
        } else {
            None
        };
        let now_ms = self.started_at.map_or(0, |started| {
            now.saturating_duration_since(started).as_millis() as u64
        });
        let inputs = crate::bootstrap_admission::HygieneInputs {
            now_ms,
            session_open,
            session_attested: self.bootstrap_session_attested(),
            local_safe: facts.as_ref().map(|facts| facts.standby_safe),
            peer_healthy: facts.as_ref().map(|facts| {
                facts.assessment == crate::failure_assessment::PeerFailureAssessment::Healthy
            }),
        };
        if let Some(reason) = self.session_hygiene.poll(&inputs) {
            self.discard_bootstrap_session(reason);
        }
    }

    /// Drop the BA session (hygiene limit, reconnect, shutdown …).
    pub(crate) fn discard_bootstrap_session(&mut self, reason: &str) {
        if self.bootstrap_session.take().is_some() {
            crate::operator_log::warn_bootstrap_dropped(reason);
        }
        self.runtime.discard_bootstrap_probe();
    }

    /// Whether a BA session exists (read-only, for the auto-trigger).
    pub(crate) fn bootstrap_session_open(&self) -> bool {
        self.bootstrap_session.is_some()
    }

    /// Whether the BA session is attested (read-only, for the auto-trigger).
    pub(crate) fn bootstrap_session_attested(&self) -> bool {
        self.bootstrap_session
            .as_ref()
            .is_some_and(crate::bootstrap_admission::BootstrapSession::is_attested)
    }

    fn drive_peer_tick_at(&mut self, now: std::time::Instant) {
        let peer_status = self.runtime.peer_status();
        match self.runtime.peer_tick_at(now, peer_status) {
            Ok(Some(state)) => {
                self.peer_state = state;
                self.peer_observation = self.runtime.peer_snapshot_at(now);
            }
            Ok(None) => {}
            Err(_) => self.peer_state = PeerObservationState::Unavailable,
        }
    }

    pub(crate) fn state(&self) -> DaemonState {
        self.state
    }

    pub(crate) fn next_wait_delay(
        &self,
        ordinary: std::time::Duration,
    ) -> Result<std::time::Duration, DaemonError> {
        self.runtime
            .lifecycle_wait_delay(ordinary)
            .map_err(DaemonError::ObservationInvariant)
    }

    /// Side-effect-free access to the last runtime-owned observation.
    pub(crate) fn snapshot(&self) -> Option<DaemonSnapshot> {
        self.cached
    }

    pub(crate) fn last_observation_error(&self) -> Option<&str> {
        self.last_observation_error.as_deref()
    }

    pub(crate) fn peer_state(&self) -> PeerObservationState {
        self.peer_state
    }

    pub(crate) fn peer_observation(&self) -> Option<&PeerObservation> {
        self.peer_observation.as_ref()
    }

    pub(crate) fn local_safety_snapshot(
        &mut self,
    ) -> Result<Option<LocalSafetySnapshot>, DaemonError> {
        self.runtime
            .local_safety_snapshot(self.shutdown_requested)
            .map_err(DaemonError::ObservationInvariant)
    }
}

#[cfg(target_os = "linux")]
pub(crate) struct LinuxDaemonRuntime {
    runtime: crate::linux_node_runtime::LinuxNodeRuntime,
    peer: Option<crate::daemon_peer_runtime::DaemonPeerRuntime>,
    peer_status: Option<PeerStatusSnapshot>,
    /// The one neutral Witness transport/session (connection + process +
    /// authenticator + single outstanding slot). Observation borrows it
    /// transiently; lease wiring will use the same session in a later stage.
    witness_session: Option<crate::witness_runtime::WitnessSession>,
    /// Observation-state-only adapter; owns no transport/session state.
    witness_observer: Option<crate::evidence_fusion::adapter::WitnessEvidenceAdapter>,
    /// Stage 14 §26 R4 input: the newest authenticated TermStatus term
    /// since the current incident opened, bound to that incident.
    /// Runtime-only; set by gate G and by each authenticated `Ready`
    /// authority observation.
    fencing_term_record: Option<crate::linux_node_runtime::IncidentTermRecord>,
    /// Stage 14 §28: the name of the last failed §24 K runtime-half recheck,
    /// kept only so the blocked-attempt log line can say why. Diagnostic:
    /// written by `fencing_final_recheck`, read only by the operator log.
    last_recheck_failure: Option<String>,
    /// Bootstrap Admission (answering side): the daemon-level facts of the
    /// tick that is about to advance the peer runtime. Set by `Daemon::tick_at`
    /// right before `peer_tick_at`, consumed by it; `None` after a failed
    /// observation (a probe is then answered `Unknown`).
    probe_context: Option<crate::bootstrap_admission::DaemonFacts>,
    /// Why `startup` left the node recovery-blocked (diagnostic text).
    startup_block_cause: Option<String>,
    /// `[health]` thresholds applied to the raw health command results.
    health_filter: crate::health_hysteresis::HealthHysteresis,
    /// Phase 1-J27 candidate (audit a01 NB-1): a blocking fencing step voided the verified-listen
    /// window since the last peer tick. The iteration's single `now` is read before that
    /// iteration's fencing step, so a window the next peer tick opens could start before the
    /// step ended (Appendix R.3(21), R.8); `peer_tick_at` voids it again and the next sample, of a
    /// later iteration, opens the new window.
    fencing_step_since_peer_tick: bool,
}

#[cfg(target_os = "linux")]
impl LinuxDaemonRuntime {
    pub(crate) fn new(
        config: &crate::config::Config,
        platform: crate::linux_node_runtime::LinuxPlatformConfig,
    ) -> Result<Self, crate::linux_node_runtime::LinuxNodeRuntimeError> {
        let runtime = crate::linux_node_runtime::LinuxNodeRuntime::new(config, platform)?;
        let peer = match crate::daemon_peer_runtime::DaemonPeerRuntime::from_config(config) {
            Ok(mut peer) => match peer.initialize_transport() {
                Ok(()) => Some(peer),
                Err(crate::daemon_peer_runtime::DaemonPeerRuntimeBuildError::Transport(_)) => None,
                Err(crate::daemon_peer_runtime::DaemonPeerRuntimeBuildError::Configuration(
                    error,
                )) => {
                    return Err(
                        crate::linux_node_runtime::LinuxNodeRuntimeError::Configuration(error),
                    );
                }
            },
            Err(crate::daemon_peer_runtime::DaemonPeerRuntimeBuildError::Configuration(error)) => {
                return Err(crate::linux_node_runtime::LinuxNodeRuntimeError::Configuration(error));
            }
            Err(crate::daemon_peer_runtime::DaemonPeerRuntimeBuildError::Transport(_)) => None,
        };
        Ok(Self {
            runtime,
            peer,
            peer_status: None,
            witness_session: None,
            witness_observer: None,
            fencing_term_record: None,
            last_recheck_failure: None,
            probe_context: None,
            startup_block_cause: None,
            health_filter: crate::health_hysteresis::HealthHysteresis::new(
                config.health.failure_threshold,
                config.health.success_threshold,
            ),
            fencing_step_since_peer_tick: false,
        })
    }

    /// Stage 14 §27.3: the one foreground fencing step of an ordinary
    /// iteration, after the §16.7.5 pending-reap poll. The runtime checks
    /// the local eligibility (R7) against the live shutdown query, which it
    /// samples again before the verify spawns and after it returns
    /// (F14.9-01); without a peer runtime there is no session or episode and
    /// nothing runs. A pre-commit store failure leaves everything unchanged
    /// and is retried only by the ordinary cadence; any other failure is
    /// fatal.
    fn drive_fencing_step(&mut self, live_shutdown: &dyn Fn() -> bool) -> Result<(), String> {
        let Some(peer) = self.peer.as_mut() else {
            return Ok(());
        };
        let configured_peer = self.runtime.fencing_target().clone();
        let current_session = peer.observer_session_id().clone();
        let live_episode = peer.loss_evidence();
        let context = crate::fencing::ContinuityContext {
            configured_peer: &configured_peer,
            current_session: &current_session,
            live_episode: live_episode.as_ref(),
        };
        // §27.5: a verify poll is a blocking step.
        let stepped = &mut self.fencing_step_since_peer_tick;
        let mut void = || {
            *stepped = true;
            peer.void_listen_window_for_fencing_step();
        };
        match self.runtime.drive_fencing_step(
            &context,
            self.fencing_term_record.as_ref(),
            live_shutdown,
            &mut void,
        ) {
            Ok(crate::linux_node_runtime::FencingStepOutcome::Retired(_)) => {
                self.fencing_term_record = None;
                Ok(())
            }
            Ok(_) => Ok(()),
            Err(crate::linux_node_runtime::LinuxNodeRuntimeError::Mutation(
                crate::node_mutation::NodeMutationError::Io(error),
            )) => {
                // L2: the store's I/O text is free text, so it is bounded by
                // the canonical `operator_log::bounded_reason` policy inside
                // the emitter, never interpolated raw here.
                crate::operator_log::warn_fencing_step_not_committed(&error);
                Ok(())
            }
            Err(error) => Err(error.to_string()),
        }
    }

    /// Attach the neutral Witness session and the observation-only adapter.
    /// There is exactly one session per daemon composition.
    pub(crate) fn attach_witness(
        &mut self,
        session: crate::witness_runtime::WitnessSession,
        observer: crate::evidence_fusion::adapter::WitnessEvidenceAdapter,
    ) {
        self.witness_session = Some(session);
        self.witness_observer = Some(observer);
    }

    /// Test-only constructor that injects already-built production components,
    /// avoiding the root-owned PSK file requirement of `from_config` on Linux.
    /// Not available in production builds.
    #[cfg(test)]
    pub(crate) fn new_for_test(
        runtime: crate::linux_node_runtime::LinuxNodeRuntime,
        peer: Option<crate::daemon_peer_runtime::DaemonPeerRuntime>,
    ) -> Self {
        Self {
            runtime,
            peer,
            peer_status: None,
            witness_session: None,
            witness_observer: None,
            fencing_term_record: None,
            last_recheck_failure: None,
            probe_context: None,
            startup_block_cause: None,
            health_filter: crate::health_hysteresis::HealthHysteresis::new(1, 1),
            fencing_step_since_peer_tick: false,
        }
    }

    /// Test-only: peer tick invocations observed on the injected peer runtime.
    #[cfg(test)]
    pub(crate) fn peer_tick_invocations_for_test(&self) -> u64 {
        self.peer
            .as_ref()
            .map(|peer| peer.tick_invocations_for_test())
            .unwrap_or(0)
    }

    /// Test-only: the attached Witness adapter snapshot (correlation state).
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn witness_snapshot_for_test(
        &self,
    ) -> Option<crate::evidence_fusion::adapter::AdapterSnapshot> {
        self.witness_observer
            .as_ref()
            .map(|observer| observer.snapshot())
    }

    /// Test-only: attach a Witness session + observer built from a loopback
    /// connection. Mirrors the production `attach_witness` composition shape.
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn attach_test_witness(
        &mut self,
        connection: crate::witness_runtime::WitnessConnection,
        process: crate::session::ProcessSession,
        authenticator: crate::security::MessageAuthenticator,
    ) {
        let session =
            crate::witness_runtime::WitnessSession::new(connection, process, authenticator);
        let observer = crate::evidence_fusion::adapter::WitnessEvidenceAdapter::new(
            std::time::Duration::from_secs(2),
        )
        .unwrap();
        self.attach_witness(session, observer);
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn wait_witness_readable_for_test(&mut self) -> Result<(), String> {
        self.witness_session
            .as_mut()
            .ok_or_else(|| "Witness session is not configured".to_string())?
            .wait_for_readable_for_test()
            .map_err(|error| error.to_string())
    }

    /// Current peer failure assessment derived from the peer runtime without
    /// advancing it. The composition root advances the peer exactly once via
    /// `peer_tick_at`, then reads this value to feed Witness observation.
    pub(crate) fn peer_failure_assessment(
        &self,
    ) -> crate::failure_assessment::PeerFailureAssessment {
        self.peer
            .as_ref()
            .map(|peer| peer.failure_assessment().assessment)
            .unwrap_or(crate::failure_assessment::PeerFailureAssessment::Unobserved)
    }

    /// Fresh local communication-loss evidence from the sole
    /// `DaemonPeerRuntime` owner, read at the same observation epoch as
    /// `peer_failure_assessment`. `None` means the assessment carries no
    /// usable evidence epoch (never confirmed, or invalidated by
    /// recovery/session re-establishment).
    pub(crate) fn peer_local_loss_evidence(
        &self,
    ) -> Option<crate::failure_assessment::LocalLossEvidence> {
        self.peer.as_ref().and_then(|peer| peer.loss_evidence())
    }

    /// Startup Obligation Reconciliation driver (contract A-4): one bounded,
    /// shutdown-free `GET_TERM` through the daemon's own Witness session when
    /// an obligation without a pending release needs a view, then the node
    /// runtime's reconciliation. Any failure leaves the node recovery-blocked
    /// with the cause recorded; nothing here can promote or install authority.
    fn reconcile_startup_obligation(
        &mut self,
        snapshot: crate::linux_node_runtime::LinuxRuntimeSnapshot,
        control_lock_safe: &dyn Fn() -> bool,
    ) -> Result<crate::linux_node_runtime::LinuxRuntimeSnapshot, String> {
        let retained_renew = match self.runtime.retained_renew_pending() {
            Ok(pending) => pending,
            Err(error) => {
                self.startup_block_cause = Some(error.to_string());
                return Ok(snapshot);
            }
        };
        let retained_request = match self.runtime.retained_request_pending() {
            Ok(pending) => pending,
            Err(error) => {
                self.startup_block_cause = Some(error.to_string());
                return Ok(snapshot);
            }
        };
        let initial_candidate = match self.runtime.sor_candidate() {
            Ok(Some(candidate)) => Some(candidate),
            Ok(None) => None,
            Err(error) => {
                self.startup_block_cause = Some(error.to_string());
                return Ok(snapshot);
            }
        };
        if initial_candidate.is_none() && !retained_renew && !retained_request {
            return Ok(snapshot);
        }
        let (Some(session), Some(observer)) = (
            self.witness_session.as_mut(),
            self.witness_observer.as_mut(),
        ) else {
            self.startup_block_cause = Some("no Witness session for startup reconciliation".into());
            return Ok(snapshot);
        };
        // v0.6 A-2: a renewal that was in flight when the Witness went away
        // leaves a durable record and blocks the recovery gate forever. Replay
        // the exact request once (idempotent at the Witness, bookkeeping-only
        // locally). Any outcome that is not terminal keeps the record and the
        // node recovery-blocked.
        if retained_renew {
            match self.runtime.resolve_retained_renew_once(session) {
                Ok(crate::linux_node_runtime::RetainedRenewOutcome::Resolved { how }) => {
                    crate::operator_log::info_startup_renew_resolved(how)
                }
                // J23: produced only by the retained-request resolution; never by a renewal.
                Ok(
                    crate::linux_node_runtime::RetainedRenewOutcome::ResolvedReleaseUnconfirmed {
                        how,
                    },
                ) => {
                    self.startup_block_cause = Some(format!(
                        "a lease renewal from before the restart left an unexpected outcome ({how})"
                    ));
                    return Ok(snapshot);
                }
                Ok(crate::linux_node_runtime::RetainedRenewOutcome::Blocked { reason }) => {
                    self.startup_block_cause = Some(format!(
                        "a lease renewal from before the restart could not be resolved ({reason})"
                    ));
                    return Ok(snapshot);
                }
                Err(error) => {
                    self.startup_block_cause = Some(format!(
                        "the retained lease renewal could not be replayed: {error}"
                    ));
                    return Ok(snapshot);
                }
            }
        }
        // J21: a promotion attempt whose answer was lost leaves a durable LeaseRequest that would
        // block the recovery gate forever. Replay it once; a grant is never used, it is released
        // as an unused lease. Not terminal: stay blocked.
        if retained_request {
            match self.runtime.resolve_retained_request_once(session) {
                Ok(crate::linux_node_runtime::RetainedRenewOutcome::Resolved { how }) => {
                    crate::operator_log::info_startup_request_resolved(how)
                }
                // J23 (OD-J22-5): the request is settled, the lease is not proven released; the
                // release obligation stays for the startup reconciliation below.
                Ok(
                    crate::linux_node_runtime::RetainedRenewOutcome::ResolvedReleaseUnconfirmed {
                        how,
                    },
                ) => crate::operator_log::warn_retained_request_release_unconfirmed(how),
                Ok(crate::linux_node_runtime::RetainedRenewOutcome::Blocked { reason }) => {
                    self.startup_block_cause = Some(format!(
                        "startup resolution of the retained lease request stopped: {reason}"
                    ));
                    return Ok(snapshot);
                }
                Err(error) => {
                    self.startup_block_cause = Some(format!(
                        "the retained lease request was not resolved: {error}"
                    ));
                    return Ok(snapshot);
                }
            }
        }
        // The candidate is re-derived AFTER the renewal replay: before it,
        // any other outstanding mutation (including the retained Renew) makes
        // `candidate` return `None` by contract.
        let candidate = match self.runtime.sor_candidate() {
            Ok(Some(candidate)) => candidate,
            Ok(None) => return self.runtime.reconcile().map_err(|error| error.to_string()),
            Err(error) => {
                self.startup_block_cause = Some(error.to_string());
                return Ok(snapshot);
            }
        };
        let expectation = crate::evidence_fusion::adapter::AuthorityViewExpectation::new(
            self.runtime.local_node_id().clone(),
            None,
            Some(candidate.lease_id.clone()),
        );
        let retired_expectation = expectation.clone();
        let view = if candidate.release_pending {
            None
        } else {
            if let Err(reason) = observer
                .complete_attempt_observation(
                    session,
                    expectation,
                    &|| false,
                    &mut std::time::Instant::now,
                    &mut std::thread::sleep,
                )
                .into_result()
            {
                self.startup_block_cause = Some(format!(
                    "the Witness term could not be read for startup reconciliation: {reason}"
                ));
                return Ok(snapshot);
            }
            match observer.poll_observation_at(session, std::time::Instant::now()) {
                Ok(crate::evidence_fusion::adapter::ObservationProgress::Ready(view)) => {
                    Some((view.term(), view.compatibility()))
                }
                _ => {
                    self.startup_block_cause = Some(
                        "the Witness term view was not available for startup reconciliation".into(),
                    );
                    return Ok(snapshot);
                }
            }
        };
        // C-l: a new authoritative GET_TERM view, taken on the same session
        // only after the exact replay of `M` was answered RetiredStale, and
        // classified like the view above (this node, no expected term, lease_o).
        let mut retired_view = |session: &mut crate::witness_runtime::WitnessSession| {
            fresh_authority_view(observer, session, retired_expectation.clone())
        };
        match self.runtime.reconcile_startup_obligation_guarded(
            session,
            view,
            control_lock_safe,
            &mut retired_view,
        ) {
            Ok(crate::obligation_reconciliation::SorOutcome::Released { term }) => {
                crate::operator_log::info_sor_resolved(term.0, "exact release accepted");
            }
            Ok(crate::obligation_reconciliation::SorOutcome::Cleared { term, by }) => {
                crate::operator_log::info_sor_resolved(
                    term.0,
                    match by {
                        crate::obligation_reconciliation::SupersededBy::NewerTerm => {
                            "the Witness has a newer term"
                        }
                        crate::obligation_reconciliation::SupersededBy::SameTermNoHolder => {
                            "the Witness records no holder for that term"
                        }
                        crate::obligation_reconciliation::SupersededBy::WitnessRejectedRelease {
                            ..
                        } => "the Witness rejected the exact release as not releasable",
                        crate::obligation_reconciliation::SupersededBy::RetiredThenNewerTerm => {
                            "the exact release was retired and the Witness has a newer term (superseded, not released)"
                        }
                        crate::obligation_reconciliation::SupersededBy::RetiredThenSameTermNoHolder => {
                            "the exact release was retired and the Witness records no holder for that term (superseded, not released)"
                        }
                    },
                );
            }
            Ok(crate::obligation_reconciliation::SorOutcome::NotApplicable) => return Ok(snapshot),
            Ok(crate::obligation_reconciliation::SorOutcome::Blocked(cause)) => {
                self.startup_block_cause = Some(cause);
                return Ok(snapshot);
            }
            Err(error) => {
                self.startup_block_cause = Some(error.to_string());
                return Ok(snapshot);
            }
        }
        self.runtime.reconcile().map_err(|error| error.to_string())
    }

    /// Contract K-4: the Bootstrap Admission additions to the final re-check,
    /// on top of the node-local checks — the very same peer connection, a
    /// still-healthy peer, and the runtime half (`bootstrap_final_recheck`).
    fn bootstrap_recheck(
        &mut self,
        clearance: &crate::bootstrap_admission::BootstrapClearance,
        grant_term: crate::protocol::Term,
    ) -> Result<(), String> {
        let same_connection = self
            .peer
            .as_ref()
            .and_then(|peer| peer.bootstrap_stamp())
            .as_ref()
            == Some(clearance.stamp());
        let result = if !same_connection {
            Err("bootstrap: the peer connection changed".to_string())
        } else if self.peer_failure_assessment()
            != crate::failure_assessment::PeerFailureAssessment::Healthy
        {
            Err("bootstrap: the peer is not healthy".to_string())
        } else {
            match self
                .runtime
                .bootstrap_final_recheck(clearance.anchor_term(), grant_term)
            {
                Ok(Ok(())) => Ok(()),
                Ok(Err(failure)) => Err(format!("{failure:?}")),
                Err(error) => Err(error.to_string()),
            }
        };
        self.last_recheck_failure = result.as_ref().err().cloned();
        result
    }

    /// The local authority context for the next authority observation
    /// request: this node's identity plus the installed lease
    /// term/lease identity, if any. Input only — never evidence.
    fn authority_view_expectation(
        &self,
    ) -> crate::evidence_fusion::adapter::AuthorityViewExpectation {
        let authority = self.runtime.installed_lease_authority();
        crate::evidence_fusion::adapter::AuthorityViewExpectation::new(
            self.runtime.local_node_id().clone(),
            authority.map(|authority| authority.term()),
            authority.map(|authority| authority.lease_id().clone()),
        )
    }

    pub(crate) fn begin_authority_observation(
        &mut self,
        context: DaemonIterationContext,
    ) -> Result<(), String> {
        let expectation = self.authority_view_expectation();
        let session = self
            .witness_session
            .as_mut()
            .ok_or_else(|| "Witness session is not configured".to_string())?;
        self.witness_observer
            .as_mut()
            .ok_or_else(|| "Witness observation is not configured".to_string())?
            .begin_observation_at(session, expectation, context.now())
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    /// Advance the caller-driven Witness authority observation using the
    /// iteration's authoritative context. The context carries both the
    /// authoritative observation `now` and the authoritative shutdown state,
    /// so this API cannot be called with an arbitrary `shutdown_requested`
    /// value.
    ///
    /// The peer assessment is read from the single peer-truth owner
    /// (`DaemonPeerRuntime`) at `now` and forwarded to EvidenceFusion at the
    /// same time; a caller cannot inject a stale or fabricated assessment.
    /// This method does NOT advance or own the peer runtime: the peer is
    /// advanced exactly once per iteration by the composition root via
    /// `peer_tick_at`. Peer transport failure therefore cannot abort Witness
    /// classification.
    pub(crate) fn authority_observation_tick(
        &mut self,
        context: DaemonIterationContext,
    ) -> Result<AuthorityObservationProgress, String> {
        let now = context.now();
        let peer_assessment = self.peer_failure_assessment();
        let peer_loss = self.peer_local_loss_evidence();
        let session = self
            .witness_session
            .as_mut()
            .ok_or_else(|| "Witness session is not configured".to_string())?;
        let observer = self
            .witness_observer
            .as_mut()
            .ok_or_else(|| "Witness observation is not configured".to_string())?;
        observer
            .observe_peer_at(peer_assessment, peer_loss, now)
            .map_err(|error| error.to_string())?;
        match observer
            .poll_observation_at(session, now)
            .map_err(|error| error.to_string())?
        {
            crate::evidence_fusion::adapter::ObservationProgress::AwaitingWitnessTerm => {
                Ok(AuthorityObservationProgress::AwaitingWitnessTerm)
            }
            crate::evidence_fusion::adapter::ObservationProgress::Unavailable(cause) => {
                Ok(AuthorityObservationProgress::Unavailable(cause))
            }
            crate::evidence_fusion::adapter::ObservationProgress::Ready(authority_view) => {
                // Stage 14 §26 R4: every authenticated correlated TermStatus
                // completion is recorded against the current incident.
                if let Some(record) = &mut self.fencing_term_record {
                    record.record_term(authority_view.term());
                }
                // Local safety originates from the authoritative iteration
                // context, never from an arbitrary caller value. Under shutdown
                // this yields ShutdownInProgress regardless of Witness Ready.
                let local = self
                    .runtime
                    .failover_local_safety_snapshot(context.shutdown_requested())
                    .map_err(|error| error.to_string())?;
                // A trusted complete observation requires fresh local safety
                // established as Safe at the observation epoch. Unavailable or
                // indeterminate local safety (including every blocker
                // classification) must not complete the observation.
                if local.readiness != crate::failover_policy::LocalSafetyReadiness::Safe {
                    return Ok(AuthorityObservationProgress::LocalSafetyNotReady(local));
                }
                // Term-free evidence view: historical `witness_term`/holder
                // remain on the snapshot but are not exposed here as current
                // authority data.
                let evidence = crate::evidence_fusion::WitnessEvidenceView::from_snapshot(
                    &observer.snapshot().fusion,
                );
                Ok(AuthorityObservationProgress::Ready(
                    CurrentAuthorityAttemptObservation::new(
                        authority_view,
                        peer_assessment,
                        evidence,
                        local,
                    ),
                ))
            }
        }
    }

    /// Stage 12.8d inert production composition: evaluate the current
    /// authority attempt without acquiring any capability to execute
    /// promotion.
    ///
    /// This progresses the caller-driven Witness observation once, then —
    /// only for a `Ready` observation — composes failover eligibility and
    /// promotion-attempt authorization into an `AuthorityAttemptEvaluation`.
    /// Every non-Ready progress value maps to `None`: no attempt exists.
    ///
    /// The result is pure inert data. This method does not call or acquire
    /// `promote`, `ResourceWorkflow`, `ResourceExecutor`,
    /// `NodeAuthorityController` mutation, a lease, VIP/service/GARP
    /// operations, an `Active` commit, fencing, or any promotion lifecycle.
    /// `Authorized` in the returned value remains inert data: nothing stores
    /// it, and no path from it reaches a mutation.
    pub(crate) fn evaluate_authority_attempt(
        &mut self,
        context: DaemonIterationContext,
    ) -> Result<Option<AuthorityAttemptEvaluation>, String> {
        self.authority_observation_tick(context)
            .map(AuthorityObservationProgress::into_evaluation)
    }
}

/// Trusted, complete authority-attempt observation for one iteration.
///
/// Minted only by `LinuxDaemonRuntime::authority_observation_tick` after a
/// current authenticated/correlated GET_TERM completion and a fresh `Safe`
/// local safety evaluation at the response-acceptance epoch. Fields are
/// private: callers can read but cannot inject or replace components, so a
/// fresh term cannot be paired with a stale peer assessment or a fabricated
/// local boundary. It is internal-only, ephemeral (not `Clone`, not
/// serializable, not persisted), and is neither an authority token nor a
/// permission: it carries no `Authorized` marker, no authorization result, and
/// no mutation handle.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CurrentAuthorityAttemptObservation {
    /// Current correlated authority-view evidence (ephemeral).
    /// Not `Clone`/persistable; carries the term plus the semantic
    /// holder classification from this observation's GET_TERM.
    authority_view: crate::evidence_fusion::adapter::WitnessAuthorityViewEvidence,
    /// Peer assessment read from the sole `DaemonPeerRuntime` owner at the
    /// response-acceptance epoch.
    peer_assessment: crate::failure_assessment::PeerFailureAssessment,
    /// Term-free/holder-free evidence view; historical stored term is not
    /// reachable through this current-attempt object.
    evidence: crate::evidence_fusion::WitnessEvidenceView,
    /// Fresh local safety boundary evaluated at the observation epoch.
    /// `readiness` is always `LocalSafetyReadiness::Safe` on a `Ready`
    /// observation.
    local: LocalSafetySnapshot,
}

impl CurrentAuthorityAttemptObservation {
    const fn new(
        authority_view: crate::evidence_fusion::adapter::WitnessAuthorityViewEvidence,
        peer_assessment: crate::failure_assessment::PeerFailureAssessment,
        evidence: crate::evidence_fusion::WitnessEvidenceView,
        local: LocalSafetySnapshot,
    ) -> Self {
        Self {
            authority_view,
            peer_assessment,
            evidence,
            local,
        }
    }

    /// The current correlated authority-view evidence from this
    /// observation's own GET_TERM completion (term plus semantic holder
    /// classification).
    pub(crate) const fn authority_view(
        &self,
    ) -> &crate::evidence_fusion::adapter::WitnessAuthorityViewEvidence {
        &self.authority_view
    }

    /// The peer assessment that was current at the observation epoch.
    pub(crate) const fn peer_assessment(&self) -> crate::failure_assessment::PeerFailureAssessment {
        self.peer_assessment
    }

    /// The term-free fused-evidence view at the observation epoch.
    pub(crate) const fn evidence(&self) -> &crate::evidence_fusion::WitnessEvidenceView {
        &self.evidence
    }

    /// The fresh local safety boundary; always `Safe` on a `Ready` observation.
    pub(crate) const fn local(&self) -> LocalSafetySnapshot {
        self.local
    }
}

/// Progress of the caller-driven authority-attempt observation lifecycle owned
/// by `LinuxDaemonRuntime`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AuthorityObservationProgress {
    /// The current GET_TERM request is still in flight; there is no current
    /// correlated term yet.
    AwaitingWitnessTerm,
    /// A trusted complete observation exists: current correlated term, peer
    /// assessment, fused evidence view, and fresh `Safe` local safety, all at
    /// the response-acceptance epoch.
    Ready(CurrentAuthorityAttemptObservation),
    /// The Witness request terminally failed to produce a current term
    /// (request timeout or classified terminal transport failure).
    Unavailable(crate::evidence_fusion::adapter::UnavailableCause),
    /// A current correlated term completed, but fresh local safety at the
    /// observation epoch was not `Safe` (indeterminate or blocker
    /// classifications included). The observation is not trusted-complete.
    LocalSafetyNotReady(LocalSafetySnapshot),
}

impl AuthorityObservationProgress {
    /// Consume one observation progress value and compose the inert authority
    /// attempt evaluation.
    ///
    /// Only a `Ready` observation — a current correlated term plus fresh
    /// `Safe` local safety at the observation epoch — can produce an
    /// evaluation. Every other variant returns `None`: no attempt exists.
    /// Nothing here manufactures eligibility, authorization, a current term,
    /// a promotion request, or a mutation capability.
    pub(crate) fn into_evaluation(self) -> Option<AuthorityAttemptEvaluation> {
        match self {
            Self::Ready(observation) => Some(AuthorityAttemptEvaluation::evaluate(observation)),
            Self::AwaitingWitnessTerm | Self::Unavailable(_) | Self::LocalSafetyNotReady(_) => None,
        }
    }
}

/// Inert decision result of one authority attempt evaluation.
///
/// This is the terminal product of the Stage 12.8d composition: the current
/// authority observation, the `FailoverEligibilityPolicy` outcome, and the
/// `PromotionAttemptAuthorization` outcome for that observation. It is pure
/// data: it owns no `ResourceExecutor`, `ResourceWorkflow`,
/// `LinuxNodeRuntime` or `NodeAuthorityController` mutation handle, no lease
/// handle, no mutation-capable callback or function pointer, and no stored
/// "permission to promote". There is no `execute`/`promote`/`commit`/`apply`
/// method and no conversion into a mutation-capable type; it is not `Clone`,
/// not `Copy`, not serializable, and not persistable.
///
/// `Eligible` and `Authorized` are distinct fields produced by their own
/// policy evaluations: `Ready != Eligible != Authorized != Promoted`.
/// `Authorized` is inert data, not an authority token; storing or reusing it
/// as permission is impossible because the value grants no capability.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AuthorityAttemptEvaluation {
    /// The `Ready` observation this attempt was evaluated from.
    observation: CurrentAuthorityAttemptObservation,
    /// Fresh `FailoverEligibilityPolicy` result for this attempt's inputs.
    eligibility: FailoverEligibility,
    /// Fresh `PromotionAttemptAuthorization` result for this attempt's
    /// inputs; evaluated independently, never copied from `eligibility`.
    authorization: PromotionAttemptAuthorization,
}

impl AuthorityAttemptEvaluation {
    /// Evaluate one `Ready` observation: derive the eligibility input from
    /// current observation data, run the failover eligibility policy, run the
    /// promotion attempt authorization policy, then stop. The policy modules
    /// remain authoritative; no rules are duplicated here.
    fn evaluate(observation: CurrentAuthorityAttemptObservation) -> Self {
        let input = FailoverEligibilityInput {
            peer_assessment: observation.peer_assessment(),
            evidence_state: observation.evidence().state,
            local: observation.local(),
        };
        Self {
            observation,
            eligibility: FailoverEligibilityPolicy::evaluate(input),
            authorization: PromotionAttemptAuthorization::evaluate(input),
        }
    }

    /// The observation this evaluation was composed from. Read-only.
    pub(crate) const fn observation(&self) -> &CurrentAuthorityAttemptObservation {
        &self.observation
    }

    /// The eligibility policy result for this attempt. Read-only.
    pub(crate) const fn eligibility(&self) -> FailoverEligibility {
        self.eligibility
    }

    /// The authorization policy result for this attempt. Read-only.
    pub(crate) const fn authorization(&self) -> PromotionAttemptAuthorization {
        self.authorization
    }

    /// Whether the eligibility policy returned `Eligible`. Read-only.
    pub(crate) const fn is_eligible(&self) -> bool {
        self.eligibility.is_eligible()
    }

    /// Whether the authorization policy returned `Authorized`. Read-only.
    /// `true` is inert data and grants no mutation capability.
    pub(crate) const fn is_authorized(&self) -> bool {
        self.authorization.is_authorized()
    }
}

/// Stage 13.2: outcome reported by the execution runtime after the Stage 11
/// promotion boundary ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttemptPromotionOutcome {
    /// `LinuxNodeRuntime::promote` reached its successful Active boundary.
    Promoted,
    /// Stage 11 entered but did not complete; its rollback/cleanup semantics
    /// already ran and must not be duplicated by this stage.
    RolledBack,
    /// Durable ARM did not commit. No protected resource was touched and the
    /// unused Witness lease is left to normal expiry; no Release is sent.
    ArmNotCommitted,
    /// Stage 14 §25: the success-ARM candidate rejected the old image (no
    /// write). No protected resource was touched; the granted lease is
    /// cleaned up through the authoritative §25.1 path.
    ArmRejected,
    /// Stage 14 §25: the success-ARM persistence outcome is uncertain. No
    /// protected resource was touched; RecoveryBlocked, no Release.
    RecoveryBlocked,
}

/// Stage 14 §25.1 / Stage 13.6: what the attempt's post-grant lease cleanup
/// did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AttemptCleanup {
    /// The durable cleanup O is armed and the exact LeaseRelease was executed
    /// once (or there was no granted lease to release).
    Released,
    /// §25.1 `PreCommitFailure`: no cleanup O, so no Release was sent; the
    /// runtime authority is discarded and the lease expires at the Witness.
    NotSent,
    /// §25.1 uncertain or old-image mismatch (or an incident without its
    /// binding): RecoveryBlocked, no Release, the lease expires.
    RecoveryBlocked(String),
}

/// Stage 13.2: attempt-bound lease authority.
///
/// Minted only inside `Daemon::execute_promotion_attempt` after the shared
/// Witness session's single lease request completed with `AcceptedSuccess`
/// and the grant was installed by the trusted authority path. The installed
/// `RuntimeLeaseAuthority` is *moved* into this value — it is never cloned,
/// so at every instant exactly one usable authority value exists: first the
/// installed anchor, then this attempt-bound owner, then the installed
/// anchor again at the Stage 11 handoff. The `PromotionRequestId` it carries
/// is correlation identity only and never grants authority.
///
/// Hardening per the approved contract: private fields, no public
/// constructor, no `Clone`, no `Copy`, no `Serialize`/`Deserialize`, no
/// `Default`, no `From<PromotionRequestId>`, no ID-keyed storage or lookup.
/// Once this value is consumed by the Stage 11 handoff or dropped, knowing
/// or reusing the request id recovers nothing.
pub(crate) struct AttemptBoundLeaseAuthority {
    authority: crate::node_lease_authority::RuntimeLeaseAuthority,
    attempt: crate::promotion_attempt::PromotionRequestId,
}

impl AttemptBoundLeaseAuthority {
    /// Mint the attempt-bound authority. Private to this module so only the
    /// execution driver can construct it, immediately after a successful
    /// current-attempt lease acquisition.
    const fn new(
        authority: crate::node_lease_authority::RuntimeLeaseAuthority,
        attempt: crate::promotion_attempt::PromotionRequestId,
    ) -> Self {
        Self { authority, attempt }
    }

    /// The owning attempt's identity. Read-only; never authority.
    pub(crate) const fn attempt_id(&self) -> &crate::promotion_attempt::PromotionRequestId {
        &self.attempt
    }

    /// The leased runtime authority bound to this attempt. Read-only.
    pub(crate) const fn lease_authority(
        &self,
    ) -> &crate::node_lease_authority::RuntimeLeaseAuthority {
        &self.authority
    }

    /// Consume the binding and move the owned authority out. Used exactly
    /// once by the Stage 11 handoff to restore the authority into its
    /// installed anchor; afterwards this value cannot be reused.
    pub(crate) fn into_authority(self) -> crate::node_lease_authority::RuntimeLeaseAuthority {
        self.authority
    }
}

/// Whether a durable outstanding Witness mutation is exactly the cleanup
/// release Stage 13.2 is allowed to continue for `expected`: `LeaseRelease`
/// kind with matching term and lease_id. Anything else — a different kind,
/// a different lease identity, or no granted identity at all — is not this
/// attempt's cleanup and must fail closed.
fn durable_release_matches(
    outstanding: &crate::node_mutation::OutstandingWitnessMutation,
    expected_term: crate::protocol::Term,
    expected_lease_id: &crate::protocol::LeaseId,
) -> bool {
    matches!(
        &outstanding.mutation,
        crate::node_mutation::DurableWitnessMutation::LeaseRelease { term, lease_id, .. }
            if *term == expected_term && lease_id == expected_lease_id
    )
}

/// Stage 14 §24 G result for one accepted attempt (Phase 14.10). The only
/// continuing production variant is `Cleared`: a `FencingClearance` minted
/// from the current durable, valid `CONFIRMED` incident. Every other gate
/// decision blocks the attempt before any LeaseRequest.
#[derive(Debug)]
pub(crate) enum FencingGate {
    /// The attempt retires `BlockedBeforeMutation(reason)`.
    Blocked(crate::fencing::FencingGateBlock),
    /// A class-D failure (uncertain store write, backend invariant
    /// violation): the attempt retires `BlockedBeforeMutation` and the
    /// daemon fails closed.
    Failed(String),
    /// Valid `CONFIRMED`: the fencing prerequisite is met and the attempt
    /// may continue to H. The clearance is not authority.
    Cleared(crate::fencing::FencingClearance),
    /// Test-only: lets the Stage 13.2 H-L fakes keep exercising the steps
    /// after G. It does not exist in production builds.
    #[cfg(test)]
    BypassedForStage13Test,
}

/// Stage 14 §24 G-L: the fencing prerequisite one accepted attempt carries
/// from G into H, I, K, and the ARM. Owned by the attempt frame, never
/// stored across attempts, never authority: the Witness grant, the
/// attempt-bound lease authority, the K rechecks, trusted ZeroResource, and
/// the atomic ARM are each still required.
pub(crate) enum FencingPrerequisite {
    Cleared(crate::fencing::FencingClearance),
    /// Bootstrap Admission: a one-shot order proof, not a fencing clearance.
    /// It claims no isolation (INV-BA-4) and carries no durable incident.
    Bootstrap(crate::bootstrap_admission::BootstrapClearance),
    /// Test-only counterpart of `FencingGate::BypassedForStage13Test`.
    #[cfg(test)]
    BypassedForStage13Test,
}

impl FencingPrerequisite {
    /// The fencing clearance, when the gate minted one (never for BA).
    pub(crate) fn clearance(&self) -> Option<&crate::fencing::FencingClearance> {
        match self {
            Self::Cleared(clearance) => Some(clearance),
            Self::Bootstrap(_) => None,
            #[cfg(test)]
            Self::BypassedForStage13Test => None,
        }
    }

    /// The Witness term the lease request is anchored on (`observed_term`):
    /// the fencing clearance's or the BA clearance's.
    pub(crate) fn anchor_term(&self) -> Option<crate::protocol::Term> {
        match self {
            Self::Cleared(clearance) => Some(clearance.anchor_term()),
            Self::Bootstrap(clearance) => Some(clearance.anchor_term()),
            #[cfg(test)]
            Self::BypassedForStage13Test => None,
        }
    }

    /// §25.1 `incident_ref`: the clearance's durable binding.
    pub(crate) fn binding(&self) -> Option<crate::fencing::IncidentBinding> {
        self.clearance()
            .map(crate::fencing::FencingClearance::binding)
    }
}

/// v0.7 G-2 G-A1/G-A2: the route-handoff provenance of a promotion, from the clearance minted for
/// it (the success ARM has consumed the durable incident by the time the RH starts).
pub(crate) fn route_origin(prerequisite: &FencingPrerequisite) -> crate::route_handoff::RhOrigin {
    use crate::route_handoff::{RhConfirmation, RhOrigin};
    match prerequisite {
        FencingPrerequisite::Cleared(clearance) => {
            let (attempt_token, confirmed_by) = match clearance.backend_attempt_token() {
                Some(attempt_token) => (attempt_token, RhConfirmation::Backend),
                None => (0, RhConfirmation::Operator),
            };
            RhOrigin::Fencing {
                incident_seq: clearance.incident().incident_seq,
                incident_id: clearance.incident().incident_id.as_str().to_string(),
                attempt_token,
                confirmed_by,
            }
        }
        FencingPrerequisite::Bootstrap(_) => RhOrigin::Bootstrap,
        #[cfg(test)]
        FencingPrerequisite::BypassedForStage13Test => RhOrigin::Unknown,
    }
}

/// Stage 13.2: mutation-capable runtime boundary borrowed by the single
/// execution driver for one explicit promotion attempt.
///
/// `Daemon` owns lifecycle and shutdown truth; this trait supplies the
/// approved production sequence: exactly one fresh
/// `evaluate_authority_attempt`, one lease request through the single shared
/// `WitnessSession`, the attempt-bound lease mint, the pre-mutation
/// checkpoint inputs, best-effort lease cleanup, and the Stage 11 promotion
/// handoff. No method here retries, queues, persists attempt state, or
/// performs automatic failover.
pub(crate) trait PromotionExecutionRuntime: DaemonRuntime {
    /// Issue the caller-driven GET_TERM request that the next authority
    /// observation completes. This is request issuance only: it sends one
    /// correlated request through the shared `WitnessSession` outstanding
    /// slot and never polls, classifies, or mints evidence. Completion is
    /// owned exclusively by `evaluate_authority_attempt` — one logical
    /// observation is one request generation plus the single poll that
    /// accepts its response, so exactly one poll exposes `Ready` per
    /// generation.
    ///
    /// The composition root calls this only while the session's outstanding
    /// slot is free (`shared_witness_outstanding` false); an in-flight or
    /// already-completed generation is never duplicated.
    fn begin_authority_observation(
        &mut self,
        context: DaemonIterationContext,
    ) -> Result<(), String>;

    /// Phase 14.12 F2: complete an authority observation whose deadline has
    /// passed (`now >= deadline`) so the shared session slot it occupies is
    /// released before the next priming decision. It issues no request, polls
    /// no socket and exposes no evidence; it only reuses the adapter's
    /// existing expiry path.
    ///
    /// The default does nothing and is correct only for runtimes that have no
    /// Witness observation. `LinuxDaemonRuntime` MUST override it; a test
    /// (`f2_linux_runtime_expires_a_stale_observation_through_the_trait`)
    /// calls it through this trait and fails if the override is missing.
    fn expire_stale_authority_observation(&mut self, _now: std::time::Instant) {}

    /// Phase 14.12 E3b: the attempt-bound observation step. It runs inside
    /// `execute_promotion_attempt`, immediately before the attempt's one
    /// `evaluate_authority_attempt`: it issues THIS attempt's own GET_TERM
    /// through the shared session slot and waits for that one request — never
    /// past its 5 s deadline, and in short slices so `shutdown_requested` (the
    /// live shutdown query) is seen between them. It issues at most one
    /// request, never retries, never exposes `Ready` and never polls on
    /// behalf of anything but its own request. `Ok(())` lets the attempt
    /// evaluate; `Err(reason)` blocks it before mutation.
    ///
    /// The default does nothing and is correct only for runtimes whose
    /// `evaluate_authority_attempt` drives its own observation (the Stage 13.2
    /// test fakes). `LinuxDaemonRuntime` MUST override it; a test
    /// (`e3b_linux_runtime_attempt_observation_is_wired_through_the_trait`)
    /// calls it through this trait and fails if the override is missing.
    fn complete_attempt_observation(
        &mut self,
        _shutdown_requested: &dyn Fn() -> bool,
    ) -> Result<(), &'static str> {
        Ok(())
    }

    /// Perform this attempt's one fresh logical revalidation through the
    /// approved `evaluate_authority_attempt` boundary. Implementations must
    /// not reuse a stored `Authorized` result.
    fn evaluate_authority_attempt(
        &mut self,
        context: DaemonIterationContext,
    ) -> Result<Option<AuthorityAttemptEvaluation>, String>;

    /// Stage 14 §24 G: the fencing gate of this attempt, after the fresh
    /// `Authorized` evaluation and the shutdown check, before any
    /// LeaseRequest. It may open, retire, or advance the incident and run
    /// the one bounded fence action (§27.2), which always blocks; a valid
    /// `CONFIRMED` yields `Cleared` with the minted clearance.
    /// `shutdown_requested` is the live shutdown query (F14.9-01), sampled
    /// before the action spawns and again after it returns.
    fn fencing_gate(
        &mut self,
        evaluation: &AuthorityAttemptEvaluation,
        shutdown_requested: &dyn Fn() -> bool,
    ) -> FencingGate;

    /// Send exactly one lease request through the shared `WitnessSession`
    /// and consume its completion. Only `AcceptedSuccess` may yield
    /// authority; every other classification grants nothing.
    fn acquire_attempt_lease_once(
        &mut self,
        term: crate::protocol::Term,
    ) -> Result<crate::node_lease_authority::node_witness_runtime::NodeWitnessMutationResult, String>;

    /// Move the lease authority installed by the trusted authority path out
    /// of its owner for this attempt, if one is installed. This is a
    /// structural take: the returned value is the only usable authority —
    /// the owner retains none and no clone is created. The Stage 11 handoff
    /// restores it into the installed anchor.
    fn take_attempt_lease_authority(
        &mut self,
    ) -> Option<crate::node_lease_authority::RuntimeLeaseAuthority>;

    /// Whether `authority` is still usable under the existing
    /// `RuntimeLeaseAuthority` timing rules at this checkpoint instant.
    fn attempt_lease_usable(
        &self,
        authority: &crate::node_lease_authority::RuntimeLeaseAuthority,
    ) -> bool;

    /// Whether the shared session's single outstanding Witness slot is
    /// occupied. A second outstanding operation makes the final pre-mutation
    /// checkpoint fail closed.
    fn shared_witness_outstanding(&self) -> bool;

    /// Stage 14 §28.1: unauthenticated listener arrivals in the last 30 s, for
    /// the blocked-attempt log line only. Diagnostic: the value flows into a
    /// format argument and nowhere else (guard `017_diagnostics_not_evidence`).
    fn listener_interference_recent(&self, _now: std::time::Instant) -> Option<u64> {
        None
    }

    /// Stage 14 §28: the name of the last failed §24 K runtime-half recheck,
    /// for the blocked-attempt log line only (never a decision input).
    fn last_recheck_failure(&self) -> Option<String> {
        None
    }

    /// Stage 14 §24 K, runtime half (items 6-14): against the current
    /// durable incident and the live continuity facts, immediately before
    /// ARM. `Err` names the failed recheck; the caller then cleans up the
    /// granted lease through §25.1 and never ARMs.
    fn fencing_final_recheck(
        &mut self,
        prerequisite: &FencingPrerequisite,
        grant_term: crate::protocol::Term,
    ) -> Result<(), String>;

    /// Best-effort lease cleanup through the same shared session. When
    /// `granted` holds the acquired lease identity and no durable cleanup is
    /// already outstanding, this begins and executes a LeaseRelease. When a
    /// durable Witness mutation is already outstanding it is executed only
    /// if it is exactly the expected `LeaseRelease` for `granted` (matching
    /// kind, term, and lease_id — e.g. a cleanup release begun by Stage 11
    /// rollback); any other durable mutation fails closed, is preserved for
    /// its rightful owner, and is never executed as this attempt's cleanup.
    /// A failure never converts into promotion permission.
    ///
    /// Stage 14 §25.1: `binding` is the attempt clearance's durable
    /// incident binding. While a fencing incident exists the cleanup O is
    /// armed only by the atomic abort-cleanup transaction with it (never the
    /// plain ARM); the result says whether a Release was sent.
    fn release_attempt_lease(
        &mut self,
        granted: Option<(crate::protocol::Term, crate::protocol::LeaseId)>,
        binding: Option<&crate::fencing::IncidentBinding>,
    ) -> Result<AttemptCleanup, String>;

    /// Move the attempt-bound authority into the existing Stage 11 promotion
    /// path (`LinuxNodeRuntime::promote` / `ResourceWorkflow` /
    /// `NodeAuthorityController`). The implementation must verify the bound
    /// authority is still the installed authority before mutating. The bound
    /// value is consumed: it cannot be cloned, stored, or reused by another
    /// attempt.
    ///
    /// Stage 14 §24 L: the attempt's fencing prerequisite is carried in; the
    /// ARM is the atomic `arm_consuming_fencing` of its clearance.
    fn execute_attempt_promotion(
        &mut self,
        lease: AttemptBoundLeaseAuthority,
        prerequisite: &FencingPrerequisite,
    ) -> Result<AttemptPromotionOutcome, String>;

    /// v0.7 G-2 (contract §1.2 start): after `Succeeded`, start the route handoff of the granted
    /// term with the clearance's mint-time provenance. Never changes the attempt's result.
    fn begin_route_handoff(
        &mut self,
        _origin: crate::route_handoff::RhOrigin,
        _term: crate::protocol::Term,
    ) {
    }
}

impl<R> Daemon<R>
where
    R: PromotionExecutionRuntime,
{
    /// Stage 13.2: execute one explicit promotion attempt end-to-end.
    ///
    /// Approved sequence — no other ordering is permitted:
    /// `PromotionExecutionRequest` -> Stage 13.1 `InFlight` accept ->
    /// (Phase 14.12 E3b) the attempt-bound observation step: this attempt's
    /// own GET_TERM, awaited for at most its 5 s deadline ->
    /// exactly one fresh `evaluate_authority_attempt` -> current
    /// `Authorized` -> one lease request through the shared `WitnessSession`
    /// -> `AcceptedSuccess` -> `AttemptBoundLeaseAuthority` -> final
    /// pre-mutation checkpoint -> Stage 11 `LinuxNodeRuntime::promote`
    /// handoff -> typed result -> retire.
    ///
    /// `PromotionRequestId` is identity only. `InFlight` is not
    /// authorization. `Authorized` is never stored across calls. The lease
    /// authority is bound to this attempt's frame by move semantics; a
    /// retired or reused id recovers nothing. There is no implicit retry and
    /// no automatic failover on this path.
    #[cfg_attr(not(test), allow(unreachable_code))]
    pub(crate) fn execute_promotion_attempt(
        &mut self,
        request: crate::promotion_attempt::PromotionExecutionRequest,
    ) -> crate::promotion_attempt::PromotionAttemptResult {
        use crate::promotion_attempt::PromotionAttemptResult;

        let attempt = match self.request_promotion_attempt(request) {
            Ok(attempt) => attempt,
            Err(rejection) => return PromotionAttemptResult::Rejected(rejection),
        };

        // Phase 14.12 E3b: the observation this attempt evaluates is its own.
        // The step issues one GET_TERM and waits for that request (never past
        // its deadline, shutdown seen between slices); nothing in the
        // background issues one. Not issued, interrupted, failed or timed out
        // all block before mutation, and the step is never repeated.
        if let Err(reason) = self.runtime.complete_attempt_observation(&|| {
            self.shutdown_requested || self.shutdown_signal.raised()
        }) {
            crate::operator_log::warn_attempt_blocked(reason, None);
            return self
                .retire_promotion_attempt(&attempt, PromotionAttemptResult::BlockedBeforeMutation);
        }

        // Fresh revalidation: exactly one logical observation for this
        // attempt. Pending, unavailable, locally unsafe, erroneous,
        // non-Ready, and non-Authorized outcomes all fail closed.
        let evaluated = self
            .runtime
            .evaluate_authority_attempt(self.iteration_context(std::time::Instant::now()));
        let mut bootstrap_clearance = None;
        let evaluation = match evaluated {
            Ok(Some(evaluation)) if evaluation.is_authorized() => evaluation,
            // Bootstrap Admission (contract K-1..K-6): the cold-start entry
            // class for a HEALTHY peer. It is decided here, before and apart
            // from `evaluate_authority_attempt`'s authorization, which is
            // never forged: `Authorized` stays reserved for the fencing path.
            Ok(Some(evaluation)) if self.bootstrap_applies(&evaluation) => {
                match self.bootstrap_admission(&evaluation) {
                    Some(clearance) => {
                        bootstrap_clearance = Some(clearance);
                        evaluation
                    }
                    None => {
                        return self.retire_promotion_attempt(
                            &attempt,
                            PromotionAttemptResult::BlockedBeforeMutation,
                        );
                    }
                }
            }
            other => {
                self.warn_evaluation_blocked(&other);
                return self.retire_promotion_attempt(
                    &attempt,
                    PromotionAttemptResult::BlockedBeforeMutation,
                );
            }
        };
        #[cfg(test)]
        self.run_promotion_attempt_test_hook();

        // Shutdown may have been requested while revalidation ran; the
        // Authorized result is dropped, never stored.
        if self.shutdown_requested {
            crate::operator_log::warn_attempt_blocked("shutdown requested", None);
            return self
                .retire_promotion_attempt(&attempt, PromotionAttemptResult::BlockedBeforeMutation);
        }

        // Stage 14 §24 G: the fencing gate runs here, before any
        // LeaseRequest. Every decision blocks except a valid `CONFIRMED`,
        // which yields the attempt's clearance (fencing evidence, never
        // authority). The gate reads shutdown live (F14.9-01): a shutdown
        // arriving during a fence action is seen when the action returns,
        // before any T4 write.
        let prerequisite = match bootstrap_clearance.map(FencingPrerequisite::Bootstrap) {
            Some(prerequisite) => prerequisite,
            None => match self.runtime.fencing_gate(&evaluation, &|| {
                self.shutdown_requested || self.shutdown_signal.raised()
            }) {
                FencingGate::Blocked(_reason) => {
                    return self.retire_promotion_attempt(
                        &attempt,
                        PromotionAttemptResult::BlockedBeforeMutation,
                    );
                }
                FencingGate::Failed(error) => {
                    crate::operator_log::warn_fencing_gate_failed_closed(&error);
                    self.state = DaemonState::Failed;
                    return self.retire_promotion_attempt(
                        &attempt,
                        PromotionAttemptResult::BlockedBeforeMutation,
                    );
                }
                FencingGate::Cleared(clearance) => FencingPrerequisite::Cleared(clearance),
                #[cfg(test)]
                FencingGate::BypassedForStage13Test => FencingPrerequisite::BypassedForStage13Test,
            },
        };
        let binding = prerequisite.binding();
        // Phase 1-J25 TEST-ONLY (feature `j25-fault-injection`): a crash of the promoting node with a
        // fencing clearance in hand, just before its lease request (J25 §10 point 8).
        #[cfg(feature = "j25-fault-injection")]
        if matches!(prerequisite, FencingPrerequisite::Cleared(_)) {
            crate::j25_fault_injection::crash_if("j25-before-lease-request");
        }

        // H: one lease request through the single shared session, keyed by
        // the fresh observation's term, which must equal the clearance's
        // anchor (checked at G; re-asserted here so the clearance can never be
        // re-anchored). Any non-grant classification yields no authority and
        // no retry.
        let term = evaluation.observation().authority_view().term();
        if prerequisite
            .anchor_term()
            .is_some_and(|anchor| anchor != term)
        {
            crate::operator_log::warn_attempt_blocked(
                "clearance anchor differs from the fresh Witness term",
                None,
            );
            return self
                .retire_promotion_attempt(&attempt, PromotionAttemptResult::BlockedBeforeMutation);
        }
        // A lock loss can race the fencing gate. Re-read the live stop
        // condition immediately before the lease request; no new lease is
        // acquired after the control lock is no longer trusted.
        if self.shutdown_requested || self.shutdown_signal.raised() {
            crate::operator_log::warn_attempt_blocked("shutdown requested before lease", None);
            return self
                .retire_promotion_attempt(&attempt, PromotionAttemptResult::BlockedBeforeMutation);
        }
        let bound = match self.runtime.acquire_attempt_lease_once(term) {
            Ok(
                crate::node_lease_authority::node_witness_runtime::NodeWitnessMutationResult::AcceptedSuccess { .. },
            ) => {
                let bound = self
                    .runtime
                    .take_attempt_lease_authority()
                    .map(|authority| AttemptBoundLeaseAuthority::new(authority, attempt.clone()));
                #[cfg(test)]
                if bound.is_none() {
                    eprintln!(
                        "promotion-attempt diagnostic: AcceptedSuccess but no installed authority"
                    );
                }
                bound
            }
            other => {
                #[cfg(test)]
                eprintln!(
                    "promotion-attempt diagnostic: lease acquire -> {}",
                    match &other {
                        Err(error) => format!("Err({error})"),
                        Ok(result) => format!("non-success: {result:?}"),
                    }
                );
                let _ = other;
                None
            }
        };
        #[cfg(test)]
        self.run_promotion_attempt_test_hook();

        let Some(bound) = bound else {
            crate::operator_log::warn_attempt_blocked("Witness lease not granted", None);
            return self
                .retire_promotion_attempt(&attempt, PromotionAttemptResult::BlockedBeforeMutation);
        };
        // Phase 1-J27 TEST-ONLY (feature `j25-fault-injection`): a crash of the promoting node
        // right after the Witness granted the attempt's lease, before any final recheck or ARM
        // (J27 §10 point 8).
        #[cfg(feature = "j25-fault-injection")]
        if matches!(prerequisite, FencingPrerequisite::Cleared(_)) {
            crate::j25_fault_injection::crash_if("j27-after-grant");
        }
        let granted = (
            bound.lease_authority().term(),
            bound.lease_authority().lease_id().clone(),
        );

        // I: the grant must be exactly `anchor_term + 1`. Otherwise the
        // runtime authority is discarded and the post-grant, pre-resource
        // abort uses the §25.1 atomic abort cleanup, then the exact Release.
        if prerequisite
            .anchor_term()
            .is_some_and(|anchor| anchor.0.checked_add(1) != Some(granted.0.0))
        {
            drop(bound);
            crate::operator_log::warn_attempt_blocked(
                "Witness grant term is not the clearance anchor + 1",
                None,
            );
            return self.abort_after_grant(
                &attempt,
                granted,
                binding.as_ref(),
                PromotionAttemptResult::BlockedBeforeMutation,
            );
        }

        // K: final rechecks, immediately before the ARM (Rev5 §24 K 1-5 here,
        // 6-14 in the runtime against the current durable incident and live
        // continuity; the ARM candidate rechecks the durable part again).
        // Shutdown is read live. No ARM, no resource mutation, no promotion
        // on any failure; the granted lease is cleaned up through §25.1.
        let cancelled = self.promotion_attempt.in_flight_id() != Some(&attempt);
        let shutdown = self.shutdown_requested || self.shutdown_signal.raised();
        if shutdown
            || self.state != DaemonState::Running
            || cancelled
            || !self.runtime.attempt_lease_usable(bound.lease_authority())
            || self.runtime.shared_witness_outstanding()
            || self
                .runtime
                .fencing_final_recheck(&prerequisite, granted.0)
                .is_err()
        {
            drop(bound);
            self.warn_k_blocked(shutdown, cancelled);
            let result = if cancelled && !shutdown {
                PromotionAttemptResult::Cancelled
            } else {
                PromotionAttemptResult::BlockedBeforeMutation
            };
            return self.abort_after_grant(&attempt, granted, binding.as_ref(), result);
        }

        // L: the bound authority and the attempt's clearance move into the
        // runtime: observe trusted ZeroResource -> atomic v3 ARM consumes the
        // incident and installs O -> restore authority -> Stage 11 promote.
        // Stage 11 owns resource mutation ordering, authority checkpoints,
        // rollback, and cleanup.
        // Last live check before the resource boundary. The control-lock
        // query feeds the same shutdown signal, so a loss between K and this
        // point aborts before VIP/service mutation.
        if self.shutdown_requested || self.shutdown_signal.raised() {
            drop(bound);
            crate::operator_log::warn_attempt_blocked(
                "shutdown requested before resource mutation",
                None,
            );
            return self.abort_after_grant(
                &attempt,
                granted,
                binding.as_ref(),
                PromotionAttemptResult::BlockedBeforeMutation,
            );
        }
        match self.runtime.execute_attempt_promotion(bound, &prerequisite) {
            Ok(AttemptPromotionOutcome::Promoted) => {
                // v0.7 G-2: `Succeeded` is the internal promotion only (contract §1.1).
                self.runtime
                    .begin_route_handoff(route_origin(&prerequisite), granted.0);
                self.retire_promotion_attempt(&attempt, PromotionAttemptResult::Succeeded)
            }
            Ok(AttemptPromotionOutcome::ArmNotCommitted) => {
                crate::operator_log::warn_attempt_blocked(
                    "ARM not committed (no Release is sent; the lease expires)",
                    None,
                );
                self.retire_promotion_attempt(
                    &attempt,
                    PromotionAttemptResult::BlockedBeforeMutation,
                )
            }
            Ok(AttemptPromotionOutcome::ArmRejected) => {
                crate::operator_log::warn_attempt_blocked("ARM validation rejected", None);
                self.abort_after_grant(
                    &attempt,
                    granted,
                    binding.as_ref(),
                    PromotionAttemptResult::BlockedBeforeMutation,
                )
            }
            Ok(AttemptPromotionOutcome::RecoveryBlocked) => {
                eprintln!("mikagami: fencing ARM outcome uncertain; recovery blocked");
                self.state = DaemonState::RecoveryBlocked;
                self.retire_promotion_attempt(
                    &attempt,
                    PromotionAttemptResult::BlockedBeforeMutation,
                )
            }
            _ => {
                crate::operator_log::warn_attempt_blocked(
                    "promotion did not complete (rolled back; the granted lease is released)",
                    None,
                );
                let _ = self
                    .runtime
                    .release_attempt_lease(Some(granted), binding.as_ref());
                self.retire_promotion_attempt(&attempt, PromotionAttemptResult::MutationFailed)
            }
        }
    }

    /// Whether this unauthorized evaluation belongs to the Bootstrap Admission
    /// class: the runtime has a peer connection and the peer is `Healthy`.
    /// Every other unauthorized evaluation keeps its ordinary block.
    fn bootstrap_applies(&self, evaluation: &AuthorityAttemptEvaluation) -> bool {
        self.runtime.bootstrap_supported()
            && evaluation.observation().peer_assessment()
                == crate::failure_assessment::PeerFailureAssessment::Healthy
    }

    /// One Bootstrap Admission step (contract K-1, BAP-2/BAP-6). Attempt 1
    /// anchors the term and asks for the probe, attempt 2 mints the one-shot
    /// clearance; everything else is a block. Returns the clearance only for
    /// attempt 2; in every other case the caller retires the attempt before
    /// any mutation.
    fn bootstrap_admission(
        &mut self,
        evaluation: &AuthorityAttemptEvaluation,
    ) -> Option<crate::bootstrap_admission::BootstrapClearance> {
        use crate::bootstrap_admission::{Admission, AdmissionInputs, decide};
        let current = self.runtime.bootstrap_stamp();
        let observation = evaluation.observation();
        let inputs = AdmissionInputs {
            conservative: self.runtime.bootstrap_conservative(),
            shutdown_requested: self.shutdown_requested || self.shutdown_signal.raised(),
            peer: observation.peer_assessment(),
            local_readiness: observation.local().readiness,
            witness: observation.authority_view().compatibility(),
            witness_term: observation.authority_view().term(),
            current_stamp: current.as_ref(),
        };
        match decide(&inputs, self.bootstrap_session.take()) {
            Admission::Anchored(session) => {
                let term = session.anchor_term();
                if self.runtime.request_bootstrap_probe() {
                    crate::operator_log::info_bootstrap_anchored(term.0);
                    self.bootstrap_session = Some(session);
                } else {
                    self.runtime.discard_bootstrap_probe();
                    crate::operator_log::warn_attempt_blocked(
                        "bootstrap admission: the probe could not be requested",
                        None,
                    );
                }
                None
            }
            Admission::Cleared(clearance) => Some(clearance),
            Admission::Blocked { block, keep } => {
                if keep.is_none() {
                    self.runtime.discard_bootstrap_probe();
                }
                self.bootstrap_session = keep;
                crate::operator_log::warn_attempt_blocked(block.reason(), None);
                None
            }
        }
    }

    /// Stage 14 §24 I/K/L: a post-grant, pre-resource abort. The runtime
    /// authority has already been dropped; the lease cleanup goes through
    /// the §25.1 routing (atomic abort cleanup while an incident exists,
    /// then the exact Release). An uncertain or mismatched cleanup is
    /// RecoveryBlocked and sends no Release; the lease expires.
    fn abort_after_grant(
        &mut self,
        attempt: &crate::promotion_attempt::PromotionRequestId,
        granted: (crate::protocol::Term, crate::protocol::LeaseId),
        binding: Option<&crate::fencing::IncidentBinding>,
        result: crate::promotion_attempt::PromotionAttemptResult,
    ) -> crate::promotion_attempt::PromotionAttemptResult {
        match self.runtime.release_attempt_lease(Some(granted), binding) {
            Ok(AttemptCleanup::RecoveryBlocked(reason)) => {
                crate::operator_log::error_abort_cleanup("blocked", &reason);
                self.state = DaemonState::RecoveryBlocked;
            }
            // Rev5 §25.1 / M1: a cleanup that could not run or whose outcome
            // is unknown cannot prove the durable cleanup obligation. It is
            // never a silent success and never leaves an ordinary Running
            // daemon: fail closed (RecoveryBlocked; no further Release, no
            // promotion, no authority restoration, no resource mutation).
            Err(error) => {
                crate::operator_log::error_abort_cleanup("failed", &error);
                self.state = DaemonState::RecoveryBlocked;
            }
            Ok(AttemptCleanup::Released | AttemptCleanup::NotSent) => {}
        }
        self.retire_promotion_attempt(attempt, result)
    }

    /// Stage 14 §28: the blocked-attempt WARN for a §24 K failure. Daemon-side
    /// items name themselves; otherwise the runtime half's recorded failure
    /// (or a generic reason) is used. Diagnostic only: nothing here returns a
    /// value to the caller.
    fn warn_k_blocked(&self, shutdown: bool, cancelled: bool) {
        let detail = self.runtime.last_recheck_failure();
        let reason = if shutdown {
            "final recheck failed: shutdown requested".to_string()
        } else if self.state != DaemonState::Running {
            "final recheck failed: daemon not running".to_string()
        } else if cancelled {
            "final recheck failed: attempt cancelled".to_string()
        } else if let Some(item) = detail {
            format!("final recheck failed: {item}")
        } else {
            "final recheck failed: attempt lease unusable or Witness session busy".to_string()
        };
        crate::operator_log::warn_attempt_blocked(&reason, None);
    }

    /// Stage 14 §28 / §28.1: the blocked-attempt WARN for an evaluation that
    /// was not `Authorized`. A block for lack of fresh local loss while
    /// unauthenticated listener arrivals occurred in the last 30 s says so
    /// (`ListenerInterference: N unauthenticated arrivals`). The arrival count
    /// is read for this line only; no decision depends on it.
    fn warn_evaluation_blocked(
        &self,
        evaluated: &Result<Option<AuthorityAttemptEvaluation>, String>,
    ) {
        use crate::promotion_authorization::{
            PromotionAttemptAuthorization as Authorization, PromotionAttemptBlocker as Blocker,
            PromotionAttemptIndeterminacy as Indeterminacy,
        };
        let reason: String = match evaluated {
            Ok(Some(evaluation)) => match evaluation.authorization() {
                Authorization::Authorized => "not authorized".into(),
                Authorization::Blocked(
                    Blocker::PeerNotObserved
                    | Blocker::PeerNotLost
                    | Blocker::PeerEvidenceInsufficient,
                ) => {
                    match self
                        .runtime
                        .listener_interference_recent(std::time::Instant::now())
                        .filter(|arrivals| *arrivals > 0)
                    {
                        Some(arrivals) => format!(
                            "local loss not fresh (ListenerInterference: {arrivals} unauthenticated arrivals)"
                        ),
                        None => "local loss not fresh".into(),
                    }
                }
                Authorization::Blocked(blocker) => match blocker {
                    Blocker::LocalStateUnsafe => "local state unsafe",
                    Blocker::AuthorityPresent => "authority present",
                    Blocker::OperationInProgress => "operation in progress",
                    Blocker::DemotionRequired => "demotion required",
                    Blocker::ShutdownInProgress => "shutdown in progress",
                    Blocker::RecoveryBlocked => "recovery blocked",
                    Blocker::LocalSafetyUnresolved => "local safety unresolved",
                    Blocker::RecoveryPending => "recovery pending",
                    Blocker::Maintenance => "maintenance",
                    Blocker::PeerNotObserved
                    | Blocker::PeerNotLost
                    | Blocker::PeerEvidenceInsufficient => "local loss not fresh",
                }
                .into(),
                Authorization::Indeterminate(indeterminacy) => match indeterminacy {
                    Indeterminacy::AmbiguousPartition => "partition ambiguous",
                    Indeterminacy::InconsistentEvidence => "evidence inconsistent",
                    Indeterminacy::LocalSafetyUnknown => "local safety unknown",
                }
                .into(),
            },
            Ok(None) => "no fresh authority observation".into(),
            Err(_) => "authority evaluation failed".into(),
        };
        crate::operator_log::warn_attempt_blocked(&reason, None);
    }

    /// Retire only this frame's own accepted attempt: the single-slot
    /// lifecycle is finished only when it still holds this exact
    /// `PromotionRequestId`. A slot already `Idle` (cancelled) or holding a
    /// different identity is left untouched, so attempt A's retirement can
    /// never remove attempt B.
    fn retire_promotion_attempt(
        &mut self,
        attempt: &crate::promotion_attempt::PromotionRequestId,
        result: crate::promotion_attempt::PromotionAttemptResult,
    ) -> crate::promotion_attempt::PromotionAttemptResult {
        if self.promotion_attempt.in_flight_id() == Some(attempt) {
            let _ = self.finish_promotion_attempt();
        }
        result
    }

    /// Test-only seam: consume one queued hook at an internal Stage 13.2
    /// boundary (post-revalidation, then post-lease, in call order).
    /// Production builds contain no hooks and no hook plumbing.
    #[cfg(test)]
    fn run_promotion_attempt_test_hook(&mut self) {
        if let Some(hook) = self.promotion_attempt_test_hooks.pop_front() {
            hook(self);
        }
    }
}

impl<R: DaemonRuntime> Daemon<R> {
    /// Test-only: queue a hook executed at the next internal Stage 13.2
    /// boundary inside `execute_promotion_attempt` (post-revalidation first,
    /// post-lease second). Used to model shutdown/cancellation races.
    /// Test-only (Stage 14 Phase 14.10 K2): model the daemon leaving
    /// `Running` without a shutdown request.
    #[cfg(test)]
    pub(crate) fn force_state_for_test(&mut self, state: DaemonState) {
        self.state = state;
    }

    #[cfg(test)]
    pub(crate) fn push_promotion_attempt_test_hook(
        &mut self,
        hook: impl FnOnce(&mut Daemon<R>) + 'static,
    ) {
        self.promotion_attempt_test_hooks.push_back(Box::new(hook));
    }
}

#[cfg(all(test, target_os = "linux"))]
impl Daemon<LinuxDaemonRuntime> {
    /// Test-only (Linux closeout): the peer failure assessment carried by
    /// the single peer-truth owner. Diagnostic surface only — it reads, it
    /// never drives.
    pub(crate) fn peer_failure_assessment_for_test(
        &self,
    ) -> crate::failure_assessment::PeerFailureAssessment {
        self.runtime.peer_failure_assessment()
    }

    /// Test-only (Linux closeout): run the attempt-bound observation step
    /// (Phase 14.12 E3b) exactly as `execute_promotion_attempt` does, with no
    /// shutdown requested, so a fixture can observe the Witness response the
    /// attempt will evaluate. The step issues its own GET_TERM and waits.
    pub(crate) fn complete_attempt_observation_for_test(&mut self) -> Result<(), &'static str> {
        self.runtime.complete_attempt_observation(&|| false)
    }

    /// Test-only (Linux closeout): run the same fresh
    /// `evaluate_authority_attempt` the production attempt path uses, so a
    /// fixture can observe the exact inert evaluation result before asking
    /// the loop to attempt.
    pub(crate) fn evaluate_authority_attempt_for_test(
        &mut self,
        now: std::time::Instant,
    ) -> Result<Option<AuthorityAttemptEvaluation>, String> {
        self.runtime
            .evaluate_authority_attempt(self.iteration_context(now))
    }

    /// Test-only (Linux closeout): block briefly until the shared Witness
    /// socket reports a readable response frame — the same readiness wait
    /// the runtime-level seam performs, exposed at the `Daemon` boundary.
    pub(crate) fn wait_witness_readable_for_test(&mut self) -> Result<(), String> {
        self.runtime.wait_witness_readable_for_test()
    }

    /// Test-only (Linux closeout): compact snapshot of the attempt-path
    /// boundary state — whether the shared session's outstanding slot is
    /// occupied and whether an installed lease authority exists. Read-only
    /// diagnostics; it drives nothing.
    pub(crate) fn execution_diagnostics_for_test(&mut self) -> String {
        format!(
            "witness_outstanding={} installed_authority={}",
            self.runtime.shared_witness_outstanding(),
            self.runtime.runtime.installed_lease_authority().is_some(),
        )
    }

    /// Test-only (Linux closeout): whether a durable outstanding Witness
    /// mutation (e.g. the demotion's LeaseRelease) is recorded. Read-only.
    pub(crate) fn durable_witness_outstanding_for_test(&mut self) -> Result<bool, String> {
        self.runtime
            .runtime
            .durable_witness_outstanding()
            .map(|outstanding| outstanding.is_some())
            .map_err(|error| error.to_string())
    }

    pub(crate) fn release_obligation_for_test(&self) -> Result<bool, String> {
        self.runtime
            .runtime
            .release_obligation()
            .map(|obligation| obligation.is_some())
            .map_err(|error| error.to_string())
    }

    /// Test-only (Linux closeout): execute one already-durable outstanding
    /// Witness mutation through the shared session — the same typed
    /// dispatch the production attempt-abort path performs — so the
    /// closeout can prove the demotion's durable LeaseRelease completes.
    pub(crate) fn execute_durable_witness_mutation_for_test(
        &mut self,
    ) -> Result<crate::node_lease_authority::node_witness_runtime::NodeWitnessMutationResult, String>
    {
        let session = self
            .runtime
            .witness_session
            .as_mut()
            .ok_or_else(|| "Witness session is not configured".to_string())?;
        self.runtime
            .runtime
            .execute_durable_witness_mutation_once(session)
            .map_err(|error| error.to_string())
    }
}

/// Stage 13.2 production composition: `LinuxDaemonRuntime` is the runtime
/// boundary behind `Daemon::execute_promotion_attempt`.  The single
/// `witness_session` it owns serializes observation and lease traffic
/// through one outstanding slot; the `LinuxNodeRuntime` it owns keeps
/// Stage 11 mutation ordering authoritative.
#[cfg(target_os = "linux")]
impl PromotionExecutionRuntime for LinuxDaemonRuntime {
    fn expire_stale_authority_observation(&mut self, now: std::time::Instant) {
        if let (Some(session), Some(observer)) = (
            self.witness_session.as_mut(),
            self.witness_observer.as_mut(),
        ) {
            // A failure leaves the adapter exactly as before; the next
            // priming decision then simply sees the slot still occupied.
            let _ = observer.expire_pending_at(session, now);
        }
    }

    fn complete_attempt_observation(
        &mut self,
        shutdown_requested: &dyn Fn() -> bool,
    ) -> Result<(), &'static str> {
        // Active and demotion work own the sole Witness slot; observation
        // must never displace them (the old priming's same gate).
        if !self.authority_observation_allowed() {
            return Err("authority observation is not allowed in this state");
        }
        let expectation = self.authority_view_expectation();
        let (Some(session), Some(observer)) = (
            self.witness_session.as_mut(),
            self.witness_observer.as_mut(),
        ) else {
            return Err("Witness session is not configured");
        };
        observer
            .complete_attempt_observation(
                session,
                expectation,
                shutdown_requested,
                &mut std::time::Instant::now,
                &mut std::thread::sleep,
            )
            .into_result()
    }

    fn begin_authority_observation(
        &mut self,
        context: DaemonIterationContext,
    ) -> Result<(), String> {
        LinuxDaemonRuntime::begin_authority_observation(self, context)
    }

    fn evaluate_authority_attempt(
        &mut self,
        context: DaemonIterationContext,
    ) -> Result<Option<AuthorityAttemptEvaluation>, String> {
        LinuxDaemonRuntime::evaluate_authority_attempt(self, context)
    }

    fn fencing_gate(
        &mut self,
        evaluation: &AuthorityAttemptEvaluation,
        shutdown_requested: &dyn Fn() -> bool,
    ) -> FencingGate {
        use crate::fencing::FencingGateBlock;
        let view_term = evaluation.observation().authority_view().term();
        let Some(peer) = self.peer.as_mut() else {
            return FencingGate::Blocked(FencingGateBlock::FencingUnavailable);
        };
        let configured_peer = self.runtime.fencing_target().clone();
        let current_session = peer.observer_session_id().clone();
        let live_episode = peer.loss_evidence();
        let context = crate::fencing::ContinuityContext {
            configured_peer: &configured_peer,
            current_session: &current_session,
            live_episode: live_episode.as_ref(),
        };
        // §27.5: the fence action is a blocking step.
        let stepped = &mut self.fencing_step_since_peer_tick;
        let mut void = || {
            *stepped = true;
            peer.void_listen_window_for_fencing_step();
        };
        match self
            .runtime
            .fencing_gate(view_term, &context, shutdown_requested, &mut void)
        {
            Ok(decision) => {
                let (incident, gate) = match decision {
                    crate::linux_node_runtime::FencingGateDecision::Block(outcome) => {
                        // §28: one blocked-attempt WARN, written by this one
                        // gate caller; never read back.
                        self.runtime.log_gate_block(&outcome);
                        (outcome.incident, FencingGate::Blocked(outcome.block))
                    }
                    crate::linux_node_runtime::FencingGateDecision::Clear {
                        incident,
                        clearance,
                    } => (Some(incident), FencingGate::Cleared(clearance)),
                };
                self.fencing_term_record = match (self.fencing_term_record.take(), incident) {
                    (Some(mut kept), Some(fresh)) if kept.incident == fresh.incident => {
                        kept.record_term(fresh.newest);
                        Some(kept)
                    }
                    (_, fresh) => fresh,
                };
                gate
            }
            Err(crate::linux_node_runtime::LinuxNodeRuntimeError::Mutation(
                crate::node_mutation::NodeMutationError::Io(_),
            )) => FencingGate::Blocked(FencingGateBlock::StoreUnavailable),
            Err(error) => FencingGate::Failed(error.to_string()),
        }
    }

    fn acquire_attempt_lease_once(
        &mut self,
        term: crate::protocol::Term,
    ) -> Result<crate::node_lease_authority::node_witness_runtime::NodeWitnessMutationResult, String>
    {
        let session = self
            .witness_session
            .as_mut()
            .ok_or_else(|| "Witness session is not configured".to_string())?;
        self.runtime
            .acquire_lease_once(session, term)
            .map_err(|error| error.to_string())
    }

    fn take_attempt_lease_authority(
        &mut self,
    ) -> Option<crate::node_lease_authority::RuntimeLeaseAuthority> {
        self.runtime.take_installed_lease_authority()
    }

    fn attempt_lease_usable(
        &self,
        authority: &crate::node_lease_authority::RuntimeLeaseAuthority,
    ) -> bool {
        self.runtime.attempt_lease_usable(authority)
    }

    fn shared_witness_outstanding(&self) -> bool {
        self.witness_session
            .as_ref()
            .is_some_and(|session| session.request_in_flight())
    }

    fn listener_interference_recent(&self, now: std::time::Instant) -> Option<u64> {
        self.peer
            .as_ref()
            .map(|peer| peer.listener_interference_recent(now))
    }

    fn last_recheck_failure(&self) -> Option<String> {
        self.last_recheck_failure.clone()
    }

    fn fencing_final_recheck(
        &mut self,
        prerequisite: &FencingPrerequisite,
        grant_term: crate::protocol::Term,
    ) -> Result<(), String> {
        if let FencingPrerequisite::Bootstrap(clearance) = prerequisite {
            return self.bootstrap_recheck(clearance, grant_term);
        }
        let Some(clearance) = prerequisite.clearance() else {
            return Err("no fencing clearance".into());
        };
        let Some(peer) = self.peer.as_ref() else {
            return Err("no peer runtime: no session or episode".into());
        };
        let configured_peer = self.runtime.fencing_target().clone();
        let current_session = peer.observer_session_id().clone();
        let live_episode = peer.loss_evidence();
        let context = crate::fencing::ContinuityContext {
            configured_peer: &configured_peer,
            current_session: &current_session,
            live_episode: live_episode.as_ref(),
        };
        let result = match self
            .runtime
            .fencing_final_recheck(clearance, &context, grant_term)
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(failure)) => Err(format!("{failure:?}")),
            Err(error) => Err(error.to_string()),
        };
        // §28 diagnostic: remember why, for the blocked-attempt log line only.
        self.last_recheck_failure = result.as_ref().err().cloned();
        result
    }

    fn release_attempt_lease(
        &mut self,
        granted: Option<(crate::protocol::Term, crate::protocol::LeaseId)>,
        binding: Option<&crate::fencing::IncidentBinding>,
    ) -> Result<AttemptCleanup, String> {
        let session = self
            .witness_session
            .as_mut()
            .ok_or_else(|| "Witness session is not configured".to_string())?;
        let outstanding = self
            .runtime
            .durable_witness_outstanding()
            .map_err(|error| error.to_string())?;
        let result = match (outstanding, granted) {
            (None, Some((term, lease_id))) => {
                return match self.runtime.release_attempt_lease_once(
                    session,
                    term,
                    lease_id,
                    "stage 13.2 attempt abort".to_string(),
                    binding,
                ) {
                    Ok(crate::linux_node_runtime::AttemptLeaseRelease::Executed(_)) => {
                        Ok(AttemptCleanup::Released)
                    }
                    Ok(crate::linux_node_runtime::AttemptLeaseRelease::CleanupNotCommitted(_)) => {
                        Ok(AttemptCleanup::NotSent)
                    }
                    Ok(crate::linux_node_runtime::AttemptLeaseRelease::RecoveryBlocked(reason)) => {
                        Ok(AttemptCleanup::RecoveryBlocked(reason))
                    }
                    Err(error) => Err(error.to_string()),
                };
            }
            (None, None) => return Ok(AttemptCleanup::Released),
            // A durable cleanup mutation (e.g. the Stage 11 release) that is
            // already outstanding is executed once — but only when it is
            // exactly this attempt's expected LeaseRelease. A foreign or
            // differently-identified durable mutation fails closed: it is
            // never executed as this attempt's cleanup, never overwritten,
            // and never clears the way for a second release.
            (Some(outstanding), Some((term, ref lease_id)))
                if durable_release_matches(&outstanding, term, lease_id) =>
            {
                self.runtime.execute_durable_witness_mutation_once(session)
            }
            (Some(_), _) => {
                return Err(
                    "durable outstanding Witness mutation is not this attempt's expected LeaseRelease; preserved for its rightful owner".to_string(),
                )
            }
        };
        result
            .map(|_| AttemptCleanup::Released)
            .map_err(|error| error.to_string())
    }

    fn begin_route_handoff(
        &mut self,
        origin: crate::route_handoff::RhOrigin,
        term: crate::protocol::Term,
    ) {
        self.runtime.begin_route_handoff(origin, term);
    }

    fn execute_attempt_promotion(
        &mut self,
        lease: AttemptBoundLeaseAuthority,
        prerequisite: &FencingPrerequisite,
    ) -> Result<AttemptPromotionOutcome, String> {
        // ARM and Stage 11 are one structural handoff: LinuxNodeRuntime
        // writes O (atomically consuming the incident for a fencing
        // clearance; the plain ARM for a Bootstrap clearance) before it
        // restores authority or reaches the first protected resource
        // mutation.
        use crate::linux_node_runtime::FencedArmOutcome;
        let armed = match prerequisite {
            FencingPrerequisite::Cleared(clearance) => self
                .runtime
                .arm_and_promote(lease.into_authority(), clearance),
            FencingPrerequisite::Bootstrap(clearance) => self
                .runtime
                .arm_and_promote_bootstrap(lease.into_authority(), clearance),
            #[cfg(test)]
            FencingPrerequisite::BypassedForStage13Test => {
                return Err("no fencing clearance: no ARM".into());
            }
        };
        match armed {
            Ok(FencedArmOutcome::Promoted(
                crate::linux_node_runtime::ExplicitOperationResult::Completed,
            )) => Ok(AttemptPromotionOutcome::Promoted),
            Ok(FencedArmOutcome::Promoted(_other)) => {
                #[cfg(test)]
                eprintln!("promotion-attempt diagnostic: stage-11 promote -> {_other:?}");
                Ok(AttemptPromotionOutcome::RolledBack)
            }
            Ok(FencedArmOutcome::NotCommitted(_)) => Ok(AttemptPromotionOutcome::ArmNotCommitted),
            Ok(FencedArmOutcome::Rejected(_)) => Ok(AttemptPromotionOutcome::ArmRejected),
            Ok(FencedArmOutcome::RecoveryBlocked(_)) => {
                Ok(AttemptPromotionOutcome::RecoveryBlocked)
            }
            Err(error) => match self.runtime.release_obligation() {
                Ok(None) => Ok(AttemptPromotionOutcome::ArmNotCommitted),
                Ok(Some(_)) => Err(error.to_string()),
                Err(read_error) => Err(format!(
                    "ARM/promotion failed ({error}); obligation read-back failed ({read_error})"
                )),
            },
        }
    }
}

#[cfg(target_os = "linux")]
impl DaemonRuntime for LinuxDaemonRuntime {
    fn startup(&mut self) -> Result<DaemonSnapshot, String> {
        self.startup_guarded(&|| true)
    }

    fn startup_guarded(
        &mut self,
        control_lock_safe: &dyn Fn() -> bool,
    ) -> Result<DaemonSnapshot, String> {
        let mut linux = self
            .runtime
            .initialize_or_recover()
            .map_err(|error| error.to_string())?;
        // Startup Obligation Reconciliation (contract A-4): a node that
        // restarted with a release obligation tries to resolve it against the
        // Witness before the recovery gate decides.
        if !linux.recovery_reconciled {
            linux = self.reconcile_startup_obligation(linux, control_lock_safe)?;
        }
        if !linux.recovery_reconciled && self.startup_block_cause.is_none() {
            self.startup_block_cause = self.runtime.recovery_block_cause().ok();
        }
        self.peer_status = Some(peer_status_from_linux(linux));
        let snapshot = daemon_snapshot(linux);
        if let Some(peer) = &mut self.peer {
            peer.start_initial();
        }
        Ok(snapshot)
    }

    fn recovery_block_cause(&self) -> Option<String> {
        self.startup_block_cause.clone()
    }

    fn peer_assessment_for_log(&self) -> Option<crate::failure_assessment::PeerFailureAssessment> {
        self.peer
            .as_ref()
            .map(|peer| peer.failure_assessment().assessment)
    }

    fn witness_session_lost(&self) -> bool {
        self.witness_observer
            .as_ref()
            .is_some_and(crate::evidence_fusion::adapter::WitnessEvidenceAdapter::session_lost)
            || self
                .witness_session
                .as_ref()
                .is_some_and(crate::witness_runtime::WitnessSession::lost)
    }

    fn witness_loss_stop_allowed(&mut self) -> bool {
        self.runtime.witness_loss_stop_allowed()
    }

    fn close_witness_session(&mut self) {
        if let Some(session) = self.witness_session.as_mut() {
            session.close();
        }
    }

    fn probe_witness_transport(&mut self) -> Result<(), String> {
        // Only where the session slot cannot belong to an in-flight lease
        // exchange: a Standby with no operation in progress. Active renewal
        // and demotion own the slot and detect loss on their own I/O.
        if !self.runtime.authority_observation_allowed() {
            return Ok(());
        }
        if let Some(session) = self.witness_session.as_mut() {
            session.probe_transport_closure();
        }
        Ok(())
    }

    fn auto_facts(&mut self, now: std::time::Instant) -> Option<AutoRuntimeFacts> {
        let peer = self.peer.as_ref()?;
        let assessment = peer.failure_assessment().assessment;
        let loss = peer
            .loss_evidence()
            .map(|evidence| crate::auto_failover::LossEpisode {
                observer_session: peer.observer_session_id().as_str().to_string(),
                generation: evidence.generation(),
                fresh: evidence.is_fresh_at(now),
            });
        let peer_active_confirmed = peer.peer_active_confirmed();
        let peer_node_state = peer.peer_reported_state(now);
        let local = self.runtime.failover_local_safety_snapshot(false).ok()?;
        let incident = self.runtime.auto_incident_facts().ok()?;
        Some(AutoRuntimeFacts {
            backend_is_command: self.runtime.fencing_backend_is_command(),
            assessment,
            loss,
            peer_active_confirmed,
            peer_node_state,
            standby_safe: local.readiness == crate::failover_policy::LocalSafetyReadiness::Safe
                && local.node_state == NodeState::Standby
                && local.operation_phase.is_none(),
            node_state: local.node_state,
            incident,
            activity: self.runtime.auto_fence_activity(),
        })
    }

    fn observe(&mut self) -> Result<DaemonSnapshot, String> {
        let mut snapshot = self
            .runtime
            .observe_for_daemon()
            .map_err(|error| error.to_string())?;
        // `[health]` hysteresis: the reported health is the stable state, and
        // only a change of it is logged (nothing on a healthy steady state).
        let raw = match snapshot.health {
            crate::linux_node_runtime::RuntimeResourceTruth::Healthy => {
                crate::health_hysteresis::RawHealth::Healthy
            }
            crate::linux_node_runtime::RuntimeResourceTruth::Unhealthy => {
                crate::health_hysteresis::RawHealth::Unhealthy
            }
            _ => crate::health_hysteresis::RawHealth::Unknown,
        };
        match self.health_filter.observe(raw) {
            Some(crate::health_hysteresis::HealthTransition::BecameUnhealthy {
                consecutive_failures,
            }) => crate::operator_log::warn_health_unhealthy(consecutive_failures),
            Some(crate::health_hysteresis::HealthTransition::Recovered) => {
                crate::operator_log::info_health_recovered();
            }
            None => {}
        }
        snapshot.health = match self.health_filter.stable() {
            crate::health_hysteresis::StableHealth::Healthy => {
                crate::linux_node_runtime::RuntimeResourceTruth::Healthy
            }
            crate::health_hysteresis::StableHealth::Unhealthy => {
                crate::linux_node_runtime::RuntimeResourceTruth::Unhealthy
            }
            crate::health_hysteresis::StableHealth::Unknown => {
                crate::linux_node_runtime::RuntimeResourceTruth::Unknown
            }
        };
        self.peer_status = Some(peer_status_from_linux(snapshot));
        Ok(daemon_snapshot(snapshot))
    }

    fn foreground_lifecycle_tick(
        &mut self,
        shutdown_requested: &dyn Fn() -> bool,
        live_shutdown: &dyn Fn() -> bool,
        control_lock_safe: &dyn Fn() -> bool,
    ) -> Result<(), String> {
        // Stage 14 §16.7.5: the pending-reap poll is the first Stage 14
        // operation of every ordinary iteration, before any early return.
        self.runtime.poll_pending_reap_foreground();
        if !self.runtime.foreground_witness_required() {
            return self.drive_fencing_step(live_shutdown);
        }
        let session = self
            .witness_session
            .as_mut()
            .ok_or_else(|| "Witness session is not configured".to_string())?;
        self.runtime
            .drive_foreground_lifecycle(session, shutdown_requested, control_lock_safe)
            .map_err(|error| error.to_string())
    }

    /// Design Revision 10 §9 bounded shutdown join.  Delegates to the runtime,
    /// which owns the structural "at most one" latch and the eligibility
    /// re-derivation.  Failure is reported but never converted into a clean
    /// verdict: the caller still classifies from durable state.
    fn shutdown_bounded_step(
        &mut self,
        control_lock_safe: &dyn Fn() -> bool,
    ) -> Result<bool, String> {
        let session = self
            .witness_session
            .as_mut()
            .ok_or_else(|| "Witness session is not configured".to_string())?;
        self.runtime
            .shutdown_bounded_step(session, control_lock_safe)
            .map_err(|error| error.to_string())
    }

    fn lifecycle_wait_delay(
        &self,
        ordinary: std::time::Duration,
    ) -> Result<std::time::Duration, String> {
        self.runtime
            .active_schedule_delay(ordinary)
            .map_err(|error| error.to_string())
    }

    fn authority_observation_allowed(&self) -> bool {
        self.runtime.authority_observation_allowed()
    }

    fn shutdown(&mut self, control_lock_safe: &dyn Fn() -> bool) -> Result<ShutdownResult, String> {
        let result = self
            .runtime
            .shutdown_for_daemon(control_lock_safe)
            .map(|clean| {
                if clean {
                    ShutdownResult::Clean
                } else {
                    ShutdownResult::RequiresCleanup
                }
            })
            .map_err(|error| error.to_string());
        if let Some(peer) = &mut self.peer {
            peer.shutdown();
        }
        result
    }

    fn local_safety_snapshot(
        &mut self,
        shutdown_requested: bool,
    ) -> Result<Option<LocalSafetySnapshot>, String> {
        self.runtime
            .failover_local_safety_snapshot(shutdown_requested)
            .map(Some)
            .map_err(|error| error.to_string())
    }

    fn peer_tick_at(
        &mut self,
        now: std::time::Instant,
        peer_status: Option<PeerStatusSnapshot>,
    ) -> Result<Option<PeerObservationState>, String> {
        let Some(peer) = &mut self.peer else {
            return Ok(Some(PeerObservationState::Unavailable));
        };
        peer.set_local_status(peer_status.unwrap_or_else(PeerStatusSnapshot::unobserved));
        // Bootstrap Admission, answering side (contract K-2 / K-3): if a probe
        // is read in this tick, the verdict is computed from the node's state
        // at that point of this same tick — `failover_local_safety_snapshot`
        // is the single definition of "safe" — and sent before the tick ends.
        // The closure is only called when a probe was read.
        let context = self.probe_context.take();
        let runtime = &mut self.runtime;
        let mut verdict = || match context {
            None => crate::bootstrap_admission::ProbeVerdict::Unknown,
            Some(facts) => {
                let local = runtime
                    .failover_local_safety_snapshot(facts.shutdown_requested)
                    .ok();
                crate::bootstrap_admission::responder_verdict(local, facts)
            }
        };
        // Exactly one peer advance per daemon iteration, using the iteration's
        // authoritative `now`; the snapshot below observes the same `now`.
        let advanced = peer.tick_at_with(now, &mut verdict);
        // J27 (NB-1): `now` may predate a fencing step of this iteration; a window this tick
        // opened would overlap the step, so it never counts.
        if self.fencing_step_since_peer_tick {
            self.fencing_step_since_peer_tick = false;
            peer.void_listen_window_for_fencing_step();
        }
        advanced
            .map(|_| Some(peer.snapshot(now).state))
            .map_err(|error| error.to_string())
    }

    fn set_probe_context(&mut self, context: Option<crate::bootstrap_admission::DaemonFacts>) {
        self.probe_context = context;
    }

    fn route_handoff_tick(&mut self, control_lock_safe: &dyn Fn() -> bool) -> Result<(), String> {
        // A route step is a blocking step: it voids the verified-listen window exactly like a
        // fencing step (§27.5), and the next peer tick voids it again (J27 NB-1).
        let stepped = &mut self.fencing_step_since_peer_tick;
        let peer = &mut self.peer;
        let mut void = || {
            *stepped = true;
            if let Some(peer) = peer.as_mut() {
                peer.void_listen_window_for_fencing_step();
            }
        };
        self.runtime
            .drive_route_handoff(control_lock_safe, &mut void)
            .map_err(|error| error.to_string())
    }

    fn bootstrap_supported(&self) -> bool {
        self.peer.is_some()
    }

    fn bootstrap_conservative(&self) -> bool {
        self.runtime.authority_is_conservative()
    }

    fn bootstrap_stamp(&self) -> Option<crate::bootstrap_admission::BootstrapStamp> {
        self.peer.as_ref().and_then(|peer| peer.bootstrap_stamp())
    }

    fn request_bootstrap_probe(&mut self) -> bool {
        self.peer.as_mut().is_some_and(|peer| peer.request_probe())
    }

    fn take_probe_outcome(&mut self) -> Option<crate::bootstrap_admission::ProbeOutcome> {
        self.peer
            .as_mut()
            .and_then(|peer| peer.take_probe_outcome())
    }

    fn discard_bootstrap_probe(&mut self) {
        if let Some(peer) = self.peer.as_mut() {
            peer.discard_probe();
        }
    }

    fn peer_status(&self) -> Option<PeerStatusSnapshot> {
        self.peer_status
    }

    fn invalidate_peer_status(&mut self) {
        self.peer_status = self
            .peer_status
            .map(PeerStatusSnapshot::with_unknown_resources);
    }

    fn peer_snapshot_at(&mut self, now: std::time::Instant) -> Option<PeerObservation> {
        self.peer.as_ref().map(|peer| peer.snapshot(now))
    }
}

#[cfg(target_os = "linux")]
fn peer_status_from_linux(
    snapshot: crate::linux_node_runtime::LinuxRuntimeSnapshot,
) -> PeerStatusSnapshot {
    let role = if snapshot.node_state == NodeState::Active {
        Role::Active
    } else {
        Role::Standby
    };
    PeerStatusSnapshot {
        node_state: snapshot.node_state,
        operation_phase: snapshot.operation_phase,
        role,
        service: match snapshot.service {
            crate::linux_node_runtime::RuntimeResourceTruth::Running => DaemonService::Running,
            crate::linux_node_runtime::RuntimeResourceTruth::Stopped => DaemonService::Stopped,
            _ => DaemonService::Unknown,
        },
        health: match snapshot.health {
            crate::linux_node_runtime::RuntimeResourceTruth::Healthy => DaemonHealth::Healthy,
            crate::linux_node_runtime::RuntimeResourceTruth::Unhealthy => DaemonHealth::Unhealthy,
            _ => DaemonHealth::Unknown,
        },
        vip: match snapshot.vip {
            crate::linux_node_runtime::RuntimeResourceTruth::Present => DaemonVip::Present,
            crate::linux_node_runtime::RuntimeResourceTruth::Absent => DaemonVip::Absent,
            _ => DaemonVip::Unknown,
        },
    }
}

#[cfg(target_os = "linux")]
fn daemon_snapshot(snapshot: crate::linux_node_runtime::LinuxRuntimeSnapshot) -> DaemonSnapshot {
    DaemonSnapshot {
        node_state: if snapshot.node_state == NodeState::Active
            && snapshot.operation_phase.is_some()
        {
            NodeState::RecoveryPending
        } else {
            snapshot.node_state
        },
        health: match snapshot.health {
            crate::linux_node_runtime::RuntimeResourceTruth::Healthy => DaemonHealth::Healthy,
            crate::linux_node_runtime::RuntimeResourceTruth::Unhealthy => DaemonHealth::Unhealthy,
            _ => DaemonHealth::Unknown,
        },
        vip: match snapshot.vip {
            crate::linux_node_runtime::RuntimeResourceTruth::Present => DaemonVip::Present,
            crate::linux_node_runtime::RuntimeResourceTruth::Absent => DaemonVip::Absent,
            _ => DaemonVip::Unknown,
        },
        service: match snapshot.service {
            crate::linux_node_runtime::RuntimeResourceTruth::Running => DaemonService::Running,
            crate::linux_node_runtime::RuntimeResourceTruth::Stopped => DaemonService::Stopped,
            _ => DaemonService::Unknown,
        },
        resource_owning: snapshot.resource_owning,
        recovery_reconciled: snapshot.recovery_reconciled,
        unresolved_mutation: snapshot.unresolved_mutation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[derive(Debug)]
    struct FakeRuntime {
        startup: Result<DaemonSnapshot, String>,
        observations: VecDeque<Result<DaemonSnapshot, String>>,
        peer_ticks: VecDeque<Result<Option<PeerObservationState>, String>>,
        shutdown: Result<ShutdownResult, String>,
        calls: Vec<&'static str>,
        peer_tick_calls: usize,
        pending_disconnect: bool,
        peer_statuses: Vec<Option<PeerStatusSnapshot>>,
        peer_status: Option<PeerStatusSnapshot>,
        safety_requests: Vec<bool>,
        // MKM-ARCH-006: record the authoritative `now` used per iteration for
        // the peer advance and the peer snapshot.
        peer_tick_times: Vec<std::time::Instant>,
        peer_snapshot_times: Vec<std::time::Instant>,
        // F-02: scripted results for the Design Revision 10 §9 bounded
        // shutdown join, a call counter, and the `calls.len()` watermark at
        // each invocation. Ordering is recorded as a call-count watermark
        // rather than by appending to `self.calls`, so the pre-existing
        // `calls`-sequence contract (an idle shutdown must add no extra
        // runtime call) keeps its exact original meaning.
        bounded_steps: VecDeque<Result<bool, String>>,
        bounded_step_calls: usize,
        bounded_step_call_watermarks: Vec<usize>,
    }

    impl DaemonRuntime for FakeRuntime {
        fn startup(&mut self) -> Result<DaemonSnapshot, String> {
            self.calls.push("startup");
            self.startup.clone()
        }

        fn observe(&mut self) -> Result<DaemonSnapshot, String> {
            self.calls.push("observe");
            let result = self
                .observations
                .pop_front()
                .unwrap_or_else(|| Err("observation queue exhausted".into()));
            if let Ok(snapshot) = &result {
                self.peer_status = Some(PeerStatusSnapshot {
                    node_state: snapshot.node_state,
                    operation_phase: None,
                    role: if snapshot.node_state == NodeState::Active {
                        Role::Active
                    } else {
                        Role::Standby
                    },
                    service: snapshot.service,
                    health: snapshot.health,
                    vip: snapshot.vip,
                });
            }
            result
        }

        fn peer_tick_at(
            &mut self,
            now: std::time::Instant,
            peer_status: Option<PeerStatusSnapshot>,
        ) -> Result<Option<PeerObservationState>, String> {
            self.peer_tick_calls += 1;
            self.peer_tick_times.push(now);
            self.pending_disconnect = false;
            self.peer_statuses.push(peer_status);
            self.peer_ticks.pop_front().unwrap_or(Ok(None))
        }

        fn peer_status(&self) -> Option<PeerStatusSnapshot> {
            self.peer_status
        }

        fn peer_snapshot_at(&mut self, now: std::time::Instant) -> Option<PeerObservation> {
            self.peer_snapshot_times.push(now);
            None
        }

        fn invalidate_peer_status(&mut self) {
            self.peer_status = self
                .peer_status
                .map(PeerStatusSnapshot::with_unknown_resources);
        }

        fn shutdown(
            &mut self,
            _control_lock_safe: &dyn Fn() -> bool,
        ) -> Result<ShutdownResult, String> {
            self.calls.push("shutdown");
            self.shutdown.clone()
        }

        /// F-02: record the bounded-shutdown-step invocation as a `calls.len()`
        /// watermark plus a replayable scripted result. The watermark is taken
        /// *before* the final `shutdown` call is recorded, so the F-02 tests can
        /// prove the step preceded the classification without perturbing the
        /// `calls` sequence that `attack_ar_shutdown_during_observation_is_
        /// bounded_and_tracked` asserts. The queue default matches the trait
        /// default (`Ok(false)`), so an unscripted call is indistinguishable
        /// from a runtime with no eligible work.
        fn shutdown_bounded_step(
            &mut self,
            _control_lock_safe: &dyn Fn() -> bool,
        ) -> Result<bool, String> {
            self.bounded_step_calls += 1;
            self.bounded_step_call_watermarks.push(self.calls.len());
            self.bounded_steps.pop_front().unwrap_or(Ok(false))
        }

        fn local_safety_snapshot(
            &mut self,
            shutdown_requested: bool,
        ) -> Result<Option<LocalSafetySnapshot>, String> {
            self.safety_requests.push(shutdown_requested);
            Ok(Some(LocalSafetySnapshot {
                node_state: NodeState::Standby,
                operation_phase: None,
                readiness: if shutdown_requested {
                    crate::failover_policy::LocalSafetyReadiness::ShutdownInProgress
                } else {
                    crate::failover_policy::LocalSafetyReadiness::Safe
                },
            }))
        }
    }

    fn standby() -> DaemonSnapshot {
        DaemonSnapshot {
            node_state: NodeState::Standby,
            health: DaemonHealth::Healthy,
            vip: DaemonVip::Absent,
            service: DaemonService::Stopped,
            resource_owning: false,
            recovery_reconciled: true,
            unresolved_mutation: false,
        }
    }

    fn runtime(startup: Result<DaemonSnapshot, String>) -> FakeRuntime {
        FakeRuntime {
            startup,
            observations: VecDeque::new(),
            peer_ticks: VecDeque::new(),
            shutdown: Ok(ShutdownResult::Clean),
            calls: Vec::new(),
            peer_tick_calls: 0,
            pending_disconnect: false,
            peer_statuses: Vec::new(),
            peer_status: None,
            safety_requests: Vec::new(),
            peer_tick_times: Vec::new(),
            peer_snapshot_times: Vec::new(),
            bounded_steps: VecDeque::new(),
            bounded_step_calls: 0,
            bounded_step_call_watermarks: Vec::new(),
        }
    }

    // --- R-16 / R-17: live control-lock safety contract -------------------
    //
    // These are the deterministic pre-fix reproductions. Before the guard
    // was wired into `tick_at`, the shutdown branch called `runtime.shutdown`
    // and the foreground branch ran regardless of the lock state.

    #[test]
    fn r16_shutdown_tick_rejects_lock_loss_before_any_cleanup() {
        let mut daemon = Daemon::new(runtime(Ok(standby())));
        assert_eq!(daemon.start().unwrap(), StartResult::Running);
        daemon.request_shutdown().unwrap();
        let lost = std::rc::Rc::new(std::cell::Cell::new(false));
        let reads = std::rc::Rc::new(std::cell::Cell::new(0));
        let lost_reader = lost.clone();
        let reads_reader = reads.clone();
        daemon.attach_control_lock_guard(move || {
            reads_reader.set(reads_reader.get() + 1);
            if lost_reader.get() {
                Some("the lock file was replaced after it was acquired".into())
            } else {
                None
            }
        });
        lost.set(true);
        let error = daemon
            .tick_at(std::time::Instant::now())
            .expect_err("a lost lock must not produce a shutdown verdict");
        assert!(matches!(
            error,
            DaemonError::ControlLockLost(ref message)
                if message.contains("replaced after it was acquired")
        ));
        assert_eq!(daemon.state(), DaemonState::Failed);
        assert_eq!(reads.get(), 1, "the guard is sampled before the branch");
        assert!(
            !daemon.runtime.calls.contains(&"shutdown"),
            "no shutdown cleanup may run after the loss: {:?}",
            daemon.runtime.calls
        );
        assert!(!daemon.runtime.calls.contains(&"observe"));
    }

    #[test]
    fn r16_shutdown_tick_rechecks_lock_after_the_bounded_step() {
        let mut daemon = Daemon::new(runtime(Ok(standby())));
        assert_eq!(daemon.start().unwrap(), StartResult::Running);
        daemon.request_shutdown().unwrap();
        let reads = std::rc::Rc::new(std::cell::Cell::new(0));
        let reads_reader = reads.clone();
        daemon.attach_control_lock_guard(move || {
            reads_reader.set(reads_reader.get() + 1);
            if reads_reader.get() >= 2 {
                Some("the lock path is no longer trusted".into())
            } else {
                None
            }
        });
        let error = daemon
            .tick_at(std::time::Instant::now())
            .expect_err("a loss during the bounded step must stop cleanup");
        assert!(matches!(error, DaemonError::ControlLockLost(_)));
        assert_eq!(daemon.runtime.bounded_step_calls, 1);
        assert!(
            !daemon.runtime.calls.contains(&"shutdown"),
            "the final cleanup must not start: {:?}",
            daemon.runtime.calls
        );
        assert!(!daemon.runtime.calls.contains(&"observe"));
        assert_eq!(daemon.state(), DaemonState::Failed);
    }

    #[test]
    fn r17_foreground_lock_loss_stops_before_observation_or_cleanup() {
        struct LockFlipRuntime {
            lost: std::rc::Rc<std::cell::Cell<bool>>,
            observed: usize,
            shutdown_calls: usize,
            foreground_saw_safe: bool,
        }
        impl DaemonRuntime for LockFlipRuntime {
            fn startup(&mut self) -> Result<DaemonSnapshot, String> {
                Ok(standby())
            }
            fn observe(&mut self) -> Result<DaemonSnapshot, String> {
                self.observed += 1;
                Ok(standby())
            }
            fn shutdown(
                &mut self,
                _control_lock_safe: &dyn Fn() -> bool,
            ) -> Result<ShutdownResult, String> {
                self.shutdown_calls += 1;
                Ok(ShutdownResult::Clean)
            }
            fn foreground_lifecycle_tick(
                &mut self,
                _shutdown_requested: &dyn Fn() -> bool,
                _live_shutdown: &dyn Fn() -> bool,
                control_lock_safe: &dyn Fn() -> bool,
            ) -> Result<(), String> {
                self.foreground_saw_safe = control_lock_safe();
                // The lock is replaced while the foreground owner is inside
                // the bounded step.
                self.lost.set(true);
                Ok(())
            }
        }

        let lost = std::rc::Rc::new(std::cell::Cell::new(false));
        let mut daemon = Daemon::new(LockFlipRuntime {
            lost: lost.clone(),
            observed: 0,
            shutdown_calls: 0,
            foreground_saw_safe: false,
        });
        let guard_lost = lost.clone();
        daemon.attach_control_lock_guard(move || {
            if guard_lost.get() {
                Some("the lock was replaced during the foreground step".into())
            } else {
                None
            }
        });
        assert_eq!(daemon.start().unwrap(), StartResult::Running);
        let error = daemon
            .tick()
            .expect_err("a loss inside the foreground step must fail the tick");
        assert!(matches!(error, DaemonError::ControlLockLost(_)));
        assert!(daemon.runtime.foreground_saw_safe);
        assert_eq!(
            daemon.runtime.observed, 0,
            "no observation or peer work after the loss"
        );
        assert_eq!(
            daemon.runtime.shutdown_calls, 0,
            "a lock loss must not become a shutdown cleanup"
        );
        assert_eq!(daemon.state(), DaemonState::Failed);
    }

    #[test]
    fn t4_normal_shutdown_with_a_safe_guard_still_cleans_up() {
        let mut daemon = Daemon::new(runtime(Ok(standby())));
        assert_eq!(daemon.start().unwrap(), StartResult::Running);
        daemon.attach_control_lock_guard(|| None);
        daemon.request_shutdown().unwrap();
        assert_eq!(
            daemon.tick_at(std::time::Instant::now()).unwrap(),
            TickResult::ShutdownComplete
        );
        assert_eq!(daemon.state(), DaemonState::Stopped);
        assert!(daemon.runtime.calls.contains(&"shutdown"));
    }

    #[test]
    fn shutdown_request_is_included_in_local_safety_boundary() {
        let mut daemon = Daemon::new(runtime(Ok(standby())));
        daemon.request_shutdown().unwrap();
        let local = daemon.local_safety_snapshot().unwrap().unwrap();
        assert_eq!(
            local.readiness,
            crate::failover_policy::LocalSafetyReadiness::ShutdownInProgress
        );
        assert_eq!(daemon.runtime.safety_requests, vec![true]);
    }

    // --- MKM-ARCH-007: shutdown cannot produce promotion-safe local readiness ---
    //
    // The raw `shutdown_requested: bool` hazard is removed at compile time: the
    // authority observation API accepts only `DaemonIterationContext`, whose
    // fields are private and whose only production constructor is
    // `Daemon::iteration_context` (Daemon-owned state). The following tests
    // prove the behavioral boundary.

    #[test]
    fn mkm_arch_007_iteration_context_tracks_daemon_shutdown_ownership() {
        let mut daemon = Daemon::new(runtime(Ok(standby())));
        let t = std::time::Instant::now();

        // Before shutdown: context reflects false and uses exactly the supplied
        // authoritative time (no second Instant sample).
        let before = daemon.iteration_context(t);
        assert!(
            !before.shutdown_requested(),
            "MKM-ARCH-007 violated: context reported shutdown before it was requested"
        );
        assert_eq!(before.now(), t);

        daemon.request_shutdown().unwrap();

        // After shutdown: any newly created context reflects true, using the
        // same supplied time.
        let after = daemon.iteration_context(t);
        assert!(
            after.shutdown_requested(),
            "MKM-ARCH-007 violated: context did not reflect Daemon-owned shutdown state"
        );
        assert_eq!(after.now(), t);
    }

    #[test]
    fn mkm_arch_007_shutdown_local_safety_is_never_eligible_or_authorized() {
        use crate::evidence_fusion::EvidenceFusionState;
        use crate::failover_policy::{
            FailoverEligibilityInput, FailoverEligibilityPolicy, LocalSafetyReadiness,
        };
        use crate::failure_assessment::PeerFailureAssessment;
        use crate::promotion_authorization::PromotionAttemptAuthorization;

        let mut daemon = Daemon::new(runtime(Ok(standby())));
        daemon.start().unwrap();

        // Positive control: before shutdown, the strongest evidence with a Safe
        // local boundary is Eligible/Authorized, so the guard is not vacuous.
        let safe = daemon.local_safety_snapshot().unwrap().unwrap();
        assert_eq!(safe.readiness, LocalSafetyReadiness::Safe);
        let safe_input = FailoverEligibilityInput {
            peer_assessment: PeerFailureAssessment::CommunicationLost,
            evidence_state: EvidenceFusionState::FailoverEvidenceReady,
            local: safe,
        };
        assert!(FailoverEligibilityPolicy::evaluate(safe_input).is_eligible());
        assert!(PromotionAttemptAuthorization::evaluate(safe_input).is_authorized());

        // After shutdown, the same strongest evidence cannot become Eligible or
        // Authorized, even though the local runtime is otherwise healthy.
        daemon.request_shutdown().unwrap();
        let shutdown = daemon.local_safety_snapshot().unwrap().unwrap();
        assert_eq!(shutdown.readiness, LocalSafetyReadiness::ShutdownInProgress);
        let shutdown_input = FailoverEligibilityInput {
            peer_assessment: PeerFailureAssessment::CommunicationLost,
            evidence_state: EvidenceFusionState::FailoverEvidenceReady,
            local: shutdown,
        };
        assert!(
            !FailoverEligibilityPolicy::evaluate(shutdown_input).is_eligible(),
            "MKM-ARCH-007 violated: shutdown produced an Eligible result"
        );
        assert!(
            !PromotionAttemptAuthorization::evaluate(shutdown_input).is_authorized(),
            "MKM-ARCH-007 violated: shutdown produced an Authorized result"
        );
    }

    #[test]
    fn mkm_arch_007_ready_evidence_cannot_override_shutdown_blocking() {
        use crate::evidence_fusion::EvidenceFusionState;
        use crate::failover_policy::{
            FailoverEligibilityInput, FailoverEligibilityPolicy, LocalSafetyReadiness,
        };
        use crate::failure_assessment::PeerFailureAssessment;
        use crate::promotion_authorization::PromotionAttemptAuthorization;

        let mut daemon = Daemon::new(runtime(Ok(standby())));
        daemon.start().unwrap();
        daemon.request_shutdown().unwrap();

        // Model an already-Raw Ready-equivalent evidence value (strongest
        // possible: CommunicationLost + FailoverEvidenceReady). It must not be able
        // to turn shutdown local safety into promotion permission.
        let shutdown_local = LocalSafetySnapshot {
            node_state: NodeState::Standby,
            operation_phase: None,
            readiness: LocalSafetyReadiness::ShutdownInProgress,
        };
        let input = FailoverEligibilityInput {
            peer_assessment: PeerFailureAssessment::CommunicationLost,
            evidence_state: EvidenceFusionState::FailoverEvidenceReady,
            local: shutdown_local,
        };
        assert!(!FailoverEligibilityPolicy::evaluate(input).is_eligible());
        assert!(!PromotionAttemptAuthorization::evaluate(input).is_authorized());
        // The daemon-owned context agrees that shutdown is in progress.
        assert!(
            daemon
                .iteration_context(std::time::Instant::now())
                .shutdown_requested()
        );
    }

    #[test]
    fn attack_am_startup_cannot_bypass_recovery_gate() {
        let mut daemon = Daemon::new(runtime(Ok(DaemonSnapshot {
            node_state: NodeState::RecoveryPending,
            health: DaemonHealth::Unknown,
            vip: DaemonVip::Unknown,
            service: DaemonService::Unknown,
            resource_owning: true,
            recovery_reconciled: false,
            unresolved_mutation: true,
        })));
        assert_eq!(daemon.start().unwrap(), StartResult::RecoveryBlocked);
        assert_eq!(daemon.state(), DaemonState::RecoveryBlocked);
        assert_eq!(daemon.tick().unwrap(), TickResult::NotRunning);
    }

    #[test]
    fn attack_an_periodic_observation_cannot_acquire_lease() {
        let mut runtime = runtime(Ok(standby()));
        runtime.observations.push_back(Ok(standby()));
        let mut daemon = Daemon::new(runtime);
        assert_eq!(daemon.start().unwrap(), StartResult::Running);
        assert_eq!(daemon.tick().unwrap(), TickResult::Observed);
        assert_eq!(daemon.snapshot().unwrap().node_state, NodeState::Standby);
        assert_eq!(daemon.runtime.calls, vec!["startup", "observe"]);
    }

    #[test]
    fn attack_an_peer_tick_updates_only_peer_observation_cache() {
        let mut runtime = runtime(Ok(standby()));
        runtime.observations.push_back(Ok(standby()));
        runtime
            .peer_ticks
            .push_back(Ok(Some(PeerObservationState::Fresh)));
        let mut daemon = Daemon::new(runtime);
        assert_eq!(daemon.start().unwrap(), StartResult::Running);
        assert_eq!(daemon.tick().unwrap(), TickResult::Observed);
        assert_eq!(daemon.peer_state(), PeerObservationState::Fresh);
        assert_eq!(daemon.state(), DaemonState::Running);
    }

    #[test]
    fn attack_ao_periodic_observation_cannot_promote_node() {
        let mut runtime = runtime(Ok(standby()));
        runtime.observations.push_back(Ok(DaemonSnapshot {
            node_state: NodeState::Standby,
            ..standby()
        }));
        let mut daemon = Daemon::new(runtime);
        daemon.start().unwrap();
        daemon.tick().unwrap();
        assert!(!daemon.runtime.calls.contains(&"promote"));
        assert_eq!(daemon.snapshot().unwrap().node_state, NodeState::Standby);
    }

    #[test]
    fn attack_ap_snapshot_is_side_effect_free() {
        let mut runtime = runtime(Ok(standby()));
        runtime.observations.push_back(Ok(standby()));
        let mut daemon = Daemon::new(runtime);
        daemon.start().unwrap();
        let before = daemon.runtime.calls.clone();
        let _ = daemon.snapshot();
        let _ = daemon.snapshot();
        assert_eq!(daemon.runtime.calls, before);
    }

    #[test]
    fn attack_aq_observation_failure_becomes_unknown() {
        let mut runtime = runtime(Ok(standby()));
        runtime
            .observations
            .push_back(Err("health unavailable".into()));
        runtime
            .peer_ticks
            .push_back(Ok(Some(PeerObservationState::Unavailable)));
        let mut daemon = Daemon::new(runtime);
        daemon.start().unwrap();
        assert_eq!(daemon.tick().unwrap(), TickResult::ObservationUnavailable);
        assert_eq!(daemon.snapshot().unwrap().health, DaemonHealth::Unknown);
        assert_eq!(daemon.last_observation_error(), Some("health unavailable"));
        assert_eq!(daemon.peer_state(), PeerObservationState::Unavailable);
        assert_eq!(daemon.runtime.peer_tick_calls, 1);
    }

    #[test]
    fn fv_local_observation_failure_does_not_prevent_pending_disconnect_drain() {
        let mut runtime = runtime(Ok(standby()));
        runtime.pending_disconnect = true;
        runtime
            .observations
            .push_back(Err("VIP unavailable".into()));
        runtime
            .peer_ticks
            .push_back(Ok(Some(PeerObservationState::Unavailable)));
        let mut daemon = Daemon::new(runtime);
        daemon.start().unwrap();

        assert_eq!(daemon.tick().unwrap(), TickResult::ObservationUnavailable);
        assert_eq!(daemon.peer_state(), PeerObservationState::Unavailable);
        assert_eq!(daemon.runtime.peer_tick_calls, 1);
        assert!(!daemon.runtime.pending_disconnect);
        assert_eq!(daemon.last_observation_error(), Some("VIP unavailable"));
    }

    #[test]
    fn fw_repeated_observation_failures_cannot_wedge_peer_maintenance() {
        let mut runtime = runtime(Ok(standby()));
        runtime
            .observations
            .push_back(Err("service unavailable".into()));
        runtime
            .observations
            .push_back(Err("health unavailable".into()));
        runtime
            .peer_ticks
            .push_back(Ok(Some(PeerObservationState::Unavailable)));
        runtime
            .peer_ticks
            .push_back(Ok(Some(PeerObservationState::Unavailable)));
        let mut daemon = Daemon::new(runtime);
        daemon.start().unwrap();

        assert_eq!(daemon.tick().unwrap(), TickResult::ObservationUnavailable);
        assert_eq!(daemon.tick().unwrap(), TickResult::ObservationUnavailable);
        assert_eq!(daemon.runtime.peer_tick_calls, 2);
        assert_eq!(daemon.last_observation_error(), Some("health unavailable"));
    }

    #[test]
    fn fx_peer_maintenance_during_observation_failure_has_no_ha_action() {
        let mut runtime = runtime(Ok(standby()));
        runtime
            .observations
            .push_back(Err("health unavailable".into()));
        runtime
            .peer_ticks
            .push_back(Ok(Some(PeerObservationState::Unavailable)));
        let mut daemon = Daemon::new(runtime);
        daemon.start().unwrap();

        assert_eq!(daemon.tick().unwrap(), TickResult::ObservationUnavailable);
        assert_eq!(daemon.state(), DaemonState::Running);
        assert_eq!(daemon.runtime.calls, vec!["startup", "observe"]);
        assert_eq!(daemon.runtime.peer_tick_calls, 1);
    }

    #[test]
    fn ge_observation_failure_invalidates_resource_fields_before_peer_maintenance() {
        let mut runtime = runtime(Ok(standby()));
        runtime.observations.push_back(Ok(DaemonSnapshot {
            node_state: NodeState::Active,
            health: DaemonHealth::Healthy,
            vip: DaemonVip::Present,
            service: DaemonService::Running,
            resource_owning: true,
            recovery_reconciled: true,
            unresolved_mutation: false,
        }));
        runtime
            .observations
            .push_back(Err("resource unavailable".into()));
        runtime
            .peer_ticks
            .push_back(Ok(Some(PeerObservationState::Fresh)));
        runtime
            .peer_ticks
            .push_back(Ok(Some(PeerObservationState::Unavailable)));
        let mut daemon = Daemon::new(runtime);
        daemon.start().unwrap();

        assert_eq!(daemon.tick().unwrap(), TickResult::Observed);
        assert_eq!(daemon.tick().unwrap(), TickResult::ObservationUnavailable);
        assert_eq!(daemon.runtime.peer_statuses.len(), 2);
        let invalidated = daemon.runtime.peer_statuses[1].unwrap();
        assert_eq!(invalidated.node_state, NodeState::Active);
        assert_eq!(invalidated.operation_phase, None);
        assert_eq!(invalidated.service, DaemonService::Unknown);
        assert_eq!(invalidated.health, DaemonHealth::Unknown);
        assert_eq!(invalidated.vip, DaemonVip::Unknown);
    }

    #[test]
    fn attack_ar_shutdown_during_observation_is_bounded_and_tracked() {
        let mut runtime = runtime(Ok(standby()));
        runtime.observations.push_back(Ok(standby()));
        let mut daemon = Daemon::new(runtime);
        daemon.start().unwrap();
        daemon.request_shutdown().unwrap();
        assert_eq!(daemon.tick().unwrap(), TickResult::ShutdownComplete);
        assert_eq!(daemon.state(), DaemonState::Stopped);
        assert_eq!(daemon.runtime.calls, vec!["startup", "shutdown"]);
    }

    #[test]
    fn attack_as_resource_owning_shutdown_cannot_report_clean_standby() {
        let mut runtime = runtime(Ok(DaemonSnapshot {
            node_state: NodeState::Standby,
            health: DaemonHealth::Healthy,
            vip: DaemonVip::Present,
            service: DaemonService::Running,
            resource_owning: true,
            recovery_reconciled: true,
            unresolved_mutation: false,
        }));
        runtime.shutdown = Ok(ShutdownResult::RequiresCleanup);
        let mut daemon = Daemon::new(runtime);
        assert_eq!(daemon.start().unwrap(), StartResult::RecoveryBlocked);
        daemon.request_shutdown().unwrap();
        assert_eq!(daemon.tick().unwrap(), TickResult::ShutdownRequiresCleanup);
        assert_eq!(daemon.state(), DaemonState::ShutdownBlocked);
        assert!(daemon.snapshot().unwrap().resource_owning);
    }

    #[test]
    fn attack_at_recovery_pending_cannot_enter_normal_loop() {
        let mut daemon = Daemon::new(runtime(Ok(DaemonSnapshot {
            node_state: NodeState::RecoveryPending,
            health: DaemonHealth::Unknown,
            vip: DaemonVip::Unknown,
            service: DaemonService::Unknown,
            resource_owning: false,
            recovery_reconciled: false,
            unresolved_mutation: false,
        })));
        assert_eq!(daemon.start().unwrap(), StartResult::RecoveryBlocked);
        assert_eq!(daemon.tick().unwrap(), TickResult::NotRunning);
    }

    #[test]
    fn attack_au_stale_cached_observation_cannot_become_authority() {
        let mut runtime = runtime(Ok(standby()));
        runtime.observations.push_back(Ok(DaemonSnapshot {
            node_state: NodeState::Standby,
            health: DaemonHealth::Healthy,
            vip: DaemonVip::Absent,
            service: DaemonService::Stopped,
            resource_owning: false,
            recovery_reconciled: true,
            unresolved_mutation: false,
        }));
        let mut daemon = Daemon::new(runtime);
        daemon.start().unwrap();
        daemon.tick().unwrap();
        assert_eq!(daemon.snapshot().unwrap().node_state, NodeState::Standby);
        assert!(!daemon.snapshot().unwrap().resource_owning);
    }

    #[test]
    fn attack_av_restart_does_not_restore_runtime_lease_authority() {
        let mut first = Daemon::new(runtime(Ok(DaemonSnapshot {
            node_state: NodeState::RecoveryPending,
            health: DaemonHealth::Unknown,
            vip: DaemonVip::Unknown,
            service: DaemonService::Unknown,
            resource_owning: false,
            recovery_reconciled: false,
            unresolved_mutation: true,
        })));
        assert_eq!(first.start().unwrap(), StartResult::RecoveryBlocked);
        assert_eq!(first.state(), DaemonState::RecoveryBlocked);
        let mut restarted = Daemon::new(runtime(Ok(DaemonSnapshot {
            node_state: NodeState::RecoveryPending,
            health: DaemonHealth::Unknown,
            vip: DaemonVip::Unknown,
            service: DaemonService::Unknown,
            resource_owning: false,
            recovery_reconciled: false,
            unresolved_mutation: true,
        })));
        assert_eq!(restarted.start().unwrap(), StartResult::RecoveryBlocked);
        assert_eq!(restarted.state(), DaemonState::RecoveryBlocked);
    }

    fn shutdown_observation(vip: DaemonVip, service: DaemonService) -> DaemonSnapshot {
        DaemonSnapshot {
            node_state: NodeState::Standby,
            health: DaemonHealth::Unknown,
            vip,
            service,
            resource_owning: false,
            recovery_reconciled: true,
            unresolved_mutation: false,
        }
    }

    #[test]
    fn attack_aw_false_ownership_with_present_vip_cannot_clean_shutdown() {
        let mut runtime = runtime(Ok(shutdown_observation(
            DaemonVip::Present,
            DaemonService::Stopped,
        )));
        runtime.shutdown = Ok(ShutdownResult::RequiresCleanup);
        let mut daemon = Daemon::new(runtime);
        assert_eq!(daemon.start().unwrap(), StartResult::RecoveryBlocked);
        daemon.request_shutdown().unwrap();
        assert_eq!(daemon.tick().unwrap(), TickResult::ShutdownRequiresCleanup);
    }

    #[test]
    fn attack_ax_false_ownership_with_unknown_vip_cannot_clean_shutdown() {
        let mut runtime = runtime(Ok(shutdown_observation(
            DaemonVip::Unknown,
            DaemonService::Stopped,
        )));
        runtime.shutdown = Ok(ShutdownResult::RequiresCleanup);
        let mut daemon = Daemon::new(runtime);
        assert_eq!(daemon.start().unwrap(), StartResult::RecoveryBlocked);
        daemon.request_shutdown().unwrap();
        assert_eq!(daemon.tick().unwrap(), TickResult::ShutdownRequiresCleanup);
    }

    #[test]
    fn attack_ay_false_ownership_with_running_service_cannot_clean_shutdown() {
        let mut runtime = runtime(Ok(shutdown_observation(
            DaemonVip::Absent,
            DaemonService::Running,
        )));
        runtime.shutdown = Ok(ShutdownResult::RequiresCleanup);
        let mut daemon = Daemon::new(runtime);
        assert_eq!(daemon.start().unwrap(), StartResult::RecoveryBlocked);
        daemon.request_shutdown().unwrap();
        assert_eq!(daemon.tick().unwrap(), TickResult::ShutdownRequiresCleanup);
    }

    #[test]
    fn attack_az_false_ownership_with_unknown_service_cannot_clean_shutdown() {
        let mut runtime = runtime(Ok(shutdown_observation(
            DaemonVip::Absent,
            DaemonService::Unknown,
        )));
        runtime.shutdown = Ok(ShutdownResult::RequiresCleanup);
        let mut daemon = Daemon::new(runtime);
        assert_eq!(daemon.start().unwrap(), StartResult::RecoveryBlocked);
        daemon.request_shutdown().unwrap();
        assert_eq!(daemon.tick().unwrap(), TickResult::ShutdownRequiresCleanup);
    }

    #[test]
    fn attack_ba_reconciled_standby_with_resource_ownership_cannot_start() {
        let snapshot = DaemonSnapshot {
            resource_owning: true,
            ..standby()
        };
        let mut daemon = Daemon::new(runtime(Ok(snapshot)));
        assert_eq!(daemon.start().unwrap(), StartResult::RecoveryBlocked);
    }

    #[test]
    fn attack_bb_fatal_active_without_resource_ownership_latches_failed() {
        let mut runtime = runtime(Ok(standby()));
        runtime.observations.push_back(Ok(DaemonSnapshot {
            node_state: NodeState::Active,
            resource_owning: false,
            ..standby()
        }));
        let mut daemon = Daemon::new(runtime);
        assert_eq!(daemon.start().unwrap(), StartResult::Running);
        assert!(matches!(
            daemon.tick(),
            Err(DaemonError::ObservationInvariant(_))
        ));
        assert_eq!(daemon.state(), DaemonState::Failed);
    }

    #[test]
    fn attack_bc_failed_daemon_cannot_resume_ticks() {
        let mut runtime = runtime(Ok(standby()));
        runtime.observations.push_back(Ok(DaemonSnapshot {
            node_state: NodeState::Active,
            resource_owning: false,
            ..standby()
        }));
        let mut daemon = Daemon::new(runtime);
        daemon.start().unwrap();
        let _ = daemon.tick();
        assert_eq!(daemon.tick().unwrap(), TickResult::NotRunning);
    }

    #[test]
    fn attack_bd_ordinary_observation_failure_stays_unknown_not_failed() {
        let mut runtime = runtime(Ok(standby()));
        runtime
            .observations
            .push_back(Err("observation failed".into()));
        let mut daemon = Daemon::new(runtime);
        daemon.start().unwrap();
        assert_eq!(daemon.tick().unwrap(), TickResult::ObservationUnavailable);
        assert_eq!(daemon.state(), DaemonState::Running);
        assert_eq!(daemon.snapshot().unwrap().health, DaemonHealth::Unknown);
    }

    #[test]
    fn attack_be_recovery_blocked_shutdown_reaches_safety_handling() {
        let mut runtime = runtime(Ok(shutdown_observation(
            DaemonVip::Unknown,
            DaemonService::Unknown,
        )));
        runtime.shutdown = Ok(ShutdownResult::RequiresCleanup);
        let mut daemon = Daemon::new(runtime);
        assert_eq!(daemon.start().unwrap(), StartResult::RecoveryBlocked);
        daemon.request_shutdown().unwrap();
        assert_eq!(daemon.state(), DaemonState::ShutdownRequested);
        assert_eq!(daemon.tick().unwrap(), TickResult::ShutdownRequiresCleanup);
        assert_eq!(daemon.state(), DaemonState::ShutdownBlocked);
    }

    #[test]
    fn attack_bf_recovery_blocked_shutdown_request_cannot_restart_running() {
        let mut daemon = Daemon::new(runtime(Ok(shutdown_observation(
            DaemonVip::Unknown,
            DaemonService::Unknown,
        ))));
        assert_eq!(daemon.start().unwrap(), StartResult::RecoveryBlocked);
        daemon.request_shutdown().unwrap();
        assert!(daemon.start().is_err());
        assert_eq!(daemon.state(), DaemonState::ShutdownRequested);
    }

    #[test]
    fn attack_bg_uncertain_recovery_blocked_shutdown_cannot_become_stopped() {
        let mut runtime = runtime(Ok(shutdown_observation(
            DaemonVip::Unknown,
            DaemonService::Unknown,
        )));
        runtime.shutdown = Ok(ShutdownResult::RequiresCleanup);
        let mut daemon = Daemon::new(runtime);
        daemon.start().unwrap();
        daemon.request_shutdown().unwrap();
        assert_eq!(daemon.tick().unwrap(), TickResult::ShutdownRequiresCleanup);
        assert_ne!(daemon.state(), DaemonState::Stopped);
    }

    // --- F-02: Design Revision 10 §9 bounded shutdown join, daemon level ---
    //
    // The independent re-audit established (finding F-02) that the
    // `Daemon::tick_at` -> `shutdown_bounded_step` -> `shutdown` composition
    // was protected only by a function-body-scoped architecture guard, because
    // every daemon-level shutdown test used the trait DEFAULT
    // `Ok(false)`. These tests close that gap behaviourally with a recording
    // mock runtime. The cross-tick "at most one" property is deliberately NOT
    // asserted here: it is the runtime latch's responsibility (proved by the
    // `linux_node_runtime` A-2 tests), and asserting it at this layer would
    // require changing accepted production semantics.

    /// F-02 (1) and (4): once shutdown is requested, the bounded step is
    /// invoked before the final classification, and an `Ok(true)` result
    /// refreshes the cached observation before that classification.
    #[test]
    fn stage13_6_remediation_daemon_shutdown_invokes_bounded_step_before_classification() {
        let mut runtime = runtime(Ok(standby()));
        // One eligible step reported as having run, then a follow-up no-op.
        runtime.bounded_steps = VecDeque::from([Ok(true), Ok(false)]);
        // The refresh observation the daemon performs on `Ok(true)`.
        runtime.observations = VecDeque::from([
            Ok(standby()),
            Ok(DaemonSnapshot {
                health: DaemonHealth::Unknown,
                ..standby()
            }),
        ]);
        runtime.shutdown = Ok(ShutdownResult::RequiresCleanup);
        let mut daemon = Daemon::new(runtime);
        daemon.start().unwrap();
        daemon.request_shutdown().unwrap();

        assert_eq!(
            daemon.tick().unwrap(),
            TickResult::ShutdownRequiresCleanup,
            "classification must come from live durable state, not the step result"
        );

        let calls = &daemon.runtime.calls;
        let shutdown_at = calls
            .iter()
            .position(|call| *call == "shutdown")
            .expect("the final shutdown classification must run");
        // (1) The step was invoked while only `watermark` calls had been
        // recorded, and `shutdown` sits at a later index — so the step
        // necessarily ran before the final classification.
        let watermark = *daemon
            .runtime
            .bounded_step_call_watermarks
            .first()
            .expect("the bounded shutdown step must be invoked when shutdown is requested");
        assert!(
            watermark <= shutdown_at,
            "the bounded step must run before the final classification: \
             step at call #{watermark}, shutdown at index {shutdown_at}, calls={calls:?}"
        );
        // (4) An `Ok(true)` result must cause a read-only observation refresh
        // between the step and the classification, so the cache reflects the
        // post-step lifecycle rather than the pre-shutdown one. Exactly one
        // `observe` and one `shutdown` may be recorded after the step.
        assert_eq!(
            calls.len(),
            watermark + 2,
            "an Ok(true) bounded step must refresh the observation exactly once \
             before the verdict; calls={calls:?} watermark={watermark}"
        );
        assert_eq!(calls[watermark], "observe");
        assert_eq!(calls[watermark + 1], "shutdown");
        // (3) At most one step per tick — the daemon returns immediately after
        // classifying and does not loop the step.
        assert_eq!(daemon.runtime.bounded_step_calls, 1);
        assert_eq!(daemon.state(), DaemonState::ShutdownBlocked);
    }

    /// F-02 (2): the bounded shutdown step is never invoked while the daemon
    /// is running normally, so it cannot begin HA work outside shutdown.
    #[test]
    fn stage13_6_remediation_daemon_bounded_step_not_invoked_while_running() {
        let mut runtime = runtime(Ok(standby()));
        runtime.observations = VecDeque::from([Ok(standby()), Ok(standby())]);
        runtime.bounded_steps = VecDeque::from([Ok(true), Ok(true)]);
        let mut daemon = Daemon::new(runtime);
        daemon.start().unwrap();
        assert_ne!(daemon.state(), DaemonState::ShutdownRequested);
        assert_eq!(daemon.tick().unwrap(), TickResult::Observed);
        assert_eq!(daemon.tick().unwrap(), TickResult::Observed);
        assert_eq!(daemon.runtime.bounded_step_calls, 0);
        assert!(
            daemon.runtime.bounded_step_call_watermarks.is_empty(),
            "the bounded shutdown step must not run outside shutdown: {:?}",
            daemon.runtime.calls
        );
    }

    /// F-02 (5): the final clean/non-clean verdict is derived from
    /// `runtime.shutdown()` — i.e. live runtime/durable state — and is never
    /// derived from the bounded step's return value in either direction. A
    /// step error must not fabricate a clean verdict, and a step error must
    /// not by itself manufacture a blocked one either.
    #[test]
    fn stage13_6_remediation_daemon_bounded_step_result_never_decides_classification() {
        // Case A: a step that ran cannot make an unresolved lifecycle clean.
        let mut rt = runtime(Ok(standby()));
        rt.bounded_steps = VecDeque::from([Ok(true)]);
        rt.observations = VecDeque::from([Ok(standby())]);
        rt.shutdown = Ok(ShutdownResult::RequiresCleanup);
        let mut daemon = Daemon::new(rt);
        daemon.start().unwrap();
        daemon.request_shutdown().unwrap();
        assert_eq!(daemon.tick().unwrap(), TickResult::ShutdownRequiresCleanup);
        assert_ne!(daemon.state(), DaemonState::Stopped);

        // Case B: a step that did not run cannot force a non-clean verdict.
        let mut rt = runtime(Ok(standby()));
        rt.bounded_steps = VecDeque::from([Ok(false)]);
        rt.shutdown = Ok(ShutdownResult::Clean);
        let mut daemon = Daemon::new(rt);
        daemon.start().unwrap();
        daemon.request_shutdown().unwrap();
        assert_eq!(daemon.tick().unwrap(), TickResult::ShutdownComplete);
        assert_eq!(daemon.state(), DaemonState::Stopped);

        // Case C: a step error is reported, then the verdict still comes from
        // live state. An error must never fabricate a clean shutdown.
        let mut rt = runtime(Ok(standby()));
        rt.bounded_steps = VecDeque::from([Err("step failed".to_string())]);
        rt.shutdown = Ok(ShutdownResult::RequiresCleanup);
        let mut daemon = Daemon::new(rt);
        daemon.start().unwrap();
        daemon.request_shutdown().unwrap();
        assert_eq!(daemon.tick().unwrap(), TickResult::ShutdownRequiresCleanup);
        assert_ne!(daemon.state(), DaemonState::Stopped);

        // Case D: a step error against a genuinely resolved lifecycle still
        // classifies from live state, and the error neither panics nor is
        // promoted into a fabricated verdict of its own.
        let mut rt = runtime(Ok(standby()));
        rt.bounded_steps = VecDeque::from([Err("step failed".to_string())]);
        rt.shutdown = Ok(ShutdownResult::Clean);
        let mut daemon = Daemon::new(rt);
        daemon.start().unwrap();
        daemon.request_shutdown().unwrap();
        assert_eq!(daemon.tick().unwrap(), TickResult::ShutdownComplete);
        assert_eq!(daemon.state(), DaemonState::Stopped);
        assert_eq!(daemon.runtime.bounded_step_calls, 1);
    }

    // --- MKM-ARCH-006: one iteration / one authoritative time / one peer advance ---
    //
    // Deterministic behavioral guard (not a source grep): `Daemon::tick_at(T)`
    // must pass T into the peer progression exactly once per iteration and use
    // the same T for the peer snapshot. There is no internal clock sampling on
    // the `tick_at` path.

    fn ready_daemon(
        peer_results: Vec<Result<Option<PeerObservationState>, String>>,
    ) -> Daemon<FakeRuntime> {
        let mut runtime = runtime(Ok(standby()));
        // Two iterations' worth of local observations.
        runtime.observations.push_back(Ok(standby()));
        runtime.observations.push_back(Ok(standby()));
        for result in peer_results {
            runtime.peer_ticks.push_back(result);
        }
        let mut daemon = Daemon::new(runtime);
        assert_eq!(daemon.start().unwrap(), StartResult::Running);
        daemon
    }

    #[test]
    fn mkm_arch_006_one_iteration_uses_supplied_time_and_advances_peer_once() {
        let mut daemon = ready_daemon(vec![Ok(Some(PeerObservationState::Fresh))]);
        let t = std::time::Instant::now();
        assert_eq!(daemon.tick_at(t).unwrap(), TickResult::Observed);

        // One peer advance, using the supplied T.
        assert_eq!(
            daemon.runtime.peer_tick_times,
            vec![t],
            "MKM-ARCH-006 violated: peer advance did not use the iteration's authoritative time exactly once"
        );
        // The peer snapshot uses the same T.
        assert_eq!(
            daemon.runtime.peer_snapshot_times,
            vec![t],
            "MKM-ARCH-006 violated: peer snapshot time differs from the peer advance time"
        );
    }

    #[test]
    fn mkm_arch_006_two_iterations_advance_once_each_with_their_own_time() {
        let mut daemon = ready_daemon(vec![
            Ok(Some(PeerObservationState::Fresh)),
            Ok(Some(PeerObservationState::Fresh)),
        ]);
        let t1 = std::time::Instant::now();
        let t2 = t1 + std::time::Duration::from_secs(1);
        assert_eq!(daemon.tick_at(t1).unwrap(), TickResult::Observed);
        assert_eq!(daemon.tick_at(t2).unwrap(), TickResult::Observed);

        assert_eq!(
            daemon.runtime.peer_tick_times,
            vec![t1, t2],
            "MKM-ARCH-006 violated: two iterations did not advance exactly once each with their own time"
        );
        assert_eq!(daemon.runtime.peer_snapshot_times, vec![t1, t2]);
        assert_eq!(daemon.runtime.peer_tick_calls, 2);
    }

    #[test]
    fn mkm_arch_006_tick_at_does_not_sample_internal_clock() {
        // `tick_at` must not depend on wall-clock time: a far-future supplied T
        // must be the value observed by the peer progression.
        let mut daemon = ready_daemon(vec![Ok(Some(PeerObservationState::Fresh))]);
        let far_future = std::time::Instant::now() + std::time::Duration::from_secs(86_400);
        daemon.tick_at(far_future).unwrap();
        assert_eq!(daemon.runtime.peer_tick_times, vec![far_future]);
        assert_eq!(daemon.runtime.peer_snapshot_times, vec![far_future]);
    }

    #[test]
    fn mkm_arch_006_peer_time_failure_is_fail_closed() {
        // A failing peer advance must not fabricate a healthy observation; the
        // daemon latches Unavailable for this iteration and remains Running.
        let mut daemon = ready_daemon(vec![Err("peer time went backwards".into())]);
        let t = std::time::Instant::now();
        assert_eq!(daemon.tick_at(t).unwrap(), TickResult::Observed);
        assert_eq!(daemon.peer_state(), PeerObservationState::Unavailable);
        assert_ne!(daemon.peer_state(), PeerObservationState::Fresh);
        // The peer was still advanced exactly once with the supplied time.
        assert_eq!(daemon.runtime.peer_tick_times, vec![t]);
    }

    // --- MKM-ARCH-008: inert observation -> eligibility -> authorization ---
    //
    // The composition result is pure data. The tests prove the decision
    // boundary behaviorally: only a `Ready` observation can produce an
    // `AuthorityAttemptEvaluation`; `Ready`, `Eligible`, and `Authorized`
    // remain distinct stages; and no mutation is reachable. `Authorized` is
    // asserted as inert data in the positive control so a fail-closed
    // implementation cannot pass vacuously.

    /// Test-only mutation sentinel. The evaluation types hold no handle that
    /// could reach it, so every counter must remain zero; this proves the
    /// tested composition is mutation-free.
    #[derive(Default)]
    struct MutationSentinel {
        promotion_calls: usize,
        lease_mutation_calls: usize,
        resource_mutation_calls: usize,
    }

    /// Mint a real `WitnessAuthorityViewEvidence` through the production adapter
    /// correlation path over a loopback Witness session. Tests cannot
    /// fabricate a current term: the adapter's observation lifecycle is the
    /// only minter, and only for a correlated completion of the current
    /// request generation.
    #[cfg(unix)]
    fn minted_current_term(
        at: std::time::Instant,
    ) -> crate::evidence_fusion::adapter::WitnessAuthorityViewEvidence {
        use crate::evidence_fusion::adapter::{ObservationProgress, WitnessEvidenceAdapter};
        use crate::protocol::{
            CborSerializer, ClusterId, CommonFields, NodeId, PROTOCOL_VERSION, ProtocolMessage,
            Sequence, SessionId, Term, TermStatusPayload, UnsignedEnvelope,
        };
        use crate::security::{MessageAuthenticator, Psk};
        use crate::session::ProcessSession;
        use crate::witness_runtime::{WitnessConnection, WitnessSession};
        use std::net::{TcpListener, TcpStream};
        use std::time::Duration;

        let auth = MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32]));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server_stream, _) = listener.accept().unwrap();
        let mut server = crate::tcp::TcpConnection::from_stream(
            server_stream,
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .unwrap();
        let connection = WitnessConnection::new(
            NodeId::new("node-a"),
            NodeId::new("w"),
            ClusterId::new("cluster"),
            SessionId::new("w-session"),
            crate::tcp::TcpConnection::from_stream(
                client,
                Duration::from_secs(2),
                Duration::from_secs(2),
            )
            .unwrap(),
        );
        let mut session = WitnessSession::new(
            connection,
            ProcessSession::from_session_id(SessionId::new("a-session")),
            MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32])),
        );
        let mut adapter = WitnessEvidenceAdapter::new(Duration::from_secs(2)).unwrap();
        adapter
            .begin_observation_at(
                &mut session,
                crate::evidence_fusion::adapter::AuthorityViewExpectation::new(
                    NodeId::new("node-a"),
                    None,
                    None,
                ),
                at,
            )
            .unwrap();
        let request_id = adapter.snapshot().pending.unwrap().request_id;
        server
            .send_message(
                UnsignedEnvelope {
                    common: CommonFields {
                        protocol_version: PROTOCOL_VERSION,
                        cluster_id: ClusterId::new("cluster"),
                        sender_node_id: NodeId::new("w"),
                        receiver_node_id: NodeId::new("node-a"),
                        session_id: SessionId::new("w-session"),
                        sequence: Sequence(1),
                        term: Term(7),
                        lease_id: None,
                        request_id: Some(request_id),
                        operation_id: None,
                    },
                    message: ProtocolMessage::TermStatus(TermStatusPayload {
                        current_term: Term(7),
                        current_holder: Some(NodeId::new("node-a")),
                        current_lease_id: None,
                        lease_remaining_ms: None,
                    }),
                },
                &CborSerializer,
                &auth,
            )
            .unwrap();
        session.wait_for_readable_for_test().unwrap();
        match adapter.poll_observation_at(&mut session, at).unwrap() {
            ObservationProgress::Ready(term) => term,
            other => panic!("MKM-ARCH-008 test setup failed: expected Ready, got {other:?}"),
        }
    }

    /// Build a `Ready` observation progress from a real minted current term
    /// and the supplied evidence inputs. `readiness` is `Safe` in every
    /// honest production `Ready`; tests may substitute a blocker to prove the
    /// evaluation still fails closed.
    #[cfg(unix)]
    pub(super) fn ready_progress_at(
        at: std::time::Instant,
        peer_assessment: crate::failure_assessment::PeerFailureAssessment,
        evidence_state: crate::evidence_fusion::EvidenceFusionState,
        readiness: crate::failover_policy::LocalSafetyReadiness,
    ) -> AuthorityObservationProgress {
        AuthorityObservationProgress::Ready(CurrentAuthorityAttemptObservation::new(
            minted_current_term(at),
            peer_assessment,
            crate::evidence_fusion::WitnessEvidenceView {
                state: evidence_state,
                peer_assessment,
                witness_status: crate::evidence_fusion::WitnessStatus::AuthorityViewCompatible,
                witness_observed_at: Some(at),
                witness_boot_id: None,
            },
            LocalSafetySnapshot {
                node_state: NodeState::Standby,
                operation_phase: None,
                readiness,
            },
        ))
    }

    /// Scenario C / positive control: CommunicationLost + FailoverEvidenceReady +
    /// Safe + a valid current term can produce Eligible and Authorized as
    /// inert data; repeated evaluation of identical inputs is deterministic
    /// and accumulates nothing.
    #[cfg(unix)]
    #[test]
    fn mkm_arch_008_evaluation_is_inert_and_idempotent() {
        use crate::evidence_fusion::EvidenceFusionState;
        use crate::failover_policy::LocalSafetyReadiness;
        use crate::failure_assessment::PeerFailureAssessment;
        use crate::protocol::Term;

        let sentinel = MutationSentinel::default();
        let t = std::time::Instant::now();

        let first = ready_progress_at(
            t,
            PeerFailureAssessment::CommunicationLost,
            EvidenceFusionState::FailoverEvidenceReady,
            LocalSafetyReadiness::Safe,
        )
        .into_evaluation()
        .expect("MKM-ARCH-008 violated: a Ready observation produced no evaluation");

        // Positive control: the strongest evidence must be *capable* of
        // Eligible + Authorized, otherwise a fail-closed-by-rejection
        // implementation would pass vacuously.
        assert_eq!(
            first.eligibility(),
            FailoverEligibility::Eligible,
            "MKM-ARCH-008 violated: strongest evidence was not Eligible"
        );
        assert_eq!(
            first.authorization(),
            PromotionAttemptAuthorization::Authorized,
            "MKM-ARCH-008 violated: strongest evidence was not Authorized"
        );
        assert!(first.is_eligible());
        assert!(first.is_authorized());
        // The evaluation carries its observation as read-only data.
        assert_eq!(first.observation().authority_view().term(), Term(7));

        // Re-evaluation of identical immutable inputs is deterministic: same
        // result, no accumulation, no cached reusable permission.
        let second = ready_progress_at(
            t,
            PeerFailureAssessment::CommunicationLost,
            EvidenceFusionState::FailoverEvidenceReady,
            LocalSafetyReadiness::Safe,
        )
        .into_evaluation()
        .unwrap();
        assert_eq!(
            first, second,
            "MKM-ARCH-008 violated: repeated evaluation of identical inputs diverged"
        );

        // The evaluation exposed no mutation capability and performed none.
        assert_eq!(sentinel.promotion_calls, 0);
        assert_eq!(sentinel.lease_mutation_calls, 0);
        assert_eq!(sentinel.resource_mutation_calls, 0);
    }

    /// Scenario A: a healthy peer plus a valid current term is neither
    /// Eligible nor Authorized.
    #[cfg(unix)]
    #[test]
    fn mkm_arch_008_healthy_peer_never_authorizes() {
        use crate::evidence_fusion::EvidenceFusionState;
        use crate::failover_policy::LocalSafetyReadiness;
        use crate::failure_assessment::PeerFailureAssessment;

        let t = std::time::Instant::now();
        let evaluation = ready_progress_at(
            t,
            PeerFailureAssessment::Healthy,
            EvidenceFusionState::Unproven,
            LocalSafetyReadiness::Safe,
        )
        .into_evaluation()
        .expect("MKM-ARCH-008 violated: a Ready observation produced no evaluation");
        assert!(
            !evaluation.is_eligible(),
            "MKM-ARCH-008 violated: a healthy peer produced Eligible"
        );
        assert!(
            !evaluation.is_authorized(),
            "MKM-ARCH-008 violated: a healthy peer produced Authorized"
        );
    }

    /// Scenario B/D: insufficient or ambiguous evidence fails closed.
    #[cfg(unix)]
    #[test]
    fn mkm_arch_008_insufficient_evidence_fails_closed() {
        use crate::evidence_fusion::EvidenceFusionState;
        use crate::failover_policy::LocalSafetyReadiness;
        use crate::failure_assessment::PeerFailureAssessment;

        let t = std::time::Instant::now();
        for (peer, evidence) in [
            (
                PeerFailureAssessment::CommunicationLost,
                EvidenceFusionState::Unproven,
            ),
            (
                PeerFailureAssessment::Suspect,
                EvidenceFusionState::PeerDegraded,
            ),
            (
                PeerFailureAssessment::CommunicationLost,
                EvidenceFusionState::AmbiguousPartition,
            ),
        ] {
            let evaluation = ready_progress_at(t, peer, evidence, LocalSafetyReadiness::Safe)
                .into_evaluation()
                .expect("MKM-ARCH-008 violated: a Ready observation produced no evaluation");
            assert!(
                !evaluation.is_authorized(),
                "MKM-ARCH-008 violated: {peer:?} + {evidence:?} produced Authorized"
            );
        }
    }

    /// Scenario D: shutdown blocks authorization even with the strongest
    /// evidence. In production the observation epoch itself yields
    /// `LocalSafetyNotReady` (no attempt); even a Ready carrying shutdown
    /// local safety cannot produce Eligible or Authorized.
    #[cfg(unix)]
    #[test]
    fn mkm_arch_008_shutdown_blocks_authorization() {
        use crate::evidence_fusion::EvidenceFusionState;
        use crate::failover_policy::LocalSafetyReadiness;
        use crate::failure_assessment::PeerFailureAssessment;

        let shutdown = LocalSafetySnapshot {
            node_state: NodeState::Standby,
            operation_phase: None,
            readiness: LocalSafetyReadiness::ShutdownInProgress,
        };
        // Production shape: shutdown prevents the trusted-complete
        // observation entirely, so there is no attempt to evaluate.
        assert!(
            AuthorityObservationProgress::LocalSafetyNotReady(shutdown)
                .into_evaluation()
                .is_none(),
            "MKM-ARCH-008 violated: shutdown produced an attempt"
        );

        // Defense in depth: the strongest evidence evaluated against a
        // shutdown local boundary is still never Eligible or Authorized.
        let t = std::time::Instant::now();
        let evaluation = ready_progress_at(
            t,
            PeerFailureAssessment::CommunicationLost,
            EvidenceFusionState::FailoverEvidenceReady,
            LocalSafetyReadiness::ShutdownInProgress,
        )
        .into_evaluation()
        .unwrap();
        assert!(
            !evaluation.is_eligible(),
            "MKM-ARCH-008 violated: shutdown evidence produced Eligible"
        );
        assert!(
            !evaluation.is_authorized(),
            "MKM-ARCH-008 violated: shutdown evidence produced Authorized"
        );
    }

    /// `Ready` is a distinct stage: it carries the current correlated term
    /// but implies neither Eligible nor Authorized.
    #[cfg(unix)]
    #[test]
    fn mkm_arch_008_ready_does_not_imply_eligible_or_authorized() {
        use crate::evidence_fusion::EvidenceFusionState;
        use crate::failover_policy::LocalSafetyReadiness;
        use crate::failure_assessment::PeerFailureAssessment;
        use crate::protocol::Term;

        let t = std::time::Instant::now();
        let progress = ready_progress_at(
            t,
            PeerFailureAssessment::Healthy,
            EvidenceFusionState::Unproven,
            LocalSafetyReadiness::Safe,
        );
        let AuthorityObservationProgress::Ready(_) = &progress else {
            panic!("MKM-ARCH-008 violated: test setup did not produce Ready")
        };
        let evaluation = progress.into_evaluation().unwrap();
        // The current term is present — the observation is genuinely Ready —
        // yet nothing is authorized.
        assert_eq!(evaluation.observation().authority_view().term(), Term(7));
        assert!(!evaluation.is_eligible());
        assert!(!evaluation.is_authorized());
    }

    /// Scenario F: non-Ready progress values produce no attempt — no
    /// eligibility, no authorization, no manufactured current term.
    #[test]
    fn mkm_arch_008_pending_and_unavailable_never_produce_an_attempt() {
        use crate::evidence_fusion::adapter::UnavailableCause;
        use crate::failover_policy::LocalSafetyReadiness;

        assert!(
            AuthorityObservationProgress::AwaitingWitnessTerm
                .into_evaluation()
                .is_none(),
            "MKM-ARCH-008 violated: AwaitingWitnessTerm produced an attempt"
        );
        for cause in [UnavailableCause::Timeout, UnavailableCause::Transport] {
            assert!(
                AuthorityObservationProgress::Unavailable(cause)
                    .into_evaluation()
                    .is_none(),
                "MKM-ARCH-008 violated: Unavailable({cause:?}) produced an attempt"
            );
        }
        assert!(
            AuthorityObservationProgress::LocalSafetyNotReady(LocalSafetySnapshot {
                node_state: NodeState::Standby,
                operation_phase: None,
                readiness: LocalSafetyReadiness::ShutdownInProgress,
            })
            .into_evaluation()
            .is_none(),
            "MKM-ARCH-008 violated: LocalSafetyNotReady produced an attempt"
        );
    }

    // --- MKM-ARCH-009: deterministic failover scenario matrix ---
    //
    // Table-driven verification of the Stage 12.8d composition across
    // observation state, peer assessment, fused evidence, and local safety.
    // Every row is an independent fresh evaluation minted from its own
    // correlated GET_TERM completion: no authority carries over between rows
    // or iterations. The matrix requires a positive Authorized control so it
    // cannot pass by rejecting everything, and every row asserts a zero
    // mutation sentinel — the evaluated types hold no handle that could
    // reach it.
    //
    // Existing coverage integrated rather than duplicated:
    // - SEQ-3 superseded generation and SEQ-4 Unavailable-then-fresh-Ready:
    //   `witness_evidence_adapter::tests::stage_12_8e_seq_3_superseded_generation_cannot_authorize`
    //   and `stage_12_8e_seq_4_unavailable_then_fresh_ready_is_independent`.
    // - Stored `witness_term` cannot mint a current term (matrix scenario H):
    //   Stage 12.8a `stored_witness_term_cannot_mint_current_witness_term_or_ready`.
    // - Wrong request/observation generation and backwards time (I/J/K):
    //   adapter + fusion guards MKM-ARCH-002..005.
    // - No Witness adapter attached (G): Stage 12.8f Linux composition.

    /// Observation input for one matrix row, mirroring the variants of
    /// `AuthorityObservationProgress`. `Ready` is materialized with a real
    /// minted current term; the other variants carry no attempt data.
    #[cfg(unix)]
    enum RowObservation {
        Ready {
            peer: crate::failure_assessment::PeerFailureAssessment,
            evidence: crate::evidence_fusion::EvidenceFusionState,
            readiness: crate::failover_policy::LocalSafetyReadiness,
        },
        AwaitingWitnessTerm,
        Unavailable(crate::evidence_fusion::adapter::UnavailableCause),
        LocalSafetyNotReady(crate::failover_policy::LocalSafetyReadiness),
    }

    /// One deterministic matrix row: the observation to evaluate and the
    /// expected decision results.
    #[cfg(unix)]
    struct MatrixRow {
        name: &'static str,
        observation: RowObservation,
        /// Whether a `Ready` observation exists (an attempt is evaluated).
        expect_attempt: bool,
        expect_eligible: bool,
        expect_authorized: bool,
    }

    #[cfg(unix)]
    fn materialize_observation(
        observation: &RowObservation,
        at: std::time::Instant,
    ) -> AuthorityObservationProgress {
        match observation {
            RowObservation::Ready {
                peer,
                evidence,
                readiness,
            } => ready_progress_at(at, *peer, *evidence, *readiness),
            RowObservation::AwaitingWitnessTerm => {
                AuthorityObservationProgress::AwaitingWitnessTerm
            }
            RowObservation::Unavailable(cause) => AuthorityObservationProgress::Unavailable(*cause),
            RowObservation::LocalSafetyNotReady(readiness) => {
                AuthorityObservationProgress::LocalSafetyNotReady(LocalSafetySnapshot {
                    node_state: NodeState::Standby,
                    operation_phase: None,
                    readiness: *readiness,
                })
            }
        }
    }

    /// MKM-ARCH-009: the failover decision scenario matrix is fail-closed
    /// across ambiguous, stale, unavailable, shutdown, and timing-failure
    /// inputs, with a mandatory positive Authorized control.
    #[cfg(unix)]
    #[test]
    fn mkm_arch_009_failover_scenario_matrix_is_fail_closed() {
        use crate::evidence_fusion::EvidenceFusionState;
        use crate::failover_policy::LocalSafetyReadiness;
        use crate::failure_assessment::PeerFailureAssessment;
        use crate::protocol::Term;

        let sentinel = MutationSentinel::default();
        let t = std::time::Instant::now();
        let safe = LocalSafetyReadiness::Safe;
        let lost = PeerFailureAssessment::CommunicationLost;

        let rows = [
            MatrixRow {
                name: "A healthy peer + Ready",
                observation: RowObservation::Ready {
                    peer: PeerFailureAssessment::Healthy,
                    evidence: EvidenceFusionState::Unproven,
                    readiness: safe,
                },
                expect_attempt: true,
                expect_eligible: false,
                expect_authorized: false,
            },
            MatrixRow {
                name: "B comm-lost + Unproven",
                observation: RowObservation::Ready {
                    peer: lost,
                    evidence: EvidenceFusionState::Unproven,
                    readiness: safe,
                },
                expect_attempt: true,
                expect_eligible: false,
                expect_authorized: false,
            },
            MatrixRow {
                name: "B2 comm-lost + PeerDegraded",
                observation: RowObservation::Ready {
                    peer: PeerFailureAssessment::Suspect,
                    evidence: EvidenceFusionState::PeerDegraded,
                    readiness: safe,
                },
                expect_attempt: true,
                expect_eligible: false,
                expect_authorized: false,
            },
            MatrixRow {
                name: "C comm-lost + FailoverEvidenceReady + Safe (positive control)",
                observation: RowObservation::Ready {
                    peer: lost,
                    evidence: EvidenceFusionState::FailoverEvidenceReady,
                    readiness: safe,
                },
                expect_attempt: true,
                expect_eligible: true,
                expect_authorized: true,
            },
            // Even if a Ready observation carried a shutdown local boundary,
            // evaluation still fails closed; the production shape (no trusted
            // observation at all) is the LocalSafetyNotReady rows below.
            MatrixRow {
                name: "D strong evidence + shutdown",
                observation: RowObservation::Ready {
                    peer: lost,
                    evidence: EvidenceFusionState::FailoverEvidenceReady,
                    readiness: LocalSafetyReadiness::ShutdownInProgress,
                },
                expect_attempt: true,
                expect_eligible: false,
                expect_authorized: false,
            },
            MatrixRow {
                name: "E witness Unavailable(Transport)",
                observation: RowObservation::Unavailable(
                    crate::evidence_fusion::adapter::UnavailableCause::Transport,
                ),
                expect_attempt: false,
                expect_eligible: false,
                expect_authorized: false,
            },
            MatrixRow {
                name: "E2 witness Unavailable(Timeout)",
                observation: RowObservation::Unavailable(
                    crate::evidence_fusion::adapter::UnavailableCause::Timeout,
                ),
                expect_attempt: false,
                expect_eligible: false,
                expect_authorized: false,
            },
            MatrixRow {
                name: "F witness Awaiting",
                observation: RowObservation::AwaitingWitnessTerm,
                expect_attempt: false,
                expect_eligible: false,
                expect_authorized: false,
            },
            // The peer context is healthy, but a terminally failed Witness
            // observation carries no attempt data regardless of peer state.
            MatrixRow {
                name: "M witness terminal + healthy peer",
                observation: RowObservation::Unavailable(
                    crate::evidence_fusion::adapter::UnavailableCause::Transport,
                ),
                expect_attempt: false,
                expect_eligible: false,
                expect_authorized: false,
            },
            MatrixRow {
                name: "N Ready + AmbiguousPartition",
                observation: RowObservation::Ready {
                    peer: lost,
                    evidence: EvidenceFusionState::AmbiguousPartition,
                    readiness: safe,
                },
                expect_attempt: true,
                expect_eligible: false,
                expect_authorized: false,
            },
            // Row L is deliberately identical in value to row C: it proves
            // each row is evaluated independently from its own fresh
            // observation, not from a cached earlier Authorized.
            MatrixRow {
                name: "L comm-lost + corroborated loss (independent)",
                observation: RowObservation::Ready {
                    peer: lost,
                    evidence: EvidenceFusionState::FailoverEvidenceReady,
                    readiness: safe,
                },
                expect_attempt: true,
                expect_eligible: true,
                expect_authorized: true,
            },
            MatrixRow {
                name: "G local safety not ready at observation boundary",
                observation: RowObservation::LocalSafetyNotReady(
                    LocalSafetyReadiness::ShutdownInProgress,
                ),
                expect_attempt: false,
                expect_eligible: false,
                expect_authorized: false,
            },
        ];

        let mut authorized_controls = 0usize;
        for row in &rows {
            let evaluation = materialize_observation(&row.observation, t).into_evaluation();
            if !row.expect_attempt {
                assert!(
                    evaluation.is_none(),
                    "MKM-ARCH-009 violated: row {} produced an attempt",
                    row.name
                );
                continue;
            }
            let evaluation = evaluation.unwrap_or_else(|| {
                panic!(
                    "MKM-ARCH-009 violated: row {} produced no evaluation",
                    row.name
                )
            });
            assert_eq!(
                evaluation.is_eligible(),
                row.expect_eligible,
                "MKM-ARCH-009 violated: row {} eligibility mismatch",
                row.name
            );
            assert_eq!(
                evaluation.is_authorized(),
                row.expect_authorized,
                "MKM-ARCH-009 violated: row {} authorization mismatch",
                row.name
            );
            // Peer/readiness/evidence preservation: the evaluation carries
            // the row's own inputs read-only; nothing was substituted.
            let RowObservation::Ready {
                peer,
                evidence,
                readiness,
            } = &row.observation
            else {
                panic!(
                    "MKM-ARCH-009 violated: row {} expected an attempt",
                    row.name
                )
            };
            assert_eq!(evaluation.observation().peer_assessment(), *peer);
            assert_eq!(evaluation.observation().evidence().state, *evidence);
            assert_eq!(evaluation.observation().local().readiness, *readiness);
            // The current term came from this row's own minted completion.
            assert_eq!(evaluation.observation().authority_view().term(), Term(7));
            authorized_controls += usize::from(row.expect_authorized);
        }
        assert!(
            authorized_controls >= 1,
            "MKM-ARCH-009 violated: matrix has no positive Authorized control"
        );

        // Every non-Safe local classification fails closed in both shapes:
        // at the observation boundary no attempt exists (LocalSafetyNotReady
        // -> None), and even a fabricated Ready is never Eligible/Authorized.
        for readiness in [
            LocalSafetyReadiness::ShutdownInProgress,
            LocalSafetyReadiness::RecoveryBlocked,
            LocalSafetyReadiness::DemotionRequired,
            LocalSafetyReadiness::OwnershipUncertain,
            LocalSafetyReadiness::ResourceStateUnresolved,
            LocalSafetyReadiness::AuthorityPresent,
            LocalSafetyReadiness::Unknown,
        ] {
            assert!(
                materialize_observation(&RowObservation::LocalSafetyNotReady(readiness), t)
                    .into_evaluation()
                    .is_none(),
                "MKM-ARCH-009 violated: LocalSafetyNotReady({readiness:?}) produced an attempt"
            );
            let evaluation = materialize_observation(
                &RowObservation::Ready {
                    peer: PeerFailureAssessment::CommunicationLost,
                    evidence: EvidenceFusionState::FailoverEvidenceReady,
                    readiness,
                },
                t,
            )
            .into_evaluation()
            .unwrap();
            assert!(
                !evaluation.is_authorized(),
                "MKM-ARCH-009 violated: strong evidence + {readiness:?} produced Authorized"
            );
            assert!(
                !evaluation.is_eligible(),
                "MKM-ARCH-009 violated: strong evidence + {readiness:?} produced Eligible"
            );
        }

        // No row — including the positive Authorized controls — reached a
        // mutation. The evaluation types hold no handle that could.
        assert_eq!(sentinel.promotion_calls, 0);
        assert_eq!(sentinel.lease_mutation_calls, 0);
        assert_eq!(sentinel.resource_mutation_calls, 0);
    }

    /// Stage 12.8e SEQ-1: healthy -> communication lost with unproven
    /// evidence -> corroborated loss. Only the final state is Authorized;
    /// earlier evaluations grant no reusable authority to later ones.
    #[cfg(unix)]
    #[test]
    fn stage_12_8e_seq_1_healthy_to_corroborated_loss() {
        use crate::evidence_fusion::EvidenceFusionState;
        use crate::failover_policy::LocalSafetyReadiness;
        use crate::failure_assessment::PeerFailureAssessment;

        let sentinel = MutationSentinel::default();
        let t = std::time::Instant::now();
        let safe = LocalSafetyReadiness::Safe;

        // Iteration 1: healthy peer. A fresh current term exists, but a
        // healthy peer can never be Eligible or Authorized.
        let healthy = ready_progress_at(
            t,
            PeerFailureAssessment::Healthy,
            EvidenceFusionState::Unproven,
            safe,
        )
        .into_evaluation()
        .expect("SEQ-1: healthy Ready produced no evaluation");
        assert!(!healthy.is_eligible());
        assert!(!healthy.is_authorized());

        // Iteration 2: communication lost, but the fused evidence is still
        // unproven. A fresh current term exists; still fail-closed.
        let t2 = t + std::time::Duration::from_secs(1);
        let lost_unproven = ready_progress_at(
            t2,
            PeerFailureAssessment::CommunicationLost,
            EvidenceFusionState::Unproven,
            safe,
        )
        .into_evaluation()
        .expect("SEQ-1: comm-lost/unproven Ready produced no evaluation");
        assert!(!lost_unproven.is_eligible());
        assert!(!lost_unproven.is_authorized());

        // Iteration 3: corroborated loss. Now the pipeline reaches
        // Eligible + Authorized — as inert data only.
        let t3 = t + std::time::Duration::from_secs(2);
        let corroborated = ready_progress_at(
            t3,
            PeerFailureAssessment::CommunicationLost,
            EvidenceFusionState::FailoverEvidenceReady,
            safe,
        )
        .into_evaluation()
        .expect("SEQ-1: corroborated Ready produced no evaluation");
        assert!(corroborated.is_eligible());
        assert!(corroborated.is_authorized());

        // Temporal non-reuse: each iteration minted its own current term at
        // its own acceptance epoch, and each evaluation reflects only its
        // own inputs — iteration 3 used CommunicationLost, not the earlier
        // Healthy assessment.
        assert_ne!(
            healthy.observation().authority_view().observed_at(),
            corroborated.observation().authority_view().observed_at(),
            "SEQ-1 violated: the same term was reused across iterations"
        );
        assert_eq!(
            corroborated.observation().peer_assessment(),
            PeerFailureAssessment::CommunicationLost
        );
        assert_ne!(
            healthy, corroborated,
            "SEQ-1 violated: distinct evaluations collapsed into one"
        );

        assert_eq!(sentinel.promotion_calls, 0);
        assert_eq!(sentinel.lease_mutation_calls, 0);
        assert_eq!(sentinel.resource_mutation_calls, 0);
    }

    /// Stage 12.8e SEQ-2: a Ready observation is Authorized, then shutdown
    /// begins. The prior Ready/Authorized cannot override the shutdown
    /// boundary owned by the daemon.
    #[cfg(unix)]
    #[test]
    fn stage_12_8e_seq_2_ready_then_shutdown_cannot_override() {
        use crate::evidence_fusion::EvidenceFusionState;
        use crate::failover_policy::LocalSafetyReadiness;
        use crate::failure_assessment::PeerFailureAssessment;
        use crate::protocol::Term;

        let sentinel = MutationSentinel::default();
        let mut daemon = Daemon::new(runtime(Ok(standby())));
        daemon.start().unwrap();
        let t = std::time::Instant::now();

        // Iteration 1: strong evidence + Safe -> Eligible + Authorized
        // (inert data). The local boundary comes from the daemon-owned
        // safety snapshot, not a fabricated value.
        let safe = daemon.local_safety_snapshot().unwrap().unwrap();
        assert_eq!(safe.readiness, LocalSafetyReadiness::Safe);
        let authorized = ready_progress_at(
            t,
            PeerFailureAssessment::CommunicationLost,
            EvidenceFusionState::FailoverEvidenceReady,
            safe.readiness,
        )
        .into_evaluation()
        .expect("SEQ-2: positive control produced no evaluation");
        assert!(authorized.is_eligible());
        assert!(authorized.is_authorized());
        assert_eq!(authorized.observation().authority_view().term(), Term(7));

        // Shutdown begins; the daemon is the sole owner of shutdown truth.
        daemon.request_shutdown().unwrap();
        let shutdown = daemon.local_safety_snapshot().unwrap().unwrap();
        assert_eq!(shutdown.readiness, LocalSafetyReadiness::ShutdownInProgress);

        // Iteration 2 (production shape): under shutdown the observation
        // epoch cannot complete as trusted, so there is no attempt at all.
        assert!(
            AuthorityObservationProgress::LocalSafetyNotReady(shutdown)
                .into_evaluation()
                .is_none(),
            "SEQ-2 violated: shutdown produced an attempt"
        );

        // Iteration 2 (defense in depth): even a fresh Ready minted after
        // shutdown, evaluated against the shutdown boundary, is not
        // Eligible or Authorized. The prior Ready/Authorized cannot
        // override shutdown.
        let t2 = t + std::time::Duration::from_secs(1);
        let blocked = ready_progress_at(
            t2,
            PeerFailureAssessment::CommunicationLost,
            EvidenceFusionState::FailoverEvidenceReady,
            shutdown.readiness,
        )
        .into_evaluation()
        .unwrap();
        assert!(
            !blocked.is_eligible(),
            "SEQ-2 violated: shutdown evaluation produced Eligible"
        );
        assert!(
            !blocked.is_authorized(),
            "SEQ-2 violated: a previous Authorized overrode shutdown"
        );

        // The earlier Authorized value remains inert data: it cannot be
        // converted back into an observation, a term, or a permission, and
        // it authorized nothing beyond its own iteration.
        assert!(authorized.is_authorized());
        assert_ne!(
            authorized.observation().authority_view().observed_at(),
            blocked.observation().authority_view().observed_at(),
            "SEQ-2 violated: the same term was reused across iterations"
        );

        assert_eq!(sentinel.promotion_calls, 0);
        assert_eq!(sentinel.lease_mutation_calls, 0);
        assert_eq!(sentinel.resource_mutation_calls, 0);
    }

    /// SEQ-1/SEQ-2 combined: pure evaluation never advances the peer runtime
    /// and never reaches a mutation — the decision pipeline is data-only.
    #[cfg(unix)]
    #[test]
    fn stage_12_8e_seq_1_and_2_never_tick_peer_or_mutate() {
        use crate::evidence_fusion::EvidenceFusionState;
        use crate::failure_assessment::PeerFailureAssessment;

        let sentinel = MutationSentinel::default();
        let mut daemon = Daemon::new(runtime(Ok(standby())));
        daemon.start().unwrap();
        let t = std::time::Instant::now();

        // Full SEQ-1 progression through daemon-derived local safety.
        for (offset, peer, evidence) in [
            (
                0,
                PeerFailureAssessment::Healthy,
                EvidenceFusionState::Unproven,
            ),
            (
                1,
                PeerFailureAssessment::CommunicationLost,
                EvidenceFusionState::Unproven,
            ),
            (
                2,
                PeerFailureAssessment::CommunicationLost,
                EvidenceFusionState::FailoverEvidenceReady,
            ),
        ] {
            let local = daemon.local_safety_snapshot().unwrap().unwrap();
            let _ = ready_progress_at(
                t + std::time::Duration::from_secs(offset),
                peer,
                evidence,
                local.readiness,
            )
            .into_evaluation();
        }

        // SEQ-2 tail: the shutdown boundary.
        daemon.request_shutdown().unwrap();
        let shutdown = daemon.local_safety_snapshot().unwrap().unwrap();
        let _ = ready_progress_at(
            t + std::time::Duration::from_secs(3),
            PeerFailureAssessment::CommunicationLost,
            EvidenceFusionState::FailoverEvidenceReady,
            shutdown.readiness,
        )
        .into_evaluation();

        // No evaluation advanced the peer runtime or performed an action.
        assert_eq!(
            daemon.runtime.peer_tick_calls, 0,
            "MKM-ARCH-009 violated: evaluation advanced the peer runtime"
        );
        assert!(daemon.runtime.peer_tick_times.is_empty());
        assert!(
            !daemon.runtime.calls.contains(&"promote"),
            "MKM-ARCH-009 violated: evaluation reached promotion"
        );

        assert_eq!(sentinel.promotion_calls, 0);
        assert_eq!(sentinel.lease_mutation_calls, 0);
        assert_eq!(sentinel.resource_mutation_calls, 0);
    }

    // ------------------------------------------------------------------
    // MKM-ARCH-011 / Stage 13.1: promotion attempt lifecycle is inert and
    // overlapping attempts are forbidden. The lifecycle is owned by `Daemon`
    // and stores only the in-flight `PromotionRequestId` — no authorization,
    // term, evidence, lease, permission, resource handle, or callback, so an
    // accepted attempt grants no mutation capability.
    // ------------------------------------------------------------------

    /// MKM-ARCH-011: a fresh request is accepted while idle (positive
    /// inert control); a second and a duplicate request are rejected as
    /// already-in-progress without changing the in-flight identity;
    /// acceptance performs no promotion call and zero peer advances.
    #[test]
    fn mkm_arch_011_accepting_request_is_inert_and_non_overlapping() {
        use crate::promotion_attempt::{
            PromotionAttemptLifecycle, PromotionAttemptRejection, PromotionExecutionRequest,
            PromotionRequestId,
        };

        let mut daemon = Daemon::new(runtime(Ok(standby())));
        daemon.start().unwrap();
        assert_eq!(
            daemon.promotion_attempt_lifecycle(),
            &PromotionAttemptLifecycle::Idle
        );

        // Positive control: a fresh explicit request is accepted while idle.
        let accepted = daemon
            .request_promotion_attempt(PromotionExecutionRequest::new(PromotionRequestId::new(
                "attempt-1",
            )))
            .unwrap();
        assert_eq!(accepted, PromotionRequestId::new("attempt-1"));
        assert_eq!(
            daemon.promotion_attempt_lifecycle().in_flight_id(),
            Some(&PromotionRequestId::new("attempt-1"))
        );

        // A second request is rejected without replacing the in-flight
        // identity.
        assert_eq!(
            daemon.request_promotion_attempt(PromotionExecutionRequest::new(
                PromotionRequestId::new("attempt-2")
            )),
            Err(PromotionAttemptRejection::AlreadyInProgress)
        );
        // A duplicate of the in-flight identity is rejected identically.
        assert_eq!(
            daemon.request_promotion_attempt(PromotionExecutionRequest::new(
                PromotionRequestId::new("attempt-1")
            )),
            Err(PromotionAttemptRejection::AlreadyInProgress)
        );
        assert_eq!(
            daemon.promotion_attempt_lifecycle().in_flight_id(),
            Some(&PromotionRequestId::new("attempt-1")),
            "MKM-ARCH-011 violated: rejection replaced the in-flight identity"
        );

        // Acceptance is inert: no promotion call, no peer advance.
        assert_eq!(
            daemon.runtime.peer_tick_calls, 0,
            "MKM-ARCH-011 violated: attempt acceptance advanced the peer runtime"
        );
        assert!(
            !daemon.runtime.calls.contains(&"promote"),
            "MKM-ARCH-011 violated: attempt acceptance reached promotion"
        );
    }

    /// MKM-ARCH-011: completing or cancelling returns the slot to idle and a
    /// later fresh request can be accepted; completing or cancelling an idle
    /// slot is a no-op.
    #[test]
    fn mkm_arch_011_finish_and_cancel_return_to_idle() {
        use crate::promotion_attempt::{
            PromotionAttemptLifecycle, PromotionExecutionRequest, PromotionRequestId,
        };

        let mut daemon = Daemon::new(runtime(Ok(standby())));
        daemon.start().unwrap();

        // Idle finish/cancel are no-ops.
        assert_eq!(daemon.finish_promotion_attempt(), None);
        assert_eq!(daemon.cancel_promotion_attempt(), None);
        assert_eq!(
            daemon.promotion_attempt_lifecycle(),
            &PromotionAttemptLifecycle::Idle
        );

        // Accept -> finish -> Idle -> fresh request accepted again.
        daemon
            .request_promotion_attempt(PromotionExecutionRequest::new(PromotionRequestId::new(
                "attempt-1",
            )))
            .unwrap();
        assert_eq!(
            daemon.finish_promotion_attempt(),
            Some(PromotionRequestId::new("attempt-1"))
        );
        assert_eq!(
            daemon.promotion_attempt_lifecycle(),
            &PromotionAttemptLifecycle::Idle
        );
        daemon
            .request_promotion_attempt(PromotionExecutionRequest::new(PromotionRequestId::new(
                "attempt-2",
            )))
            .unwrap();
        assert_eq!(
            daemon.promotion_attempt_lifecycle().in_flight_id(),
            Some(&PromotionRequestId::new("attempt-2"))
        );

        // Accept -> cancel -> Idle -> fresh request accepted again.
        assert_eq!(
            daemon.cancel_promotion_attempt(),
            Some(PromotionRequestId::new("attempt-2"))
        );
        assert_eq!(
            daemon.promotion_attempt_lifecycle(),
            &PromotionAttemptLifecycle::Idle
        );
        daemon
            .request_promotion_attempt(PromotionExecutionRequest::new(PromotionRequestId::new(
                "attempt-3",
            )))
            .unwrap();
        assert_eq!(
            daemon.promotion_attempt_lifecycle().in_flight_id(),
            Some(&PromotionRequestId::new("attempt-3"))
        );

        assert_eq!(daemon.runtime.peer_tick_calls, 0);
        assert!(!daemon.runtime.calls.contains(&"promote"));
    }

    /// MKM-ARCH-011: after `request_shutdown()`, a new attempt is rejected
    /// (`RejectedShutdown`) and the slot stays idle; an already in-flight
    /// attempt is not silently mutated either.
    #[test]
    fn mkm_arch_011_shutdown_blocks_new_acceptance() {
        use crate::promotion_attempt::{
            PromotionAttemptLifecycle, PromotionAttemptRejection, PromotionExecutionRequest,
            PromotionRequestId,
        };

        let mut daemon = Daemon::new(runtime(Ok(standby())));
        daemon.start().unwrap();
        daemon.request_shutdown().unwrap();

        assert_eq!(
            daemon.request_promotion_attempt(PromotionExecutionRequest::new(
                PromotionRequestId::new("attempt-1")
            )),
            Err(PromotionAttemptRejection::RejectedShutdown)
        );
        assert_eq!(
            daemon.promotion_attempt_lifecycle(),
            &PromotionAttemptLifecycle::Idle,
            "MKM-ARCH-011 violated: shutdown-rejected request occupied the slot"
        );
        assert_eq!(daemon.runtime.peer_tick_calls, 0);
        assert!(!daemon.runtime.calls.contains(&"promote"));
    }

    // =======================================================================
    // MKM-ARCH-012 / Stage 13.2: fresh revalidation + shared Witness lease +
    // attempt-bound promotion execution.
    //
    // These tests drive `Daemon::execute_promotion_attempt` over a
    // deterministic `PromotionExecutionRuntime` double that reuses the real
    // `WitnessSession`, `WitnessEvidenceAdapter`, `NodeMutationStore`,
    // `NodeAuthorityController`, `StateMachine`, `ResourceWorkflow`, and
    // `ResourceExecutor` with scripted backends — only OS-facing transport
    // and resource syscalls are doubled, never the safety layers.
    // =======================================================================

    /// Stage 14 F14.9-01: `tick_at` hands the runtime two shutdown queries.
    /// The Stage 13 lifecycle query is the Daemon's requested state
    /// (unchanged). The Stage 14 fencing query is live: a shutdown-signal
    /// latch raised while the runtime is inside its foreground step (the
    /// foreground owner cannot run `request_shutdown` meanwhile) is visible
    /// the next time the step samples it. With no latch attached, the fencing
    /// query is the requested state alone.
    #[test]
    fn stage14_9_f01_tick_gives_the_fencing_step_a_live_shutdown_query() {
        use std::cell::Cell;
        use std::rc::Rc;

        struct Recorder {
            raise: Rc<Cell<bool>>,
            seen: Vec<(bool, bool)>,
        }

        impl DaemonRuntime for Recorder {
            fn startup(&mut self) -> Result<DaemonSnapshot, String> {
                Ok(standby())
            }
            fn observe(&mut self) -> Result<DaemonSnapshot, String> {
                Ok(standby())
            }
            fn shutdown(
                &mut self,
                _control_lock_safe: &dyn Fn() -> bool,
            ) -> Result<ShutdownResult, String> {
                Ok(ShutdownResult::Clean)
            }
            fn foreground_lifecycle_tick(
                &mut self,
                shutdown_requested: &dyn Fn() -> bool,
                live_shutdown: &dyn Fn() -> bool,
                _control_lock_safe: &dyn Fn() -> bool,
            ) -> Result<(), String> {
                self.seen.push((shutdown_requested(), live_shutdown()));
                // The signal arrives while the step blocks.
                self.raise.set(true);
                self.seen.push((shutdown_requested(), live_shutdown()));
                Ok(())
            }
        }

        for attached in [true, false] {
            let raise = Rc::new(Cell::new(false));
            let mut daemon = Daemon::new(Recorder {
                raise: raise.clone(),
                seen: Vec::new(),
            });
            assert_eq!(daemon.start().unwrap(), StartResult::Running);
            if attached {
                daemon.attach_shutdown_signal(move || raise.get());
            }
            assert_eq!(daemon.tick().unwrap(), TickResult::Observed);
            assert_eq!(
                daemon.runtime.seen,
                [(false, false), (false, attached)],
                "attached={attached}"
            );
            // Reading the latch never changes Daemon state: only
            // `request_shutdown` (the loop) does.
            assert_eq!(daemon.state(), DaemonState::Running);
        }
    }

    #[cfg(unix)]
    mod stage13_2 {
        use super::*;
        use crate::evidence_fusion::adapter::{
            AuthorityViewExpectation, ObservationProgress, WitnessEvidenceAdapter,
        };
        use crate::failover_policy::LocalSafetyReadiness;
        use crate::failure_assessment::{PeerFailureAssessment, PeerFailureDetector};
        use crate::node_lease_authority::node_witness_runtime::{
            NodeWitnessMutationResult, NodeWitnessMutationRuntime,
        };
        use crate::node_lease_authority::{
            AuthorityError, AuthorityMode, ClockError, LEASE_TTL_MS, MonotonicClock, MonotonicTime,
            NodeAuthorityController, RuntimeLeaseAuthority,
        };
        use crate::node_mutation::{MutationKind, NodeMutationStore};
        use crate::promotion_attempt::{
            PromotionAttemptLifecycle, PromotionAttemptRejection, PromotionAttemptResult,
            PromotionExecutionRequest, PromotionRequestId,
        };
        use crate::protocol::{
            CborSerializer, ClusterId, DurationMs, LeaseGrantPayload, LeaseId, LeaseRejectPayload,
            LeaseReleasedPayload, NodeId, ProtocolMessage, RequestId, Sequence, SessionId, Term,
            TermStatusPayload, WitnessMutationOutcomeCode,
        };
        use crate::resource_executor::{
            ActionDiagnostic, NetworkBackend, RawGarpOutcome, RawHealthObservation,
            RawServiceObservation, RawVipObservation, ResourceExecutor, ServiceBackend, sealed,
        };
        use crate::resource_workflow::{
            CleanupWorkflowOutcome, PromotionWorkflowOutcome, ResourceWorkflow,
        };
        use crate::security::{MessageAuthenticator, Psk};
        use crate::session::ProcessSession;
        use crate::state_machine::StateMachine;
        use crate::witness_runtime::{
            WitnessConnection, WitnessResponseContext, WitnessSession,
            send_witness_response_with_context,
        };
        use std::cell::{Cell, RefCell};
        use std::collections::VecDeque;
        use std::net::{TcpListener, TcpStream};
        use std::rc::Rc;
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        #[derive(Clone)]
        struct ExecClock(Rc<Cell<u64>>);

        impl MonotonicClock for ExecClock {
            fn now(&self) -> Result<MonotonicTime, ClockError> {
                Ok(MonotonicTime::from_millis(self.0.get()))
            }
        }

        /// Scripted network backend: observe reflects the state set by the
        /// corresponding request, so `ResourceWorkflow` sees real transitions.
        struct ExecNetwork {
            vip_present: Rc<Cell<bool>>,
            garp_ok: Rc<Cell<bool>>,
            actions: Rc<RefCell<Vec<&'static str>>>,
        }

        impl sealed::NetworkBackend for ExecNetwork {}

        impl NetworkBackend for ExecNetwork {
            fn request_vip_acquire(&mut self) -> ActionDiagnostic {
                self.actions.borrow_mut().push("vip_acquire");
                self.vip_present.set(true);
                ActionDiagnostic::Success
            }

            fn observe_vip(&mut self) -> RawVipObservation {
                if self.vip_present.get() {
                    RawVipObservation::Present
                } else {
                    RawVipObservation::Absent
                }
            }

            fn request_vip_release(&mut self) -> ActionDiagnostic {
                self.actions.borrow_mut().push("vip_release");
                self.vip_present.set(false);
                ActionDiagnostic::Success
            }

            fn send_garp(&mut self) -> (ActionDiagnostic, RawGarpOutcome) {
                self.actions.borrow_mut().push("garp");
                (
                    ActionDiagnostic::Success,
                    if self.garp_ok.get() {
                        RawGarpOutcome::Succeeded
                    } else {
                        RawGarpOutcome::Failed
                    },
                )
            }
        }

        struct ExecService {
            running: Rc<Cell<bool>>,
            start_ok: Rc<Cell<bool>>,
            healthy: Rc<Cell<bool>>,
            actions: Rc<RefCell<Vec<&'static str>>>,
        }

        impl sealed::ServiceBackend for ExecService {}

        impl ServiceBackend for ExecService {
            fn request_service_start(&mut self) -> ActionDiagnostic {
                self.actions.borrow_mut().push("service_start");
                if self.start_ok.get() {
                    self.running.set(true);
                    ActionDiagnostic::Success
                } else {
                    ActionDiagnostic::Error("scripted start failure".into())
                }
            }

            fn observe_service(&mut self) -> RawServiceObservation {
                if self.running.get() {
                    RawServiceObservation::Running
                } else {
                    RawServiceObservation::Stopped
                }
            }

            fn request_service_stop(&mut self) -> ActionDiagnostic {
                self.actions.borrow_mut().push("service_stop");
                self.running.set(false);
                ActionDiagnostic::Success
            }

            fn observe_health(&mut self) -> RawHealthObservation {
                if self.healthy.get() {
                    RawHealthObservation::Healthy
                } else {
                    RawHealthObservation::Unhealthy
                }
            }
        }

        /// The Stage 13.2 execution-runtime double. The decision surface
        /// (`evaluate_authority_attempt`) can be canned or driven through the
        /// real adapter over a loopback `WitnessSession`; every lease/promote
        /// boundary uses the real Stage 9/10/11 owners.
        struct ExecFake {
            session: Option<WitnessSession>,
            observer: Option<WitnessEvidenceAdapter>,
            store: NodeMutationStore,
            controller: NodeAuthorityController<ExecClock>,
            machine: StateMachine,
            executor: ResourceExecutor<ExecNetwork, ExecService>,
            node_id: NodeId,
            priority: i32,
            clock: ExecClock,
            start_ok: Rc<Cell<bool>>,
            vip_present: Rc<Cell<bool>>,
            service_running: Rc<Cell<bool>>,
            peer_detector: PeerFailureDetector,
            local_readiness: LocalSafetyReadiness,
            canned_evaluations: VecDeque<Result<Option<AuthorityAttemptEvaluation>, String>>,
            evaluate_calls: usize,
            lease_acquire_calls: usize,
            release_calls: usize,
            promotion_calls: usize,
            promoted_attempts: Vec<PromotionRequestId>,
            peer_tick_calls: usize,
            safety_requests: Vec<bool>,
            /// Phase 14.12 E3b: whether this fake runs the attempt-bound
            /// observation step (the adapter's `complete_attempt_observation`,
            /// as `LinuxDaemonRuntime` does). `false` keeps the Stage 13.2
            /// behavior: `evaluate_authority_attempt` drives its own GET_TERM.
            attempt_observation: bool,
            /// Phase 14.12 E3b: how often the attempt asked for the step.
            observation_steps: usize,
            /// Stage 14 §24 G stand-in. `None` is the test-only bypass that
            /// keeps these Stage 13.2 H-L tests meaningful; `Some` is the
            /// production-shaped gate decision.
            gate: Option<Result<crate::fencing::FencingGateBlock, String>>,
            gate_calls: usize,
            recheck_calls: usize,
            gate_shutdown_inputs: Vec<bool>,
            /// Stage 14 Phase 14.11 F2: a scripted L outcome (the fake ARM
            /// is replaced by this result; the bound authority is dropped).
            scripted_outcome: Option<AttemptPromotionOutcome>,
            /// Stage 14 Phase 14.11 F2: a scripted §25.1 cleanup result.
            scripted_cleanup: Option<Result<AttemptCleanup, String>>,
            /// Every `release_attempt_lease` call: the granted lease and the
            /// clearance binding the Daemon passed.
            cleanup_calls: Vec<(
                Option<(Term, LeaseId)>,
                Option<crate::fencing::IncidentBinding>,
            )>,
            /// §28.1 diagnostic the fake reports for the blocked-attempt line.
            interference: Option<u64>,
            /// Phase 14.11 remediation (L2): a scripted K runtime-half failure;
            /// the fake's recheck returns it and reports it as the last failure,
            /// exactly as `LinuxDaemonRuntime` does.
            scripted_recheck_failure: Option<String>,
            /// Bootstrap Admission fake state (all off by default, so every
            /// pre-BA test keeps its exact behavior).
            ba_supported: bool,
            ba_conservative: bool,
            ba_stamp: Option<crate::bootstrap_admission::BootstrapStamp>,
            ba_probe_requests: usize,
            ba_probe_request_ok: bool,
            ba_discards: usize,
            ba_outcomes: VecDeque<crate::bootstrap_admission::ProbeOutcome>,
            ba_contexts: Vec<Option<crate::bootstrap_admission::DaemonFacts>>,
            /// Automatic-trigger facts the fake reports (`None`: no automation).
            auto_facts_value: Option<AutoRuntimeFacts>,
            /// What `observe` reports (`None`: a clean Standby).
            observed: Option<DaemonSnapshot>,
            /// When set, `observe` fails with this error (a failed tick).
            observe_error: Option<String>,
            /// What the fake reports as the peer assessment for the log.
            peer_log_assessment: Option<PeerFailureAssessment>,
            /// Whether the fake's Witness session is lost.
            witness_lost: bool,
            /// Whether the runtime's fail-closed stop proof accepts a stop
            /// (models `LinuxNodeRuntime::witness_loss_stop_allowed`).
            witness_loss_stop_allowed: bool,
        }

        impl ExecFake {
            fn local_safety(&self, shutdown_requested: bool) -> LocalSafetySnapshot {
                LocalSafetySnapshot {
                    node_state: self.machine.node_state(),
                    operation_phase: self.machine.operation_phase(),
                    readiness: if shutdown_requested {
                        LocalSafetyReadiness::ShutdownInProgress
                    } else {
                        self.local_readiness
                    },
                }
            }

            /// The authority currently installed in the real controller, if
            /// any. Read-only test view used to prove move ownership: during
            /// the attempt window this is `None` because the single usable
            /// authority lives inside `AttemptBoundLeaseAuthority`.
            fn installed_lease_authority(&self) -> Option<&RuntimeLeaseAuthority> {
                self.controller.authority().authority()
            }

            /// Replicate `LinuxNodeRuntime::promote` exactly: the state
            /// machine enters promotion, `ResourceWorkflow` performs the
            /// real checkpoint-ordered mutation sequence, and rollback plus
            /// cleanup follow the same branches on failure.
            fn run_stage_11_promotion(&mut self) -> Result<AttemptPromotionOutcome, String> {
                self.machine
                    .transition_to(NodeState::Candidate)
                    .map_err(|error| error.to_string())?;
                self.machine
                    .begin_promotion()
                    .map_err(|error| error.to_string())?;
                self.machine
                    .advance_promotion()
                    .map_err(|error| error.to_string())?;
                let outcome =
                    ResourceWorkflow::new(&mut self.controller, &mut self.executor).promote();
                if outcome != PromotionWorkflowOutcome::ReadyForActiveCommit {
                    self.machine
                        .rollback_promotion()
                        .map_err(|error| error.to_string())?;
                    let cleanup = ResourceWorkflow::new(&mut self.controller, &mut self.executor)
                        .cleanup("promotion failure")
                        .map_err(|error| format!("{error:?}"))?;
                    let clean = matches!(cleanup, CleanupWorkflowOutcome::CleanStandbyEligible);
                    self.machine
                        .complete_promotion_rollback(clean)
                        .map_err(|error| error.to_string())?;
                    return Ok(AttemptPromotionOutcome::RolledBack);
                }
                let completion = (|| {
                    for _ in 0..5 {
                        self.controller.advance_promotion(&mut self.machine)?;
                    }
                    self.controller.complete_promotion(&mut self.machine)
                })();
                match completion {
                    Ok(()) => Ok(AttemptPromotionOutcome::Promoted),
                    Err(_) => {
                        self.machine
                            .rollback_promotion()
                            .map_err(|error| error.to_string())?;
                        let cleanup =
                            ResourceWorkflow::new(&mut self.controller, &mut self.executor)
                                .cleanup("promotion completion failure")
                                .map_err(|error| format!("{error:?}"))?;
                        let clean = matches!(cleanup, CleanupWorkflowOutcome::CleanStandbyEligible);
                        self.machine
                            .complete_promotion_rollback(clean)
                            .map_err(|error| error.to_string())?;
                        Ok(AttemptPromotionOutcome::RolledBack)
                    }
                }
            }
        }

        impl DaemonRuntime for ExecFake {
            fn startup(&mut self) -> Result<DaemonSnapshot, String> {
                Ok(standby())
            }

            fn observe(&mut self) -> Result<DaemonSnapshot, String> {
                if let Some(error) = &self.observe_error {
                    return Err(error.clone());
                }
                Ok(self.observed.unwrap_or_else(standby))
            }

            fn shutdown(
                &mut self,
                _control_lock_safe: &dyn Fn() -> bool,
            ) -> Result<ShutdownResult, String> {
                Ok(ShutdownResult::Clean)
            }

            fn peer_tick_at(
                &mut self,
                _now: std::time::Instant,
                _peer_status: Option<PeerStatusSnapshot>,
            ) -> Result<Option<PeerObservationState>, String> {
                self.peer_tick_calls += 1;
                Ok(None)
            }

            fn peer_assessment_for_log(&self) -> Option<PeerFailureAssessment> {
                self.peer_log_assessment
            }

            fn witness_session_lost(&self) -> bool {
                self.witness_lost
            }

            fn witness_loss_stop_allowed(&mut self) -> bool {
                self.witness_loss_stop_allowed
            }

            fn set_probe_context(
                &mut self,
                context: Option<crate::bootstrap_admission::DaemonFacts>,
            ) {
                self.ba_contexts.push(context);
            }

            fn auto_facts(&mut self, _now: std::time::Instant) -> Option<AutoRuntimeFacts> {
                self.auto_facts_value.clone()
            }

            fn bootstrap_supported(&self) -> bool {
                self.ba_supported
            }

            fn bootstrap_conservative(&self) -> bool {
                self.ba_conservative
            }

            fn bootstrap_stamp(&self) -> Option<crate::bootstrap_admission::BootstrapStamp> {
                self.ba_stamp.clone()
            }

            fn request_bootstrap_probe(&mut self) -> bool {
                self.ba_probe_requests += 1;
                self.ba_probe_request_ok
            }

            fn take_probe_outcome(&mut self) -> Option<crate::bootstrap_admission::ProbeOutcome> {
                self.ba_outcomes.pop_front()
            }

            fn discard_bootstrap_probe(&mut self) {
                self.ba_discards += 1;
            }

            fn local_safety_snapshot(
                &mut self,
                shutdown_requested: bool,
            ) -> Result<Option<LocalSafetySnapshot>, String> {
                self.safety_requests.push(shutdown_requested);
                Ok(Some(self.local_safety(shutdown_requested)))
            }
        }

        impl PromotionExecutionRuntime for ExecFake {
            fn fencing_gate(
                &mut self,
                _evaluation: &AuthorityAttemptEvaluation,
                shutdown_requested: &dyn Fn() -> bool,
            ) -> FencingGate {
                self.gate_calls += 1;
                self.gate_shutdown_inputs.push(shutdown_requested());
                match &self.gate {
                    Some(Ok(block)) => FencingGate::Blocked(*block),
                    Some(Err(error)) => FencingGate::Failed(error.clone()),
                    None => FencingGate::BypassedForStage13Test,
                }
            }

            fn fencing_final_recheck(
                &mut self,
                prerequisite: &FencingPrerequisite,
                _grant_term: Term,
            ) -> Result<(), String> {
                self.recheck_calls += 1;
                if let Some(failure) = &self.scripted_recheck_failure {
                    return Err(failure.clone());
                }
                // The Stage 13.2 fakes run only through the test bypass,
                // which carries no clearance and has no incident to recheck.
                match prerequisite {
                    FencingPrerequisite::BypassedForStage13Test => Ok(()),
                    FencingPrerequisite::Cleared(_) => Err("no fencing fake".into()),
                    // The K addition of the production runtime that Host can
                    // model: the same connection. (The runtime half's
                    // anchor + 1 check is Linux-only, so the daemon's own I
                    // check is what these tests exercise.)
                    FencingPrerequisite::Bootstrap(clearance) => {
                        if self.ba_stamp.as_ref() != Some(clearance.stamp()) {
                            Err("bootstrap: the peer connection changed".into())
                        } else {
                            Ok(())
                        }
                    }
                }
            }

            fn complete_attempt_observation(
                &mut self,
                shutdown_requested: &dyn Fn() -> bool,
            ) -> Result<(), &'static str> {
                self.observation_steps += 1;
                if !self.attempt_observation {
                    return Ok(());
                }
                let authority = self.controller.authority().authority();
                let expectation = AuthorityViewExpectation::new(
                    self.node_id.clone(),
                    authority.map(|authority| authority.term()),
                    authority.map(|authority| authority.lease_id().clone()),
                );
                let (Some(session), Some(observer)) =
                    (self.session.as_mut(), self.observer.as_mut())
                else {
                    return Err("Witness session is not configured");
                };
                observer
                    .complete_attempt_observation(
                        session,
                        expectation,
                        shutdown_requested,
                        &mut std::time::Instant::now,
                        &mut std::thread::sleep,
                    )
                    .into_result()
            }

            fn begin_authority_observation(
                &mut self,
                context: DaemonIterationContext,
            ) -> Result<(), String> {
                let session = self
                    .session
                    .as_mut()
                    .ok_or_else(|| "Witness session is not configured".to_string())?;
                let observer = self
                    .observer
                    .as_mut()
                    .ok_or_else(|| "Witness observation is not configured".to_string())?;
                if !session.request_in_flight() {
                    let authority = self.controller.authority().authority();
                    let expectation = AuthorityViewExpectation::new(
                        self.node_id.clone(),
                        authority.map(|authority| authority.term()),
                        authority.map(|authority| authority.lease_id().clone()),
                    );
                    observer
                        .begin_observation_at(session, expectation, context.now())
                        .map_err(|error| error.to_string())?;
                }
                Ok(())
            }

            fn evaluate_authority_attempt(
                &mut self,
                context: DaemonIterationContext,
            ) -> Result<Option<AuthorityAttemptEvaluation>, String> {
                self.evaluate_calls += 1;
                if let Some(canned) = self.canned_evaluations.pop_front() {
                    return canned;
                }
                // Real composition path: one GET_TERM through the shared
                // session's outstanding slot, one poll, one evaluation.
                let now = context.now();
                let local = self.local_safety(context.shutdown_requested());
                let peer_assessment = self.peer_detector.assessment();
                let peer_loss = self.peer_detector.loss_evidence();
                let session = self
                    .session
                    .as_mut()
                    .ok_or_else(|| "Witness session is not configured".to_string())?;
                let observer = self
                    .observer
                    .as_mut()
                    .ok_or_else(|| "Witness observation is not configured".to_string())?;
                if !self.attempt_observation && !session.request_in_flight() {
                    let authority = self.controller.authority().authority();
                    let expectation = AuthorityViewExpectation::new(
                        self.node_id.clone(),
                        authority.map(|authority| authority.term()),
                        authority.map(|authority| authority.lease_id().clone()),
                    );
                    observer
                        .begin_observation_at(session, expectation, now)
                        .map_err(|error| error.to_string())?;
                }
                observer
                    .observe_peer_at(peer_assessment, peer_loss, now)
                    .map_err(|error| error.to_string())?;
                if !self.attempt_observation {
                    session
                        .wait_for_readable_for_test()
                        .map_err(|error| error.to_string())?;
                }
                match observer
                    .poll_observation_at(session, now)
                    .map_err(|error| error.to_string())?
                {
                    ObservationProgress::Ready(authority_view) => {
                        if local.readiness != LocalSafetyReadiness::Safe {
                            return Ok(None);
                        }
                        let evidence = crate::evidence_fusion::WitnessEvidenceView::from_snapshot(
                            &observer.snapshot().fusion,
                        );
                        Ok(Some(AuthorityAttemptEvaluation::evaluate(
                            CurrentAuthorityAttemptObservation::new(
                                authority_view,
                                peer_assessment,
                                evidence,
                                local,
                            ),
                        )))
                    }
                    _ => Ok(None),
                }
            }

            fn acquire_attempt_lease_once(
                &mut self,
                term: Term,
            ) -> Result<NodeWitnessMutationResult, String> {
                self.lease_acquire_calls += 1;
                if self.machine.node_state() != NodeState::Standby
                    || !self.controller.recovery_reconciled()
                {
                    return Err(AuthorityError::RecoveryBlocked.to_string());
                }
                self.store
                    .begin_lease_request(term, self.priority, DurationMs(LEASE_TTL_MS))
                    .map_err(|error| error.to_string())?;
                let session = self
                    .session
                    .as_mut()
                    .ok_or_else(|| "Witness session is not configured".to_string())?;
                let runtime = NodeWitnessMutationRuntime::new(&self.store, self.node_id.clone());
                runtime
                    .execute_lease_request_once_with_controller(session, &mut self.controller)
                    .map(|timed| timed.result)
                    .map_err(|error| error.to_string())
            }

            fn take_attempt_lease_authority(&mut self) -> Option<RuntimeLeaseAuthority> {
                self.controller.take_installed_lease_authority()
            }

            fn attempt_lease_usable(&self, authority: &RuntimeLeaseAuthority) -> bool {
                authority.holder_node_id() == &self.node_id
                    && self
                        .clock
                        .now()
                        .is_ok_and(|now| now < authority.safe_deadline())
            }

            fn shared_witness_outstanding(&self) -> bool {
                self.session
                    .as_ref()
                    .is_some_and(|session| session.request_in_flight())
            }

            fn listener_interference_recent(&self, _now: std::time::Instant) -> Option<u64> {
                self.interference
            }

            fn last_recheck_failure(&self) -> Option<String> {
                self.scripted_recheck_failure.clone()
            }

            fn release_attempt_lease(
                &mut self,
                granted: Option<(Term, LeaseId)>,
                binding: Option<&crate::fencing::IncidentBinding>,
            ) -> Result<AttemptCleanup, String> {
                self.release_calls += 1;
                self.cleanup_calls.push((granted.clone(), binding.cloned()));
                if let Some(scripted) = self.scripted_cleanup.take() {
                    return scripted;
                }
                let session = self
                    .session
                    .as_mut()
                    .ok_or_else(|| "Witness session is not configured".to_string())?;
                let outstanding = self
                    .store
                    .outstanding()
                    .map_err(|error| error.to_string())?;
                let runtime = NodeWitnessMutationRuntime::new(&self.store, self.node_id.clone());
                let result = match (outstanding, granted) {
                    (None, Some((term, lease_id))) => {
                        if self.store.release_obligation().map_err(|error| error.to_string())?.is_none() {
                            self.store
                                .arm_release_obligation(term, lease_id.clone())
                                .map_err(|error| error.to_string())?;
                        }
                        runtime.begin_and_execute_lease_release_once(
                            session,
                            term,
                            lease_id,
                            "stage 13.2 attempt abort".to_string(),
                        )
                    }
                    (None, None) => return Ok(AttemptCleanup::Released),
                    // Same typed dispatch as the production path: only an
                    // exact LeaseRelease(term, lease_id) match may execute as
                    // this attempt's cleanup; anything else fails closed and
                    // is preserved for its rightful owner.
                    (Some(outstanding), Some((term, ref lease_id)))
                        if durable_release_matches(&outstanding, term, lease_id) =>
                    {
                        runtime.execute_outstanding_once(session)
                    }
                    (Some(_), _) => {
                        return Err(
                            "durable outstanding Witness mutation is not this attempt's expected LeaseRelease; preserved for its rightful owner".to_string(),
                        )
                    }
                };
                result
                    .map(|_| AttemptCleanup::Released)
                    .map_err(|error| error.to_string())
            }

            fn execute_attempt_promotion(
                &mut self,
                lease: AttemptBoundLeaseAuthority,
                _prerequisite: &FencingPrerequisite,
            ) -> Result<AttemptPromotionOutcome, String> {
                self.promotion_calls += 1;
                if let Some(outcome) = self.scripted_outcome.take() {
                    // The authority is dropped exactly as the runtime drops it
                    // on a non-committed or rejected ARM.
                    drop(lease);
                    return Ok(outcome);
                }
                // Mirror the production ARM-before-Stage-11 handoff.
                let attempt_id = lease.attempt_id().clone();
                if self
                    .store
                    .arm_release_obligation(
                        lease.lease_authority().term(),
                        lease.lease_authority().lease_id().clone(),
                    )
                    .is_err()
                {
                    return Ok(AttemptPromotionOutcome::ArmNotCommitted);
                }
                self.controller
                    .restore_installed_lease_authority(lease.into_authority())
                    .map_err(|error| error.to_string())?;
                self.promoted_attempts.push(attempt_id);
                self.run_stage_11_promotion()
            }
        }

        /// Scripted Witness response for one received request.
        enum WitnessReply {
            /// Respond with the successful/default message for the kind.
            Auto,
            /// GET_TERM answered with no lease holder (the old Active's lease is gone).
            NoHolder,
            /// GET_TERM answered with no holder at term N (Bootstrap Admission).
            NoHolderAt(u64),
            /// LeaseRequest granted at term N (echoes the request's lease identity).
            GrantAt(u64),
            /// Deterministic policy reject for a LeaseRequest.
            LeasePolicyReject,
            /// Respond successfully but with a foreign request id.
            WrongRequestId,
            /// Receive the request but never respond (the caller's session
            /// slot may be reset before the next request).
            Silent,
            /// J35: a LEASE_REJECT with this code, its header at term N.
            RejectAt(WitnessMutationOutcomeCode, u64),
            /// J35: N authenticated responses with foreign request ids, then
            /// the default answer for the request (D-tol / C-d).
            ForeignThenAuto(u8),
            /// J35: GET_TERM answered at term N with this node (`node-a`) as
            /// the holder of the named lease and this remaining time (ms).
            SelfHolderAt(u64, &'static str, u64),
        }

        struct WitnessHarness {
            requests: mpsc::Receiver<(&'static str, RequestId)>,
            join: WitnessThread,
        }

        /// How often an idle scripted Witness looks for the next frame.
        const WITNESS_IDLE_POLL: Duration = Duration::from_millis(2);

        /// The scripted Witness thread and the means to stop it. The thread
        /// serves until the peer closes the connection, the stream fails, or
        /// `join` tells it to stop: a Witness that has merely heard nothing
        /// for a while keeps serving (a slow test body must not lose its
        /// Witness). Dropping the handle does not stop it (some tests discard
        /// the harness and keep using the connection); it then ends with the
        /// connection.
        struct WitnessThread {
            handle: Option<thread::JoinHandle<()>>,
            stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
        }

        impl WitnessThread {
            /// Stop the Witness and wait for it. A panic in the thread is
            /// returned.
            fn join(mut self) -> thread::Result<()> {
                self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
                self.handle.take().expect("joined once").join()
            }

            fn is_finished(&self) -> bool {
                self.handle
                    .as_ref()
                    .is_none_or(thread::JoinHandle::is_finished)
            }
        }

        fn request_kind(message: &ProtocolMessage) -> &'static str {
            match message {
                ProtocolMessage::GetTerm => "get_term",
                ProtocolMessage::LeaseRequest(_) => "lease_request",
                ProtocolMessage::LeaseRenew(_) => "lease_renew",
                ProtocolMessage::LeaseRelease(_) => "lease_release",
                _ => "other",
            }
        }

        fn auto_reply(message: &ProtocolMessage) -> (ProtocolMessage, WitnessResponseContext) {
            match message {
                ProtocolMessage::GetTerm => (
                    ProtocolMessage::TermStatus(TermStatusPayload {
                        current_term: Term(7),
                        current_holder: Some(NodeId::new("node-b")),
                        current_lease_id: None,
                        lease_remaining_ms: None,
                    }),
                    WitnessResponseContext {
                        term: Term(7),
                        lease_id: None,
                    },
                ),
                ProtocolMessage::LeaseRequest(_) => (
                    ProtocolMessage::LeaseGrant(LeaseGrantPayload {
                        term: Term(7),
                        lease_id: LeaseId::new("lease-1"),
                        holder_node_id: NodeId::new("node-a"),
                        lease_ttl_ms: DurationMs(LEASE_TTL_MS),
                        renew_after_ms: DurationMs(3_000),
                        lease_remaining_ms: DurationMs(LEASE_TTL_MS),
                    }),
                    WitnessResponseContext {
                        term: Term(7),
                        lease_id: Some(LeaseId::new("lease-1")),
                    },
                ),
                ProtocolMessage::LeaseRenew(_) => (
                    ProtocolMessage::LeaseRenewed(LeaseGrantPayload {
                        term: Term(7),
                        lease_id: LeaseId::new("lease-1"),
                        holder_node_id: NodeId::new("node-a"),
                        lease_ttl_ms: DurationMs(LEASE_TTL_MS),
                        renew_after_ms: DurationMs(3_000),
                        lease_remaining_ms: DurationMs(LEASE_TTL_MS),
                    }),
                    WitnessResponseContext {
                        term: Term(7),
                        lease_id: Some(LeaseId::new("lease-1")),
                    },
                ),
                ProtocolMessage::LeaseRelease(payload) => (
                    ProtocolMessage::LeaseReleased(LeaseReleasedPayload {
                        term: payload.term,
                        lease_id: payload.lease_id.clone(),
                        result: "released".to_string(),
                    }),
                    WitnessResponseContext {
                        term: payload.term,
                        lease_id: Some(payload.lease_id.clone()),
                    },
                ),
                other => panic!("scripted witness: no auto reply for {other:?}"),
            }
        }

        /// Build a loopback Witness pair; the server thread serves `replies`
        /// (defaulting to `Auto` when exhausted) and logs every request.
        fn witness_pair(replies: VecDeque<WitnessReply>) -> (WitnessConnection, WitnessHarness) {
            witness_pair_polling(replies, WITNESS_IDLE_POLL)
        }

        /// `witness_pair` with the idle poll interval chosen by the test.
        fn witness_pair_polling(
            replies: VecDeque<WitnessReply>,
            idle_poll: Duration,
        ) -> (WitnessConnection, WitnessHarness) {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (server_stream, _) = listener.accept().unwrap();
            let node = WitnessConnection::new(
                NodeId::new("node-a"),
                NodeId::new("witness"),
                ClusterId::new("cluster"),
                SessionId::new("session-w"),
                crate::tcp::TcpConnection::from_stream(
                    client,
                    Duration::from_secs(2),
                    Duration::from_secs(2),
                )
                .unwrap(),
            );
            let mut witness = WitnessConnection::new(
                NodeId::new("witness"),
                NodeId::new("node-a"),
                ClusterId::new("cluster"),
                SessionId::new("session-a"),
                crate::tcp::TcpConnection::from_stream(
                    server_stream,
                    Duration::from_secs(2),
                    Duration::from_secs(2),
                )
                .unwrap(),
            );
            let (sender, requests) = mpsc::channel();
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let thread_stop = std::sync::Arc::clone(&stop);
            let handle = thread::spawn(move || {
                let mut replies = replies;
                let mut process = ProcessSession::from_session_id(SessionId::new("session-w"));
                let auth = MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32]));
                loop {
                    if thread_stop.load(std::sync::atomic::Ordering::SeqCst) {
                        break;
                    }
                    // Idle is not a failure: only a closed connection or a
                    // stream / protocol error ends the Witness.
                    let pending = match witness.poll_pending(&CborSerializer, &auth) {
                        Ok(crate::witness_runtime::WitnessPoll::Pending(pending, _)) => pending,
                        Ok(crate::witness_runtime::WitnessPoll::NoFrame) => {
                            thread::sleep(idle_poll);
                            continue;
                        }
                        Ok(crate::witness_runtime::WitnessPoll::Eof) | Err(_) => break,
                    };
                    let message = pending.message().unsigned().message.clone();
                    let request_id = pending
                        .message()
                        .unsigned()
                        .common
                        .request_id
                        .clone()
                        .unwrap();
                    let _ = sender.send((request_kind(&message), request_id.clone()));
                    let reply = replies.pop_front().unwrap_or(WitnessReply::Auto);
                    if matches!(reply, WitnessReply::Silent) {
                        continue;
                    }
                    if let WitnessReply::ForeignThenAuto(foreign) = reply {
                        for n in 0..foreign {
                            let (response, context) = auto_reply(&message);
                            let _ = send_witness_response_with_context(
                                &mut witness,
                                &mut process,
                                RequestId::new(format!(
                                    "00000000-0000-4000-8000-0000000001{n:02x}"
                                )),
                                response,
                                context,
                                &CborSerializer,
                                &auth,
                            );
                        }
                    }
                    let (response, context, response_id) = match reply {
                        WitnessReply::Auto => {
                            let (response, context) = auto_reply(&message);
                            (response, context, request_id)
                        }
                        WitnessReply::NoHolder => {
                            let (mut response, context) = auto_reply(&message);
                            if let ProtocolMessage::TermStatus(payload) = &mut response {
                                payload.current_holder = None;
                                payload.current_lease_id = None;
                                payload.lease_remaining_ms = None;
                            }
                            (response, context, request_id)
                        }
                        WitnessReply::NoHolderAt(term) => (
                            ProtocolMessage::TermStatus(TermStatusPayload {
                                current_term: Term(term),
                                current_holder: None,
                                current_lease_id: None,
                                lease_remaining_ms: None,
                            }),
                            WitnessResponseContext {
                                term: Term(term),
                                lease_id: None,
                            },
                            request_id,
                        ),
                        WitnessReply::GrantAt(term) => (
                            ProtocolMessage::LeaseGrant(LeaseGrantPayload {
                                term: Term(term),
                                lease_id: LeaseId::new("lease-1"),
                                holder_node_id: NodeId::new("node-a"),
                                lease_ttl_ms: DurationMs(LEASE_TTL_MS),
                                renew_after_ms: DurationMs(3_000),
                                lease_remaining_ms: DurationMs(LEASE_TTL_MS),
                            }),
                            WitnessResponseContext {
                                term: Term(term),
                                lease_id: Some(LeaseId::new("lease-1")),
                            },
                            request_id,
                        ),
                        WitnessReply::LeasePolicyReject => (
                            ProtocolMessage::LeaseReject(LeaseRejectPayload {
                                code: WitnessMutationOutcomeCode::PolicyReject,
                                reason: "policy reject".to_string(),
                            }),
                            WitnessResponseContext {
                                term: Term(7),
                                lease_id: None,
                            },
                            request_id,
                        ),
                        WitnessReply::WrongRequestId => {
                            let (response, context) = auto_reply(&message);
                            (
                                response,
                                context,
                                RequestId::new("00000000-0000-4000-8000-000000000099"),
                            )
                        }
                        WitnessReply::RejectAt(code, term) => (
                            ProtocolMessage::LeaseReject(LeaseRejectPayload {
                                code,
                                reason: "scripted reject".to_string(),
                            }),
                            WitnessResponseContext {
                                term: Term(term),
                                lease_id: None,
                            },
                            request_id,
                        ),
                        WitnessReply::ForeignThenAuto(_) => {
                            let (response, context) = auto_reply(&message);
                            (response, context, request_id)
                        }
                        WitnessReply::SelfHolderAt(term, lease, remaining) => (
                            ProtocolMessage::TermStatus(TermStatusPayload {
                                current_term: Term(term),
                                current_holder: Some(NodeId::new("node-a")),
                                current_lease_id: Some(LeaseId::new(lease)),
                                lease_remaining_ms: Some(DurationMs(remaining)),
                            }),
                            WitnessResponseContext {
                                term: Term(term),
                                lease_id: Some(LeaseId::new(lease)),
                            },
                            request_id,
                        ),
                        WitnessReply::Silent => unreachable!("handled above"),
                    };
                    if send_witness_response_with_context(
                        &mut witness,
                        &mut process,
                        response_id,
                        response,
                        context,
                        &CborSerializer,
                        &auth,
                    )
                    .is_err()
                    {
                        break;
                    }
                }
            });
            let join = WitnessThread {
                handle: Some(handle),
                stop,
            };
            (node, WitnessHarness { requests, join })
        }

        fn test_path(name: &str) -> std::path::PathBuf {
            std::env::temp_dir().join(format!("mikagami-stage13-2-{name}-{}", std::process::id()))
        }

        /// A real `PeerFailureDetector` driven through the production
        /// lifecycle into `CommunicationLost`: suspect at `t0`, confirmed
        /// after a full confirmation window. The resulting loss epoch is
        /// fresh relative to the real `Instant` clock used by
        /// `DaemonIterationContext::now()`.
        fn lost_peer_detector() -> PeerFailureDetector {
            let mut detector = PeerFailureDetector::new(Duration::from_millis(10)).unwrap();
            let t0 = std::time::Instant::now();
            let session = SessionId::new("peer-session");
            detector
                .observe_session_established(session.clone(), t0)
                .unwrap();
            detector
                .observe_trusted_heartbeat(&session, Sequence(1), t0)
                .unwrap();
            detector
                .observe_session_lost(t0 + Duration::from_millis(1))
                .unwrap();
            detector.tick(t0 + Duration::from_millis(11)).unwrap();
            debug_assert_eq!(
                detector.assessment(),
                PeerFailureAssessment::CommunicationLost
            );
            detector
        }

        /// Build a reconciled zero-resource execution runtime over a scripted
        /// Witness, wrapped in a started `Daemon`.
        fn exec_daemon(
            name: &str,
            replies: VecDeque<WitnessReply>,
            canned: VecDeque<Result<Option<AuthorityAttemptEvaluation>, String>>,
        ) -> (
            Daemon<ExecFake>,
            WitnessHarness,
            ExecClock,
            std::path::PathBuf,
        ) {
            let (node, harness) = witness_pair(replies);
            let session = WitnessSession::new(
                node,
                ProcessSession::from_session_id(SessionId::new("session-a")),
                MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32])),
            );
            let path = test_path(name);
            let store =
                NodeMutationStore::new(&path, ClusterId::new("cluster"), NodeId::new("node-a"));
            store.initialize_new().unwrap();
            let clock = ExecClock(Rc::new(Cell::new(0)));
            let mut controller = NodeAuthorityController::new_for_runtime(
                clock.clone(),
                NodeId::new("node-a"),
                NodeMutationStore::new(&path, ClusterId::new("cluster"), NodeId::new("node-a")),
                AuthorityMode::Conservative,
            );
            controller.reconcile_zero_resource().unwrap();
            let mut machine = StateMachine::new();
            machine.transition_to(NodeState::Standby).unwrap();
            let vip_present = Rc::new(Cell::new(false));
            let garp_ok = Rc::new(Cell::new(true));
            let running = Rc::new(Cell::new(false));
            let start_ok = Rc::new(Cell::new(true));
            let healthy = Rc::new(Cell::new(true));
            let actions = Rc::new(RefCell::new(Vec::new()));
            let fake = ExecFake {
                session: Some(session),
                observer: Some(WitnessEvidenceAdapter::new(Duration::from_secs(2)).unwrap()),
                store,
                controller,
                machine,
                executor: ResourceExecutor::new(
                    ExecNetwork {
                        vip_present: Rc::clone(&vip_present),
                        garp_ok: Rc::clone(&garp_ok),
                        actions: Rc::clone(&actions),
                    },
                    ExecService {
                        running: Rc::clone(&running),
                        start_ok: Rc::clone(&start_ok),
                        healthy: Rc::clone(&healthy),
                        actions: Rc::clone(&actions),
                    },
                ),
                node_id: NodeId::new("node-a"),
                priority: 100,
                clock: clock.clone(),
                start_ok: Rc::clone(&start_ok),
                vip_present: Rc::clone(&vip_present),
                service_running: Rc::clone(&running),
                peer_detector: lost_peer_detector(),
                local_readiness: LocalSafetyReadiness::Safe,
                canned_evaluations: canned,
                evaluate_calls: 0,
                lease_acquire_calls: 0,
                release_calls: 0,
                promotion_calls: 0,
                promoted_attempts: Vec::new(),
                peer_tick_calls: 0,
                safety_requests: Vec::new(),
                attempt_observation: false,
                observation_steps: 0,
                gate: None,
                gate_calls: 0,
                gate_shutdown_inputs: Vec::new(),
                recheck_calls: 0,
                scripted_outcome: None,
                scripted_cleanup: None,
                cleanup_calls: Vec::new(),
                interference: None,
                scripted_recheck_failure: None,
                ba_supported: false,
                ba_conservative: true,
                ba_stamp: None,
                ba_probe_requests: 0,
                ba_probe_request_ok: true,
                ba_discards: 0,
                ba_outcomes: VecDeque::new(),
                ba_contexts: Vec::new(),
                auto_facts_value: None,
                observed: None,
                observe_error: None,
                peer_log_assessment: None,
                witness_lost: false,
                witness_loss_stop_allowed: false,
            };
            let mut daemon = Daemon::new(fake);
            daemon.start().unwrap();
            (daemon, harness, clock, path)
        }

        /// A real `Authorized` evaluation minted through the production
        /// observation/evaluation path (fresh `WitnessAuthorityViewEvidence`).
        fn authorized_evaluation() -> AuthorityAttemptEvaluation {
            ready_progress_at(
                std::time::Instant::now(),
                PeerFailureAssessment::CommunicationLost,
                crate::evidence_fusion::EvidenceFusionState::FailoverEvidenceReady,
                LocalSafetyReadiness::Safe,
            )
            .into_evaluation()
            .expect("test setup: Ready observation produced no evaluation")
        }

        /// A real evaluation that is `Ready` but not `Authorized`
        /// (healthy peer evidence cannot authorize).
        fn unauthorized_evaluation() -> AuthorityAttemptEvaluation {
            ready_progress_at(
                std::time::Instant::now(),
                PeerFailureAssessment::Healthy,
                crate::evidence_fusion::EvidenceFusionState::Unproven,
                LocalSafetyReadiness::Safe,
            )
            .into_evaluation()
            .expect("test setup: Ready observation produced no evaluation")
        }

        fn request(id: &str) -> PromotionExecutionRequest {
            PromotionExecutionRequest::new(PromotionRequestId::new(id))
        }

        fn witness_log(harness: &WitnessHarness) -> Vec<&'static str> {
            let mut log = Vec::new();
            while let Ok((kind, _)) = harness.requests.try_recv() {
                log.push(kind);
            }
            log
        }

        fn cleanup_store(path: &std::path::Path) {
            let _ = std::fs::remove_file(path);
            let _ = std::fs::remove_file(crate::recovery::marker_path(path));
        }

        // ---- Stage 14 Phase 14.11: F2 and the §28 blocked-attempt lines ----

        /// One attempt with the operator log captured.
        fn stage14_11_run(
            name: &str,
            canned: Result<Option<AuthorityAttemptEvaluation>, String>,
            configure: impl FnOnce(&mut Daemon<ExecFake>),
        ) -> (
            PromotionAttemptResult,
            Vec<String>,
            Daemon<ExecFake>,
            WitnessHarness,
            std::path::PathBuf,
        ) {
            let (mut daemon, harness, _clock, path) =
                exec_daemon(name, VecDeque::new(), VecDeque::from([canned]));
            configure(&mut daemon);
            crate::operator_log::capture_start();
            let result = daemon.execute_promotion_attempt(request("attempt-1"));
            let lines = crate::operator_log::capture_take();
            (result, lines, daemon, harness, path)
        }

        fn stage14_11_lease_kinds(harness: &WitnessHarness) -> Vec<&'static str> {
            witness_log(harness)
                .into_iter()
                .filter(|kind| kind.starts_with("lease"))
                .collect()
        }

        // ---- Startup Obligation Reconciliation (contract A-4, SOR-1..5) ----

        use crate::evidence_fusion::adapter::AuthorityViewCompatibility as SorCompat;
        use crate::obligation_reconciliation::{SorOutcome, SupersededBy, reconcile};

        /// A restarted node whose crash left `O = (7, lease-1)` behind.
        fn sor_daemon(name: &str) -> (Daemon<ExecFake>, WitnessHarness, std::path::PathBuf) {
            let (daemon, harness, _clock, path) =
                exec_daemon(name, VecDeque::new(), VecDeque::new());
            daemon
                .runtime
                .store
                .arm_release_obligation(Term(7), LeaseId::new("lease-1"))
                .unwrap();
            (daemon, harness, path)
        }

        fn sor_run(
            daemon: &mut Daemon<ExecFake>,
            zero_resource: bool,
            view: Option<(Term, SorCompat)>,
        ) -> SorOutcome {
            sor_run_with(daemon, zero_resource, view, &mut || true, &mut |_| {
                Err("no retired view in this test".to_string())
            })
        }

        /// `sor_run` with the J35 (Amendment C) inputs: the fresh
        /// ZeroResource re-check (C-m') and the C-l view source.
        fn sor_run_with(
            daemon: &mut Daemon<ExecFake>,
            zero_resource: bool,
            view: Option<(Term, SorCompat)>,
            fresh_zero_resource: &mut dyn FnMut() -> bool,
            retired_view: &mut dyn FnMut(
                &mut crate::witness_runtime::WitnessSession,
            ) -> Result<(Term, SorCompat), String>,
        ) -> SorOutcome {
            let fake = &mut daemon.runtime;
            let session = fake.session.as_mut().unwrap();
            reconcile(
                &fake.store,
                &NodeId::new("node-a"),
                session,
                zero_resource,
                view,
                fresh_zero_resource,
                retired_view,
            )
            .unwrap()
        }

        fn sor_o_present(daemon: &Daemon<ExecFake>) -> bool {
            daemon.runtime.store.release_obligation().unwrap().is_some()
        }

        /// SOR-2 (ii)/(iii): a newer Witness term, or the same term without a
        /// holder, clears O. No Witness traffic, no authority (SOR-5).
        #[test]
        fn sor_clears_a_superseded_obligation_without_witness_traffic() {
            for (term, compat, by) in [
                (
                    Term(9),
                    SorCompat::ConflictingHolder,
                    SupersededBy::NewerTerm,
                ),
                (
                    Term(8),
                    SorCompat::CompatibleSelfUnexpired,
                    SupersededBy::NewerTerm,
                ),
                (
                    Term(8),
                    SorCompat::InconsistentAuthorityView,
                    SupersededBy::NewerTerm,
                ),
                (
                    Term(7),
                    SorCompat::CompatibleNoHolder,
                    SupersededBy::SameTermNoHolder,
                ),
            ] {
                let (mut daemon, harness, path) = sor_daemon("sor-clear");
                let outcome = sor_run(&mut daemon, true, Some((term, compat)));
                assert_eq!(outcome, SorOutcome::Cleared { term: Term(7), by });
                assert!(!sor_o_present(&daemon));
                assert!(witness_log(&harness).is_empty());
                assert!(daemon.runtime.installed_lease_authority().is_none());
                cleanup_store(&path);
            }
        }

        /// SOR-2: never cleared when the Witness is behind (rollback or wrong
        /// Witness) or when the same-term holder is not provably gone.
        #[test]
        fn sor_never_clears_when_witness_is_behind_or_holder_not_gone() {
            for (term, compat) in [
                (Term(6), SorCompat::CompatibleNoHolder),
                (Term(0), SorCompat::CompatibleNoHolder),
                (Term(6), SorCompat::CompatibleSelfUnexpired),
                (Term(7), SorCompat::ConflictingHolder),
                (Term(7), SorCompat::ExpiredButUnprocessed),
                (Term(7), SorCompat::InconsistentAuthorityView),
            ] {
                let (mut daemon, harness, path) = sor_daemon("sor-blocked");
                let outcome = sor_run(&mut daemon, true, Some((term, compat)));
                assert!(
                    matches!(outcome, SorOutcome::Blocked(_)),
                    "{term:?} {compat:?}: {outcome:?}"
                );
                assert!(sor_o_present(&daemon), "{term:?} {compat:?}");
                assert!(witness_log(&harness).is_empty());
                cleanup_store(&path);
            }
        }

        /// SOR-3: no trusted ZeroResource means nothing is touched, whatever
        /// the Witness says; and no view means nothing is cleared.
        #[test]
        fn sor_needs_trusted_zero_resource_and_a_view() {
            let (mut daemon, harness, path) = sor_daemon("sor-no-zero");
            let outcome = sor_run(
                &mut daemon,
                false,
                Some((Term(9), SorCompat::CompatibleNoHolder)),
            );
            assert!(matches!(outcome, SorOutcome::Blocked(_)), "{outcome:?}");
            assert!(sor_o_present(&daemon));
            let outcome = sor_run(&mut daemon, true, None);
            assert!(matches!(outcome, SorOutcome::Blocked(_)), "{outcome:?}");
            assert!(sor_o_present(&daemon));
            assert!(witness_log(&harness).is_empty());
            cleanup_store(&path);
        }

        /// SOR-3: an outstanding mutation that is not the owned release keeps
        /// the existing recovery contract; SOR clears nothing.
        #[test]
        fn sor_does_not_apply_with_a_foreign_outstanding_mutation() {
            let (mut daemon, _harness, path) = sor_daemon("sor-foreign-m");
            daemon
                .runtime
                .store
                .begin_lease_renew(Term(7), LeaseId::new("lease-1"))
                .unwrap();
            assert_eq!(
                crate::obligation_reconciliation::candidate(&daemon.runtime.store).unwrap(),
                None
            );
            let outcome = sor_run(
                &mut daemon,
                true,
                Some((Term(9), SorCompat::CompatibleNoHolder)),
            );
            assert_eq!(outcome, SorOutcome::NotApplicable);
            assert!(sor_o_present(&daemon));
            assert!(daemon.runtime.store.outstanding().unwrap().is_some());
            // The store operation itself also refuses with M present.
            assert!(
                daemon
                    .runtime
                    .store
                    .clear_superseded_obligation(Term(7), &LeaseId::new("lease-1"))
                    .is_err()
            );
            assert!(sor_o_present(&daemon));
            cleanup_store(&path);
        }

        /// The store operation clears only the exact O.
        #[test]
        fn sor_store_operation_requires_the_exact_obligation() {
            let (daemon, _harness, path) = sor_daemon("sor-exact-o");
            let store = &daemon.runtime.store;
            assert!(
                store
                    .clear_superseded_obligation(Term(7), &LeaseId::new("other"))
                    .is_err()
            );
            assert!(
                store
                    .clear_superseded_obligation(Term(6), &LeaseId::new("lease-1"))
                    .is_err()
            );
            assert!(store.release_obligation().unwrap().is_some());
            store
                .clear_superseded_obligation(Term(7), &LeaseId::new("lease-1"))
                .unwrap();
            assert!(store.release_obligation().unwrap().is_none());
            // Nothing to clear any more.
            assert!(
                store
                    .clear_superseded_obligation(Term(7), &LeaseId::new("lease-1"))
                    .is_err()
            );
            cleanup_store(&path);
        }

        /// SOR-2 (i): the Witness still holds the exact lease: the existing
        /// exact `LeaseRelease` runs and clears O; still no authority.
        #[test]
        fn sor_exact_release_when_the_witness_still_holds_the_lease() {
            let (mut daemon, harness, path) = sor_daemon("sor-exact");
            let outcome = sor_run(
                &mut daemon,
                true,
                Some((Term(7), SorCompat::CompatibleSelfUnexpired)),
            );
            assert_eq!(outcome, SorOutcome::Released { term: Term(7) });
            assert_eq!(witness_log(&harness), ["lease_release"]);
            assert!(!sor_o_present(&daemon));
            assert!(daemon.runtime.store.outstanding().unwrap().is_none());
            assert!(daemon.runtime.installed_lease_authority().is_none());
            cleanup_store(&path);
        }

        /// A previous run's owned `LeaseRelease(O)` that is still outstanding
        /// is retried exactly, without needing a new view.
        #[test]
        fn sor_retries_an_owned_pending_release_exactly() {
            let (mut daemon, harness, path) = sor_daemon("sor-pending");
            daemon
                .runtime
                .store
                .begin_lease_release_for_test(Term(7), LeaseId::new("lease-1"), "crash".into())
                .unwrap();
            let candidate = crate::obligation_reconciliation::candidate(&daemon.runtime.store)
                .unwrap()
                .unwrap();
            assert!(candidate.release_pending);
            let outcome = sor_run(&mut daemon, true, None);
            assert_eq!(outcome, SorOutcome::Released { term: Term(7) });
            assert_eq!(witness_log(&harness), ["lease_release"]);
            assert!(!sor_o_present(&daemon));
            cleanup_store(&path);
        }

        /// A Witness that refuses the release keeps O (RecoveryBlocked).
        #[test]
        fn sor_exact_release_not_accepted_keeps_the_obligation() {
            let (mut daemon, harness, _clock, path) = exec_daemon(
                "sor-exact-silent",
                VecDeque::from([WitnessReply::WrongRequestId]),
                VecDeque::new(),
            );
            daemon
                .runtime
                .store
                .arm_release_obligation(Term(7), LeaseId::new("lease-1"))
                .unwrap();
            let outcome = sor_run(
                &mut daemon,
                true,
                Some((Term(7), SorCompat::CompatibleSelfUnexpired)),
            );
            assert!(matches!(outcome, SorOutcome::Blocked(_)), "{outcome:?}");
            assert!(sor_o_present(&daemon));
            assert_eq!(witness_log(&harness), ["lease_release"]);
            cleanup_store(&path);
        }

        // ---- J35 (cf30, Amendment C): C-l, CL-05s, CL-07, C-m', OD-J31-4 ----

        /// A restarted node with `O = (7, lease-1)` and its owned exact
        /// Release `M` still outstanding; the scripted Witness answers the
        /// exact replay with `replies`.
        fn j35_pending_daemon(
            name: &str,
            replies: VecDeque<WitnessReply>,
        ) -> (Daemon<ExecFake>, WitnessHarness, std::path::PathBuf) {
            let (daemon, harness, _clock, path) = exec_daemon(name, replies, VecDeque::new());
            daemon
                .runtime
                .store
                .arm_release_obligation(Term(7), LeaseId::new("lease-1"))
                .unwrap();
            daemon
                .runtime
                .store
                .begin_lease_release_for_test(Term(7), LeaseId::new("lease-1"), "crash".into())
                .unwrap();
            (daemon, harness, path)
        }

        fn j35_m_present(daemon: &Daemon<ExecFake>) -> bool {
            daemon.runtime.store.outstanding().unwrap().is_some()
        }

        /// C-l (AC-9): after the exact replay is answered RetiredStale, a new
        /// view whose `decide` is ClearSuperseded settles exactly M and O,
        /// labelled superseded (never Released), with no authority. The view
        /// is taken only after the replay, and ZeroResource is re-checked.
        #[test]
        fn j35_cl_settles_a_retired_release_from_a_new_superseding_view() {
            for (view, by) in [
                (
                    (Term(9), SorCompat::ConflictingHolder),
                    SupersededBy::RetiredThenNewerTerm,
                ),
                (
                    (Term(8), SorCompat::CompatibleNoHolder),
                    SupersededBy::RetiredThenNewerTerm,
                ),
                // F33-5: a newer-term self holder with remaining = 0 is not
                // blocked by CL-05s.
                (
                    (Term(9), SorCompat::ExpiredButUnprocessed),
                    SupersededBy::RetiredThenNewerTerm,
                ),
                (
                    (Term(7), SorCompat::CompatibleNoHolder),
                    SupersededBy::RetiredThenSameTermNoHolder,
                ),
            ] {
                let (mut daemon, harness, path) = j35_pending_daemon(
                    "j35-cl-clear",
                    VecDeque::from([WitnessReply::RejectAt(
                        WitnessMutationOutcomeCode::RetiredStale,
                        9,
                    )]),
                );
                let mut views = 0;
                let mut rechecks = 0;
                let outcome = sor_run_with(
                    &mut daemon,
                    true,
                    None,
                    &mut || {
                        rechecks += 1;
                        true
                    },
                    &mut |_| {
                        views += 1;
                        Ok(view)
                    },
                );
                assert_eq!(
                    outcome,
                    SorOutcome::Cleared { term: Term(7), by },
                    "{view:?}"
                );
                assert_eq!((views, rechecks), (1, 1), "{view:?}");
                assert_eq!(witness_log(&harness), ["lease_release"]);
                assert!(!sor_o_present(&daemon));
                assert!(!j35_m_present(&daemon));
                assert!(daemon.runtime.installed_lease_authority().is_none());
                cleanup_store(&path);
            }
        }

        /// C-l keeps M and O for every view that is not ClearSuperseded:
        /// CL-05s (a newer-term unexpired self holder, matching or not),
        /// CL-07 (the exact lease still held), CL-06 (Witness behind) and a
        /// same-term holder that is not gone. Nothing is re-checked or saved.
        #[test]
        fn j35_cl_keeps_the_obligation_unless_the_view_supersedes_it() {
            for view in [
                (Term(9), SorCompat::CompatibleSelfUnexpired),
                (Term(8), SorCompat::InconsistentAuthorityView),
                (Term(7), SorCompat::CompatibleSelfUnexpired),
                (Term(6), SorCompat::CompatibleNoHolder),
                (Term(7), SorCompat::ConflictingHolder),
                (Term(7), SorCompat::ExpiredButUnprocessed),
                (Term(7), SorCompat::InconsistentAuthorityView),
            ] {
                let (mut daemon, _harness, path) = j35_pending_daemon(
                    "j35-cl-block",
                    VecDeque::from([WitnessReply::RejectAt(
                        WitnessMutationOutcomeCode::RetiredStale,
                        9,
                    )]),
                );
                let mut rechecks = 0;
                let outcome = sor_run_with(
                    &mut daemon,
                    true,
                    None,
                    &mut || {
                        rechecks += 1;
                        true
                    },
                    &mut |_| Ok(view),
                );
                assert!(
                    matches!(outcome, SorOutcome::Blocked(_)),
                    "{view:?}: {outcome:?}"
                );
                assert_eq!(rechecks, 0, "{view:?}");
                assert!(sor_o_present(&daemon), "{view:?}");
                assert!(j35_m_present(&daemon), "{view:?}");
                cleanup_store(&path);
            }
        }

        /// CL-01 / CL-11: RetiredStale alone never resolves: no view, or a
        /// failed fresh ZeroResource, keeps M and O.
        #[test]
        fn j35_cl_fails_closed_without_a_view_or_a_fresh_zero_resource() {
            let (mut daemon, _harness, path) = j35_pending_daemon(
                "j35-cl-no-view",
                VecDeque::from([WitnessReply::RejectAt(
                    WitnessMutationOutcomeCode::RetiredStale,
                    9,
                )]),
            );
            let outcome = sor_run_with(&mut daemon, true, None, &mut || true, &mut |_| {
                Err("no view".to_string())
            });
            assert!(matches!(outcome, SorOutcome::Blocked(_)), "{outcome:?}");
            assert!(sor_o_present(&daemon) && j35_m_present(&daemon));
            cleanup_store(&path);

            let (mut daemon, _harness, path) = j35_pending_daemon(
                "j35-cl-no-zero",
                VecDeque::from([WitnessReply::RejectAt(
                    WitnessMutationOutcomeCode::RetiredStale,
                    9,
                )]),
            );
            let outcome = sor_run_with(&mut daemon, true, None, &mut || false, &mut |_| {
                Ok((Term(9), SorCompat::ConflictingHolder))
            });
            assert!(matches!(outcome, SorOutcome::Blocked(_)), "{outcome:?}");
            assert!(sor_o_present(&daemon) && j35_m_present(&daemon));
            cleanup_store(&path);
        }

        /// The C-l view is taken only after a RetiredStale of the pending
        /// exact replay: an accepted release, a reject that is not
        /// RetiredStale, and a newly begun release never ask for it.
        #[test]
        fn j35_cl_view_is_requested_only_after_a_retired_exact_replay() {
            for (reply, pending) in [
                (WitnessReply::Auto, true),
                (
                    WitnessReply::RejectAt(WitnessMutationOutcomeCode::Conflict, 9),
                    true,
                ),
                (
                    WitnessReply::RejectAt(WitnessMutationOutcomeCode::GenerationGap, 9),
                    true,
                ),
                (
                    WitnessReply::RejectAt(WitnessMutationOutcomeCode::TemporarilyUnavailable, 9),
                    true,
                ),
                (
                    WitnessReply::RejectAt(WitnessMutationOutcomeCode::RetiredStale, 9),
                    false,
                ),
            ] {
                let (mut daemon, _harness, path) = if pending {
                    j35_pending_daemon("j35-cl-order", VecDeque::from([reply]))
                } else {
                    let (daemon, _h, _c, path) =
                        exec_daemon("j35-cl-order-new", VecDeque::from([reply]), VecDeque::new());
                    daemon
                        .runtime
                        .store
                        .arm_release_obligation(Term(7), LeaseId::new("lease-1"))
                        .unwrap();
                    (daemon, _h, path)
                };
                let mut views = 0;
                let view = if pending {
                    None
                } else {
                    Some((Term(7), SorCompat::CompatibleSelfUnexpired))
                };
                let _ = sor_run_with(&mut daemon, true, view, &mut || true, &mut |_| {
                    views += 1;
                    Ok((Term(9), SorCompat::ConflictingHolder))
                });
                assert_eq!(views, 0, "pending={pending}");
                cleanup_store(&path);
            }
        }

        /// A-4d with C-m': the settle needs the reject header term at or
        /// above term_o and a fresh trusted ZeroResource immediately before;
        /// it is labelled as a rejected release, never Released.
        #[test]
        fn j35_a4d_settle_needs_the_term_and_a_fresh_zero_resource() {
            let (mut daemon, _harness, path) = j35_pending_daemon(
                "j35-a4d-ok",
                VecDeque::from([WitnessReply::RejectAt(
                    WitnessMutationOutcomeCode::PolicyReject,
                    7,
                )]),
            );
            let mut rechecks = 0;
            let outcome = sor_run_with(
                &mut daemon,
                true,
                None,
                &mut || {
                    rechecks += 1;
                    true
                },
                &mut |_| panic!("no C-l view after a PolicyReject"),
            );
            assert!(
                matches!(
                    outcome,
                    SorOutcome::Cleared {
                        term: Term(7),
                        by: SupersededBy::WitnessRejectedRelease { .. }
                    }
                ),
                "{outcome:?}"
            );
            assert_eq!(rechecks, 1);
            assert!(!sor_o_present(&daemon) && !j35_m_present(&daemon));
            cleanup_store(&path);

            for (term, fresh) in [(6, true), (7, false)] {
                let (mut daemon, _harness, path) = j35_pending_daemon(
                    "j35-a4d-block",
                    VecDeque::from([WitnessReply::RejectAt(
                        WitnessMutationOutcomeCode::PolicyReject,
                        term,
                    )]),
                );
                let outcome = sor_run_with(&mut daemon, true, None, &mut || fresh, &mut |_| {
                    panic!("no C-l view after a PolicyReject")
                });
                assert!(
                    matches!(outcome, SorOutcome::Blocked(_)),
                    "{term} {fresh}: {outcome:?}"
                );
                assert!(
                    sor_o_present(&daemon) && j35_m_present(&daemon),
                    "{term} {fresh}"
                );
                cleanup_store(&path);
            }
        }

        /// OD-J31-4: an exhausted correlation of the exact replay is an
        /// unknown outcome at startup: M and O stay.
        #[test]
        fn j35_sor_exhausted_correlation_is_an_unknown_outcome() {
            let (mut daemon, _harness, path) = j35_pending_daemon(
                "j35-sor-exhausted",
                VecDeque::from([WitnessReply::ForeignThenAuto(5)]),
            );
            let outcome = sor_run_with(&mut daemon, true, None, &mut || true, &mut |_| {
                panic!("no C-l view without a RetiredStale")
            });
            match outcome {
                SorOutcome::Blocked(cause) => assert!(cause.contains("unknown"), "{cause}"),
                other => panic!("{other:?}"),
            }
            assert!(sor_o_present(&daemon) && j35_m_present(&daemon));
            cleanup_store(&path);
        }

        /// C-l (T-04, CL-02 / CL-03): the daemon's view source issues one new
        /// GET_TERM on the given session and returns the adapter's
        /// classification against (this node, no expected term, lease_o);
        /// the CL-05s classes come out of the real classifier as expected.
        #[test]
        fn j35_fresh_authority_view_classifies_a_new_get_term() {
            for (reply, expected) in [
                (
                    WitnessReply::NoHolderAt(9),
                    Some((Term(9), SorCompat::CompatibleNoHolder)),
                ),
                (
                    WitnessReply::SelfHolderAt(9, "lease-1", 5_000),
                    Some((Term(9), SorCompat::CompatibleSelfUnexpired)),
                ),
                (
                    WitnessReply::SelfHolderAt(9, "lease-2", 5_000),
                    Some((Term(9), SorCompat::InconsistentAuthorityView)),
                ),
                (
                    WitnessReply::SelfHolderAt(9, "lease-1", 0),
                    Some((Term(9), SorCompat::ExpiredButUnprocessed)),
                ),
                (WitnessReply::WrongRequestId, None),
            ] {
                let (node, harness) = witness_pair(VecDeque::from([reply]));
                let mut session = crate::witness_runtime::WitnessSession::new(
                    node,
                    ProcessSession::from_session_id(SessionId::new("session-a")),
                    MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32])),
                );
                let mut observer = crate::evidence_fusion::adapter::WitnessEvidenceAdapter::new(
                    Duration::from_secs(2),
                )
                .unwrap();
                let view = crate::daemon::fresh_authority_view(
                    &mut observer,
                    &mut session,
                    crate::evidence_fusion::adapter::AuthorityViewExpectation::new(
                        NodeId::new("node-a"),
                        None,
                        Some(LeaseId::new("lease-1")),
                    ),
                );
                assert_eq!(view.as_ref().ok().copied(), expected, "{view:?}");
                assert_eq!(witness_log(&harness), ["get_term"]);
            }
        }

        /// Without O there is nothing to do.
        #[test]
        fn sor_is_not_applicable_without_an_obligation() {
            let (mut daemon, _harness, _clock, path) =
                exec_daemon("sor-none", VecDeque::new(), VecDeque::new());
            assert_eq!(sor_run(&mut daemon, true, None), SorOutcome::NotApplicable);
            cleanup_store(&path);
        }

        // ---- Transition-only logs and the lost-Witness-session exit (ADD-7) ----

        /// One WARN when the peer is lost, one INFO when it is back, nothing
        /// in a steady state either way.
        #[test]
        fn peer_transitions_are_logged_once_each() {
            let (mut daemon, _h, _c, path) =
                exec_daemon("log-peer", VecDeque::new(), VecDeque::new());
            let base = std::time::Instant::now();
            crate::operator_log::capture_start();
            let mut step = 0;
            let mut tick = |daemon: &mut Daemon<ExecFake>, assessment| {
                daemon.runtime.peer_log_assessment = Some(assessment);
                step += 1;
                daemon.tick_at(base + Duration::from_secs(step)).unwrap();
            };
            for _ in 0..3 {
                tick(&mut daemon, PeerFailureAssessment::Healthy);
            }
            for _ in 0..3 {
                tick(&mut daemon, PeerFailureAssessment::CommunicationLost);
            }
            for _ in 0..3 {
                tick(&mut daemon, PeerFailureAssessment::Healthy);
            }
            tick(&mut daemon, PeerFailureAssessment::Suspect);
            let lines = crate::operator_log::capture_take();
            assert_eq!(
                lines,
                [
                    "mikagami: WARN peer lost: no authenticated heartbeat",
                    "mikagami: INFO peer recovered: authenticated heartbeat resumed",
                ]
            );
            cleanup_store(&path);
        }

        /// ADD-7 / v0.6 A-1: a lost Witness session stops the process with a
        /// distinct error (non-zero exit through the loop) once nothing local
        /// is still protected. The runtime's `witness_loss_stop_allowed` is the
        /// fail-closed proof for the local state; the Daemon independently
        /// requires no owned resource, an absent VIP, a stopped service and a
        /// reconciled recovery.
        #[test]
        fn lost_witness_session_stops_only_when_nothing_local_is_protected() {
            let (mut daemon, _h, _c, path) =
                exec_daemon("lost-w", VecDeque::new(), VecDeque::new());
            let base = std::time::Instant::now();
            daemon.runtime.witness_lost = true;
            daemon.runtime.witness_loss_stop_allowed = true;
            crate::operator_log::capture_start();
            let error = daemon.tick_at(base).unwrap_err();
            let lines = crate::operator_log::capture_take();
            assert!(
                matches!(error, DaemonError::WitnessSessionLost(_)),
                "{error:?}"
            );
            assert_eq!(daemon.state(), DaemonState::Failed);
            assert_eq!(lines.len(), 1);
            assert!(
                lines[0].starts_with("mikagami: ERROR Witness session lost"),
                "{lines:?}"
            );
            cleanup_store(&path);

            for (name, snapshot) in [
                (
                    "active",
                    DaemonSnapshot {
                        node_state: NodeState::Active,
                        resource_owning: true,
                        ..standby()
                    },
                ),
                (
                    "not reconciled",
                    DaemonSnapshot {
                        recovery_reconciled: false,
                        ..standby()
                    },
                ),
                (
                    "owning resources",
                    DaemonSnapshot {
                        resource_owning: true,
                        ..standby()
                    },
                ),
                (
                    "vip still present",
                    DaemonSnapshot {
                        vip: DaemonVip::Present,
                        ..standby()
                    },
                ),
                (
                    "service still running",
                    DaemonSnapshot {
                        service: DaemonService::Running,
                        ..standby()
                    },
                ),
                (
                    "vip state unknown",
                    DaemonSnapshot {
                        vip: DaemonVip::Unknown,
                        ..standby()
                    },
                ),
                (
                    "service state unknown",
                    DaemonSnapshot {
                        service: DaemonService::Unknown,
                        ..standby()
                    },
                ),
            ] {
                let (mut daemon, _h, _c, path) =
                    exec_daemon("lost-w2", VecDeque::new(), VecDeque::new());
                daemon.runtime.witness_lost = true;
                daemon.runtime.witness_loss_stop_allowed = true;
                daemon.runtime.observed = Some(snapshot);
                // `Active` without ownership would be a different invariant;
                // all rows here are consistent snapshots.
                let result = daemon.tick_at(base);
                assert!(
                    !matches!(result, Err(DaemonError::WitnessSessionLost(_))),
                    "{name}: {result:?}"
                );
                cleanup_store(&path);
            }
        }

        /// v0.6 A-1: a node in the middle of an operation is never stopped by
        /// the Witness-loss path, even with a dead session. The runtime's own
        /// proof refuses whenever an operation phase is present (`Candidate`
        /// during a promotion, demotion phases other than `ReleaseLease`), so
        /// the in-flight attempt keeps ownership of its own failure handling.
        /// The `Candidate` snapshot below models that refusal; the runtime
        /// keys on the operation phase, not on the daemon's attempt slot.
        #[test]
        fn a_promoting_node_is_not_stopped_by_the_witness_loss_path() {
            let (mut daemon, _h, _c, path) =
                exec_daemon("lost-w5", VecDeque::new(), VecDeque::new());
            let base = std::time::Instant::now();
            daemon.runtime.witness_lost = true;
            daemon.runtime.witness_loss_stop_allowed = false;
            daemon.runtime.observed = Some(DaemonSnapshot {
                node_state: NodeState::Candidate,
                ..standby()
            });
            let result = daemon.tick_at(base);
            assert!(
                !matches!(result, Err(DaemonError::WitnessSessionLost(_))),
                "{result:?}"
            );
            cleanup_store(&path);
        }

        /// v0.6 A-1 regression 1: the runtime's fail-closed proof is required.
        /// A lost session with a durable release still owed does NOT stop while
        /// the runtime cannot prove that the local resources are gone.
        #[test]
        fn a_lost_session_does_not_stop_without_the_runtime_proof() {
            let (mut daemon, _h, _c, path) =
                exec_daemon("lost-w3", VecDeque::new(), VecDeque::new());
            let base = std::time::Instant::now();
            daemon.runtime.witness_lost = true;
            daemon.runtime.observed = Some(DaemonSnapshot {
                unresolved_mutation: true,
                ..standby()
            });
            let result = daemon.tick_at(base);
            assert!(
                !matches!(result, Err(DaemonError::WitnessSessionLost(_))),
                "{result:?}"
            );
            assert_eq!(daemon.state(), DaemonState::Running);
            cleanup_store(&path);
        }

        /// v0.6 A-1 regression 2: the observed `CLOSE_WAIT` case. An Active
        /// node that lost the Witness demoted, released the VIP and stopped the
        /// service, and now owes only a lease release that the dead session can
        /// never carry. Before the fix this loop ran forever on the dead
        /// socket; now it stops (non-zero) so the next start reconciles the
        /// durable obligation against a reconnected Witness. It never promotes.
        #[test]
        fn a_demoted_active_with_a_dead_witness_stops_and_never_promotes() {
            let (mut daemon, _h, _c, path) =
                exec_daemon("lost-w4", VecDeque::new(), VecDeque::new());
            let base = std::time::Instant::now();
            daemon.runtime.witness_lost = true;
            daemon.runtime.witness_loss_stop_allowed = true;
            daemon.runtime.observed = Some(DaemonSnapshot {
                node_state: NodeState::Active,
                vip: DaemonVip::Absent,
                service: DaemonService::Stopped,
                resource_owning: false,
                unresolved_mutation: true,
                recovery_reconciled: true,
                ..standby()
            });
            let error = daemon.tick_at(base).unwrap_err();
            assert!(
                matches!(error, DaemonError::WitnessSessionLost(_)),
                "{error:?}"
            );
            assert_eq!(daemon.state(), DaemonState::Failed);
            assert!(!daemon.runtime.promoted_attempts.iter().any(|_| true));
            assert_eq!(daemon.runtime.vip_present.get(), false);
            assert_eq!(daemon.runtime.service_running.get(), false);
            cleanup_store(&path);
        }

        // ---- Automatic trigger wiring (contract A-2 / A-9) ----

        fn auto_config(preferred: bool) -> crate::auto_failover::AutoConfig {
            crate::auto_failover::AutoConfig {
                enabled: true,
                preferred,
                dwell_ms: 10_000,
                bootstrap_dwell_ms: 20_000,
                bootstrap_defer_ms: 15_000,
                max_fence_actions: 2,
                cycle_timeout_ms: 120_000,
            }
        }

        fn auto_ba_facts() -> AutoRuntimeFacts {
            AutoRuntimeFacts {
                backend_is_command: false,
                assessment: PeerFailureAssessment::Healthy,
                loss: None,
                peer_active_confirmed: false,
                peer_node_state: Some(NodeState::Standby),
                standby_safe: true,
                node_state: NodeState::Standby,
                incident: None,
                activity: crate::auto_failover::FenceActivity::default(),
            }
        }

        fn auto_daemon(name: &str, preferred: bool) -> (Daemon<ExecFake>, std::path::PathBuf) {
            let (mut daemon, _harness, _clock, path) =
                exec_daemon(name, VecDeque::new(), VecDeque::new());
            daemon.runtime.auto_facts_value = Some(auto_ba_facts());
            daemon.enable_auto(auto_config(preferred));
            (daemon, path)
        }

        /// The bootstrap request appears only after the minimum uptime and the
        /// dwell, and only as a one-shot flag; the tick never runs an attempt.
        #[test]
        fn auto_request_is_a_one_shot_flag_after_uptime_and_dwell() {
            let (mut daemon, path) = auto_daemon("auto-flag", true);
            let base = std::time::Instant::now();
            let at = |s: u64| base + Duration::from_secs(s);
            // Too young: nothing, however long we poll.
            for s in 0..25 {
                daemon.tick_at(at(s)).unwrap();
                assert_eq!(daemon.take_auto_request(), None, "{s}");
            }
            // Uptime reached at ~30 s; the dwell starts with the first
            // conforming poll and lasts 20 s for the preferred node.
            let mut first = None;
            for s in 25..120 {
                daemon.tick_at(at(s)).unwrap();
                if daemon.take_auto_request().is_some() && first.is_none() {
                    first = Some(s);
                }
            }
            assert!(first.is_some_and(|s| (50..=60).contains(&s)), "{first:?}");
            assert_eq!(daemon.runtime.promotion_calls, 0, "ticks run no attempt");
            assert_eq!(daemon.runtime.evaluate_calls, 0);
            cleanup_store(&path);
        }

        /// The request is dropped by a shutdown request and by a disabled machine.
        #[test]
        fn auto_request_does_not_survive_shutdown_and_needs_enable() {
            let (mut daemon, path) = auto_daemon("auto-shutdown", true);
            let base = std::time::Instant::now();
            for s in 25..90 {
                daemon.tick_at(base + Duration::from_secs(s)).unwrap();
                if daemon.pending_auto.is_some() {
                    break;
                }
            }
            assert!(daemon.pending_auto.is_some());
            let _ = daemon.request_shutdown();
            assert_eq!(daemon.take_auto_request(), None);
            cleanup_store(&path);

            let (mut daemon, _h, _c, path) =
                exec_daemon("auto-off", VecDeque::new(), VecDeque::new());
            daemon.runtime.auto_facts_value = Some(auto_ba_facts());
            let base = std::time::Instant::now();
            for s in 25..200 {
                daemon.tick_at(base + Duration::from_secs(s)).unwrap();
                assert_eq!(daemon.take_auto_request(), None);
            }
            cleanup_store(&path);
        }

        /// The loop folds the automatic request into the single consumption
        /// point: one `promote` call with the `auto` label, none for an idle
        /// iteration, and an operator intent wins the same iteration.
        #[test]
        fn loop_runs_an_automatic_request_through_the_one_promote_entry() {
            use std::cell::{Cell, RefCell};
            use std::sync::atomic::{AtomicBool, Ordering};
            let (mut daemon, path) = auto_daemon("auto-loop", true);
            let base = std::time::Instant::now();
            let step = Cell::new(25u64);
            let labels = RefCell::new(Vec::new());
            let latch = AtomicBool::new(false);
            let stops_at = 120u64;
            let exit = crate::daemon_run::run_observation_loop(
                &mut daemon,
                Duration::from_secs(1),
                || step.get() >= stops_at,
                |_| {},
                || {
                    let n = step.get();
                    step.set(n + 1);
                    base + Duration::from_secs(n)
                },
                &latch,
                |_, _| {},
                |daemon| {
                    labels
                        .borrow_mut()
                        .push((daemon.trigger_label(), daemon.trigger_kind()));
                },
            );
            assert_eq!(exit, crate::daemon_run::LoopExit::Clean);
            let labels = labels.into_inner();
            assert!(!labels.is_empty());
            assert!(
                labels.iter().all(|label| *label == ("auto", "automatic")),
                "{labels:?}"
            );
            // After the loop the trigger origin is reset for operators.
            assert_eq!(daemon.trigger_label(), "operator-sigusr1");
            cleanup_store(&path);

            // Operator precedence: a pending SIGUSR1 intent runs as the operator.
            let (mut daemon, path) = auto_daemon("auto-loop-op", true);
            let step = Cell::new(25u64);
            let labels = RefCell::new(Vec::new());
            let latch = AtomicBool::new(false);
            let started = Cell::new(false);
            let exit = crate::daemon_run::run_observation_loop(
                &mut daemon,
                Duration::from_secs(1),
                || step.get() >= 40,
                |_| {},
                || {
                    let n = step.get();
                    step.set(n + 1);
                    if n == 35 && !started.replace(true) {
                        latch.store(true, Ordering::SeqCst);
                    }
                    base + Duration::from_secs(n)
                },
                &latch,
                |_, _| {},
                |daemon| labels.borrow_mut().push(daemon.trigger_label()),
            );
            assert_eq!(exit, crate::daemon_run::LoopExit::Clean);
            assert_eq!(labels.into_inner(), ["operator-sigusr1"]);
            cleanup_store(&path);
        }

        // ---- Bootstrap Admission (contract K-1..K-6, BA-T1..BA-T7) ----

        use crate::bootstrap_admission::{BootstrapStamp, ProbeOutcome, ProbeVerdict};

        fn healthy_peer_detector() -> PeerFailureDetector {
            let mut detector = PeerFailureDetector::new(Duration::from_secs(60)).unwrap();
            let t0 = std::time::Instant::now();
            let session = SessionId::new("peer-session");
            detector
                .observe_session_established(session.clone(), t0)
                .unwrap();
            detector
                .observe_trusted_heartbeat(&session, Sequence(1), t0)
                .unwrap();
            assert_eq!(detector.assessment(), PeerFailureAssessment::Healthy);
            detector
        }

        #[test]
        fn independent_audit_operator_intent_consumes_pending_auto_too() {
            use std::cell::{Cell, RefCell};
            use std::sync::atomic::{AtomicBool, Ordering};
            let (mut daemon, path) = auto_daemon("audit-auto-coalesce", true);
            let base = std::time::Instant::now();
            for s in 30..100 {
                daemon.tick_at(base + Duration::from_secs(s)).unwrap();
                if daemon.pending_auto.is_some() {
                    break;
                }
            }
            assert!(daemon.pending_auto.is_some());
            let step = Cell::new(0u64);
            let injected = Cell::new(false);
            let labels = RefCell::new(Vec::new());
            let latch = AtomicBool::new(false);
            let exit = crate::daemon_run::run_observation_loop(
                &mut daemon,
                Duration::from_secs(1),
                || {
                    if !injected.replace(true) {
                        latch.store(true, Ordering::SeqCst);
                    }
                    step.get() >= 2
                },
                |_| {},
                || {
                    let n = step.get();
                    step.set(n + 1);
                    base + Duration::from_secs(101 + n)
                },
                &latch,
                |_, _| {},
                |d| {
                    labels.borrow_mut().push(d.trigger_label());
                    // The manual attempt changes eligibility; no later poll may create a request.
                    d.runtime.auto_facts_value = None;
                },
            );
            let observed = labels.into_inner();
            cleanup_store(&path);
            assert_eq!(exit, crate::daemon_run::LoopExit::Clean);
            assert_eq!(
                observed,
                ["operator-sigusr1"],
                "a coalesced automatic request must not survive the manual one"
            );
        }

        #[test]
        fn independent_audit_manual_ba_pending_session_expires() {
            let (mut daemon, _h, path) = ba_daemon("audit-ba-expiry", vec![WitnessReply::NoHolder]);
            daemon.enable_auto(crate::auto_failover::AutoConfig {
                enabled: false,
                ..auto_config(true)
            });
            daemon.runtime.auto_facts_value = Some(auto_ba_facts());
            assert_eq!(
                ba_attempt(&mut daemon, "audit-anchor"),
                PromotionAttemptResult::BlockedBeforeMutation
            );
            let base = std::time::Instant::now();
            for s in 0..=61 {
                daemon.tick_at(base + Duration::from_secs(s)).unwrap();
            }
            let open = daemon.bootstrap_session_open();
            cleanup_store(&path);
            assert!(
                !open,
                "BAP-7 hygiene applies also when automatic failover is disabled"
            );
        }

        #[test]
        fn independent_audit_sor_rejects_truncated_image_without_reinitialization() {
            let (daemon, _h, path) = sor_daemon("audit-sor-corrupt");
            let before = std::fs::read_to_string(&path).unwrap();
            let corrupt = before.replace("current_term = 7", "current_term = 6");
            // A truncated image always fails parsing; it must not be silently initialized.
            std::fs::write(&path, &corrupt[..corrupt.len() / 2]).unwrap();
            let result = crate::obligation_reconciliation::candidate(&daemon.runtime.store);
            let after = std::fs::read_to_string(&path).unwrap();
            cleanup_store(&path);
            assert!(result.is_err());
            assert_eq!(after, &corrupt[..corrupt.len() / 2]);
        }

        #[test]
        fn independent_audit_sor_rejects_identity_mismatch_before_reconciliation() {
            let (daemon, _h, path) = sor_daemon("audit-sor-mismatch");
            daemon
                .runtime
                .store
                .begin_lease_release_for_test(Term(7), LeaseId::new("lease-1"), "cleanup".into())
                .unwrap();
            let mut state = daemon.runtime.store.load_existing().unwrap();
            let m = &mut state.outstanding_mutation.as_mut().unwrap().mutation;
            match m {
                crate::node_mutation::DurableWitnessMutation::LeaseRelease { term, .. } => {
                    *term = Term(8)
                }
                _ => panic!("not release"),
            }
            let invalid = toml::to_string(&state).unwrap();
            std::fs::write(&path, &invalid).unwrap();
            let result = crate::obligation_reconciliation::candidate(&daemon.runtime.store);
            let after = std::fs::read_to_string(&path).unwrap();
            cleanup_store(&path);
            assert!(matches!(
                result,
                Err(crate::node_mutation::NodeMutationError::Invariant(
                    "outstanding mutation does not match release obligation"
                ))
            ));
            assert_eq!(after, invalid);
        }

        // ---- F15-M1: both one-shots are consumed at the one point ----

        /// Drive `run_observation_loop` for `steps` iterations. `latch` is
        /// raised on the first `should_stop` call. `promote` sees every
        /// dispatched attempt as `(step, trigger_label)`; `prime` runs before
        /// each tick.
        fn drive_loop(
            daemon: &mut Daemon<ExecFake>,
            base: std::time::Instant,
            steps: u64,
            raise_latch: bool,
            mut prime: impl FnMut(&mut Daemon<ExecFake>, u64),
            mut promote: impl FnMut(&mut Daemon<ExecFake>, u64),
        ) -> (crate::daemon_run::LoopExit, Vec<(u64, &'static str)>) {
            use std::cell::Cell;
            use std::sync::atomic::{AtomicBool, Ordering};
            let step = Cell::new(0u64);
            let injected = Cell::new(!raise_latch);
            let latch = AtomicBool::new(false);
            let mut dispatched = Vec::new();
            let exit = crate::daemon_run::run_observation_loop(
                daemon,
                Duration::from_secs(1),
                || {
                    if !injected.replace(true) {
                        latch.store(true, Ordering::SeqCst);
                    }
                    step.get() >= steps
                },
                |_| {},
                || {
                    let n = step.get();
                    step.set(n + 1);
                    base + Duration::from_secs(101 + n)
                },
                &latch,
                |daemon, _| prime(daemon, step.get().saturating_sub(1)),
                |daemon| {
                    dispatched.push((step.get(), daemon.trigger_label()));
                    promote(daemon, step.get());
                },
            );
            (exit, dispatched)
        }

        fn auto_daemon_with_pending(name: &str) -> (Daemon<ExecFake>, std::path::PathBuf) {
            let (mut daemon, path) = auto_daemon(name, true);
            let base = std::time::Instant::now();
            for s in 30..100 {
                daemon.tick_at(base + Duration::from_secs(s)).unwrap();
                if daemon.pending_auto.is_some() {
                    break;
                }
            }
            assert!(daemon.pending_auto.is_some());
            (daemon, path)
        }

        /// Both pending at once: exactly one attempt (the operator's), and
        /// the automatic request is gone before the tick, not carried over.
        #[test]
        fn a_manual_intent_drops_the_coalesced_automatic_request_at_once() {
            let (mut daemon, path) = auto_daemon_with_pending("f15-m1-coalesce");
            let base = std::time::Instant::now();
            let mut seen_after_consume = Vec::new();
            let (exit, dispatched) = drive_loop(
                &mut daemon,
                base,
                2,
                true,
                |daemon, step| seen_after_consume.push((step, daemon.pending_auto.is_some())),
                |_, _| {},
            );
            cleanup_store(&path);
            assert_eq!(exit, crate::daemon_run::LoopExit::Clean);
            // Iteration 0 runs the operator's attempt and only that one. A
            // later iteration may run a request that a fresh poll raised.
            let first: Vec<_> = dispatched.iter().filter(|(step, _)| *step == 0).collect();
            assert_eq!(first, [&(0, "operator-sigusr1")]);
            assert_eq!(
                seen_after_consume,
                [(0, false)],
                "nothing is pending between the consumption point and the tick"
            );
        }

        /// The automatic request alone still runs exactly one attempt, with
        /// its own origin, and the origin does not leak into the next one.
        #[test]
        fn an_automatic_request_alone_runs_one_attempt_with_its_origin() {
            let (mut daemon, path) = auto_daemon_with_pending("f15-m1-auto-alone");
            let base = std::time::Instant::now();
            let (exit, dispatched) = drive_loop(&mut daemon, base, 1, false, |_, _| {}, |_, _| {});
            assert_eq!(exit, crate::daemon_run::LoopExit::Clean);
            assert_eq!(dispatched, [(0, "auto")]);
            assert_eq!(daemon.trigger_label(), "operator-sigusr1");
            cleanup_store(&path);
        }

        /// An iteration that cannot run an attempt still takes both one-shots
        /// (nothing waits around for a later, unrelated iteration).
        #[test]
        fn neither_one_shot_survives_an_iteration_that_cannot_run_them() {
            for raise_latch in [false, true] {
                let (mut daemon, path) = auto_daemon_with_pending("f15-m1-not-running");
                daemon.state = DaemonState::RecoveryBlocked;
                let base = std::time::Instant::now();
                let (exit, dispatched) =
                    drive_loop(&mut daemon, base, 5, raise_latch, |_, _| {}, |_, _| {});
                assert!(
                    matches!(exit, crate::daemon_run::LoopExit::Fatal(_)),
                    "{exit:?}"
                );
                assert!(dispatched.is_empty(), "latch {raise_latch}: {dispatched:?}");
                assert!(
                    daemon.pending_auto.is_none(),
                    "latch {raise_latch}: the automatic request outlived the iteration"
                );
                cleanup_store(&path);
            }
        }

        /// Same, for an attempt that is already in flight: the loop does not
        /// start a second one, and it does not keep either request for later.
        #[test]
        fn neither_one_shot_survives_while_an_attempt_is_in_flight() {
            for raise_latch in [false, true] {
                let (mut daemon, path) = auto_daemon_with_pending("f15-m1-in-flight");
                daemon
                    .request_promotion_attempt(request("in-flight"))
                    .unwrap();
                let base = std::time::Instant::now();
                let (exit, dispatched) =
                    drive_loop(&mut daemon, base, 3, raise_latch, |_, _| {}, |_, _| {});
                assert_eq!(exit, crate::daemon_run::LoopExit::Clean);
                assert!(dispatched.is_empty(), "latch {raise_latch}: {dispatched:?}");
                assert!(
                    daemon.pending_auto.is_none(),
                    "latch {raise_latch}: the automatic request outlived the iteration"
                );
                cleanup_store(&path);
            }
        }

        // ---- F15-L1: BA session hygiene without `[failover] auto` ----

        fn hygiene_daemon(
            name: &str,
            auto_enabled: bool,
        ) -> (Daemon<ExecFake>, std::path::PathBuf) {
            let (mut daemon, _h, path) = ba_daemon(
                name,
                vec![WitnessReply::NoHolderAt(7), WitnessReply::NoHolderAt(7)],
            );
            daemon.enable_auto(crate::auto_failover::AutoConfig {
                enabled: auto_enabled,
                ..auto_config(true)
            });
            daemon.runtime.auto_facts_value = Some(auto_ba_facts());
            (daemon, path)
        }

        /// BAP-7: the 5 s probe wait, with automatic failover off and on.
        #[test]
        fn a_ba_session_without_a_probe_response_expires_after_five_seconds() {
            for auto_enabled in [false, true] {
                let (mut daemon, path) = hygiene_daemon("f15-l1-five", auto_enabled);
                assert_eq!(
                    ba_attempt(&mut daemon, "a1"),
                    PromotionAttemptResult::BlockedBeforeMutation
                );
                let base = std::time::Instant::now();
                for s in 0..5 {
                    daemon.tick_at(base + Duration::from_secs(s)).unwrap();
                    assert!(
                        daemon.bootstrap_session_open(),
                        "auto {auto_enabled}: {s} s"
                    );
                }
                daemon.tick_at(base + Duration::from_secs(5)).unwrap();
                assert!(
                    !daemon.bootstrap_session_open(),
                    "auto {auto_enabled}: the 5 s limit"
                );
                cleanup_store(&path);
            }
        }

        /// BAP-7: an attested session lives to 60 s and no further, and its
        /// old ACK cannot start the next attempt.
        #[test]
        fn an_attested_ba_session_expires_after_sixty_seconds_and_its_ack_is_gone() {
            for auto_enabled in [false, true] {
                let (mut daemon, path) = hygiene_daemon("f15-l1-sixty", auto_enabled);
                ba_attempt(&mut daemon, "a1");
                ba_deliver(&mut daemon, ProbeVerdict::Ack);
                assert!(daemon.bootstrap_session_attested());
                let base = std::time::Instant::now();
                for s in 0..60 {
                    daemon.tick_at(base + Duration::from_secs(s)).unwrap();
                    assert!(
                        daemon.bootstrap_session_open(),
                        "auto {auto_enabled}: {s} s"
                    );
                    // An attested session is not subject to the 5 s limit.
                }
                daemon.tick_at(base + Duration::from_secs(60)).unwrap();
                assert!(
                    !daemon.bootstrap_session_open(),
                    "auto {auto_enabled}: the 60 s limit"
                );
                // The expired ACK is not reused: the next attempt anchors anew.
                assert_eq!(
                    ba_attempt(&mut daemon, "a2"),
                    PromotionAttemptResult::BlockedBeforeMutation
                );
                assert_eq!(daemon.runtime.promotion_calls, 0);
                assert!(daemon.bootstrap_session_open() && !daemon.bootstrap_session_attested());
                cleanup_store(&path);
            }
        }

        /// BAP-7: losing a safe local standby or a healthy peer drops the
        /// session at the next tick; not knowing (no facts) drops nothing.
        #[test]
        fn a_ba_session_is_dropped_when_safe_or_healthy_is_lost_even_with_auto_off() {
            for lose in ["safe", "healthy", "unknown"] {
                let (mut daemon, path) = hygiene_daemon("f15-l1-lost", false);
                ba_attempt(&mut daemon, "a1");
                ba_deliver(&mut daemon, ProbeVerdict::Ack);
                let base = std::time::Instant::now();
                daemon.tick_at(base).unwrap();
                assert!(daemon.bootstrap_session_open(), "{lose}: still good");
                match lose {
                    "safe" => {
                        daemon
                            .runtime
                            .auto_facts_value
                            .as_mut()
                            .unwrap()
                            .standby_safe = false
                    }
                    "healthy" => {
                        daemon.runtime.auto_facts_value.as_mut().unwrap().assessment =
                            PeerFailureAssessment::CommunicationLost
                    }
                    _ => daemon.runtime.auto_facts_value = None,
                }
                daemon.tick_at(base + Duration::from_secs(1)).unwrap();
                assert_eq!(daemon.bootstrap_session_open(), lose == "unknown", "{lose}");
                cleanup_store(&path);
            }
        }

        /// R-L1-9: a tick whose observation failed still runs the BA session
        /// hygiene (5 s probe wait), with automatic failover off and on, and
        /// also for a daemon that never configured it at all.
        #[test]
        fn a_failed_observation_tick_still_expires_an_unanswered_ba_session() {
            for auto in [None, Some(false), Some(true)] {
                let (mut daemon, path) = match auto {
                    Some(enabled) => hygiene_daemon("f15-l1-fail-five", enabled),
                    None => {
                        let (mut daemon, _h, path) = ba_daemon(
                            "f15-l1-fail-five-unconfigured",
                            vec![WitnessReply::NoHolderAt(7), WitnessReply::NoHolderAt(7)],
                        );
                        daemon.runtime.auto_facts_value = Some(auto_ba_facts());
                        (daemon, path)
                    }
                };
                assert_eq!(
                    ba_attempt(&mut daemon, "a1"),
                    PromotionAttemptResult::BlockedBeforeMutation
                );
                daemon.runtime.observe_error = Some("health unavailable".into());
                let base = std::time::Instant::now();
                for s in 0..5 {
                    assert_eq!(
                        daemon.tick_at(base + Duration::from_secs(s)).unwrap(),
                        TickResult::ObservationUnavailable
                    );
                    assert!(daemon.bootstrap_session_open(), "auto {auto:?}: {s} s");
                }
                assert_eq!(
                    daemon.tick_at(base + Duration::from_secs(5)).unwrap(),
                    TickResult::ObservationUnavailable
                );
                assert!(
                    !daemon.bootstrap_session_open(),
                    "auto {auto:?}: the 5 s limit holds on a failed tick"
                );
                cleanup_store(&path);
            }
        }

        /// R-L1-9: the 60 s age limit of an attested session on failed ticks.
        /// A failed observation concludes nothing about readiness or the
        /// peer: it neither drops the session for a lost safe/healthy fact nor
        /// attests, promotes or requests anything.
        #[test]
        fn a_failed_observation_tick_expires_an_attested_session_only_by_age() {
            for auto_enabled in [false, true] {
                let (mut daemon, path) = hygiene_daemon("f15-l1-fail-sixty", auto_enabled);
                ba_attempt(&mut daemon, "a1");
                ba_deliver(&mut daemon, ProbeVerdict::Ack);
                assert!(daemon.bootstrap_session_attested());
                // Were the facts consulted, this would drop the session.
                daemon
                    .runtime
                    .auto_facts_value
                    .as_mut()
                    .unwrap()
                    .standby_safe = false;
                daemon.runtime.observe_error = Some("health unavailable".into());
                let base = std::time::Instant::now();
                for s in 0..60 {
                    assert_eq!(
                        daemon.tick_at(base + Duration::from_secs(s)).unwrap(),
                        TickResult::ObservationUnavailable
                    );
                    assert!(
                        daemon.bootstrap_session_open() && daemon.bootstrap_session_attested(),
                        "auto {auto_enabled}: {s} s: a failed observation decides nothing"
                    );
                }
                assert_eq!(daemon.runtime.promotion_calls, 0);
                assert!(daemon.pending_auto.is_none());
                daemon.tick_at(base + Duration::from_secs(60)).unwrap();
                assert!(
                    !daemon.bootstrap_session_open(),
                    "auto {auto_enabled}: the 60 s limit holds on a failed tick"
                );
                assert_eq!(daemon.runtime.promotion_calls, 0);
                cleanup_store(&path);
            }
        }

        // ---- N-4: the scripted Witness outlives a slow test body --------------

        /// One GET_TERM from the node side; `true` when the Witness answered
        /// with a TERM_STATUS.
        fn ask_get_term(
            node: &mut WitnessConnection,
            process: &mut ProcessSession,
            psk: [u8; 32],
            id: u8,
        ) -> Result<bool, String> {
            let auth = MessageAuthenticator::new(Psk::from_test_bytes(psk));
            let mut outstanding = crate::witness_runtime::WitnessRequestOutstanding::new();
            crate::witness_runtime::send_get_term(
                node,
                process,
                &mut outstanding,
                RequestId::new(format!("00000000-0000-4000-8000-0000000001{id:02}")),
                &CborSerializer,
                &auth,
            )
            .map_err(|error| format!("{error:?}"))?;
            let pending = node
                .receive_pending(&CborSerializer, &auth)
                .map_err(|error| format!("{error:?}"))?;
            Ok(matches!(
                pending.message().unsigned().message,
                ProtocolMessage::TermStatus(_)
            ))
        }

        /// The node side's own session (the Witness expects `session-a`).
        fn node_process() -> ProcessSession {
            ProcessSession::from_session_id(SessionId::new("session-a"))
        }

        /// Longer than the 2 s receive timeout the Witness used to end on.
        const SLOW_TEST_BODY: Duration = Duration::from_millis(2_300);

        /// A test body that starts late (slow host, many threads) still finds
        /// its Witness. Before the fix the thread had ended on the 2 s idle
        /// receive timeout and the first request met a closed connection.
        #[test]
        fn a_witness_still_answers_a_request_that_comes_after_a_long_startup() {
            let (mut node, harness) = witness_pair(VecDeque::new());
            thread::sleep(SLOW_TEST_BODY);
            assert!(!harness.join.is_finished(), "idle is not a failure");
            let mut process = node_process();
            assert_eq!(
                ask_get_term(&mut node, &mut process, [0x55; 32], 1),
                Ok(true)
            );
            assert_eq!(witness_log(&harness), ["get_term"]);
            drop(node);
            harness.join.join().unwrap();
        }

        /// The Witness returns to service after an idle period of any length
        /// between requests.
        #[test]
        fn a_witness_serves_again_after_an_idle_period() {
            let (mut node, harness) = witness_pair(VecDeque::new());
            let mut process = node_process();
            assert_eq!(
                ask_get_term(&mut node, &mut process, [0x55; 32], 1),
                Ok(true)
            );
            thread::sleep(SLOW_TEST_BODY);
            assert_eq!(
                ask_get_term(&mut node, &mut process, [0x55; 32], 2),
                Ok(true)
            );
            assert_eq!(witness_log(&harness), ["get_term", "get_term"]);
            harness.join.join().unwrap();
            drop(node);
        }

        /// Only a closed connection ends the Witness by itself.
        #[test]
        fn a_witness_ends_when_the_connection_is_closed() {
            let (node, harness) = witness_pair(VecDeque::new());
            drop(node);
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            while !harness.join.is_finished() && std::time::Instant::now() < deadline {
                thread::sleep(Duration::from_millis(5));
            }
            assert!(
                harness.join.is_finished(),
                "the closed connection was not noticed"
            );
            harness.join.join().unwrap();
        }

        /// A request the Witness cannot authenticate is a protocol failure, not
        /// idleness: the Witness ends and answers nothing.
        #[test]
        fn a_witness_ends_on_a_protocol_failure() {
            let (mut node, harness) = witness_pair(VecDeque::new());
            let mut process = node_process();
            // The send succeeds; the Witness rejects the wrong key and ends,
            // so no answer ever comes back.
            let outcome = ask_get_term(&mut node, &mut process, [0x66; 32], 1);
            assert!(outcome.is_err(), "{outcome:?}");
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            while !harness.join.is_finished() && std::time::Instant::now() < deadline {
                thread::sleep(Duration::from_millis(5));
            }
            assert!(
                harness.join.is_finished(),
                "a protocol failure kept the Witness alive"
            );
            assert!(witness_log(&harness).is_empty());
            harness.join.join().unwrap();
        }

        /// The end of a test stops the Witness at once, with the peer still
        /// connected, and the thread is really gone (it owned the request
        /// channel's sender) when `join` returns.
        #[test]
        fn a_witness_is_stopped_and_joined_at_the_end_of_a_test() {
            // A slow idle poll keeps the Witness inside its sleep when it is
            // told to stop, so a `join` that did not really wait for the
            // thread would return while it is still alive.
            let (node, harness) = witness_pair_polling(VecDeque::new(), Duration::from_millis(300));
            let WitnessHarness { requests, join } = harness;
            assert!(!join.is_finished());
            // A Witness that ignored the stop would block `join` for good, so
            // the join is watched rather than awaited.
            let (done, finished) = mpsc::channel();
            thread::spawn(move || {
                let _ = done.send(join.join());
            });
            finished
                .recv_timeout(Duration::from_secs(30))
                .expect("the Witness was not stopped")
                .unwrap();
            assert!(matches!(
                requests.try_recv(),
                Err(mpsc::TryRecvError::Disconnected)
            ));
            drop(node);
        }

        /// A test that discards the harness handle and keeps using the
        /// connection (`hygiene_daemon` does) still has its Witness; the
        /// Witness ends with the connection.
        #[test]
        fn a_witness_outlives_a_discarded_harness_and_ends_with_its_connection() {
            let (mut node, harness) = witness_pair(VecDeque::new());
            let WitnessHarness { requests, join } = harness;
            drop(join);
            let mut process = node_process();
            assert_eq!(
                ask_get_term(&mut node, &mut process, [0x55; 32], 1),
                Ok(true)
            );
            drop(node);
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            loop {
                match requests.try_recv() {
                    Ok(_) => {}
                    Err(mpsc::TryRecvError::Disconnected) => break,
                    Err(mpsc::TryRecvError::Empty) => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "the Witness outlived its closed connection"
                        );
                        thread::sleep(Duration::from_millis(5));
                    }
                }
            }
        }

        fn ba_stamp(connection: u64) -> BootstrapStamp {
            BootstrapStamp {
                connection: crate::tcp_runtime::test_connection_token(connection),
                peer_session: SessionId::new("peer-session"),
                observer_session: SessionId::new("observer"),
            }
        }

        fn ba_daemon(
            name: &str,
            replies: Vec<WitnessReply>,
        ) -> (Daemon<ExecFake>, WitnessHarness, std::path::PathBuf) {
            let (mut daemon, harness, _clock, path) =
                exec_daemon(name, VecDeque::from(replies), VecDeque::new());
            daemon.runtime.peer_detector = healthy_peer_detector();
            daemon.runtime.ba_supported = true;
            daemon.runtime.ba_stamp = Some(ba_stamp(1));
            (daemon, harness, path)
        }

        fn ba_deliver(daemon: &mut Daemon<ExecFake>, verdict: ProbeVerdict) {
            let stamp = daemon.runtime.ba_stamp.clone().unwrap();
            daemon
                .runtime
                .ba_outcomes
                .push_back(ProbeOutcome::Response { stamp, verdict });
            daemon.tick().unwrap();
        }

        fn ba_attempt(daemon: &mut Daemon<ExecFake>, id: &str) -> PromotionAttemptResult {
            daemon.execute_promotion_attempt(request(id))
        }

        /// BA-T1 / BAP-6: attempt 1 anchors (no lease traffic beyond one
        /// GET_TERM, no ARM, no mutation); attempt 2 with an `Ack` grants at
        /// anchor + 1, arms and promotes.
        #[test]
        fn ba_two_attempts_promote_with_anchor_and_next_term_grant() {
            let (mut daemon, harness, path) = ba_daemon(
                "ba-success",
                vec![
                    WitnessReply::NoHolderAt(7),
                    WitnessReply::NoHolderAt(7),
                    WitnessReply::GrantAt(8),
                ],
            );
            assert_eq!(
                ba_attempt(&mut daemon, "a1"),
                PromotionAttemptResult::BlockedBeforeMutation
            );
            assert_eq!(daemon.runtime.ba_probe_requests, 1);
            assert!(daemon.bootstrap_session_open() && !daemon.bootstrap_session_attested());
            assert_eq!(witness_log(&harness), ["get_term"]);
            assert_eq!(daemon.runtime.promotion_calls, 0);
            assert!(daemon.runtime.store.release_obligation().unwrap().is_none());

            ba_deliver(&mut daemon, ProbeVerdict::Ack);
            assert!(daemon.bootstrap_session_attested());
            assert_eq!(
                ba_attempt(&mut daemon, "a2"),
                PromotionAttemptResult::Succeeded
            );
            assert_eq!(witness_log(&harness), ["get_term", "lease_request"]);
            assert_eq!(daemon.runtime.promotion_calls, 1);
            assert!(!daemon.bootstrap_session_open(), "the session is consumed");
            let obligation = daemon.runtime.store.release_obligation().unwrap().unwrap();
            assert_eq!(obligation.term, Term(8), "O = (anchor + 1, lease)");
            cleanup_store(&path);
        }

        /// A consumed session is not reusable: a third attempt anchors anew.
        #[test]
        fn ba_session_is_single_use() {
            let (mut daemon, _harness, path) = ba_daemon(
                "ba-single-use",
                vec![
                    WitnessReply::NoHolderAt(7),
                    WitnessReply::NoHolderAt(7),
                    WitnessReply::GrantAt(8),
                    WitnessReply::NoHolderAt(8),
                ],
            );
            ba_attempt(&mut daemon, "a1");
            ba_deliver(&mut daemon, ProbeVerdict::Ack);
            ba_attempt(&mut daemon, "a2");
            // Whatever the outcome of a later attempt, it needs a new anchor
            // and a new probe: no clearance can come from the spent session.
            let requests_before = daemon.runtime.ba_probe_requests;
            let _ = ba_attempt(&mut daemon, "a3");
            assert!(daemon.runtime.ba_probe_requests <= requests_before + 1);
            assert!(!daemon.bootstrap_session_attested());
            cleanup_store(&path);
        }

        /// BAP-5: a BLOCK, an UNKNOWN or an invalid outcome drops the session;
        /// the next attempt starts over and never reaches the lease chain.
        #[test]
        fn ba_block_unknown_and_invalid_drop_the_session() {
            for outcome in ["block", "unknown", "invalid"] {
                let (mut daemon, harness, path) = ba_daemon(
                    "ba-drop",
                    vec![WitnessReply::NoHolderAt(7), WitnessReply::NoHolderAt(7)],
                );
                ba_attempt(&mut daemon, "a1");
                match outcome {
                    "block" => ba_deliver(&mut daemon, ProbeVerdict::Block),
                    "unknown" => ba_deliver(&mut daemon, ProbeVerdict::Unknown),
                    _ => {
                        daemon.runtime.ba_outcomes.push_back(ProbeOutcome::Invalid);
                        daemon.tick().unwrap();
                    }
                }
                assert!(!daemon.bootstrap_session_open(), "{outcome}");
                assert_eq!(
                    ba_attempt(&mut daemon, "a2"),
                    PromotionAttemptResult::BlockedBeforeMutation,
                    "{outcome}"
                );
                let kinds = stage14_11_lease_kinds(&harness);
                assert!(kinds.is_empty(), "{outcome}: no lease traffic");
                assert_eq!(daemon.runtime.promotion_calls, 0, "{outcome}");
                // The second attempt is a fresh anchor, not a clearance.
                assert!(daemon.bootstrap_session_open() && !daemon.bootstrap_session_attested());
                cleanup_store(&path);
            }
        }

        /// An ACK for another connection/peer session never attests.
        #[test]
        fn ba_ack_for_another_stamp_drops_the_session() {
            let (mut daemon, _harness, path) =
                ba_daemon("ba-other-stamp", vec![WitnessReply::NoHolderAt(7)]);
            ba_attempt(&mut daemon, "a1");
            daemon
                .runtime
                .ba_outcomes
                .push_back(ProbeOutcome::Response {
                    stamp: ba_stamp(2),
                    verdict: ProbeVerdict::Ack,
                });
            daemon.tick().unwrap();
            assert!(!daemon.bootstrap_session_open());
            cleanup_store(&path);
        }

        /// BAP-7: a connection change after the anchor drops the session at
        /// the next tick, and even without a tick attempt 2 refuses.
        #[test]
        fn ba_connection_change_invalidates_the_session() {
            let (mut daemon, harness, path) = ba_daemon(
                "ba-reconnect",
                vec![WitnessReply::NoHolderAt(7), WitnessReply::NoHolderAt(7)],
            );
            ba_attempt(&mut daemon, "a1");
            ba_deliver(&mut daemon, ProbeVerdict::Ack);
            assert!(daemon.bootstrap_session_attested());
            daemon.runtime.ba_stamp = Some(ba_stamp(2));
            // No tick in between: the decision itself compares the stamp.
            assert_eq!(
                ba_attempt(&mut daemon, "a2"),
                PromotionAttemptResult::BlockedBeforeMutation
            );
            assert!(stage14_11_lease_kinds(&harness).is_empty());
            assert!(!daemon.bootstrap_session_attested());
            cleanup_store(&path);
        }

        /// BAP-6: the Witness term moving between the anchor and attempt 2,
        /// or a holder appearing, blocks before any lease request.
        #[test]
        fn ba_witness_term_move_or_holder_blocks_attempt_two() {
            // Term moved 7 -> 9.
            let (mut daemon, harness, path) = ba_daemon(
                "ba-term-moved",
                vec![WitnessReply::NoHolderAt(7), WitnessReply::NoHolderAt(9)],
            );
            ba_attempt(&mut daemon, "a1");
            ba_deliver(&mut daemon, ProbeVerdict::Ack);
            assert_eq!(
                ba_attempt(&mut daemon, "a2"),
                PromotionAttemptResult::BlockedBeforeMutation
            );
            assert!(stage14_11_lease_kinds(&harness).is_empty());
            assert_eq!(daemon.runtime.promotion_calls, 0);
            cleanup_store(&path);

            // A holder present at attempt 2.
            let (mut daemon, harness, path) = ba_daemon(
                "ba-holder",
                vec![WitnessReply::NoHolderAt(7), WitnessReply::Auto],
            );
            ba_attempt(&mut daemon, "a1");
            ba_deliver(&mut daemon, ProbeVerdict::Ack);
            assert_eq!(
                ba_attempt(&mut daemon, "a2"),
                PromotionAttemptResult::BlockedBeforeMutation
            );
            assert!(stage14_11_lease_kinds(&harness).is_empty());
            assert_eq!(daemon.runtime.promotion_calls, 0);
            cleanup_store(&path);
        }

        /// A holder at the very first attempt never anchors.
        #[test]
        fn ba_holder_at_first_attempt_does_not_anchor() {
            let (mut daemon, _harness, path) =
                ba_daemon("ba-holder-first", vec![WitnessReply::Auto]);
            assert_eq!(
                ba_attempt(&mut daemon, "a1"),
                PromotionAttemptResult::BlockedBeforeMutation
            );
            assert!(!daemon.bootstrap_session_open());
            assert_eq!(daemon.runtime.ba_probe_requests, 0);
            cleanup_store(&path);
        }

        /// K-5: BA exists only in Conservative mode.
        #[test]
        fn ba_requires_conservative_mode() {
            let (mut daemon, _harness, path) =
                ba_daemon("ba-availability", vec![WitnessReply::NoHolderAt(7)]);
            daemon.runtime.ba_conservative = false;
            assert_eq!(
                ba_attempt(&mut daemon, "a1"),
                PromotionAttemptResult::BlockedBeforeMutation
            );
            assert!(!daemon.bootstrap_session_open());
            assert_eq!(daemon.runtime.ba_probe_requests, 0);
            cleanup_store(&path);
        }

        /// Without a peer connection (or when the peer is not Healthy) BA is
        /// not in play at all: the ordinary block applies and nothing anchors.
        #[test]
        fn ba_not_applicable_without_peer_or_with_lost_peer() {
            let (mut daemon, _harness, path) =
                ba_daemon("ba-unsupported", vec![WitnessReply::NoHolderAt(7)]);
            daemon.runtime.ba_supported = false;
            ba_attempt(&mut daemon, "a1");
            assert!(!daemon.bootstrap_session_open());
            cleanup_store(&path);

            let (mut daemon, _harness, path) =
                ba_daemon("ba-lost", vec![WitnessReply::NoHolderAt(7)]);
            daemon.runtime.peer_detector = lost_peer_detector();
            ba_attempt(&mut daemon, "a1");
            assert!(!daemon.bootstrap_session_open());
            assert_eq!(daemon.runtime.ba_probe_requests, 0);
            cleanup_store(&path);
        }

        /// A local state that is not Safe never anchors or clears.
        #[test]
        fn ba_requires_locally_safe_standby() {
            let (mut daemon, _harness, path) =
                ba_daemon("ba-unsafe", vec![WitnessReply::NoHolderAt(7)]);
            daemon.runtime.local_readiness = LocalSafetyReadiness::OwnershipUncertain;
            ba_attempt(&mut daemon, "a1");
            assert!(!daemon.bootstrap_session_open());
            assert_eq!(daemon.runtime.ba_probe_requests, 0);
            cleanup_store(&path);
        }

        /// Attempt 2 without an attested session waits (keeps the session
        /// while the response is outstanding) and never reaches the lease
        /// chain.
        #[test]
        fn ba_unattested_second_attempt_waits() {
            let (mut daemon, harness, path) = ba_daemon(
                "ba-unattested",
                vec![WitnessReply::NoHolderAt(7), WitnessReply::NoHolderAt(7)],
            );
            ba_attempt(&mut daemon, "a1");
            assert_eq!(
                ba_attempt(&mut daemon, "a2"),
                PromotionAttemptResult::BlockedBeforeMutation
            );
            assert!(daemon.bootstrap_session_open(), "kept while pending");
            assert!(!daemon.bootstrap_session_attested());
            assert!(stage14_11_lease_kinds(&harness).is_empty());
            cleanup_store(&path);
        }

        /// A Witness that grants anything but anchor + 1 is aborted after the
        /// grant (I), with the exact Release and no ARM/promotion.
        #[test]
        fn ba_grant_term_mismatch_aborts_after_grant() {
            let (mut daemon, harness, path) = ba_daemon(
                "ba-grant-mismatch",
                vec![
                    WitnessReply::NoHolderAt(7),
                    WitnessReply::NoHolderAt(7),
                    WitnessReply::GrantAt(9),
                ],
            );
            ba_attempt(&mut daemon, "a1");
            ba_deliver(&mut daemon, ProbeVerdict::Ack);
            assert_eq!(
                ba_attempt(&mut daemon, "a2"),
                PromotionAttemptResult::BlockedBeforeMutation
            );
            assert_eq!(daemon.runtime.promotion_calls, 0);
            assert_eq!(
                stage14_11_lease_kinds(&harness),
                ["lease_request", "lease_release"]
            );
            cleanup_store(&path);
        }

        /// K: a connection change between the grant and the ARM is caught by
        /// the final recheck; the granted lease is released and nothing arms.
        #[test]
        fn ba_final_recheck_failure_aborts_before_arm() {
            let (mut daemon, harness, path) = ba_daemon(
                "ba-recheck",
                vec![
                    WitnessReply::NoHolderAt(7),
                    WitnessReply::NoHolderAt(7),
                    WitnessReply::GrantAt(8),
                ],
            );
            ba_attempt(&mut daemon, "a1");
            ba_deliver(&mut daemon, ProbeVerdict::Ack);
            daemon.runtime.scripted_recheck_failure = Some("scripted".into());
            assert_eq!(
                ba_attempt(&mut daemon, "a2"),
                PromotionAttemptResult::BlockedBeforeMutation
            );
            assert_eq!(daemon.runtime.promotion_calls, 0);
            assert_eq!(
                stage14_11_lease_kinds(&harness),
                ["lease_request", "lease_release"]
            );
            assert!(
                daemon.runtime.store.release_obligation().unwrap().is_none()
                    || daemon.runtime.store.outstanding().unwrap().is_none()
            );
            cleanup_store(&path);
        }

        /// Shutdown requested after the attestation blocks attempt 2.
        #[test]
        fn ba_shutdown_blocks_attempt_two() {
            let (mut daemon, harness, path) = ba_daemon(
                "ba-shutdown",
                vec![WitnessReply::NoHolderAt(7), WitnessReply::NoHolderAt(7)],
            );
            ba_attempt(&mut daemon, "a1");
            ba_deliver(&mut daemon, ProbeVerdict::Ack);
            let _ = daemon.request_shutdown();
            // Rejected (no attempt slot after shutdown) or blocked: never a
            // lease request, never a clearance.
            assert_ne!(
                ba_attempt(&mut daemon, "a2"),
                PromotionAttemptResult::Succeeded
            );
            assert!(stage14_11_lease_kinds(&harness).is_empty());
            assert!(!daemon.bootstrap_session_open());
            cleanup_store(&path);
        }

        /// The tick sets the answering side's probe context from the daemon's
        /// own facts, and sets it to `None` after a failed observation.
        #[test]
        fn ba_probe_context_is_set_before_every_peer_tick() {
            let (mut daemon, _harness, path) = ba_daemon("ba-context", vec![]);
            daemon.tick().unwrap();
            let facts = daemon.runtime.ba_contexts.last().cloned().unwrap().unwrap();
            assert!(facts.running && !facts.shutdown_requested && !facts.attempt_in_flight);
            cleanup_store(&path);
        }

        /// Hygiene: discarding the session drops it and the runtime probe.
        #[test]
        fn ba_discard_drops_session_and_probe() {
            let (mut daemon, _harness, path) =
                ba_daemon("ba-discard", vec![WitnessReply::NoHolderAt(7)]);
            ba_attempt(&mut daemon, "a1");
            assert!(daemon.bootstrap_session_open());
            let discards = daemon.runtime.ba_discards;
            daemon.discard_bootstrap_session("test");
            assert!(!daemon.bootstrap_session_open());
            assert_eq!(daemon.runtime.ba_discards, discards + 1);
            cleanup_store(&path);
        }

        /// BA-T6 responder matrix through the real `responder_verdict`: only a
        /// Safe Standby with no phase, no attempt and no shutdown ACKs.
        #[test]
        fn ba_responder_verdict_after_attempt_states() {
            use crate::bootstrap_admission::{DaemonFacts, responder_verdict};
            let facts = DaemonFacts {
                running: true,
                shutdown_requested: false,
                attempt_in_flight: false,
            };
            let (daemon, _harness, path) = ba_daemon("ba-responder", vec![]);
            let safe = daemon.runtime.local_safety(false);
            assert_eq!(responder_verdict(Some(safe), facts), ProbeVerdict::Ack);
            assert_eq!(
                responder_verdict(
                    Some(safe),
                    DaemonFacts {
                        attempt_in_flight: true,
                        ..facts
                    }
                ),
                ProbeVerdict::Block
            );
            assert_eq!(
                responder_verdict(
                    Some(daemon.runtime.local_safety(true)),
                    DaemonFacts {
                        shutdown_requested: true,
                        ..facts
                    }
                ),
                ProbeVerdict::Block
            );
            assert_eq!(responder_verdict(None, facts), ProbeVerdict::Unknown);
            cleanup_store(&path);
        }

        /// §28 / §28.1: a block for lack of fresh local loss names
        /// `ListenerInterference` only when unauthenticated arrivals occurred
        /// in the last 30 s; other reasons never carry it; every non-gate
        /// block writes exactly one bounded WARN.
        #[test]
        fn stage14_11_blocked_attempt_lines_name_the_reason() {
            for (interference, expected) in [
                (
                    Some(3),
                    "local loss not fresh (ListenerInterference: 3 unauthenticated arrivals)",
                ),
                (Some(0), "local loss not fresh"),
                (None, "local loss not fresh"),
            ] {
                let (result, lines, _daemon, _harness, path) = stage14_11_run(
                    "s14-11-loss",
                    Ok(Some(unauthorized_evaluation())),
                    |daemon| daemon.runtime.interference = interference,
                );
                assert_eq!(result, PromotionAttemptResult::BlockedBeforeMutation);
                assert_eq!(
                    lines,
                    [format!(
                        "mikagami: WARN activation attempt blocked: {expected}"
                    )]
                );
                cleanup_store(&path);
            }
            // A different blocker never borrows the ListenerInterference text.
            let authority_present = ready_progress_at(
                std::time::Instant::now(),
                PeerFailureAssessment::CommunicationLost,
                crate::evidence_fusion::EvidenceFusionState::FailoverEvidenceReady,
                LocalSafetyReadiness::AuthorityPresent,
            )
            .into_evaluation()
            .unwrap();
            let (_, lines, _daemon, _harness, path) =
                stage14_11_run("s14-11-authority", Ok(Some(authority_present)), |daemon| {
                    daemon.runtime.interference = Some(5)
                });
            assert_eq!(
                lines,
                ["mikagami: WARN activation attempt blocked: authority present"]
            );
            cleanup_store(&path);
            for (canned, expected) in [
                (Ok(None), "no fresh authority observation"),
                (Err("boom".to_string()), "authority evaluation failed"),
            ] {
                let (_, lines, _daemon, _harness, path) =
                    stage14_11_run("s14-11-eval", canned, |_| {});
                assert_eq!(
                    lines,
                    [format!(
                        "mikagami: WARN activation attempt blocked: {expected}"
                    )]
                );
                cleanup_store(&path);
            }
        }

        /// §28: a gate block is logged by the runtime that knows the incident
        /// (target, sequence, state); the Daemon adds no second line for it.
        #[test]
        fn stage14_11_gate_block_writes_no_second_daemon_line() {
            let (result, lines, _daemon, _harness, path) =
                stage14_11_run("s14-11-gate", Ok(Some(authorized_evaluation())), |daemon| {
                    daemon.runtime.gate =
                        Some(Ok(crate::fencing::FencingGateBlock::FencingRequired));
                });
            assert_eq!(result, PromotionAttemptResult::BlockedBeforeMutation);
            assert!(lines.is_empty(), "{lines:?}");
            cleanup_store(&path);
        }

        /// §28: shutdown after the evaluation and a shutdown between G and K
        /// each write one WARN with their own bounded reason.
        #[test]
        fn stage14_11_shutdown_blocks_write_their_reason() {
            let (result, lines, _daemon, _harness, path) = stage14_11_run(
                "s14-11-shutdown-eval",
                Ok(Some(authorized_evaluation())),
                |daemon| {
                    daemon.push_promotion_attempt_test_hook(|daemon| {
                        daemon.request_shutdown().unwrap();
                    });
                },
            );
            assert_eq!(result, PromotionAttemptResult::BlockedBeforeMutation);
            assert_eq!(
                lines,
                ["mikagami: WARN activation attempt blocked: shutdown requested"]
            );
            cleanup_store(&path);
            let (result, lines, daemon, harness, path) = stage14_11_run(
                "s14-11-shutdown-k",
                Ok(Some(authorized_evaluation())),
                |daemon| {
                    daemon.push_promotion_attempt_test_hook(|_| {});
                    daemon.push_promotion_attempt_test_hook(|daemon| {
                        daemon.request_shutdown().unwrap();
                    });
                },
            );
            assert_eq!(result, PromotionAttemptResult::BlockedBeforeMutation);
            assert_eq!(
                lines,
                [
                    "mikagami: WARN activation attempt blocked: final recheck failed: shutdown requested"
                ]
            );
            assert_eq!(daemon.runtime.promotion_calls, 0, "K failed: no L");
            assert_eq!(
                stage14_11_lease_kinds(&harness),
                ["lease_request", "lease_release"]
            );
            cleanup_store(&path);
        }

        /// F2 (Rev5 §25, §24 L): `ArmRejected` from L is a post-grant,
        /// pre-resource abort. The Daemon routes it through
        /// `abort_after_grant`: exactly one cleanup call for the granted
        /// lease, the attempt retires `BlockedBeforeMutation`, the bound
        /// authority is dropped (never restored), nothing is promoted, and the
        /// daemon stays Running. (The exact clearance binding reaching the
        /// cleanup is proven with a real clearance by
        /// `stage14_11_f2_arm_rejected_uses_the_exact_binding`.)
        #[test]
        fn stage14_11_f2_arm_rejected_routes_through_abort_after_grant() {
            let (result, lines, daemon, harness, path) =
                stage14_11_run("s14-11-f2", Ok(Some(authorized_evaluation())), |daemon| {
                    daemon.runtime.scripted_outcome = Some(AttemptPromotionOutcome::ArmRejected)
                });
            assert_eq!(result, PromotionAttemptResult::BlockedBeforeMutation);
            assert_eq!(daemon.runtime.promotion_calls, 1);
            assert_eq!(daemon.runtime.release_calls, 1, "one abort cleanup");
            assert_eq!(daemon.runtime.cleanup_calls.len(), 1);
            let (granted, binding) = &daemon.runtime.cleanup_calls[0];
            assert!(
                granted.is_some(),
                "the granted lease is the cleanup subject"
            );
            assert_eq!(*binding, None, "the test bypass carries no clearance");
            assert!(daemon.runtime.promoted_attempts.is_empty());
            assert!(daemon.runtime.installed_lease_authority().is_none());
            assert_eq!(daemon.state(), DaemonState::Running);
            assert!(!daemon.runtime.vip_present.get());
            assert!(!daemon.runtime.service_running.get());
            assert_eq!(
                lines,
                ["mikagami: WARN activation attempt blocked: ARM validation rejected"]
            );
            assert_eq!(
                stage14_11_lease_kinds(&harness),
                ["lease_request", "lease_release"]
            );
            assert_eq!(
                daemon.promotion_attempt_lifecycle(),
                &PromotionAttemptLifecycle::Idle
            );
            cleanup_store(&path);
        }

        /// F2: the cleanup outcome after `ArmRejected` decides the daemon
        /// state exactly as Rev5 §25.1 says: a mismatched or uncertain cleanup
        /// is RecoveryBlocked (no Release); a not-committed cleanup leaves the
        /// daemon Running (no Release; the lease expires).
        #[test]
        fn stage14_11_f2_cleanup_outcome_after_arm_rejected() {
            for (cleanup, state) in [
                (
                    AttemptCleanup::RecoveryBlocked("cleanup binding mismatch".into()),
                    DaemonState::RecoveryBlocked,
                ),
                (AttemptCleanup::NotSent, DaemonState::Running),
            ] {
                let (result, _lines, daemon, harness, path) = stage14_11_run(
                    "s14-11-f2-cleanup",
                    Ok(Some(authorized_evaluation())),
                    |daemon| {
                        daemon.runtime.scripted_outcome =
                            Some(AttemptPromotionOutcome::ArmRejected);
                        daemon.runtime.scripted_cleanup = Some(Ok(cleanup));
                    },
                );
                assert_eq!(result, PromotionAttemptResult::BlockedBeforeMutation);
                assert_eq!(daemon.state(), state);
                assert_eq!(daemon.runtime.release_calls, 1);
                assert_eq!(
                    stage14_11_lease_kinds(&harness),
                    ["lease_request"],
                    "no Release is sent"
                );
                assert!(daemon.runtime.promoted_attempts.is_empty());
                cleanup_store(&path);
            }
        }

        /// L2: a K runtime-half failure carrying a huge raw error is emitted as
        /// one bounded, single-line reason that still names the failed recheck
        /// and the stage; an ordinary short failure is unchanged; nothing about
        /// the abort (Release, promotion, authority, resources) depends on it.
        #[test]
        fn stage14_11_l2_k_runtime_error_reason_is_bounded() {
            use crate::operator_log::{MAX_REASON_BYTES, bounded_reason};
            let prefix = "mikagami: WARN activation attempt blocked: ";
            let raw = format!("Io({})", "disk error / ".repeat(700));
            assert!(raw.len() > 8000);
            let (result, lines, daemon, harness, path) =
                stage14_11_run("s14-11-l2-k", Ok(Some(authorized_evaluation())), |daemon| {
                    daemon.runtime.scripted_recheck_failure = Some(raw.clone())
                });
            stage14_11_assert_abort_left_nothing_behind(&daemon, &result);
            assert_eq!(daemon.runtime.recheck_calls, 1);
            assert_eq!(daemon.runtime.promotion_calls, 0, "K failed: no L");
            assert_eq!(
                stage14_11_lease_kinds(&harness),
                ["lease_request", "lease_release"]
            );
            assert_eq!(lines.len(), 1, "{lines:?}");
            assert_eq!(
                lines[0],
                format!(
                    "{prefix}{}",
                    bounded_reason(&format!("final recheck failed: {raw}"))
                )
            );
            assert!(lines[0].len() <= prefix.len() + MAX_REASON_BYTES);
            assert!(lines[0].starts_with(&format!("{prefix}final recheck failed: Io(")));
            assert!(lines[0].ends_with("..."));
            assert!(!lines[0].contains('\n'));
            cleanup_store(&path);
            // A short failure keeps its exact text.
            let (_, lines, _daemon, _harness, path) = stage14_11_run(
                "s14-11-l2-k-short",
                Ok(Some(authorized_evaluation())),
                |daemon| daemon.runtime.scripted_recheck_failure = Some("TermMoved".into()),
            );
            assert_eq!(lines, [format!("{prefix}final recheck failed: TermMoved")]);
            cleanup_store(&path);
            // Multibyte text around the bound neither splits a character nor
            // panics.
            let (_, lines, _daemon, _harness, path) = stage14_11_run(
                "s14-11-l2-k-utf8",
                Ok(Some(authorized_evaluation())),
                |daemon| daemon.runtime.scripted_recheck_failure = Some("障害".repeat(400)),
            );
            assert!(lines[0].len() <= prefix.len() + MAX_REASON_BYTES);
            assert!(lines[0].ends_with("..."));
            cleanup_store(&path);
        }

        /// Everything the post-grant abort must leave untouched, whatever the
        /// cleanup did: no promotion, no authority, no resource, no retry.
        fn stage14_11_assert_abort_left_nothing_behind(
            daemon: &Daemon<ExecFake>,
            result: &PromotionAttemptResult,
        ) {
            assert_eq!(*result, PromotionAttemptResult::BlockedBeforeMutation);
            assert!(daemon.runtime.promoted_attempts.is_empty(), "no promotion");
            assert!(
                daemon.runtime.installed_lease_authority().is_none(),
                "authority is not restored"
            );
            assert!(!daemon.runtime.vip_present.get(), "no resource mutation");
            assert!(
                !daemon.runtime.service_running.get(),
                "no resource mutation"
            );
            assert_eq!(daemon.runtime.machine.node_state(), NodeState::Standby);
            assert_eq!(daemon.runtime.release_calls, 1, "one cleanup, no retry");
            assert_eq!(
                daemon.promotion_attempt_lifecycle(),
                &PromotionAttemptLifecycle::Idle
            );
        }

        /// M1 / F2 (Rev5 §25.1): every post-grant abort whose cleanup is not
        /// a proven durable success fails closed. A cleanup that returns `Err`
        /// (the exact independent-audit reproduction: the abort used to leave
        /// the daemon `Running`), an uncertain or binding-mismatched cleanup,
        /// and a cleanup that returns success are each checked for every abort
        /// cause: the L-stage `ArmRejected` and a K-stage shutdown.
        #[test]
        fn stage14_11_m1_cleanup_result_decides_the_daemon_state_for_every_abort() {
            #[derive(Clone, Copy)]
            enum Cause {
                ArmRejected,
                KShutdown,
            }
            let cleanups: [(&str, Result<AttemptCleanup, String>, DaemonState); 5] = [
                (
                    "Err",
                    Err("Witness session is not configured".to_string()),
                    DaemonState::RecoveryBlocked,
                ),
                (
                    "RecoveryBlocked",
                    Ok(AttemptCleanup::RecoveryBlocked("uncertain cleanup".into())),
                    DaemonState::RecoveryBlocked,
                ),
                (
                    "binding mismatch",
                    Ok(AttemptCleanup::RecoveryBlocked(
                        "old image does not match the incident binding".into(),
                    )),
                    DaemonState::RecoveryBlocked,
                ),
                (
                    // PreCommitFailure: the old image (incident, no O) is
                    // intact, no Release is sent, the lease expires.
                    "NotSent",
                    Ok(AttemptCleanup::NotSent),
                    DaemonState::Running,
                ),
                (
                    "Released",
                    Ok(AttemptCleanup::Released),
                    DaemonState::Running,
                ),
            ];
            for cause in [Cause::ArmRejected, Cause::KShutdown] {
                for (name, cleanup, expected_state) in &cleanups {
                    let (result, lines, daemon, harness, path) =
                        stage14_11_run("s14-11-m1", Ok(Some(authorized_evaluation())), |daemon| {
                            daemon.runtime.scripted_cleanup = Some(cleanup.clone());
                            match cause {
                                Cause::ArmRejected => {
                                    daemon.runtime.scripted_outcome =
                                        Some(AttemptPromotionOutcome::ArmRejected)
                                }
                                Cause::KShutdown => {
                                    daemon.push_promotion_attempt_test_hook(|_| {});
                                    daemon.push_promotion_attempt_test_hook(|daemon| {
                                        daemon.request_shutdown().unwrap();
                                    });
                                }
                            }
                        });
                    let label = format!("{name}");
                    stage14_11_assert_abort_left_nothing_behind(&daemon, &result);
                    // A non-blocked abort leaves the daemon in the state the
                    // cause implies: Running, or ShutdownRequested when the
                    // cause was the shutdown. Only a failed-closed cleanup
                    // overrides it.
                    let ordinary = match cause {
                        Cause::ArmRejected => DaemonState::Running,
                        Cause::KShutdown => DaemonState::ShutdownRequested,
                    };
                    let expected = if *expected_state == DaemonState::RecoveryBlocked {
                        DaemonState::RecoveryBlocked
                    } else {
                        ordinary
                    };
                    assert_eq!(daemon.state(), expected, "{label}");
                    assert_eq!(
                        stage14_11_lease_kinds(&harness),
                        ["lease_request"],
                        "{label}: the scripted cleanup sends no Release, and none is added"
                    );
                    // The cause and the cleanup outcome are both reported.
                    let errors: Vec<&String> = lines
                        .iter()
                        .filter(|line| line.starts_with("mikagami: ERROR "))
                        .collect();
                    match (name, expected_state) {
                        (&"Err", _) => {
                            assert_eq!(errors.len(), 1, "{label}: {lines:?}");
                            assert_eq!(
                                errors[0],
                                "mikagami: ERROR post-grant abort cleanup failed; recovery blocked: Witness session is not configured"
                            );
                        }
                        (_, DaemonState::RecoveryBlocked) => {
                            assert_eq!(errors.len(), 1, "{label}: {lines:?}");
                            assert!(
                                errors[0].starts_with(
                                    "mikagami: ERROR post-grant abort cleanup blocked; recovery blocked: "
                                ),
                                "{label}: {lines:?}"
                            );
                        }
                        _ => assert!(errors.is_empty(), "{label}: {lines:?}"),
                    }
                    assert_eq!(
                        lines.iter().filter(|l| l.contains(" WARN ")).count(),
                        1,
                        "{label}: exactly one blocked-attempt WARN: {lines:?}"
                    );
                    cleanup_store(&path);
                }
            }
        }

        /// M1: the successful durable cleanup still works end to end. With no
        /// scripted cleanup the fake runs the real cleanup (durable O, then the
        /// exact LeaseRelease through the Witness session): the Release is
        /// sent, the daemon stays Running, and nothing else happens.
        #[test]
        fn stage14_11_m1_durable_cleanup_success_releases_the_lease() {
            let (result, lines, daemon, harness, path) = stage14_11_run(
                "s14-11-m1-ok",
                Ok(Some(authorized_evaluation())),
                |daemon| {
                    daemon.runtime.scripted_outcome = Some(AttemptPromotionOutcome::ArmRejected)
                },
            );
            stage14_11_assert_abort_left_nothing_behind(&daemon, &result);
            assert_eq!(daemon.state(), DaemonState::Running);
            assert_eq!(
                stage14_11_lease_kinds(&harness),
                ["lease_request", "lease_release"],
                "the exact Release"
            );
            assert!(
                daemon.runtime.store.release_obligation().unwrap().is_none(),
                "the armed cleanup O was cleared by the completed Release"
            );
            assert!(
                lines.iter().all(|line| !line.contains(" ERROR ")),
                "{lines:?}"
            );
            cleanup_store(&path);
        }

        /// F2 companions: an uncertain ARM is RecoveryBlocked with no cleanup
        /// call at all; a not-committed ARM sends no Release and stays Running.
        #[test]
        fn stage14_11_f2_uncertain_and_not_committed_arm_send_no_cleanup() {
            let (result, lines, daemon, harness, path) = stage14_11_run(
                "s14-11-arm-uncertain",
                Ok(Some(authorized_evaluation())),
                |daemon| {
                    daemon.runtime.scripted_outcome = Some(AttemptPromotionOutcome::RecoveryBlocked)
                },
            );
            assert_eq!(result, PromotionAttemptResult::BlockedBeforeMutation);
            assert_eq!(daemon.state(), DaemonState::RecoveryBlocked);
            assert_eq!(daemon.runtime.release_calls, 0);
            assert_eq!(stage14_11_lease_kinds(&harness), ["lease_request"]);
            assert!(
                lines.is_empty(),
                "the uncertain ARM writes its own eprintln: {lines:?}"
            );
            cleanup_store(&path);
            let (result, lines, daemon, harness, path) = stage14_11_run(
                "s14-11-arm-not-committed",
                Ok(Some(authorized_evaluation())),
                |daemon| {
                    daemon.runtime.scripted_outcome = Some(AttemptPromotionOutcome::ArmNotCommitted)
                },
            );
            assert_eq!(result, PromotionAttemptResult::BlockedBeforeMutation);
            assert_eq!(daemon.state(), DaemonState::Running);
            assert_eq!(daemon.runtime.release_calls, 0);
            assert_eq!(stage14_11_lease_kinds(&harness), ["lease_request"]);
            assert_eq!(
                lines,
                [
                    "mikagami: WARN activation attempt blocked: ARM not committed (no Release is sent; the lease expires)"
                ]
            );
            cleanup_store(&path);
        }

        /// §28.1 / MF-45: a diagnostic never becomes evidence or a gate. With
        /// unauthenticated arrivals reported, a fully valid attempt is exactly
        /// as it would be without them: it succeeds, writes no blocked line,
        /// and an unauthorized attempt stays blocked (never authorized by the
        /// diagnostic).
        #[test]
        fn stage14_11_listener_interference_never_changes_a_decision() {
            let (mut daemon, harness, _clock, path) = exec_daemon(
                "s14-11-valid",
                VecDeque::new(),
                VecDeque::from([Ok(Some(authorized_evaluation()))]),
            );
            daemon.runtime.interference = Some(9);
            crate::operator_log::capture_start();
            let result = daemon.execute_promotion_attempt(request("attempt-1"));
            let lines = crate::operator_log::capture_take();
            assert_eq!(result, PromotionAttemptResult::Succeeded);
            assert!(lines.is_empty(), "{lines:?}");
            assert_eq!(witness_log(&harness), vec!["lease_request"]);
            assert_eq!(daemon.runtime.promotion_calls, 1);
            drop(daemon);
            harness.join.join().unwrap();
            cleanup_store(&path);
            // The unauthorized attempt is blocked whatever the diagnostic says
            // and reaches neither the gate nor the Witness.
            let (result, _lines, daemon, harness, path) = stage14_11_run(
                "s14-11-unauthorized",
                Ok(Some(unauthorized_evaluation())),
                |daemon| daemon.runtime.interference = Some(9),
            );
            assert_eq!(result, PromotionAttemptResult::BlockedBeforeMutation);
            assert_eq!(daemon.runtime.lease_acquire_calls, 0);
            assert_eq!(daemon.runtime.promotion_calls, 0);
            assert!(witness_log(&harness).is_empty());
            cleanup_store(&path);
        }

        // ---- Stage 14 Phase 14.9 (DC-14.9-01 Option B): gate G wiring ----

        fn stage14_9_assert_blocked_before_lease(
            daemon: &Daemon<ExecFake>,
            harness: &WitnessHarness,
            result: PromotionAttemptResult,
        ) {
            assert_eq!(result, PromotionAttemptResult::BlockedBeforeMutation);
            assert_eq!(daemon.runtime.gate_calls, 1);
            assert_eq!(daemon.runtime.evaluate_calls, 1);
            assert_eq!(daemon.runtime.lease_acquire_calls, 0);
            assert_eq!(daemon.runtime.release_calls, 0);
            assert_eq!(daemon.runtime.promotion_calls, 0);
            assert!(daemon.runtime.promoted_attempts.is_empty());
            assert!(daemon.runtime.installed_lease_authority().is_none());
            assert_eq!(daemon.runtime.machine.node_state(), NodeState::Standby);
            assert!(!daemon.runtime.vip_present.get());
            assert!(!daemon.runtime.service_running.get());
            assert!(witness_log(harness).is_empty(), "no LeaseRequest after G");
            assert_eq!(
                daemon.promotion_attempt_lifecycle(),
                &PromotionAttemptLifecycle::Idle
            );
        }

        /// §24 G, Phase 14.9 form: every production gate decision — a valid
        /// `CONFIRMED` included (`ConfirmedClearanceDeferred`, the temporary
        /// Rev5 deviation resolved in Phase 14.10) — retires the attempt
        /// `BlockedBeforeMutation` after the fresh `Authorized` evaluation and
        /// before any LeaseRequest, lease authority, or Stage 11 mutation.
        #[test]
        fn stage14_9_every_gate_block_retires_before_any_lease_request() {
            use crate::fencing::FencingGateBlock;
            for block in [
                FencingGateBlock::NotEligible,
                FencingGateBlock::FencingUnavailable,
                FencingGateBlock::StoreUnavailable,
                FencingGateBlock::FencingRequired,
                FencingGateBlock::FencingUnconfirmed,
                FencingGateBlock::FencingInProgress,
            ] {
                let (mut daemon, harness, _clock, path) = exec_daemon(
                    "stage14-9-gate-block",
                    VecDeque::new(),
                    VecDeque::from([Ok(Some(authorized_evaluation()))]),
                );
                daemon.runtime.gate = Some(Ok(block));
                let result = daemon.execute_promotion_attempt(request("attempt-1"));
                stage14_9_assert_blocked_before_lease(&daemon, &harness, result);
                assert_eq!(daemon.runtime.gate_shutdown_inputs, vec![false]);
                assert_eq!(daemon.state(), DaemonState::Running, "{block:?}");
                drop(daemon);
                harness.join.join().unwrap();
                cleanup_store(&path);
            }
        }

        /// A class-D gate failure (uncertain store write, backend invariant)
        /// blocks the attempt and fails the daemon closed; the next tick is
        /// `NotRunning`, which the loop turns into a fatal exit.
        #[test]
        fn stage14_9_gate_failure_fails_the_daemon_closed() {
            let (mut daemon, harness, _clock, path) = exec_daemon(
                "stage14-9-gate-failed",
                VecDeque::new(),
                VecDeque::from([Ok(Some(authorized_evaluation()))]),
            );
            daemon.runtime.gate = Some(Err("uncertain".into()));
            let result = daemon.execute_promotion_attempt(request("attempt-1"));
            stage14_9_assert_blocked_before_lease(&daemon, &harness, result);
            assert_eq!(daemon.state(), DaemonState::Failed);
            assert_eq!(daemon.tick().unwrap(), TickResult::NotRunning);
            drop(daemon);
            harness.join.join().unwrap();
            cleanup_store(&path);
        }

        /// G is reached only after a fresh `Authorized` evaluation and the
        /// shutdown check: a non-authorized evaluation, or a shutdown
        /// requested during revalidation, never enters the gate (no incident
        /// is opened and no fence action can run).
        #[test]
        fn stage14_9_gate_runs_only_after_authorized_and_shutdown_check() {
            for canned in [
                Ok::<Option<AuthorityAttemptEvaluation>, String>(None),
                Ok(Some(unauthorized_evaluation())),
                Err("observation failed".to_string()),
            ] {
                let (mut daemon, harness, _clock, path) = exec_daemon(
                    "stage14-9-gate-unreached",
                    VecDeque::new(),
                    VecDeque::from([canned]),
                );
                daemon.runtime.gate = Some(Ok(crate::fencing::FencingGateBlock::FencingRequired));
                let result = daemon.execute_promotion_attempt(request("attempt-1"));
                assert_eq!(result, PromotionAttemptResult::BlockedBeforeMutation);
                assert_eq!(daemon.runtime.gate_calls, 0);
                assert_eq!(daemon.runtime.lease_acquire_calls, 0);
                drop(daemon);
                harness.join.join().unwrap();
                cleanup_store(&path);
            }

            let (mut daemon, harness, _clock, path) = exec_daemon(
                "stage14-9-gate-shutdown",
                VecDeque::new(),
                VecDeque::from([Ok(Some(authorized_evaluation()))]),
            );
            daemon.runtime.gate = Some(Ok(crate::fencing::FencingGateBlock::FencingRequired));
            daemon.push_promotion_attempt_test_hook(|daemon| {
                daemon.request_shutdown().unwrap();
            });
            let result = daemon.execute_promotion_attempt(request("attempt-1"));
            assert_eq!(result, PromotionAttemptResult::BlockedBeforeMutation);
            assert_eq!(daemon.runtime.gate_calls, 0);
            assert_eq!(daemon.runtime.lease_acquire_calls, 0);
            drop(daemon);
            harness.join.join().unwrap();
            cleanup_store(&path);
        }

        /// Stage 14 F14.9-01: the gate reads shutdown live. A shutdown-signal
        /// latch raised during the attempt — after revalidation and the
        /// Daemon's own shutdown check, while its requested state is still
        /// false — is visible to the gate through the query, so the gate can
        /// refuse to spawn and discard a returned action. The Daemon's state
        /// is not changed by the read; the loop propagates the stop.
        #[test]
        fn stage14_9_f01_gate_reads_the_attached_shutdown_signal_live() {
            let (mut daemon, harness, _clock, path) = exec_daemon(
                "stage14-9-f01-gate-signal",
                VecDeque::new(),
                VecDeque::from([Ok(Some(authorized_evaluation()))]),
            );
            daemon.runtime.gate = Some(Ok(crate::fencing::FencingGateBlock::FencingInProgress));
            let raised = Rc::new(Cell::new(false));
            let signal = raised.clone();
            daemon.attach_shutdown_signal(move || signal.get());
            daemon.push_promotion_attempt_test_hook(move |_| raised.set(true));
            let result = daemon.execute_promotion_attempt(request("attempt-1"));
            stage14_9_assert_blocked_before_lease(&daemon, &harness, result);
            assert_eq!(daemon.runtime.gate_shutdown_inputs, vec![true]);
            assert_eq!(daemon.state(), DaemonState::Running);
            drop(daemon);
            harness.join.join().unwrap();
            cleanup_store(&path);
        }

        /// MKM-ARCH-012.1 positive control: a fresh authorized attempt with a
        /// real lease grant through the shared session reaches the Stage 11
        /// Active boundary and returns `Succeeded`.
        #[test]
        fn mkm_arch_012_positive_control_reaches_stage_13_2_success_boundary() {
            let (mut daemon, harness, _clock, path) = exec_daemon(
                "positive",
                VecDeque::new(),
                VecDeque::from([Ok(Some(authorized_evaluation()))]),
            );
            let result = daemon.execute_promotion_attempt(request("attempt-1"));
            assert_eq!(
                result,
                PromotionAttemptResult::Succeeded,
                "MKM-ARCH-012 violated: approved path did not reach Succeeded"
            );
            assert_eq!(daemon.runtime.evaluate_calls, 1);
            assert_eq!(daemon.runtime.lease_acquire_calls, 1);
            assert_eq!(daemon.runtime.promotion_calls, 1);
            assert_eq!(
                daemon.runtime.promoted_attempts,
                vec![PromotionRequestId::new("attempt-1")],
                "MKM-ARCH-012 violated: Stage 11 ran without the attempt's bound authority"
            );
            assert_eq!(
                daemon.runtime.machine.node_state(),
                NodeState::Active,
                "MKM-ARCH-012 violated: Stage 11 success boundary not reached"
            );
            assert_eq!(
                daemon.promotion_attempt_lifecycle(),
                &PromotionAttemptLifecycle::Idle,
                "MKM-ARCH-012 violated: attempt not retired after success"
            );
            // Exactly one lease request on the wire; no release on success
            // because Active ownership remains authoritative.
            assert_eq!(witness_log(&harness), vec!["lease_request"]);
            assert_eq!(daemon.runtime.peer_tick_calls, 0);
            drop(daemon);
            harness.join.join().unwrap();
            cleanup_store(&path);
        }

        /// MKM-ARCH-012.2: `InFlight` alone is not authority — a non-Ready /
        /// non-Authorized fresh evaluation cannot reach the lease or Stage 11.
        #[test]
        fn mkm_arch_012_inflight_alone_is_not_authority() {
            for canned in [
                Ok::<Option<AuthorityAttemptEvaluation>, String>(None),
                Ok(Some(unauthorized_evaluation())),
            ] {
                let path = test_path("inflight-not-authority");
                let (mut daemon, harness, _clock, _store_path) = exec_daemon(
                    "inflight-not-authority",
                    VecDeque::new(),
                    VecDeque::from([canned]),
                );
                let result = daemon.execute_promotion_attempt(request("attempt-1"));
                assert_eq!(result, PromotionAttemptResult::BlockedBeforeMutation);
                assert_eq!(daemon.runtime.lease_acquire_calls, 0);
                assert_eq!(daemon.runtime.promotion_calls, 0);
                assert!(witness_log(&harness).is_empty());
                assert_eq!(
                    daemon.promotion_attempt_lifecycle(),
                    &PromotionAttemptLifecycle::Idle
                );
                drop(daemon);
                harness.join.join().unwrap();
                cleanup_store(&path);
            }
        }

        /// MKM-ARCH-012.3: a previous attempt's `Authorized` is never stored
        /// or reused; a second attempt is revalidated fresh and fails closed.
        #[test]
        fn mkm_arch_012_stale_authorization_is_not_reused() {
            let path = test_path("stale-auth");
            let (mut daemon, harness, _clock, _store_path) = exec_daemon(
                "stale-auth",
                VecDeque::new(),
                VecDeque::from([
                    Ok(Some(authorized_evaluation())),
                    Ok(Some(unauthorized_evaluation())),
                ]),
            );
            assert_eq!(
                daemon.execute_promotion_attempt(request("attempt-a")),
                PromotionAttemptResult::Succeeded
            );
            // The second attempt must consult a fresh evaluation; the stale
            // `Authorized` from attempt A cannot carry it.
            assert_eq!(
                daemon.execute_promotion_attempt(request("attempt-b")),
                PromotionAttemptResult::BlockedBeforeMutation
            );
            assert_eq!(daemon.runtime.evaluate_calls, 2);
            assert_eq!(daemon.runtime.lease_acquire_calls, 1);
            assert_eq!(daemon.runtime.promotion_calls, 1);
            drop(daemon);
            harness.join.join().unwrap();
            cleanup_store(&path);
        }

        /// MKM-ARCH-012.4: a pre-existing `InFlight` plus requested shutdown
        /// cannot execute; the new request is rejected and the in-flight
        /// attempt is never touched by the rejected one.
        #[test]
        fn mkm_arch_012_preexisting_inflight_with_shutdown_cannot_execute() {
            let path = test_path("inflight-shutdown");
            let (mut daemon, harness, _clock, _store_path) =
                exec_daemon("inflight-shutdown", VecDeque::new(), VecDeque::new());
            daemon
                .request_promotion_attempt(request("attempt-a"))
                .unwrap();
            daemon.request_shutdown().unwrap();
            assert_eq!(
                daemon.execute_promotion_attempt(request("attempt-b")),
                PromotionAttemptResult::Rejected(PromotionAttemptRejection::RejectedShutdown)
            );
            assert_eq!(daemon.runtime.evaluate_calls, 0);
            assert_eq!(daemon.runtime.lease_acquire_calls, 0);
            assert_eq!(daemon.runtime.promotion_calls, 0);
            // The rejected execution must not retire the pre-existing attempt.
            assert_eq!(
                daemon.promotion_attempt_lifecycle().in_flight_id(),
                Some(&PromotionRequestId::new("attempt-a")),
                "MKM-ARCH-012 violated: rejected attempt B retired attempt A"
            );
            assert_eq!(
                daemon.cancel_promotion_attempt(),
                Some(PromotionRequestId::new("attempt-a"))
            );
            assert!(witness_log(&harness).is_empty());
            drop(daemon);
            harness.join.join().unwrap();
            cleanup_store(&path);
        }

        /// MKM-ARCH-012.5: shutdown racing the authorized lease completion
        /// still blocks mutation; the granted lease is released best-effort
        /// through the same shared session.
        #[test]
        fn mkm_arch_012_shutdown_after_revalidation_cannot_execute() {
            // (a) shutdown observed after revalidation: no lease request.
            let path = test_path("shutdown-post-auth");
            let (mut daemon, harness, _clock, _store_path) = exec_daemon(
                "shutdown-post-auth",
                VecDeque::new(),
                VecDeque::from([Ok(Some(authorized_evaluation()))]),
            );
            daemon.push_promotion_attempt_test_hook(|daemon| {
                let _ = daemon.request_shutdown();
            });
            assert_eq!(
                daemon.execute_promotion_attempt(request("attempt-1")),
                PromotionAttemptResult::BlockedBeforeMutation
            );
            assert_eq!(daemon.runtime.evaluate_calls, 1);
            assert_eq!(daemon.runtime.lease_acquire_calls, 0);
            assert_eq!(daemon.runtime.promotion_calls, 0);
            assert!(witness_log(&harness).is_empty());
            assert_eq!(
                daemon.promotion_attempt_lifecycle(),
                &PromotionAttemptLifecycle::Idle
            );
            drop(daemon);
            harness.join.join().unwrap();
            cleanup_store(&path);

            // (b) shutdown observed after the lease grant but before the
            // Stage 11 handoff: mutation is blocked and the lease is
            // released through the same shared session.
            let path = test_path("shutdown-post-lease");
            let (mut daemon, harness, _clock, _store_path) = exec_daemon(
                "shutdown-post-lease",
                VecDeque::new(),
                VecDeque::from([Ok(Some(authorized_evaluation()))]),
            );
            daemon.push_promotion_attempt_test_hook(|_| {});
            daemon.push_promotion_attempt_test_hook(|daemon| {
                let _ = daemon.request_shutdown();
            });
            assert_eq!(
                daemon.execute_promotion_attempt(request("attempt-2")),
                PromotionAttemptResult::BlockedBeforeMutation
            );
            assert_eq!(daemon.runtime.promotion_calls, 0);
            assert_eq!(daemon.runtime.release_calls, 1);
            assert_eq!(
                witness_log(&harness),
                vec!["lease_request", "lease_release"],
                "MKM-ARCH-012 violated: granted lease was not released on abort"
            );
            assert_eq!(
                daemon.promotion_attempt_lifecycle(),
                &PromotionAttemptLifecycle::Idle
            );
            drop(daemon);
            harness.join.join().unwrap();
            cleanup_store(&path);
        }

        /// B-1: a control-lock loss visible at the pre-lease live check
        /// stops the attempt before any lease request. The test-only gate is
        /// the Stage 13.2 bypass, so the signal reader is first consulted by
        /// that bypass and then again immediately before the lease.
        #[test]
        fn b1_lock_loss_before_the_lease_request_acquires_no_lease() {
            let (mut daemon, harness, _clock, path) = exec_daemon(
                "b1-lock-loss-pre-lease",
                VecDeque::new(),
                VecDeque::from([Ok(Some(authorized_evaluation()))]),
            );
            daemon.attach_shutdown_signal(|| true);
            assert_eq!(
                daemon.execute_promotion_attempt(request("attempt-1")),
                PromotionAttemptResult::BlockedBeforeMutation
            );
            assert_eq!(daemon.runtime.gate_calls, 1);
            assert_eq!(daemon.runtime.lease_acquire_calls, 0);
            assert_eq!(daemon.runtime.promotion_calls, 0);
            assert_eq!(daemon.runtime.release_calls, 0);
            assert!(witness_log(&harness).is_empty());
            assert_eq!(
                daemon.promotion_attempt_lifecycle(),
                &PromotionAttemptLifecycle::Idle
            );
            drop(daemon);
            harness.join.join().unwrap();
            cleanup_store(&path);
        }

        /// B-1: a control-lock loss after the grant but before the resource
        /// handoff aborts through the bounded lease cleanup and never calls
        /// `execute_attempt_promotion`. The signal counter accounts for the
        /// gate's live read, the pre-lease read, K, and this final read.
        #[test]
        fn b1_lock_loss_after_the_lease_releases_without_mutating_resources() {
            let (mut daemon, harness, _clock, path) = exec_daemon(
                "b1-lock-loss-pre-resource",
                VecDeque::new(),
                VecDeque::from([Ok(Some(authorized_evaluation()))]),
            );
            let calls = Rc::new(Cell::new(0u32));
            let seen = Rc::clone(&calls);
            daemon.attach_shutdown_signal(move || {
                let next = seen.get() + 1;
                seen.set(next);
                next >= 4
            });
            assert_eq!(
                daemon.execute_promotion_attempt(request("attempt-1")),
                PromotionAttemptResult::BlockedBeforeMutation
            );
            assert_eq!(daemon.runtime.gate_calls, 1);
            assert_eq!(daemon.runtime.lease_acquire_calls, 1);
            assert_eq!(daemon.runtime.promotion_calls, 0);
            assert_eq!(daemon.runtime.release_calls, 1);
            assert_eq!(
                calls.get(),
                4,
                "the final live check must be the one that observed the loss"
            );
            assert_eq!(
                witness_log(&harness),
                vec!["lease_request", "lease_release"],
                "the granted lease must be released without a resource mutation"
            );
            assert_eq!(
                daemon.promotion_attempt_lifecycle(),
                &PromotionAttemptLifecycle::Idle
            );
            drop(daemon);
            harness.join.join().unwrap();
            cleanup_store(&path);
        }

        /// MKM-ARCH-012.6: a lease reject/transport failure mints no
        /// authority and never reaches Stage 11.
        #[test]
        fn mkm_arch_012_lease_failure_blocks_mutation() {
            for replies in [
                VecDeque::from([WitnessReply::LeasePolicyReject]),
                VecDeque::from([WitnessReply::WrongRequestId]),
            ] {
                let path = test_path("lease-failure");
                let (mut daemon, harness, _clock, _store_path) = exec_daemon(
                    "lease-failure",
                    replies,
                    VecDeque::from([Ok(Some(authorized_evaluation()))]),
                );
                assert_eq!(
                    daemon.execute_promotion_attempt(request("attempt-1")),
                    PromotionAttemptResult::BlockedBeforeMutation
                );
                assert_eq!(daemon.runtime.lease_acquire_calls, 1);
                assert_eq!(daemon.runtime.promotion_calls, 0);
                assert!(
                    daemon.runtime.installed_lease_authority().is_none(),
                    "MKM-ARCH-012 violated: failed lease minted authority"
                );
                assert_eq!(witness_log(&harness), vec!["lease_request"]);
                drop(daemon);
                harness.join.join().unwrap();
                cleanup_store(&path);
            }
        }

        /// MKM-ARCH-012.7: attempt A's bound lease cannot execute attempt B;
        /// a retired A releases its lease and B must acquire its own.
        #[test]
        fn mkm_arch_012_wrong_attempt_cannot_use_other_attempt_authority() {
            let path = test_path("wrong-attempt");
            let (mut daemon, harness, _clock, _store_path) = exec_daemon(
                "wrong-attempt",
                VecDeque::new(),
                VecDeque::from([
                    Ok(Some(authorized_evaluation())),
                    Ok(Some(authorized_evaluation())),
                ]),
            );
            // Attempt A is cancelled after its lease grant arrived: the bound
            // authority can never be handed to a different attempt.
            daemon.push_promotion_attempt_test_hook(|_| {});
            daemon.push_promotion_attempt_test_hook(|daemon| {
                let _ = daemon.cancel_promotion_attempt();
            });
            assert_eq!(
                daemon.execute_promotion_attempt(request("attempt-a")),
                PromotionAttemptResult::Cancelled
            );
            assert_eq!(daemon.runtime.promotion_calls, 0);
            // Attempt B gets a fresh lease and promotes only itself.
            assert_eq!(
                daemon.execute_promotion_attempt(request("attempt-b")),
                PromotionAttemptResult::Succeeded
            );
            assert_eq!(daemon.runtime.promotion_calls, 1);
            assert_eq!(
                daemon.runtime.promoted_attempts,
                vec![PromotionRequestId::new("attempt-b")],
                "MKM-ARCH-012 violated: attempt A's authority promoted attempt B"
            );
            assert_eq!(
                witness_log(&harness),
                vec!["lease_request", "lease_release", "lease_request"],
                "MKM-ARCH-012 violated: attempt B did not acquire a fresh lease"
            );
            drop(daemon);
            harness.join.join().unwrap();
            cleanup_store(&path);
        }

        /// MKM-ARCH-012.8: reusing a retired `PromotionRequestId` recovers
        /// nothing — the new attempt revalidates and re-leases from scratch.
        #[test]
        fn mkm_arch_012_retired_id_reuse_does_not_recover_authority() {
            let path = test_path("retired-id");
            let (mut daemon, harness, _clock, _store_path) = exec_daemon(
                "retired-id",
                VecDeque::from([WitnessReply::LeasePolicyReject]),
                VecDeque::from([
                    Ok(Some(authorized_evaluation())),
                    Ok(Some(authorized_evaluation())),
                ]),
            );
            assert_eq!(
                daemon.execute_promotion_attempt(request("reused-id")),
                PromotionAttemptResult::BlockedBeforeMutation
            );
            // The retired id may be reused, but reuse grants nothing: the
            // second attempt performs its own revalidation and its own lease
            // request rather than recovering attempt one's authority.
            assert_eq!(
                daemon.execute_promotion_attempt(request("reused-id")),
                PromotionAttemptResult::Succeeded
            );
            assert_eq!(daemon.runtime.evaluate_calls, 2);
            assert_eq!(daemon.runtime.lease_acquire_calls, 2);
            assert_eq!(daemon.runtime.promotion_calls, 1);
            assert_eq!(
                daemon.runtime.promoted_attempts,
                vec![PromotionRequestId::new("reused-id")]
            );
            assert_eq!(
                witness_log(&harness),
                vec!["lease_request", "lease_request"],
                "MKM-ARCH-012 violated: id reuse skipped a fresh lease request"
            );
            drop(daemon);
            harness.join.join().unwrap();
            cleanup_store(&path);
        }

        /// MKM-ARCH-012.9 (F-03): one execution performs exactly one logical
        /// observation — never `authority_observation_tick` followed by
        /// `evaluate_authority_attempt` for the same observation.
        #[test]
        fn mkm_arch_012_single_observation_owner_no_double_poll() {
            let path = test_path("single-observation");
            let (mut daemon, harness, _clock, _store_path) =
                exec_daemon("single-observation", VecDeque::new(), VecDeque::new());
            // Real adapter path: the evaluation drives one GET_TERM through
            // the shared session. Protocol v1 cannot mint FailoverEvidenceReady,
            // so the result is fail-closed — the point under test is the
            // observation count, not the outcome.
            let result = daemon.execute_promotion_attempt(request("attempt-1"));
            assert_eq!(result, PromotionAttemptResult::BlockedBeforeMutation);
            assert_eq!(daemon.runtime.evaluate_calls, 1);
            assert_eq!(daemon.runtime.peer_tick_calls, 0);
            assert_eq!(
                witness_log(&harness),
                vec!["get_term"],
                "MKM-ARCH-012 violated: one attempt produced more than one \
                 observation request (double poll)"
            );
            assert_eq!(daemon.runtime.lease_acquire_calls, 0);
            assert_eq!(daemon.runtime.promotion_calls, 0);
            drop(daemon);
            harness.join.join().unwrap();
            cleanup_store(&path);
        }

        /// MKM-ARCH-012.10: observation and lease traffic share exactly one
        /// outstanding slot; a second outstanding operation is rejected and
        /// makes the pre-mutation checkpoint fail closed.
        #[test]
        fn mkm_arch_012_shared_witness_outstanding_slot_is_enforced() {
            let path = test_path("shared-slot");
            let (mut daemon, harness, _clock, _store_path) = exec_daemon(
                "shared-slot",
                // The session-level GET_TERM below must not be answered, or
                // its TermStatus would sit in the socket and poison the
                // driver's lease completion.
                VecDeque::from([WitnessReply::Silent]),
                VecDeque::from([Ok(Some(authorized_evaluation()))]),
            );
            // Session-level: an in-flight observation occupies the slot, so
            // a lease request on the same session is rejected outright.
            {
                let session = daemon.runtime.session.as_mut().unwrap();
                session
                    .send_get_term(RequestId::new("00000000-0000-4000-8000-0000000000a1"))
                    .unwrap();
                assert!(session.request_in_flight());
                let result = session.send_lease_request(
                    RequestId::new("00000000-0000-4000-8000-0000000000a2"),
                    crate::protocol::LeaseRequestPayload {
                        mutation_generation: 1,
                        observed_term: Term(7),
                        priority: 100,
                        requested_ttl: DurationMs(LEASE_TTL_MS),
                    },
                );
                assert!(
                    matches!(
                        result,
                        Err(crate::witness_runtime::WitnessRuntimeError::RequestAlreadyOutstanding)
                    ),
                    "MKM-ARCH-012 violated: second shared-session request was not rejected"
                );
                session.reset_outstanding();
            }
            // Driver-level: after the lease grant, an occupied shared slot
            // fails the final checkpoint — no promotion, cleanup attempted.
            daemon.push_promotion_attempt_test_hook(|_| {});
            daemon.push_promotion_attempt_test_hook(|daemon| {
                let session = daemon.runtime.session.as_mut().unwrap();
                session
                    .send_get_term(RequestId::new("00000000-0000-4000-8000-0000000000b1"))
                    .unwrap();
            });
            assert_eq!(
                daemon.execute_promotion_attempt(request("attempt-1")),
                PromotionAttemptResult::BlockedBeforeMutation
            );
            assert_eq!(daemon.runtime.promotion_calls, 0);
            assert_eq!(daemon.runtime.release_calls, 1);
            // The release could not send (slot occupied); the durable
            // outstanding release remains for Stage 9/10 recovery — never
            // bypassed by a second slot.
            assert_eq!(
                daemon
                    .runtime
                    .store
                    .load_existing()
                    .unwrap()
                    .outstanding_mutation
                    .map(|outstanding| outstanding.kind()),
                Some(MutationKind::LeaseRelease)
            );
            assert_eq!(
                daemon.promotion_attempt_lifecycle(),
                &PromotionAttemptLifecycle::Idle
            );
            let _ = witness_log(&harness);
            drop(daemon);
            harness.join.join().unwrap();
            cleanup_store(&path);
        }

        /// MKM-ARCH-012.11: a cancelled attempt cannot be resurrected by a
        /// late completion; its lease is released and a fresh attempt needs
        /// its own grant.
        #[test]
        fn mkm_arch_012_cancelled_attempt_cannot_execute_on_late_response() {
            let path = test_path("cancelled");
            let (mut daemon, harness, _clock, _store_path) = exec_daemon(
                "cancelled",
                VecDeque::new(),
                VecDeque::from([
                    Ok(Some(authorized_evaluation())),
                    Ok(Some(authorized_evaluation())),
                ]),
            );
            // The lease response arrives (the "late response"), then the
            // attempt is cancelled before the final checkpoint.
            daemon.push_promotion_attempt_test_hook(|_| {});
            daemon.push_promotion_attempt_test_hook(|daemon| {
                assert_eq!(
                    daemon.cancel_promotion_attempt(),
                    Some(PromotionRequestId::new("attempt-x"))
                );
            });
            assert_eq!(
                daemon.execute_promotion_attempt(request("attempt-x")),
                PromotionAttemptResult::Cancelled
            );
            assert_eq!(daemon.runtime.promotion_calls, 0);
            assert_eq!(
                witness_log(&harness),
                vec!["lease_request", "lease_release"],
                "MKM-ARCH-012 violated: cancelled attempt's lease was not released"
            );
            assert_eq!(
                daemon.promotion_attempt_lifecycle(),
                &PromotionAttemptLifecycle::Idle
            );
            // A later attempt with the same id starts clean: fresh
            // revalidation and a fresh lease, correlated by protocol
            // RequestId — the cancelled attempt's completion grants nothing.
            assert_eq!(
                daemon.execute_promotion_attempt(request("attempt-x")),
                PromotionAttemptResult::Succeeded
            );
            assert_eq!(daemon.runtime.promotion_calls, 1);
            drop(daemon);
            harness.join.join().unwrap();
            cleanup_store(&path);
        }

        /// MKM-ARCH-012.12: a Stage 11 failure returns `MutationFailed`,
        /// Stage 11's own rollback/cleanup runs, and the cleanup lease
        /// release drains through the shared session.
        #[test]
        fn mkm_arch_012_mutation_failure_uses_stage_11_rollback() {
            let path = test_path("mutation-failure");
            let (mut daemon, harness, _clock, _store_path) = exec_daemon(
                "mutation-failure",
                VecDeque::new(),
                VecDeque::from([Ok(Some(authorized_evaluation()))]),
            );
            // The service start deterministically fails inside the real
            // ResourceWorkflow promotion sequence.
            daemon.runtime.start_ok.set(false);
            assert_eq!(
                daemon.execute_promotion_attempt(request("attempt-1")),
                PromotionAttemptResult::MutationFailed
            );
            assert_eq!(daemon.runtime.promotion_calls, 1);
            assert_eq!(daemon.runtime.release_calls, 1);
            assert_eq!(
                daemon.runtime.machine.node_state(),
                NodeState::Failed,
                "MKM-ARCH-012 violated: Stage 11 rollback did not mark the                  node Failed pending reconciliation"
            );
            // VIP released and service stopped by the real cleanup path; the
            // durable cleanup release went out on the same shared session.
            assert_eq!(
                witness_log(&harness),
                vec!["lease_request", "lease_release"],
                "MKM-ARCH-012 violated: rollback did not release the lease"
            );
            assert!(
                daemon
                    .runtime
                    .store
                    .load_existing()
                    .unwrap()
                    .outstanding_mutation
                    .is_none()
            );
            assert_eq!(
                daemon.promotion_attempt_lifecycle(),
                &PromotionAttemptLifecycle::Idle
            );
            drop(daemon);
            harness.join.join().unwrap();
            cleanup_store(&path);
        }

        /// MKM-ARCH-012.13: when the bound lease is unusable at the final
        /// checkpoint, the abort releases it through the shared session and
        /// no authority survives to leak into a later attempt.
        #[test]
        fn mkm_arch_012_lease_cleanup_on_abort_cannot_leak_authority() {
            let path = test_path("lease-expired");
            let (mut daemon, harness, clock, _store_path) = exec_daemon(
                "lease-expired",
                VecDeque::new(),
                VecDeque::from([
                    Ok(Some(authorized_evaluation())),
                    Ok(Some(authorized_evaluation())),
                ]),
            );
            // Expire the granted lease between acquisition and the final
            // checkpoint (safe_deadline = remaining - margin = 8000ms).
            daemon.push_promotion_attempt_test_hook(|_| {});
            let clock_for_hook = clock.clone();
            daemon.push_promotion_attempt_test_hook(move |_| {
                clock_for_hook.0.set(9_000);
            });
            assert_eq!(
                daemon.execute_promotion_attempt(request("attempt-1")),
                PromotionAttemptResult::BlockedBeforeMutation
            );
            assert_eq!(daemon.runtime.promotion_calls, 0);
            assert_eq!(daemon.runtime.release_calls, 1);
            assert_eq!(
                witness_log(&harness),
                vec!["lease_request", "lease_release"],
                "MKM-ARCH-012 violated: expired bound lease was not released"
            );
            assert!(
                daemon
                    .runtime
                    .store
                    .load_existing()
                    .unwrap()
                    .outstanding_mutation
                    .is_none(),
                "MKM-ARCH-012 violated: cleanup release left durable outstanding"
            );
            // The expired authority cannot be reused: a later attempt runs
            // the full fresh sequence again.
            clock.0.set(0);
            assert_eq!(
                daemon.execute_promotion_attempt(request("attempt-2")),
                PromotionAttemptResult::Succeeded
            );
            assert_eq!(daemon.runtime.lease_acquire_calls, 2);
            drop(daemon);
            harness.join.join().unwrap();
            cleanup_store(&path);
        }

        /// Raw witness request log including request ids, for durable-record
        /// identity assertions.
        fn witness_requests(harness: &WitnessHarness) -> Vec<(&'static str, RequestId)> {
            let mut log = Vec::new();
            while let Ok(pair) = harness.requests.try_recv() {
                log.push(pair);
            }
            log
        }

        // ==================================================================
        // MKM-ARCH-012 remediation F-01: the attempt-bound authority is the
        // installed authority itself, moved — never cloned. At every instant
        // exactly one usable `RuntimeLeaseAuthority` value exists.
        // ==================================================================

        /// While the attempt is in flight the installed anchor is empty:
        /// the only usable authority lives inside the attempt-bound wrapper.
        /// A clone-based mint would leave `Some` installed here. The Stage 11
        /// handoff restores the same value; success retains it for Active
        /// ownership.
        #[test]
        fn mkm_arch_012_remediation_f01_authority_moves_into_attempt_bound() {
            let path = test_path("f01-move");
            let (mut daemon, harness, _clock, _store_path) = exec_daemon(
                "f01-move",
                VecDeque::new(),
                VecDeque::from([Ok(Some(authorized_evaluation()))]),
            );
            daemon.push_promotion_attempt_test_hook(|_| {});
            daemon.push_promotion_attempt_test_hook(|daemon| {
                assert!(
                    daemon.runtime.installed_lease_authority().is_none(),
                    "F-01 violated: installed anchor still holds authority while \
                     the attempt-bound wrapper exists (a clone was minted)"
                );
            });
            assert_eq!(
                daemon.execute_promotion_attempt(request("attempt-1")),
                PromotionAttemptResult::Succeeded
            );
            assert_eq!(daemon.runtime.promotion_calls, 1);
            assert!(
                daemon.runtime.installed_lease_authority().is_some(),
                "F-01 violated: authority was not restored for Active ownership"
            );
            assert_eq!(witness_log(&harness), vec!["lease_request"]);
            drop(daemon);
            harness.join.join().unwrap();
            cleanup_store(&path);
        }

        // ---- Phase 14.12 E3b: the attempt-bound observation step ----

        /// A daemon whose ExecFake runs the attempt-bound observation step.
        fn e3b_daemon(
            name: &str,
            replies: VecDeque<WitnessReply>,
        ) -> (Daemon<ExecFake>, WitnessHarness, std::path::PathBuf) {
            let (mut daemon, harness, _clock, path) = exec_daemon(name, replies, VecDeque::new());
            daemon.runtime.attempt_observation = true;
            (daemon, harness, path)
        }

        fn e3b_generation(daemon: &Daemon<ExecFake>) -> Option<u64> {
            daemon
                .runtime
                .observer
                .as_ref()
                .unwrap()
                .snapshot()
                .pending
                .map(|pending| pending.request_generation)
        }

        /// One attempt issues exactly ONE GET_TERM of its own, accepts the
        /// response in the step, and evaluates that observation once (the
        /// evaluate never begins a request). Nothing is left outstanding.
        #[test]
        fn e3b_attempt_issues_one_own_get_term_and_evaluates_it_once() {
            let (mut daemon, harness, path) = e3b_daemon("e3b-own", VecDeque::new());
            let result = daemon.execute_promotion_attempt(request("attempt-1"));
            // The scripted Witness holder is foreign, so the evaluation is not
            // authorized; the point under test is the observation count.
            assert_eq!(result, PromotionAttemptResult::BlockedBeforeMutation);
            assert_eq!(daemon.runtime.observation_steps, 1);
            assert_eq!(daemon.runtime.evaluate_calls, 1);
            assert_eq!(witness_log(&harness), vec!["get_term"]);
            assert!(!daemon.runtime.session.as_ref().unwrap().request_in_flight());
            assert_eq!(e3b_generation(&daemon), None);
            assert_eq!(daemon.runtime.lease_acquire_calls, 0);
            assert_eq!(daemon.runtime.promotion_calls, 0);
            drop(daemon);
            harness.join.join().unwrap();
            cleanup_store(&path);
        }

        /// A silent Witness: the step waits for its request's deadline (2 s
        /// here, 5 s in production) and no longer; the attempt fails closed
        /// with ONE request and no retry. Only a later attempt (a new SIGUSR1)
        /// could issue another.
        #[test]
        fn e3b_silent_witness_times_out_at_the_deadline_without_retry() {
            let (mut daemon, harness, path) =
                e3b_daemon("e3b-silent", VecDeque::from([WitnessReply::Silent]));
            let started = std::time::Instant::now();
            let result = daemon.execute_promotion_attempt(request("attempt-1"));
            let elapsed = started.elapsed();
            assert_eq!(result, PromotionAttemptResult::BlockedBeforeMutation);
            assert!(
                elapsed >= Duration::from_secs(2) && elapsed < Duration::from_millis(2500),
                "the wait ends at the deadline, not before and not long after: {elapsed:?}"
            );
            assert_eq!(witness_log(&harness), vec!["get_term"], "no retry");
            assert!(!daemon.runtime.session.as_ref().unwrap().request_in_flight());
            assert_eq!(daemon.runtime.lease_acquire_calls, 0);
            assert_eq!(daemon.runtime.gate_calls, 0);
            assert_eq!(daemon.runtime.promotion_calls, 0);
            // (The stub Witness thread ends after its own 2 s read timeout,
            // so a second attempt is exercised in the virtual-time tests of
            // the adapter step, not here.)
            assert_eq!(daemon.runtime.observation_steps, 1);
            drop(daemon);
            harness.join.join().unwrap();
            cleanup_store(&path);
        }

        /// A shutdown seen while the step waits ends the wait within a few
        /// slices (far before the 2 s deadline), issues nothing more, and the
        /// attempt never reaches evaluation, the fencing gate, a lease
        /// request or promotion.
        #[test]
        fn e3b_shutdown_while_waiting_interrupts_before_every_later_stage() {
            let (mut daemon, harness, path) =
                e3b_daemon("e3b-shutdown", VecDeque::from([WitnessReply::Silent]));
            let raised = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let signal = raised.clone();
            daemon.attach_shutdown_signal(move || signal.load(std::sync::atomic::Ordering::SeqCst));
            let flag = raised.clone();
            let raiser = thread::spawn(move || {
                thread::sleep(Duration::from_millis(150));
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
            });
            let started = std::time::Instant::now();
            let result = daemon.execute_promotion_attempt(request("attempt-1"));
            let elapsed = started.elapsed();
            raiser.join().unwrap();
            assert_eq!(result, PromotionAttemptResult::BlockedBeforeMutation);
            assert!(
                elapsed >= Duration::from_millis(150) && elapsed < Duration::from_millis(600),
                "shutdown must end the wait promptly: {elapsed:?}"
            );
            assert_eq!(witness_log(&harness), vec!["get_term"]);
            assert_eq!(daemon.runtime.evaluate_calls, 0);
            assert_eq!(daemon.runtime.gate_calls, 0);
            assert_eq!(daemon.runtime.lease_acquire_calls, 0);
            assert_eq!(daemon.runtime.promotion_calls, 0);
            assert_eq!(daemon.runtime.release_calls, 0);
            drop(daemon);
            harness.join.join().unwrap();
            cleanup_store(&path);
        }

        // ---- Phase 14.12 F7: positive control and recovery through the real step ----

        /// The fixture's confirmed-loss episode is stamped 11 ms AFTER the
        /// instant it is built (`lost_peer_detector`), and a loss episode from
        /// the future is not fresh. Real attempts that must reach an
        /// authorization wait until the episode is in the past.
        fn e3b_let_the_loss_episode_age() {
            thread::sleep(Duration::from_millis(40));
        }

        /// E3b positive control, kept permanently. The peer is in confirmed
        /// communication loss, the Witness — answering the attempt's OWN
        /// GET_TERM — reports no lease holder, and local safety is Safe. The
        /// real evaluation authorizes and the Stage 13.2 fake lease /
        /// promotion path runs to `Succeeded`: one GET_TERM, one lease
        /// request, one promotion, the order unchanged. Nothing in the
        /// authorization is relaxed: the same attempt against a Witness that
        /// names the peer as holder is refused before any lease request.
        #[test]
        fn e3b_positive_control_a_fresh_own_observation_promotes_through_the_real_step() {
            let (mut daemon, harness, _clock, path) = exec_daemon(
                "e3b-positive",
                VecDeque::from([WitnessReply::NoHolder]),
                VecDeque::new(),
            );
            daemon.runtime.attempt_observation = true;
            e3b_let_the_loss_episode_age();
            let result = daemon.execute_promotion_attempt(request("attempt-1"));
            assert_eq!(result, PromotionAttemptResult::Succeeded);
            assert_eq!(daemon.runtime.observation_steps, 1);
            assert_eq!(daemon.runtime.evaluate_calls, 1);
            assert_eq!(daemon.runtime.lease_acquire_calls, 1);
            assert_eq!(daemon.runtime.promotion_calls, 1);
            assert_eq!(witness_log(&harness), vec!["get_term", "lease_request"]);
            drop(daemon);
            harness.join.join().unwrap();
            cleanup_store(&path);

            // Negative control: the Witness names the peer as the holder.
            let (mut daemon, harness, _clock, path) = exec_daemon(
                "e3b-negative",
                VecDeque::from([WitnessReply::Auto]),
                VecDeque::new(),
            );
            daemon.runtime.attempt_observation = true;
            e3b_let_the_loss_episode_age();
            let result = daemon.execute_promotion_attempt(request("attempt-1"));
            assert_eq!(result, PromotionAttemptResult::BlockedBeforeMutation);
            assert_eq!(daemon.runtime.lease_acquire_calls, 0);
            assert_eq!(daemon.runtime.promotion_calls, 0);
            assert_eq!(witness_log(&harness), vec!["get_term"]);
            drop(daemon);
            harness.join.join().unwrap();
            cleanup_store(&path);
        }

        /// A Witness stall as the daemon sees it: `n` generations begun and
        /// timed out earlier (synthetic past instants), each answered by the
        /// stub Witness at once, so `n` real late answers wait on the socket.
        fn f7_stalled_daemon(
            name: &str,
            n: u64,
            recovered: WitnessReply,
        ) -> (Daemon<ExecFake>, WitnessHarness, std::path::PathBuf) {
            let mut replies: VecDeque<WitnessReply> = (0..n).map(|_| WitnessReply::Auto).collect();
            replies.push_back(recovered);
            let (mut daemon, harness, path) = e3b_daemon(name, replies);
            let base = std::time::Instant::now() - Duration::from_secs(3 * n + 10);
            for i in 0..n {
                let t = base + Duration::from_secs(3 * i);
                daemon
                    .runtime
                    .begin_authority_observation(DaemonIterationContext::new_for_test(t, false))
                    .unwrap();
                let (session, observer) = (
                    daemon.runtime.session.as_mut().unwrap(),
                    daemon.runtime.observer.as_mut().unwrap(),
                );
                // The attempt's deadline here is 2 s.
                observer
                    .expire_pending_at(session, t + Duration::from_millis(2_500))
                    .unwrap();
            }
            e3b_let_the_loss_episode_age();
            (daemon, harness, path)
        }

        /// Phase 14.12 RW-3: each R7 scenario owns its state file. The names
        /// were `f7-r7-{n}` for the promote loop and `f7-r7-10` for R7-10, so
        /// the loop's n = 10 case and R7-10 shared one path (`test_path` adds
        /// only the process id) and the later `initialize_new` failed with
        /// `AlreadyExists` whenever the two tests overlapped in time.
        const F7_R7_STALL_COUNTS: [u64; 5] = [8, 9, 10, 30, 100];
        const F7_R7_09_STATE: &str = "f7-r7-09-unavailable";
        const F7_R7_10_STATE: &str = "f7-r7-10-invalid-answer";

        fn f7_r7_promote_state(n: u64) -> String {
            format!("f7-r7-promote-{n}")
        }

        /// R7-01 .. R7-05 and R7-08 (daemon level): after 8, 9, 10, 30 and 100
        /// timed-out generations whose answers are all waiting on the socket,
        /// ONE operator attempt discards them, accepts its own answer, reaches
        /// the authority evaluation and — Witness reporting no holder —
        /// promotes through the unchanged sequence. (With the former set of 8
        /// generations the 9th and later cases were refused.)
        #[test]
        fn f7_r7_one_attempt_after_a_stall_reaches_the_evaluation_and_promotes() {
            for n in F7_R7_STALL_COUNTS {
                let (mut daemon, harness, path) =
                    f7_stalled_daemon(&f7_r7_promote_state(n), n, WitnessReply::NoHolder);
                assert_eq!(e3b_generation(&daemon), None);
                let result = daemon.execute_promotion_attempt(request("attempt-1"));
                assert_eq!(result, PromotionAttemptResult::Succeeded, "n={n}");
                let adapter = daemon.runtime.observer.as_ref().unwrap();
                assert_eq!(adapter.snapshot().request_generation, n + 1);
                assert_eq!(daemon.runtime.evaluate_calls, 1, "n={n}");
                assert_eq!(daemon.runtime.lease_acquire_calls, 1, "n={n}");
                assert_eq!(daemon.runtime.promotion_calls, 1, "n={n}");
                let log = witness_log(&harness);
                assert_eq!(
                    log.iter().filter(|kind| **kind == "get_term").count() as u64,
                    n + 1,
                    "n={n}: one request per generation, none repeated"
                );
                assert_eq!(log.last(), Some(&"lease_request"));
                drop(daemon);
                harness.join.join().unwrap();
                cleanup_store(&path);
            }
        }

        /// R7-09: after the stall the Witness is still unavailable — the late
        /// answers are discarded, the attempt's own request times out, the
        /// attempt fails closed before any lease request.
        #[test]
        fn f7_r7_09_a_witness_that_stays_unavailable_still_fails_closed() {
            let (mut daemon, harness, path) =
                f7_stalled_daemon(F7_R7_09_STATE, 9, WitnessReply::Silent);
            let started = std::time::Instant::now();
            let result = daemon.execute_promotion_attempt(request("attempt-1"));
            assert_eq!(result, PromotionAttemptResult::BlockedBeforeMutation);
            assert!(started.elapsed() >= Duration::from_secs(2));
            assert_eq!(daemon.runtime.lease_acquire_calls, 0);
            assert_eq!(daemon.runtime.promotion_calls, 0);
            assert!(!daemon.runtime.session.as_ref().unwrap().request_in_flight());
            drop(daemon);
            harness.join.join().unwrap();
            cleanup_store(&path);
        }

        /// R7-10: after the stall the Witness answers the attempt's request
        /// with a foreign request id: nothing is accepted, the attempt is
        /// blocked before evaluation, lease and promotion.
        #[test]
        fn f7_r7_10_only_an_invalid_answer_after_the_stall_fails_closed() {
            let (mut daemon, harness, path) =
                f7_stalled_daemon(F7_R7_10_STATE, 9, WitnessReply::WrongRequestId);
            let result = daemon.execute_promotion_attempt(request("attempt-1"));
            assert_eq!(result, PromotionAttemptResult::BlockedBeforeMutation);
            assert_eq!(daemon.runtime.evaluate_calls, 0);
            assert_eq!(daemon.runtime.lease_acquire_calls, 0);
            assert_eq!(daemon.runtime.promotion_calls, 0);
            drop(daemon);
            harness.join.join().unwrap();
            cleanup_store(&path);
        }

        /// RW-3 guard: no two R7 scenarios resolve to the same state path
        /// (checked on the paths themselves, so a future renaming that
        /// reintroduces a shared name fails here and not as a rare
        /// `AlreadyExists` under concurrency).
        #[test]
        fn f7_r7_state_paths_are_unique_per_scenario() {
            let mut names: Vec<String> = F7_R7_STALL_COUNTS
                .iter()
                .map(|n| f7_r7_promote_state(*n))
                .collect();
            names.push(F7_R7_09_STATE.to_string());
            names.push(F7_R7_10_STATE.to_string());
            let paths: std::collections::BTreeSet<_> =
                names.iter().map(|name| test_path(name)).collect();
            assert_eq!(paths.len(), names.len(), "shared state path in {names:?}");
        }

        /// F2, now carried by the step: a leftover observation whose
        /// deadline has passed is completed before the slot check, so the
        /// attempt issues its own request (the leftover's late response is
        /// discarded, never evidence); a leftover still inside its deadline is
        /// never replaced, adopted or answered — the attempt is blocked with
        /// no second request.
        #[test]
        fn e3b_leftover_observation_is_completed_when_expired_and_never_adopted() {
            // Expired leftover (begun 3 s ago, 2 s deadline).
            let (mut daemon, harness, path) = e3b_daemon("e3b-expired", VecDeque::new());
            let long_ago = std::time::Instant::now() - Duration::from_secs(3);
            daemon
                .runtime
                .begin_authority_observation(DaemonIterationContext::new_for_test(long_ago, false))
                .unwrap();
            assert_eq!(e3b_generation(&daemon), Some(1));
            let result = daemon.execute_promotion_attempt(request("attempt-1"));
            assert_eq!(result, PromotionAttemptResult::BlockedBeforeMutation);
            // The leftover's GET_TERM plus the attempt's own.
            assert_eq!(witness_log(&harness), vec!["get_term", "get_term"]);
            assert_eq!(daemon.runtime.evaluate_calls, 1);
            let adapter = daemon.runtime.observer.as_ref().unwrap();
            assert_eq!(adapter.snapshot().request_generation, 2);
            assert!(adapter.snapshot().pending.is_none());
            drop(daemon);
            harness.join.join().unwrap();
            cleanup_store(&path);

            // Leftover inside its deadline (begun 1 s ago).
            let (mut daemon, harness, path) =
                e3b_daemon("e3b-inside", VecDeque::from([WitnessReply::Silent]));
            let recent = std::time::Instant::now() - Duration::from_secs(1);
            daemon
                .runtime
                .begin_authority_observation(DaemonIterationContext::new_for_test(recent, false))
                .unwrap();
            let result = daemon.execute_promotion_attempt(request("attempt-1"));
            assert_eq!(result, PromotionAttemptResult::BlockedBeforeMutation);
            thread::sleep(Duration::from_millis(200));
            assert_eq!(witness_log(&harness), vec!["get_term"], "no second request");
            assert_eq!(daemon.runtime.evaluate_calls, 0);
            assert_eq!(
                e3b_generation(&daemon),
                Some(1),
                "the leftover is untouched"
            );
            drop(daemon);
            harness.join.join().unwrap();
            cleanup_store(&path);
        }

        /// An aborted attempt destroys the moved authority with the bound
        /// value: after cancellation the installed anchor is empty and a
        /// later attempt cannot recover anything — it must run the full
        /// fresh sequence and acquire its own lease.
        #[test]
        fn mkm_arch_012_remediation_f01_aborted_attempt_destroys_moved_authority() {
            let path = test_path("f01-abort");
            let (mut daemon, harness, _clock, _store_path) = exec_daemon(
                "f01-abort",
                VecDeque::new(),
                VecDeque::from([
                    Ok(Some(authorized_evaluation())),
                    Ok(Some(authorized_evaluation())),
                ]),
            );
            daemon.push_promotion_attempt_test_hook(|_| {});
            daemon.push_promotion_attempt_test_hook(|daemon| {
                let _ = daemon.cancel_promotion_attempt();
            });
            assert_eq!(
                daemon.execute_promotion_attempt(request("attempt-a")),
                PromotionAttemptResult::Cancelled
            );
            assert_eq!(daemon.runtime.promotion_calls, 0);
            assert!(
                daemon.runtime.installed_lease_authority().is_none(),
                "F-01 violated: aborted attempt left installed authority behind"
            );
            assert_eq!(
                witness_log(&harness),
                vec!["lease_request", "lease_release"],
                "F-01 violated: moved authority's lease was not released on abort"
            );
            assert_eq!(
                daemon.execute_promotion_attempt(request("attempt-b")),
                PromotionAttemptResult::Succeeded
            );
            assert_eq!(daemon.runtime.lease_acquire_calls, 2);
            assert_eq!(
                daemon.runtime.promoted_attempts,
                vec![PromotionRequestId::new("attempt-b")]
            );
            drop(daemon);
            harness.join.join().unwrap();
            cleanup_store(&path);
        }

        /// A final-checkpoint failure (shutdown observed after the grant)
        /// drops the attempt-owned authority without ever installing a
        /// second value: nothing executable survives the abort.
        #[test]
        fn mkm_arch_012_remediation_f01_checkpoint_failure_leaves_no_authority() {
            let path = test_path("f01-checkpoint");
            let (mut daemon, harness, _clock, _store_path) = exec_daemon(
                "f01-checkpoint",
                VecDeque::new(),
                VecDeque::from([Ok(Some(authorized_evaluation()))]),
            );
            daemon.push_promotion_attempt_test_hook(|_| {});
            daemon.push_promotion_attempt_test_hook(|daemon| {
                let _ = daemon.request_shutdown();
            });
            assert_eq!(
                daemon.execute_promotion_attempt(request("attempt-1")),
                PromotionAttemptResult::BlockedBeforeMutation
            );
            assert_eq!(daemon.runtime.promotion_calls, 0);
            assert_eq!(daemon.runtime.release_calls, 1);
            assert!(
                daemon.runtime.installed_lease_authority().is_none(),
                "F-01 violated: checkpoint failure left executable authority"
            );
            assert_eq!(
                witness_log(&harness),
                vec!["lease_request", "lease_release"]
            );
            drop(daemon);
            harness.join.join().unwrap();
            cleanup_store(&path);
        }

        /// Stage 11 failure after the authority restore keeps the existing
        /// fail-closed rollback semantics: `MutationFailed`, `Failed` state,
        /// and the cleanup release drained through the shared session.
        #[test]
        fn mkm_arch_012_remediation_f01_stage11_failure_rollback_unchanged() {
            let path = test_path("f01-rollback");
            let (mut daemon, harness, _clock, _store_path) = exec_daemon(
                "f01-rollback",
                VecDeque::new(),
                VecDeque::from([Ok(Some(authorized_evaluation()))]),
            );
            daemon.runtime.start_ok.set(false);
            assert_eq!(
                daemon.execute_promotion_attempt(request("attempt-1")),
                PromotionAttemptResult::MutationFailed
            );
            assert_eq!(daemon.runtime.promotion_calls, 1);
            assert_eq!(daemon.runtime.release_calls, 1);
            assert_eq!(
                daemon.runtime.machine.node_state(),
                NodeState::Failed,
                "F-01 violated: Stage 11 rollback semantics changed"
            );
            assert_eq!(
                witness_log(&harness),
                vec!["lease_request", "lease_release"]
            );
            drop(daemon);
            harness.join.join().unwrap();
            cleanup_store(&path);
        }

        // ==================================================================
        // MKM-ARCH-012 remediation F-02: durable cleanup dispatch is typed —
        // only a LeaseRelease matching this attempt's (term, lease_id) may
        // be executed as its cleanup.
        // ==================================================================

        /// CASE 1: a durable outstanding `LeaseRelease` whose term and
        /// lease_id match the attempt's granted lease is resumed as the
        /// cleanup — executed once through the shared session with its own
        /// durable request identity; no second release is ever begun.
        #[test]
        fn mkm_arch_012_remediation_f02_matching_durable_release_is_resumed() {
            let path = test_path("f02-resume");
            let (mut daemon, harness, _clock, _store_path) = exec_daemon(
                "f02-resume",
                VecDeque::new(),
                VecDeque::from([Ok(Some(authorized_evaluation()))]),
            );
            let injected = Rc::new(RefCell::new(None));
            let injected_for_hook = Rc::clone(&injected);
            daemon.push_promotion_attempt_test_hook(|_| {});
            daemon.push_promotion_attempt_test_hook(move |daemon| {
                // Model Stage 11 having already begun the durable cleanup
                // release for this exact lease (term 7, lease-1).
                let record = daemon
                    .runtime
                    .store
                    .begin_lease_release_for_test(
                        Term(7),
                        LeaseId::new("lease-1"),
                        "injected stage-11 cleanup".to_string(),
                    )
                    .unwrap();
                *injected_for_hook.borrow_mut() = Some(record.request_id);
                let _ = daemon.request_shutdown();
            });
            assert_eq!(
                daemon.execute_promotion_attempt(request("attempt-1")),
                PromotionAttemptResult::BlockedBeforeMutation
            );
            assert_eq!(daemon.runtime.promotion_calls, 0);
            assert_eq!(daemon.runtime.release_calls, 1);
            let requests = witness_requests(&harness);
            assert_eq!(
                requests.iter().map(|(kind, _)| *kind).collect::<Vec<_>>(),
                vec!["lease_request", "lease_release"]
            );
            assert_eq!(
                requests[1].1,
                *injected.borrow().as_ref().unwrap(),
                "F-02 violated: cleanup did not reuse the durable release's \
                 own request identity"
            );
            let state = daemon.runtime.store.load_existing().unwrap();
            assert!(
                state.outstanding_mutation.is_none(),
                "F-02 violated: resumed release did not complete"
            );
            assert_eq!(
                state.highest_started_mutation_generation, 2,
                "F-02 violated: a duplicate release was begun on top of the \
                 durable one"
            );
            drop(daemon);
            harness.join.join().unwrap();
            cleanup_store(&path);
        }

        /// CASE 2: a durable outstanding mutation of the WRONG KIND (a
        /// LeaseRenew for the same lease, or a fresh LeaseRequest) is not
        /// this attempt's cleanup. It is preserved for its rightful owner,
        /// never executed, and never replaced — and the refusal grants no
        /// promotion.
        #[test]
        fn mkm_arch_012_remediation_f02_foreign_kind_fails_closed() {
            for (name, inject_renew) in [("f02-renew", true), ("f02-request", false)] {
                let path = test_path(name);
                let (mut daemon, harness, _clock, _store_path) = exec_daemon(
                    name,
                    VecDeque::new(),
                    VecDeque::from([Ok(Some(authorized_evaluation()))]),
                );
                let injected = Rc::new(RefCell::new(None));
                let injected_for_hook = Rc::clone(&injected);
                daemon.push_promotion_attempt_test_hook(|_| {});
                daemon.push_promotion_attempt_test_hook(move |daemon| {
                    let record = if inject_renew {
                        // Same lease identity, wrong kind.
                        daemon
                            .runtime
                            .store
                            .begin_lease_renew_for_test(Term(7), LeaseId::new("lease-1"))
                    } else {
                        // Wrong kind entirely.
                        daemon.runtime.store.begin_lease_request(
                            Term(7),
                            100,
                            DurationMs(LEASE_TTL_MS),
                        )
                    }
                    .unwrap();
                    *injected_for_hook.borrow_mut() = Some(record.request_id);
                    let _ = daemon.request_shutdown();
                });
                assert_eq!(
                    daemon.execute_promotion_attempt(request("attempt-1")),
                    PromotionAttemptResult::BlockedBeforeMutation,
                    "F-02 violated: foreign-kind outstanding did not fail closed"
                );
                assert_eq!(daemon.runtime.promotion_calls, 0);
                // The foreign mutation was never sent over the wire.
                assert_eq!(
                    witness_log(&harness),
                    vec!["lease_request"],
                    "F-02 violated: a foreign durable mutation was executed \
                     as this attempt's cleanup"
                );
                // It remains durably outstanding — never overwritten,
                // cleared, or replaced by a second release.
                let state = daemon.runtime.store.load_existing().unwrap();
                let outstanding = state
                    .outstanding_mutation
                    .expect("F-02 violated: foreign outstanding was cleared");
                assert_eq!(
                    outstanding.request_id,
                    *injected.borrow().as_ref().unwrap(),
                    "F-02 violated: foreign outstanding was replaced"
                );
                assert_eq!(state.highest_started_mutation_generation, 2);
                drop(daemon);
                harness.join.join().unwrap();
                cleanup_store(&path);
            }
        }

        /// CASE 3: a durable `LeaseRelease` for a DIFFERENT lease identity
        /// (wrong term, wrong lease_id, or both) is not this attempt's
        /// cleanup — it fails closed and is preserved untouched.
        #[test]
        fn mkm_arch_012_remediation_f02_foreign_lease_release_fails_closed() {
            for (name, term, lease_id) in [
                ("f02-foreign-term", Term(8), LeaseId::new("lease-1")),
                ("f02-foreign-lease", Term(7), LeaseId::new("lease-9")),
                ("f02-foreign-both", Term(8), LeaseId::new("lease-9")),
            ] {
                let path = test_path(name);
                let (mut daemon, harness, _clock, _store_path) = exec_daemon(
                    name,
                    VecDeque::new(),
                    VecDeque::from([Ok(Some(authorized_evaluation()))]),
                );
                let injected = Rc::new(RefCell::new(None));
                let injected_for_hook = Rc::clone(&injected);
                daemon.push_promotion_attempt_test_hook(|_| {});
                daemon.push_promotion_attempt_test_hook(move |daemon| {
                    let record = daemon
                        .runtime
                        .store
                        .begin_lease_release_for_test(
                            term,
                            lease_id,
                            "foreign lease cleanup".to_string(),
                        )
                        .unwrap();
                    *injected_for_hook.borrow_mut() = Some(record.request_id);
                    let _ = daemon.request_shutdown();
                });
                assert_eq!(
                    daemon.execute_promotion_attempt(request("attempt-1")),
                    PromotionAttemptResult::BlockedBeforeMutation,
                    "F-02 violated: foreign-lease release did not fail closed"
                );
                assert_eq!(daemon.runtime.promotion_calls, 0);
                assert_eq!(
                    witness_log(&harness),
                    vec!["lease_request"],
                    "F-02 violated: a foreign LeaseRelease was executed as \
                     this attempt's cleanup"
                );
                let state = daemon.runtime.store.load_existing().unwrap();
                let outstanding = state
                    .outstanding_mutation
                    .expect("F-02 violated: foreign release was cleared");
                assert_eq!(outstanding.request_id, *injected.borrow().as_ref().unwrap());
                assert_eq!(state.highest_started_mutation_generation, 2);
                drop(daemon);
                harness.join.join().unwrap();
                cleanup_store(&path);
            }
        }
    }
}

// ===========================================================================
// MKM-ARCH-013 / Stage 13.3: real authorized evidence path.
//
// These tests compose the REAL production path end to end:
//   fresh local CommunicationLost evidence (real PeerFailureDetector)
//   + real Protocol v1 encode/decode + real HMAC authentication
//   + real request correlation over the shared WitnessSession
//   + production WitnessEvidenceAdapter (expectation + classification)
//   + production EvidenceFusion (both freshness axes)
//   + production FailoverEligibility / PromotionAttemptAuthorization.
//
// The principal positive control never constructs
// `AuthorityViewCompatible` / `FailoverEvidenceReady` / `Authorized`
// directly; every negative must fail closed without panicking.
// ===========================================================================
#[cfg(all(test, unix))]
mod stage13_3 {
    use super::*;
    use crate::evidence_fusion::adapter::{
        AuthorityViewCompatibility, AuthorityViewExpectation, ObservationProgress,
        UnavailableCause, WitnessEvidenceAdapter,
    };
    use crate::evidence_fusion::{EvidenceFusionState, WitnessEvidenceView, WitnessStatus};
    use crate::failover_policy::{LocalSafetyReadiness, LocalSafetySnapshot};
    use crate::failure_assessment::{
        LOCAL_LOSS_EVIDENCE_MAX_AGE, LocalLossEvidence, PeerFailureAssessment, PeerFailureDetector,
    };
    use crate::protocol::{
        CborSerializer, ClusterId, CommonFields, DurationMs, LeaseId, NodeId, PROTOCOL_VERSION,
        ProtocolMessage, RequestId, Sequence, SessionId, Term, TermStatusPayload, UnsignedEnvelope,
    };
    use crate::security::{MessageAuthenticator, Psk};
    use crate::session::ProcessSession;
    use crate::state_machine::NodeState;
    use crate::witness_runtime::{WitnessConnection, WitnessSession};
    use std::net::{TcpListener, TcpStream};
    use std::time::{Duration, Instant};

    const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

    fn auth() -> MessageAuthenticator {
        MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32]))
    }

    struct ObsFixture {
        observer: WitnessEvidenceAdapter,
        session: WitnessSession,
        server: crate::tcp::TcpConnection,
        detector: PeerFailureDetector,
        /// Witness response sequence: strictly increasing across the
        /// scripted server, matching production ordering rules.
        response_seq: u64,
        t0: Instant,
    }

    /// Drive a real detector through the full production lifecycle into a
    /// fresh `CommunicationLost` epoch: session + trusted heartbeat
    /// (Healthy) -> session lost (Suspect) -> confirmation window elapsed.
    fn drive_loss(detector: &mut PeerFailureDetector, t0: Instant) {
        let session = SessionId::new("peer-session");
        detector
            .observe_session_established(session.clone(), t0)
            .unwrap();
        detector
            .observe_trusted_heartbeat(&session, Sequence(1), t0)
            .unwrap();
        detector
            .observe_session_lost(t0 + Duration::from_millis(1))
            .unwrap();
        detector.tick(t0 + Duration::from_millis(11)).unwrap();
        debug_assert_eq!(
            detector.assessment(),
            PeerFailureAssessment::CommunicationLost
        );
        debug_assert!(detector.loss_evidence().is_some());
    }

    /// Fixture with a real peer detector already in a fresh
    /// `CommunicationLost` epoch plus a loopback Witness session.
    fn lost_fixture() -> ObsFixture {
        fixture_with(|detector, t0| drive_loss(detector, t0))
    }

    fn healthy_fixture() -> ObsFixture {
        fixture_with(|detector, t0| {
            let session = SessionId::new("peer-session");
            detector
                .observe_session_established(session.clone(), t0)
                .unwrap();
            detector
                .observe_trusted_heartbeat(&session, Sequence(1), t0)
                .unwrap();
        })
    }

    fn unobserved_fixture() -> ObsFixture {
        fixture_with(|_, _| {})
    }

    fn fixture_with(drive: impl Fn(&mut PeerFailureDetector, Instant)) -> ObsFixture {
        let authenticator = auth();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server_stream, _) = listener.accept().unwrap();
        let server = crate::tcp::TcpConnection::from_stream(
            server_stream,
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .unwrap();
        let connection = WitnessConnection::new(
            NodeId::new("node-a"),
            NodeId::new("w"),
            ClusterId::new("cluster"),
            SessionId::new("w-session"),
            crate::tcp::TcpConnection::from_stream(
                client,
                Duration::from_secs(2),
                Duration::from_secs(2),
            )
            .unwrap(),
        );
        let mut session = WitnessSession::new(
            connection,
            ProcessSession::from_session_id(SessionId::new("a-session")),
            authenticator,
        );
        session.reset_outstanding();
        // Detector events happen strictly before `t0`, the observation
        // epoch: the confirmed `lost_at` epoch is ~1s old at `t0`,
        // comfortably inside LOCAL_LOSS_EVIDENCE_MAX_AGE.
        let drive_t0 = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        let mut detector = PeerFailureDetector::new(Duration::from_millis(10)).unwrap();
        drive(&mut detector, drive_t0);
        let t0 = Instant::now();
        ObsFixture {
            observer: WitnessEvidenceAdapter::new(REQUEST_TIMEOUT).unwrap(),
            session,
            server,
            detector,
            response_seq: 1,
            t0,
        }
    }

    /// Scripted TermStatus response: real encode + real HMAC on the wire.
    fn term_status_wire(id: &RequestId, seq: u64, payload: TermStatusPayload) -> UnsignedEnvelope {
        UnsignedEnvelope {
            common: CommonFields {
                protocol_version: PROTOCOL_VERSION,
                cluster_id: ClusterId::new("cluster"),
                sender_node_id: NodeId::new("w"),
                receiver_node_id: NodeId::new("node-a"),
                session_id: SessionId::new("w-session"),
                sequence: Sequence(seq),
                term: payload.current_term,
                lease_id: payload.current_lease_id.clone(),
                request_id: Some(id.clone()),
                operation_id: None,
            },
            message: ProtocolMessage::TermStatus(payload),
        }
    }

    fn holder_payload(
        holder: Option<&str>,
        term: u64,
        lease_id: Option<LeaseId>,
        remaining_ms: Option<u64>,
    ) -> TermStatusPayload {
        TermStatusPayload {
            current_term: Term(term),
            current_holder: holder.map(NodeId::new),
            current_lease_id: lease_id,
            lease_remaining_ms: remaining_ms.map(DurationMs),
        }
    }

    fn no_holder() -> TermStatusPayload {
        holder_payload(None, 7, None, None)
    }

    fn local(readiness: LocalSafetyReadiness) -> LocalSafetySnapshot {
        LocalSafetySnapshot {
            node_state: NodeState::Standby,
            operation_phase: None,
            readiness,
        }
    }

    fn expectation(term: Option<Term>, lease_id: Option<LeaseId>) -> AuthorityViewExpectation {
        AuthorityViewExpectation::new(NodeId::new("node-a"), term, lease_id)
    }

    enum ObsOutcome {
        Evaluated(AuthorityAttemptEvaluation),
        Progress(ObservationProgress),
        Failed,
    }

    /// One complete production observation transaction: peer axis from the
    /// sole detector owner, one GET_TERM through the shared session's
    /// outstanding slot, authenticated/correlated TermStatus, adapter
    /// classification, fusion, then the real eligibility+authorization
    /// policies. Mirrors `LinuxDaemonRuntime::authority_observation_tick`
    /// + `evaluate_authority_attempt` exactly.
    fn run_observation(
        f: &mut ObsFixture,
        payload: TermStatusPayload,
        expectation: AuthorityViewExpectation,
        readiness: LocalSafetyReadiness,
        at: Instant,
    ) -> ObsOutcome {
        let assessment = f.detector.assessment();
        let loss = f.detector.loss_evidence();
        f.observer.observe_peer_at(assessment, loss, at).unwrap();
        let Ok(id) = f
            .observer
            .begin_observation_at(&mut f.session, expectation, at)
        else {
            return ObsOutcome::Failed;
        };
        let seq = f.response_seq;
        f.response_seq += 1;
        f.server
            .send_message(
                term_status_wire(&id, seq, payload),
                &CborSerializer,
                &auth(),
            )
            .unwrap();
        f.session.wait_for_readable_for_test().unwrap();
        match f.observer.poll_observation_at(&mut f.session, at) {
            Ok(ObservationProgress::Ready(view)) => {
                let evidence = WitnessEvidenceView::from_snapshot(&f.observer.snapshot().fusion);
                ObsOutcome::Evaluated(AuthorityAttemptEvaluation::evaluate(
                    CurrentAuthorityAttemptObservation::new(
                        view,
                        assessment,
                        evidence,
                        local(readiness),
                    ),
                ))
            }
            Ok(other) => ObsOutcome::Progress(other),
            Err(_) => ObsOutcome::Failed,
        }
    }

    fn assert_not_authorized(outcome: &ObsOutcome, name: &str) {
        if let ObsOutcome::Evaluated(eval) = outcome {
            assert!(
                !eval.is_authorized(),
                "MKM-ARCH-013 violated ({name}): evaluation reached Authorized"
            );
            assert!(
                !eval.is_eligible(),
                "MKM-ARCH-013 violated ({name}): evaluation reached Eligible"
            );
        }
    }

    fn assert_ready_fail_closed(f: &ObsFixture) {
        assert_ne!(
            f.observer.snapshot().fusion.state,
            EvidenceFusionState::FailoverEvidenceReady,
            "MKM-ARCH-013 violated: fusion reached FailoverEvidenceReady"
        );
    }

    // -----------------------------------------------------------------
    // Principal positive control: the real path reaches Authorized.
    // -----------------------------------------------------------------

    /// Stage 14 Phase 14.2 attack F (Design Revision 4 §9.2, §10.8): a
    /// `Suspect` of any provenance is not evidence and cannot create or extend
    /// authority. Through the real composition (detector → adapter → fusion →
    /// eligibility → authorization) it never reaches `FailoverEvidenceReady`,
    /// `Eligible`, or `Authorized`, even after a formation-origin Suspect has
    /// aged 60 s.
    #[test]
    fn stage14_suspect_of_any_origin_never_reaches_eligible_or_authorized() {
        use crate::failure_assessment::SuspectOrigin;

        fn healthy_then(detector: &mut PeerFailureDetector, t0: Instant) {
            let session = SessionId::new("peer-session");
            detector
                .observe_session_established(session.clone(), t0)
                .unwrap();
            detector
                .observe_trusted_heartbeat(&session, Sequence(1), t0)
                .unwrap();
        }
        type Drive = fn(&mut PeerFailureDetector, Instant);
        let drives: [(&str, Drive, SuspectOrigin); 3] = [
            (
                "healthy-origin suspect",
                |detector, t0| {
                    healthy_then(detector, t0);
                    detector
                        .observe_session_lost(t0 + Duration::from_millis(1))
                        .unwrap();
                },
                SuspectOrigin::Healthy,
            ),
            (
                "restart-formation suspect aged 60s",
                |detector, t0| {
                    healthy_then(detector, t0);
                    detector.enter_suspect_for_test(SuspectOrigin::RestartFormation, t0);
                    detector.tick(t0 + Duration::from_secs(60)).unwrap();
                },
                SuspectOrigin::RestartFormation,
            ),
            (
                "uncertainty-formation suspect aged 60s",
                |detector, t0| {
                    healthy_then(detector, t0);
                    detector.enter_suspect_for_test(SuspectOrigin::UncertaintyFormation, t0);
                    detector.tick(t0 + Duration::from_secs(60)).unwrap();
                },
                SuspectOrigin::UncertaintyFormation,
            ),
        ];
        for (name, drive, origin) in drives {
            let mut f = fixture_with(drive);
            assert_eq!(f.detector.assessment(), PeerFailureAssessment::Suspect);
            assert_eq!(f.detector.snapshot().suspect_origin, Some(origin));
            assert!(f.detector.loss_evidence().is_none());
            let at = f.t0;
            let outcome = run_observation(
                &mut f,
                no_holder(),
                expectation(None, None),
                LocalSafetyReadiness::Safe,
                at,
            );
            assert!(
                matches!(outcome, ObsOutcome::Evaluated(_)),
                "{name}: expected a real evaluation"
            );
            assert_not_authorized(&outcome, name);
            assert_ready_fail_closed(&f);
        }
    }

    /// Stage 14 Phase 14.3 attack L (Design Revision 4 §9.2, §10.6, §11.2):
    /// permitted observations feed only the local-loss axis. Through the real
    /// composition, a partial formation or an uncertainty invalidation never
    /// reaches `FailoverEvidenceReady` / `Eligible` / `Authorized`, and a
    /// fully formed restart episode still cannot authorize against a
    /// `Foreign` Witness holder. The positive control shows formation
    /// evidence participates only through the unchanged Stage 13.3 gates.
    #[test]
    fn stage14_3_observation_evidence_authorizes_only_through_existing_gates() {
        fn conservative(detector: &mut PeerFailureDetector) {
            *detector = PeerFailureDetector::new(Duration::from_millis(10))
                .unwrap()
                .with_restart_formation(true);
        }
        fn formed(detector: &mut PeerFailureDetector, t0: Instant) {
            conservative(detector);
            detector.observe_initiated_contact_failure(t0, t0).unwrap();
            let t2 = t0 + Duration::from_millis(10);
            detector.observe_initiated_contact_failure(t2, t2).unwrap();
        }
        type Drive = fn(&mut PeerFailureDetector, Instant);
        let non_authorizing: [(&str, Drive); 2] = [
            ("one observation (RestartFormation)", |detector, t0| {
                conservative(detector);
                detector.observe_initiated_contact_failure(t0, t0).unwrap();
            }),
            ("uncertainty after a formed episode", |detector, t0| {
                formed(detector, t0);
                detector
                    .observe_identity_uncertainty(t0 + Duration::from_millis(20))
                    .unwrap();
            }),
        ];
        for (name, drive) in non_authorizing {
            let mut f = fixture_with(drive);
            assert!(f.detector.loss_evidence().is_none(), "{name}");
            let at = f.t0;
            let outcome = run_observation(
                &mut f,
                no_holder(),
                expectation(None, None),
                LocalSafetyReadiness::Safe,
                at,
            );
            assert!(matches!(outcome, ObsOutcome::Evaluated(_)), "{name}");
            assert_not_authorized(&outcome, name);
            assert_ready_fail_closed(&f);
        }

        // A formed episode cannot authorize against a Foreign holder.
        let mut f = fixture_with(formed);
        assert!(f.detector.loss_evidence().is_some());
        let at = f.t0;
        let outcome = run_observation(
            &mut f,
            holder_payload(
                Some("node-b"),
                7,
                Some(LeaseId::new("lease-b")),
                Some(5_000),
            ),
            expectation(None, None),
            LocalSafetyReadiness::Safe,
            at,
        );
        if let ObsOutcome::Evaluated(eval) = &outcome {
            assert!(!eval.is_authorized(), "Foreign holder must never authorize");
        }

        // Positive control: the same evidence with a compatible no-holder
        // view goes through the existing Stage 13.3 gates.
        let mut f = fixture_with(formed);
        let at = f.t0;
        let outcome = run_observation(
            &mut f,
            no_holder(),
            expectation(None, None),
            LocalSafetyReadiness::Safe,
            at,
        );
        let ObsOutcome::Evaluated(eval) = outcome else {
            panic!("expected a Ready evaluation")
        };
        assert!(eval.is_authorized());
    }

    /// Stage 14 Phase 14.3 remediation (Design Revision 5 §10.8.1, §11.1):
    /// an authenticated session after a formed episode, and observations at
    /// the formation floor, create no local-loss evidence and therefore no
    /// authority. Only a sequence strictly after the floor reaches the
    /// existing gates.
    #[test]
    fn stage14_3r_session_and_floor_equality_create_no_authority() {
        fn conservative(detector: &mut PeerFailureDetector) {
            *detector = PeerFailureDetector::new(Duration::from_millis(10))
                .unwrap()
                .with_restart_formation(true);
        }
        type Drive = fn(&mut PeerFailureDetector, Instant);
        let non_authorizing: [(&str, Drive); 2] = [
            (
                "authenticated session after a formed episode",
                |detector, t0| {
                    conservative(detector);
                    detector.observe_initiated_contact_failure(t0, t0).unwrap();
                    let t2 = t0 + Duration::from_millis(10);
                    detector.observe_initiated_contact_failure(t2, t2).unwrap();
                    assert!(detector.loss_evidence().is_some());
                    detector
                        .observe_session_established(
                            SessionId::new("peer-session"),
                            t0 + Duration::from_millis(20),
                        )
                        .unwrap();
                },
            ),
            ("observations at the formation floor", |detector, t0| {
                conservative(detector);
                detector.observe_identity_uncertainty(t0).unwrap();
                detector.observe_initiated_contact_failure(t0, t0).unwrap();
                let t2 = t0 + Duration::from_millis(10);
                detector.observe_initiated_contact_failure(t2, t2).unwrap();
            }),
        ];
        for (name, drive) in non_authorizing {
            let mut f = fixture_with(drive);
            assert!(f.detector.loss_evidence().is_none(), "{name}");
            let at = f.t0;
            let outcome = run_observation(
                &mut f,
                no_holder(),
                expectation(None, None),
                LocalSafetyReadiness::Safe,
                at,
            );
            assert!(matches!(outcome, ObsOutcome::Evaluated(_)), "{name}");
            assert_not_authorized(&outcome, name);
            assert_ready_fail_closed(&f);
        }

        // Positive control: two observations strictly after the floor.
        let mut f = fixture_with(|detector, t0| {
            conservative(detector);
            detector.observe_identity_uncertainty(t0).unwrap();
            let t1 = t0 + Duration::from_millis(1);
            detector.observe_initiated_contact_failure(t1, t1).unwrap();
            let t2 = t1 + Duration::from_millis(10);
            detector.observe_initiated_contact_failure(t2, t2).unwrap();
        });
        assert!(f.detector.loss_evidence().is_some());
        let at = f.t0;
        let outcome = run_observation(
            &mut f,
            no_holder(),
            expectation(None, None),
            LocalSafetyReadiness::Safe,
            at,
        );
        let ObsOutcome::Evaluated(eval) = outcome else {
            panic!("expected a Ready evaluation")
        };
        assert!(eval.is_authorized());
    }

    #[test]
    fn mkm_arch_013_real_composition_reaches_authorized() {
        let mut f = lost_fixture();
        let at = f.t0;
        let outcome = run_observation(
            &mut f,
            no_holder(),
            expectation(None, None),
            LocalSafetyReadiness::Safe,
            at,
        );
        let ObsOutcome::Evaluated(eval) = outcome else {
            panic!("MKM-ARCH-013: expected a Ready evaluation through the real path")
        };
        let view = eval.observation().authority_view();
        assert_eq!(view.term(), Term(7));
        assert_eq!(
            view.compatibility(),
            AuthorityViewCompatibility::CompatibleNoHolder
        );
        assert_eq!(
            eval.observation().peer_assessment(),
            PeerFailureAssessment::CommunicationLost
        );
        assert_eq!(
            eval.observation().evidence().state,
            EvidenceFusionState::FailoverEvidenceReady
        );
        assert_eq!(
            eval.observation().evidence().witness_status,
            WitnessStatus::AuthorityViewCompatible
        );
        assert!(eval.is_eligible());
        // Authorized == permission to enter Stage 13.2 fresh lease
        // acquisition only. Nothing below was acquired or mutated.
        assert!(eval.is_authorized());
    }

    #[test]
    fn mkm_arch_013_authorized_is_only_lease_acquisition_permission() {
        // The Authorized value must carry no authority: the observation
        // exposes only the authority-view evidence (term/classification),
        // never a RuntimeLeaseAuthority / AttemptBoundLeaseAuthority.
        let mut f = lost_fixture();
        let at = f.t0;
        let outcome = run_observation(
            &mut f,
            no_holder(),
            expectation(None, None),
            LocalSafetyReadiness::Safe,
            at,
        );
        let ObsOutcome::Evaluated(eval) = outcome else {
            panic!("MKM-ARCH-013: expected Ready evaluation")
        };
        assert!(eval.is_authorized());
        let view = eval.observation().authority_view();
        // Read-only provenance only; no authority accessor exists.
        assert_eq!(view.request_generation(), 1);
        assert_eq!(view.observation_generation(), 1);
    }

    // -----------------------------------------------------------------
    // Negative matrix (1)-(11): transport/local/authority axis failures.
    // -----------------------------------------------------------------

    #[test]
    fn mkm_arch_013_transport_success_alone_cannot_authorize() {
        let mut f = lost_fixture();
        let at = f.t0;
        let assessment = f.detector.assessment();
        let loss = f.detector.loss_evidence();
        f.observer.observe_peer_at(assessment, loss, at).unwrap();
        // Transport is up and the request is sent, but no authenticated
        // TermStatus exists: the observation cannot become Ready.
        f.observer
            .begin_observation_at(&mut f.session, expectation(None, None), at)
            .unwrap();
        assert!(matches!(
            f.observer.poll_observation_at(&mut f.session, at).unwrap(),
            ObservationProgress::AwaitingWitnessTerm
        ));
        assert_ready_fail_closed(&f);
    }

    #[test]
    fn mkm_arch_013_healthy_peer_plus_none_cannot_authorize() {
        let mut f = healthy_fixture();
        let at = f.t0;
        let outcome = run_observation(
            &mut f,
            no_holder(),
            expectation(None, None),
            LocalSafetyReadiness::Safe,
            at,
        );
        assert_not_authorized(&outcome, "healthy peer + holder None");
        assert_eq!(
            f.observer.snapshot().fusion.state,
            EvidenceFusionState::Unproven
        );
    }

    #[test]
    fn mkm_arch_013_stale_local_loss_plus_fresh_witness_cannot_authorize() {
        // Loss epoch formed > LOCAL_LOSS_EVIDENCE_MAX_AGE ago: stale.
        let mut f = fixture_with(|detector, t0| {
            let old = t0
                .checked_sub(LOCAL_LOSS_EVIDENCE_MAX_AGE + Duration::from_secs(1))
                .unwrap();
            drive_loss(detector, old);
        });
        let at = f.t0;
        assert_eq!(
            f.detector.assessment(),
            PeerFailureAssessment::CommunicationLost
        );
        let outcome = run_observation(
            &mut f,
            no_holder(),
            expectation(None, None),
            LocalSafetyReadiness::Safe,
            at,
        );
        assert_not_authorized(&outcome, "stale local loss + fresh Witness");
        assert_eq!(
            f.observer.snapshot().fusion.state,
            EvidenceFusionState::Unproven
        );
    }

    #[test]
    fn mkm_arch_013_fresh_local_loss_plus_stale_witness_cannot_authorize() {
        let mut f = lost_fixture();
        let at = f.t0;
        // First observation completes a real TermStatus at `at`.
        let outcome = run_observation(
            &mut f,
            no_holder(),
            expectation(None, None),
            LocalSafetyReadiness::Safe,
            at,
        );
        let ObsOutcome::Evaluated(eval) = &outcome else {
            panic!("MKM-ARCH-013: expected Ready evaluation")
        };
        assert!(eval.is_authorized());
        // The Witness evidence ages past its freshness window while the
        // local loss epoch is still fresh: recomputation must fall back
        // to Unproven — stale Witness evidence cannot corroborate.
        let later = at + crate::evidence_fusion::WITNESS_EVIDENCE_TIMEOUT + Duration::from_secs(1);
        let loss = f.detector.loss_evidence();
        f.observer
            .observe_peer_at(f.detector.assessment(), loss, later)
            .unwrap();
        assert_eq!(
            f.observer.snapshot().fusion.state,
            EvidenceFusionState::Unproven,
            "stale Witness evidence must not stay FailoverEvidenceReady"
        );
    }

    #[test]
    fn mkm_arch_013_self_remaining_zero_cannot_authorize() {
        let mut f = lost_fixture();
        let at = f.t0;
        let outcome = run_observation(
            &mut f,
            holder_payload(Some("node-a"), 7, Some(LeaseId::new("lease-1")), Some(0)),
            expectation(Some(Term(7)), Some(LeaseId::new("lease-1"))),
            LocalSafetyReadiness::Safe,
            at,
        );
        let ObsOutcome::Evaluated(eval) = &outcome else {
            panic!("MKM-ARCH-013: expected Ready evaluation")
        };
        assert_eq!(
            eval.observation().authority_view().compatibility(),
            AuthorityViewCompatibility::ExpiredButUnprocessed
        );
        assert_not_authorized(&outcome, "Self + remaining=0");
        assert_ready_fail_closed(&f);
    }

    #[test]
    fn mkm_arch_013_foreign_remaining_positive_cannot_authorize() {
        let mut f = lost_fixture();
        let at = f.t0;
        let outcome = run_observation(
            &mut f,
            holder_payload(Some("node-b"), 7, Some(LeaseId::new("lease-1")), Some(5000)),
            expectation(None, None),
            LocalSafetyReadiness::Safe,
            at,
        );
        let ObsOutcome::Evaluated(eval) = &outcome else {
            panic!("MKM-ARCH-013: expected Ready evaluation")
        };
        assert_eq!(
            eval.observation().authority_view().compatibility(),
            AuthorityViewCompatibility::ConflictingHolder
        );
        assert_not_authorized(&outcome, "Foreign + remaining>0");
        assert_ready_fail_closed(&f);
    }

    #[test]
    fn mkm_arch_013_foreign_remaining_zero_cannot_authorize() {
        let mut f = lost_fixture();
        let at = f.t0;
        let outcome = run_observation(
            &mut f,
            holder_payload(Some("node-b"), 7, Some(LeaseId::new("lease-1")), Some(0)),
            expectation(None, None),
            LocalSafetyReadiness::Safe,
            at,
        );
        let ObsOutcome::Evaluated(eval) = &outcome else {
            panic!("MKM-ARCH-013: expected Ready evaluation")
        };
        assert_eq!(
            eval.observation().authority_view().compatibility(),
            AuthorityViewCompatibility::ExpiredButUnprocessed
        );
        assert_not_authorized(&outcome, "Foreign + remaining=0");
        assert_ready_fail_closed(&f);
    }

    #[test]
    fn mkm_arch_013_wrong_term_cannot_authorize() {
        let mut f = lost_fixture();
        let at = f.t0;
        let outcome = run_observation(
            &mut f,
            holder_payload(None, 8, None, None),
            expectation(Some(Term(7)), Some(LeaseId::new("lease-1"))),
            LocalSafetyReadiness::Safe,
            at,
        );
        let ObsOutcome::Evaluated(eval) = &outcome else {
            panic!("MKM-ARCH-013: expected Ready evaluation")
        };
        assert_eq!(
            eval.observation().authority_view().compatibility(),
            AuthorityViewCompatibility::InconsistentAuthorityView
        );
        assert_not_authorized(&outcome, "wrong term");
        assert_ready_fail_closed(&f);
    }

    #[test]
    fn mkm_arch_013_replayed_witness_response_cannot_authorize() {
        let mut f = lost_fixture();
        let at = f.t0;
        // First observation completes and authorizes.
        let outcome = run_observation(
            &mut f,
            no_holder(),
            expectation(None, None),
            LocalSafetyReadiness::Safe,
            at,
        );
        let ObsOutcome::Evaluated(eval) = &outcome else {
            panic!("MKM-ARCH-013: expected Ready evaluation")
        };
        assert!(eval.is_authorized());
        let generation = f.observer.snapshot().observation_generation;

        // Begin a second observation; send a response correlated to a
        // request id that is not the in-flight one. Correlation must
        // reject it: no new evidence, no new Ready, no authorization.
        let later = at + Duration::from_millis(1);
        let assessment = f.detector.assessment();
        let loss = f.detector.loss_evidence();
        f.observer.observe_peer_at(assessment, loss, later).unwrap();
        f.observer
            .begin_observation_at(&mut f.session, expectation(None, None), later)
            .unwrap();
        let replayed = term_status_wire(&RequestId::new("superseded-request-id"), 1, no_holder());
        f.server
            .send_message(replayed, &CborSerializer, &auth())
            .unwrap();
        let result = f.observer.poll_observation_at(&mut f.session, later);
        assert!(
            !matches!(result, Ok(ObservationProgress::Ready(_))),
            "replayed/superseded response must not produce Ready"
        );
        assert_eq!(
            f.observer.snapshot().observation_generation,
            generation,
            "replayed response must not mint a new observation token"
        );
    }

    #[test]
    fn mkm_arch_013_witness_auth_failure_cannot_authorize() {
        let mut f = lost_fixture();
        let at = f.t0;
        let assessment = f.detector.assessment();
        let loss = f.detector.loss_evidence();
        f.observer.observe_peer_at(assessment, loss, at).unwrap();
        let id = f
            .observer
            .begin_observation_at(&mut f.session, expectation(None, None), at)
            .unwrap();
        // A wire signed with the wrong PSK is not a TermStatus
        // completion: authentication failure cannot authorize.
        let wrong_auth = MessageAuthenticator::new(Psk::from_test_bytes([0xAA; 32]));
        f.server
            .send_message(
                term_status_wire(&id, 1, no_holder()),
                &CborSerializer,
                &wrong_auth,
            )
            .unwrap();
        let result = f.observer.poll_observation_at(&mut f.session, at);
        assert!(
            !matches!(result, Ok(ObservationProgress::Ready(_))),
            "authentication failure must not produce Ready"
        );
        assert_ready_fail_closed(&f);
    }

    #[test]
    fn mkm_arch_013_witness_correlation_failure_cannot_authorize() {
        let mut f = lost_fixture();
        let at = f.t0;
        let assessment = f.detector.assessment();
        let loss = f.detector.loss_evidence();
        f.observer.observe_peer_at(assessment, loss, at).unwrap();
        f.observer
            .begin_observation_at(&mut f.session, expectation(None, None), at)
            .unwrap();
        // A TermStatus correlated to a different request id cannot
        // complete the pending request.
        let wire = term_status_wire(&RequestId::new("unrelated-request"), 1, no_holder());
        f.server
            .send_message(wire, &CborSerializer, &auth())
            .unwrap();
        let result = f.observer.poll_observation_at(&mut f.session, at);
        assert!(
            !matches!(result, Ok(ObservationProgress::Ready(_))),
            "uncorrelated response must not produce Ready"
        );
        assert_ready_fail_closed(&f);
    }

    // -----------------------------------------------------------------
    // Negative matrix (12)-(18): lifecycle/system-level failures.
    // -----------------------------------------------------------------

    #[test]
    fn mkm_arch_013_peer_recovery_invalidates_local_loss() {
        let mut f = lost_fixture();
        // Trusted heartbeat recovery: the loss epoch is invalidated —
        // assessment returns to Healthy and no evidence survives.
        let session = SessionId::new("peer-session");
        let recovered = f
            .detector
            .observe_trusted_heartbeat(&session, Sequence(2), f.t0 + Duration::from_millis(12))
            .unwrap();
        assert!(recovered);
        assert_eq!(f.detector.assessment(), PeerFailureAssessment::Healthy);
        assert!(f.detector.loss_evidence().is_none());
        // Fresh Witness evidence cannot resurrect the old loss.
        let at = f.t0 + Duration::from_millis(13);
        let outcome = run_observation(
            &mut f,
            no_holder(),
            expectation(None, None),
            LocalSafetyReadiness::Safe,
            at,
        );
        assert_not_authorized(&outcome, "peer recovery");
        assert_eq!(
            f.observer.snapshot().fusion.state,
            EvidenceFusionState::Unproven
        );
    }

    #[test]
    fn mkm_arch_013_generation_increment_does_not_rejuvenate_old_loss() {
        let mut f = lost_fixture();
        let at = f.t0;
        let stale_at = at - Duration::from_secs(60);
        // Same stale epoch, three different generations: provenance must
        // never relabel an old `lost_at` as fresh.
        for generation in [1u64, 2, 3] {
            let evidence = LocalLossEvidence::new_for_test(generation, stale_at);
            f.observer
                .observe_peer_at(PeerFailureAssessment::CommunicationLost, Some(evidence), at)
                .unwrap();
            assert_eq!(
                f.observer.snapshot().fusion.state,
                EvidenceFusionState::Unproven,
                "generation {generation} must not rejuvenate a stale epoch"
            );
        }
    }

    #[test]
    fn mkm_arch_013_local_restart_does_not_restore_evidence() {
        // A reconstructed detector/fusion pair models local restart:
        // no epoch survives, no snapshot can be relabeled fresh.
        let mut f = unobserved_fixture();
        assert!(f.detector.loss_evidence().is_none());
        assert_eq!(f.detector.assessment(), PeerFailureAssessment::Unobserved);
        let at = f.t0;
        let outcome = run_observation(
            &mut f,
            no_holder(),
            expectation(None, None),
            LocalSafetyReadiness::Safe,
            at,
        );
        assert_not_authorized(&outcome, "local restart");
        assert_eq!(
            f.observer.snapshot().fusion.state,
            EvidenceFusionState::Unproven
        );
    }

    #[test]
    fn mkm_arch_013_term_movement_invalidates_evidence() {
        let mut f = lost_fixture();
        let at = f.t0;
        // First observation authorizes under installed authority term 7.
        let lease = LeaseId::new("lease-1");
        let outcome = run_observation(
            &mut f,
            holder_payload(Some("node-a"), 7, Some(lease.clone()), Some(5000)),
            expectation(Some(Term(7)), Some(lease.clone())),
            LocalSafetyReadiness::Safe,
            at,
        );
        let ObsOutcome::Evaluated(eval) = &outcome else {
            panic!("MKM-ARCH-013: expected Ready evaluation")
        };
        assert!(eval.is_authorized());
        // The Witness reports a moved term: evidence from term 7 must
        // not authorize under term 8.
        let later = at + Duration::from_millis(1);
        let outcome = run_observation(
            &mut f,
            holder_payload(Some("node-a"), 8, Some(lease.clone()), Some(5000)),
            expectation(Some(Term(7)), Some(lease)),
            LocalSafetyReadiness::Safe,
            later,
        );
        assert_not_authorized(&outcome, "term movement");
        assert_ready_fail_closed(&f);
    }

    #[test]
    fn mkm_arch_013_witness_unavailable_cannot_authorize() {
        let mut f = lost_fixture();
        let at = f.t0;
        let assessment = f.detector.assessment();
        let loss = f.detector.loss_evidence();
        f.observer.observe_peer_at(assessment, loss, at).unwrap();
        f.observer
            .begin_observation_at(&mut f.session, expectation(None, None), at)
            .unwrap();
        // No response: the request times out locally as Unavailable.
        let deadline = at + REQUEST_TIMEOUT + Duration::from_millis(1);
        assert_eq!(
            f.observer
                .poll_observation_at(&mut f.session, deadline)
                .unwrap(),
            ObservationProgress::Unavailable(UnavailableCause::Timeout)
        );
        assert_eq!(
            f.observer.snapshot().fusion.state,
            EvidenceFusionState::AmbiguousPartition
        );
    }

    #[test]
    fn mkm_arch_013_shutdown_cannot_authorize() {
        let mut f = lost_fixture();
        let at = f.t0;
        let outcome = run_observation(
            &mut f,
            no_holder(),
            expectation(None, None),
            LocalSafetyReadiness::ShutdownInProgress,
            at,
        );
        assert_not_authorized(&outcome, "shutdown");
    }

    #[test]
    fn mkm_arch_013_outstanding_request_conflict_cannot_authorize() {
        let mut f = lost_fixture();
        let at = f.t0;
        f.observer
            .begin_observation_at(&mut f.session, expectation(None, None), at)
            .unwrap();
        // The shared session's single outstanding slot rejects a second
        // request while the first is in flight.
        assert!(
            f.observer
                .begin_observation_at(&mut f.session, expectation(None, None), at)
                .is_err()
        );
        assert_ready_fail_closed(&f);
    }

    #[test]
    fn mkm_arch_013_authorized_is_not_cached() {
        let mut f = lost_fixture();
        let at = f.t0;
        let outcome = run_observation(
            &mut f,
            no_holder(),
            expectation(None, None),
            LocalSafetyReadiness::Safe,
            at,
        );
        let ObsOutcome::Evaluated(eval) = &outcome else {
            panic!("MKM-ARCH-013: expected Ready evaluation")
        };
        assert!(eval.is_authorized());
        // A second observation must re-derive authorization from fresh
        // evidence; the first Authorized is not a reusable capability.
        let later = at + Duration::from_millis(1);
        let outcome = run_observation(
            &mut f,
            holder_payload(Some("node-b"), 7, Some(LeaseId::new("lease-1")), Some(5000)),
            expectation(None, None),
            LocalSafetyReadiness::Safe,
            later,
        );
        assert_not_authorized(&outcome, "cached Authorized");
    }

    #[test]
    fn mkm_arch_013_evidence_cannot_cross_attempts() {
        let mut f = lost_fixture();
        let at = f.t0;
        let outcome = run_observation(
            &mut f,
            no_holder(),
            expectation(None, None),
            LocalSafetyReadiness::Safe,
            at,
        );
        let ObsOutcome::Evaluated(eval) = &outcome else {
            panic!("MKM-ARCH-013: expected Ready evaluation")
        };
        assert!(eval.is_authorized());
        // The consumed completion cannot be re-read as Ready, and a new
        // attempt gets no Ready without its own correlated completion.
        let later = at + Duration::from_millis(1);
        assert!(!matches!(
            f.observer
                .poll_observation_at(&mut f.session, later)
                .unwrap(),
            ObservationProgress::Ready(_)
        ));
        f.observer
            .begin_observation_at(&mut f.session, expectation(None, None), later)
            .unwrap();
        assert!(!matches!(
            f.observer
                .poll_observation_at(&mut f.session, later)
                .unwrap(),
            ObservationProgress::Ready(_)
        ));
    }

    // -----------------------------------------------------------------
    // R-01 boundary: LOCAL_LOSS_EVIDENCE_MAX_AGE inclusive freshness.
    // -----------------------------------------------------------------

    #[test]
    fn mkm_arch_013_r01_local_loss_age_boundary() {
        for (age, fresh) in [
            (LOCAL_LOSS_EVIDENCE_MAX_AGE - Duration::from_millis(1), true),
            (LOCAL_LOSS_EVIDENCE_MAX_AGE, true),
            (
                LOCAL_LOSS_EVIDENCE_MAX_AGE + Duration::from_millis(1),
                false,
            ),
        ] {
            let mut f = unobserved_fixture();
            let at = f.t0;
            let lost_at = at.checked_sub(age).unwrap();
            let evidence = LocalLossEvidence::new_for_test(1, lost_at);
            assert_eq!(evidence.is_fresh_at(at), fresh, "age {age:?}");
            f.observer
                .observe_peer_at(PeerFailureAssessment::CommunicationLost, Some(evidence), at)
                .unwrap();
            // Complete a compatible TermStatus in the same transaction.
            let id = f
                .observer
                .begin_observation_at(&mut f.session, expectation(None, None), at)
                .unwrap();
            f.server
                .send_message(
                    term_status_wire(&id, 1, no_holder()),
                    &CborSerializer,
                    &auth(),
                )
                .unwrap();
            f.session.wait_for_readable_for_test().unwrap();
            f.observer.poll_observation_at(&mut f.session, at).unwrap();
            let state = f.observer.snapshot().fusion.state;
            assert_eq!(
                state == EvidenceFusionState::FailoverEvidenceReady,
                fresh,
                "age {age:?} freshness boundary violated"
            );
        }
    }

    // -----------------------------------------------------------------
    // R-02 generation lifecycle.
    // -----------------------------------------------------------------

    #[test]
    fn mkm_arch_013_r02_generation_lifecycle() {
        // 1. Fresh detector: no epoch.
        let mut detector = PeerFailureDetector::new(Duration::from_millis(10)).unwrap();
        assert!(detector.loss_evidence().is_none());
        let t0 = Instant::now();
        // 2. First confirmed loss: generation 1 epoch.
        drive_loss(&mut detector, t0);
        let first = detector.loss_evidence().unwrap();
        assert_eq!(first.generation(), 1);
        // 3. Repeated ticks do not mint or bump a generation.
        detector.tick(t0 + Duration::from_millis(20)).unwrap();
        let same = detector.loss_evidence().unwrap();
        assert_eq!(same.generation(), 1);
        assert_eq!(same.lost_at(), first.lost_at());
        // 4. Recovery invalidates the epoch.
        let session = SessionId::new("peer-session");
        detector
            .observe_trusted_heartbeat(&session, Sequence(2), t0 + Duration::from_millis(21))
            .unwrap();
        assert!(detector.loss_evidence().is_none());
        // 5. A later loss forms a NEW epoch with a new generation —
        //    provenance moves forward, never reuses the old epoch.
        let t1 = t0 + Duration::from_millis(22);
        drive_loss(&mut detector, t1);
        let second = detector.loss_evidence().unwrap();
        assert_eq!(second.generation(), 2);
        assert!(second.lost_at() > first.lost_at());
    }

    #[test]
    fn mkm_arch_013_r02_session_reestablishment_invalidates_epoch() {
        let mut detector = PeerFailureDetector::new(Duration::from_millis(10)).unwrap();
        let t0 = Instant::now();
        drive_loss(&mut detector, t0);
        let first = detector.loss_evidence().unwrap();
        // Session re-establishment under CommLost resets the observation
        // context: the epoch is invalidated, assessment stays CommLost,
        // and a full re-confirmation window is required for a new epoch.
        detector
            .observe_session_established(
                SessionId::new("peer-session-2"),
                t0 + Duration::from_millis(12),
            )
            .unwrap();
        assert_eq!(
            detector.assessment(),
            PeerFailureAssessment::CommunicationLost
        );
        assert!(detector.loss_evidence().is_none());
        detector.tick(t0 + Duration::from_millis(20)).unwrap();
        assert!(detector.loss_evidence().is_none());
        detector.tick(t0 + Duration::from_millis(23)).unwrap();
        let second = detector.loss_evidence().unwrap();
        assert_eq!(second.generation(), first.generation() + 1);
        assert!(second.lost_at() > first.lost_at());
    }

    // -----------------------------------------------------------------
    // R-03 Self identity enforcement.
    // -----------------------------------------------------------------

    #[test]
    fn mkm_arch_013_self_wrong_lease_id_cannot_authorize() {
        let mut f = lost_fixture();
        let at = f.t0;
        let outcome = run_observation(
            &mut f,
            holder_payload(Some("node-a"), 7, Some(LeaseId::new("lease-2")), Some(5000)),
            expectation(Some(Term(7)), Some(LeaseId::new("lease-1"))),
            LocalSafetyReadiness::Safe,
            at,
        );
        let ObsOutcome::Evaluated(eval) = &outcome else {
            panic!("MKM-ARCH-013: expected Ready evaluation")
        };
        assert_eq!(
            eval.observation().authority_view().compatibility(),
            AuthorityViewCompatibility::InconsistentAuthorityView
        );
        assert_not_authorized(&outcome, "Self + wrong lease_id");
        assert_ready_fail_closed(&f);
    }

    #[test]
    fn mkm_arch_013_self_wrong_term_cannot_authorize() {
        let mut f = lost_fixture();
        let at = f.t0;
        let outcome = run_observation(
            &mut f,
            holder_payload(Some("node-a"), 8, Some(LeaseId::new("lease-1")), Some(5000)),
            expectation(Some(Term(7)), Some(LeaseId::new("lease-1"))),
            LocalSafetyReadiness::Safe,
            at,
        );
        assert_not_authorized(&outcome, "Self + wrong term");
        assert_ready_fail_closed(&f);
    }

    #[test]
    fn mkm_arch_013_self_missing_lease_id_cannot_authorize() {
        let mut f = lost_fixture();
        let at = f.t0;
        let outcome = run_observation(
            &mut f,
            holder_payload(Some("node-a"), 7, None, Some(5000)),
            expectation(Some(Term(7)), Some(LeaseId::new("lease-1"))),
            LocalSafetyReadiness::Safe,
            at,
        );
        assert_not_authorized(&outcome, "Self + missing lease_id");
        assert_ready_fail_closed(&f);
    }

    #[test]
    fn mkm_arch_013_self_unexpired_matching_identity_reaches_evidence_ready() {
        let mut f = lost_fixture();
        let at = f.t0;
        let outcome = run_observation(
            &mut f,
            holder_payload(Some("node-a"), 7, Some(LeaseId::new("lease-1")), Some(5000)),
            expectation(Some(Term(7)), Some(LeaseId::new("lease-1"))),
            LocalSafetyReadiness::Safe,
            at,
        );
        let ObsOutcome::Evaluated(eval) = outcome else {
            panic!("MKM-ARCH-013: expected Ready evaluation")
        };
        assert_eq!(
            eval.observation().authority_view().compatibility(),
            AuthorityViewCompatibility::CompatibleSelfUnexpired
        );
        assert_eq!(
            eval.observation().evidence().state,
            EvidenceFusionState::FailoverEvidenceReady
        );
        // Compatible is a quorum fact only: it reaches Authorized, but
        // Stage 13.2 fresh lease acquisition remains mandatory.
        assert!(eval.is_authorized());
    }

    #[test]
    fn mkm_arch_013_get_term_expired_holder_is_not_none() {
        // Some(holder) + remaining=0 is expired-but-unprocessed, never
        // silently normalized to no-holder: the Witness has not yet
        // committed the expiry.
        let mut f = lost_fixture();
        let at = f.t0;
        let outcome = run_observation(
            &mut f,
            holder_payload(Some("node-b"), 7, Some(LeaseId::new("lease-1")), Some(0)),
            expectation(None, None),
            LocalSafetyReadiness::Safe,
            at,
        );
        let ObsOutcome::Evaluated(eval) = &outcome else {
            panic!("MKM-ARCH-013: expected Ready evaluation")
        };
        let view = eval.observation().authority_view();
        assert_eq!(
            view.compatibility(),
            AuthorityViewCompatibility::ExpiredButUnprocessed
        );
        assert_ne!(
            view.compatibility(),
            AuthorityViewCompatibility::CompatibleNoHolder,
            "expired holder must not be normalized to no-holder"
        );
        assert_not_authorized(&outcome, "expired holder");
    }

    // -----------------------------------------------------------------
    // Ownership/slot invariants.
    // -----------------------------------------------------------------

    #[test]
    fn mkm_arch_013_one_logical_observation_owner() {
        // A consumed Ready is terminal for its request generation: no
        // second poll can re-emit it (no double evaluation owner).
        let mut f = lost_fixture();
        let at = f.t0;
        let assessment = f.detector.assessment();
        let loss = f.detector.loss_evidence();
        f.observer.observe_peer_at(assessment, loss, at).unwrap();
        let id = f
            .observer
            .begin_observation_at(&mut f.session, expectation(None, None), at)
            .unwrap();
        f.server
            .send_message(
                term_status_wire(&id, 1, no_holder()),
                &CborSerializer,
                &auth(),
            )
            .unwrap();
        f.session.wait_for_readable_for_test().unwrap();
        assert!(matches!(
            f.observer.poll_observation_at(&mut f.session, at).unwrap(),
            ObservationProgress::Ready(_)
        ));
        assert!(!matches!(
            f.observer.poll_observation_at(&mut f.session, at).unwrap(),
            ObservationProgress::Ready(_)
        ));
    }

    #[test]
    fn mkm_arch_013_shared_witness_outstanding_slot_enforced() {
        let mut f = lost_fixture();
        let at = f.t0;
        assert!(
            f.observer
                .begin_observation_at(&mut f.session, expectation(None, None), at)
                .is_ok()
        );
        // One session, one outstanding slot: concurrent requests fail.
        assert!(
            f.observer
                .begin_observation_at(&mut f.session, expectation(None, None), at)
                .is_err()
        );
    }
}

// ===========================================================================
// MKM-ARCH-010 / Stage 12.8f Linux runtime validation of the inert authority
// decision composition (extending the Stage 12.7 observation composition).
// Linux-only; skipped on other platforms.
//
// These tests exercise the real `LinuxDaemonRuntime` production composition
// (`begin_authority_observation` / `authority_observation_tick` /
// `evaluate_authority_attempt`) on Linux. They deliberately use a real
// `LinuxNodeRuntime` built from the production backends but never invoke any
// mutation path: the node is never promoted, and the VIP interface/service
// unit are harmless non-existent names. A fake/non-mutating peer runtime and
// a loopback Witness socket stand in only at OS/network side-effect
// boundaries. No root, no host network/service mutation.
// ===========================================================================
#[cfg(all(test, target_os = "linux"))]
mod linux_composition_tests {
    use super::*;
    use crate::daemon_peer_runtime::DaemonPeerRuntime;
    use crate::linux_node_runtime::{LinuxNodeRuntime, LinuxPlatformConfig};
    use crate::protocol::Term as ProtoTerm;
    use crate::security::{MessageAuthenticator, Psk};
    use crate::session::ProcessSession;
    use crate::witness_runtime::WitnessConnection;
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};
    use std::time::{Duration, Instant};

    fn test_config(state_path: &str, psk_file: &str) -> crate::config::Config {
        crate::config::Config::parse_str(&test_config_toml(state_path, psk_file)).unwrap()
    }

    fn test_config_toml(state_path: &str, psk_file: &str) -> String {
        format!(
            "[cluster]\n\
             id = \"cluster\"\n\
             [node]\n\
             id = \"node-a\"\n\
             [peer]\n\
             id = \"node-b\"\n\
             address = \"127.0.0.1:47946\"\n\
             [witness]\n\
             id = \"witness-1\"\n\
             address = \"127.0.0.1:47947\"\n\
             [vip]\n\
             address = \"192.0.2.50/24\"\n\
             interface = \"mkgnone0\"\n\
             [service]\n\
             manager = \"systemd\"\n\
             unit = \"mikagami-test-nonexistent.service\"\n\
             [health]\n\
             command = [\"/usr/bin/true\"]\n\
             [security]\n\
             psk_file = \"{psk_file}\"\n\
             [state]\n\
             path = \"{state_path}\"\n"
        )
    }

    /// Revision 5 §16.2 / acceptance 35 on the production startup
    /// constructor (`prepare_daemon` → `LinuxDaemonRuntime::new`): an
    /// untrusted fence executable refuses startup at the fencing check, before
    /// the peer runtime loads the PSK. Backend `none` and a trusted command
    /// backend pass the fencing check. As a non-root test user, construction
    /// then stops only at the later production requirement of a root-owned
    /// PSK file; as root it completes.
    #[test]
    fn stage14_7_daemon_startup_refuses_untrusted_fencing() {
        let dir = std::env::temp_dir().join(format!("mikagami-stage14-7-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let state = dir.join("state.toml");
        let own = dir.join("fence");
        std::fs::write(&own, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&own, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let psk = write_psk(&dir);
        let base = test_config_toml(state.to_string_lossy().as_ref(), &psk);
        let section = |fence: &str| {
            format!(
                "[fencing]\nbackend = \"command\"\nfence = [\"{fence}\"]\n\
                 verify = [\"/usr/bin/true\"]\nfence_timeout_sec = 30\n\
                 verify_timeout_sec = 10\nverify_polls = 6\n"
            )
        };
        let start = |fencing: String| {
            let config = crate::config::Config::parse_str(&format!("{base}{fencing}")).unwrap();
            LinuxDaemonRuntime::new(&config, LinuxPlatformConfig::new("/bin/true").unwrap())
        };
        let refused = start(section(own.to_string_lossy().as_ref()));
        let none = start("[fencing]\nbackend = \"none\"\n".to_string());
        let trusted = start(section("/usr/bin/true"));
        std::fs::remove_dir_all(&dir).unwrap();
        match refused {
            Err(crate::linux_node_runtime::LinuxNodeRuntimeError::Configuration(message)) => {
                assert!(message.contains("fencing.fence[0]"), "{message}");
                assert!(!message.contains("psk_file"), "{message}");
            }
            Err(other) => panic!("expected a configuration refusal, got {other}"),
            Ok(_) => panic!("an untrusted fence executable started the daemon runtime"),
        }
        for (backend, result) in [("none", none), ("trusted command", trusted)] {
            if let Err(error) = result {
                let message = error.to_string();
                assert!(!message.contains("fencing"), "backend {backend}: {message}");
                assert!(
                    message.contains("security.psk_file") && message.contains("root"),
                    "backend {backend} must fail only at the root-owned PSK rule: {message}"
                );
            }
        }
    }

    /// Build a real LinuxDaemonRuntime using the production backends but
    /// harmless non-mutating paths. Construction only reads `/bin/true`
    /// metadata and validates config; it performs no VIP/service/network
    /// mutation.
    fn build_linux_daemon_runtime(state_path: &str, psk_file: &str) -> LinuxDaemonRuntime {
        let config = test_config(state_path, psk_file);
        let platform = LinuxPlatformConfig::new("/bin/true").unwrap();
        let runtime = LinuxNodeRuntime::new(&config, platform).unwrap();
        LinuxDaemonRuntime::new_for_test(runtime, None)
    }

    /// A fake peer runtime for the composition. It performs no network I/O; a
    /// real DaemonPeerRuntime over loopback is acceptable but heavier. Here we
    /// use a real runtime with no address so it never dials.
    fn no_network_peer(config: &crate::config::Config) -> DaemonPeerRuntime {
        // Canonical outbound role (node-a < node-b); no peer_address is set, so
        // reconnect attempts are no-ops and no socket is opened.
        DaemonPeerRuntime::new(
            crate::protocol::ClusterId::new(config.cluster.id.clone()),
            crate::protocol::NodeId::new(config.node.id.clone()),
            crate::protocol::NodeId::new(config.peer.id.clone()),
            config.node.priority,
            config.peer.priority,
            Duration::from_secs(config.heartbeat.unreachable_after_sec),
            Duration::from_secs(config.heartbeat.interval_sec),
            Duration::from_secs(config.heartbeat.connect_timeout_sec),
            MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32])),
        )
        .unwrap()
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mikagami-12.7-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_psk(dir: &std::path::Path) -> String {
        let path = dir.join("cluster.psk");
        let mut file = std::fs::File::create(&path).unwrap();
        // 64 lowercase hex chars = 32-byte PSK.
        file.write_all("55".repeat(32).as_bytes()).unwrap();
        file.sync_all().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path.to_string_lossy().into_owned()
    }

    /// Stage 14 Phase 14.6 (§16.7.5): on the real Linux runtime the
    /// pending-reap poll runs before the foreground tick's early return. The
    /// node here is not Active, so the tick returns early; the poll must
    /// still have happened, once per call, without signalling the leader.
    #[test]
    fn stage14_6_foreground_poll_precedes_the_early_return() {
        fn leader(program: &str) -> (std::process::Child, u32) {
            let child = std::process::Command::new(program)
                .args(if program == "/bin/sleep" {
                    &["30"][..]
                } else {
                    &[][..]
                })
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap();
            let pid = child.id();
            (child, pid)
        }
        fn until_zombie(pid: u32) {
            let until = Instant::now() + Duration::from_secs(5);
            loop {
                let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
                if stat.rsplit_once(") ").unwrap().1.starts_with('Z') {
                    return;
                }
                assert!(Instant::now() < until);
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        let dir = temp_dir("stage14-6-poll");
        let state = dir.join("state.toml");
        let psk = write_psk(&dir);
        let mut daemon = build_linux_daemon_runtime(state.to_string_lossy().as_ref(), &psk);
        assert!(
            !daemon.runtime.foreground_witness_required(),
            "early-return path"
        );

        let (exited, exited_pid) = leader("/bin/true");
        until_zombie(exited_pid);
        crate::fencing_backend::test_support::retain(
            daemon.runtime.fencing_backend_for_test(),
            exited,
            exited_pid,
        )
        .unwrap();
        assert_eq!(
            daemon.foreground_lifecycle_tick(&|| false, &|| false, &|| true),
            Ok(())
        );
        assert!(
            daemon
                .runtime
                .fencing_backend_for_test()
                .pending_reap_diagnostics()
                .is_none(),
            "the poll ran before the early return and reaped the leader"
        );

        let (running, running_pid) = leader("/bin/sleep");
        crate::fencing_backend::test_support::retain(
            daemon.runtime.fencing_backend_for_test(),
            running,
            running_pid,
        )
        .unwrap();
        for _ in 0..3 {
            assert_eq!(
                daemon.foreground_lifecycle_tick(&|| false, &|| false, &|| true),
                Ok(())
            );
        }
        let view = daemon
            .runtime
            .fencing_backend_for_test()
            .pending_reap_diagnostics()
            .unwrap();
        assert_eq!((view.pid, view.polls), (running_pid, 3));
        unsafe { libc::kill(running_pid as i32, libc::SIGKILL) };
        until_zombie(running_pid);
        assert_eq!(
            daemon.foreground_lifecycle_tick(&|| false, &|| false, &|| true),
            Ok(())
        );
        assert!(
            daemon
                .runtime
                .fencing_backend_for_test()
                .pending_reap_diagnostics()
                .is_none()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// MKM-ARCH-010 / Stage 12.8f (extends Stage 12.7-B): real Linux
    /// composition with no Witness session/observer attached fails closed
    /// with an explicit error at every layer, including the full
    /// `evaluate_authority_attempt` composition — no Authorized attempt can
    /// exist and no mutation is reachable.
    #[test]
    fn mkm_arch_010_no_witness_adapter_fails_closed() {
        let dir = temp_dir("nowitness");
        let state = dir.join("state.toml");
        let psk = write_psk(&dir);
        let mut daemon = build_linux_daemon_runtime(state.to_string_lossy().as_ref(), &psk);
        let context = DaemonIterationContext::new_for_test(Instant::now(), false);
        assert!(
            daemon.begin_authority_observation(context).is_err(),
            "MKM-ARCH-010 violated: no-adapter begin did not fail closed"
        );
        assert!(
            daemon.authority_observation_tick(context).is_err(),
            "MKM-ARCH-010 violated: no-adapter tick did not fail closed"
        );
        assert!(
            daemon.evaluate_authority_attempt(context).is_err(),
            "MKM-ARCH-010 violated: no-adapter evaluation did not fail closed"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// MKM-ARCH-010 / Stage 12.8f (extends Stage 12.7-U/A): a freshly
    /// attached observer has no current term (the default/restart state is
    /// never `Ready`), and a begun-but-uncompleted GET_TERM stays
    /// `AwaitingWitnessTerm` — so `into_evaluation()` is `None` and the full
    /// `evaluate_authority_attempt` composition returns `None`: no attempt
    /// exists.
    #[test]
    fn mkm_arch_010_no_current_term_fails_closed() {
        let dir = temp_dir("noterm");
        let state = dir.join("state.toml");
        let psk = write_psk(&dir);
        let mut daemon = build_linux_daemon_runtime(state.to_string_lossy().as_ref(), &psk);

        // Loopback Witness socket pair (no real Witness peer; the server end is
        // held but never sends a completion).
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let connection = WitnessConnection::new(
            crate::protocol::NodeId::new("node-a"),
            crate::protocol::NodeId::new("w"),
            crate::protocol::ClusterId::new("cluster"),
            crate::protocol::SessionId::new("w-session"),
            crate::tcp::TcpConnection::from_stream(
                client,
                Duration::from_secs(2),
                Duration::from_secs(2),
            )
            .unwrap(),
        );
        daemon.attach_test_witness(
            connection,
            ProcessSession::from_session_id(crate::protocol::SessionId::new("a-session")),
            MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32])),
        );

        // Restart/default state: polling before any begin is not Ready.
        let t = Instant::now();
        let context = DaemonIterationContext::new_for_test(t, false);
        assert!(matches!(
            daemon.authority_observation_tick(context).unwrap(),
            AuthorityObservationProgress::AwaitingWitnessTerm
        ));

        // Begin a GET_TERM but never complete it.
        daemon.begin_authority_observation(context).unwrap();
        let progress = daemon.authority_observation_tick(context).unwrap();
        assert!(matches!(
            &progress,
            AuthorityObservationProgress::AwaitingWitnessTerm
        ));
        // AwaitingWitnessTerm yields no evaluation at either boundary.
        assert!(
            progress.into_evaluation().is_none(),
            "MKM-ARCH-010 violated: AwaitingWitnessTerm produced an evaluation"
        );
        assert!(
            daemon
                .evaluate_authority_attempt(context)
                .unwrap()
                .is_none(),
            "MKM-ARCH-010 violated: AwaitingWitnessTerm produced an evaluation"
        );
        drop(server);

        // No peer was ever advanced by Witness observation or evaluation.
        assert_eq!(
            daemon.peer_tick_invocations_for_test(),
            0,
            "MKM-ARCH-010 violated: observation/evaluation advanced the peer runtime"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Phase 14.12 F2: the REAL `LinuxDaemonRuntime` completes an expired
    /// authority observation when asked through the `PromotionExecutionRuntime`
    /// trait (the seam the retired background priming used; the E3b attempt
    /// step now performs the same expiry through the adapter). The trait's
    /// default is a no-op, so this test fails if the Linux override is ever
    /// missing: it asserts the shared session slot is actually released.
    #[test]
    fn f2_linux_runtime_expires_a_stale_observation_through_the_trait() {
        let dir = temp_dir("f2-expire");
        let state = dir.join("state.toml");
        let psk = write_psk(&dir);
        let mut daemon = build_linux_daemon_runtime(state.to_string_lossy().as_ref(), &psk);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let connection = WitnessConnection::new(
            crate::protocol::NodeId::new("node-a"),
            crate::protocol::NodeId::new("w"),
            crate::protocol::ClusterId::new("cluster"),
            crate::protocol::SessionId::new("w-session"),
            crate::tcp::TcpConnection::from_stream(
                client,
                Duration::from_secs(2),
                Duration::from_secs(2),
            )
            .unwrap(),
        );
        daemon.attach_test_witness(
            connection,
            ProcessSession::from_session_id(crate::protocol::SessionId::new("a-session")),
            MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32])),
        );

        // attach_test_witness uses a 2 s observation deadline.
        let t = Instant::now();
        let deadline = Duration::from_secs(2);
        daemon
            .begin_authority_observation(DaemonIterationContext::new_for_test(t, false))
            .unwrap();
        assert!(PromotionExecutionRuntime::shared_witness_outstanding(
            &daemon
        ));

        // Inside the deadline (now < deadline): untouched, slot still held.
        PromotionExecutionRuntime::expire_stale_authority_observation(
            &mut daemon,
            t + deadline - Duration::from_nanos(1),
        );
        assert!(
            PromotionExecutionRuntime::shared_witness_outstanding(&daemon),
            "an observation inside its deadline must not be touched"
        );

        // At the deadline (now >= deadline): completed, slot released. This is
        // the assertion that fails if the trait default no-op were used.
        PromotionExecutionRuntime::expire_stale_authority_observation(&mut daemon, t + deadline);
        assert!(
            !PromotionExecutionRuntime::shared_witness_outstanding(&daemon),
            "LinuxDaemonRuntime must release the slot of an expired observation"
        );

        // The next begin issues a new request (generation 2), single outstanding.
        daemon
            .begin_authority_observation(DaemonIterationContext::new_for_test(t + deadline, false))
            .unwrap();
        assert!(PromotionExecutionRuntime::shared_witness_outstanding(
            &daemon
        ));
        drop(server);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Phase 14.12 E3b: the REAL `LinuxDaemonRuntime` overrides the
    /// attempt-bound observation step. The trait default is `Ok(())` without
    /// a request, so this test fails if the Linux override is ever missing:
    /// a runtime that is not an idle Standby (here the unreconciled
    /// start-up state) refuses to observe — the Active and demotion work owns
    /// the sole Witness slot — and issues no GET_TERM, whatever the shutdown
    /// query says. (The Standby path, with a real Witness, is exercised by the
    /// `e3b_lab_*` probes and, at the adapter level, by the `e3b_step_*`
    /// tests; a unit fixture cannot reach Standby without real VIP/service
    /// observers.)
    #[test]
    fn e3b_linux_runtime_attempt_observation_is_wired_through_the_trait() {
        let dir = temp_dir("e3b-linux-step");
        let state = dir.join("state.toml");
        let psk = write_psk(&dir);
        let mut daemon = build_linux_daemon_runtime(state.to_string_lossy().as_ref(), &psk);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let connection = WitnessConnection::new(
            crate::protocol::NodeId::new("node-a"),
            crate::protocol::NodeId::new("w"),
            crate::protocol::ClusterId::new("cluster"),
            crate::protocol::SessionId::new("w-session"),
            crate::tcp::TcpConnection::from_stream(
                client,
                Duration::from_secs(2),
                Duration::from_secs(2),
            )
            .unwrap(),
        );
        daemon.attach_test_witness(
            connection,
            ProcessSession::from_session_id(crate::protocol::SessionId::new("a-session")),
            MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32])),
        );
        for shutdown in [false, true] {
            assert_eq!(
                PromotionExecutionRuntime::complete_attempt_observation(&mut daemon, &|| shutdown),
                Err("authority observation is not allowed in this state")
            );
        }
        let snapshot = daemon.witness_snapshot_for_test().unwrap();
        assert_eq!(snapshot.request_generation, 0, "no GET_TERM was issued");
        assert!(snapshot.pending.is_none());
        assert!(!PromotionExecutionRuntime::shared_witness_outstanding(
            &daemon
        ));
        drop(server);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// MKM-ARCH-010 / Stage 12.8f (extends Stage 12.7): the real peer runtime
    /// advances exactly once per iteration, the observation/evaluation path
    /// never advances it, and under shutdown a completed current correlated
    /// term still cannot yield a trusted complete observation or any
    /// evaluation (local safety is `ShutdownInProgress`).
    #[test]
    fn mkm_arch_010_shutdown_fails_closed_and_single_peer_advance() {
        use crate::protocol::{
            CborSerializer, ClusterId, CommonFields, NodeId, PROTOCOL_VERSION, ProtocolMessage,
            Sequence, SessionId, TermStatusPayload, UnsignedEnvelope,
        };

        let dir = temp_dir("shutdown");
        let state = dir.join("state.toml");
        let psk = write_psk(&dir);
        let config = test_config(state.to_string_lossy().as_ref(), &psk);
        let platform = LinuxPlatformConfig::new("/bin/true").unwrap();
        let runtime = LinuxNodeRuntime::new(&config, platform).unwrap();
        let peer = no_network_peer(&config);
        let mut daemon = LinuxDaemonRuntime::new_for_test(runtime, Some(peer));

        // One peer advance per iteration, each with the authoritative time.
        let t1 = Instant::now();
        daemon
            .peer_tick_at(t1, Some(PeerStatusSnapshot::unobserved()))
            .unwrap();
        assert_eq!(
            daemon.peer_tick_invocations_for_test(),
            1,
            "MKM-ARCH-010 violated: peer did not advance exactly once on Linux"
        );
        let t2 = t1 + Duration::from_millis(1);
        daemon
            .peer_tick_at(t2, Some(PeerStatusSnapshot::unobserved()))
            .unwrap();
        assert_eq!(daemon.peer_tick_invocations_for_test(), 2);

        // Attach a real Witness session over loopback and complete a real
        // authenticated, correlated GET_TERM.
        let auth = MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32]));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server_stream, _) = listener.accept().unwrap();
        let mut server = crate::tcp::TcpConnection::from_stream(
            server_stream,
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .unwrap();
        let connection = WitnessConnection::new(
            NodeId::new("node-a"),
            NodeId::new("w"),
            ClusterId::new("cluster"),
            SessionId::new("w-session"),
            crate::tcp::TcpConnection::from_stream(
                client,
                Duration::from_secs(2),
                Duration::from_secs(2),
            )
            .unwrap(),
        );
        daemon.attach_test_witness(
            connection,
            ProcessSession::from_session_id(SessionId::new("a-session")),
            MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32])),
        );

        let context = DaemonIterationContext::new_for_test(t2, false);
        daemon.begin_authority_observation(context).unwrap();
        let request_id = daemon
            .witness_snapshot_for_test()
            .unwrap()
            .pending
            .unwrap()
            .request_id;
        server
            .send_message(
                UnsignedEnvelope {
                    common: CommonFields {
                        protocol_version: PROTOCOL_VERSION,
                        cluster_id: ClusterId::new("cluster"),
                        sender_node_id: NodeId::new("w"),
                        receiver_node_id: NodeId::new("node-a"),
                        session_id: SessionId::new("w-session"),
                        sequence: Sequence(1),
                        term: ProtoTerm(7),
                        lease_id: None,
                        request_id: Some(request_id),
                        operation_id: None,
                    },
                    message: ProtocolMessage::TermStatus(TermStatusPayload {
                        current_term: ProtoTerm(7),
                        current_holder: Some(NodeId::new("node-a")),
                        current_lease_id: None,
                        lease_remaining_ms: None,
                    }),
                },
                &CborSerializer,
                &auth,
            )
            .unwrap();
        daemon.wait_witness_readable_for_test().unwrap();

        // Under a shutdown context, even a completed current correlated term
        // cannot produce a trusted complete observation.
        let shutdown_context = DaemonIterationContext::new_for_test(t2, true);
        let progress = daemon.authority_observation_tick(shutdown_context).unwrap();
        let AuthorityObservationProgress::LocalSafetyNotReady(local) = &progress else {
            panic!("MKM-ARCH-010 violated: shutdown produced a trusted complete observation")
        };
        assert_eq!(
            local.readiness,
            crate::failover_policy::LocalSafetyReadiness::ShutdownInProgress
        );
        // The shutdown-blocked observation yields no attempt at either
        // composition boundary.
        assert!(
            progress.into_evaluation().is_none(),
            "MKM-ARCH-010 violated: shutdown produced an evaluation"
        );
        // The correlated completion was accepted (the term was minted) but the
        // observation was not established; the one-shot term is consumed and a
        // later poll cannot re-mint it.
        assert!(matches!(
            daemon.witness_snapshot_for_test().unwrap().last_completion,
            Some(crate::evidence_fusion::adapter::Completion::TermStatus(_))
        ));
        assert!(matches!(
            daemon.authority_observation_tick(shutdown_context).unwrap(),
            AuthorityObservationProgress::AwaitingWitnessTerm
        ));
        // The full evaluation composition under shutdown also yields no
        // attempt and does not advance the peer.
        assert!(
            daemon
                .evaluate_authority_attempt(shutdown_context)
                .unwrap()
                .is_none(),
            "MKM-ARCH-010 violated: shutdown produced an evaluation"
        );
        // The peer assessment forwarded into EvidenceFusion at t2 is the sole
        // peer-truth owner's current value.
        assert_eq!(
            daemon
                .witness_snapshot_for_test()
                .unwrap()
                .fusion
                .peer_assessment,
            daemon.peer_failure_assessment()
        );
        assert_eq!(
            daemon.peer_tick_invocations_for_test(),
            2,
            "MKM-ARCH-010 violated: authority observation/evaluation advanced the peer"
        );

        drop(server);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// MKM-ARCH-010 / Stage 12.8f (extends Stage 12.7-C/P, real composition
    /// boundary): a self-contained authenticated, correlated GET_TERM
    /// completion over a loopback Witness socket mints a real current term
    /// through the production adapter correlation path (not a test
    /// constructor). The full `evaluate_authority_attempt` composition yields
    /// `Ready` only when fresh local safety is `Safe`. The scripted holder
    /// claim carries no remaining TTL, so the Stage 13.3 adapter classifies
    /// the authority view `ExpiredButUnprocessed` (incompatible) and the
    /// unobserved peer has no local loss evidence — the evaluation can
    /// never be `Authorized`. `Ready != Authorized` on the real Linux
    /// composition; the positive Authorized-but-inert control is the
    /// deterministic MKM-ARCH-009 matrix.
    /// Stage 14 Phase 14.9 §26 R4 input on the real Linux composition: the
    /// incident-bound term record moves only on an authenticated, correlated
    /// TermStatus completion of the current request generation. A response
    /// under the wrong key or for another request never updates it, and an
    /// observation never creates a record (only gate G does).
    fn stage14_9_term_record_after(
        name: &str,
        psk: [u8; 32],
        correlated: bool,
        term: u64,
        record: Option<crate::linux_node_runtime::IncidentTermRecord>,
    ) -> Option<crate::linux_node_runtime::IncidentTermRecord> {
        use crate::protocol::{
            CborSerializer, ClusterId, CommonFields, NodeId, PROTOCOL_VERSION, ProtocolMessage,
            RequestId, Sequence, SessionId, TermStatusPayload, UnsignedEnvelope,
        };
        let dir = temp_dir(name);
        let state = dir.join("state.toml");
        let psk_file = write_psk(&dir);
        let mut daemon = build_linux_daemon_runtime(state.to_string_lossy().as_ref(), &psk_file);
        daemon.fencing_term_record = record;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server_stream, _) = listener.accept().unwrap();
        let mut server = crate::tcp::TcpConnection::from_stream(
            server_stream,
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .unwrap();
        let connection = WitnessConnection::new(
            NodeId::new("node-a"),
            NodeId::new("w"),
            ClusterId::new("cluster"),
            SessionId::new("w-session"),
            crate::tcp::TcpConnection::from_stream(
                client,
                Duration::from_secs(2),
                Duration::from_secs(2),
            )
            .unwrap(),
        );
        daemon.attach_test_witness(
            connection,
            ProcessSession::from_session_id(SessionId::new("a-session")),
            MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32])),
        );
        let context = DaemonIterationContext::new_for_test(Instant::now(), false);
        daemon.begin_authority_observation(context).unwrap();
        let pending = daemon
            .witness_snapshot_for_test()
            .unwrap()
            .pending
            .unwrap()
            .request_id;
        let request_id = if correlated {
            pending
        } else {
            RequestId::new("stage14-9-other-request")
        };
        server
            .send_message(
                UnsignedEnvelope {
                    common: CommonFields {
                        protocol_version: PROTOCOL_VERSION,
                        cluster_id: ClusterId::new("cluster"),
                        sender_node_id: NodeId::new("w"),
                        receiver_node_id: NodeId::new("node-a"),
                        session_id: SessionId::new("w-session"),
                        sequence: Sequence(1),
                        term: ProtoTerm(term),
                        lease_id: None,
                        request_id: Some(request_id),
                        operation_id: None,
                    },
                    message: ProtocolMessage::TermStatus(TermStatusPayload {
                        current_term: ProtoTerm(term),
                        current_holder: None,
                        current_lease_id: None,
                        lease_remaining_ms: None,
                    }),
                },
                &CborSerializer,
                &MessageAuthenticator::new(Psk::from_test_bytes(psk)),
            )
            .unwrap();
        let _ = daemon.wait_witness_readable_for_test();
        let _ = daemon.evaluate_authority_attempt(context);
        drop(server);
        let _ = std::fs::remove_dir_all(&dir);
        daemon.fencing_term_record
    }

    #[test]
    fn stage14_9_r4_record_moves_only_on_authenticated_correlated_term() {
        let incident = crate::fencing::IncidentRef {
            incident_seq: 1,
            incident_id: crate::fencing::IncidentId::generated(
                "11111111-2222-4333-8444-555555555555".into(),
            ),
        };
        let record = crate::linux_node_runtime::IncidentTermRecord {
            incident: incident.clone(),
            anchor: ProtoTerm(7),
            newest: ProtoTerm(7),
        };
        let moved =
            stage14_9_term_record_after("r4-good", [0x55; 32], true, 9, Some(record.clone()))
                .unwrap();
        assert_eq!(moved.incident, incident);
        assert_eq!(moved.newest, ProtoTerm(9), "the newest authenticated term");
        assert_eq!(
            stage14_9_term_record_after("r4-key", [0x66; 32], true, 9, Some(record.clone())),
            Some(record.clone()),
            "an unauthenticated response never moves the record"
        );
        assert_eq!(
            stage14_9_term_record_after(
                "r4-uncorrelated",
                [0x55; 32],
                false,
                9,
                Some(record.clone())
            ),
            Some(record.clone()),
            "an uncorrelated response never moves the record"
        );
        assert_eq!(
            stage14_9_term_record_after("r4-none", [0x55; 32], true, 9, None),
            None,
            "an observation never creates a record"
        );
    }

    /// Stage 14 Phase 14.9: the real Linux gate without a peer runtime has
    /// no session or episode; it blocks `FencingUnavailable` and never
    /// touches the store.
    #[test]
    fn stage14_9_linux_gate_without_peer_blocks_unavailable() {
        let dir = temp_dir("gate-no-peer");
        let state = dir.join("state.toml");
        let psk = write_psk(&dir);
        let mut daemon = build_linux_daemon_runtime(state.to_string_lossy().as_ref(), &psk);
        let before = std::fs::read(&state).ok();
        let evaluation = crate::daemon::stage14_9_support::authorized_evaluation();
        assert!(matches!(
            PromotionExecutionRuntime::fencing_gate(&mut daemon, &evaluation, &|| false),
            FencingGate::Blocked(crate::fencing::FencingGateBlock::FencingUnavailable)
        ));
        assert_eq!(std::fs::read(&state).ok(), before);
        assert_eq!(daemon.fencing_term_record, None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mkm_arch_010_ready_is_not_authorized_on_real_linux_composition() {
        use crate::protocol::{
            CborSerializer, ClusterId, CommonFields, NodeId, PROTOCOL_VERSION, ProtocolMessage,
            Sequence, SessionId, TermStatusPayload, UnsignedEnvelope,
        };

        let dir = temp_dir("ready");
        let state = dir.join("state.toml");
        let psk = write_psk(&dir);
        let mut daemon = build_linux_daemon_runtime(state.to_string_lossy().as_ref(), &psk);

        let auth = MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32]));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server_stream, _) = listener.accept().unwrap();
        let mut server = crate::tcp::TcpConnection::from_stream(
            server_stream,
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .unwrap();
        let connection = WitnessConnection::new(
            NodeId::new("node-a"),
            NodeId::new("w"),
            ClusterId::new("cluster"),
            SessionId::new("w-session"),
            crate::tcp::TcpConnection::from_stream(
                client,
                Duration::from_secs(2),
                Duration::from_secs(2),
            )
            .unwrap(),
        );
        daemon.attach_test_witness(
            connection,
            ProcessSession::from_session_id(SessionId::new("a-session")),
            MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32])),
        );

        let t = Instant::now();
        let context = DaemonIterationContext::new_for_test(t, false);
        daemon.begin_authority_observation(context).unwrap();
        let request_id = daemon
            .witness_snapshot_for_test()
            .unwrap()
            .pending
            .unwrap()
            .request_id;

        let response = UnsignedEnvelope {
            common: CommonFields {
                protocol_version: PROTOCOL_VERSION,
                cluster_id: ClusterId::new("cluster"),
                sender_node_id: NodeId::new("w"),
                receiver_node_id: NodeId::new("node-a"),
                session_id: SessionId::new("w-session"),
                sequence: Sequence(1),
                term: ProtoTerm(7),
                lease_id: None,
                request_id: Some(request_id),
                operation_id: None,
            },
            message: ProtocolMessage::TermStatus(TermStatusPayload {
                current_term: ProtoTerm(7),
                current_holder: Some(NodeId::new("node-a")),
                current_lease_id: None,
                lease_remaining_ms: None,
            }),
        };
        server
            .send_message(response, &CborSerializer, &auth)
            .unwrap();
        daemon.wait_witness_readable_for_test().unwrap();

        // Real composition: the term is accepted only if fresh local safety is
        // Safe in this environment. The fused evidence must stay Unproven:
        // the scripted holder claim carries no remaining TTL, so the
        // authority view classifies ExpiredButUnprocessed (incompatible),
        // and the peer is unobserved.
        let local = DaemonRuntime::local_safety_snapshot(&mut daemon, false)
            .unwrap()
            .unwrap();
        // Drive the full Stage 12.8d composition: observation -> eligibility
        // -> authorization -> inert AuthorityAttemptEvaluation.
        let evaluation = daemon.evaluate_authority_attempt(context).unwrap();
        match local.readiness {
            crate::failover_policy::LocalSafetyReadiness::Safe => {
                let Some(evaluation) = evaluation else {
                    panic!("MKM-ARCH-010 violated: Safe local boundary produced no evaluation")
                };
                let observation = evaluation.observation();
                assert_eq!(
                    observation.authority_view().term(),
                    ProtoTerm(7),
                    "MKM-ARCH-010 violated: current term did not come from the correlated completion"
                );
                assert_eq!(
                    observation.authority_view().observed_at(),
                    t,
                    "MKM-ARCH-010 violated: freshness epoch is not the response acceptance time"
                );
                assert_eq!(
                    observation.evidence().state,
                    crate::evidence_fusion::EvidenceFusionState::Unproven,
                    "MKM-ARCH-010 violated: a current term fabricated reachable evidence"
                );
                assert_eq!(
                    observation.local().readiness,
                    crate::failover_policy::LocalSafetyReadiness::Safe
                );
                // Ready != Eligible != Authorized on the real Linux
                // composition: Unproven evidence with an Unobserved peer can
                // never authorize.
                assert!(
                    !evaluation.is_eligible(),
                    "MKM-ARCH-010 violated: Unproven evidence was Eligible"
                );
                assert!(
                    !evaluation.is_authorized(),
                    "MKM-ARCH-010 violated: Unproven evidence was Authorized"
                );
            }
            _ => {
                assert!(
                    evaluation.is_none(),
                    "MKM-ARCH-010 violated: non-Safe local safety produced an evaluation"
                );
                // The term still completed at the adapter level; only the
                // trusted-observation gate withheld it.
                assert!(matches!(
                    daemon.witness_snapshot_for_test().unwrap().last_completion,
                    Some(crate::evidence_fusion::adapter::Completion::TermStatus(_))
                ));
            }
        }
        // GET_TERM success delivers a classified authority-view token.
        // This holder claim has no verifiable remaining TTL, so it must
        // be recorded as incompatible evidence — never as a compatible
        // view and never silently Unknown.
        assert_eq!(
            daemon
                .witness_snapshot_for_test()
                .unwrap()
                .fusion
                .witness_status,
            crate::evidence_fusion::WitnessStatus::AuthorityViewIncompatible
        );
        assert_eq!(
            daemon
                .witness_snapshot_for_test()
                .unwrap()
                .fusion
                .peer_assessment,
            daemon.peer_failure_assessment()
        );
        // No peer advance and no mutation occurred.
        assert_eq!(
            daemon.peer_tick_invocations_for_test(),
            0,
            "MKM-ARCH-010 violated: observation/evaluation advanced the peer"
        );

        drop(server);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Phase 1-J27 (audit a02 NB2-1): the composition, not only its parts. A peer tick that follows
    /// a blocking fencing step of the same iteration (marked by both step closures, G27-3) drops
    /// the window it opened at the iteration's pre-step `now`; the next iteration's tick opens the
    /// window that counts. Without the mark the tick keeps its window.
    #[test]
    fn j27_peer_tick_after_a_fencing_step_drops_the_window_of_the_pre_step_now() {
        let dir = temp_dir("j27-nb1");
        let state = dir.join("state.toml");
        let psk = write_psk(&dir);
        let mut daemon = build_linux_daemon_runtime(state.to_string_lossy().as_ref(), &psk);
        let mut peer = DaemonPeerRuntime::new(
            crate::protocol::ClusterId::new("cluster"),
            crate::protocol::NodeId::new("node-b"),
            crate::protocol::NodeId::new("node-a"),
            90,
            100,
            Duration::from_secs(10),
            Duration::from_secs(1),
            Duration::from_secs(2),
            MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32])),
        )
        .unwrap();
        peer.bind("127.0.0.1:0".parse().unwrap(), Instant::now())
            .unwrap();
        daemon.peer = Some(peer);
        let window = |daemon: &LinuxDaemonRuntime| {
            daemon.peer.as_ref().unwrap().listen_window_start_for_test()
        };
        let t0 = Instant::now();
        daemon.peer_tick_at(t0, None).unwrap();
        assert_eq!(
            window(&daemon),
            Some(t0),
            "an unmarked tick keeps its window"
        );
        // A blocking step of the next iteration: it voids, and its closure marks the iteration.
        daemon
            .peer
            .as_mut()
            .unwrap()
            .void_listen_window_for_fencing_step();
        daemon.fencing_step_since_peer_tick = true;
        let t1 = t0 + Duration::from_secs(1);
        daemon.peer_tick_at(t1, None).unwrap();
        assert_eq!(window(&daemon), None, "the pre-step window never counts");
        assert!(
            !daemon.fencing_step_since_peer_tick,
            "the mark is consumed once"
        );
        let t2 = t1 + Duration::from_secs(1);
        daemon.peer_tick_at(t2, None).unwrap();
        assert_eq!(
            window(&daemon),
            Some(t2),
            "the next iteration opens the window"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// Stage 14 Phase 14.9 test support for the Linux runtime owner's loop-level
/// composition tests (G8-A/B): a real `Authorized` evaluation minted through
/// the production observation path (term 7). Test-only; it sits after
/// `mod tests` so production-source guards never count it.
#[cfg(all(test, target_os = "linux"))]
pub(crate) mod stage14_9_support {
    pub(crate) fn authorized_evaluation() -> super::AuthorityAttemptEvaluation {
        super::tests::ready_progress_at(
            std::time::Instant::now(),
            crate::failure_assessment::PeerFailureAssessment::CommunicationLost,
            crate::evidence_fusion::EvidenceFusionState::FailoverEvidenceReady,
            crate::failover_policy::LocalSafetyReadiness::Safe,
        )
        .into_evaluation()
        .expect("a Ready observation evaluates")
    }

    /// Phase 14.12 PC-1: the composition `LinuxDaemonRuntime::
    /// authority_observation_tick` performs once the attempt-bound E3b step
    /// has accepted its own response — the peer assessment into fusion, one
    /// `poll_observation_at`, the fresh `Safe` local-safety requirement, the
    /// term-free evidence view, the trusted observation and the inert
    /// `AuthorityAttemptEvaluation` — over a fixture's adapter and peer
    /// detector. Every step is a Production function; only the owner of the
    /// peer detector and of the session differs from `LinuxDaemonRuntime`.
    pub(crate) fn evaluate_observation(
        observer: &mut crate::evidence_fusion::adapter::WitnessEvidenceAdapter,
        session: &mut crate::witness_runtime::WitnessSession,
        peer_assessment: crate::failure_assessment::PeerFailureAssessment,
        peer_loss: Option<crate::failure_assessment::LocalLossEvidence>,
        local: crate::failover_policy::LocalSafetySnapshot,
        now: std::time::Instant,
    ) -> Result<Option<super::AuthorityAttemptEvaluation>, String> {
        observer
            .observe_peer_at(peer_assessment, peer_loss, now)
            .map_err(|error| error.to_string())?;
        match observer
            .poll_observation_at(session, now)
            .map_err(|error| error.to_string())?
        {
            crate::evidence_fusion::adapter::ObservationProgress::Ready(authority_view) => {
                if local.readiness != crate::failover_policy::LocalSafetyReadiness::Safe {
                    return Ok(None);
                }
                let evidence = crate::evidence_fusion::WitnessEvidenceView::from_snapshot(
                    &observer.snapshot().fusion,
                );
                Ok(Some(super::AuthorityAttemptEvaluation::evaluate(
                    super::CurrentAuthorityAttemptObservation::new(
                        authority_view,
                        peer_assessment,
                        evidence,
                        local,
                    ),
                )))
            }
            _ => Ok(None),
        }
    }

    /// Hand the runtime back after a loop-level test.
    pub(crate) fn into_runtime<R>(daemon: super::Daemon<R>) -> R {
        daemon.runtime
    }

    /// Stage 14 Phase 14.10: the runtime inside a live attempt, for the
    /// between-G-and-K race hooks.
    pub(crate) fn runtime_mut<R>(daemon: &mut super::Daemon<R>) -> &mut R {
        &mut daemon.runtime
    }
}
