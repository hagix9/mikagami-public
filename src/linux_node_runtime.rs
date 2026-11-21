//! Explicit Linux composition root for the real resource backends.
//!
//! This module owns platform construction only.  It does not run a loop and
//! does not create authority; authority remains owned by the existing node
//! controller and Witness mutation runtime.

#![allow(dead_code)]

use crate::config::{Config, Mode, ServiceManager};
#[cfg(target_os = "linux")]
use crate::failover_policy::{LocalSafetyReadiness, LocalSafetySnapshot};
use crate::node_lease_authority::node_witness_runtime::{
    NodeWitnessMutationResult, NodeWitnessMutationRuntime, NodeWitnessRuntimeError,
};
use crate::node_lease_authority::{
    AuthorityError, AuthorityMode, NodeAuthorityController, OwnershipClass, RenewalDue,
    RuntimeLeaseAuthority, SystemMonotonicClock,
};
use crate::node_mutation::{ArmGate, NodeMutationError};
use crate::obligation_reconciliation::{SorCandidate, SorOutcome};
use crate::protocol::{ClusterId, DurationMs, LeaseId, NodeId, Term};
use crate::receive::ReceiveError;
use crate::resource_executor::{
    ExternalServiceBackend, HealthObservation, LinuxNetworkBackend, LinuxNetworkConfig,
    LinuxSystemdServiceBackend, NetworkBackend, ResourceExecutor, ServiceAdapter, ServiceBackend,
    ServiceObservation, VipObservation,
};
use crate::resource_workflow::{
    CleanupWorkflowOutcome, PromotionWorkflowOutcome, ResourceWorkflow, ResourceWorkflowError,
};
use crate::state_machine::{NodeState, OperationPhase, StateMachine, TransitionError};
use crate::witness_runtime::WitnessSession;
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinuxPlatformConfig {
    pub(crate) arping_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinuxPlatformConfigError(String);

impl fmt::Display for LinuxPlatformConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for LinuxPlatformConfigError {}

impl LinuxPlatformConfig {
    pub(crate) fn new(path: impl Into<PathBuf>) -> Result<Self, LinuxPlatformConfigError> {
        let arping_path = path.into();
        if arping_path.as_os_str().is_empty() || !arping_path.is_absolute() {
            return Err(LinuxPlatformConfigError(
                "arping path must be an explicit absolute path".into(),
            ));
        }
        Ok(Self { arping_path })
    }

    fn network_config(
        &self,
        config: &Config,
    ) -> Result<LinuxNetworkConfig, LinuxPlatformConfigError> {
        LinuxNetworkConfig::from_cidr(
            config.vip.interface.clone(),
            &config.vip.address,
            self.arping_path.clone(),
            config.vip.arp_count,
        )
        .map_err(|error| LinuxPlatformConfigError(error.to_string()))
    }
}

#[derive(Debug)]
pub(crate) enum LinuxNodeRuntimeError {
    Configuration(String),
    Platform(String),
    Backend(String),
    Mutation(NodeMutationError),
    Authority(AuthorityError),
    Witness(NodeWitnessRuntimeError),
    Workflow(ResourceWorkflowError),
    Transition(TransitionError),
    Receive(ReceiveError),
    /// The shared control lock was lost. Cleanup must not start a new
    /// protected effect; the caller reports a non-zero stop.
    ControlLockLost,
}

impl fmt::Display for LinuxNodeRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(error) => write!(formatter, "configuration error: {error}"),
            Self::Platform(error) => {
                write!(formatter, "Linux platform configuration error: {error}")
            }
            Self::Backend(error) => write!(formatter, "Linux backend construction error: {error}"),
            Self::Mutation(error) => write!(formatter, "node mutation error: {error}"),
            Self::Authority(error) => write!(formatter, "authority error: {error}"),
            Self::Witness(error) => write!(formatter, "Witness runtime error: {error}"),
            Self::Workflow(error) => write!(formatter, "resource workflow error: {error:?}"),
            Self::Transition(error) => write!(formatter, "state transition error: {error}"),
            Self::Receive(error) => write!(formatter, "Witness receive error: {error}"),
            Self::ControlLockLost => formatter.write_str(
                "the control lock was lost; no further resource or lease operation was started",
            ),
        }
    }
}

impl std::error::Error for LinuxNodeRuntimeError {}

impl From<NodeMutationError> for LinuxNodeRuntimeError {
    fn from(error: NodeMutationError) -> Self {
        Self::Mutation(error)
    }
}

impl From<AuthorityError> for LinuxNodeRuntimeError {
    fn from(error: AuthorityError) -> Self {
        Self::Authority(error)
    }
}

impl From<NodeWitnessRuntimeError> for LinuxNodeRuntimeError {
    fn from(error: NodeWitnessRuntimeError) -> Self {
        Self::Witness(error)
    }
}

impl From<ResourceWorkflowError> for LinuxNodeRuntimeError {
    fn from(error: ResourceWorkflowError) -> Self {
        Self::Workflow(error)
    }
}

impl From<TransitionError> for LinuxNodeRuntimeError {
    fn from(error: TransitionError) -> Self {
        Self::Transition(error)
    }
}

impl From<ReceiveError> for LinuxNodeRuntimeError {
    fn from(error: ReceiveError) -> Self {
        Self::Receive(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExplicitOperationResult {
    Completed,
    Blocked,
    CleanupRequired,
    LeaseReleasePending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeResourceTruth {
    Present,
    Absent,
    Running,
    Stopped,
    Healthy,
    Unhealthy,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LinuxRuntimeSnapshot {
    pub(crate) node_state: NodeState,
    pub(crate) operation_phase: Option<OperationPhase>,
    pub(crate) vip: RuntimeResourceTruth,
    pub(crate) service: RuntimeResourceTruth,
    pub(crate) health: RuntimeResourceTruth,
    pub(crate) resource_owning: bool,
    pub(crate) authority_present: bool,
    pub(crate) recovery_reconciled: bool,
    pub(crate) unresolved_mutation: bool,
}

pub(crate) struct LinuxNodeRuntime<
    N = LinuxNetworkBackend,
    S = ServiceAdapter,
    C = SystemMonotonicClock,
> {
    controller: NodeAuthorityController<C>,
    executor: ResourceExecutor<N, S>,
    state_machine: StateMachine,
    mutation_store: crate::node_mutation::NodeMutationStore,
    node_id: NodeId,
    priority: i32,
    /// Design Revision 10 §9 permits shutdown to join the existing owner with
    /// *at most one* bounded eligible reconciliation step.  This latch makes
    /// that bound structural: once a step has been consumed no further
    /// shutdown step can run, so no retry loop is possible.
    shutdown_step_performed: bool,
    /// Stage 14 §16.7.1: the single bounded-process backend and its one
    /// pending-reap slot, owned here and driven only by the foreground owner.
    /// It is always constructed, whatever the `[fencing]` backend. Its only
    /// step entry is `run_fencing_process` (Phase 14.9): the gate G fence
    /// action and the `drive_fencing_step` verify poll.
    fencing_backend: crate::fencing_backend::CommandBackend,
    /// Stage 14 Design Revision 5 §16.1/§16.2: the validated `[fencing]`
    /// settings, trust-checked before this owner exists. Read only by the
    /// fencing gate and step (backend kind, argv, timeouts, poll budget).
    fencing_settings: crate::fencing_backend::FencingSettings,
    /// Stage 14 §26 R1: the configured fencing target, `config.peer.id`.
    fencing_target: NodeId,
    /// Stage 14 §13.2 T7: the runtime-only verify poll counter of the
    /// current process session, keyed by the exact incident and attempt
    /// token. Never persisted; a new token or incident starts at zero.
    verify_poll_counter: Option<(crate::fencing::IncidentRef, u64, u64)>,
    /// Phase 1-J29 (B1 / C1): what the fencing steps of this process did, for
    /// the automatic trigger only. Counted at the step itself, so a later
    /// retirement of the incident cannot erase it; runtime-only, never
    /// persisted and never evidence or authority (a new process starts at
    /// zero, A-9).
    auto_fence_activity: crate::auto_failover::FenceActivity,
    /// Amendment C, C-d (OD-J31-2 / OD-J31-4): the memory-only count of
    /// consecutive exhausted correlations of the retained mutation. Never
    /// persisted; a new process starts at zero.
    uncorrelated_retry: crate::node_lease_authority::node_witness_runtime::UncorrelatedRetryCounter,
    /// Amendment C, C-c (OD-J31-2): the spacing of post-demotion retries of a
    /// retained Renew that timed out on the same session. Runtime-only.
    renew_retry_backoff: crate::node_lease_authority::node_witness_runtime::RenewRetryBackoff,
    /// Stage 14 §18.4-§18.5: where the operator intent lives and what it
    /// must name. Read only by the ingestion step.
    attestation: AttestationBinding,
    /// v0.7 G-2 (`G2_SAFETY_CONTRACT.md` R4.1): the validated `[route]` settings, or `None` when
    /// no route handoff is configured (then no RH step ever runs).
    route: Option<crate::route_handoff::RouteSettings>,
    /// The RH of the term this node was promoted into in this process, until it is abandoned.
    route_driver: Option<crate::route_handoff::RhDriver>,
    /// G-2 §5.1 condition 1: a renewal of the current loop iteration was answered
    /// `AcceptedSuccess`. Reset at the start of every foreground lifecycle step.
    renewed_this_tick: bool,
    /// G-2 §5.1 condition 3: bounded process steps run in the current loop iteration.
    process_steps_this_tick: u32,
    /// Audit L-1: the internal-promotion line and the RH start line are written by the next
    /// RH tick, so they follow the attempt's own `Succeeded` line in the journal.
    /// `Some(true)` with a route handoff, `Some(false)` without one.
    pending_promotion_journal: Option<bool>,
    #[cfg(test)]
    promotion_test_hook: Option<Box<dyn FnMut()>>,
    /// Test-only: the non-root test user owns its private intent directory.
    #[cfg(test)]
    attestation_owner_for_test: Option<u32>,
}

/// The local facts the §18.5 ingestion step checks an intent against, fixed
/// when the runtime owner is built.
struct AttestationBinding {
    intent_dir: PathBuf,
    cluster_id: ClusterId,
    subject: String,
}

/// Stage 14 §18.5: what one ingestion step did. `removed` reports whether the
/// intent file was unlinked (and the directory fsynced) after the outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AttestationIngestion {
    /// Local state does not permit ingestion now; nothing was read.
    NotEligible,
    Absent,
    /// An install is in progress (`nlink != 1` with a `tmp-*` sibling).
    Deferred,
    /// File posture or parse failure: no state change.
    RejectedFile {
        fault: crate::attestation::IntentFault,
        removed: bool,
    },
    /// A bad intent: no state change.
    RejectedIntent {
        mismatch: crate::attestation::IntentMismatch,
        removed: bool,
    },
    /// The incident failed §26 continuity: retired (T9), intent rejected.
    Retired {
        violation: crate::fencing::ContinuityViolation,
        removed: bool,
    },
    /// Valid, but the incident is already `CONFIRMED`: no write.
    AlreadyConfirmed {
        removed: bool,
    },
    /// T8 committed: `CONFIRMED(operator)`.
    Confirmed {
        incident: crate::fencing::IncidentRef,
        removed: bool,
    },
    /// The T8 write failed before commit; the file stays for a later step.
    PreCommitFailure(String),
}

/// Stage 14 §27.2 T4: what the gate's one fence action did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FencingActionRecord {
    pub(crate) attempt_token: u64,
    /// Provenance only (§16.4): never confirmation.
    pub(crate) outcome: crate::fencing::ActionOutcome,
    /// `VERIFYING(k, outcome)` committed after the post-return rechecks;
    /// `false` is the C4 discard (rechecks failed or a pre-commit failure).
    pub(crate) verifying_persisted: bool,
}

/// Stage 14 §24 G: the gate's decision (Phase 14.10). A valid `CONFIRMED`
/// yields the clearance; everything else is a block with what the gate did.
#[derive(Debug)]
pub(crate) enum FencingGateDecision {
    /// The attempt retires `BlockedBeforeMutation(outcome.block)`.
    Block(FencingGateOutcome),
    /// The current durable `CONFIRMED` incident minted the attempt's
    /// clearance; the attempt may continue to H. Not authority.
    Clear {
        incident: IncidentTermRecord,
        clearance: crate::fencing::FencingClearance,
    },
}

/// Stage 14 §24 K (runtime half, items 6-14): the first final recheck that
/// failed. Any failure means no ARM, no resource mutation, no promotion; the
/// granted lease is cleaned up through §25.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FencingRecheckFailure {
    /// K6: not Standby, a phase is in progress, or an authority is installed.
    LocalState,
    /// K6: trusted ZeroResource was not observed.
    ZeroResource,
    /// K7: O or M is present.
    ObligationOrMutation,
    /// K8 / K14: the durable incident is absent, retired, or replaced.
    Incident,
    /// K9: the durable incident is not `CONFIRMED`.
    NotConfirmed,
    /// K10: the target is not the configured peer.
    Target,
    /// K11: the observer session is not the current session.
    ObserverSession,
    /// K12: no live episode, or a different loss generation.
    Episode,
    /// K13: current Witness term knowledge is not `anchor_term + 1`.
    WitnessTerm,
}

/// Stage 14 §25 success-ARM result of `arm_and_promote`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FencedArmOutcome {
    /// `ConfirmedCommitted`: incident consumed and O armed; authority
    /// restored; Stage 11 `promote` ran with this result.
    Promoted(ExplicitOperationResult),
    /// `PreCommitFailure`: old image (`CONFIRMED`, no O); no resource
    /// mutation; Rev 10 §4 unused-lease abort (no Release).
    NotCommitted(String),
    /// Old-image validation mismatch: nothing written; no resource mutation.
    Rejected(String),
    /// Uncertain persistence: RecoveryBlocked; no resource mutation.
    RecoveryBlocked(String),
}

/// Stage 14 §25.1 / Stage 13.6 result of `release_attempt_lease_once`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AttemptLeaseRelease {
    /// The durable cleanup O is armed (§25.1 commit, the unchanged plain ARM
    /// with no incident, or already present) and the exact LeaseRelease was
    /// begun and executed once.
    Executed(NodeWitnessMutationResult),
    /// §25.1 `PreCommitFailure`: old image (incident, no O); no Release; the
    /// runtime authority is discarded and the lease expires.
    CleanupNotCommitted(String),
    /// §25.1 uncertain or old-image mismatch, or an incident without its
    /// cleanup binding: RecoveryBlocked; no Release; the lease expires.
    RecoveryBlocked(String),
}

/// Stage 14 §24 G: a blocking gate decision and what the gate did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FencingGateOutcome {
    pub(crate) block: crate::fencing::FencingGateBlock,
    /// The current incident after the gate, as the R4 term record of this
    /// gate's fresh view (whose term equals the incident's anchor).
    pub(crate) incident: Option<IncidentTermRecord>,
    /// A stale incident retired (T9) at this gate.
    pub(crate) retired: Option<crate::fencing::ContinuityViolation>,
    /// Whether this gate opened the incident (T1/T2).
    pub(crate) opened: bool,
    pub(crate) action: Option<FencingActionRecord>,
    /// Stage 14 §28: the `fencing.state` operator name of the incident this
    /// block concerns. Presentation only (the operator log); no decision
    /// reads it.
    pub(crate) state: Option<&'static str>,
}

/// Stage 14 §26 R4 input for the fencing step and ingestion: the newest
/// authenticated TermStatus term observed since the incident opened, bound to
/// that exact incident. The gate sets it from the fresh `Authorized` view
/// (the anchor observation); every later authenticated correlated TermStatus
/// completion is recorded through `record_term`. A Witness `Unavailable`
/// never clears it. Runtime-only; a record for another incident is never
/// used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IncidentTermRecord {
    pub(crate) incident: crate::fencing::IncidentRef,
    pub(crate) anchor: Term,
    pub(crate) newest: Term,
}

impl IncidentTermRecord {
    /// Record one authenticated TermStatus term. The newest term replaces the
    /// previous one while it still equals the anchor; once a term other than
    /// the anchor was observed it is kept, so a later term cannot mask an
    /// R4 failure that the fencing step has not yet acted on.
    pub(crate) fn record_term(&mut self, term: Term) {
        if self.newest == self.anchor {
            self.newest = term;
        }
    }
}

/// Stage 14 §28: the bounded operator-log name of a §26 continuity failure.
/// Presentation only: it is never compared, parsed, or persisted.
fn retire_reason(violation: crate::fencing::ContinuityViolation) -> &'static str {
    use crate::fencing::ContinuityViolation;
    match violation {
        ContinuityViolation::Target => "target is no longer the configured peer",
        ContinuityViolation::ObserverSession => "observer session changed",
        ContinuityViolation::Episode => "peer-loss episode ended",
        ContinuityViolation::WitnessEpoch => "Witness term moved",
    }
}

/// The automatic trigger's view of one durable incident (identity and
/// progress; only equality is used). `UNKNOWN` stores no token, so it is
/// reported with the token high-water: every attempt (T2/T3) raises it, and
/// an attempt that ends `UNKNOWN` again is a change the trigger counts
/// against `max_fence_actions` (Phase 1-J28 H-1).
pub(crate) fn auto_incident_facts_of(
    incident: &crate::fencing::FencingIncident,
) -> crate::auto_failover::IncidentFacts {
    use crate::auto_failover::{IncidentFacts, IncidentKind};
    use crate::fencing::FencingState;
    let (kind, attempt_token) = match incident.state {
        FencingState::Unknown(_) => (IncidentKind::Unknown, incident.attempt_token_high_water),
        FencingState::Requested { attempt_token } => (IncidentKind::Requested, attempt_token),
        FencingState::Verifying { attempt_token, .. } => (IncidentKind::Verifying, attempt_token),
        FencingState::Confirmed(_) => (IncidentKind::Confirmed, 0),
        FencingState::Failed { attempt_token } => (IncidentKind::Failed, attempt_token),
    };
    IncidentFacts {
        seq: incident.incident_seq,
        attempt_token,
        kind,
    }
}

/// Stage 14 §17 / §13.2: what one verify poll's result did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VerifyApplied {
    /// §17.2: a post-return recheck failed; the result was discarded.
    Discarded,
    /// An inconclusive poll with budget remaining (no durable write), or an
    /// idempotent no-op.
    Unchanged,
    /// T5 / T6 / T7 committed; the new state.
    Written(crate::fencing::FencingState),
    /// The write failed before commit; nothing changed.
    PreCommitFailure(String),
}

/// Stage 14 §27.3: what one `drive_fencing_step` did (at most one of
/// retirement, ingestion, or one verify poll).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FencingStepOutcome {
    /// R7 local state or shutdown: nothing was read or written.
    NotEligible,
    NoIncident,
    /// §26: continuity failed; the exact incident was retired (T9).
    Retired(crate::fencing::ContinuityViolation),
    /// No R4 term record for this current-session incident: fail closed,
    /// no mutation.
    R4EvidenceMissing,
    /// §18.5 ingestion ran and found an intent (or a posture failure).
    Ingested(AttestationIngestion),
    /// A verify poll ran.
    Polled {
        attempt_token: u64,
        result: crate::fencing_backend::VerifyOutcome,
        applied: VerifyApplied,
    },
    /// Nothing to do in this state (UNKNOWN, REQUESTED, CONFIRMED, FAILED,
    /// or an exhausted budget).
    NoAction,
}

/// Wall-clock milliseconds for display fields only (never a deadline).
fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64)
}

/// v0.7 G-2: the Linux runtime as the route handoff's platform (read-only facts, the lease
/// timing, and the one bounded helper step).
struct LinuxRhPlatform<'a, N, S, C>
where
    N: NetworkBackend,
    S: ServiceBackend,
    C: crate::node_lease_authority::MonotonicClock,
{
    runtime: &'a mut LinuxNodeRuntime<N, S, C>,
    control_lock_safe: &'a dyn Fn() -> bool,
    before_blocking_step: &'a mut dyn FnMut(),
}

impl<N, S, C> crate::route_handoff::RhPlatform for LinuxRhPlatform<'_, N, S, C>
where
    N: NetworkBackend,
    S: ServiceBackend,
    C: crate::node_lease_authority::MonotonicClock,
{
    fn facts(&mut self) -> crate::route_handoff::RhFacts {
        use crate::route_handoff::NodeClass;
        let runtime = &*self.runtime;
        let now_ms = runtime
            .controller
            .authority()
            .clock()
            .now()
            .map(|now| now.as_millis())
            .unwrap_or(0);
        let node = match (
            runtime.state_machine.node_state(),
            runtime.state_machine.operation_phase(),
        ) {
            (NodeState::Active, None) => NodeClass::Active,
            (NodeState::Active | NodeState::Degraded | NodeState::QuorumUnknown, _) => {
                NodeClass::ActiveHold
            }
            _ => NodeClass::Other,
        };
        let authority = runtime.controller.authority().authority();
        crate::route_handoff::RhFacts {
            now_ms,
            unix_ms: unix_now_ms(),
            node,
            lease_term: authority.map(|authority| authority.term().0),
            lease_usable: authority
                .is_some_and(|authority| runtime.attempt_lease_usable(authority)),
            renewed_this_tick: runtime.renewed_this_tick,
            other_step_this_tick: runtime.process_steps_this_tick > 0,
            pending_reap_free: runtime.fencing_backend.pending_reap_diagnostics().is_none(),
            control_lock_safe: (self.control_lock_safe)(),
        }
    }

    fn lease_remaining(&mut self) -> Option<std::time::Duration> {
        let runtime = &*self.runtime;
        let authority = runtime.controller.authority().authority()?;
        let now = runtime.controller.authority().clock().now().ok()?;
        Some(std::time::Duration::from_millis(
            authority
                .safe_deadline()
                .as_millis()
                .saturating_sub(now.as_millis()),
        ))
    }

    fn control_lock_safe(&mut self) -> bool {
        (self.control_lock_safe)()
    }

    fn spawn_route_step(
        &mut self,
        step: crate::route_handoff::RhStep,
        record: &crate::route_handoff::RhRecord,
        intent: &std::path::Path,
    ) -> Result<crate::route_handoff::RhAnswer, String> {
        // §27.5 / R4.1 L-R3-1: a route step is a blocking step like a fencing step.
        (self.before_blocking_step)();
        self.runtime
            .run_route_process(step, record, intent)
            .map_err(|error| error.to_string())
    }

    fn journal(&mut self, record: &crate::route_handoff::RhRecord, warn: bool) {
        crate::operator_log::route_handoff_state(&record.describe(), &record.reason, warn);
    }

    fn measured(&mut self, line: &str) {
        crate::operator_log::info_route_step_measured(line);
    }
}

impl LinuxNodeRuntime<LinuxNetworkBackend, ServiceAdapter, SystemMonotonicClock> {
    pub(crate) fn new(
        config: &Config,
        platform: LinuxPlatformConfig,
    ) -> Result<Self, LinuxNodeRuntimeError> {
        config
            .validate()
            .map_err(|error| LinuxNodeRuntimeError::Configuration(error.to_string()))?;
        // §16.2 at startup: an untrusted fence/verify executable refuses the
        // daemon before any backend is built.
        let fencing_settings =
            crate::fencing_backend::FencingSettings::startup(config.fencing.as_ref())
                .map_err(|error| LinuxNodeRuntimeError::Configuration(error.to_string()))?;
        let network_config = platform
            .network_config(config)
            .map_err(|error| LinuxNodeRuntimeError::Platform(error.to_string()))?;
        let network = LinuxNetworkBackend::new(network_config)
            .map_err(|error| LinuxNodeRuntimeError::Backend(error.to_string()))?;
        let attestation = AttestationBinding {
            intent_dir: crate::attestation::intent_dir(std::path::Path::new(&config.state.path))
                .ok_or_else(|| {
                    LinuxNodeRuntimeError::Configuration(
                        "state.path has no parent directory".into(),
                    )
                })?
                .to_path_buf(),
            cluster_id: ClusterId::new(config.cluster.id.clone()),
            subject: crate::attestation::canonical_subject(config)
                .unwrap_or(config.cluster.id.as_str())
                .to_string(),
        };
        let start_timeout = Duration::from_secs(config.service.start_timeout_sec);
        let stop_timeout = Duration::from_secs(config.service.stop_timeout_sec);
        let health_timeout = Duration::from_secs(config.health.timeout_sec);
        let service = match config.service.manager {
            ServiceManager::Systemd => {
                let unit = config.service.unit.clone().ok_or_else(|| {
                    LinuxNodeRuntimeError::Configuration("service.unit is required".into())
                })?;
                ServiceAdapter::Systemd(
                    LinuxSystemdServiceBackend::new(
                        unit,
                        start_timeout,
                        stop_timeout,
                        config.health.command.clone(),
                        health_timeout,
                    )
                    .map_err(|error| LinuxNodeRuntimeError::Backend(error.to_string()))?,
                )
            }
            ServiceManager::Command => {
                let argv = |value: &Option<Vec<String>>, key: &str| {
                    value.clone().ok_or_else(|| {
                        LinuxNodeRuntimeError::Configuration(format!("{key} is required"))
                    })
                };
                ServiceAdapter::External(
                    ExternalServiceBackend::new(
                        argv(&config.service.start, "service.start")?,
                        argv(&config.service.stop, "service.stop")?,
                        argv(&config.service.status, "service.status")?,
                        config.health.command.clone(),
                        start_timeout,
                        stop_timeout,
                        health_timeout,
                    )
                    .map_err(|error| LinuxNodeRuntimeError::Configuration(error.to_string()))?,
                )
            }
        };

        let cluster_id = ClusterId::new(config.cluster.id.clone());
        let node_id = NodeId::new(config.node.id.clone());
        let mutation_store = crate::node_mutation::NodeMutationStore::new(
            config.state.path.clone(),
            cluster_id,
            node_id.clone(),
        );
        let mode = match config.cluster.mode {
            Mode::Conservative => AuthorityMode::Conservative,
            Mode::Availability => AuthorityMode::Availability,
        };
        let controller = NodeAuthorityController::new_for_runtime(
            SystemMonotonicClock::new(),
            node_id.clone(),
            mutation_store,
            mode,
        );
        if let Some(notice) = fencing_settings.startup_notice() {
            eprintln!("mikagami: {notice}");
        }
        if let Some(route) = &config.route {
            crate::fencing_backend::trust_route_helper(&route.helper)
                .map_err(LinuxNodeRuntimeError::Configuration)?;
        }
        let route = crate::route_handoff::RouteSettings::startup(config, unix_now_ms())
            .map_err(LinuxNodeRuntimeError::Configuration)?;
        Ok(Self {
            controller,
            executor: ResourceExecutor::new(network, service),
            state_machine: StateMachine::new(),
            mutation_store: crate::node_mutation::NodeMutationStore::new(
                config.state.path.clone(),
                ClusterId::new(config.cluster.id.clone()),
                node_id.clone(),
            ),
            node_id,
            priority: config.node.priority,
            shutdown_step_performed: false,
            fencing_backend: crate::fencing_backend::CommandBackend::system(),
            fencing_settings,
            fencing_target: NodeId::new(config.peer.id.clone()),
            verify_poll_counter: None,
            auto_fence_activity: crate::auto_failover::FenceActivity::default(),
            uncorrelated_retry: Default::default(),
            renew_retry_backoff: Default::default(),
            attestation,
            route,
            route_driver: None,
            renewed_this_tick: false,
            process_steps_this_tick: 0,
            pending_promotion_journal: None,
            #[cfg(test)]
            promotion_test_hook: None,
            #[cfg(test)]
            attestation_owner_for_test: None,
        })
    }
}

/// Stage 14 Phase 14.11 (L1-MEM): the minimum wait the *renew* term of the
/// Active schedule can impose between two foreground iterations.
///
/// A Witness grant may legally carry any `0 < renew_after_ms < lease_ttl_ms`
/// (`validate_grant`), so `renew_in` can be `0` after every successful
/// renewal; without a floor the loop would then spin one authenticated
/// Witness round trip per iteration with no wait. The floor bounds the
/// foreground tick rate, which in turn bounds the entries the diagnostic
/// `ListenerInterference` window can hold (see
/// `MIKAGAMI_STAGE_14_PHASE_14_11_L1_MEM_SCHEDULER_ADDENDUM.md`).
///
/// It applies to the renew term only: `expiry_in` is never floored, and the
/// outstanding-`LeaseRenew` branch is unchanged.
pub(crate) const ACTIVE_RENEW_MIN_WAIT: Duration = Duration::from_millis(100);

/// The Active wait for already-known relative delays (side-effect free).
///
/// - outstanding `LeaseRenew`: `min(ordinary, expiry_in)` (unchanged; `renew_in`
///   is deliberately not consulted);
/// - otherwise: `min(ordinary, max(renew_in, ACTIVE_RENEW_MIN_WAIT), expiry_in)`.
///
/// The result is a *requested* wait: it never exceeds `ordinary` and never
/// exceeds `expiry_in`, so the floor cannot lengthen the requested wait beyond
/// the ordinary cadence or beyond the safe deadline. The actual wake depends on
/// OS scheduling and sleep overshoot, so it is not guaranteed to precede the
/// safe deadline, and neither is the physical completion of a demotion. Use of
/// the authority at or after the safe deadline is refused by the existing
/// checkpoints (`check_authority_usable`, `renewal_due`), not by this wait.
pub(crate) fn active_wait_delay(
    ordinary: Duration,
    renew_in: Duration,
    expiry_in: Duration,
    renew_outstanding: bool,
) -> Duration {
    if renew_outstanding {
        return ordinary.min(expiry_in);
    }
    ordinary
        .min(renew_in.max(ACTIVE_RENEW_MIN_WAIT))
        .min(expiry_in)
}

/// v0.6 A-2: the result of replaying a retained `LeaseRenew` at startup.
#[derive(Debug)]
pub(crate) enum RetainedRenewOutcome {
    /// The durable record is cleared; `how` is the classification for the log.
    Resolved { how: &'static str },
    /// The record is retained; the caller must stay recovery-blocked.
    Blocked { reason: String },
    /// J23 (OD-J22-5): the retained request is resolved, but the Release of its unused grant is
    /// not confirmed; the release obligation and the Release record stay for the startup
    /// reconciliation. Only the retained-request resolution produces it.
    ResolvedReleaseUnconfirmed { how: &'static str },
}

/// J23 (C-F): the fixed lease id of every generation fence. It is defined once, next to the fence
/// send path in the platform-independent `node_witness_runtime` (which checks it before sending).
pub(crate) use crate::node_lease_authority::node_witness_runtime::GENERATION_FENCE_LEASE_ID;

/// J23 (C-F): the fixed reason of every generation fence (part of its fingerprint; NEVER CHANGE it
/// without a migration, see `GENERATION_FENCE_LEASE_ID`).
pub(crate) const GENERATION_FENCE_REASON: &str =
    "generation fence of a retained lease request (no lease is released)";

/// J23 (C-F): the log text of a retained LeaseRequest resolved by its generation fence.
pub(crate) const RETAINED_REQUEST_FENCED: &str = "generation fence: the request was never committed and can no longer commit; no lease was granted";

/// J23 (OD-J22-1, C-F): the generation fence of a retained LeaseRequest `request`.
///
/// The fence is an existing LEASE_RELEASE at the request's generation with term 0 and the fixed,
/// non-UUID lease id and reason. Its request id is derived deterministically from the request's id
/// and generation (SHA-256, then shaped as a canonical UUIDv4), so the fence is identical after any
/// restart and needs no durable record of its own; it differs from the request's id. A fence never
/// creates authority: the Witness can only commit it as a PolicyReject (it matches no lease), which
/// fills the generation so that the request can never commit afterwards.
pub(crate) fn generation_fence_of(
    request: &crate::node_mutation::OutstandingWitnessMutation,
) -> Result<crate::node_mutation::OutstandingWitnessMutation, LinuxNodeRuntimeError> {
    if request.kind() != crate::node_mutation::MutationKind::LeaseRequest {
        return Err(LinuxNodeRuntimeError::Backend(
            "a generation fence is derived only from a retained LeaseRequest".to_string(),
        ));
    }
    let fence_id = crate::node_lease_authority::node_witness_runtime::generation_fence_request_id(
        &request.request_id,
        request.mutation_generation,
    );
    let id = crate::protocol::RequestId::new(fence_id.clone());
    if !crate::protocol::is_valid_mutating_request_id(&fence_id) || id == request.request_id {
        return Err(LinuxNodeRuntimeError::Backend(
            "the derived generation fence id is not a distinct canonical request id".to_string(),
        ));
    }
    Ok(crate::node_mutation::OutstandingWitnessMutation {
        request_id: id,
        mutation_generation: request.mutation_generation,
        mutation: crate::node_mutation::DurableWitnessMutation::LeaseRelease {
            term: Term(0),
            lease_id: LeaseId::new(GENERATION_FENCE_LEASE_ID),
            reason: GENERATION_FENCE_REASON.to_string(),
        },
    })
}

/// J23: the log text of a terminal answer to the exact replay of a retained LeaseRequest.
fn request_replay_label(
    result: &crate::node_lease_authority::node_witness_runtime::NodeWitnessMutationResult,
) -> &'static str {
    use crate::node_lease_authority::node_witness_runtime::NodeWitnessMutationResult as R;
    match result {
        R::RetiredStale { .. } => "exact replay: retired stale (the generation was used before)",
        R::DeterministicReject { .. } => "exact replay: deterministic reject",
        _ => "exact replay: no terminal answer",
    }
}

/// J22 (OD-J21-5 B-1): the log text of a retained LeaseRequest whose grant was released as an
/// unused lease (reconstructed, or created by the first delivery of the replay) and the Witness
/// confirmed it with LEASE_RELEASED (both durable records are gone).
pub(crate) const UNUSED_GRANT_RELEASED: &str = "exact replay: an earlier commit of the request answered with its current grant; the Witness confirmed its release (LEASE_RELEASED)";

/// J22 (OD-J21-5 B-1): the durable record left by the Release of an unused grant from a retained
/// LeaseRequest. The resolution reports from it, never from the attempt alone, so that "released"
/// is written only when the Witness answered LEASE_RELEASED and both records are gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnusedGrantRelease {
    /// Neither the release obligation nor a Release record remains.
    NothingRecorded,
    /// The release obligation is recorded; no Release was begun.
    ObligationOnly,
    /// The release obligation and the exact Release record remain.
    ReleasePending,
    /// Any other combination (for example a Release record without its obligation).
    Inconsistent,
}

impl UnusedGrantRelease {
    fn from_record(
        obligation: bool,
        outstanding: Option<crate::node_mutation::MutationKind>,
    ) -> Self {
        match (obligation, outstanding) {
            (false, None) => Self::NothingRecorded,
            (true, None) => Self::ObligationOnly,
            (true, Some(crate::node_mutation::MutationKind::LeaseRelease)) => Self::ReleasePending,
            _ => Self::Inconsistent,
        }
    }

    fn describe(self) -> &'static str {
        match self {
            Self::NothingRecorded => "nothing is recorded; the lease expires at the Witness",
            Self::ObligationOnly => {
                "the release obligation is recorded; the startup reconciliation releases it"
            }
            Self::ReleasePending => {
                "the release obligation and the Release record stay for the startup reconciliation"
            }
            Self::Inconsistent => "the durable record is inconsistent",
        }
    }

    /// The Release was sent and answered.
    ///
    /// J23 (C-F): the exact replay is reached only after the generation fence was answered
    /// retired-stale, so a grant answered to it is the reconstruction of an earlier commit of the
    /// request. J23 (OD-J22-5): a request whose unused grant is not proven released is a distinct
    /// outcome (`ResolvedReleaseUnconfirmed`), logged as a warning, never as "released".
    fn after_answer(
        self,
        answer: &NodeWitnessMutationResult,
    ) -> Result<RetainedRenewOutcome, LinuxNodeRuntimeError> {
        use crate::node_lease_authority::node_witness_runtime::NodeWitnessSuccess;
        use NodeWitnessMutationResult as R;
        match (answer, self) {
            (
                R::AcceptedSuccess {
                    response: NodeWitnessSuccess::LeaseReleased(_),
                    ..
                },
                Self::NothingRecorded,
            ) => Ok(RetainedRenewOutcome::Resolved {
                how: UNUSED_GRANT_RELEASED,
            }),
            (R::DeterministicReject { .. }, Self::ReleasePending) => {
                Ok(RetainedRenewOutcome::ResolvedReleaseUnconfirmed {
                    how: "exact replay: an earlier commit answered with its current grant; its Release was rejected, release NOT confirmed; the release obligation and the Release record stay for the startup reconciliation",
                })
            }
            (R::RetiredStale { .. }, Self::ReleasePending) => {
                Ok(RetainedRenewOutcome::ResolvedReleaseUnconfirmed {
                    how: "exact replay: an earlier commit answered with its current grant; its Release was answered retired-stale, release NOT confirmed; the release obligation and the Release record stay for the startup reconciliation",
                })
            }
            (
                R::Conflict { .. } | R::GenerationGap { .. } | R::TemporarilyUnavailable { .. },
                Self::ReleasePending,
            ) => Ok(RetainedRenewOutcome::ResolvedReleaseUnconfirmed {
                how: "exact replay: an earlier commit answered with its current grant; its Release got no release outcome, release NOT confirmed; the release obligation and the Release record stay for the startup reconciliation",
            }),
            _ => Err(LinuxNodeRuntimeError::Backend(format!(
                "the unused grant's Release answer does not match the durable record ({})",
                self.describe()
            ))),
        }
    }

    /// The Release attempt stopped (not begun, not sent, or its answer or completion was lost).
    fn after_stop(self, cause: &str) -> Result<RetainedRenewOutcome, LinuxNodeRuntimeError> {
        let what = match self {
            Self::NothingRecorded | Self::ObligationOnly => "was not sent",
            Self::ReleasePending => "is not confirmed",
            Self::Inconsistent => {
                return Err(LinuxNodeRuntimeError::Backend(format!(
                    "the unused grant's Release stopped ({cause}) and {}",
                    self.describe()
                )));
            }
        };
        // The durable state comes first and the cause last: the operator log bounds the line
        // (`bounded_reason`, 240 bytes), so only the cause detail can be cut.
        Ok(RetainedRenewOutcome::Blocked {
            reason: format!(
                "the retained request was answered with a grant; its Release {what}; {}; cause: {cause}",
                self.describe()
            ),
        })
    }
}

fn renew_result_is_terminal(
    result: &crate::node_lease_authority::node_witness_runtime::NodeWitnessMutationResult,
) -> bool {
    use crate::node_lease_authority::node_witness_runtime::NodeWitnessMutationResult as R;
    matches!(
        result,
        R::AcceptedSuccess { .. } | R::DeterministicReject { .. } | R::RetiredStale { .. }
    )
}

fn renew_result_label(
    result: &crate::node_lease_authority::node_witness_runtime::NodeWitnessMutationResult,
) -> &'static str {
    use crate::node_lease_authority::node_witness_runtime::NodeWitnessMutationResult as R;
    match result {
        R::AcceptedSuccess { .. } => "renewal accepted",
        R::DeterministicReject { .. } => "deterministic reject",
        R::RetiredStale { .. } => "retired stale",
        R::Conflict { .. } => "conflict",
        R::GenerationGap { .. } => "generation gap",
        R::TemporarilyUnavailable { .. } => "temporarily unavailable",
    }
}

impl<N, S, C> LinuxNodeRuntime<N, S, C>
where
    N: NetworkBackend,
    S: ServiceBackend,
    C: crate::node_lease_authority::MonotonicClock,
{
    pub(crate) fn foreground_witness_required(&self) -> bool {
        self.state_machine.node_state() == NodeState::Active
            || matches!(
                self.state_machine.operation_phase(),
                Some(OperationPhase::Demotion(
                    crate::state_machine::DemotionPhase::ReleaseLease
                ))
            )
    }

    /// GET_TERM priming is a Standby-only concern. Active and demotion work
    /// own the sole Witness slot and must never be displaced by observation.
    pub(crate) fn authority_observation_allowed(&self) -> bool {
        self.state_machine.node_state() == NodeState::Standby
            && self.state_machine.operation_phase().is_none()
    }

    pub(crate) fn active_schedule_delay(
        &self,
        ordinary: Duration,
    ) -> Result<Duration, LinuxNodeRuntimeError> {
        if self.state_machine.node_state() != NodeState::Active
            || self.state_machine.operation_phase().is_some()
            || self.controller.authority().demotion_latched()
        {
            return Ok(ordinary);
        }
        let Some(delays) = self.controller.active_schedule_delays()? else {
            return Ok(ordinary);
        };
        let renew_outstanding = self
            .mutation_store
            .outstanding()?
            .is_some_and(|outstanding| {
                outstanding.kind() == crate::node_mutation::MutationKind::LeaseRenew
            });
        Ok(active_wait_delay(
            ordinary,
            delays.renew_in,
            delays.expiry_in,
            renew_outstanding,
        ))
    }

    #[cfg(test)]
    fn from_test_parts(
        controller: NodeAuthorityController<C>,
        executor: ResourceExecutor<N, S>,
        mutation_store: crate::node_mutation::NodeMutationStore,
        node_id: NodeId,
        priority: i32,
    ) -> Self {
        Self {
            controller,
            executor,
            state_machine: StateMachine::new(),
            mutation_store,
            node_id,
            priority,
            shutdown_step_performed: false,
            fencing_backend: crate::fencing_backend::CommandBackend::system(),
            fencing_settings: crate::fencing_backend::FencingSettings::None,
            fencing_target: NodeId::new("node-b"),
            verify_poll_counter: None,
            auto_fence_activity: crate::auto_failover::FenceActivity::default(),
            uncorrelated_retry: Default::default(),
            renew_retry_backoff: Default::default(),
            attestation: AttestationBinding {
                intent_dir: std::env::temp_dir(),
                cluster_id: ClusterId::new("cluster"),
                subject: "example.service".to_string(),
            },
            route: None,
            route_driver: None,
            renewed_this_tick: false,
            process_steps_this_tick: 0,
            pending_promotion_journal: None,
            promotion_test_hook: None,
            attestation_owner_for_test: None,
        }
    }

    /// Stage 14 §18.5 daemon ingestion step: validate the one intent file,
    /// then make at most one durable write — T8 through the exact CAS, or T9
    /// when the incident's own §26 continuity failed — preserving M and O. It
    /// reads at most one file and never leases, promotes, or touches
    /// resources.
    ///
    /// Its one production caller is `drive_fencing_step` (§27.3; Phase 14.9),
    /// which owns the daemon-level gating (Running, not shutting down) and
    /// supplies the continuity context and the newest authenticated
    /// TermStatus term from the incident-bound record.
    pub(crate) fn ingest_attestation(
        &self,
        context: &crate::fencing::ContinuityContext<'_>,
        latest_observed_term: Option<Term>,
    ) -> Result<AttestationIngestion, LinuxNodeRuntimeError> {
        let owner = crate::attestation::ROOT_UID;
        // Test-only: a non-root test run owns its private intent directory.
        #[cfg(test)]
        let owner = self.attestation_owner_for_test.unwrap_or(owner);
        let result = self.ingest_attestation_as(context, latest_observed_term, owner)?;
        // §28: one WARN per rejected intent, with a bounded reason. The line
        // is written after the outcome and is never read back.
        match &result {
            AttestationIngestion::RejectedFile { fault, .. } => {
                crate::operator_log::warn_attestation_rejected(&format!("{fault:?}"));
            }
            AttestationIngestion::RejectedIntent { mismatch, .. } => {
                crate::operator_log::warn_attestation_rejected(&format!("{mismatch:?}"));
            }
            AttestationIngestion::PreCommitFailure(_) => {
                crate::operator_log::warn_attestation_rejected("not committed");
            }
            _ => {}
        }
        Ok(result)
    }

    fn ingest_attestation_as(
        &self,
        context: &crate::fencing::ContinuityContext<'_>,
        latest_observed_term: Option<Term>,
        owner: u32,
    ) -> Result<AttestationIngestion, LinuxNodeRuntimeError> {
        use crate::attestation::{IntentBinding, IntentRead, IntentVerdict};
        use crate::fencing::FencingEventOutcome;
        // §18.5: Standby, no phase, no installed authority, no O/M, and an
        // open incident.
        if self.state_machine.node_state() != NodeState::Standby
            || self.state_machine.operation_phase().is_some()
            || self.controller.authority().authority().is_some()
        {
            return Ok(AttestationIngestion::NotEligible);
        }
        let persistent = self.mutation_store.load_existing()?;
        if persistent.release_obligation.is_some() || persistent.outstanding_mutation.is_some() {
            return Ok(AttestationIngestion::NotEligible);
        }
        let Some(incident) = persistent.fencing_incident else {
            return Ok(AttestationIngestion::NotEligible);
        };
        // F14.8-01: one validated directory object for the read, the removal,
        // and the directory fsync. An untrusted directory is never touched.
        let trusted =
            match crate::attestation::TrustedDir::open(&self.attestation.intent_dir, owner) {
                Ok(trusted) => trusted,
                Err(fault) => {
                    return Ok(AttestationIngestion::RejectedFile {
                        fault,
                        removed: false,
                    });
                }
            };
        let removed = || crate::attestation::remove_intent(&trusted).is_ok();
        let intent = match crate::attestation::read_intent(&trusted) {
            IntentRead::Absent => return Ok(AttestationIngestion::Absent),
            IntentRead::Defer => return Ok(AttestationIngestion::Deferred),
            IntentRead::Reject(fault) => {
                return Ok(AttestationIngestion::RejectedFile {
                    fault,
                    removed: removed(),
                });
            }
            IntentRead::Intent(intent) => intent,
        };
        let binding = IntentBinding {
            cluster_id: &self.attestation.cluster_id,
            node_id: &self.node_id,
            subject: &self.attestation.subject,
        };
        match crate::attestation::validate_intent(
            &intent,
            &incident,
            &binding,
            context,
            latest_observed_term,
        ) {
            IntentVerdict::Reject(mismatch) => Ok(AttestationIngestion::RejectedIntent {
                mismatch,
                removed: removed(),
            }),
            IntentVerdict::Retire(violation) => {
                self.mutation_store
                    .retire_fencing_incident(&incident.incident_ref())?;
                crate::operator_log::info_fencing_incident_retired(
                    incident.incident_seq,
                    incident.target_node_id.as_str(),
                    retire_reason(violation),
                );
                Ok(AttestationIngestion::Retired {
                    violation,
                    removed: removed(),
                })
            }
            IntentVerdict::Accept(attestation_id) => {
                match incident
                    .confirm_by_attestation(attestation_id)
                    .map_err(|error| LinuxNodeRuntimeError::Backend(format!("{error:?}")))?
                {
                    FencingEventOutcome::NoOp => {
                        Ok(AttestationIngestion::AlreadyConfirmed { removed: removed() })
                    }
                    FencingEventOutcome::Transition(transition) => {
                        match self.mutation_store.apply_fencing_transition(transition) {
                            Ok(_) => {
                                crate::operator_log::info_fencing_transition(
                                    incident.incident_seq,
                                    incident.target_node_id.as_str(),
                                    incident.state.operator_name(),
                                    "CONFIRMED",
                                );
                                Ok(AttestationIngestion::Confirmed {
                                    incident: incident.incident_ref(),
                                    removed: removed(),
                                })
                            }
                            Err(NodeMutationError::Io(reason)) => {
                                Ok(AttestationIngestion::PreCommitFailure(reason))
                            }
                            Err(error) => Err(error.into()),
                        }
                    }
                }
            }
        }
    }

    /// Stage 14 §26 R1: the configured fencing target.
    pub(crate) fn fencing_target(&self) -> &NodeId {
        &self.fencing_target
    }

    /// §24 G / §27.3 / §18.5 local eligibility (§26 R7): not shutting down,
    /// Standby with no phase and no installed authority, and O = M = None.
    /// Returns the durable image the step works from, or `None`.
    fn fencing_eligible_image(
        &self,
        shutdown_requested: bool,
    ) -> Result<Option<crate::node_mutation::NodeMutationPersistentState>, LinuxNodeRuntimeError>
    {
        if shutdown_requested
            || self.state_machine.node_state() != NodeState::Standby
            || self.state_machine.operation_phase().is_some()
            || self.controller.authority().authority().is_some()
        {
            return Ok(None);
        }
        let persistent = self.mutation_store.load_existing()?;
        if persistent.release_obligation.is_some() || persistent.outstanding_mutation.is_some() {
            return Ok(None);
        }
        Ok(Some(persistent))
    }

    /// §27.2 step 3 / §17.2: a step's result applies only if, after it
    /// returned, there is still no shutdown, the local state is eligible, the
    /// durable incident is still exactly `expected`, and §26 continuity
    /// still holds against `epoch`. `shutdown_requested` must be a live
    /// sample taken after the bounded step returned (F14.9-01), never a value
    /// captured before the step.
    fn fencing_result_applies(
        &self,
        expected: &crate::fencing::FencingIncident,
        shutdown_requested: bool,
        context: &crate::fencing::ContinuityContext<'_>,
        epoch: crate::fencing::WitnessEpoch,
    ) -> Result<bool, LinuxNodeRuntimeError> {
        let Some(image) = self.fencing_eligible_image(shutdown_requested)? else {
            return Ok(false);
        };
        if image.fencing_incident.as_ref() != Some(expected) {
            return Ok(false);
        }
        Ok(expected.check_continuity(context, epoch).is_ok())
    }

    /// One legal §13.2 transition through the exact-CAS store write. `None`
    /// is a pre-commit failure: nothing changed. Uncertain or mismatched
    /// writes are errors for the caller's fail-closed path.
    fn apply_fencing(
        &self,
        transition: crate::fencing::FencingTransition,
    ) -> Result<Option<crate::fencing::FencingIncident>, LinuxNodeRuntimeError> {
        // §28: one INFO per committed durable transition. The names are read
        // before the transition is consumed and are never used afterwards.
        let from = transition.from().state.operator_name();
        // Phase 1-J25 TEST-ONLY (feature `j25-fault-injection`): a crash of the promoting node just
        // before / just after its CONFIRMED is written (J25 §10 points 6 and 7).
        #[cfg(feature = "j25-fault-injection")]
        let confirming = matches!(
            transition.to().state,
            crate::fencing::FencingState::Confirmed(_)
        );
        #[cfg(feature = "j25-fault-injection")]
        if confirming {
            crate::j25_fault_injection::crash_if("j25-before-confirm-persist");
        }
        match self.mutation_store.apply_fencing_transition(transition) {
            Ok(incident) => {
                #[cfg(feature = "j25-fault-injection")]
                if confirming {
                    crate::j25_fault_injection::crash_if("j25-after-confirm-persist");
                }
                crate::operator_log::info_fencing_transition(
                    incident.incident_seq,
                    incident.target_node_id.as_str(),
                    from,
                    incident.state.operator_name(),
                );
                Ok(Some(incident))
            }
            Err(NodeMutationError::Io(_)) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// The single production `run_step` call site (§16.6; §33.3
    /// `017_sole_fencing_executor_owner`): the gate G fence action and the
    /// `drive_fencing_step` verify poll each run their one bounded step here,
    /// through the one backend owner, from the startup-trusted settings. The
    /// backend keeps every Phase 14.5/14.6 guarantee (spawn gate, trust
    /// re-check, deadlines, process group, pending-reap transfer). A §16.7.3
    /// invariant violation is returned as an error for the class-D fatal
    /// path; the step result is only provenance or a verify classification.
    fn run_fencing_process(
        &mut self,
        kind: crate::fencing_backend::StepKind,
        incident: &crate::fencing::FencingIncident,
        attempt_token: u64,
    ) -> Result<crate::fencing_backend::StepReport, LinuxNodeRuntimeError> {
        use crate::fencing_backend::{StepIdentity, StepKind, StepRequest};
        let Some(settings) = self.fencing_settings.command() else {
            return Err(LinuxNodeRuntimeError::Configuration(
                "a fencing step requires the command backend".into(),
            ));
        };
        let (argv, timeout) = match kind {
            StepKind::Action => (&settings.fence, settings.fence_timeout),
            StepKind::Verify => (&settings.verify, settings.verify_timeout),
            StepKind::Route => {
                return Err(LinuxNodeRuntimeError::Configuration(
                    "a route-handoff step is not a fencing step".into(),
                ));
            }
        };
        let request = StepRequest {
            argv,
            timeout,
            identity: StepIdentity {
                incident_seq: incident.incident_seq,
                incident_id: incident.incident_id.clone(),
                attempt_token,
            },
            cluster: self.attestation.cluster_id.as_str(),
            target_node: incident.target_node_id.as_str(),
        };
        self.process_steps_this_tick = self.process_steps_this_tick.saturating_add(1);
        let report = self
            .fencing_backend
            .run_step(&request)
            .map_err(|violation| {
                LinuxNodeRuntimeError::Backend(violation.into_observation_invariant())
            })?;
        for line in self.fencing_backend.step_log_lines(&report) {
            eprintln!("mikagami: {line}");
        }
        Ok(report)
    }

    /// v0.7 G-2: the second production `run_step` call site (guard 017 lists exactly these two
    /// owners): one bounded route-handoff step with the RH-only deadline set
    /// (`StepTimeout::route`, return within `ROUTE_STEP_RETURN_BUDGET`), through the same backend
    /// owner, spawn gate, trust re-check, process group and pending-reap slot as the fencing
    /// steps. The caller (`route_handoff::RhDriver::tick`) has already checked the §5.1 budget.
    fn run_route_process(
        &mut self,
        step: crate::route_handoff::RhStep,
        record: &crate::route_handoff::RhRecord,
        intent: &std::path::Path,
    ) -> Result<crate::route_handoff::RhAnswer, LinuxNodeRuntimeError> {
        use crate::fencing_backend::{
            RouteOutcome, StepIdentity, StepOutcome, StepRequest, StepTimeout,
        };
        use crate::route_handoff::RhAnswer;
        let Some(route) = self.route.as_ref() else {
            return Err(LinuxNodeRuntimeError::Configuration(
                "a route-handoff step requires [route]".into(),
            ));
        };
        let argv = route.argv(step, intent);
        let (incident_seq, incident_id, attempt_token) =
            crate::route_handoff::step_identity(record);
        let request = StepRequest {
            argv: &argv,
            timeout: StepTimeout::route(),
            identity: StepIdentity {
                incident_seq,
                incident_id: crate::fencing::IncidentId::route_step_label(&incident_id)
                    .ok_or_else(|| {
                        LinuxNodeRuntimeError::Configuration(
                            "the route step label is not a canonical incident id".into(),
                        )
                    })?,
                attempt_token,
            },
            cluster: self.attestation.cluster_id.as_str(),
            target_node: self.fencing_target.as_str(),
        };
        self.process_steps_this_tick = self.process_steps_this_tick.saturating_add(1);
        let report = self
            .fencing_backend
            .run_step(&request)
            .map_err(|violation| {
                LinuxNodeRuntimeError::Backend(violation.into_observation_invariant())
            })?;
        for line in self.fencing_backend.step_log_lines(&report) {
            eprintln!("mikagami: {line}");
        }
        // Only an in-time exit 0 with complete output is an answer; everything else is none.
        Ok(match report.outcome {
            StepOutcome::Route(RouteOutcome::Output(bytes)) => RhAnswer::Output(bytes),
            _ => RhAnswer::NoAnswer,
        })
    }

    /// v0.7 G-2 (contract §1.1, §1.2 start): called once after the attempt retired
    /// `Succeeded`, with the clearance's mint-time provenance and the granted term. Never fails
    /// the promotion: an RH that cannot start is logged and leaves the route alone.
    pub(crate) fn begin_route_handoff(
        &mut self,
        origin: crate::route_handoff::RhOrigin,
        term: Term,
    ) {
        if let Some(mut older) = self.route_driver.take() {
            older.abandon_superseded(unix_now_ms());
        }
        let Some(route) = self.route.as_ref() else {
            self.pending_promotion_journal = Some(false);
            return;
        };
        self.pending_promotion_journal = Some(true);
        let now_ms = self
            .controller
            .authority()
            .clock()
            .now()
            .map(|now| now.as_millis())
            .unwrap_or(0);
        match crate::route_handoff::RhDriver::begin(
            route.store.clone(),
            route.settings,
            crate::route_handoff::RhBegin {
                cluster: self.attestation.cluster_id.as_str().to_string(),
                node: self.node_id.as_str().to_string(),
                peer_node: self.fencing_target.as_str().to_string(),
                term: term.0,
                origin,
                now_ms,
                unix_ms: unix_now_ms(),
            },
        ) {
            Ok(driver) => self.route_driver = Some(driver),
            Err(error) => crate::operator_log::warn_route_handoff(&format!(
                "route handoff of term {} not started: {error}; the route is not changed",
                term.0
            )),
        }
    }

    /// v0.7 G-2: the RH tick, the last blocking work of the loop iteration (contract §5.1
    /// condition 1). At most one bounded helper step.
    pub(crate) fn drive_route_handoff(
        &mut self,
        control_lock_safe: &dyn Fn() -> bool,
        before_blocking_step: &mut dyn FnMut(),
    ) -> Result<(), LinuxNodeRuntimeError> {
        // The renewal fact is consumed by this tick whatever happens: one renewal allows at most
        // one RH step (contract §5.1 condition 3).
        let renewed = self.renewed_this_tick;
        self.renewed_this_tick = false;
        if let Some(route) = self.pending_promotion_journal.take() {
            crate::operator_log::info_promotion_internal_only(route);
            if let Some(driver) = &self.route_driver {
                let record = driver.record();
                crate::operator_log::route_handoff_state(
                    &record.describe(),
                    &record.reason,
                    record.state.operator_required(),
                );
            }
        }
        let Some(mut driver) = self.route_driver.take() else {
            return Ok(());
        };
        self.renewed_this_tick = renewed;
        let result = {
            let mut platform = LinuxRhPlatform {
                runtime: self,
                control_lock_safe,
                before_blocking_step,
            };
            driver.tick(&mut platform)
        };
        self.renewed_this_tick = false;
        if !matches!(
            driver.record().state,
            crate::route_handoff::RhState::Abandoned { .. }
        ) {
            self.route_driver = Some(driver);
        }
        result.map(|_| ()).map_err(LinuxNodeRuntimeError::Backend)
    }

    /// Stage 14 §24 G — Phase 14.9 fail-closed form (DC-14.9-01 Option B).
    ///
    /// Inside an accepted attempt whose fresh evaluation is `Authorized`,
    /// before any LeaseRequest: load the incident; retire it (T9) if a §26
    /// rule fails against the fresh view (`GateView`); with none, open one
    /// (T1 `B=none` / T2 `B=command`) bound to the view term, this session,
    /// and the live episode; for `UNKNOWN`/`FAILED` with `B=command` request
    /// again (T3). A `REQUESTED(k)` committed here runs the one bounded fence
    /// action in this frame (§27.2), after `before_blocking_step` voided the
    /// verified-listen window (§27.5); its outcome is provenance only and is
    /// persisted as `VERIFYING(k, outcome)` (T4) only if every post-return
    /// recheck holds. The gate never passes: every path returns a block, a
    /// valid `CONFIRMED` included, and no clearance is minted here.
    ///
    /// Shutdown (F14.9-01; §26 R7, §27.2, §27.4) is the live query
    /// `shutdown_requested`, read-only and owned by the Daemon. It is sampled
    /// at entry (eligibility), immediately before the action can spawn (a
    /// shutdown there runs nothing: no spawn, no provenance, no T4), and
    /// after the bounded action and its backend cleanup returned (a shutdown
    /// that arrived during the action discards its result: no T4).
    /// Stage 14 §28: the blocked-attempt WARN for a gate decision, written by
    /// the one gate caller after `fencing_gate` returned `Block`. The bounded
    /// reason, the target, the incident sequence, and the state are read from
    /// the outcome; the line is never read back.
    pub(crate) fn log_gate_block(&self, outcome: &FencingGateOutcome) {
        use crate::fencing::FencingGateBlock;
        let reason = match outcome.block {
            FencingGateBlock::NotEligible => "local state not eligible for fencing",
            FencingGateBlock::FencingUnavailable => "fencing unavailable (no live loss episode)",
            FencingGateBlock::StoreUnavailable => "fencing store unavailable",
            FencingGateBlock::FencingRequired => "fencing required",
            FencingGateBlock::FencingUnconfirmed => "fencing unconfirmed",
            FencingGateBlock::FencingInProgress => "fencing in progress",
        };
        let incident = outcome
            .incident
            .as_ref()
            .zip(outcome.state)
            .map(|(record, state)| crate::operator_log::BlockedIncident {
                seq: record.incident.incident_seq,
                target: self.fencing_target.as_str(),
                state,
            });
        crate::operator_log::warn_attempt_blocked(reason, incident);
    }

    pub(crate) fn fencing_gate(
        &mut self,
        view_term: Term,
        context: &crate::fencing::ContinuityContext<'_>,
        shutdown_requested: &dyn Fn() -> bool,
        before_blocking_step: &mut dyn FnMut(),
    ) -> Result<FencingGateDecision, LinuxNodeRuntimeError> {
        use crate::fencing::{
            FencingBackend, FencingGateBlock, FencingState, IncidentOpening, WitnessEpoch,
        };
        let mut outcome = FencingGateOutcome {
            block: FencingGateBlock::NotEligible,
            incident: None,
            retired: None,
            opened: false,
            action: None,
            state: None,
        };
        let Some(image) = self.fencing_eligible_image(shutdown_requested())? else {
            return Ok(FencingGateDecision::Block(outcome));
        };
        let mut current = image.fencing_incident;
        if let Some(incident) = &current
            && let Err(violation) =
                incident.check_continuity(context, WitnessEpoch::GateView(view_term))
        {
            self.mutation_store
                .retire_fencing_incident(&incident.incident_ref())?;
            crate::operator_log::info_fencing_incident_retired(
                incident.incident_seq,
                incident.target_node_id.as_str(),
                retire_reason(violation),
            );
            outcome.retired = Some(violation);
            current = None;
        }
        let backend = self.fencing_settings.backend();
        let requested = match current {
            None => {
                let Some(episode) = context.live_episode else {
                    outcome.block = FencingGateBlock::FencingUnavailable;
                    return Ok(FencingGateDecision::Block(outcome));
                };
                let opened = self.mutation_store.open_fencing_incident(IncidentOpening {
                    target_node_id: context.configured_peer.clone(),
                    anchor_term: view_term,
                    observer_session_id: context.current_session.clone(),
                    observer_loss_generation: episode.generation(),
                    backend,
                })?;
                crate::operator_log::info_fencing_incident_opened(
                    opened.incident_seq,
                    opened.target_node_id.as_str(),
                    opened.state.operator_name(),
                );
                outcome.opened = true;
                opened
            }
            Some(incident) => {
                outcome.incident = Some(IncidentTermRecord {
                    incident: incident.incident_ref(),
                    anchor: incident.anchor_term,
                    newest: view_term,
                });
                outcome.state = Some(incident.state.operator_name());
                match (&incident.state, backend) {
                    (
                        FencingState::Unknown(_) | FencingState::Failed { .. },
                        FencingBackend::None,
                    ) => {
                        outcome.block = FencingGateBlock::FencingUnconfirmed;
                        return Ok(FencingGateDecision::Block(outcome));
                    }
                    (FencingState::Unknown(_) | FencingState::Failed { .. }, _) => {
                        let transition = incident.request_again(backend).map_err(|error| {
                            LinuxNodeRuntimeError::Backend(format!("{error:?}"))
                        })?;
                        match self.apply_fencing(transition)? {
                            Some(requested) => requested,
                            None => {
                                outcome.block = FencingGateBlock::StoreUnavailable;
                                return Ok(FencingGateDecision::Block(outcome));
                            }
                        }
                    }
                    (FencingState::Requested { .. } | FencingState::Verifying { .. }, _) => {
                        outcome.block = FencingGateBlock::FencingInProgress;
                        return Ok(FencingGateDecision::Block(outcome));
                    }
                    (FencingState::Confirmed(_), _) => {
                        // §24 G: a valid CONFIRMED mints the clearance from the
                        // store's own validated load under the mutation guard
                        // (R1-R4 against the fresh view, state CONFIRMED). It
                        // is fencing evidence for the existing authority path,
                        // never authority itself.
                        return match self.mutation_store.mint_fencing_clearance(
                            &incident.incident_ref(),
                            context,
                            view_term,
                        ) {
                            Ok(clearance) => Ok(FencingGateDecision::Clear {
                                incident: IncidentTermRecord {
                                    incident: incident.incident_ref(),
                                    anchor: incident.anchor_term,
                                    newest: view_term,
                                },
                                clearance,
                            }),
                            Err(
                                NodeMutationError::FencingClearanceRefused(_)
                                | NodeMutationError::FencingIncident(_),
                            ) => {
                                outcome.block = FencingGateBlock::NotEligible;
                                Ok(FencingGateDecision::Block(outcome))
                            }
                            Err(NodeMutationError::Io(_)) => {
                                outcome.block = FencingGateBlock::StoreUnavailable;
                                Ok(FencingGateDecision::Block(outcome))
                            }
                            Err(error) => Err(error.into()),
                        };
                    }
                }
            }
        };
        outcome.incident = Some(IncidentTermRecord {
            incident: requested.incident_ref(),
            anchor: requested.anchor_term,
            newest: view_term,
        });
        outcome.state = Some(requested.state.operator_name());
        let FencingState::Requested { attempt_token } = requested.state else {
            // T1 (`B = none`): UNKNOWN(not-attempted); attestation only.
            outcome.block = FencingGateBlock::FencingRequired;
            return Ok(FencingGateDecision::Block(outcome));
        };
        // §27.4: no step starts after shutdown is observed. `REQUESTED(k)`
        // stays as committed; restart retires it (§22).
        if shutdown_requested() {
            outcome.block = FencingGateBlock::NotEligible;
            return Ok(FencingGateDecision::Block(outcome));
        }
        before_blocking_step();
        // J29 B1: counted before the spawn, whatever the outcome (an action
        // that may have reached the backend is a fence action).
        self.auto_fence_activity.actions_run += 1;
        let report = self.run_fencing_process(
            crate::fencing_backend::StepKind::Action,
            &requested,
            attempt_token,
        )?;
        let crate::fencing_backend::StepOutcome::Action(action) = report.outcome else {
            return Err(LinuxNodeRuntimeError::Backend(
                "a fence action step returned a verify classification".into(),
            ));
        };
        // §27.2 step 3: shutdown is re-read now that the action returned.
        let verifying_persisted = if self.fencing_result_applies(
            &requested,
            shutdown_requested(),
            context,
            WitnessEpoch::GateView(view_term),
        )? {
            let transition = requested
                .action_returned(attempt_token, action)
                .map_err(|error| LinuxNodeRuntimeError::Backend(format!("{error:?}")))?;
            self.apply_fencing(transition)?.is_some()
        } else {
            false
        };
        outcome.action = Some(FencingActionRecord {
            attempt_token,
            outcome: action,
            verifying_persisted,
        });
        outcome.state = Some(if verifying_persisted {
            "VERIFYING"
        } else {
            "REQUESTED"
        });
        outcome.block = FencingGateBlock::FencingInProgress;
        Ok(FencingGateDecision::Block(outcome))
    }

    /// Stage 14 §27.3 `drive_fencing_step`: one bounded branch of the
    /// foreground lifecycle, at most once per ordinary iteration, only in
    /// eligible local state with an incident open. It performs at most one
    /// of:
    ///
    /// - retirement (T9) when §26 R1-R3 fail, or R4 against the incident's
    ///   newest authenticated TermStatus term (`term_record`);
    /// - §18.5 attestation ingestion (T8 / T9 inside the ingestion step);
    /// - one verify poll for `VERIFYING(k)` (T5 / T6 / T7 after the §17.2
    ///   post-return rechecks), after `before_blocking_step` voided the
    ///   verified-listen window (§27.5).
    ///
    /// It never runs a fence action, never opens an incident, never retries
    /// within a call, and never mints a clearance. A missing term record for
    /// a current-session incident fails closed with no mutation.
    ///
    /// Shutdown (F14.9-01; §26 R7, §18.5, §27.4, §17.2) is the live query
    /// `shutdown_requested`, read-only and owned by the Daemon. It is sampled
    /// at entry (eligibility), immediately before the nonblocking ingestion
    /// (§18.5: ingestion runs only while not shutting down), immediately
    /// before the verify can spawn (a shutdown there runs nothing and
    /// consumes no poll), and after the bounded verify and its backend
    /// cleanup returned (a shutdown that arrived during the poll discards its
    /// result: no T5/T6/T7). An executed poll stays counted against its
    /// attempt token whether or not its result applied.
    pub(crate) fn drive_fencing_step(
        &mut self,
        context: &crate::fencing::ContinuityContext<'_>,
        term_record: Option<&IncidentTermRecord>,
        shutdown_requested: &dyn Fn() -> bool,
        before_blocking_step: &mut dyn FnMut(),
    ) -> Result<FencingStepOutcome, LinuxNodeRuntimeError> {
        use crate::fencing::{FencingEventOutcome, FencingState, WitnessEpoch};
        use crate::fencing_backend::{StepKind, StepOutcome, VerifyOutcome};
        let Some(image) = self.fencing_eligible_image(shutdown_requested())? else {
            return Ok(FencingStepOutcome::NotEligible);
        };
        let Some(incident) = image.fencing_incident else {
            return Ok(FencingStepOutcome::NoIncident);
        };
        let incident_ref = incident.incident_ref();
        // R1-R3 first: a restart (R2) or an ended episode (R3) retires the
        // incident whatever the Witness evidence.
        if let Err(violation) =
            incident.check_continuity(context, WitnessEpoch::LatestObserved(None))
        {
            self.mutation_store.retire_fencing_incident(&incident_ref)?;
            crate::operator_log::info_fencing_incident_retired(
                incident_ref.incident_seq,
                incident.target_node_id.as_str(),
                retire_reason(violation),
            );
            return Ok(FencingStepOutcome::Retired(violation));
        }
        let Some(newest) = term_record
            .filter(|record| record.incident == incident_ref)
            .map(|record| record.newest)
        else {
            return Ok(FencingStepOutcome::R4EvidenceMissing);
        };
        let epoch = WitnessEpoch::LatestObserved(Some(newest));
        if let Err(violation) = incident.check_continuity(context, epoch) {
            self.mutation_store.retire_fencing_incident(&incident_ref)?;
            crate::operator_log::info_fencing_incident_retired(
                incident_ref.incident_seq,
                incident.target_node_id.as_str(),
                retire_reason(violation),
            );
            return Ok(FencingStepOutcome::Retired(violation));
        }
        // §18.5 / R7: no ingestion (hence no T8) once shutdown is observed.
        if shutdown_requested() {
            return Ok(FencingStepOutcome::NotEligible);
        }
        match self.ingest_attestation(context, Some(newest))? {
            AttestationIngestion::Absent | AttestationIngestion::NotEligible => {}
            ingested => return Ok(FencingStepOutcome::Ingested(ingested)),
        }
        let FencingState::Verifying { attempt_token, .. } = incident.state else {
            return Ok(FencingStepOutcome::NoAction);
        };
        let Some(budget) = self
            .fencing_settings
            .command()
            .map(|settings| settings.verify_polls)
        else {
            return Ok(FencingStepOutcome::NoAction);
        };
        let used = match &self.verify_poll_counter {
            Some((record, token, used)) if record == &incident_ref && *token == attempt_token => {
                *used
            }
            _ => 0,
        };
        if used >= budget {
            return Ok(FencingStepOutcome::NoAction);
        }
        // §27.4: no step starts after shutdown is observed; no poll is used.
        if shutdown_requested() {
            return Ok(FencingStepOutcome::NotEligible);
        }
        before_blocking_step();
        let report = self.run_fencing_process(StepKind::Verify, &incident, attempt_token)?;
        let used = used + 1;
        self.verify_poll_counter = Some((incident_ref, attempt_token, used));
        let StepOutcome::Verify(result) = report.outcome else {
            return Err(LinuxNodeRuntimeError::Backend(
                "a verify step returned an action classification".into(),
            ));
        };
        // §17.2: shutdown is re-read now that the poll returned.
        let applied =
            if !self.fencing_result_applies(&incident, shutdown_requested(), context, epoch)? {
                VerifyApplied::Discarded
            } else {
                let event = match &result {
                    VerifyOutcome::Isolated => incident.confirm_by_verification(attempt_token),
                    VerifyOutcome::NotIsolated => incident.verification_not_isolated(attempt_token),
                    VerifyOutcome::Inconclusive(kind) => {
                        incident.verification_inconclusive(attempt_token, *kind, used >= budget)
                    }
                }
                .map_err(|error| LinuxNodeRuntimeError::Backend(format!("{error:?}")))?;
                match event {
                    FencingEventOutcome::NoOp => VerifyApplied::Unchanged,
                    FencingEventOutcome::Transition(transition) => {
                        match self.apply_fencing(transition)? {
                            Some(written) => {
                                // J29 C1: a committed `FAILED` verdict, counted
                                // where it is written.
                                if matches!(
                                    written.state,
                                    crate::fencing::FencingState::Failed { .. }
                                ) {
                                    self.auto_fence_activity.not_isolated_verdicts += 1;
                                }
                                VerifyApplied::Written(written.state)
                            }
                            None => VerifyApplied::PreCommitFailure(
                                "verify result not committed".into(),
                            ),
                        }
                    }
                }
            };
        Ok(FencingStepOutcome::Polled {
            attempt_token,
            result,
            applied,
        })
    }

    #[cfg(test)]
    fn set_attestation_dir_for_test(&mut self, dir: PathBuf) {
        self.attestation.intent_dir = dir;
    }

    #[cfg(test)]
    fn set_fencing_settings_for_test(&mut self, settings: crate::fencing_backend::FencingSettings) {
        self.fencing_settings = settings;
    }

    #[cfg(test)]
    pub(crate) fn fencing_settings_for_test(&self) -> &crate::fencing_backend::FencingSettings {
        &self.fencing_settings
    }

    #[cfg(test)]
    pub(crate) fn fencing_backend_for_test(
        &mut self,
    ) -> &mut crate::fencing_backend::CommandBackend {
        &mut self.fencing_backend
    }

    pub(crate) fn initialize_or_recover(
        &mut self,
    ) -> Result<LinuxRuntimeSnapshot, LinuxNodeRuntimeError> {
        match self.mutation_store.initialize_new() {
            Ok(_) | Err(NodeMutationError::AlreadyExists) => self.reconcile(),
            Err(error) => Err(error.into()),
        }
    }

    pub(crate) fn recover(&mut self) -> Result<LinuxRuntimeSnapshot, LinuxNodeRuntimeError> {
        if self.state_machine.node_state() == NodeState::Failed {
            self.state_machine.reset_for_recovery()?;
        }
        self.reconcile()
    }

    pub(crate) fn reconcile(&mut self) -> Result<LinuxRuntimeSnapshot, LinuxNodeRuntimeError> {
        let vip = self.executor.observe_vip();
        let service = self.executor.observe_service();
        let zero_resource = vip.is_absent() && service.is_stopped();
        let persistent = self.mutation_store.load_existing()?;
        let has_mutation = persistent.outstanding_mutation.is_some();
        let has_obligation = persistent.release_obligation.is_some();
        let can_reconcile = zero_resource && !has_mutation && !has_obligation;
        #[cfg(test)]
        eprintln!(
            "stage13.6 recovery diagnostic: vip={vip:?} service={service:?} zero_resource={zero_resource} has_mutation={has_mutation} has_obligation={has_obligation}"
        );

        if can_reconcile {
            let reconciliation = self.controller.reconcile_zero_resource();
            #[cfg(test)]
            if let Err(error) = &reconciliation {
                eprintln!(
                    "stage13.6 recovery diagnostic: zero-resource reconciliation failed: {error}"
                );
            }
            if reconciliation.is_ok() {
                match self.state_machine.node_state() {
                    NodeState::Init | NodeState::RecoveryPending => {
                        self.state_machine
                            .transition_to(NodeState::Standby)
                            .map_err(LinuxNodeRuntimeError::from)?;
                    }
                    _ => {}
                }
            }
        } else {
            if self.state_machine.node_state() == NodeState::Init {
                self.state_machine
                    .transition_to(NodeState::RecoveryPending)
                    .map_err(LinuxNodeRuntimeError::from)?;
            }
            if self.state_machine.node_state() == NodeState::RecoveryPending {
                // A resource-bearing image with no O/M is an ARM-invariant
                // violation.  Cleanup is mandatory, but successful cleanup
                // alone must never turn this into ordinary Standby: the
                // controller remains RecoveryBlocked until explicit recovery.
                let _ = {
                    let mut workflow =
                        ResourceWorkflow::new(&mut self.controller, &mut self.executor);
                    workflow.cleanup_local_resources()
                };
            }
        }
        self.snapshot()
    }

    /// Design Revision 10 §9: once shutdown is observed, join the existing
    /// owner with **at most one** bounded eligible reconciliation step before
    /// the final shutdown classification.
    ///
    /// Eligibility is deliberately narrow and is re-derived from real state on
    /// every call.  The step is performed only when the node is already inside
    /// its post-cleanup demotion phase *and* a durable mutation is already
    /// outstanding for the post-cleanup owner.  It therefore never demotes from
    /// Active, never begins a fresh mutation, never reinstalls authority, never
    /// promotes, and never acquires a protected resource: it can only complete
    /// or retain work that is already durably owed.
    ///
    /// The latch makes "at most one" structural, so repeated shutdown ticks
    /// cannot form a retry loop.  Any failure leaves O/M intact and the caller
    /// still classifies from actual state, which stays fail-closed.
    pub(crate) fn shutdown_bounded_step(
        &mut self,
        session: &mut WitnessSession,
        control_lock_safe: &dyn Fn() -> bool,
    ) -> Result<bool, LinuxNodeRuntimeError> {
        // R-16: the shutdown join can issue a durable LeaseRelease. It is a
        // protected operation and must not begin after the lock is lost.
        if !control_lock_safe() {
            return Err(LinuxNodeRuntimeError::ControlLockLost);
        }
        if self.shutdown_step_performed {
            return Ok(false);
        }
        let eligible = self.foreground_witness_required()
            && matches!(
                self.state_machine.operation_phase(),
                Some(OperationPhase::Demotion(
                    crate::state_machine::DemotionPhase::ReleaseLease
                ))
            )
            && self.mutation_store.outstanding()?.is_some();
        if !eligible {
            return Ok(false);
        }
        self.shutdown_step_performed = true;
        // A bounded step that cannot complete must still classify truthfully.
        // Errors are absorbed here on purpose: shutdown verdict is computed
        // from durable state below, and a retained obligation or latched
        // cleanup failure keeps the verdict non-clean.  Absorbing is recorded
        // so a terminal rejection is not mistaken for a transport retry.
        let result = self.drive_post_cleanup_reconciliation(session, control_lock_safe);
        // A loss while the step was in flight is not absorbed as a normal
        // retry: the process must stop before the final shutdown verdict.
        if !control_lock_safe() {
            return Err(LinuxNodeRuntimeError::ControlLockLost);
        }
        if let Err(error) = result {
            eprintln!(
                "mikagami: bounded shutdown reconciliation step did not complete cleanly: {error}"
            );
        }
        Ok(true)
    }

    /// Build the immutable local safety boundary consumed by failover policy.
    /// The daemon owns `shutdown_requested`; all other fields come from the
    /// existing authority, recovery, ownership, and mutation owners.
    pub(crate) fn failover_local_safety_snapshot(
        &mut self,
        shutdown_requested: bool,
    ) -> Result<LocalSafetySnapshot, LinuxNodeRuntimeError> {
        let readiness = if shutdown_requested {
            LocalSafetyReadiness::ShutdownInProgress
        } else if !self.controller.recovery_reconciled() {
            LocalSafetyReadiness::RecoveryBlocked
        } else if self.controller.demotion_required() {
            LocalSafetyReadiness::DemotionRequired
        } else {
            match self.controller.ownership_class() {
                OwnershipClass::ZeroResource => {
                    let persistent = self.mutation_store.load_existing()?;
                    if persistent.outstanding_mutation.is_some()
                        || persistent.release_obligation.is_some()
                    {
                        LocalSafetyReadiness::ResourceStateUnresolved
                    } else if self.controller.authority().authority().is_some() {
                        LocalSafetyReadiness::AuthorityPresent
                    } else {
                        let vip = self.executor.observe_vip();
                        let service = self.executor.observe_service();
                        if vip.is_absent() && service.is_stopped() {
                            LocalSafetyReadiness::Safe
                        } else {
                            LocalSafetyReadiness::ResourceStateUnresolved
                        }
                    }
                }
                OwnershipClass::ResourceOwning | OwnershipClass::Unknown => {
                    LocalSafetyReadiness::OwnershipUncertain
                }
            }
        };

        Ok(LocalSafetySnapshot::from_state_machine_with_readiness(
            &self.state_machine,
            readiness,
        ))
    }

    /// v0.6 A-1: the Witness session is permanently lost and this node has no
    /// local resource left to protect, so the only remaining work is a
    /// Witness lease operation that the dead session can never complete.
    ///
    /// The caller has already established that the session is lost. This
    /// predicate is the runtime's proof that stopping (non-zero) is
    /// fail-closed:
    /// - recovery is reconciled and no resource is owned;
    /// - an `Active` node qualifies only after its demotion has already
    ///   released the local resources (phase `ReleaseLease`), i.e. only the
    ///   lease release is outstanding;
    /// - a Standby-like node qualifies only with no operation in progress;
    /// - the VIP is absent and the service is stopped right now.
    ///
    /// The durable release obligation is deliberately NOT required to be
    /// empty: it cannot be sent on a dead session, and keeping the process
    /// alive would retain the dead socket and retry a request that can never
    /// be delivered. The next start's startup reconciliation resolves it.
    pub(crate) fn witness_loss_stop_allowed(&mut self) -> bool {
        if !self.controller.recovery_reconciled() || self.controller.resource_owning() {
            return false;
        }
        match self.state_machine.node_state() {
            NodeState::Active => {
                if !matches!(
                    self.state_machine.operation_phase(),
                    Some(OperationPhase::Demotion(
                        crate::state_machine::DemotionPhase::ReleaseLease
                    ))
                ) {
                    return false;
                }
            }
            NodeState::Standby | NodeState::Degraded | NodeState::Maintenance => {
                if self.state_machine.operation_phase().is_some() {
                    return false;
                }
            }
            _ => return false,
        }
        self.observe_trusted_zero_resource()
    }

    pub(crate) fn snapshot(&mut self) -> Result<LinuxRuntimeSnapshot, LinuxNodeRuntimeError> {
        let persistent = self.mutation_store.load_existing()?;
        Ok(LinuxRuntimeSnapshot {
            node_state: self.state_machine.node_state(),
            operation_phase: self.state_machine.operation_phase(),
            vip: map_vip(self.executor.observe_vip()),
            service: map_service(self.executor.observe_service()),
            // Health checks execute an arbitrary configured command. Status
            // must remain a passive observation, so health is not probed here.
            health: RuntimeResourceTruth::Unknown,
            resource_owning: self.controller.resource_owning(),
            authority_present: self.controller.authority().authority().is_some(),
            recovery_reconciled: self.controller.recovery_reconciled(),
            unresolved_mutation: persistent.outstanding_mutation.is_some()
                || persistent.release_obligation.is_some(),
        })
    }

    pub(crate) fn observe_for_daemon(
        &mut self,
    ) -> Result<LinuxRuntimeSnapshot, LinuxNodeRuntimeError> {
        let vip = self.executor.observe_vip();
        let service = self.executor.observe_service();
        let health = self.executor.observe_health();
        let persistent = self.mutation_store.load_existing()?;
        Ok(LinuxRuntimeSnapshot {
            node_state: self.state_machine.node_state(),
            operation_phase: self.state_machine.operation_phase(),
            vip: map_vip(vip),
            service: map_service(service),
            health: map_health(health),
            resource_owning: self.controller.resource_owning(),
            authority_present: self.controller.authority().authority().is_some(),
            recovery_reconciled: self.controller.recovery_reconciled(),
            unresolved_mutation: persistent.outstanding_mutation.is_some()
                || persistent.release_obligation.is_some(),
        })
    }

    /// Stage 14 §16.7.5: one pending-reap poll per ordinary foreground
    /// iteration. It never waits, sleeps, signals or spawns; an empty slot
    /// costs nothing. Only the §28 transitions are logged.
    pub(crate) fn poll_pending_reap_foreground(&mut self) {
        if let Some(line) = self.fencing_backend.foreground_pending_reap() {
            eprintln!("mikagami: {line}");
        }
    }

    /// Shutdown classification: the unchanged Design Revision 10 conditions
    /// AND, after exactly one pending-reap poll, an empty slot (Stage 14
    /// §16.7.8). An occupied slot is never clean and is never waited on or
    /// signalled here; the retained leader stays owned until the process
    /// exits. Every early return below is already non-clean.
    pub(crate) fn shutdown_for_daemon(
        &mut self,
        control_lock_safe: &dyn Fn() -> bool,
    ) -> Result<bool, LinuxNodeRuntimeError> {
        // R-16: cleanup is not inherently safe. A lost control lock means
        // another controller may already own these resources, so even a
        // voluntary-looking shutdown must not start demotion or cleanup.
        if !control_lock_safe() {
            return Err(LinuxNodeRuntimeError::ControlLockLost);
        }
        let pending = self.fencing_backend.shutdown_pending_reap();
        for line in &pending.log_lines {
            eprintln!("mikagami: {line}");
        }
        let mut snapshot = self.snapshot()?;
        if snapshot.node_state == NodeState::Active {
            if matches!(snapshot.operation_phase, Some(OperationPhase::Demotion(_))) {
                return Ok(false);
            }
            if !control_lock_safe() {
                return Err(LinuxNodeRuntimeError::ControlLockLost);
            }
            if self.demote(control_lock_safe)? != ExplicitOperationResult::Completed {
                return Ok(false);
            }
            // Do not continue into the resource-owning branch after a loss
            // during demotion: the service/VIP/lease cleanup already saw the
            // guard, and a new effect must not start here.
            if !control_lock_safe() {
                return Err(LinuxNodeRuntimeError::ControlLockLost);
            }
            snapshot = self.snapshot()?;
        }
        if snapshot.resource_owning {
            if !control_lock_safe() {
                return Err(LinuxNodeRuntimeError::ControlLockLost);
            }
            let outcome = {
                let mut workflow = ResourceWorkflow::new(&mut self.controller, &mut self.executor);
                workflow.cleanup_local_resources_guarded(control_lock_safe)
            };
            if !control_lock_safe() {
                return Err(LinuxNodeRuntimeError::ControlLockLost);
            }
            if outcome != CleanupWorkflowOutcome::CleanStandbyEligible {
                return Ok(false);
            }
            snapshot = self.snapshot()?;
        }
        let persistent = self.mutation_store.load_existing()?;
        if persistent.outstanding_mutation.is_some() || persistent.release_obligation.is_some() {
            return Ok(false);
        }
        if matches!(
            snapshot.node_state,
            NodeState::Failed | NodeState::RecoveryPending
        ) || !self.controller.recovery_reconciled()
        {
            return Ok(false);
        }
        if !control_lock_safe() {
            return Err(LinuxNodeRuntimeError::ControlLockLost);
        }
        Ok(snapshot.vip == RuntimeResourceTruth::Absent
            && snapshot.service == RuntimeResourceTruth::Stopped
            && !snapshot.resource_owning
            && pending.slot_empty)
    }

    /// Stage 13.2 lease acquisition: one durable LeaseRequest executed through
    /// the shared `WitnessSession` owned by the daemon runtime.  A grant is
    /// installed into the authority controller only after transport,
    /// provenance, and semantic validation succeed.
    pub(crate) fn acquire_lease_once(
        &mut self,
        session: &mut WitnessSession,
        observed_term: Term,
    ) -> Result<NodeWitnessMutationResult, LinuxNodeRuntimeError> {
        self.ensure_lease_acquisition_eligible()?;
        self.mutation_store.begin_lease_request(
            observed_term,
            self.priority,
            DurationMs(crate::node_lease_authority::LEASE_TTL_MS),
        )?;
        let runtime = NodeWitnessMutationRuntime::new(&self.mutation_store, self.node_id.clone());
        Ok(runtime
            .execute_lease_request_once_with_controller(session, &mut self.controller)?
            .result)
    }

    /// This node's protocol identity, used by authority-view holder
    /// classification (Self vs Foreign). Read-only; no authority.
    pub(crate) fn local_node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// Read-only view of the lease authority currently installed in the
    /// controller, if any. Used to build the per-observation
    /// `AuthorityViewExpectation` (term/lease identity context). This
    /// never moves, clones, or weakens the installed authority.
    pub(crate) fn installed_lease_authority(&self) -> Option<&RuntimeLeaseAuthority> {
        self.controller.authority().authority()
    }

    /// Stage 13.2 move-out boundary: transfer the lease authority installed
    /// by the trusted grant path into the promotion-attempt frame. This is a
    /// structural take — the returned value is the only usable
    /// `RuntimeLeaseAuthority` and the controller retains none until the
    /// Stage 11 handoff restores it.
    pub(crate) fn take_installed_lease_authority(&mut self) -> Option<RuntimeLeaseAuthority> {
        self.controller.take_installed_lease_authority()
    }

    /// Stage 13.2 restore boundary: reinstall the attempt-owned authority
    /// immediately before Stage 11 mutation. Fails closed if a different
    /// authority appeared or the loss latch was set while it was bound to the
    /// attempt.
    pub(crate) fn restore_installed_lease_authority(
        &mut self,
        authority: RuntimeLeaseAuthority,
    ) -> Result<(), AuthorityError> {
        self.controller.restore_installed_lease_authority(authority)
    }

    fn observe_trusted_zero_resource(&mut self) -> bool {
        self.executor.observe_vip().is_absent() && self.executor.observe_service().is_stopped()
    }

    /// Re-establish the trusted ZeroResource postcondition through the same
    /// verified cleanup path that mints `CleanupProvenance`.  This is the
    /// precondition for every durable LeaseRelease begin/send site.
    fn ensure_trusted_zero_resource(&mut self) -> Result<bool, LinuxNodeRuntimeError> {
        self.ensure_trusted_zero_resource_guarded(&|| true)
    }

    /// Guarded form of `ensure_trusted_zero_resource`. The cleanup inside this
    /// function is a protected effect: a lost lock must not stop the service or
    /// release the VIP while re-establishing ZeroResource.
    fn ensure_trusted_zero_resource_guarded(
        &mut self,
        control_lock_safe: &dyn Fn() -> bool,
    ) -> Result<bool, LinuxNodeRuntimeError> {
        Self::trusted_zero_resource_guarded(
            &mut self.controller,
            &mut self.executor,
            control_lock_safe,
        )
    }

    /// The body of `ensure_trusted_zero_resource_guarded` over the two owners
    /// it touches, so the startup reconciliation can re-establish ZeroResource
    /// (C-m') while it holds the mutation store.
    fn trusted_zero_resource_guarded(
        controller: &mut NodeAuthorityController<C>,
        executor: &mut ResourceExecutor<N, S>,
        control_lock_safe: &dyn Fn() -> bool,
    ) -> Result<bool, LinuxNodeRuntimeError> {
        if !control_lock_safe() {
            return Err(LinuxNodeRuntimeError::ControlLockLost);
        }
        let outcome = {
            let mut workflow = ResourceWorkflow::new(controller, executor);
            workflow.cleanup_local_resources_guarded(control_lock_safe)
        };
        if !control_lock_safe() {
            return Err(LinuxNodeRuntimeError::ControlLockLost);
        }
        Ok(outcome == CleanupWorkflowOutcome::CleanStandbyEligible)
    }

    /// Revision 10 ARM boundary, Stage 14 §24 L / §25 form. Trusted
    /// ZeroResource is observed first; then the one atomic v3 candidate
    /// consumes the clearance's `CONFIRMED` incident and installs O
    /// (`arm_consuming_fencing`). Only at `ConfirmedCommitted` is the
    /// authority restored to Stage 11 and `promote` allowed to reach
    /// `ResourceWorkflow::promote` / VIP acquisition. On `PreCommitFailure`,
    /// a validation mismatch, or uncertainty the authority is dropped here
    /// and no resource is touched.
    pub(crate) fn arm_and_promote(
        &mut self,
        authority: RuntimeLeaseAuthority,
        clearance: &crate::fencing::FencingClearance,
    ) -> Result<FencedArmOutcome, LinuxNodeRuntimeError> {
        if !self.observe_trusted_zero_resource() {
            return Err(AuthorityError::RecoveryBlocked.into());
        }
        match self.mutation_store.arm_consuming_fencing(
            authority.term(),
            authority.lease_id().clone(),
            clearance,
            &self.fencing_target,
        ) {
            Ok(_) => {
                // §28: one INFO for the atomic consumption (T10). Written
                // after the commit; never read back.
                crate::operator_log::info_fencing_incident_consumed(
                    clearance.incident().incident_seq,
                    clearance.target_node_id().as_str(),
                    "success ARM (CONFIRMED -> none, release obligation armed)",
                );
            }
            Err(NodeMutationError::Io(reason)) => {
                return Ok(FencedArmOutcome::NotCommitted(reason));
            }
            Err(NodeMutationError::FencingIncident(reason)) => {
                return Ok(FencedArmOutcome::Rejected(reason.to_string()));
            }
            Err(error) => return Ok(FencedArmOutcome::RecoveryBlocked(error.to_string())),
        }
        self.controller
            .restore_installed_lease_authority(authority)?;
        Ok(FencedArmOutcome::Promoted(self.promote()?))
    }

    /// Contract K-4: the Bootstrap Admission ARM + promote handoff, in the
    /// same order as `arm_and_promote`: trusted ZeroResource, then the plain
    /// ARM (`O = (term, lease)`; no fencing incident exists for BA), and only
    /// after a committed ARM the authority is restored and Stage 11 `promote`
    /// runs. One synchronous call: the grant never leaves it and no tick runs
    /// inside it. Conservative mode only (K-5), re-asserted here.
    pub(crate) fn arm_and_promote_bootstrap(
        &mut self,
        authority: RuntimeLeaseAuthority,
        clearance: &crate::bootstrap_admission::BootstrapClearance,
    ) -> Result<FencedArmOutcome, LinuxNodeRuntimeError> {
        // The clearance's anchor was checked against the Witness grant at H,
        // I and K; here it only has to exist.
        let _ = clearance.anchor_term();
        if !self.controller.is_conservative() || !self.observe_trusted_zero_resource() {
            return Err(AuthorityError::RecoveryBlocked.into());
        }
        // Guard BG-12: this `match` is a top-level statement, its scrutinee is
        // the one plain ARM routed through `plain_arm_gate`, and every arm but
        // `Committed` returns. The authority restore and `promote` below are
        // therefore reachable only after a committed ARM.
        match crate::node_mutation::plain_arm_gate(
            self.mutation_store
                .arm_release_obligation(authority.term(), authority.lease_id().clone()),
        ) {
            ArmGate::Committed => crate::operator_log::info_bootstrap_activated(authority.term().0),
            ArmGate::NotCommitted(reason) => return Ok(FencedArmOutcome::NotCommitted(reason)),
            ArmGate::Rejected(reason) => return Ok(FencedArmOutcome::Rejected(reason)),
            ArmGate::RecoveryBlocked(reason) => {
                return Ok(FencedArmOutcome::RecoveryBlocked(reason));
            }
        }
        self.controller
            .restore_installed_lease_authority(authority)?;
        Ok(FencedArmOutcome::Promoted(self.promote()?))
    }

    /// Whether the node runs the Conservative authority mode.
    pub(crate) fn authority_is_conservative(&self) -> bool {
        self.controller.is_conservative()
    }

    /// Contract K-4 / BAP-6.5: the runtime half of the final re-check before
    /// the BA ARM. Standby with no phase and no installed authority, trusted
    /// ZeroResource, `O = M = None`, no fencing incident, and the validated
    /// grant term equal to `anchor_term + 1`. Reads only.
    pub(crate) fn bootstrap_final_recheck(
        &mut self,
        anchor_term: Term,
        grant_term: Term,
    ) -> Result<Result<(), FencingRecheckFailure>, LinuxNodeRuntimeError> {
        if !self.controller.is_conservative()
            || self.state_machine.node_state() != NodeState::Standby
            || self.state_machine.operation_phase().is_some()
            || self.controller.authority().authority().is_some()
        {
            return Ok(Err(FencingRecheckFailure::LocalState));
        }
        if !self.observe_trusted_zero_resource() {
            return Ok(Err(FencingRecheckFailure::ZeroResource));
        }
        let image = self.mutation_store.load_existing()?;
        if image.release_obligation.is_some() || image.outstanding_mutation.is_some() {
            return Ok(Err(FencingRecheckFailure::ObligationOrMutation));
        }
        if image.fencing_incident.is_some() {
            return Ok(Err(FencingRecheckFailure::Incident));
        }
        if anchor_term.0.checked_add(1) != Some(grant_term.0) {
            return Ok(Err(FencingRecheckFailure::WitnessTerm));
        }
        Ok(Ok(()))
    }

    /// Stage 14 §24 K, runtime half (items 6-14), immediately before ARM:
    /// Standby with no phase and no installed authority, trusted
    /// ZeroResource, `O = M = None`, the clearance's exact durable incident
    /// present and `CONFIRMED`, target = configured peer, observer session =
    /// current session, the live episode's generation = the clearance's, and
    /// the validated grant term = `anchor_term + 1`. Reads only. The ARM
    /// candidate rechecks the durable part again (`arm_consuming_fencing`).
    pub(crate) fn fencing_final_recheck(
        &mut self,
        clearance: &crate::fencing::FencingClearance,
        context: &crate::fencing::ContinuityContext<'_>,
        grant_term: Term,
    ) -> Result<Result<(), FencingRecheckFailure>, LinuxNodeRuntimeError> {
        use crate::fencing::FencingState;
        if self.state_machine.node_state() != NodeState::Standby
            || self.state_machine.operation_phase().is_some()
            || self.controller.authority().authority().is_some()
        {
            return Ok(Err(FencingRecheckFailure::LocalState));
        }
        if !self.observe_trusted_zero_resource() {
            return Ok(Err(FencingRecheckFailure::ZeroResource));
        }
        let image = self.mutation_store.load_existing()?;
        if image.release_obligation.is_some() || image.outstanding_mutation.is_some() {
            return Ok(Err(FencingRecheckFailure::ObligationOrMutation));
        }
        let Some(incident) = image
            .fencing_incident
            .filter(|incident| &incident.incident_ref() == clearance.incident())
        else {
            return Ok(Err(FencingRecheckFailure::Incident));
        };
        if !matches!(incident.state, FencingState::Confirmed(_)) {
            return Ok(Err(FencingRecheckFailure::NotConfirmed));
        }
        if &incident.target_node_id != context.configured_peer
            || clearance.target_node_id() != context.configured_peer
        {
            return Ok(Err(FencingRecheckFailure::Target));
        }
        if &incident.observer_session_id != context.current_session
            || clearance.observer_session_id() != context.current_session
        {
            return Ok(Err(FencingRecheckFailure::ObserverSession));
        }
        if context
            .live_episode
            .is_none_or(|episode| episode.generation() != clearance.observer_loss_generation())
            || incident.observer_loss_generation != clearance.observer_loss_generation()
        {
            return Ok(Err(FencingRecheckFailure::Episode));
        }
        if incident.anchor_term != clearance.anchor_term()
            || clearance.anchor_term().0.checked_add(1) != Some(grant_term.0)
        {
            return Ok(Err(FencingRecheckFailure::WitnessTerm));
        }
        Ok(Ok(()))
    }

    /// Whether the given attempt-bound lease is still usable under the
    /// existing `RuntimeLeaseAuthority` timing rules (holder is this node and
    /// the monotonic safe deadline is still in the future).
    pub(crate) fn attempt_lease_usable(&self, authority: &RuntimeLeaseAuthority) -> bool {
        authority.holder_node_id() == &self.node_id
            && self
                .controller
                .authority()
                .clock()
                .now()
                .is_ok_and(|now| now < authority.safe_deadline())
    }

    /// Best-effort Stage 13.2 lease cleanup: arm the durable cleanup O and
    /// begin a durable LeaseRelease for the granted lease, executed once
    /// through the same shared session. A failure leaves the durable
    /// outstanding mutation for normal Stage 9/10 recovery; it never converts
    /// into promotion permission.
    ///
    /// Stage 14 §25 / §25.1 routing when O is not yet armed:
    /// - a fencing incident is present: the atomic abort-cleanup transaction
    ///   (`retire_incident_and_arm_cleanup_obligation`) with the attempt's
    ///   clearance binding — never the plain ARM. `PreCommitFailure` sends no
    ///   Release; uncertainty or a mismatch is RecoveryBlocked with no
    ///   Release. An incident without a binding is RecoveryBlocked;
    /// - a binding but no incident: RecoveryBlocked (the attempt's incident
    ///   vanished; no Release without the durable cleanup O);
    /// - no incident and no binding: the unchanged Stage 13.6 plain ARM.
    ///
    /// An O that is already armed (after the success ARM) is released as-is.
    pub(crate) fn release_attempt_lease_once(
        &mut self,
        session: &mut WitnessSession,
        term: Term,
        lease_id: LeaseId,
        reason: String,
        binding: Option<&crate::fencing::IncidentBinding>,
    ) -> Result<AttemptLeaseRelease, LinuxNodeRuntimeError> {
        if !self.ensure_trusted_zero_resource()? {
            return Err(AuthorityError::RecoveryBlocked.into());
        }
        let image = self.mutation_store.load_existing()?;
        if image.release_obligation.is_none() {
            match (image.fencing_incident.is_some(), binding) {
                (true, Some(binding)) => {
                    match self
                        .mutation_store
                        .retire_incident_and_arm_cleanup_obligation(
                            term,
                            lease_id.clone(),
                            binding,
                            &self.fencing_target,
                        ) {
                        Ok(_) => {
                            // §28: one INFO for the atomic abort cleanup
                            // (§25.1). Written after the commit; never read
                            // back.
                            crate::operator_log::info_fencing_incident_consumed(
                                binding.incident.incident_seq,
                                self.fencing_target.as_str(),
                                "abort cleanup (retired, release obligation armed)",
                            );
                        }
                        Err(NodeMutationError::Io(reason)) => {
                            return Ok(AttemptLeaseRelease::CleanupNotCommitted(reason));
                        }
                        Err(error) => {
                            return Ok(AttemptLeaseRelease::RecoveryBlocked(error.to_string()));
                        }
                    }
                }
                (true, None) => {
                    return Ok(AttemptLeaseRelease::RecoveryBlocked(
                        "a fencing incident is present without its cleanup binding".into(),
                    ));
                }
                (false, Some(_)) => {
                    return Ok(AttemptLeaseRelease::RecoveryBlocked(
                        "the attempt's fencing incident is absent before its cleanup".into(),
                    ));
                }
                (false, None) => {
                    // Unchanged Stage 13.6: no fencing incident, plain ARM.
                    self.mutation_store
                        .arm_release_obligation(term, lease_id.clone())?;
                }
            }
        }
        let runtime = NodeWitnessMutationRuntime::new(&self.mutation_store, self.node_id.clone());
        Ok(AttemptLeaseRelease::Executed(
            runtime.begin_and_execute_lease_release_once(session, term, lease_id, reason)?,
        ))
    }

    /// The durable Witness mutation record currently outstanding, if any.
    /// Cleanup dispatch must inspect its typed identity (mutation kind, term,
    /// and lease_id) before executing it — presence alone does not prove it
    /// is the expected cleanup release for this attempt.
    pub(crate) fn durable_witness_outstanding(
        &mut self,
    ) -> Result<Option<crate::node_mutation::OutstandingWitnessMutation>, LinuxNodeRuntimeError>
    {
        Ok(self.mutation_store.outstanding()?)
    }

    pub(crate) fn release_obligation(
        &self,
    ) -> Result<Option<crate::node_mutation::ReleaseObligation>, LinuxNodeRuntimeError> {
        Ok(self.mutation_store.release_obligation()?)
    }

    /// Execute one already-durable outstanding Witness mutation (for example
    /// a cleanup LeaseRelease begun by Stage 11 rollback) through the shared
    /// session, without demotion state-machine effects.
    ///
    /// This is a third LeaseRelease transmission path and therefore carries the
    /// same fresh trusted ZeroResource gate as every other Release path.  The
    /// proof is re-established here rather than reused from ARM or from the
    /// cleanup that originally began the mutation, because local resources may
    /// have reappeared in between.  On failure nothing is transmitted, O and M
    /// are retained, and no second mutation is begun.
    pub(crate) fn execute_durable_witness_mutation_once(
        &mut self,
        session: &mut WitnessSession,
    ) -> Result<NodeWitnessMutationResult, LinuxNodeRuntimeError> {
        if !self.ensure_trusted_zero_resource()? {
            return Err(AuthorityError::RecoveryBlocked.into());
        }
        let runtime = NodeWitnessMutationRuntime::new(&self.mutation_store, self.node_id.clone());
        Ok(runtime.execute_outstanding_once(session)?)
    }

    /// Read-only facts for the automatic trigger (no Witness I/O, no
    /// mutation): whether the configured fencing backend runs commands, and
    /// the current durable incident's identity and progress.
    pub(crate) fn auto_incident_facts(
        &self,
    ) -> Result<Option<crate::auto_failover::IncidentFacts>, LinuxNodeRuntimeError> {
        let image = self.mutation_store.load_existing()?;
        Ok(image.fencing_incident.as_ref().map(auto_incident_facts_of))
    }

    /// Phase 1-J29: the fencing activity counts of this process, for the
    /// automatic trigger (read-only, no I/O).
    pub(crate) fn auto_fence_activity(&self) -> crate::auto_failover::FenceActivity {
        self.auto_fence_activity
    }

    /// Whether the validated `[fencing]` backend runs a fence command.
    pub(crate) fn fencing_backend_is_command(&self) -> bool {
        self.fencing_settings.backend() != crate::fencing::FencingBackend::None
    }

    /// Diagnostic text naming why this node is not reconciled (O / M / local
    /// resources / state), for the recovery-gate message. Never evidence.
    pub(crate) fn recovery_block_cause(&mut self) -> Result<String, LinuxNodeRuntimeError> {
        let image = self.mutation_store.load_existing()?;
        if let Some(outstanding) = &image.outstanding_mutation {
            return Ok(format!(
                "a Witness mutation ({:?}) is still outstanding from before the restart",
                outstanding.kind()
            ));
        }
        if let Some(obligation) = &image.release_obligation {
            return Ok(format!(
                "a lease release obligation (term {}) is armed and was not resolved",
                obligation.term.0
            ));
        }
        if image.fencing_incident.is_some() {
            return Ok("a fencing incident is open".into());
        }
        if self.state_machine.node_state() == NodeState::Failed {
            return Ok("the node state machine is Failed".into());
        }
        Ok("local resources (VIP or service) were present or could not be observed".into())
    }

    /// Startup Obligation Reconciliation (contract A-4): the release
    /// obligation this restarted node may try to resolve, if any (see
    /// `obligation_reconciliation::candidate`).
    pub(crate) fn sor_candidate(&self) -> Result<Option<SorCandidate>, LinuxNodeRuntimeError> {
        Ok(crate::obligation_reconciliation::candidate(
            &self.mutation_store,
        )?)
    }

    /// Startup Obligation Reconciliation (contract A-4, SOR-1..SOR-5). The
    /// trusted ZeroResource proof (a fresh verified cleanup) comes first; the
    /// rest is `obligation_reconciliation::reconcile`. No authority is
    /// installed and no promotion is allowed: a resolved `O` leaves an
    /// ordinary Standby (SOR-5). `view` is only consulted when no owned
    /// `LeaseRelease` is already pending.
    pub(crate) fn reconcile_startup_obligation(
        &mut self,
        session: &mut WitnessSession,
        view: Option<(
            Term,
            crate::evidence_fusion::adapter::AuthorityViewCompatibility,
        )>,
    ) -> Result<SorOutcome, LinuxNodeRuntimeError> {
        self.reconcile_startup_obligation_guarded(session, view, &|| true, &mut |_| {
            Err("no Witness view source for the retired-release resolution".to_string())
        })
    }

    /// The daemon's startup reconciliation (Amendment C):
    /// - C-m': every exceptional settle (A-4d, C-l) is preceded by a fresh
    ///   trusted ZeroResource through the guarded verified cleanup, with the
    ///   daemon's live control-lock predicate (F33-2 / b01 I-4);
    /// - C-l: `retired_view` supplies the new GET_TERM view on the same
    ///   session after an exact replay answered RetiredStale.
    pub(crate) fn reconcile_startup_obligation_guarded(
        &mut self,
        session: &mut WitnessSession,
        view: Option<(
            Term,
            crate::evidence_fusion::adapter::AuthorityViewCompatibility,
        )>,
        control_lock_safe: &dyn Fn() -> bool,
        retired_view: &mut dyn FnMut(
            &mut WitnessSession,
        ) -> Result<
            (
                Term,
                crate::evidence_fusion::adapter::AuthorityViewCompatibility,
            ),
            String,
        >,
    ) -> Result<SorOutcome, LinuxNodeRuntimeError> {
        if self.sor_candidate()?.is_none() {
            return Ok(SorOutcome::NotApplicable);
        }
        let zero_resource = self.ensure_trusted_zero_resource_guarded(control_lock_safe)?;
        let controller = &mut self.controller;
        let executor = &mut self.executor;
        // A lost lock or a cleanup error is never proof: `false`.
        let mut fresh_zero_resource = || {
            Self::trusted_zero_resource_guarded(controller, executor, control_lock_safe)
                .unwrap_or(false)
        };
        Ok(crate::obligation_reconciliation::reconcile(
            &self.mutation_store,
            &self.node_id,
            session,
            zero_resource,
            view,
            &mut fresh_zero_resource,
            retired_view,
        )?)
    }

    /// v0.6 A-2: whether the durable store still holds a Witness mutation of
    /// kind `LeaseRenew` from before this process started.
    ///
    /// A renewal can be lost with the Witness connection while it is already
    /// sent. The record is retained on purpose (it is the only way to keep the
    /// request-id/generation stream convergent), but it must not block startup
    /// forever after the Witness returns.
    pub(crate) fn retained_renew_pending(&self) -> Result<bool, LinuxNodeRuntimeError> {
        Ok(matches!(
            self.mutation_store.load_existing()?.outstanding_mutation,
            Some(outstanding) if outstanding.kind() == crate::node_mutation::MutationKind::LeaseRenew
        ))
    }

    /// v0.6 A-2: resolve a retained `LeaseRenew` by replaying the exact
    /// durable request once (same request id, generation, term and lease).
    ///
    /// Safety: the node is a Standby with no authority installed, so an
    /// `AcceptedSuccess` completes bookkeeping only - `retry_outstanding_once`
    /// never installs authority, touches a resource or promotes. It proves
    /// ZeroResource by observation first and sends nothing otherwise. A
    /// terminal outcome (accepted, deterministic reject or retired-stale)
    /// clears the record; any other outcome leaves it, so the caller stays
    /// recovery-blocked (fail-closed). Replaying may extend the old lease by
    /// at most one TTL at the Witness, which delays a peer promotion but
    /// cannot create a second Active.
    pub(crate) fn resolve_retained_renew_once(
        &mut self,
        session: &mut WitnessSession,
    ) -> Result<RetainedRenewOutcome, LinuxNodeRuntimeError> {
        if !self.observe_trusted_zero_resource() {
            return Ok(RetainedRenewOutcome::Blocked {
                reason: "a local resource is still observed".to_string(),
            });
        }
        let runtime = NodeWitnessMutationRuntime::new(&self.mutation_store, self.node_id.clone());
        match runtime.retry_outstanding_once(session) {
            Ok(result) if renew_result_is_terminal(&result) => Ok(RetainedRenewOutcome::Resolved {
                how: renew_result_label(&result),
            }),
            Ok(result) => Ok(RetainedRenewOutcome::Blocked {
                reason: format!(
                    "the Witness answered a non-terminal {}",
                    renew_result_label(&result)
                ),
            }),
            // Transport/latency/closure: nothing is proven; keep the record.
            Err(
                crate::node_lease_authority::node_witness_runtime::NodeWitnessRuntimeError::Witness(
                    crate::witness_runtime::WitnessRuntimeError::Tcp(_),
                ),
            )
            | Err(
                crate::node_lease_authority::node_witness_runtime::NodeWitnessRuntimeError::Witness(
                    crate::witness_runtime::WitnessRuntimeError::SessionClosed,
                ),
            ) => Ok(RetainedRenewOutcome::Blocked {
                reason: "the Witness connection failed during the replay".to_string(),
            }),
            // OD-J31-4: an exhausted correlation is an unknown outcome; the
            // record stays and the node stays recovery-blocked.
            Err(
                crate::node_lease_authority::node_witness_runtime::NodeWitnessRuntimeError::Witness(
                    crate::witness_runtime::WitnessRuntimeError::UncorrelatedResponsesExhausted,
                ),
            ) => Ok(RetainedRenewOutcome::Blocked {
                reason:
                    "the outcome of the replay is unknown (only uncorrelated responses were read)"
                        .to_string(),
            }),
            Err(error) => Err(LinuxNodeRuntimeError::Backend(error.to_string())),
        }
    }

    /// J21 (OD-J20-6): whether the durable store still holds a `LeaseRequest` from before this
    /// process started (a promotion attempt whose answer was lost with the connection). Without a
    /// resolution the record keeps the node recovery-blocked forever.
    pub(crate) fn retained_request_pending(&self) -> Result<bool, LinuxNodeRuntimeError> {
        Ok(matches!(
            self.mutation_store.load_existing()?.outstanding_mutation,
            Some(outstanding) if outstanding.kind() == crate::node_mutation::MutationKind::LeaseRequest
        ))
    }

    /// J21: resolve a retained `LeaseRequest` by replaying the exact durable request once (same
    /// request id, generation and payload).
    ///
    /// Safety: the node is a Standby with no authority installed and must prove ZeroResource by
    /// observation first; nothing is sent otherwise. `retry_outstanding_once` never installs
    /// authority, touches a resource or promotes. A grant answered to the replay (reconstructed
    /// without extension, or - if the original request never reached the Witness - created by
    /// this first delivery) is never used: it goes to the existing unused-lease cleanup
    /// (`release_attempt_lease_once`), which records the release obligation and sends the exact
    /// Release; a Release that does not complete is finished by the startup reconciliation. A terminal reject (deterministic or retired-stale) clears the record. Any other
    /// outcome keeps it, so the caller stays recovery-blocked (fail-closed). A coexisting release
    /// obligation or fencing incident is left to the existing paths.
    ///
    /// J23 (OD-J22-1, C-F): before the replay, the generation fence (`generation_fence_of`) is sent
    /// once over its own path. A fence the Witness commits (PolicyReject) settles the request
    /// without any grant; only a retired-stale fence leads to the exact replay described above.
    pub(crate) fn resolve_retained_request_once(
        &mut self,
        session: &mut WitnessSession,
    ) -> Result<RetainedRenewOutcome, LinuxNodeRuntimeError> {
        use crate::node_lease_authority::node_witness_runtime::{
            NodeWitnessMutationResult, NodeWitnessSuccess,
        };
        if !self.observe_trusted_zero_resource() {
            return Ok(RetainedRenewOutcome::Blocked {
                reason: "a local resource is still observed".to_string(),
            });
        }
        let image = self.mutation_store.load_existing()?;
        if image.release_obligation.is_some() || image.fencing_incident.is_some() {
            return Ok(RetainedRenewOutcome::Blocked {
                reason: "a release obligation or fencing incident coexists with the retained lease request"
                    .to_string(),
            });
        }
        let Some(retained) = image.outstanding_mutation.clone().filter(|outstanding| {
            outstanding.kind() == crate::node_mutation::MutationKind::LeaseRequest
        }) else {
            return Err(LinuxNodeRuntimeError::Backend(
                "no retained lease request to resolve".to_string(),
            ));
        };
        let runtime = NodeWitnessMutationRuntime::new(&self.mutation_store, self.node_id.clone());
        // J23 (OD-J22-1, C-F): fence the generation first. Only the first commit of a generation
        // counts at the Witness. A fence committed as a PolicyReject (first or as a duplicate)
        // proves the request was not committed before it, and can never commit afterwards; the
        // request is then settled without a grant. A retired-stale fence means the generation was
        // used before: only then the exact replay follows, with the J21 / J22 contract. Anything
        // else proves nothing: the record stays and the node stays recovery-blocked.
        let fence = generation_fence_of(&retained)?;
        match runtime.exchange_generation_fence_once(session, &fence) {
            Ok(NodeWitnessMutationResult::DeterministicReject { .. }) => {
                self.mutation_store.complete(
                    &retained.request_id,
                    retained.mutation_generation,
                    crate::node_mutation::MutationKind::LeaseRequest,
                    crate::node_mutation::TerminalMutationDisposition::RetiredStale,
                )?;
                return Ok(RetainedRenewOutcome::Resolved {
                    how: RETAINED_REQUEST_FENCED,
                });
            }
            Ok(NodeWitnessMutationResult::RetiredStale { .. }) => {}
            Ok(result) => {
                return Ok(RetainedRenewOutcome::Blocked {
                    reason: format!(
                        "the generation fence was answered with a non-terminal {}",
                        renew_result_label(&result)
                    ),
                });
            }
            Err(
                crate::node_lease_authority::node_witness_runtime::NodeWitnessRuntimeError::Witness(
                    crate::witness_runtime::WitnessRuntimeError::Tcp(_),
                ),
            )
            | Err(
                crate::node_lease_authority::node_witness_runtime::NodeWitnessRuntimeError::Witness(
                    crate::witness_runtime::WitnessRuntimeError::SessionClosed,
                ),
            ) => {
                return Ok(RetainedRenewOutcome::Blocked {
                    reason: "the Witness connection failed during the generation fence".to_string(),
                });
            }
            Err(
                crate::node_lease_authority::node_witness_runtime::NodeWitnessRuntimeError::Witness(
                    crate::witness_runtime::WitnessRuntimeError::UncorrelatedResponsesExhausted,
                ),
            ) => {
                return Ok(RetainedRenewOutcome::Blocked {
                    reason: "the outcome of the generation fence is unknown (only uncorrelated responses were read)"
                        .to_string(),
                });
            }
            Err(error) => return Err(LinuxNodeRuntimeError::Backend(error.to_string())),
        }
        match runtime.retry_outstanding_once(session) {
            Ok(NodeWitnessMutationResult::AcceptedSuccess {
                response: NodeWitnessSuccess::LeaseGrant(grant),
                ..
            }) => {
                // Never used: the grant goes to the unused-lease cleanup, which records the
                // durable release obligation before the exact Release and restores no authority.
                // J22 (OD-J21-5 B-1): what is reported is derived from the Witness answer AND the
                // durable record left after it; only a LEASE_RELEASED answer whose completion is
                // durable is reported as released.
                let attempt = self.release_attempt_lease_once(
                    session,
                    grant.term,
                    grant.lease_id.clone(),
                    "startup: a retained lease request was answered with a current grant"
                        .to_string(),
                    None,
                );
                let image = self.mutation_store.load_existing()?;
                let recorded = UnusedGrantRelease::from_record(
                    image.release_obligation.is_some(),
                    image.outstanding_mutation.as_ref().map(|o| o.kind()),
                );
                match attempt {
                    Ok(AttemptLeaseRelease::Executed(answer)) => recorded.after_answer(&answer),
                    Ok(AttemptLeaseRelease::CleanupNotCommitted(reason))
                    | Ok(AttemptLeaseRelease::RecoveryBlocked(reason)) => {
                        recorded.after_stop(&reason)
                    }
                    Err(error) => recorded.after_stop(&error.to_string()),
                }
            }
            Ok(result @ NodeWitnessMutationResult::DeterministicReject { .. })
            | Ok(result @ NodeWitnessMutationResult::RetiredStale { .. }) => {
                Ok(RetainedRenewOutcome::Resolved {
                    how: request_replay_label(&result),
                })
            }
            Ok(result) => Ok(RetainedRenewOutcome::Blocked {
                reason: format!(
                    "the Witness answered a non-terminal {}",
                    renew_result_label(&result)
                ),
            }),
            Err(
                crate::node_lease_authority::node_witness_runtime::NodeWitnessRuntimeError::Witness(
                    crate::witness_runtime::WitnessRuntimeError::Tcp(_),
                ),
            )
            | Err(
                crate::node_lease_authority::node_witness_runtime::NodeWitnessRuntimeError::Witness(
                    crate::witness_runtime::WitnessRuntimeError::SessionClosed,
                ),
            ) => Ok(RetainedRenewOutcome::Blocked {
                reason: "the Witness connection failed during the replay".to_string(),
            }),
            // OD-J31-4: an exhausted correlation is an unknown outcome; the
            // record stays and the node stays recovery-blocked.
            Err(
                crate::node_lease_authority::node_witness_runtime::NodeWitnessRuntimeError::Witness(
                    crate::witness_runtime::WitnessRuntimeError::UncorrelatedResponsesExhausted,
                ),
            ) => Ok(RetainedRenewOutcome::Blocked {
                reason:
                    "the outcome of the replay is unknown (only uncorrelated responses were read)"
                        .to_string(),
            }),
            Err(error) => Err(LinuxNodeRuntimeError::Backend(error.to_string())),
        }
    }

    fn ensure_lease_acquisition_eligible(&self) -> Result<(), LinuxNodeRuntimeError> {
        if !lease_acquisition_allowed(
            self.state_machine.node_state(),
            self.controller.recovery_reconciled(),
        ) {
            return Err(AuthorityError::RecoveryBlocked.into());
        }
        Ok(())
    }

    pub(crate) fn renew_lease_once<F>(
        &mut self,
        session: &mut WitnessSession,
        before_authority_install: F,
    ) -> Result<NodeWitnessMutationResult, LinuxNodeRuntimeError>
    where
        F: FnOnce() -> Result<(), AuthorityError>,
    {
        let authority = self
            .controller
            .authority()
            .authority()
            .ok_or(AuthorityError::NoAuthority)?;
        match self.mutation_store.outstanding()? {
            None => {
                self.mutation_store
                    .begin_lease_renew(authority.term(), authority.lease_id().clone())?;
            }
            Some(outstanding)
                if matches!(
                    &outstanding.mutation,
                    crate::node_mutation::DurableWitnessMutation::LeaseRenew { term, lease_id }
                        if *term == authority.term() && lease_id == authority.lease_id()
                ) => {}
            Some(_) => {
                self.controller.request_demotion_on_authority_loss();
                return Err(NodeMutationError::OutstandingExists.into());
            }
        }
        let runtime = NodeWitnessMutationRuntime::new(&self.mutation_store, self.node_id.clone());
        Ok(runtime
            .execute_lease_renew_once_with_controller(
                session,
                &mut self.controller,
                before_authority_install,
            )?
            .result)
    }

    /// One bounded Stage 13.6 foreground lifecycle step.  It never promotes
    /// and uses the daemon's sole WitnessSession.
    pub(crate) fn drive_foreground_lifecycle(
        &mut self,
        session: &mut WitnessSession,
        shutdown_requested: &dyn Fn() -> bool,
        control_lock_safe: &dyn Fn() -> bool,
    ) -> Result<(), LinuxNodeRuntimeError> {
        // G-2 §5.1: the per-iteration facts of the route-handoff budget start here (the
        // foreground lifecycle is the first runtime step of every iteration).
        self.renewed_this_tick = false;
        self.process_steps_this_tick = 0;
        // R-17: no foreground lifecycle effect (renewal, demotion or
        // post-cleanup lease reconciliation) may start after a live loss.
        if !control_lock_safe() {
            return Err(LinuxNodeRuntimeError::ControlLockLost);
        }
        if self.state_machine.node_state() == NodeState::Active
            && self.state_machine.operation_phase().is_none()
        {
            // R-17: a live control-lock loss is not a normal shutdown and
            // must not become a demotion/cleanup trigger. Stop before any
            // new renewal request is constructed.
            if !control_lock_safe() {
                return Err(LinuxNodeRuntimeError::ControlLockLost);
            }
            if shutdown_requested() {
                self.controller.request_demotion_on_authority_loss();
                let _ = self.demote(control_lock_safe)?;
                return Ok(());
            }
            match self.controller.renewal_due() {
                Ok(RenewalDue::NotDue) => return Ok(()),
                Ok(RenewalDue::NoAuthority) | Err(_) => {
                    crate::operator_log::warn_demoting(
                        "the Witness lease expired or its authority is gone",
                    );
                    if !control_lock_safe() {
                        return Err(LinuxNodeRuntimeError::ControlLockLost);
                    }
                    let _ = self.demote(control_lock_safe)?;
                    return Ok(());
                }
                Ok(RenewalDue::Due) => {}
            }

            if session.outstanding_identity().is_some() {
                let exact_renew_owner = match (
                    session.outstanding_renew_identity(),
                    self.mutation_store.outstanding()?,
                ) {
                    (Some((request_id, generation, term, lease_id)), Some(outstanding)) => {
                        request_id == outstanding.request_id
                            && generation == outstanding.mutation_generation
                            && outstanding.kind() == crate::node_mutation::MutationKind::LeaseRenew
                            && matches!(
                                &outstanding.mutation,
                                crate::node_mutation::DurableWitnessMutation::LeaseRenew {
                                    term: current_term,
                                    lease_id: current_lease,
                                } if *current_term == term && current_lease == &lease_id
                            )
                    }
                    _ => false,
                };
                if exact_renew_owner {
                    // The call stack that sent this exact durable Renew owns
                    // response completion. Join it by doing no second send.
                    return Ok(());
                }
                crate::operator_log::warn_demoting(
                    "a Witness mutation other than this lease's renewal is outstanding",
                );
                if !control_lock_safe() {
                    return Err(LinuxNodeRuntimeError::ControlLockLost);
                }
                self.controller.request_demotion_on_authority_loss();
                let _ = self.demote(control_lock_safe)?;
                return Ok(());
            }
            // R-17: the last check before the request is constructed. The
            // same guard is sampled again by the authority-install boundary
            // below, so a loss during the in-flight exchange cannot extend
            // the local lease authority.
            if !control_lock_safe() {
                return Err(LinuxNodeRuntimeError::ControlLockLost);
            }
            // C-d: the retained Renew (if any) this iteration re-sends.
            let renew_before = self.mutation_store.outstanding()?;
            let renewal = self.renew_lease_once(session, || {
                if shutdown_requested() || !control_lock_safe() {
                    Err(AuthorityError::AuthorityLost)
                } else {
                    Ok(())
                }
            });
            // A request already sent cannot be recalled. If the lock was
            // lost while it was in flight, never treat a late response as
            // safety proof and never start demotion/cleanup from here.
            if !control_lock_safe() {
                return Err(LinuxNodeRuntimeError::ControlLockLost);
            }
            if renewal.is_ok() {
                if let Some(before) = &renew_before {
                    self.uncorrelated_retry
                        .record_correlated(&before.request_id, before.mutation_generation);
                }
            }
            let renewal = match renewal {
                // C-d / OD-J31-4: an exhausted correlation is an unknown
                // outcome. Below the limit it is handled like the transport
                // uncertainty below (exact M kept, the old safe deadline
                // unchanged); at the limit it falls through to the existing
                // demotion.
                Err(LinuxNodeRuntimeError::Witness(NodeWitnessRuntimeError::Witness(
                    crate::witness_runtime::WitnessRuntimeError::UncorrelatedResponsesExhausted,
                ))) if self.exhausted_retry_allowed()? => {
                    if shutdown_requested() || self.controller.renewal_due().is_err() {
                        self.controller.request_demotion_on_authority_loss();
                        let _ = self.demote(control_lock_safe)?;
                    }
                    return Ok(());
                }
                other => other,
            };
            match renewal {
                Ok(NodeWitnessMutationResult::AcceptedSuccess { .. }) => {
                    if shutdown_requested() {
                        self.controller.request_demotion_on_authority_loss();
                        let _ = self.demote(control_lock_safe)?;
                    } else {
                        // G-2 §5.1 condition 1.
                        self.renewed_this_tick = true;
                    }
                    return Ok(());
                }
                Ok(NodeWitnessMutationResult::TemporarilyUnavailable { .. }) => {
                    // Keep the exact M and the old deadline.  The ordinary
                    // foreground cadence supplies the next bounded retry.
                    if shutdown_requested() || self.controller.renewal_due().is_err() {
                        self.controller.request_demotion_on_authority_loss();
                        let _ = self.demote(control_lock_safe)?;
                    }
                    return Ok(());
                }
                Err(LinuxNodeRuntimeError::Witness(NodeWitnessRuntimeError::Witness(
                    crate::witness_runtime::WitnessRuntimeError::Tcp(_)
                    | crate::witness_runtime::WitnessRuntimeError::SessionClosed,
                ))) => {
                    // Transport/timeout/EOF uncertainty retains exact M and
                    // may continue only while the old authority is usable.
                    if shutdown_requested() || self.controller.renewal_due().is_err() {
                        if !shutdown_requested() {
                            crate::operator_log::warn_demoting(
                                "the Witness cannot be reached and the lease is about to expire",
                            );
                        }
                        self.controller.request_demotion_on_authority_loss();
                        let _ = self.demote(control_lock_safe)?;
                    }
                    return Ok(());
                }
                Ok(_) | Err(_) => {
                    crate::operator_log::warn_demoting(
                        "the Witness did not accept the lease renewal",
                    );
                    self.controller.request_demotion_on_authority_loss();
                    let _ = self.demote(control_lock_safe)?;
                    return Ok(());
                }
            }
        }

        if matches!(
            self.state_machine.operation_phase(),
            Some(OperationPhase::Demotion(
                crate::state_machine::DemotionPhase::ReleaseLease
            ))
        ) {
            self.drive_post_cleanup_reconciliation(session, control_lock_safe)?;
            if !control_lock_safe() {
                return Err(LinuxNodeRuntimeError::ControlLockLost);
            }
        }
        Ok(())
    }

    fn drive_post_cleanup_reconciliation(
        &mut self,
        session: &mut WitnessSession,
        control_lock_safe: &dyn Fn() -> bool,
    ) -> Result<(), LinuxNodeRuntimeError> {
        match self.mutation_store.outstanding()? {
            Some(outstanding)
                if outstanding.kind() == crate::node_mutation::MutationKind::LeaseRenew =>
            {
                // This is a Witness mutation, not a purely local bookkeeping
                // step. Do not issue it after a live loss.
                if !control_lock_safe() {
                    return Err(LinuxNodeRuntimeError::ControlLockLost);
                }
                // C-c: after a timeout on this same session, skip due
                // iterations (1, 2, 4, ...; at most the 60 s cap between two
                // attempts) instead of re-sending on every one.
                let session_key = session.provenance();
                if !self.renew_retry_backoff.may_send(
                    &session_key,
                    &outstanding.request_id,
                    outstanding.mutation_generation,
                    std::time::Instant::now(),
                ) {
                    return Ok(());
                }
                let attempt_at = std::time::Instant::now();
                // Bookkeeping-only: deliberately bypass authority integration.
                let runtime =
                    NodeWitnessMutationRuntime::new(&self.mutation_store, self.node_id.clone());
                let result = runtime.execute_outstanding_once(session);
                if !control_lock_safe() {
                    return Err(LinuxNodeRuntimeError::ControlLockLost);
                }
                match &result {
                    Err(error)
                        if crate::node_lease_authority::node_witness_runtime::is_timeout(error) =>
                    {
                        self.renew_retry_backoff.record_timeout(
                            &session_key,
                            &outstanding.request_id,
                            outstanding.mutation_generation,
                            attempt_at,
                        );
                    }
                    _ => self.renew_retry_backoff.clear(),
                }
                if result.is_ok() {
                    self.uncorrelated_retry.record_correlated(
                        &outstanding.request_id,
                        outstanding.mutation_generation,
                    );
                }
                match result {
                    Ok(result) => {
                        if matches!(
                            result,
                            NodeWitnessMutationResult::Conflict { .. }
                                | NodeWitnessMutationResult::GenerationGap { .. }
                        ) {
                            self.state_machine.mark_cleanup_failed()?;
                        }
                    }
                    Err(NodeWitnessRuntimeError::Witness(
                        crate::witness_runtime::WitnessRuntimeError::Tcp(_)
                        | crate::witness_runtime::WitnessRuntimeError::SessionClosed,
                    )) => return Ok(()),
                    // C-d: unknown outcome; retry below the limit, the existing
                    // latch at the limit.
                    Err(NodeWitnessRuntimeError::Witness(
                        crate::witness_runtime::WitnessRuntimeError::UncorrelatedResponsesExhausted,
                    )) if self.uncorrelated_retry.record_exhausted(
                        &outstanding.request_id,
                        outstanding.mutation_generation,
                    ) == crate::node_lease_authority::node_witness_runtime::UncorrelatedRetry::Retry =>
                    {
                        return Ok(());
                    }
                    Err(error) => {
                        // Fail closed into a latched cleanup failure, but keep
                        // the cause observable: a terminal integrity failure
                        // and a transient store failure must stay
                        // distinguishable after the fact.
                        eprintln!(
                            "mikagami: retained-Renew reconciliation failed, latching cleanup failure: {error}"
                        );
                        self.state_machine.mark_cleanup_failed()?;
                        return Ok(());
                    }
                }
            }
            Some(outstanding)
                if outstanding.kind() == crate::node_mutation::MutationKind::LeaseRelease =>
            {
                match self.execute_pending_witness_mutation_once_guarded(session, control_lock_safe)
                {
                    Ok(_) => {
                        self.uncorrelated_retry.record_correlated(
                            &outstanding.request_id,
                            outstanding.mutation_generation,
                        );
                    }
                    Err(LinuxNodeRuntimeError::ControlLockLost) => {
                        return Err(LinuxNodeRuntimeError::ControlLockLost);
                    }
                    Err(LinuxNodeRuntimeError::Witness(
                        crate::node_lease_authority::node_witness_runtime::NodeWitnessRuntimeError::Witness(
                            crate::witness_runtime::WitnessRuntimeError::Tcp(_)
                            | crate::witness_runtime::WitnessRuntimeError::SessionClosed,
                        ),
                    )) => return Ok(()),
                    // C-d: unknown outcome; M and O stay. Retry below the
                    // limit, the existing latch at the limit.
                    Err(LinuxNodeRuntimeError::Witness(
                        crate::node_lease_authority::node_witness_runtime::NodeWitnessRuntimeError::Witness(
                            crate::witness_runtime::WitnessRuntimeError::UncorrelatedResponsesExhausted,
                        ),
                    )) if self.uncorrelated_retry.record_exhausted(
                        &outstanding.request_id,
                        outstanding.mutation_generation,
                    ) == crate::node_lease_authority::node_witness_runtime::UncorrelatedRetry::Retry =>
                    {
                        return Ok(());
                    }
                    Err(error) => {
                        // Fail closed into a latched cleanup failure while
                        // keeping the cause observable.  A RecoveryBlocked
                        // ZeroResource gate, a terminal integrity rejection and
                        // a durable-store failure remain distinguishable.
                        eprintln!(
                            "mikagami: retained-Release reconciliation failed, latching cleanup failure: {error}"
                        );
                        self.state_machine.mark_cleanup_failed()?;
                        return Ok(());
                    }
                }
            }
            Some(_) => return Err(NodeMutationError::OutstandingExists.into()),
            None => {
                if self.mutation_store.release_obligation()?.is_some() {
                    // A session owner that is not this durable mutation must
                    // return before Release is begun.  Never overwrite,
                    // reset, or reinterpret that owner.
                    if session.outstanding_identity().is_some() {
                        return Ok(());
                    }
                    let outcome = {
                        let mut workflow =
                            ResourceWorkflow::new(&mut self.controller, &mut self.executor);
                        workflow
                            .cleanup_guarded("stage 13.6 post-cleanup release", control_lock_safe)?
                    };
                    if !control_lock_safe() {
                        return Err(LinuxNodeRuntimeError::ControlLockLost);
                    }
                    if outcome == CleanupWorkflowOutcome::CleanupRequired {
                        self.state_machine.mark_cleanup_failed()?;
                    }
                }
            }
        }
        Ok(())
    }

    fn promote(&mut self) -> Result<ExplicitOperationResult, LinuxNodeRuntimeError> {
        self.state_machine
            .transition_to(NodeState::Candidate)
            .map_err(LinuxNodeRuntimeError::from)?;
        self.state_machine.begin_promotion()?;
        self.state_machine.advance_promotion()?;

        let outcome = {
            let mut workflow = ResourceWorkflow::new(&mut self.controller, &mut self.executor);
            workflow.promote()
        };
        if outcome != PromotionWorkflowOutcome::ReadyForActiveCommit {
            self.state_machine.rollback_promotion()?;
            return self.finish_promotion_cleanup("promotion failure");
        }
        #[cfg(test)]
        if let Some(hook) = self.promotion_test_hook.as_mut() {
            hook();
        }
        let completion = (|| {
            for _ in 0..5 {
                self.controller.advance_promotion(&mut self.state_machine)?;
            }
            self.controller
                .complete_promotion(&mut self.state_machine)?;
            Ok::<(), LinuxNodeRuntimeError>(())
        })();
        match completion {
            Ok(()) => Ok(ExplicitOperationResult::Completed),
            Err(_) => {
                self.state_machine.rollback_promotion()?;
                self.finish_promotion_cleanup("promotion completion failure")
            }
        }
    }

    pub(crate) fn demote(
        &mut self,
        control_lock_safe: &dyn Fn() -> bool,
    ) -> Result<ExplicitOperationResult, LinuxNodeRuntimeError> {
        // A normal demotion is allowed only while the control lock is still
        // trusted. This check is repeated around the cleanup workflow, whose
        // individual effects are checked again before each syscall.
        if !control_lock_safe() {
            return Err(LinuxNodeRuntimeError::ControlLockLost);
        }
        self.controller.begin_demotion(&mut self.state_machine)?;
        if !control_lock_safe() {
            self.state_machine.mark_cleanup_failed()?;
            return Err(LinuxNodeRuntimeError::ControlLockLost);
        }
        let outcome = {
            let mut workflow = ResourceWorkflow::new(&mut self.controller, &mut self.executor);
            workflow.cleanup_guarded("explicit demotion", control_lock_safe)?
        };
        if !control_lock_safe() {
            self.state_machine.mark_cleanup_failed()?;
            return Err(LinuxNodeRuntimeError::ControlLockLost);
        }
        match outcome {
            CleanupWorkflowOutcome::CleanStandbyEligible => {
                for _ in 0..5 {
                    self.state_machine.advance_demotion()?;
                }
                self.state_machine.complete_demotion()?;
                Ok(ExplicitOperationResult::Completed)
            }
            CleanupWorkflowOutcome::LeaseReleasePending(_) => {
                for _ in 0..4 {
                    self.state_machine.advance_demotion()?;
                }
                Ok(ExplicitOperationResult::LeaseReleasePending)
            }
            CleanupWorkflowOutcome::CleanupRequired => {
                self.state_machine.mark_cleanup_failed()?;
                Ok(ExplicitOperationResult::CleanupRequired)
            }
        }
    }

    pub(crate) fn execute_pending_witness_mutation_once(
        &mut self,
        session: &mut WitnessSession,
    ) -> Result<NodeWitnessMutationResult, LinuxNodeRuntimeError> {
        self.execute_pending_witness_mutation_once_guarded(session, &|| true)
    }

    fn execute_pending_witness_mutation_once_guarded(
        &mut self,
        session: &mut WitnessSession,
        control_lock_safe: &dyn Fn() -> bool,
    ) -> Result<NodeWitnessMutationResult, LinuxNodeRuntimeError> {
        if !control_lock_safe() {
            return Err(LinuxNodeRuntimeError::ControlLockLost);
        }
        if !self.ensure_trusted_zero_resource_guarded(control_lock_safe)? {
            return Err(AuthorityError::RecoveryBlocked.into());
        }
        // C-a(1) (E-4): the exact durable record this exchange sends.
        let sent = self.mutation_store.outstanding()?;
        let runtime = NodeWitnessMutationRuntime::new(&self.mutation_store, self.node_id.clone());
        let result = runtime.execute_outstanding_once(session)?;
        // The request may already be on the wire. Never use its result to
        // start the post-release cleanup/state transition after a live loss.
        if !control_lock_safe() {
            return Err(LinuxNodeRuntimeError::ControlLockLost);
        }
        if matches!(
            result,
            NodeWitnessMutationResult::AcceptedSuccess {
            response: crate::node_lease_authority::node_witness_runtime::NodeWitnessSuccess::LeaseReleased(_),
                ..
            }
        ) {
            if !self.ensure_trusted_zero_resource_guarded(control_lock_safe)?
                || self.controller.reconcile_zero_resource().is_err()
            {
                self.state_machine.mark_cleanup_failed()?;
                return Ok(result);
            }
            if !control_lock_safe() {
                return Err(LinuxNodeRuntimeError::ControlLockLost);
            }
            self.state_machine.advance_demotion()?;
            self.state_machine.complete_demotion()?;
        } else if let NodeWitnessMutationResult::DeterministicReject {
            witness_term,
            reason,
            ..
        } = &result
        {
            if !self.settle_not_releasable_once(
                session,
                sent.as_ref(),
                *witness_term,
                reason,
                control_lock_safe,
            )? {
                self.state_machine.mark_cleanup_failed()?;
            }
        } else if matches!(
            result,
            NodeWitnessMutationResult::RetiredStale { .. }
                | NodeWitnessMutationResult::Conflict { .. }
                | NodeWitnessMutationResult::GenerationGap { .. }
        ) {
            // AC-8: RetiredStale, Conflict and GenerationGap are never a
            // settle; in-process they stay RecoveryBlocked (C-l is startup
            // only).
            self.state_machine.mark_cleanup_failed()?;
        }
        Ok(result)
    }

    /// Amendment C, C-a(1): the only in-process not-releasable settle. After
    /// the exact owned Release was answered with a correlated PolicyReject
    /// (`DeterministicReject` exists only for PolicyReject, from an
    /// authenticated frame of this session whose request id is `M`'s: E-1 to
    /// E-3), `M` and `O` are settled atomically when all of these hold:
    /// - E-4: the answered record is the exact LeaseRelease of `O`, still
    ///   retained unchanged;
    /// - E-5: the rejecting header term `H` is at or above `term_o`;
    /// - E-8: the session is not lost and the control lock is safe;
    /// - E-7: trusted ZeroResource is re-established immediately before;
    /// - E-6 / AC-2: the store settles exactly `M` and `O` in one save, with
    ///   the fencing-incident check inside the same guard.
    ///
    /// `false` means nothing was settled; the caller keeps its existing
    /// RecoveryBlocked latch. A settle is never a release proof (AC-3) and
    /// installs no authority (AC-4): the node only becomes an ordinary
    /// Standby. The reject reason is logged, never a decision input (AC-7).
    fn settle_not_releasable_once(
        &mut self,
        session: &WitnessSession,
        sent: Option<&crate::node_mutation::OutstandingWitnessMutation>,
        witness_term: Term,
        reason: &str,
        control_lock_safe: &dyn Fn() -> bool,
    ) -> Result<bool, LinuxNodeRuntimeError> {
        let Some(sent) = sent else {
            return Ok(false);
        };
        let crate::node_mutation::DurableWitnessMutation::LeaseRelease { term, lease_id, .. } =
            &sent.mutation
        else {
            return Ok(false);
        };
        let image = self.mutation_store.load_existing()?;
        let owned = image
            .release_obligation
            .as_ref()
            .is_some_and(|obligation| obligation.term == *term && obligation.lease_id == *lease_id);
        let retained = image
            .outstanding_mutation
            .as_ref()
            .is_some_and(|outstanding| {
                outstanding.request_id == sent.request_id
                    && outstanding.mutation_generation == sent.mutation_generation
                    && outstanding.mutation == sent.mutation
            });
        if !owned || !retained || witness_term.0 < term.0 {
            return Ok(false);
        }
        if session.lost() || !control_lock_safe() {
            return Ok(false);
        }
        if !self.ensure_trusted_zero_resource_guarded(control_lock_safe)? {
            return Ok(false);
        }
        if self
            .mutation_store
            .settle_rejected_owned_release(
                &sent.request_id,
                sent.mutation_generation,
                *term,
                lease_id,
            )
            .is_err()
        {
            return Ok(false);
        }
        // `M` and `O` are gone. As after an accepted release, the controller
        // returns to ZeroResource before the demotion completes (C-h).
        if self.controller.reconcile_zero_resource().is_err() {
            self.state_machine.mark_cleanup_failed()?;
            return Ok(true);
        }
        if !control_lock_safe() {
            return Err(LinuxNodeRuntimeError::ControlLockLost);
        }
        self.state_machine.advance_demotion()?;
        self.state_machine.complete_demotion()?;
        crate::operator_log::info_release_settled_not_releasable(term.0, reason);
        Ok(true)
    }

    /// C-d: count one exhausted correlation of the retained mutation; whether
    /// the caller may still retry (below `UNCORRELATED_RETRY_LIMIT`).
    fn exhausted_retry_allowed(&mut self) -> Result<bool, LinuxNodeRuntimeError> {
        let Some(outstanding) = self.mutation_store.outstanding()? else {
            return Ok(false);
        };
        Ok(self
            .uncorrelated_retry
            .record_exhausted(&outstanding.request_id, outstanding.mutation_generation)
            == crate::node_lease_authority::node_witness_runtime::UncorrelatedRetry::Retry)
    }

    fn finish_promotion_cleanup(
        &mut self,
        reason: &str,
    ) -> Result<ExplicitOperationResult, LinuxNodeRuntimeError> {
        let outcome = {
            let mut workflow = ResourceWorkflow::new(&mut self.controller, &mut self.executor);
            workflow.cleanup(reason)?
        };
        match outcome {
            CleanupWorkflowOutcome::CleanStandbyEligible => {
                if self.controller.demotion_required() {
                    self.state_machine.complete_promotion_rollback(false)?;
                    return Ok(ExplicitOperationResult::CleanupRequired);
                }
                self.state_machine.complete_promotion_rollback(true)?;
                Ok(ExplicitOperationResult::Blocked)
            }
            CleanupWorkflowOutcome::LeaseReleasePending(_)
            | CleanupWorkflowOutcome::CleanupRequired => {
                self.state_machine.complete_promotion_rollback(false)?;
                Ok(ExplicitOperationResult::CleanupRequired)
            }
        }
    }
}

fn map_vip(observation: VipObservation) -> RuntimeResourceTruth {
    if observation.is_present() {
        RuntimeResourceTruth::Present
    } else if observation.is_absent() {
        RuntimeResourceTruth::Absent
    } else {
        RuntimeResourceTruth::Unknown
    }
}

fn map_service(observation: ServiceObservation) -> RuntimeResourceTruth {
    if observation.is_running() {
        RuntimeResourceTruth::Running
    } else if observation.is_stopped() {
        RuntimeResourceTruth::Stopped
    } else {
        RuntimeResourceTruth::Unknown
    }
}

fn map_health(observation: HealthObservation) -> RuntimeResourceTruth {
    if observation.is_healthy() {
        RuntimeResourceTruth::Healthy
    } else if observation.is_unhealthy() {
        RuntimeResourceTruth::Unhealthy
    } else {
        RuntimeResourceTruth::Unknown
    }
}

fn lease_acquisition_allowed(state: NodeState, recovery_reconciled: bool) -> bool {
    state == NodeState::Standby && recovery_reconciled
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::node_mutation::NodeMutationPersistentState;
    use crate::protocol::{
        CanonicalSerializer, CborSerializer, ClusterId, CommonFields, DurationMs,
        LeaseGrantPayload, LeaseId, NodeId, ProtocolMessage, Sequence, SessionId, Term,
        UnsignedEnvelope,
    };
    use crate::resource_executor::{
        ActionDiagnostic, RawGarpOutcome, RawHealthObservation, RawServiceObservation,
        RawVipObservation, sealed,
    };
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[derive(Clone, Debug)]
    struct TestNetwork {
        vip: Rc<RefCell<VecDeque<RawVipObservation>>>,
        fallback: RawVipObservation,
        actions: Rc<RefCell<Vec<&'static str>>>,
        garp_clock: Option<Rc<Cell<u64>>>,
        advance_garp_clock: Rc<Cell<bool>>,
        /// Stage 14 Phase 14.10 seam: observations the VIP reports once it
        /// was acquired, and the Node document snapshotted at the instant of
        /// the first protected resource mutation (the ARM barrier proof).
        after_acquire: Rc<RefCell<VecDeque<RawVipObservation>>>,
        barrier_probe: Rc<RefCell<Option<(PathBuf, Vec<String>)>>>,
    }

    impl sealed::NetworkBackend for TestNetwork {}

    impl NetworkBackend for TestNetwork {
        fn request_vip_acquire(&mut self) -> ActionDiagnostic {
            if let Some((path, seen)) = self.barrier_probe.borrow_mut().as_mut() {
                seen.push(std::fs::read_to_string(path).unwrap_or_default());
            }
            self.actions.borrow_mut().push("vip_acquire");
            let appeared: Vec<_> = self.after_acquire.borrow_mut().drain(..).collect();
            self.vip.borrow_mut().extend(appeared);
            ActionDiagnostic::Success
        }

        fn observe_vip(&mut self) -> RawVipObservation {
            self.vip.borrow_mut().pop_front().unwrap_or(self.fallback)
        }

        fn request_vip_release(&mut self) -> ActionDiagnostic {
            self.actions.borrow_mut().push("vip_release");
            ActionDiagnostic::Success
        }

        fn send_garp(&mut self) -> (ActionDiagnostic, RawGarpOutcome) {
            self.actions.borrow_mut().push("garp");
            if self.advance_garp_clock.get()
                && let Some(clock) = &self.garp_clock
            {
                clock.set(8_000);
            }
            (ActionDiagnostic::Success, RawGarpOutcome::Succeeded)
        }
    }

    #[derive(Clone, Debug)]
    struct TestService {
        service: Rc<RefCell<VecDeque<RawServiceObservation>>>,
        service_fallback: RawServiceObservation,
        health: Rc<RefCell<VecDeque<RawHealthObservation>>>,
        health_fallback: RawHealthObservation,
        actions: Rc<RefCell<Vec<&'static str>>>,
        /// Stage 14 Phase 14.10 seam: observations the service reports once
        /// it was started.
        after_start: Rc<RefCell<VecDeque<RawServiceObservation>>>,
    }

    impl sealed::ServiceBackend for TestService {}

    impl ServiceBackend for TestService {
        fn request_service_start(&mut self) -> ActionDiagnostic {
            self.actions.borrow_mut().push("service_start");
            let appeared: Vec<_> = self.after_start.borrow_mut().drain(..).collect();
            self.service.borrow_mut().extend(appeared);
            ActionDiagnostic::Success
        }

        fn observe_service(&mut self) -> RawServiceObservation {
            self.service
                .borrow_mut()
                .pop_front()
                .unwrap_or(self.service_fallback)
        }

        fn request_service_stop(&mut self) -> ActionDiagnostic {
            self.actions.borrow_mut().push("service_stop");
            ActionDiagnostic::Success
        }

        fn observe_health(&mut self) -> RawHealthObservation {
            self.actions.borrow_mut().push("health");
            self.health
                .borrow_mut()
                .pop_front()
                .unwrap_or(self.health_fallback)
        }
    }

    #[derive(Clone, Debug)]
    struct TestClock {
        now: Rc<Cell<u64>>,
        failed: Rc<Cell<bool>>,
    }

    impl crate::node_lease_authority::MonotonicClock for TestClock {
        fn now(
            &self,
        ) -> Result<
            crate::node_lease_authority::MonotonicTime,
            crate::node_lease_authority::ClockError,
        > {
            if self.failed.get() {
                return Err(crate::node_lease_authority::ClockError::Unavailable);
            }
            Ok(crate::node_lease_authority::MonotonicTime::from_millis(
                self.now.get(),
            ))
        }
    }

    struct TestRuntimeParts {
        runtime: LinuxNodeRuntime<TestNetwork, TestService, TestClock>,
        actions: Rc<RefCell<Vec<&'static str>>>,
        vip: Rc<RefCell<VecDeque<RawVipObservation>>>,
        service: Rc<RefCell<VecDeque<RawServiceObservation>>>,
        path: PathBuf,
        advance_garp_clock: Rc<Cell<bool>>,
        clock_failed: Rc<Cell<bool>>,
        health: Rc<RefCell<VecDeque<RawHealthObservation>>>,
        after_acquire: Rc<RefCell<VecDeque<RawVipObservation>>>,
        after_start: Rc<RefCell<VecDeque<RawServiceObservation>>>,
        barrier_probe: Rc<RefCell<Option<(PathBuf, Vec<String>)>>>,
    }

    static NEXT_RUNTIME_TEST: AtomicU64 = AtomicU64::new(1);

    fn test_runtime(
        vip: impl IntoIterator<Item = RawVipObservation>,
        service: impl IntoIterator<Item = RawServiceObservation>,
        health: impl IntoIterator<Item = RawHealthObservation>,
        mode: AuthorityMode,
        garp_clock: Option<Rc<Cell<u64>>>,
    ) -> TestRuntimeParts {
        let id = NEXT_RUNTIME_TEST.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("mikagami-stage11-7-{}-{id}", std::process::id()));
        let store = crate::node_mutation::NodeMutationStore::new(
            &path,
            ClusterId::new("cluster"),
            NodeId::new("node-a"),
        );
        store.initialize_new().unwrap();
        let clock_failed = Rc::new(Cell::new(false));
        let clock = TestClock {
            now: garp_clock.clone().unwrap_or_else(|| Rc::new(Cell::new(0))),
            failed: clock_failed.clone(),
        };
        let controller = NodeAuthorityController::new_for_runtime(
            clock.clone(),
            NodeId::new("node-a"),
            store,
            mode,
        );
        let actions = Rc::new(RefCell::new(Vec::new()));
        let advance_garp_clock = Rc::new(Cell::new(true));
        let after_acquire = Rc::new(RefCell::new(VecDeque::new()));
        let after_start = Rc::new(RefCell::new(VecDeque::new()));
        let barrier_probe = Rc::new(RefCell::new(None));
        let network = TestNetwork {
            vip: Rc::new(RefCell::new(vip.into_iter().collect())),
            fallback: RawVipObservation::Absent,
            actions: actions.clone(),
            garp_clock,
            advance_garp_clock: advance_garp_clock.clone(),
            after_acquire: after_acquire.clone(),
            barrier_probe: barrier_probe.clone(),
        };
        let service = TestService {
            service: Rc::new(RefCell::new(service.into_iter().collect())),
            service_fallback: RawServiceObservation::Stopped,
            health: Rc::new(RefCell::new(health.into_iter().collect())),
            health_fallback: RawHealthObservation::Unavailable,
            actions: actions.clone(),
            after_start: after_start.clone(),
        };
        let health_queue = service.health.clone();
        let vip_queue = network.vip.clone();
        let service_queue = service.service.clone();
        let runtime_store = crate::node_mutation::NodeMutationStore::new(
            &path,
            ClusterId::new("cluster"),
            NodeId::new("node-a"),
        );
        TestRuntimeParts {
            runtime: LinuxNodeRuntime::from_test_parts(
                controller,
                ResourceExecutor::new(network, service),
                runtime_store,
                NodeId::new("node-a"),
                100,
            ),
            actions,
            vip: vip_queue,
            service: service_queue,
            path,
            advance_garp_clock,
            clock_failed,
            health: health_queue,
            after_acquire,
            after_start,
            barrier_probe,
        }
    }

    fn cleanup_test_path(path: &PathBuf) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(path.with_extension("recovery"));
    }

    // ---- v0.6 A-1: Witness-loss stop proof ------------------------------

    // ---- v0.6 A-2: retained LeaseRenew resolution at startup --------------

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum RenewScript {
        Renewed,
        RetiredStale,
        CloseWithoutAnswer,
    }

    /// Loopback Witness that answers exactly one LeaseRenew (or closes), and
    /// records every request it received.
    fn renew_fixture(
        script: RenewScript,
    ) -> (
        WitnessSession,
        std::sync::mpsc::Receiver<String>,
        std::thread::JoinHandle<()>,
    ) {
        use crate::security::{MessageAuthenticator, Psk};
        use crate::session::ProcessSession;
        use crate::tcp::TcpConnection;
        use crate::witness_runtime::WitnessConnection;
        use std::net::{TcpListener, TcpStream};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let (sender, requests) = std::sync::mpsc::channel();
        let join = std::thread::spawn(move || {
            use crate::witness_runtime::{
                WitnessResponseContext, send_witness_response_with_context,
            };
            let auth = MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32]));
            let mut witness = WitnessConnection::new(
                NodeId::new("witness"),
                NodeId::new("node-a"),
                ClusterId::new("cluster"),
                SessionId::new("session-a"),
                TcpConnection::from_stream(server, Duration::from_secs(5), Duration::from_secs(5))
                    .unwrap(),
            );
            let mut process = ProcessSession::from_session_id(SessionId::new("session-w"));
            let Ok(pending) = witness.receive_pending(&CborSerializer, &auth) else {
                return;
            };
            let request_id = pending
                .message()
                .unsigned()
                .common
                .request_id
                .clone()
                .unwrap();
            let kind = match &pending.message().unsigned().message {
                ProtocolMessage::LeaseRenew(payload) => {
                    let _ = sender.send(format!(
                        "renew term={} lease={}",
                        payload.term.0,
                        payload.lease_id.as_str()
                    ));
                    (payload.term, payload.lease_id.clone())
                }
                other => {
                    let _ = sender.send(format!("unexpected {other:?}"));
                    return;
                }
            };
            if script == RenewScript::CloseWithoutAnswer {
                return;
            }
            let (response, context) = match script {
                RenewScript::Renewed => (
                    ProtocolMessage::LeaseRenewed(LeaseGrantPayload {
                        term: kind.0,
                        lease_id: kind.1.clone(),
                        holder_node_id: NodeId::new("node-a"),
                        lease_ttl_ms: DurationMs(crate::node_lease_authority::LEASE_TTL_MS),
                        renew_after_ms: DurationMs(3_000),
                        lease_remaining_ms: DurationMs(crate::node_lease_authority::LEASE_TTL_MS),
                    }),
                    WitnessResponseContext {
                        term: kind.0,
                        lease_id: Some(kind.1.clone()),
                    },
                ),
                RenewScript::RetiredStale => (
                    ProtocolMessage::LeaseReject(crate::protocol::LeaseRejectPayload {
                        code: crate::protocol::WitnessMutationOutcomeCode::RetiredStale,
                        reason: "retired".into(),
                    }),
                    WitnessResponseContext {
                        term: kind.0,
                        lease_id: None,
                    },
                ),
                RenewScript::CloseWithoutAnswer => unreachable!(),
            };
            let _ = send_witness_response_with_context(
                &mut witness,
                &mut process,
                request_id,
                response,
                context,
                &CborSerializer,
                &auth,
            );
        });
        let node = WitnessConnection::new(
            NodeId::new("node-a"),
            NodeId::new("witness"),
            ClusterId::new("cluster"),
            SessionId::new("session-w"),
            TcpConnection::from_stream(client, Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
        );
        let session = WitnessSession::new(
            node,
            ProcessSession::from_session_id(SessionId::new("session-a")),
            MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32])),
        );
        (session, requests, join)
    }

    /// Loopback Witness that rejects whichever mutation arrives with a
    /// deterministic policy reject, and records its kind.
    fn release_reject_fixture(
        reject_term: Term,
    ) -> (
        WitnessSession,
        std::sync::mpsc::Receiver<&'static str>,
        std::thread::JoinHandle<()>,
    ) {
        use crate::security::{MessageAuthenticator, Psk};
        use crate::session::ProcessSession;
        use crate::tcp::TcpConnection;
        use crate::witness_runtime::WitnessConnection;
        use std::net::{TcpListener, TcpStream};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let (sender, requests) = std::sync::mpsc::channel();
        let join = std::thread::spawn(move || {
            use crate::witness_runtime::{
                WitnessResponseContext, send_witness_response_with_context,
            };
            let auth = MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32]));
            let mut witness = WitnessConnection::new(
                NodeId::new("witness"),
                NodeId::new("node-a"),
                ClusterId::new("cluster"),
                SessionId::new("session-a"),
                TcpConnection::from_stream(server, Duration::from_secs(5), Duration::from_secs(5))
                    .unwrap(),
            );
            let mut process = ProcessSession::from_session_id(SessionId::new("session-w"));
            let Ok(pending) = witness.receive_pending(&CborSerializer, &auth) else {
                return;
            };
            let request_id = pending
                .message()
                .unsigned()
                .common
                .request_id
                .clone()
                .unwrap();
            let kind = match &pending.message().unsigned().message {
                ProtocolMessage::LeaseRelease(_) => "release",
                ProtocolMessage::LeaseRenew(_) => "renew",
                _ => "other",
            };
            let _ = sender.send(kind);
            let _ = send_witness_response_with_context(
                &mut witness,
                &mut process,
                request_id,
                ProtocolMessage::LeaseReject(crate::protocol::LeaseRejectPayload {
                    code: crate::protocol::WitnessMutationOutcomeCode::PolicyReject,
                    reason: "there is no active lease to release".to_string(),
                }),
                WitnessResponseContext {
                    term: reject_term,
                    lease_id: None,
                },
                &CborSerializer,
                &auth,
            );
        });
        let node = WitnessConnection::new(
            NodeId::new("node-a"),
            NodeId::new("witness"),
            ClusterId::new("cluster"),
            SessionId::new("session-w"),
            TcpConnection::from_stream(client, Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
        );
        let session = WitnessSession::new(
            node,
            ProcessSession::from_session_id(SessionId::new("session-a")),
            MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32])),
        );
        (session, requests, join)
    }

    /// v0.6 B-1 (audit): a reject from a Witness whose term is BEHIND the
    /// obligation proves nothing - the Witness may have lost its state. The
    /// obligation must be retained and the node stays recovery-blocked.
    #[test]
    fn a_reject_from_an_older_witness_term_does_not_clear_the_obligation() {
        let mut parts = sor_runtime("behind-reject");
        parts
            .runtime
            .mutation_store
            .begin_lease_release_for_test(Term(7), LeaseId::new("lease-1"), "startup".into())
            .unwrap();
        let (mut session, requests, join) = release_reject_fixture(Term(6));
        let outcome = parts
            .runtime
            .reconcile_startup_obligation(&mut session, None)
            .unwrap();
        join.join().unwrap();
        assert_eq!(requests.try_iter().collect::<Vec<_>>(), ["release"]);
        assert!(matches!(outcome, SorOutcome::Blocked(_)), "{outcome:?}");
        // The obligation and the release record are retained.
        assert!(
            parts
                .runtime
                .mutation_store
                .release_obligation()
                .unwrap()
                .is_some()
        );
        assert!(
            parts
                .runtime
                .mutation_store
                .outstanding()
                .unwrap()
                .is_some()
        );
        cleanup_test_path(&parts.path);
    }

    /// v0.6 A-4: the Witness rejecting the exact release as "not releasable"
    /// is proof that the obligation is moot. Keeping it would block the node
    /// forever (the common case: the lease expired while the node was down).
    #[test]
    fn a_rejected_exact_release_clears_the_obligation_and_returns_to_standby() {
        let mut parts = sor_runtime("rejected-release");
        parts
            .runtime
            .mutation_store
            .begin_lease_release_for_test(Term(7), LeaseId::new("lease-1"), "startup".into())
            .unwrap();
        let (mut session, requests, join) = release_reject_fixture(Term(7));
        let outcome = parts
            .runtime
            .reconcile_startup_obligation(&mut session, None)
            .unwrap();
        join.join().unwrap();
        assert_eq!(requests.try_iter().collect::<Vec<_>>(), ["release"]);
        assert!(
            matches!(
                outcome,
                SorOutcome::Cleared {
                    by: crate::obligation_reconciliation::SupersededBy::WitnessRejectedRelease { .. },
                    ..
                }
            ),
            "{outcome:?}"
        );
        sor_assert_standby(&mut parts);
        cleanup_test_path(&parts.path);
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum J21RequestScript {
        GrantStillCurrent,
        RetiredStale,
        Conflict,
        CloseWithoutAnswer,
    }

    /// J21: loopback Witness that answers exactly one LeaseRequest (or closes) and records every
    /// request it received.
    fn j21_request_fixture(
        script: J21RequestScript,
    ) -> (
        WitnessSession,
        std::sync::mpsc::Receiver<String>,
        std::thread::JoinHandle<()>,
    ) {
        use crate::security::{MessageAuthenticator, Psk};
        use crate::session::ProcessSession;
        use crate::tcp::TcpConnection;
        use crate::witness_runtime::WitnessConnection;
        use std::net::{TcpListener, TcpStream};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let (sender, requests) = std::sync::mpsc::channel();
        let join = std::thread::spawn(move || {
            use crate::witness_runtime::{
                WitnessResponseContext, send_witness_response_with_context,
            };
            let auth = MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32]));
            let mut witness = WitnessConnection::new(
                NodeId::new("witness"),
                NodeId::new("node-a"),
                ClusterId::new("cluster"),
                SessionId::new("session-a"),
                TcpConnection::from_stream(server, Duration::from_secs(5), Duration::from_secs(5))
                    .unwrap(),
            );
            let mut process = ProcessSession::from_session_id(SessionId::new("session-w"));
            // J23 (C-F): the fence comes first; answer it as "generation already used" so the J21
            // scenario (the original request was committed) continues with its exact replay.
            let pending = loop {
                let Ok(pending) = witness.receive_pending(&CborSerializer, &auth) else {
                    return;
                };
                if !j23_answer_fence_as_retired(
                    &mut witness,
                    &mut process,
                    &auth,
                    &pending,
                    &sender,
                ) {
                    break pending;
                }
            };
            let request_id = pending
                .message()
                .unsigned()
                .common
                .request_id
                .clone()
                .unwrap();
            let observed = match &pending.message().unsigned().message {
                ProtocolMessage::LeaseRequest(payload) => {
                    let _ = sender.send(format!("request observed={}", payload.observed_term.0));
                    payload.observed_term
                }
                other => {
                    let _ = sender.send(format!("unexpected {other:?}"));
                    return;
                }
            };
            if script == J21RequestScript::CloseWithoutAnswer {
                return;
            }
            let granted = Term(observed.0 + 1);
            let (response, context) = match script {
                J21RequestScript::GrantStillCurrent => (
                    ProtocolMessage::LeaseGrant(LeaseGrantPayload {
                        term: granted,
                        lease_id: LeaseId::new("lease-r"),
                        holder_node_id: NodeId::new("node-a"),
                        lease_ttl_ms: DurationMs(crate::node_lease_authority::LEASE_TTL_MS),
                        renew_after_ms: DurationMs(3_000),
                        lease_remaining_ms: DurationMs(4_000),
                    }),
                    WitnessResponseContext {
                        term: granted,
                        lease_id: Some(LeaseId::new("lease-r")),
                    },
                ),
                J21RequestScript::RetiredStale | J21RequestScript::Conflict => (
                    ProtocolMessage::LeaseReject(crate::protocol::LeaseRejectPayload {
                        code: if script == J21RequestScript::RetiredStale {
                            crate::protocol::WitnessMutationOutcomeCode::RetiredStale
                        } else {
                            crate::protocol::WitnessMutationOutcomeCode::Conflict
                        },
                        reason: "j21".into(),
                    }),
                    WitnessResponseContext {
                        term: granted,
                        lease_id: None,
                    },
                ),
                J21RequestScript::CloseWithoutAnswer => unreachable!(),
            };
            let _ = send_witness_response_with_context(
                &mut witness,
                &mut process,
                request_id,
                response,
                context,
                &CborSerializer,
                &auth,
            );
        });
        let node = WitnessConnection::new(
            NodeId::new("node-a"),
            NodeId::new("witness"),
            ClusterId::new("cluster"),
            SessionId::new("session-w"),
            TcpConnection::from_stream(client, Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
        );
        let session = WitnessSession::new(
            node,
            ProcessSession::from_session_id(SessionId::new("session-a")),
            MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32])),
        );
        (session, requests, join)
    }

    fn j21_runtime_with_retained_request() -> TestRuntimeParts {
        let mut parts = test_runtime([], [], [], AuthorityMode::Conservative, None);
        parts.runtime.reconcile().unwrap();
        parts
            .runtime
            .mutation_store
            .begin_lease_request(Term(7), 100, DurationMs(10_000))
            .unwrap();
        assert!(parts.runtime.retained_request_pending().unwrap());
        parts
    }

    /// J21: a grant that is still current is never used; its lease goes to the release
    /// obligation and no authority is installed.
    #[test]
    fn j21_retained_request_with_a_current_grant_is_handed_to_the_release_obligation() {
        let mut parts = j21_runtime_with_retained_request();
        let (mut session, requests, join) =
            j21_request_fixture(J21RequestScript::GrantStillCurrent);
        let outcome = parts.runtime.resolve_retained_request_once(&mut session);
        join.join().unwrap();
        // J22 (B-1): the lost Release answer is reported as not confirmed, no longer an error.
        assert!(
            matches!(&outcome, Ok(RetainedRenewOutcome::Blocked { reason }) if reason.contains("is not confirmed")),
            "the Release to a closed fixture is not confirmed after the obligation is recorded: {outcome:?}"
        );
        assert_eq!(
            requests.try_iter().collect::<Vec<_>>(),
            [J23_FENCE_RECORD, "request observed=7"]
        );
        assert!(!parts.runtime.retained_request_pending().unwrap());
        // The fixture answers one request only: the exact Release that follows cannot complete,
        // so the obligation and the Release record stay for the startup reconciliation.
        let outstanding = parts.runtime.mutation_store.outstanding().unwrap();
        assert!(
            outstanding
                .as_ref()
                .is_some_and(|o| o.kind() == crate::node_mutation::MutationKind::LeaseRelease),
            "{outstanding:?}"
        );
        let obligation = parts
            .runtime
            .mutation_store
            .release_obligation()
            .unwrap()
            .expect("the still-current lease must be released");
        assert_eq!(obligation.term, Term(8));
        assert_eq!(obligation.lease_id, LeaseId::new("lease-r"));
        assert!(
            parts.runtime.controller.authority().authority().is_none(),
            "startup resolution must never install authority"
        );
        cleanup_test_path(&parts.path);
    }

    /// J21: a retired-stale answer clears the record without a grant, an obligation or authority.
    #[test]
    fn j21_retired_stale_retained_request_is_cleared() {
        let mut parts = j21_runtime_with_retained_request();
        let (mut session, requests, join) = j21_request_fixture(J21RequestScript::RetiredStale);
        assert!(matches!(
            parts
                .runtime
                .resolve_retained_request_once(&mut session)
                .unwrap(),
            RetainedRenewOutcome::Resolved { .. }
        ));
        join.join().unwrap();
        assert_eq!(requests.try_iter().count(), 2);
        assert!(!parts.runtime.retained_request_pending().unwrap());
        assert!(
            parts
                .runtime
                .mutation_store
                .release_obligation()
                .unwrap()
                .is_none()
        );
        assert!(parts.runtime.controller.authority().authority().is_none());
        assert!(parts.runtime.reconcile().unwrap().recovery_reconciled);
        cleanup_test_path(&parts.path);
    }

    /// J21: a closed connection or a non-terminal answer proves nothing; the record stays.
    #[test]
    fn j21_unanswered_or_non_terminal_retained_request_stays_blocked() {
        for script in [
            J21RequestScript::CloseWithoutAnswer,
            J21RequestScript::Conflict,
        ] {
            let mut parts = j21_runtime_with_retained_request();
            let (mut session, requests, join) = j21_request_fixture(script);
            assert!(matches!(
                parts
                    .runtime
                    .resolve_retained_request_once(&mut session)
                    .unwrap(),
                RetainedRenewOutcome::Blocked { .. }
            ));
            join.join().unwrap();
            assert_eq!(requests.try_iter().count(), 2);
            assert!(parts.runtime.retained_request_pending().unwrap());
            assert!(parts.runtime.reconcile().unwrap().unresolved_mutation);
            assert!(parts.runtime.controller.authority().authority().is_none());
            cleanup_test_path(&parts.path);
        }
    }

    /// J21: with a resource still observed, nothing is sent at all.
    #[test]
    fn j21_retained_request_is_not_sent_while_a_resource_is_observed() {
        let mut parts = test_runtime(
            [RawVipObservation::Present],
            [RawServiceObservation::Stopped],
            [],
            AuthorityMode::Conservative,
            None,
        );
        parts
            .runtime
            .mutation_store
            .begin_lease_request(Term(7), 100, DurationMs(10_000))
            .unwrap();
        let (mut session, requests, join) =
            j21_request_fixture(J21RequestScript::GrantStillCurrent);
        assert!(matches!(
            parts
                .runtime
                .resolve_retained_request_once(&mut session)
                .unwrap(),
            RetainedRenewOutcome::Blocked { .. }
        ));
        drop(session);
        join.join().unwrap();
        assert_eq!(requests.try_iter().count(), 0);
        assert!(parts.runtime.retained_request_pending().unwrap());
        cleanup_test_path(&parts.path);
    }

    /// J23: how the J21 / J22 scripted fixtures record an answered generation fence.
    const J23_FENCE_RECORD: &str = "fence";

    /// J23 (C-F): if `pending` is the generation fence of a retained request, answer it as the
    /// Witness does when the generation was already used (RetiredStale: the original request was
    /// committed earlier) and return true. The scripted J21 / J22 fixtures use it so their scenarios
    /// keep describing the exact replay that follows such a fence. The fence is recorded as
    /// `J23_FENCE_RECORD` in the fixture's request log, so a test that expects nothing to be sent
    /// also fails when a fence is sent (independent audit N-1).
    fn j23_answer_fence_as_retired(
        witness: &mut crate::witness_runtime::WitnessConnection,
        process: &mut crate::session::ProcessSession,
        auth: &crate::security::MessageAuthenticator,
        pending: &crate::witness_runtime::PendingWitnessMessage,
        sender: &std::sync::mpsc::Sender<String>,
    ) -> bool {
        let ProtocolMessage::LeaseRelease(payload) = &pending.message().unsigned().message else {
            return false;
        };
        if payload.term != Term(0) || payload.lease_id.as_str() != GENERATION_FENCE_LEASE_ID {
            return false;
        }
        let _ = sender.send(J23_FENCE_RECORD.to_string());
        let request_id = pending
            .message()
            .unsigned()
            .common
            .request_id
            .clone()
            .unwrap();
        let _ = crate::witness_runtime::send_witness_response_with_context(
            witness,
            process,
            request_id,
            ProtocolMessage::LeaseReject(crate::protocol::LeaseRejectPayload {
                code: crate::protocol::WitnessMutationOutcomeCode::RetiredStale,
                reason: "j23: the generation was used by an earlier commit".into(),
            }),
            crate::witness_runtime::WitnessResponseContext {
                term: Term(0),
                lease_id: None,
            },
            &CborSerializer,
            auth,
        );
        true
    }

    /// J22: what the loopback Witness answers to each request it receives, in order.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum J22Answer {
        /// A grant at the observed term + 1 for `lease-r` with the full TTL remaining (the answer
        /// to a replay that is the first delivery looks the same).
        Grant,
        /// `LEASE_RELEASED` for the released lease.
        Released,
        /// A reject with this outcome code.
        Reject(crate::protocol::WitnessMutationOutcomeCode),
        /// Close the connection without an answer.
        Close,
    }

    /// J22: loopback Witness that answers the requests it receives in order and records each one;
    /// it closes the connection after the script or at `Close`.
    fn j22_fixture(
        script: Vec<J22Answer>,
    ) -> (
        WitnessSession,
        std::sync::mpsc::Receiver<String>,
        std::thread::JoinHandle<()>,
    ) {
        use crate::security::{MessageAuthenticator, Psk};
        use crate::session::ProcessSession;
        use crate::tcp::TcpConnection;
        use crate::witness_runtime::WitnessConnection;
        use std::net::{TcpListener, TcpStream};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let (sender, requests) = std::sync::mpsc::channel();
        let join = std::thread::spawn(move || {
            use crate::witness_runtime::{
                WitnessResponseContext, send_witness_response_with_context,
            };
            let auth = MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32]));
            let mut witness = WitnessConnection::new(
                NodeId::new("witness"),
                NodeId::new("node-a"),
                ClusterId::new("cluster"),
                SessionId::new("session-a"),
                TcpConnection::from_stream(server, Duration::from_secs(5), Duration::from_secs(5))
                    .unwrap(),
            );
            let mut process = ProcessSession::from_session_id(SessionId::new("session-w"));
            for answer in script {
                // J23 (C-F): as in the J21 fixture, the fence is answered as "generation already
                // used" without consuming a script entry.
                let pending = loop {
                    let Ok(pending) = witness.receive_pending(&CborSerializer, &auth) else {
                        return;
                    };
                    if !j23_answer_fence_as_retired(
                        &mut witness,
                        &mut process,
                        &auth,
                        &pending,
                        &sender,
                    ) {
                        break pending;
                    }
                };
                let request_id = pending
                    .message()
                    .unsigned()
                    .common
                    .request_id
                    .clone()
                    .unwrap();
                let (term, lease_id) = match &pending.message().unsigned().message {
                    ProtocolMessage::LeaseRequest(payload) => {
                        let _ =
                            sender.send(format!("request observed={}", payload.observed_term.0));
                        (Term(payload.observed_term.0 + 1), LeaseId::new("lease-r"))
                    }
                    ProtocolMessage::LeaseRelease(payload) => {
                        let _ = sender.send(format!(
                            "release term={} lease={}",
                            payload.term.0,
                            payload.lease_id.as_str()
                        ));
                        (payload.term, payload.lease_id.clone())
                    }
                    other => {
                        let _ = sender.send(format!("unexpected {other:?}"));
                        return;
                    }
                };
                let (response, context) = match answer {
                    J22Answer::Close => return,
                    J22Answer::Grant => (
                        ProtocolMessage::LeaseGrant(LeaseGrantPayload {
                            term,
                            lease_id: lease_id.clone(),
                            holder_node_id: NodeId::new("node-a"),
                            lease_ttl_ms: DurationMs(crate::node_lease_authority::LEASE_TTL_MS),
                            renew_after_ms: DurationMs(3_000),
                            lease_remaining_ms: DurationMs(
                                crate::node_lease_authority::LEASE_TTL_MS,
                            ),
                        }),
                        WitnessResponseContext {
                            term,
                            lease_id: Some(lease_id),
                        },
                    ),
                    J22Answer::Released => (
                        ProtocolMessage::LeaseReleased(crate::protocol::LeaseReleasedPayload {
                            term,
                            lease_id,
                            result: "released".into(),
                        }),
                        WitnessResponseContext {
                            term,
                            lease_id: None,
                        },
                    ),
                    J22Answer::Reject(code) => (
                        ProtocolMessage::LeaseReject(crate::protocol::LeaseRejectPayload {
                            code,
                            reason: "j22".into(),
                        }),
                        WitnessResponseContext {
                            term,
                            lease_id: None,
                        },
                    ),
                };
                let _ = send_witness_response_with_context(
                    &mut witness,
                    &mut process,
                    request_id,
                    response,
                    context,
                    &CborSerializer,
                    &auth,
                );
            }
        });
        let node = WitnessConnection::new(
            NodeId::new("node-a"),
            NodeId::new("witness"),
            ClusterId::new("cluster"),
            SessionId::new("session-w"),
            TcpConnection::from_stream(client, Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
        );
        let session = WitnessSession::new(
            node,
            ProcessSession::from_session_id(SessionId::new("session-a")),
            MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32])),
        );
        (session, requests, join)
    }

    /// J22: (release obligation present, kind of the outstanding mutation).
    fn j22_record(parts: &TestRuntimeParts) -> (bool, Option<crate::node_mutation::MutationKind>) {
        let image = parts.runtime.mutation_store.load_existing().unwrap();
        (
            image.release_obligation.is_some(),
            image.outstanding_mutation.as_ref().map(|o| o.kind()),
        )
    }

    /// J22: the resolution never installs authority, never takes a resource and never makes the
    /// node Active, whatever the Witness answered (promotion authorization stays separate).
    fn j22_assert_no_authority_resource_or_promotion(parts: &TestRuntimeParts) {
        assert!(
            parts.runtime.controller.authority().authority().is_none(),
            "startup resolution must never install authority"
        );
        let actions = parts.actions.borrow();
        for effect in ["vip_acquire", "service_start", "garp"] {
            assert!(!actions.contains(&effect), "{effect} in {actions:?}");
        }
        assert_ne!(parts.runtime.state_machine.node_state(), NodeState::Active);
    }

    fn j22_run(
        parts: &mut TestRuntimeParts,
        script: Vec<J22Answer>,
    ) -> (
        Result<RetainedRenewOutcome, LinuxNodeRuntimeError>,
        Vec<String>,
    ) {
        let (mut session, requests, join) = j22_fixture(script);
        let outcome = parts.runtime.resolve_retained_request_once(&mut session);
        drop(session);
        join.join().unwrap();
        (outcome, requests.try_iter().collect())
    }

    /// J22 (B-1, and the first delivery of J22-A): a grant answered to the replay - reconstructed,
    /// or newly created when the original request never reached the Witness - is never used. Only a
    /// LEASE_RELEASED answer whose completion is durable is reported as released; both durable
    /// records are then gone.
    #[test]
    fn j22_unused_grant_is_reported_released_only_after_lease_released() {
        let mut parts = j21_runtime_with_retained_request();
        let (outcome, requests) = j22_run(&mut parts, vec![J22Answer::Grant, J22Answer::Released]);
        assert!(
            matches!(&outcome, Ok(RetainedRenewOutcome::Resolved { how }) if *how == UNUSED_GRANT_RELEASED),
            "{outcome:?}"
        );
        assert_eq!(
            requests,
            [
                J23_FENCE_RECORD,
                "request observed=7",
                "release term=8 lease=lease-r"
            ]
        );
        assert_eq!(j22_record(&parts), (false, None));
        j22_assert_no_authority_resource_or_promotion(&parts);
        assert!(parts.runtime.reconcile().unwrap().recovery_reconciled);
        j22_assert_no_authority_resource_or_promotion(&parts);
        cleanup_test_path(&parts.path);
    }

    /// J22 (B-1): every Release answer other than LEASE_RELEASED is reported as NOT confirmed, and
    /// the obligation and the exact Release record stay for the startup reconciliation.
    #[test]
    fn j22_unconfirmed_release_is_never_reported_as_released() {
        use crate::protocol::WitnessMutationOutcomeCode as C;
        for code in [
            C::PolicyReject,
            C::RetiredStale,
            C::Conflict,
            C::GenerationGap,
            C::TemporarilyUnavailable,
        ] {
            let mut parts = j21_runtime_with_retained_request();
            let (outcome, requests) =
                j22_run(&mut parts, vec![J22Answer::Grant, J22Answer::Reject(code)]);
            // J23 (OD-J22-5): an unconfirmed Release is its own outcome, never "Resolved".
            let Ok(RetainedRenewOutcome::ResolvedReleaseUnconfirmed { how }) = &outcome else {
                panic!("{code:?}: {outcome:?}");
            };
            assert_ne!(*how, UNUSED_GRANT_RELEASED, "{code:?}");
            assert!(how.contains("release NOT confirmed"), "{code:?}: {how}");
            assert_eq!(requests.len(), 3, "{code:?}: {requests:?}");
            assert_eq!(
                j22_record(&parts),
                (true, Some(crate::node_mutation::MutationKind::LeaseRelease)),
                "{code:?}"
            );
            j22_assert_no_authority_resource_or_promotion(&parts);
            cleanup_test_path(&parts.path);
        }
    }

    /// J22 (B-1, Release answer lost): the Witness closes before answering the Release; nothing is
    /// proven, the node stays blocked and both records stay.
    #[test]
    fn j22_lost_release_answer_is_not_confirmed_and_keeps_both_records() {
        let mut parts = j21_runtime_with_retained_request();
        let (outcome, requests) = j22_run(&mut parts, vec![J22Answer::Grant, J22Answer::Close]);
        let Ok(RetainedRenewOutcome::Blocked { reason }) = &outcome else {
            panic!("{outcome:?}");
        };
        assert!(
            reason.contains("is not confirmed")
                && reason.contains("stay for the startup reconciliation")
                && !reason.contains(UNUSED_GRANT_RELEASED),
            "{reason}"
        );
        // The operator log bounds the daemon's line; the durable state survives the bound.
        let logged = crate::operator_log::bounded_reason(&format!(
            "startup resolution of the retained lease request stopped: {reason}"
        ));
        assert!(
            logged.contains("stay for the startup reconciliation"),
            "{logged}"
        );
        assert_eq!(requests.len(), 3);
        assert_eq!(
            j22_record(&parts),
            (true, Some(crate::node_mutation::MutationKind::LeaseRelease))
        );
        j22_assert_no_authority_resource_or_promotion(&parts);
        cleanup_test_path(&parts.path);
    }

    /// J22 (B-3, arm failure and a Release record that cannot be written): the Release is never
    /// sent and the report names what is durable. Durable writes: 1 completes the LeaseRequest,
    /// 2 records the obligation, 3 begins the Release, 4 completes the released obligation.
    #[test]
    fn j22_release_stopped_before_sending_is_reported_from_the_durable_record() {
        for (failing_write, expected_record, says) in [
            (2, (false, None), "nothing is recorded"),
            (3, (true, None), "the release obligation is recorded"),
        ] {
            let mut parts = j21_runtime_with_retained_request();
            parts
                .runtime
                .mutation_store
                .fail_nth_save_for_test(failing_write);
            let (outcome, requests) = j22_run(&mut parts, vec![J22Answer::Grant]);
            let Ok(RetainedRenewOutcome::Blocked { reason }) = &outcome else {
                panic!("write {failing_write}: {outcome:?}");
            };
            assert!(
                reason.contains("was not sent") && reason.contains(says),
                "write {failing_write}: {reason}"
            );
            assert_eq!(
                requests,
                [J23_FENCE_RECORD, "request observed=7"],
                "write {failing_write}"
            );
            assert_eq!(j22_record(&parts), expected_record, "write {failing_write}");
            j22_assert_no_authority_resource_or_promotion(&parts);
            cleanup_test_path(&parts.path);
        }
    }

    /// J22 (IA-J22-05): ZeroResource cannot be re-proven before the Release (a VIP reappears after
    /// the first observation): the Release is never sent and nothing is recorded; only cleanup
    /// (never an acquire) may act on the resource.
    #[test]
    fn j22_release_not_sent_when_zero_resource_cannot_be_re_proven() {
        let mut parts = j21_runtime_with_retained_request();
        {
            let mut vip = parts.vip.borrow_mut();
            vip.clear();
            vip.push_back(RawVipObservation::Absent);
            vip.extend(std::iter::repeat(RawVipObservation::Present).take(16));
        }
        let (outcome, requests) = j22_run(&mut parts, vec![J22Answer::Grant]);
        let Ok(RetainedRenewOutcome::Blocked { reason }) = &outcome else {
            panic!("{outcome:?}");
        };
        assert!(
            reason.contains("was not sent") && reason.contains("nothing is recorded"),
            "{reason}"
        );
        assert_eq!(requests, [J23_FENCE_RECORD, "request observed=7"]);
        assert_eq!(j22_record(&parts), (false, None));
        j22_assert_no_authority_resource_or_promotion(&parts);
        cleanup_test_path(&parts.path);
    }

    /// J22 (B-1, persistence after the Release): LEASE_RELEASED arrives but its completion cannot be
    /// written; this is NOT reported as released and both records stay.
    #[test]
    fn j22_release_completion_failure_is_not_reported_as_released() {
        let mut parts = j21_runtime_with_retained_request();
        parts.runtime.mutation_store.fail_nth_save_for_test(4);
        let (outcome, requests) = j22_run(&mut parts, vec![J22Answer::Grant, J22Answer::Released]);
        let Ok(RetainedRenewOutcome::Blocked { reason }) = &outcome else {
            panic!("{outcome:?}");
        };
        assert!(reason.contains("is not confirmed"), "{reason}");
        assert_eq!(requests.len(), 3);
        assert_eq!(
            j22_record(&parts),
            (true, Some(crate::node_mutation::MutationKind::LeaseRelease))
        );
        j22_assert_no_authority_resource_or_promotion(&parts);
        cleanup_test_path(&parts.path);
    }

    /// J22 (B-3, O): a retained LeaseRequest and a release obligation cannot coexist: the store
    /// refuses to begin the request next to an obligation, so the resolution never meets it.
    #[test]
    fn j22_retained_request_cannot_coexist_with_a_release_obligation() {
        let mut parts = test_runtime([], [], [], AuthorityMode::Conservative, None);
        parts.runtime.reconcile().unwrap();
        parts
            .runtime
            .mutation_store
            .arm_release_obligation(Term(5), LeaseId::new("lease-o"))
            .unwrap();
        let before = parts.runtime.mutation_store.load_existing().unwrap();
        assert!(matches!(
            parts
                .runtime
                .mutation_store
                .begin_lease_request(Term(7), 100, DurationMs(10_000)),
            Err(NodeMutationError::Invariant(_))
        ));
        assert_eq!(
            parts.runtime.mutation_store.load_existing().unwrap(),
            before
        );
        assert!(!parts.runtime.retained_request_pending().unwrap());
        cleanup_test_path(&parts.path);
    }

    /// J22 (B-3, incident): a retained LeaseRequest next to a fencing incident is left to the
    /// existing fencing path: nothing is sent and nothing changes.
    #[test]
    fn j22_retained_request_next_to_a_fencing_incident_sends_nothing() {
        let mut parts = test_runtime([], [], [], AuthorityMode::Conservative, None);
        parts.runtime.reconcile().unwrap();
        parts
            .runtime
            .mutation_store
            .open_fencing_incident(crate::fencing::IncidentOpening {
                target_node_id: NodeId::new("node-b"),
                anchor_term: Term(41),
                observer_session_id: crate::protocol::SessionId::new("0123456789abcdef"),
                observer_loss_generation: 1,
                backend: crate::fencing::FencingBackend::None,
            })
            .unwrap();
        parts
            .runtime
            .mutation_store
            .begin_lease_request(Term(7), 100, DurationMs(10_000))
            .unwrap();
        let before = parts.runtime.mutation_store.load_existing().unwrap();
        let (outcome, requests) = j22_run(&mut parts, vec![J22Answer::Grant]);
        assert!(
            matches!(&outcome, Ok(RetainedRenewOutcome::Blocked { reason }) if reason.contains("coexists")),
            "{outcome:?}"
        );
        assert!(requests.is_empty(), "{requests:?}");
        assert_eq!(
            parts.runtime.mutation_store.load_existing().unwrap(),
            before
        );
        j22_assert_no_authority_resource_or_promotion(&parts);
        cleanup_test_path(&parts.path);
    }

    /// J22 (B-3, UNKNOWN): the Witness closes the connection without an answer (as it does for an
    /// UNKNOWN lease); the retained request stays and the node stays blocked.
    #[test]
    fn j22_unknown_answer_keeps_the_retained_request() {
        let mut parts = j21_runtime_with_retained_request();
        let (outcome, requests) = j22_run(&mut parts, vec![J22Answer::Close]);
        assert!(
            matches!(&outcome, Ok(RetainedRenewOutcome::Blocked { .. })),
            "{outcome:?}"
        );
        assert_eq!(requests, [J23_FENCE_RECORD, "request observed=7"]);
        assert_eq!(
            j22_record(&parts),
            (
                false,
                Some(crate::node_mutation::MutationKind::LeaseRequest)
            )
        );
        assert!(parts.runtime.reconcile().unwrap().unresolved_mutation);
        j22_assert_no_authority_resource_or_promotion(&parts);
        cleanup_test_path(&parts.path);
    }

    /// J22 (B-3, retained request corrupt): an unreadable node record proves nothing: the check and
    /// the resolution fail closed and nothing is sent.
    #[test]
    fn j22_corrupt_retained_request_record_fails_closed() {
        let mut parts = j21_runtime_with_retained_request();
        let store_path = parts.runtime.mutation_store.path_for_test();
        std::fs::write(&store_path, b"not a node mutation record").unwrap();
        assert!(parts.runtime.retained_request_pending().is_err());
        let (outcome, requests) = j22_run(&mut parts, vec![J22Answer::Grant]);
        assert!(outcome.is_err(), "{outcome:?}");
        assert!(requests.is_empty(), "{requests:?}");
        j22_assert_no_authority_resource_or_promotion(&parts);
        cleanup_test_path(&parts.path);
    }

    // ---- J23 (OD-J22-1, C-F): the generation fence against the REAL Witness authority --------

    #[derive(Clone, Copy)]
    struct J23Boot;
    impl crate::witness_state::BootIdProvider for J23Boot {
        fn current_boot_id(
            &self,
        ) -> Result<crate::witness_state::BootId, crate::witness_state::WitnessStateError> {
            Ok(crate::witness_state::BootId::new("boot-a"))
        }
    }

    #[derive(Clone, Copy)]
    struct J23Clock(u64);
    impl crate::witness_state::MonotonicClock for J23Clock {
        fn now_ms(&self) -> Result<u64, crate::witness_state::WitnessStateError> {
            Ok(self.0)
        }
    }

    type J23Store = crate::witness_state::WitnessStateStore<J23Boot, J23Clock>;

    fn j23_store(file: &std::path::Path, now: u64) -> J23Store {
        crate::witness_state::WitnessStateStore::with_providers(
            file,
            ClusterId::new("cluster"),
            J23Boot,
            J23Clock(now),
        )
    }

    fn j23_empty_witness() -> crate::witness_state::WitnessPersistentState {
        crate::witness_state::WitnessPersistentState::new(
            ClusterId::new("cluster"),
            crate::witness_state::BootId::new("boot-a"),
        )
    }

    fn j23_witness_file(
        name: &str,
        state: crate::witness_state::WitnessPersistentState,
    ) -> PathBuf {
        let file = std::env::temp_dir().join(format!(
            "mikagami-j23-witness-{name}-{}",
            std::process::id()
        ));
        j23_store(&file, 2_000).save(&state).unwrap();
        file
    }

    fn j23_witness_state(file: &std::path::Path) -> crate::witness_state::WitnessPersistentState {
        j23_store(file, 2_000).load().state.unwrap()
    }

    /// The authority part of a Witness state.
    fn j23_authority(
        state: &crate::witness_state::WitnessPersistentState,
    ) -> (
        Term,
        Option<LeaseId>,
        Option<NodeId>,
        Option<DurationMs>,
        Option<u64>,
        String,
    ) {
        (
            state.current_term,
            state.active_lease_id.clone(),
            state.holder_node_id.clone(),
            state.lease_ttl_ms,
            state.lease_deadline_monotonic_ms,
            format!("{:?}", state.lease_state),
        )
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum J23Step {
        /// Run the real Witness authority and send its answer.
        Answer,
        /// Run the real Witness authority (it commits), then close without the answer.
        CommitThenClose,
    }

    /// J23: a loopback Witness that runs the REAL Witness authority (`handle_*_authority`, the same
    /// calls as `witness_server::serve_connection`) over a state file, one step per request, and
    /// records each request. An authority error closes the connection without an answer (WS-5).
    fn j23_real_witness(
        file: PathBuf,
        now: u64,
        steps: Vec<J23Step>,
    ) -> (
        WitnessSession,
        std::sync::mpsc::Receiver<String>,
        std::thread::JoinHandle<()>,
    ) {
        use crate::security::{MessageAuthenticator, Psk};
        use crate::session::ProcessSession;
        use crate::tcp::TcpConnection;
        use crate::witness_runtime::WitnessConnection;
        use std::net::{TcpListener, TcpStream};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let (sender, requests) = std::sync::mpsc::channel();
        let join = std::thread::spawn(move || {
            use crate::witness_authority::{
                handle_lease_release_authority, handle_lease_renew_authority,
                handle_lease_request_authority, send_prepared_lease_response,
            };
            let auth = MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32]));
            let mut witness = WitnessConnection::new(
                NodeId::new("witness"),
                NodeId::new("node-a"),
                ClusterId::new("cluster"),
                SessionId::new("session-a"),
                TcpConnection::from_stream(server, Duration::from_secs(5), Duration::from_secs(5))
                    .unwrap(),
            );
            let mut process = ProcessSession::from_session_id(SessionId::new("session-w"));
            let store = j23_store(&file, now);
            for step in steps {
                let Ok(pending) = witness.receive_pending(&CborSerializer, &auth) else {
                    return;
                };
                let id = pending
                    .message()
                    .unsigned()
                    .common
                    .request_id
                    .clone()
                    .map(|id| id.as_str().to_string())
                    .unwrap_or_default();
                let prepared = match &pending.message().unsigned().message {
                    ProtocolMessage::LeaseRequest(payload) => {
                        let _ = sender.send(format!(
                            "request gen={} observed={} id={id}",
                            payload.mutation_generation, payload.observed_term.0
                        ));
                        handle_lease_request_authority(&mut witness, &pending, &store)
                    }
                    ProtocolMessage::LeaseRelease(payload) => {
                        let _ = sender.send(format!(
                            "release gen={} term={} lease={} id={id}",
                            payload.mutation_generation,
                            payload.term.0,
                            payload.lease_id.as_str()
                        ));
                        handle_lease_release_authority(&mut witness, &pending, &store)
                    }
                    ProtocolMessage::LeaseRenew(_) => {
                        let _ = sender.send("renew".to_string());
                        handle_lease_renew_authority(&mut witness, &pending, &store)
                    }
                    other => {
                        let _ = sender.send(format!("unexpected {other:?}"));
                        return;
                    }
                };
                match prepared {
                    Ok(prepared) => {
                        if step == J23Step::CommitThenClose {
                            let _ = sender.send("answer dropped".to_string());
                            return;
                        }
                        let _ = send_prepared_lease_response(
                            &mut witness,
                            &mut process,
                            prepared,
                            &CborSerializer,
                            &auth,
                        );
                    }
                    Err(error) => {
                        let _ = sender.send(format!("authority error {error:?}"));
                        return;
                    }
                }
            }
        });
        let node = crate::witness_runtime::WitnessConnection::new(
            NodeId::new("node-a"),
            NodeId::new("witness"),
            ClusterId::new("cluster"),
            SessionId::new("session-w"),
            TcpConnection::from_stream(client, Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
        );
        let session = WitnessSession::new(
            node,
            ProcessSession::from_session_id(SessionId::new("session-a")),
            MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32])),
        );
        (session, requests, join)
    }

    fn j23_run(
        parts: &mut TestRuntimeParts,
        file: &std::path::Path,
        now: u64,
        steps: Vec<J23Step>,
    ) -> (
        Result<RetainedRenewOutcome, LinuxNodeRuntimeError>,
        Vec<String>,
    ) {
        let (mut session, requests, join) = j23_real_witness(file.to_path_buf(), now, steps);
        let outcome = parts.runtime.resolve_retained_request_once(&mut session);
        drop(session);
        join.join().unwrap();
        (outcome, requests.try_iter().collect())
    }

    /// J23: a node with one retained LeaseRequest observed at `observed` (generation 1).
    fn j23_node(observed: u64) -> TestRuntimeParts {
        let mut parts = test_runtime([], [], [], AuthorityMode::Conservative, None);
        parts.runtime.reconcile().unwrap();
        parts
            .runtime
            .mutation_store
            .begin_lease_request(Term(observed), 100, DurationMs(10_000))
            .unwrap();
        parts
    }

    fn j23_retained(parts: &TestRuntimeParts) -> crate::node_mutation::OutstandingWitnessMutation {
        parts
            .runtime
            .mutation_store
            .load_existing()
            .unwrap()
            .outstanding_mutation
            .expect("a retained request")
    }

    /// J23: deliver `request` (the node's durable LeaseRequest) to the Witness directly, as the
    /// original connection's late frame would arrive.
    fn j23_deliver(
        file: &std::path::Path,
        now: u64,
        request: &crate::node_mutation::OutstandingWitnessMutation,
    ) -> ProtocolMessage {
        let message = request.to_protocol_message();
        let ProtocolMessage::LeaseRequest(payload) = message.clone() else {
            panic!("not a LeaseRequest");
        };
        let envelope = crate::protocol::UnsignedEnvelope {
            common: crate::protocol::CommonFields {
                protocol_version: crate::protocol::PROTOCOL_VERSION,
                cluster_id: ClusterId::new("cluster"),
                sender_node_id: NodeId::new("node-a"),
                receiver_node_id: NodeId::new("witness"),
                session_id: SessionId::new("session-a"),
                sequence: crate::protocol::Sequence(1),
                term: Term(0),
                lease_id: None,
                request_id: Some(request.request_id.clone()),
                operation_id: None,
            },
            message,
        };
        let observation = crate::witness_runtime::WitnessRequestObservation::LeaseRequest {
            request_id: request.request_id.clone(),
            sender_node_id: NodeId::new("node-a"),
            term: Term(0),
            lease_id: None,
            payload,
        };
        crate::witness_authority::prepare_lease_request_authority(
            &j23_store(file, now),
            &observation,
            &envelope,
        )
        .unwrap()
        .message
    }

    /// J23: replay `fence` to the Witness directly (a second attempt of the same fence).
    fn j23_replay_fence(
        file: &std::path::Path,
        now: u64,
        fence: &crate::node_mutation::OutstandingWitnessMutation,
    ) -> ProtocolMessage {
        let message = fence.to_protocol_message();
        let ProtocolMessage::LeaseRelease(payload) = message.clone() else {
            panic!("not a LeaseRelease");
        };
        let envelope = crate::protocol::UnsignedEnvelope {
            common: crate::protocol::CommonFields {
                protocol_version: crate::protocol::PROTOCOL_VERSION,
                cluster_id: ClusterId::new("cluster"),
                sender_node_id: NodeId::new("node-a"),
                receiver_node_id: NodeId::new("witness"),
                session_id: SessionId::new("session-a"),
                sequence: crate::protocol::Sequence(1),
                term: Term(0),
                lease_id: None,
                request_id: Some(fence.request_id.clone()),
                operation_id: None,
            },
            message,
        };
        let observation = crate::witness_runtime::WitnessRequestObservation::LeaseRelease {
            request_id: fence.request_id.clone(),
            sender_node_id: NodeId::new("node-a"),
            term: Term(0),
            lease_id: None,
            payload,
        };
        crate::witness_authority::prepare_lease_release_authority(
            &j23_store(file, now),
            &observation,
            &envelope,
        )
        .unwrap()
        .message
    }

    fn j23_reject_code(
        message: &ProtocolMessage,
    ) -> Option<crate::protocol::WitnessMutationOutcomeCode> {
        match message {
            ProtocolMessage::LeaseReject(payload) => Some(payload.code),
            _ => None,
        }
    }

    /// J24 (N-3): the effect of the fence send path, observed rather than read from the source:
    /// whatever the Witness does with the fence (commits it, finds the generation used, or commits
    /// it and loses the answer), `exchange_generation_fence_once` leaves the node store untouched -
    /// the same bytes, the same inode, the same modification time and no new file next to it. This
    /// also covers calls the lexical guards cannot follow (trait objects, function pointers).
    #[test]
    fn j24_fence_exchange_writes_no_byte_of_the_node_store() {
        use std::os::unix::fs::MetadataExt;
        fn snapshot(path: &std::path::Path) -> (Vec<u8>, u64, i64, i64, Vec<String>) {
            let meta = std::fs::metadata(path).unwrap();
            let stem = path.file_name().unwrap().to_string_lossy().into_owned();
            let mut siblings: Vec<String> = std::fs::read_dir(path.parent().unwrap())
                .unwrap()
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .filter(|name| name.starts_with(&stem))
                .collect();
            siblings.sort();
            (
                std::fs::read(path).unwrap(),
                meta.ino(),
                meta.mtime(),
                meta.mtime_nsec(),
                siblings,
            )
        }
        for (name, deliver_first, step) in [
            ("committed", false, J23Step::Answer),
            ("retired", true, J23Step::Answer),
            ("lost-answer", false, J23Step::CommitThenClose),
        ] {
            let parts = j23_node(0);
            let retained = j23_retained(&parts);
            let file = j23_witness_file(&format!("j24-{name}"), j23_empty_witness());
            if deliver_first {
                assert!(matches!(
                    j23_deliver(&file, 2_000, &retained),
                    ProtocolMessage::LeaseGrant(_)
                ));
            }
            let fence = generation_fence_of(&retained).unwrap();
            let before = snapshot(&parts.path);
            let (mut session, requests, join) = j23_real_witness(file.clone(), 2_500, vec![step]);
            let runtime = NodeWitnessMutationRuntime::new(
                &parts.runtime.mutation_store,
                parts.runtime.node_id.clone(),
            );
            let answer = runtime.exchange_generation_fence_once(&mut session, &fence);
            drop(session);
            join.join().unwrap();
            match name {
                "committed" => assert!(
                    matches!(
                        answer,
                        Ok(NodeWitnessMutationResult::DeterministicReject { .. })
                    ),
                    "{name}: {answer:?}"
                ),
                "retired" => assert!(
                    matches!(answer, Ok(NodeWitnessMutationResult::RetiredStale { .. })),
                    "{name}: {answer:?}"
                ),
                _ => assert!(answer.is_err(), "{name}: {answer:?}"),
            }
            let sent: Vec<String> = requests.try_iter().collect();
            assert_eq!(
                sent.first().map(String::as_str),
                Some(
                    format!(
                        "release gen=1 term=0 lease={GENERATION_FENCE_LEASE_ID} id={}",
                        fence.request_id.as_str()
                    )
                    .as_str()
                ),
                "{name}: {sent:?}"
            );
            assert_eq!(
                snapshot(&parts.path),
                before,
                "{name}: the fence path wrote the node store"
            );
            let _ = std::fs::remove_file(&file);
            cleanup_test_path(&parts.path);
        }
    }

    /// J23: the fence is deterministic, distinct from the request, a canonical request id, and it
    /// can never match a lease (term 0, a lease id that is not UUID-shaped).
    #[test]
    fn j23_generation_fence_is_deterministic_and_never_a_lease() {
        let parts = j23_node(0);
        let request = j23_retained(&parts);
        let fence = generation_fence_of(&request).unwrap();
        assert_eq!(
            fence,
            generation_fence_of(&request).unwrap(),
            "identical after a restart"
        );
        assert_ne!(fence.request_id, request.request_id);
        assert!(crate::protocol::is_valid_mutating_request_id(
            fence.request_id.as_str()
        ));
        assert_eq!(fence.mutation_generation, request.mutation_generation);
        assert_eq!(
            fence.mutation,
            crate::node_mutation::DurableWitnessMutation::LeaseRelease {
                term: Term(0),
                lease_id: LeaseId::new(GENERATION_FENCE_LEASE_ID),
                reason: GENERATION_FENCE_REASON.to_string(),
            }
        );
        assert!(!crate::protocol::is_valid_mutating_request_id(
            GENERATION_FENCE_LEASE_ID
        ));
        let other = j23_node(0);
        assert_ne!(
            generation_fence_of(&j23_retained(&other))
                .unwrap()
                .request_id,
            fence.request_id,
            "another request has another fence"
        );
        let mut renew = request.clone();
        renew.mutation = crate::node_mutation::DurableWitnessMutation::LeaseRenew {
            term: Term(1),
            lease_id: LeaseId::new("lease-r"),
        };
        assert!(generation_fence_of(&renew).is_err());
        cleanup_test_path(&parts.path);
        cleanup_test_path(&other.path);
    }

    /// J23 B-1 / B-3 (the fence first): the original request never reached the Witness. The fence
    /// fills the generation: no grant, no term change, Standby; the late original never commits.
    #[test]
    fn j23_fence_settles_an_undelivered_request_without_any_grant() {
        let mut parts = j23_node(0);
        let request = j23_retained(&parts);
        let fence = generation_fence_of(&request).unwrap();
        let file = j23_witness_file("b1", j23_empty_witness());
        let before = j23_witness_state(&file);
        let (outcome, requests) = j23_run(&mut parts, &file, 2_000, vec![J23Step::Answer]);
        assert!(
            matches!(&outcome, Ok(RetainedRenewOutcome::Resolved { how }) if *how == RETAINED_REQUEST_FENCED),
            "{outcome:?}"
        );
        assert_eq!(
            requests,
            [format!(
                "release gen=1 term=0 lease={GENERATION_FENCE_LEASE_ID} id={}",
                fence.request_id.as_str()
            )]
        );
        let after = j23_witness_state(&file);
        assert_eq!(
            j23_authority(&after),
            j23_authority(&before),
            "no grant, no term change"
        );
        assert_eq!(after.generation_watermarks.get("node-a"), Some(&1));
        assert_eq!(j22_record(&parts), (false, None), "the request is settled");
        j22_assert_no_authority_resource_or_promotion(&parts);
        assert!(parts.runtime.reconcile().unwrap().recovery_reconciled);
        // The original arrives late: it can no longer commit.
        assert_eq!(
            j23_reject_code(&j23_deliver(&file, 3_000, &request)),
            Some(crate::protocol::WitnessMutationOutcomeCode::RetiredStale)
        );
        assert_eq!(
            j23_witness_state(&file),
            after,
            "the late original commits nothing"
        );
        let _ = std::fs::remove_file(&file);
        cleanup_test_path(&parts.path);
    }

    /// J23 B-2 / B-3 (the request first): the original request was committed (a grant). The fence
    /// does not override it (retired-stale, nothing committed); the exact replay reconstructs the
    /// grant, which is never used and is released; Standby.
    #[test]
    fn j23_fence_after_a_committed_request_replays_and_releases_the_unused_grant() {
        let mut parts = j23_node(0);
        let request = j23_retained(&parts);
        let file = j23_witness_file("b2", j23_empty_witness());
        assert!(matches!(
            j23_deliver(&file, 2_000, &request),
            ProtocolMessage::LeaseGrant(_)
        ));
        let committed = j23_witness_state(&file);
        assert_eq!(committed.current_term, Term(1));
        let (outcome, requests) = j23_run(
            &mut parts,
            &file,
            2_500,
            vec![J23Step::Answer, J23Step::Answer, J23Step::Answer],
        );
        assert!(
            matches!(&outcome, Ok(RetainedRenewOutcome::Resolved { how }) if *how == UNUSED_GRANT_RELEASED),
            "{outcome:?}"
        );
        assert_eq!(requests.len(), 3, "{requests:?}");
        assert!(
            requests[0].starts_with("release gen=1 term=0"),
            "{requests:?}"
        );
        assert!(requests[1].starts_with("request gen=1"), "{requests:?}");
        assert!(
            requests[2].starts_with("release gen=2 term=1"),
            "{requests:?}"
        );
        let after = j23_witness_state(&file);
        assert_eq!(after.current_term, Term(1), "no further grant");
        assert_eq!(after.holder_node_id, None, "the unused grant is released");
        assert_eq!(j22_record(&parts), (false, None));
        j22_assert_no_authority_resource_or_promotion(&parts);
        let _ = std::fs::remove_file(&file);
        cleanup_test_path(&parts.path);
    }

    /// J23 B-4 / B-5: the fence commits but its answer is lost; the node stays blocked. After the
    /// restart (and a restart of the Witness: a new store from the same file), the identical fence
    /// is a duplicate: the request is settled, and the Witness state does not change.
    #[test]
    fn j23_lost_fence_answer_is_settled_by_the_identical_fence_after_restarts() {
        let mut parts = j23_node(0);
        let request = j23_retained(&parts);
        let fence = generation_fence_of(&request).unwrap();
        let file = j23_witness_file("b4", j23_empty_witness());
        let (first, first_requests) =
            j23_run(&mut parts, &file, 2_000, vec![J23Step::CommitThenClose]);
        assert!(
            matches!(&first, Ok(RetainedRenewOutcome::Blocked { reason }) if reason.contains("generation fence")),
            "{first:?}"
        );
        assert_eq!(
            first_requests.last().map(String::as_str),
            Some("answer dropped")
        );
        assert_eq!(
            j22_record(&parts),
            (
                false,
                Some(crate::node_mutation::MutationKind::LeaseRequest)
            ),
            "nothing is proven: the request stays"
        );
        let committed = j23_witness_state(&file);
        assert_eq!(committed.generation_watermarks.get("node-a"), Some(&1));
        // The node restarts: the same fence is derived again.
        assert_eq!(generation_fence_of(&j23_retained(&parts)).unwrap(), fence);
        let (second, second_requests) = j23_run(&mut parts, &file, 60_000, vec![J23Step::Answer]);
        assert!(
            matches!(&second, Ok(RetainedRenewOutcome::Resolved { how }) if *how == RETAINED_REQUEST_FENCED),
            "{second:?}"
        );
        assert_eq!(second_requests[0], first_requests[0], "the identical fence");
        assert_eq!(
            j23_witness_state(&file),
            committed,
            "a duplicate commits nothing"
        );
        // A further replay after another Witness restart is still the same duplicate answer.
        assert_eq!(
            j23_reject_code(&j23_replay_fence(&file, 90_000, &fence)),
            Some(crate::protocol::WitnessMutationOutcomeCode::PolicyReject)
        );
        assert_eq!(j23_witness_state(&file), committed);
        j22_assert_no_authority_resource_or_promotion(&parts);
        let _ = std::fs::remove_file(&file);
        cleanup_test_path(&parts.path);
    }

    /// J23 B-6: node-b holds a regular lease; node-a's fence leaves that lease, its term, deadline
    /// and node-b's watermark untouched.
    #[test]
    fn j23_fence_never_touches_another_holders_lease() {
        let mut parts = j23_node(5);
        let mut state = j23_empty_witness();
        state.current_term = Term(5);
        state.active_lease_id = Some(LeaseId::new("00000000-0000-4000-8000-0000000000b5"));
        state.holder_node_id = Some(NodeId::new("node-b"));
        state.lease_ttl_ms = Some(DurationMs(10_000));
        state.lease_deadline_monotonic_ms = Some(9_000);
        state.lease_state = crate::witness_state::LeaseState::Active;
        state.generation_watermarks.insert("node-b".to_string(), 7);
        let file = j23_witness_file("b6", state);
        let before = j23_witness_state(&file);
        let (outcome, _) = j23_run(&mut parts, &file, 2_000, vec![J23Step::Answer]);
        assert!(
            matches!(&outcome, Ok(RetainedRenewOutcome::Resolved { how }) if *how == RETAINED_REQUEST_FENCED),
            "{outcome:?}"
        );
        let after = j23_witness_state(&file);
        assert_eq!(
            j23_authority(&after),
            j23_authority(&before),
            "node-b's lease is unchanged"
        );
        assert_eq!(after.generation_watermarks.get("node-b"), Some(&7));
        assert_eq!(after.generation_watermarks.get("node-a"), Some(&1));
        j22_assert_no_authority_resource_or_promotion(&parts);
        let _ = std::fs::remove_file(&file);
        cleanup_test_path(&parts.path);
    }

    /// J23 B-7: anomalies that are not a normal change fail closed: the request stays, nothing is
    /// granted, the Witness state does not change.
    #[test]
    fn j23_fence_anomalies_fail_closed() {
        // (a) generation gap / Witness rolled back behind the node: the request is generation 2,
        // the Witness has seen nothing from node-a.
        let mut parts = test_runtime([], [], [], AuthorityMode::Conservative, None);
        parts.runtime.reconcile().unwrap();
        let first = parts
            .runtime
            .mutation_store
            .begin_lease_request(Term(0), 100, DurationMs(10_000))
            .unwrap();
        parts
            .runtime
            .mutation_store
            .complete(
                &first.request_id,
                first.mutation_generation,
                crate::node_mutation::MutationKind::LeaseRequest,
                crate::node_mutation::TerminalMutationDisposition::RetiredStale,
            )
            .unwrap();
        parts
            .runtime
            .mutation_store
            .begin_lease_request(Term(0), 100, DurationMs(10_000))
            .unwrap();
        let file = j23_witness_file("b7-gap", j23_empty_witness());
        let before = j23_witness_state(&file);
        let (outcome, _) = j23_run(&mut parts, &file, 2_000, vec![J23Step::Answer]);
        assert!(
            matches!(&outcome, Ok(RetainedRenewOutcome::Blocked { reason }) if reason.contains("generation gap")),
            "gap: {outcome:?}"
        );
        assert_eq!(j23_witness_state(&file), before, "gap: nothing committed");
        assert_eq!(
            j22_record(&parts),
            (
                false,
                Some(crate::node_mutation::MutationKind::LeaseRequest)
            )
        );
        let _ = std::fs::remove_file(&file);
        cleanup_test_path(&parts.path);

        // (b) request id collision / payload mismatch: the fence's id is already committed with
        // another payload.
        let mut parts = j23_node(0);
        let fence = generation_fence_of(&j23_retained(&parts)).unwrap();
        let file = j23_witness_file("b7-conflict", j23_empty_witness());
        let mut tampered = fence.clone();
        tampered.mutation = crate::node_mutation::DurableWitnessMutation::LeaseRelease {
            term: Term(0),
            lease_id: LeaseId::new(GENERATION_FENCE_LEASE_ID),
            reason: "another payload under the same request id".to_string(),
        };
        assert_eq!(
            j23_reject_code(&j23_replay_fence(&file, 2_000, &tampered)),
            Some(crate::protocol::WitnessMutationOutcomeCode::PolicyReject)
        );
        let before = j23_witness_state(&file);
        let (outcome, _) = j23_run(&mut parts, &file, 2_000, vec![J23Step::Answer]);
        assert!(
            matches!(&outcome, Ok(RetainedRenewOutcome::Blocked { reason }) if reason.contains("conflict")),
            "conflict: {outcome:?}"
        );
        assert_eq!(
            j23_witness_state(&file),
            before,
            "conflict: nothing committed"
        );
        assert_eq!(
            j22_record(&parts),
            (
                false,
                Some(crate::node_mutation::MutationKind::LeaseRequest)
            )
        );
        let _ = std::fs::remove_file(&file);
        cleanup_test_path(&parts.path);

        // (c) UNKNOWN lease state, (d) a corrupt Witness state: the Witness authority fails and
        // closes without an answer.
        for (name, corrupt) in [("unknown", false), ("corrupt", true)] {
            let mut parts = j23_node(0);
            let mut state = j23_empty_witness();
            state.lease_state = crate::witness_state::LeaseState::Unknown;
            let file = j23_witness_file(&format!("b7-{name}"), state);
            if corrupt {
                std::fs::write(&file, b"not a witness state").unwrap();
            }
            let before = std::fs::read(&file).unwrap();
            let (outcome, requests) = j23_run(&mut parts, &file, 2_000, vec![J23Step::Answer]);
            assert!(
                matches!(&outcome, Ok(RetainedRenewOutcome::Blocked { reason }) if reason.contains("connection failed during the generation fence")),
                "{name}: {outcome:?} {requests:?}"
            );
            assert!(
                requests.iter().any(|r| r.starts_with("authority error")),
                "{name}: the Witness refused without an answer: {requests:?}"
            );
            assert_eq!(
                std::fs::read(&file).unwrap(),
                before,
                "{name}: nothing committed"
            );
            assert_eq!(
                j22_record(&parts),
                (
                    false,
                    Some(crate::node_mutation::MutationKind::LeaseRequest)
                ),
                "{name}"
            );
            j22_assert_no_authority_resource_or_promotion(&parts);
            let _ = std::fs::remove_file(&file);
            cleanup_test_path(&parts.path);
        }
    }

    /// J23: the Witness is ahead of the node (the generation was used, the record is gone): the
    /// fence is retired-stale and the exact replay is retired-stale too; settled without a grant.
    #[test]
    fn j23_witness_ahead_settles_through_the_retired_replay_without_a_grant() {
        let mut parts = j23_node(0);
        let mut state = j23_empty_witness();
        state.generation_watermarks.insert("node-a".to_string(), 5);
        let file = j23_witness_file("ahead", state);
        let before = j23_witness_state(&file);
        let (outcome, requests) = j23_run(
            &mut parts,
            &file,
            2_000,
            vec![J23Step::Answer, J23Step::Answer],
        );
        assert!(
            matches!(&outcome, Ok(RetainedRenewOutcome::Resolved { how }) if how.starts_with("exact replay: retired stale")),
            "{outcome:?}"
        );
        assert_eq!(requests.len(), 2, "{requests:?}");
        assert_eq!(j23_witness_state(&file), before, "nothing committed");
        assert_eq!(j22_record(&parts), (false, None));
        let _ = std::fs::remove_file(&file);
        cleanup_test_path(&parts.path);
    }

    /// J23: a fence answered with anything but a reject proves nothing; an accepted fence (a
    /// LEASE_RELEASED, which the contract excludes) fails closed; the request stays.
    #[test]
    fn j23_fence_answered_with_a_success_or_a_non_terminal_reject_fails_closed() {
        use crate::protocol::WitnessMutationOutcomeCode as C;
        for (name, answer) in [
            (
                "released",
                ProtocolMessage::LeaseReleased(crate::protocol::LeaseReleasedPayload {
                    term: Term(0),
                    lease_id: LeaseId::new(GENERATION_FENCE_LEASE_ID),
                    result: "released".into(),
                }),
            ),
            (
                "temporarily-unavailable",
                ProtocolMessage::LeaseReject(crate::protocol::LeaseRejectPayload {
                    code: C::TemporarilyUnavailable,
                    reason: "j23".into(),
                }),
            ),
        ] {
            let mut parts = j23_node(0);
            let (mut session, join) = j23_scripted_fence(answer);
            let outcome = parts.runtime.resolve_retained_request_once(&mut session);
            drop(session);
            join.join().unwrap();
            match name {
                "released" => assert!(outcome.is_err(), "{name}: {outcome:?}"),
                _ => assert!(
                    matches!(&outcome, Ok(RetainedRenewOutcome::Blocked { .. })),
                    "{name}: {outcome:?}"
                ),
            }
            assert_eq!(
                j22_record(&parts),
                (
                    false,
                    Some(crate::node_mutation::MutationKind::LeaseRequest)
                ),
                "{name}"
            );
            j22_assert_no_authority_resource_or_promotion(&parts);
            cleanup_test_path(&parts.path);
        }
    }

    /// J23: a loopback Witness that answers the first request (the fence) with `answer`.
    fn j23_scripted_fence(
        answer: ProtocolMessage,
    ) -> (WitnessSession, std::thread::JoinHandle<()>) {
        use crate::security::{MessageAuthenticator, Psk};
        use crate::session::ProcessSession;
        use crate::tcp::TcpConnection;
        use crate::witness_runtime::{
            WitnessConnection, WitnessResponseContext, send_witness_response_with_context,
        };
        use std::net::{TcpListener, TcpStream};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let join = std::thread::spawn(move || {
            let auth = MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32]));
            let mut witness = WitnessConnection::new(
                NodeId::new("witness"),
                NodeId::new("node-a"),
                ClusterId::new("cluster"),
                SessionId::new("session-a"),
                TcpConnection::from_stream(server, Duration::from_secs(5), Duration::from_secs(5))
                    .unwrap(),
            );
            let mut process = ProcessSession::from_session_id(SessionId::new("session-w"));
            let Ok(pending) = witness.receive_pending(&CborSerializer, &auth) else {
                return;
            };
            let request_id = pending
                .message()
                .unsigned()
                .common
                .request_id
                .clone()
                .unwrap();
            let _ = send_witness_response_with_context(
                &mut witness,
                &mut process,
                request_id,
                answer,
                WitnessResponseContext {
                    term: Term(0),
                    lease_id: None,
                },
                &CborSerializer,
                &auth,
            );
        });
        let node = WitnessConnection::new(
            NodeId::new("node-a"),
            NodeId::new("witness"),
            ClusterId::new("cluster"),
            SessionId::new("session-w"),
            TcpConnection::from_stream(client, Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
        );
        let session = WitnessSession::new(
            node,
            ProcessSession::from_session_id(SessionId::new("session-a")),
            MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32])),
        );
        (session, join)
    }

    /// J23 (independent audit N-4): the fence's fingerprint inputs are pinned to literal values; a
    /// change would turn a fence committed by an earlier version into a Conflict. The golden id
    /// was computed independently of the implementation (Python hashlib, recorded in J23).
    #[test]
    fn j23_generation_fence_values_are_pinned() {
        assert_eq!(GENERATION_FENCE_LEASE_ID, "mikagami-generation-fence");
        assert_eq!(
            GENERATION_FENCE_REASON,
            "generation fence of a retained lease request (no lease is released)"
        );
        assert_eq!(
            crate::node_lease_authority::node_witness_runtime::generation_fence_request_id(
                &crate::protocol::RequestId::new("00000000-0000-4000-8000-000000000001"),
                1,
            ),
            "b8967e09-7fc4-4c5b-9129-0bd5fdb8d80e"
        );
    }

    /// J23 (independent audit N-5): the fence commits, but the completion of the retained request
    /// fails to persist: the resolution fails, the request stays, nothing is granted; the next
    /// attempt sends the identical fence, gets the duplicate PolicyReject and settles it.
    #[test]
    fn j23_failed_completion_after_a_committed_fence_keeps_the_request_and_settles_later() {
        let mut parts = j23_node(0);
        let file = j23_witness_file("complete-fails", j23_empty_witness());
        parts.runtime.mutation_store.fail_nth_save_for_test(1);
        let (first, first_requests) = j23_run(&mut parts, &file, 2_000, vec![J23Step::Answer]);
        assert!(first.is_err(), "{first:?}");
        assert_eq!(
            j22_record(&parts),
            (
                false,
                Some(crate::node_mutation::MutationKind::LeaseRequest)
            ),
            "the failed completion keeps the request"
        );
        let committed = j23_witness_state(&file);
        assert_eq!(committed.generation_watermarks.get("node-a"), Some(&1));
        assert_eq!(committed.current_term, Term(0), "no grant");
        let (second, second_requests) = j23_run(&mut parts, &file, 3_000, vec![J23Step::Answer]);
        assert!(
            matches!(&second, Ok(RetainedRenewOutcome::Resolved { how }) if *how == RETAINED_REQUEST_FENCED),
            "{second:?}"
        );
        assert_eq!(second_requests, first_requests, "the identical fence");
        assert_eq!(
            j23_witness_state(&file),
            committed,
            "the duplicate commits nothing"
        );
        assert_eq!(j22_record(&parts), (false, None));
        j22_assert_no_authority_resource_or_promotion(&parts);
        let _ = std::fs::remove_file(&file);
        cleanup_test_path(&parts.path);
    }

    fn runtime_with_retained_renew() -> TestRuntimeParts {
        let mut parts = test_runtime([], [], [], AuthorityMode::Conservative, None);
        parts.runtime.reconcile().unwrap();
        parts
            .runtime
            .mutation_store
            .arm_release_obligation(Term(7), LeaseId::new("lease-1"))
            .unwrap();
        parts
            .runtime
            .mutation_store
            .begin_lease_renew(Term(7), LeaseId::new("lease-1"))
            .unwrap();
        assert!(parts.runtime.retained_renew_pending().unwrap());
        parts
    }

    /// An accepted exact replay clears the record and installs no authority.
    #[test]
    fn retained_renew_is_replayed_once_and_cleared() {
        let mut parts = runtime_with_retained_renew();
        let (mut session, requests, join) = renew_fixture(RenewScript::Renewed);
        assert!(matches!(
            parts
                .runtime
                .resolve_retained_renew_once(&mut session)
                .unwrap(),
            RetainedRenewOutcome::Resolved { .. }
        ));
        join.join().unwrap();
        assert_eq!(requests.try_iter().collect::<Vec<_>>().len(), 1);
        assert!(!parts.runtime.retained_renew_pending().unwrap());
        assert!(
            parts.runtime.controller.authority().authority().is_none(),
            "startup resolution must never install authority"
        );
        // The runtime is a plain Standby again.
        let snapshot = parts.runtime.reconcile().unwrap();
        assert!(snapshot.recovery_reconciled);
        cleanup_test_path(&parts.path);
    }

    /// A retired-stale reject is terminal: the record clears without any
    /// promotion and the node can recover.
    #[test]
    fn retired_stale_retained_renew_is_cleared() {
        let mut parts = runtime_with_retained_renew();
        let (mut session, requests, join) = renew_fixture(RenewScript::RetiredStale);
        assert!(matches!(
            parts
                .runtime
                .resolve_retained_renew_once(&mut session)
                .unwrap(),
            RetainedRenewOutcome::Resolved { .. }
        ));
        join.join().unwrap();
        assert_eq!(requests.try_iter().count(), 1);
        assert!(!parts.runtime.retained_renew_pending().unwrap());
        assert!(parts.runtime.reconcile().unwrap().recovery_reconciled);
        cleanup_test_path(&parts.path);
    }

    /// A Witness that closes without answering proves nothing: the record is
    /// retained and the caller must stay recovery-blocked.
    #[test]
    fn unanswered_retained_renew_stays_and_blocks_recovery() {
        let mut parts = runtime_with_retained_renew();
        let (mut session, requests, join) = renew_fixture(RenewScript::CloseWithoutAnswer);
        assert!(matches!(
            parts
                .runtime
                .resolve_retained_renew_once(&mut session)
                .unwrap(),
            RetainedRenewOutcome::Blocked { .. }
        ));
        join.join().unwrap();
        assert_eq!(requests.try_iter().count(), 1);
        assert!(parts.runtime.retained_renew_pending().unwrap());
        // The record (and the obligation) stay; the caller is responsible for
        // staying recovery-blocked. `recovery_reconciled` was already true
        // before the crash and is not cleared here.
        let snapshot = parts.runtime.reconcile().unwrap();
        assert!(snapshot.unresolved_mutation);
        cleanup_test_path(&parts.path);
    }

    /// With a resource still observed, nothing is sent at all.
    #[test]
    fn retained_renew_is_not_sent_while_a_resource_is_observed() {
        let mut parts = test_runtime(
            [RawVipObservation::Present],
            [RawServiceObservation::Stopped],
            [],
            AuthorityMode::Conservative,
            None,
        );
        parts
            .runtime
            .mutation_store
            .arm_release_obligation(Term(7), LeaseId::new("lease-1"))
            .unwrap();
        parts
            .runtime
            .mutation_store
            .begin_lease_renew(Term(7), LeaseId::new("lease-1"))
            .unwrap();
        let (mut session, requests, join) = renew_fixture(RenewScript::Renewed);
        assert!(matches!(
            parts
                .runtime
                .resolve_retained_renew_once(&mut session)
                .unwrap(),
            RetainedRenewOutcome::Blocked { .. }
        ));
        drop(session);
        join.join().unwrap();
        assert_eq!(requests.try_iter().count(), 0);
        assert!(parts.runtime.retained_renew_pending().unwrap());
        cleanup_test_path(&parts.path);
    }

    /// The runtime proof must accept a stop only for a reconciled, plain
    /// zero-resource Standby. Anything still owning or observing a resource,
    /// or holding an operation, refuses.
    #[test]
    fn witness_loss_stop_allowed_needs_a_reconciled_zero_resource_standby() {
        let mut parts = test_runtime([], [], [], AuthorityMode::Conservative, None);
        // Recovery is not reconciled yet: no stop.
        assert!(!parts.runtime.witness_loss_stop_allowed());
        parts.runtime.reconcile().unwrap();
        assert!(parts.runtime.witness_loss_stop_allowed());

        // The service is still observed running: no stop.
        let mut parts = test_runtime(
            [],
            [RawServiceObservation::Running],
            [],
            AuthorityMode::Conservative,
            None,
        );
        parts.runtime.reconcile().unwrap();
        assert!(!parts.runtime.witness_loss_stop_allowed());

        // The VIP is still observed present: no stop.
        let mut parts = test_runtime(
            [RawVipObservation::Present],
            [],
            [],
            AuthorityMode::Conservative,
            None,
        );
        parts.runtime.reconcile().unwrap();
        assert!(!parts.runtime.witness_loss_stop_allowed());

        // An unavailable observation is uncertainty, never absence.
        let mut parts = test_runtime(
            [RawVipObservation::Unavailable],
            [RawServiceObservation::Unavailable],
            [],
            AuthorityMode::Conservative,
            None,
        );
        parts.runtime.reconcile().unwrap();
        assert!(!parts.runtime.witness_loss_stop_allowed());
    }

    // ---- Startup Obligation Reconciliation (contract A-4, SOR-1..SOR-5) ----

    use crate::evidence_fusion::adapter::AuthorityViewCompatibility as SorCompat;

    fn sor_runtime(name_hint: &str) -> TestRuntimeParts {
        let _ = name_hint;
        let mut parts = test_runtime([], [], [], AuthorityMode::Conservative, None);
        // A crash left O = (7, lease-1) behind.
        parts
            .runtime
            .mutation_store
            .arm_release_obligation(Term(7), LeaseId::new("lease-1"))
            .unwrap();
        let snapshot = parts.runtime.reconcile().unwrap();
        assert!(
            !snapshot.recovery_reconciled,
            "O blocks the plain reconcile"
        );
        assert_eq!(snapshot.node_state, NodeState::RecoveryPending);
        parts
    }

    fn sor_assert_standby(parts: &mut TestRuntimeParts) {
        let snapshot = parts.runtime.reconcile().unwrap();
        assert!(snapshot.recovery_reconciled);
        assert_eq!(snapshot.node_state, NodeState::Standby);
        assert!(
            !snapshot.authority_present,
            "SOR installs no authority (SOR-5)"
        );
        assert!(
            parts
                .runtime
                .mutation_store
                .release_obligation()
                .unwrap()
                .is_none()
        );
    }

    fn sor_o_present(parts: &TestRuntimeParts) -> bool {
        parts
            .runtime
            .mutation_store
            .release_obligation()
            .unwrap()
            .is_some()
    }

    /// SOR-2 (ii)/(iii): a newer Witness term, or the same term without a
    /// holder, clears O after trusted ZeroResource and leaves a plain Standby.
    #[test]
    fn sor_clears_a_superseded_obligation_and_returns_to_standby() {
        for (term, compat, by) in [
            (
                Term(9),
                SorCompat::ConflictingHolder,
                crate::obligation_reconciliation::SupersededBy::NewerTerm,
            ),
            (
                Term(8),
                SorCompat::InconsistentAuthorityView,
                crate::obligation_reconciliation::SupersededBy::NewerTerm,
            ),
            (
                Term(7),
                SorCompat::CompatibleNoHolder,
                crate::obligation_reconciliation::SupersededBy::SameTermNoHolder,
            ),
        ] {
            let mut parts = sor_runtime("clear");
            let (mut session, _witness) = stage14_10_witness(Term(8));
            let outcome = parts
                .runtime
                .reconcile_startup_obligation(&mut session, Some((term, compat)))
                .unwrap();
            assert_eq!(outcome, SorOutcome::Cleared { term: Term(7), by });
            sor_assert_standby(&mut parts);
            cleanup_test_path(&parts.path);
        }
    }

    /// SOR-2 (i): the Witness still holds the exact lease: the existing exact
    /// `LeaseRelease` runs, O is gone, the node is an ordinary Standby.
    #[test]
    fn sor_exact_release_when_the_witness_still_holds_the_lease() {
        let mut parts = sor_runtime("exact");
        let (mut session, witness) = stage14_10_witness(Term(8));
        let outcome = parts
            .runtime
            .reconcile_startup_obligation(
                &mut session,
                Some((Term(7), SorCompat::CompatibleSelfUnexpired)),
            )
            .unwrap();
        assert_eq!(outcome, SorOutcome::Released { term: Term(7) });
        let seen: Vec<_> = witness.requests.try_iter().collect();
        assert_eq!(seen, [("release", Term(7))]);
        sor_assert_standby(&mut parts);
        cleanup_test_path(&parts.path);
    }

    /// The recovery-gate cause names the obstacle.
    #[test]
    fn recovery_block_cause_names_the_obstacle() {
        let mut parts = sor_runtime("cause");
        let cause = parts.runtime.recovery_block_cause().unwrap();
        assert!(cause.contains("release obligation (term 7)"), "{cause}");
        cleanup_test_path(&parts.path);
    }

    // ---- Stage 14 Phase 14.11 L1-MEM: the Active renew floor ---------------
    //
    // `active_wait_delay` / `ACTIVE_RENEW_MIN_WAIT` bound the foreground tick
    // rate (and through it the ListenerInterference window). The renew term
    // alone is floored; `expiry_in` and the outstanding-LeaseRenew branch are
    // not. Addendum: MIKAGAMI_STAGE_14_PHASE_14_11_L1_MEM_SCHEDULER_ADDENDUM.md.

    fn ms(value: u64) -> Duration {
        Duration::from_millis(value)
    }

    /// The explicit table. Columns: ordinary, renew_in, expiry_in, outstanding
    /// LeaseRenew, expected wait (all ms).
    #[test]
    fn stage14_11_l1_active_wait_delay_table() {
        const FAR: u64 = 1_000_000;
        let table: &[(u64, u64, u64, bool, u64)] = &[
            // renew term floored to 100 ms
            (1_000, 0, FAR, false, 100),
            (1_000, 1, FAR, false, 100),
            (1_000, 99, FAR, false, 100),
            (1_000, 100, FAR, false, 100),
            (1_000, 101, FAR, false, 101),
            (1_000, 999, FAR, false, 999),
            (1_000, 1_000, FAR, false, 1_000),
            (1_000, 5_000, FAR, false, 1_000),
            // expiry has priority and is never floored
            (1_000, 0, 1, false, 1),
            (1_000, 0, 99, false, 99),
            (1_000, 0, 100, false, 100),
            (1_000, 0, 101, false, 100),
            (1_000, 1, 1, false, 1),
            (1_000, 500, 50, false, 50),
            (1_000, 0, 0, false, 0),
            // outstanding LeaseRenew: min(ordinary, expiry_in), renew_in unused
            (1_000, 0, FAR, true, 1_000),
            (1_000, 1, FAR, true, 1_000),
            (1_000, 0, 1, true, 1),
            (1_000, 0, 99, true, 99),
            (1_000, 0, 100, true, 100),
            (1_000, 0, 101, true, 101),
            (1_000, 0, 5_000, true, 1_000),
            // the ordinary cadence is a ceiling
            (500, 0, FAR, false, 100),
            (50, 0, FAR, false, 50),
        ];
        for &(ordinary, renew_in, expiry_in, outstanding, expected) in table {
            assert_eq!(
                active_wait_delay(ms(ordinary), ms(renew_in), ms(expiry_in), outstanding),
                ms(expected),
                "ordinary={ordinary} renew_in={renew_in} expiry_in={expiry_in} \
                 outstanding={outstanding}"
            );
        }
        assert_eq!(ACTIVE_RENEW_MIN_WAIT, ms(100));
    }

    /// Closed-form properties over a grid: the wait never exceeds the ordinary
    /// cadence or the expiry, equals the pre-floor wait whenever `renew_in` is
    /// at least the floor, and the floor never touches the other two branches.
    #[test]
    fn stage14_11_l1_active_wait_delay_grid_properties() {
        let values = [
            0u64, 1, 2, 50, 98, 99, 100, 101, 102, 500, 999, 1_000, 1_001, 5_000,
        ];
        for &ordinary in &[1_000u64, 2_000, 5_000] {
            for &renew_in in &values {
                for &expiry_in in &values {
                    let with_floor =
                        active_wait_delay(ms(ordinary), ms(renew_in), ms(expiry_in), false);
                    let before = ordinary.min(renew_in).min(expiry_in);
                    assert!(with_floor <= ms(ordinary));
                    assert!(with_floor <= ms(expiry_in), "never past the expiry");
                    assert!(with_floor >= ms(before), "the floor only lengthens");
                    assert!(
                        with_floor <= ms(before.max(100).min(ordinary).min(expiry_in)),
                        "lengthened by at most the floor"
                    );
                    if renew_in >= 100 || expiry_in <= renew_in {
                        assert_eq!(with_floor, ms(before), "unchanged outside the floor");
                    }
                    assert_eq!(
                        active_wait_delay(ms(ordinary), ms(renew_in), ms(expiry_in), true),
                        ms(ordinary.min(expiry_in)),
                        "the outstanding-Renew branch is unchanged"
                    );
                }
            }
        }
    }

    fn stage14_11_l1_active_parts(clock: &Rc<Cell<u64>>) -> TestRuntimeParts {
        let mut parts = test_runtime(
            [
                RawVipObservation::Absent,
                RawVipObservation::Absent,
                RawVipObservation::Present,
                RawVipObservation::Absent,
                RawVipObservation::Absent,
            ],
            [
                RawServiceObservation::Stopped,
                RawServiceObservation::Stopped,
                RawServiceObservation::Running,
                RawServiceObservation::Stopped,
                RawServiceObservation::Stopped,
            ],
            [RawHealthObservation::Healthy],
            AuthorityMode::Conservative,
            Some(clock.clone()),
        );
        parts.advance_garp_clock.set(false);
        reconcile_zero_resource(&mut parts);
        // renew_due = 3000 ms, safe_deadline = 8000 ms (grant 3000 / 10000).
        install_test_authority(&mut parts.runtime);
        assert_eq!(
            parts.runtime.promote().unwrap(),
            ExplicitOperationResult::Completed
        );
        assert_eq!(parts.runtime.state_machine.node_state(), NodeState::Active);
        assert!(parts.runtime.state_machine.operation_phase().is_none());
        parts
    }

    // --- R-16 / R-17 focused Linux-runtime boundaries ---------------------

    #[test]
    fn r16_zero_resource_cleanup_is_not_started_after_a_loss() {
        // The bounded shutdown join can call `ensure_trusted_zero_resource`,
        // which itself stops the service and releases the VIP. That cleanup is
        // a protected effect too: a denied guard must not reach either syscall.
        let mut parts = test_runtime(
            [RawVipObservation::Present],
            [RawServiceObservation::Running],
            [],
            AuthorityMode::Conservative,
            None,
        );
        let result = parts
            .runtime
            .ensure_trusted_zero_resource_guarded(&|| false);
        assert!(matches!(
            result,
            Err(LinuxNodeRuntimeError::ControlLockLost)
        ));
        assert!(
            parts.actions.borrow().is_empty(),
            "no service stop or VIP release may start: {:?}",
            parts.actions.borrow()
        );
        cleanup_test_path(&parts.path);
    }

    #[test]
    fn r16_shutdown_cleanup_stops_after_service_stop_when_the_lock_is_lost() {
        let clock = Rc::new(Cell::new(0u64));
        let mut parts = stage14_11_l1_active_parts(&clock);
        let baseline = parts.actions.borrow().len();
        let actions_for_guard = parts.actions.clone();
        let guard = move || {
            let actions = actions_for_guard.borrow();
            !(actions.len() > baseline && actions.last() == Some(&"service_stop"))
        };
        let result = parts.runtime.shutdown_for_daemon(&guard);
        assert!(
            matches!(result, Err(LinuxNodeRuntimeError::ControlLockLost)),
            "the loss must not be reported as a clean shutdown: {result:?}"
        );
        let actions = parts.actions.borrow();
        assert_eq!(
            &actions[baseline..],
            &["service_stop"],
            "the service stop already in flight completed, but no VIP release or lease cleanup started"
        );
        assert_ne!(parts.runtime.state_machine.node_state(), NodeState::Active);
        cleanup_test_path(&parts.path);
    }

    type AuthoritySnapshot = (
        Term,
        LeaseId,
        crate::node_lease_authority::MonotonicTime,
        crate::node_lease_authority::MonotonicTime,
    );

    struct R17Run {
        result: Result<(), LinuxNodeRuntimeError>,
        served: usize,
        actions: Vec<&'static str>,
        state: NodeState,
        phase: Option<OperationPhase>,
        authority_before: Option<AuthoritySnapshot>,
        authority_after: Option<AuthoritySnapshot>,
        path: PathBuf,
    }

    /// One real authenticated foreground step against a loopback Witness.
    /// `initially_lost` models a loss before the request; `lose_during`
    /// models the lock being replaced after the request was received and
    /// before the response is processed.
    fn r17_foreground_once(initially_lost: bool, lose_during: bool) -> R17Run {
        use crate::security::{MessageAuthenticator, Psk};
        use crate::session::ProcessSession;
        use crate::tcp::TcpConnection;
        use crate::witness_runtime::{WitnessConnection, WitnessResponseContext};
        use std::net::{TcpListener, TcpStream};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicUsize};
        use std::thread;

        let clock = Rc::new(Cell::new(3_000u64));
        let mut parts = stage14_11_l1_active_parts(&clock);
        // The production ARM leaves the cleanup obligation O for this
        // attempt's lease; a durable Renew is allowed only while O names the
        // same term/lease (node_mutation invariant). The test fixture's
        // direct `promote` does not arm it, so arm the exact lease here.
        parts
            .runtime
            .mutation_store
            .arm_release_obligation(Term(7), LeaseId::new("lease-1"))
            .unwrap();
        let actions_before = parts.actions.borrow().len();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let node = WitnessConnection::new(
            NodeId::new("node-a"),
            NodeId::new("witness"),
            ClusterId::new("cluster"),
            SessionId::new("session-w"),
            TcpConnection::from_stream(client, Duration::from_secs(3), Duration::from_secs(3))
                .unwrap(),
        );
        let mut witness = WitnessConnection::new(
            NodeId::new("witness"),
            NodeId::new("node-a"),
            ClusterId::new("cluster"),
            SessionId::new("session-a"),
            TcpConnection::from_stream(server, Duration::from_secs(2), Duration::from_secs(2))
                .unwrap(),
        );
        let lost = Arc::new(AtomicBool::new(initially_lost));
        let served = Arc::new(AtomicUsize::new(0));
        let server_lost = lost.clone();
        let server_served = served.clone();
        let server_thread = thread::spawn(move || {
            let auth = MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32]));
            let mut process = ProcessSession::from_session_id(SessionId::new("session-w"));
            let Ok(pending) = witness.receive_pending(&CborSerializer, &auth) else {
                return;
            };
            if lose_during {
                server_lost.store(true, Ordering::SeqCst);
            }
            let request_id = pending
                .message()
                .unsigned()
                .common
                .request_id
                .clone()
                .unwrap();
            crate::witness_runtime::send_witness_response_with_context(
                &mut witness,
                &mut process,
                request_id,
                ProtocolMessage::LeaseRenewed(LeaseGrantPayload {
                    term: Term(7),
                    lease_id: LeaseId::new("lease-1"),
                    holder_node_id: NodeId::new("node-a"),
                    lease_ttl_ms: DurationMs(10_000),
                    renew_after_ms: DurationMs(3_000),
                    lease_remaining_ms: DurationMs(10_000),
                }),
                WitnessResponseContext {
                    term: Term(7),
                    lease_id: Some(LeaseId::new("lease-1")),
                },
                &CborSerializer,
                &auth,
            )
            .unwrap();
            server_served.fetch_add(1, Ordering::SeqCst);
        });
        let mut session = WitnessSession::new(
            node,
            ProcessSession::from_session_id(SessionId::new("session-a")),
            MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32])),
        );
        let guard_lost = lost.clone();
        let authority_before = parts.runtime.installed_lease_authority().map(|authority| {
            (
                authority.term(),
                authority.lease_id().clone(),
                authority.safe_deadline(),
                authority.renew_due(),
            )
        });
        let result = parts
            .runtime
            .drive_foreground_lifecycle(&mut session, &|| false, &|| {
                !guard_lost.load(Ordering::SeqCst)
            });
        let authority_after = parts.runtime.installed_lease_authority().map(|authority| {
            (
                authority.term(),
                authority.lease_id().clone(),
                authority.safe_deadline(),
                authority.renew_due(),
            )
        });
        let actions = parts.actions.borrow()[actions_before..].to_vec();
        let state = parts.runtime.state_machine.node_state();
        let phase = parts.runtime.state_machine.operation_phase();
        drop(session);
        server_thread.join().unwrap();
        R17Run {
            result,
            served: served.load(Ordering::SeqCst),
            actions,
            state,
            phase,
            authority_before,
            authority_after,
            path: parts.path,
        }
    }

    #[test]
    fn t2_active_renewal_is_not_sent_after_a_lock_loss() {
        let run = r17_foreground_once(true, false);
        assert!(matches!(
            run.result,
            Err(LinuxNodeRuntimeError::ControlLockLost)
        ));
        assert_eq!(run.served, 0, "no LeaseRenew request may leave the node");
        assert!(run.actions.is_empty(), "no demotion/VIP/service cleanup");
        assert_eq!(run.state, NodeState::Active);
        assert!(run.phase.is_none());
        cleanup_test_path(&run.path);
    }

    #[test]
    fn t3_in_flight_renewal_cannot_extend_authority_or_trigger_cleanup_after_lock_loss() {
        let run = r17_foreground_once(false, true);
        assert!(matches!(
            run.result,
            Err(LinuxNodeRuntimeError::ControlLockLost)
        ));
        assert_eq!(run.served, 1, "the already-sent request completed once");
        assert!(
            run.actions.is_empty(),
            "a late response must not start demotion or cleanup: {:?}",
            run.actions
        );
        assert_eq!(run.state, NodeState::Active);
        assert!(
            run.phase.is_none(),
            "no demotion phase may be entered from the late response"
        );
        assert_eq!(
            run.authority_after, run.authority_before,
            "the late response must not extend the local authority deadline"
        );
        cleanup_test_path(&run.path);
    }

    #[test]
    fn t5_normal_active_renewal_succeeds_and_keeps_active() {
        let run = r17_foreground_once(false, false);
        assert!(run.result.is_ok(), "normal renewal: {:?}", run.result);
        assert_eq!(run.served, 1, "exactly one renewal request");
        assert!(run.actions.is_empty(), "no demotion/VIP/service cleanup");
        assert_eq!(run.state, NodeState::Active);
        assert!(run.phase.is_none());
        cleanup_test_path(&run.path);
    }

    /// The runtime applies the floor to the renew term and leaves expiry alone.
    #[test]
    fn stage14_11_l1_runtime_renew_floor_and_expiry_priority_boundaries() {
        let clock = Rc::new(Cell::new(0u64));
        let parts = stage14_11_l1_active_parts(&clock);
        let ordinary = ms(1_000);
        let delay = |at: u64| {
            clock.set(at);
            parts.runtime.active_schedule_delay(ordinary).unwrap()
        };
        // renew_in = 0 (due), 1, 99, 100, 101 ms; expiry is far (~5 s).
        assert_eq!(delay(3_001), ms(100), "overdue: renew_in 0");
        assert_eq!(delay(3_000), ms(100), "renew_in = 0");
        assert_eq!(delay(2_999), ms(100), "renew_in = 1 ms");
        assert_eq!(delay(2_901), ms(100), "renew_in = 99 ms");
        assert_eq!(delay(2_900), ms(100), "renew_in = 100 ms");
        assert_eq!(delay(2_899), ms(101), "renew_in = 101 ms");
        assert_eq!(delay(2_000), ms(1_000), "renew_in = 1000 ms: ordinary");
        // The renew term is overdue; expiry_in = 1, 99, 100, 101 ms.
        assert_eq!(delay(7_999), ms(1), "expiry_in = 1 ms wins");
        assert_eq!(delay(7_901), ms(99), "expiry_in = 99 ms wins");
        assert_eq!(delay(7_900), ms(100), "expiry_in = 100 ms: exact boundary");
        assert_eq!(delay(7_899), ms(100), "expiry_in = 101 ms: floor wins");
        // At/after the safe deadline there is no Active schedule at all.
        assert_eq!(delay(8_000), ordinary);
        assert_eq!(delay(8_001), ordinary);
        cleanup_test_path(&parts.path);
    }

    /// An outstanding LeaseRenew keeps the existing branch (no renew term, no
    /// floor), including at the boundaries.
    #[test]
    fn stage14_11_l1_runtime_outstanding_renew_branch_is_unchanged() {
        let clock = Rc::new(Cell::new(0u64));
        let parts = stage14_11_l1_active_parts(&clock);
        parts
            .runtime
            .mutation_store
            .arm_release_obligation(Term(7), LeaseId::new("lease-1"))
            .unwrap();
        parts
            .runtime
            .mutation_store
            .begin_lease_renew(Term(7), LeaseId::new("lease-1"))
            .unwrap();
        let ordinary = ms(1_000);
        let delay = |at: u64| {
            clock.set(at);
            parts.runtime.active_schedule_delay(ordinary).unwrap()
        };
        assert_eq!(delay(3_000), ordinary, "renew due, Renew outstanding");
        assert_eq!(delay(3_001), ordinary);
        assert_eq!(delay(2_999), ordinary);
        assert_eq!(delay(7_999), ms(1));
        assert_eq!(delay(7_901), ms(99));
        assert_eq!(delay(7_900), ms(100));
        assert_eq!(delay(7_899), ms(101), "no floor on this branch");
        assert_eq!(delay(8_000), ordinary);
        cleanup_test_path(&parts.path);
    }

    /// Standby, an operation phase, and a latched demotion keep the ordinary
    /// cadence even where the renew term would be 0 and expiry is near.
    #[test]
    fn stage14_11_l1_runtime_non_active_schedules_keep_the_ordinary_cadence() {
        let ordinary = ms(1_000);
        // Standby with an installed authority.
        let clock = Rc::new(Cell::new(0u64));
        let mut standby = test_runtime(
            [RawVipObservation::Absent],
            [RawServiceObservation::Stopped],
            [],
            AuthorityMode::Conservative,
            Some(clock.clone()),
        );
        reconcile_zero_resource(&mut standby);
        install_test_authority(&mut standby.runtime);
        assert_eq!(
            standby.runtime.state_machine.node_state(),
            NodeState::Standby
        );
        for at in [3_000, 7_950, 7_999] {
            clock.set(at);
            assert_eq!(
                standby.runtime.active_schedule_delay(ordinary).unwrap(),
                ordinary
            );
        }
        cleanup_test_path(&standby.path);
        // Active with a latched demotion.
        let clock = Rc::new(Cell::new(0u64));
        let mut latched = stage14_11_l1_active_parts(&clock);
        latched.runtime.controller.request_demotion();
        for at in [3_000, 7_950, 7_999] {
            clock.set(at);
            assert_eq!(
                latched.runtime.active_schedule_delay(ordinary).unwrap(),
                ordinary
            );
        }
        cleanup_test_path(&latched.path);
        // Active, then a demotion operation phase.
        let clock = Rc::new(Cell::new(0u64));
        let mut demoting = stage14_11_l1_active_parts(&clock);
        demoting
            .runtime
            .controller
            .begin_demotion(&mut demoting.runtime.state_machine)
            .unwrap();
        assert!(demoting.runtime.state_machine.operation_phase().is_some());
        for at in [3_000, 7_950, 7_999] {
            clock.set(at);
            assert_eq!(
                demoting.runtime.active_schedule_delay(ordinary).unwrap(),
                ordinary
            );
        }
        cleanup_test_path(&demoting.path);
    }

    /// One iteration of the production ordering for the node half of the
    /// loop: foreground lifecycle step, the rest of the tick (`tail_ms` of
    /// controller time after the Witness response was validated), then the
    /// wait the loop would take.
    struct L1Tick {
        at_ms: u64,
        delay_ms: u64,
        active: bool,
    }

    struct L1WitnessRun {
        trace: Vec<L1Tick>,
        renew_requests_served: usize,
        parts_path: PathBuf,
    }

    /// A real authenticated Witness peer (PSK-HMAC framing, `receive_pending`
    /// verification, `send_witness_response_with_context`) answers up to
    /// `witness_rounds` LeaseRenew requests with the given grant. The grant
    /// then passes the node's `validate_grant` and authority install.
    fn stage14_11_l1_witness_run(
        renew_after_ms: u64,
        lease_remaining_ms: u64,
        witness_rounds: usize,
        iterations: usize,
        ordinary_ms: u64,
        tail_ms: u64,
    ) -> L1WitnessRun {
        use crate::security::{MessageAuthenticator, Psk};
        use crate::session::ProcessSession;
        use crate::tcp::TcpConnection;
        use crate::witness_runtime::{
            WitnessConnection, WitnessResponseContext, send_witness_response_with_context,
        };
        use std::net::{TcpListener, TcpStream};
        use std::sync::Arc;
        use std::sync::atomic::AtomicUsize;
        use std::thread;

        let clock = Rc::new(Cell::new(0u64));
        let mut parts = stage14_11_l1_active_parts(&clock);
        parts
            .runtime
            .mutation_store
            .arm_release_obligation(Term(7), LeaseId::new("lease-1"))
            .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let node = WitnessConnection::new(
            NodeId::new("node-a"),
            NodeId::new("witness"),
            ClusterId::new("cluster"),
            SessionId::new("session-w"),
            TcpConnection::from_stream(client, Duration::from_secs(2), Duration::from_secs(2))
                .unwrap(),
        );
        let mut witness = WitnessConnection::new(
            NodeId::new("witness"),
            NodeId::new("node-a"),
            ClusterId::new("cluster"),
            SessionId::new("session-a"),
            TcpConnection::from_stream(server, Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
        );
        let served = Arc::new(AtomicUsize::new(0));
        let served_in_thread = served.clone();
        let server_thread = thread::spawn(move || {
            let auth = MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32]));
            let mut process = ProcessSession::from_session_id(SessionId::new("session-w"));
            for _ in 0..witness_rounds {
                let Ok(pending) = witness.receive_pending(&CborSerializer, &auth) else {
                    return;
                };
                let request_id = pending
                    .message()
                    .unsigned()
                    .common
                    .request_id
                    .clone()
                    .unwrap();
                send_witness_response_with_context(
                    &mut witness,
                    &mut process,
                    request_id,
                    ProtocolMessage::LeaseRenewed(LeaseGrantPayload {
                        term: Term(7),
                        lease_id: LeaseId::new("lease-1"),
                        holder_node_id: NodeId::new("node-a"),
                        lease_ttl_ms: DurationMs(10_000),
                        renew_after_ms: DurationMs(renew_after_ms),
                        lease_remaining_ms: DurationMs(lease_remaining_ms),
                    }),
                    WitnessResponseContext {
                        term: Term(7),
                        lease_id: Some(LeaseId::new("lease-1")),
                    },
                    &CborSerializer,
                    &auth,
                )
                .unwrap();
                served_in_thread.fetch_add(1, Ordering::SeqCst);
            }
        });
        let mut session = WitnessSession::new(
            node,
            ProcessSession::from_session_id(SessionId::new("session-a")),
            MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32])),
        );
        let mut trace = Vec::new();
        for _ in 0..iterations {
            let at = clock.get();
            parts
                .runtime
                .drive_foreground_lifecycle(&mut session, &|| false, &|| true)
                .unwrap();
            clock.set(at + tail_ms);
            let delay = parts
                .runtime
                .active_schedule_delay(ms(ordinary_ms))
                .unwrap()
                .as_millis() as u64;
            let active = parts.runtime.state_machine.node_state() == NodeState::Active
                && parts.runtime.state_machine.operation_phase().is_none();
            trace.push(L1Tick {
                at_ms: at,
                delay_ms: delay,
                active,
            });
            clock.set(at + tail_ms + delay);
            if !active {
                break;
            }
        }
        drop(session);
        let _ = server_thread.join();
        L1WitnessRun {
            trace,
            renew_requests_served: served.load(Ordering::SeqCst),
            parts_path: parts.path.clone(),
        }
    }

    /// Most ticks in any closed 30 s window of controller time.
    fn stage14_11_l1_max_ticks_in_30s(trace: &[L1Tick]) -> usize {
        let mut best = 0;
        for (index, first) in trace.iter().enumerate() {
            let count = trace[index..]
                .iter()
                .take_while(|tick| tick.at_ms - first.at_ms <= 30_000)
                .count();
            best = best.max(count);
        }
        best
    }

    /// THE probe of the research task, now a regression test: an authenticated
    /// Witness grants `renew_after_ms = 1` (valid per `validate_grant`) and the
    /// rest of the tick costs 1 ms. Before the floor this produced 297
    /// consecutive zero waits (300 ticks in 297 ms). Now every Active wait is
    /// at least the 100 ms floor and a closed 30 s window holds at most 303
    /// ticks.
    #[test]
    fn stage14_11_l1_authenticated_witness_renew_after_1ms_has_no_zero_wait_chain() {
        let run = stage14_11_l1_witness_run(1, 10_000, 1_000, 340, 1_000, 1);
        let active: Vec<&L1Tick> = run.trace.iter().filter(|tick| tick.active).collect();
        assert_eq!(active.len(), run.trace.len(), "the node stays Active");
        assert!(
            run.renew_requests_served >= 300,
            "real authenticated renewals were exercised: {}",
            run.renew_requests_served
        );
        assert_eq!(
            run.trace.iter().filter(|tick| tick.delay_ms == 0).count(),
            0,
            "no zero wait"
        );
        let hot: Vec<u64> = run
            .trace
            .iter()
            .filter(|tick| tick.at_ms >= 3_000)
            .map(|tick| tick.delay_ms)
            .collect();
        assert!(hot.len() >= 300);
        assert!(
            hot.iter().all(|delay| *delay >= 100),
            "every wait >= the floor: {hot:?}"
        );
        // The tick spacing is the floor plus the tail: strictly bounded.
        let window = stage14_11_l1_max_ticks_in_30s(&run.trace);
        assert!(window <= 303, "ticks in a closed 30 s window: {window}");
        cleanup_test_path(&run.parts_path);
    }

    /// A conformant Witness (renew_after 3000 / ttl 10000) sees the unchanged
    /// cadence: ordinary waits, one renewal per 3 s, no floor in effect.
    #[test]
    fn stage14_11_l1_authenticated_witness_conformant_cadence_is_unchanged() {
        let run = stage14_11_l1_witness_run(3_000, 10_000, 1_000, 120, 1_000, 0);
        assert!(run.trace.iter().all(|tick| tick.active));
        assert!(
            run.trace.iter().all(|tick| tick.delay_ms == 1_000),
            "ordinary waits only"
        );
        assert_eq!(
            run.renew_requests_served, 39,
            "one renewal every 3 s over 120 s"
        );
        assert!(stage14_11_l1_max_ticks_in_30s(&run.trace) <= 31);
        cleanup_test_path(&run.parts_path);
    }

    /// Expiry has priority over the floor: a grant whose usable window
    /// (lease_remaining - 2000 ms safety margin) is 50 ms yields a wait that
    /// lands on the safe deadline, the next iteration demotes, and exactly one
    /// renewal ran (the pre-floor code kept renewing in a zero-wait loop).
    #[test]
    fn stage14_11_l1_authenticated_witness_short_usable_window_fails_closed_at_the_deadline() {
        let run = stage14_11_l1_witness_run(1, 2_050, 1_000, 40, 1_000, 1);
        assert_eq!(run.renew_requests_served, 1, "no renewal loop");
        let first_renewal_tick = run
            .trace
            .iter()
            .position(|tick| tick.at_ms == 3_000)
            .unwrap();
        let after = &run.trace[first_renewal_tick];
        assert!(after.active);
        assert_eq!(
            after.delay_ms, 49,
            "expiry_in (50 ms usable - 1 ms tail), not the floor"
        );
        let next = &run.trace[first_renewal_tick + 1];
        assert_eq!(
            next.at_ms, 3_050,
            "the next iteration is at the safe deadline"
        );
        assert!(!next.active, "and it demotes: fail closed");
        assert_eq!(
            next.delay_ms, 1_000,
            "after the demotion the wait is the ordinary cadence again"
        );
        assert_eq!(
            run.trace.len(),
            first_renewal_tick + 2,
            "the loop ends the Active tenure"
        );
        cleanup_test_path(&run.parts_path);
    }

    /// Renewal failure (Witness gone): the durable Renew is retained, the wait
    /// stays the ordinary cadence (no hot retry), and the node demotes exactly
    /// at the safe deadline.
    #[test]
    fn stage14_11_l1_authenticated_witness_down_retains_renew_and_demotes_at_the_deadline() {
        let run = stage14_11_l1_witness_run(3_000, 10_000, 0, 40, 1_000, 0);
        assert_eq!(run.renew_requests_served, 0);
        let last = run.trace.last().unwrap();
        assert_eq!(
            last.at_ms, 8_000,
            "demotion tick is exactly the safe deadline"
        );
        assert!(!last.active);
        assert_eq!(last.delay_ms, 1_000, "ordinary cadence after the demotion");
        for tick in &run.trace[..run.trace.len() - 1] {
            assert!(tick.active);
            assert_eq!(
                tick.delay_ms, 1_000,
                "no hot retry while the Renew is outstanding"
            );
        }
        cleanup_test_path(&run.parts_path);
    }

    fn reconcile_zero_resource(parts: &mut TestRuntimeParts) -> LinuxRuntimeSnapshot {
        parts.runtime.reconcile().unwrap()
    }

    fn install_test_authority(runtime: &mut LinuxNodeRuntime<TestNetwork, TestService, TestClock>) {
        runtime
            .controller
            .install_test_grant_for_resource_workflow(
                &LeaseGrantPayload {
                    term: Term(7),
                    lease_id: LeaseId::new("lease-1"),
                    holder_node_id: NodeId::new("node-a"),
                    lease_ttl_ms: DurationMs(10_000),
                    renew_after_ms: DurationMs(3_000),
                    lease_remaining_ms: DurationMs(10_000),
                },
                crate::node_lease_authority::MonotonicTime::from_millis(0),
            )
            .unwrap();
    }

    fn strong_loss_input(
        local: LocalSafetySnapshot,
    ) -> crate::failover_policy::FailoverEligibilityInput {
        crate::failover_policy::FailoverEligibilityInput {
            peer_assessment: crate::failure_assessment::PeerFailureAssessment::CommunicationLost,
            evidence_state: crate::evidence_fusion::EvidenceFusionState::FailoverEvidenceReady,
            local,
        }
    }

    #[test]
    fn failover_local_safety_snapshot_maps_daemon_shutdown_to_blocker() {
        let mut parts = test_runtime(
            [RawVipObservation::Absent],
            [RawServiceObservation::Stopped],
            [],
            AuthorityMode::Conservative,
            None,
        );
        reconcile_zero_resource(&mut parts);
        let local = parts.runtime.failover_local_safety_snapshot(true).unwrap();
        assert_eq!(local.node_state, NodeState::Standby);
        assert_eq!(local.operation_phase, None);
        assert_eq!(local.readiness, LocalSafetyReadiness::ShutdownInProgress);
        assert!(
            !crate::failover_policy::FailoverEligibilityPolicy::evaluate(strong_loss_input(local))
                .is_eligible()
        );
        cleanup_test_path(&parts.path);
    }

    #[test]
    fn failover_local_safety_snapshot_maps_controller_blockers() {
        let mut recovery = test_runtime(
            [RawVipObservation::Absent],
            [RawServiceObservation::Stopped],
            [],
            AuthorityMode::Conservative,
            None,
        );
        recovery
            .runtime
            .state_machine
            .transition_to(NodeState::Standby)
            .unwrap();
        let local = recovery
            .runtime
            .failover_local_safety_snapshot(false)
            .unwrap();
        assert_eq!(local.readiness, LocalSafetyReadiness::RecoveryBlocked);
        cleanup_test_path(&recovery.path);

        let mut demotion = test_runtime(
            [RawVipObservation::Absent],
            [RawServiceObservation::Stopped],
            [],
            AuthorityMode::Conservative,
            None,
        );
        reconcile_zero_resource(&mut demotion);
        demotion
            .runtime
            .controller
            .mark_resource_ownership_started();
        demotion.runtime.controller.request_demotion();
        let local = demotion
            .runtime
            .failover_local_safety_snapshot(false)
            .unwrap();
        assert_eq!(local.readiness, LocalSafetyReadiness::DemotionRequired);
        cleanup_test_path(&demotion.path);

        let mut ownership = test_runtime(
            [RawVipObservation::Absent],
            [RawServiceObservation::Stopped],
            [],
            AuthorityMode::Availability,
            None,
        );
        reconcile_zero_resource(&mut ownership);
        ownership.runtime.controller.mark_ownership_uncertain();
        let local = ownership
            .runtime
            .failover_local_safety_snapshot(false)
            .unwrap();
        assert_eq!(local.readiness, LocalSafetyReadiness::OwnershipUncertain);
        cleanup_test_path(&ownership.path);
    }

    #[test]
    fn failover_local_safety_snapshot_maps_unresolved_mutation_and_safe_state() {
        let mut parts = test_runtime(
            [RawVipObservation::Absent],
            [RawServiceObservation::Stopped],
            [],
            AuthorityMode::Conservative,
            None,
        );
        reconcile_zero_resource(&mut parts);
        parts
            .runtime
            .mutation_store
            .begin_lease_request(Term(7), 100, DurationMs(10_000))
            .unwrap();
        let local = parts.runtime.failover_local_safety_snapshot(false).unwrap();
        assert_eq!(
            local.readiness,
            LocalSafetyReadiness::ResourceStateUnresolved
        );
        assert!(
            !crate::failover_policy::FailoverEligibilityPolicy::evaluate(strong_loss_input(local))
                .is_eligible()
        );
        cleanup_test_path(&parts.path);

        let mut safe = test_runtime(
            [RawVipObservation::Absent],
            [RawServiceObservation::Stopped],
            [],
            AuthorityMode::Conservative,
            None,
        );
        reconcile_zero_resource(&mut safe);
        let local = safe.runtime.failover_local_safety_snapshot(false).unwrap();
        assert_eq!(local.readiness, LocalSafetyReadiness::Safe);
        assert!(
            crate::failover_policy::FailoverEligibilityPolicy::evaluate(strong_loss_input(local))
                .is_eligible()
        );
        cleanup_test_path(&safe.path);
    }

    #[test]
    fn live_authority_maps_to_runtime_blocker_and_blocks_failover_eligibility() {
        let mut parts = test_runtime(
            [
                RawVipObservation::Absent,
                RawVipObservation::Absent,
                RawVipObservation::Absent,
            ],
            [
                RawServiceObservation::Stopped,
                RawServiceObservation::Stopped,
                RawServiceObservation::Stopped,
            ],
            [],
            AuthorityMode::Conservative,
            None,
        );
        reconcile_zero_resource(&mut parts);
        install_test_authority(&mut parts.runtime);

        let snapshot = parts.runtime.failover_local_safety_snapshot(false).unwrap();
        assert_eq!(snapshot.node_state, NodeState::Standby);
        assert_eq!(snapshot.operation_phase, None);
        assert_eq!(snapshot.readiness, LocalSafetyReadiness::AuthorityPresent);
        assert_eq!(
            crate::failover_policy::FailoverEligibilityPolicy::evaluate(strong_loss_input(
                snapshot,
            )),
            crate::failover_policy::FailoverEligibility::Ineligible(
                crate::failover_policy::FailoverIneligibility::LocalStateUnsafe,
            )
        );
        cleanup_test_path(&parts.path);
    }

    #[test]
    fn current_vip_present_blocks_safe_readiness() {
        let mut parts = test_runtime(
            [
                RawVipObservation::Absent,
                RawVipObservation::Absent,
                RawVipObservation::Present,
            ],
            [
                RawServiceObservation::Stopped,
                RawServiceObservation::Stopped,
            ],
            [],
            AuthorityMode::Conservative,
            None,
        );
        reconcile_zero_resource(&mut parts);
        let local = parts.runtime.failover_local_safety_snapshot(false).unwrap();
        assert_eq!(
            local.readiness,
            LocalSafetyReadiness::ResourceStateUnresolved
        );
        assert!(
            !crate::failover_policy::FailoverEligibilityPolicy::evaluate(strong_loss_input(local))
                .is_eligible()
        );
        cleanup_test_path(&parts.path);
    }

    #[test]
    fn current_service_running_blocks_safe_readiness() {
        let mut parts = test_runtime(
            [
                RawVipObservation::Absent,
                RawVipObservation::Absent,
                RawVipObservation::Absent,
            ],
            [
                RawServiceObservation::Stopped,
                RawServiceObservation::Stopped,
                RawServiceObservation::Running,
            ],
            [],
            AuthorityMode::Conservative,
            None,
        );
        reconcile_zero_resource(&mut parts);
        let local = parts.runtime.failover_local_safety_snapshot(false).unwrap();
        assert_eq!(
            local.readiness,
            LocalSafetyReadiness::ResourceStateUnresolved
        );
        assert!(
            !crate::failover_policy::FailoverEligibilityPolicy::evaluate(strong_loss_input(local))
                .is_eligible()
        );
        cleanup_test_path(&parts.path);
    }

    #[test]
    fn unknown_resource_observation_fails_closed() {
        let mut vip_unknown = test_runtime(
            [
                RawVipObservation::Absent,
                RawVipObservation::Absent,
                RawVipObservation::Unavailable,
            ],
            [
                RawServiceObservation::Stopped,
                RawServiceObservation::Stopped,
            ],
            [],
            AuthorityMode::Conservative,
            None,
        );
        reconcile_zero_resource(&mut vip_unknown);
        let local = vip_unknown
            .runtime
            .failover_local_safety_snapshot(false)
            .unwrap();
        assert_eq!(
            local.readiness,
            LocalSafetyReadiness::ResourceStateUnresolved
        );
        cleanup_test_path(&vip_unknown.path);

        let mut service_unknown = test_runtime(
            [
                RawVipObservation::Absent,
                RawVipObservation::Absent,
                RawVipObservation::Absent,
            ],
            [
                RawServiceObservation::Stopped,
                RawServiceObservation::Stopped,
                RawServiceObservation::Unavailable,
            ],
            [],
            AuthorityMode::Conservative,
            None,
        );
        reconcile_zero_resource(&mut service_unknown);
        let local = service_unknown
            .runtime
            .failover_local_safety_snapshot(false)
            .unwrap();
        assert_eq!(
            local.readiness,
            LocalSafetyReadiness::ResourceStateUnresolved
        );
        cleanup_test_path(&service_unknown.path);
    }

    #[test]
    fn resource_drift_after_reconcile_invalidates_safe_snapshot() {
        let mut parts = test_runtime(
            [
                RawVipObservation::Absent,
                RawVipObservation::Absent,
                RawVipObservation::Absent,
            ],
            [
                RawServiceObservation::Stopped,
                RawServiceObservation::Stopped,
                RawServiceObservation::Stopped,
            ],
            [],
            AuthorityMode::Conservative,
            None,
        );
        reconcile_zero_resource(&mut parts);
        let initially_safe = parts.runtime.failover_local_safety_snapshot(false).unwrap();
        assert_eq!(initially_safe.readiness, LocalSafetyReadiness::Safe);
        parts.vip.borrow_mut().push_back(RawVipObservation::Present);
        parts
            .service
            .borrow_mut()
            .push_back(RawServiceObservation::Running);
        let after_drift = parts.runtime.failover_local_safety_snapshot(false).unwrap();
        assert_eq!(
            after_drift.readiness,
            LocalSafetyReadiness::ResourceStateUnresolved
        );
        assert!(
            !crate::failover_policy::FailoverEligibilityPolicy::evaluate(strong_loss_input(
                after_drift
            ))
            .is_eligible()
        );
        cleanup_test_path(&parts.path);
    }

    #[test]
    fn ownership_unknown_is_not_zero_resource() {
        let mut parts = test_runtime(
            [
                RawVipObservation::Absent,
                RawVipObservation::Absent,
                RawVipObservation::Absent,
            ],
            [
                RawServiceObservation::Stopped,
                RawServiceObservation::Stopped,
                RawServiceObservation::Stopped,
            ],
            [],
            AuthorityMode::Availability,
            None,
        );
        reconcile_zero_resource(&mut parts);
        parts.runtime.controller.mark_ownership_uncertain();
        let local = parts.runtime.failover_local_safety_snapshot(false).unwrap();
        assert_eq!(local.readiness, LocalSafetyReadiness::OwnershipUncertain);
        assert!(
            !crate::failover_policy::FailoverEligibilityPolicy::evaluate(strong_loss_input(local))
                .is_eligible()
        );
        cleanup_test_path(&parts.path);
    }

    #[test]
    fn resource_owning_blocks_even_with_clean_observation() {
        let mut parts = test_runtime(
            [RawVipObservation::Absent, RawVipObservation::Absent],
            [
                RawServiceObservation::Stopped,
                RawServiceObservation::Stopped,
            ],
            [],
            AuthorityMode::Availability,
            None,
        );
        reconcile_zero_resource(&mut parts);
        parts.runtime.controller.mark_resource_ownership_started();
        let local = parts.runtime.failover_local_safety_snapshot(false).unwrap();
        assert_eq!(local.readiness, LocalSafetyReadiness::OwnershipUncertain);
        cleanup_test_path(&parts.path);
    }

    #[test]
    fn attack_aa_restart_does_not_restore_persisted_lease_mutation_as_active_authority() {
        let first = test_runtime(
            [RawVipObservation::Absent],
            [RawServiceObservation::Stopped],
            [],
            AuthorityMode::Conservative,
            None,
        );
        first
            .runtime
            .mutation_store
            .begin_lease_renew_for_test(Term(7), LeaseId::new("persisted-lease-aa"))
            .unwrap();
        let persisted = first.runtime.mutation_store.load_existing().unwrap();
        assert!(matches!(
            persisted.outstanding_mutation,
            Some(crate::node_mutation::OutstandingWitnessMutation {
                mutation: crate::node_mutation::DurableWitnessMutation::LeaseRenew {
                    term: Term(7),
                    ref lease_id,
                },
                ..
            }) if lease_id == &LeaseId::new("persisted-lease-aa")
        ));
        let path = first.path.clone();
        drop(first);

        let mut restarted = test_runtime(
            [RawVipObservation::Absent],
            [RawServiceObservation::Stopped],
            [],
            AuthorityMode::Conservative,
            None,
        );
        restarted.runtime.mutation_store = crate::node_mutation::NodeMutationStore::new(
            &path,
            ClusterId::new("cluster"),
            NodeId::new("node-a"),
        );
        let snapshot = restarted.runtime.reconcile().unwrap();
        assert_eq!(snapshot.node_state, NodeState::RecoveryPending);
        assert!(!snapshot.authority_present);
        assert_ne!(snapshot.node_state, NodeState::Active);
        assert!(
            restarted
                .runtime
                .ensure_lease_acquisition_eligible()
                .is_err()
        );
        cleanup_test_path(&path);
        cleanup_test_path(&restarted.path);
    }

    #[test]
    fn attack_ab_resources_present_enters_recovery_cleanup_service_before_vip() {
        let mut parts = test_runtime(
            [RawVipObservation::Present, RawVipObservation::Absent],
            [
                RawServiceObservation::Running,
                RawServiceObservation::Stopped,
            ],
            [],
            AuthorityMode::Availability,
            None,
        );
        let snapshot = parts.runtime.reconcile().unwrap();
        assert_eq!(snapshot.node_state, NodeState::RecoveryPending);
        assert!(!snapshot.recovery_reconciled);
        assert!(parts.runtime.ensure_lease_acquisition_eligible().is_err());
        let actions = parts.actions.borrow();
        assert_eq!(&actions[..], &["service_stop", "vip_release"]);
        cleanup_test_path(&parts.path);
    }

    #[test]
    fn attack_ac_stale_operation_does_not_resume_promotion() {
        let mut parts = test_runtime(
            [RawVipObservation::Absent],
            [RawServiceObservation::Stopped],
            [],
            AuthorityMode::Availability,
            None,
        );
        parts
            .runtime
            .mutation_store
            .begin_lease_request(Term(1), 100, DurationMs(10_000))
            .unwrap();
        let snapshot = parts.runtime.reconcile().unwrap();
        assert_eq!(snapshot.node_state, NodeState::RecoveryPending);
        assert_eq!(snapshot.operation_phase, None);
        assert!(!snapshot.authority_present);
        assert!(parts.runtime.ensure_lease_acquisition_eligible().is_err());
        cleanup_test_path(&parts.path);
    }

    #[test]
    fn attack_ad_persisted_stale_lease_release_does_not_become_runtime_authority() {
        let parts = test_runtime(
            [RawVipObservation::Absent],
            [RawServiceObservation::Stopped],
            [],
            AuthorityMode::Conservative,
            None,
        );
        parts
            .runtime
            .mutation_store
            .begin_lease_release_for_test(Term(1), LeaseId::new("stale-lease-ad"), "stale".into())
            .unwrap();
        let persisted = parts.runtime.mutation_store.load_existing().unwrap();
        assert!(matches!(
            persisted.outstanding_mutation,
            Some(crate::node_mutation::OutstandingWitnessMutation {
                mutation: crate::node_mutation::DurableWitnessMutation::LeaseRelease {
                    term: Term(1),
                    ref lease_id,
                    ..
                },
                ..
            }) if lease_id == &LeaseId::new("stale-lease-ad")
        ));
        let path = parts.path.clone();
        drop(parts);
        let mut restarted = test_runtime(
            [RawVipObservation::Absent],
            [RawServiceObservation::Stopped],
            [],
            AuthorityMode::Conservative,
            None,
        );
        restarted.runtime.mutation_store = crate::node_mutation::NodeMutationStore::new(
            &path,
            ClusterId::new("cluster"),
            NodeId::new("node-a"),
        );
        let snapshot = restarted.runtime.reconcile().unwrap();
        assert_eq!(snapshot.node_state, NodeState::RecoveryPending);
        assert!(!snapshot.authority_present);
        assert_ne!(snapshot.node_state, NodeState::Active);
        assert!(
            restarted
                .runtime
                .ensure_lease_acquisition_eligible()
                .is_err()
        );
        cleanup_test_path(&path);
        cleanup_test_path(&restarted.path);
    }

    #[test]
    fn attack_ae_recovery_unknown_blocks_standby_and_lease() {
        let mut parts = test_runtime(
            [RawVipObservation::Absent],
            [
                RawServiceObservation::Unavailable,
                RawServiceObservation::Unavailable,
                RawServiceObservation::Unavailable,
            ],
            [],
            AuthorityMode::Availability,
            None,
        );
        let snapshot = parts.runtime.reconcile().unwrap();
        assert_eq!(snapshot.node_state, NodeState::RecoveryPending);
        assert_eq!(snapshot.service, RuntimeResourceTruth::Unknown);
        assert!(parts.runtime.ensure_lease_acquisition_eligible().is_err());
        cleanup_test_path(&parts.path);
    }

    #[test]
    fn attack_af_stop_success_service_unknown_blocks_vip_release() {
        let mut parts = test_runtime(
            [RawVipObservation::Present],
            [
                RawServiceObservation::Running,
                RawServiceObservation::Unavailable,
            ],
            [],
            AuthorityMode::Availability,
            None,
        );
        let snapshot = parts.runtime.reconcile().unwrap();
        assert_eq!(snapshot.node_state, NodeState::RecoveryPending);
        assert_eq!(&*parts.actions.borrow(), &["service_stop"]);
        cleanup_test_path(&parts.path);
    }

    #[test]
    fn attack_ag_vip_delete_success_vip_unknown_blocks_standby() {
        let mut parts = test_runtime(
            [RawVipObservation::Present, RawVipObservation::Unavailable],
            [
                RawServiceObservation::Running,
                RawServiceObservation::Stopped,
            ],
            [],
            AuthorityMode::Availability,
            None,
        );
        let snapshot = parts.runtime.reconcile().unwrap();
        assert_eq!(snapshot.node_state, NodeState::RecoveryPending);
        assert_eq!(&*parts.actions.borrow(), &["service_stop", "vip_release"]);
        cleanup_test_path(&parts.path);
    }

    #[test]
    fn attack_ah_unhealthy_service_running_cannot_commit_active() {
        let mut parts = test_runtime(
            [
                RawVipObservation::Absent,
                RawVipObservation::Absent,
                RawVipObservation::Present,
                RawVipObservation::Absent,
            ],
            [
                RawServiceObservation::Stopped,
                RawServiceObservation::Stopped,
                RawServiceObservation::Running,
                RawServiceObservation::Stopped,
            ],
            [RawHealthObservation::Unhealthy],
            AuthorityMode::Availability,
            None,
        );
        reconcile_zero_resource(&mut parts);
        install_test_authority(&mut parts.runtime);
        let result = parts.runtime.promote().unwrap();
        assert_eq!(result, ExplicitOperationResult::Blocked);
        let snapshot = parts.runtime.snapshot().unwrap();
        assert_ne!(snapshot.node_state, NodeState::Active);
        let actions = parts.actions.borrow();
        assert!(
            actions
                .windows(2)
                .any(|pair| pair == ["service_stop", "vip_release"])
        );
        cleanup_test_path(&parts.path);
    }

    #[test]
    fn attack_ai_authority_expiry_before_active_commit_cleans_up() {
        let clock_now = Rc::new(Cell::new(0));
        let mut parts = test_runtime(
            [
                RawVipObservation::Absent,
                RawVipObservation::Absent,
                RawVipObservation::Present,
                RawVipObservation::Absent,
            ],
            [
                RawServiceObservation::Stopped,
                RawServiceObservation::Stopped,
                RawServiceObservation::Running,
                RawServiceObservation::Stopped,
            ],
            [RawHealthObservation::Healthy],
            AuthorityMode::Conservative,
            Some(clock_now.clone()),
        );
        reconcile_zero_resource(&mut parts);
        install_test_authority(&mut parts.runtime);
        let result = parts.runtime.promote().unwrap();
        assert_eq!(result, ExplicitOperationResult::CleanupRequired);
        assert_eq!(
            clock_now.get(),
            8_000,
            "actions: {:?}",
            parts.actions.borrow()
        );
        assert_ne!(
            parts.runtime.snapshot().unwrap().node_state,
            NodeState::Active
        );
        assert!(parts.actions.borrow().contains(&"service_stop"));
        cleanup_test_path(&parts.path);
    }

    #[test]
    fn gb_authority_expiry_after_workflow_success_enters_cleanup() {
        let clock_now = Rc::new(Cell::new(0));
        let mut parts = test_runtime(
            [
                RawVipObservation::Absent,
                RawVipObservation::Absent,
                RawVipObservation::Present,
                RawVipObservation::Absent,
                RawVipObservation::Absent,
            ],
            [
                RawServiceObservation::Stopped,
                RawServiceObservation::Stopped,
                RawServiceObservation::Running,
                RawServiceObservation::Stopped,
                RawServiceObservation::Stopped,
            ],
            [RawHealthObservation::Healthy],
            AuthorityMode::Conservative,
            Some(clock_now.clone()),
        );
        parts.advance_garp_clock.set(false);
        reconcile_zero_resource(&mut parts);
        install_test_authority(&mut parts.runtime);
        let hook_calls = Rc::new(Cell::new(0));
        let hook_calls_for_test = hook_calls.clone();
        parts.runtime.promotion_test_hook = Some(Box::new(move || {
            hook_calls_for_test.set(hook_calls_for_test.get() + 1);
            clock_now.set(8_001);
        }));

        assert_eq!(
            parts.runtime.promote().unwrap(),
            ExplicitOperationResult::CleanupRequired
        );
        let snapshot = parts.runtime.snapshot().unwrap();
        assert_eq!(snapshot.node_state, NodeState::Failed);
        assert_ne!(snapshot.node_state, NodeState::Active);
        assert_eq!(hook_calls.get(), 1, "post-workflow hook was not reached");
        assert!(parts.actions.borrow().contains(&"vip_acquire"));
        assert!(parts.actions.borrow().contains(&"service_start"));
        assert!(parts.actions.borrow().contains(&"health"));
        assert!(parts.actions.borrow().contains(&"garp"));
        assert!(parts.actions.borrow().contains(&"service_stop"));
        assert!(parts.actions.borrow().contains(&"vip_release"));
        cleanup_test_path(&parts.path);
    }

    #[test]
    fn gd_late_authority_loss_with_cleanup_failure_fails_closed() {
        let clock_now = Rc::new(Cell::new(0));
        let mut parts = test_runtime(
            [
                RawVipObservation::Absent,
                RawVipObservation::Absent,
                RawVipObservation::Present,
                RawVipObservation::Absent,
                RawVipObservation::Absent,
            ],
            [
                RawServiceObservation::Stopped,
                RawServiceObservation::Stopped,
                RawServiceObservation::Running,
                RawServiceObservation::Unavailable,
            ],
            [RawHealthObservation::Healthy],
            AuthorityMode::Conservative,
            Some(clock_now.clone()),
        );
        parts.advance_garp_clock.set(false);
        reconcile_zero_resource(&mut parts);
        install_test_authority(&mut parts.runtime);
        let hook_calls = Rc::new(Cell::new(0));
        let hook_calls_for_test = hook_calls.clone();
        parts.runtime.promotion_test_hook = Some(Box::new(move || {
            hook_calls_for_test.set(hook_calls_for_test.get() + 1);
            clock_now.set(8_001);
        }));

        assert_eq!(
            parts.runtime.promote().unwrap(),
            ExplicitOperationResult::CleanupRequired
        );
        let snapshot = parts.runtime.snapshot().unwrap();
        assert_eq!(snapshot.node_state, NodeState::Failed);
        assert_eq!(hook_calls.get(), 1, "post-workflow hook was not reached");
        assert!(parts.runtime.controller.demotion_required());
        assert!(parts.actions.borrow().contains(&"service_stop"));
        assert!(!parts.actions.borrow().contains(&"vip_release"));
        cleanup_test_path(&parts.path);
    }

    #[test]
    fn attack_aj_unresolved_lease_release_blocks_standby_and_fresh_lease() {
        let mut parts = test_runtime(
            [RawVipObservation::Absent],
            [RawServiceObservation::Stopped],
            [],
            AuthorityMode::Conservative,
            None,
        );
        parts
            .runtime
            .mutation_store
            .begin_lease_release_for_test(Term(7), LeaseId::new("lease-1"), "cleanup".into())
            .unwrap();
        let snapshot = parts.runtime.reconcile().unwrap();
        assert_eq!(snapshot.node_state, NodeState::RecoveryPending);
        assert!(snapshot.unresolved_mutation);
        assert!(parts.runtime.ensure_lease_acquisition_eligible().is_err());
        cleanup_test_path(&parts.path);
    }

    #[test]
    fn attack_ak_repeated_promote_during_cleanup_cannot_start_again() {
        let mut parts = test_runtime(
            [
                RawVipObservation::Absent,
                RawVipObservation::Absent,
                RawVipObservation::Present,
            ],
            [
                RawServiceObservation::Stopped,
                RawServiceObservation::Stopped,
                RawServiceObservation::Running,
                RawServiceObservation::Unavailable,
            ],
            [RawHealthObservation::Unhealthy],
            AuthorityMode::Availability,
            None,
        );
        reconcile_zero_resource(&mut parts);
        install_test_authority(&mut parts.runtime);
        let first = parts.runtime.promote().unwrap();
        assert_eq!(first, ExplicitOperationResult::CleanupRequired);
        let acquire_count = parts
            .actions
            .borrow()
            .iter()
            .filter(|action| **action == "vip_acquire")
            .count();
        assert!(parts.runtime.promote().is_err());
        let second_count = parts
            .actions
            .borrow()
            .iter()
            .filter(|action| **action == "vip_acquire")
            .count();
        assert_eq!(acquire_count, second_count);
        assert_ne!(
            parts.runtime.snapshot().unwrap().node_state,
            NodeState::Active
        );
        cleanup_test_path(&parts.path);
    }

    #[test]
    fn attack_al_restart_during_incomplete_cleanup_stays_recovery_pending() {
        let mut first = test_runtime(
            [RawVipObservation::Present],
            [
                RawServiceObservation::Running,
                RawServiceObservation::Unavailable,
            ],
            [],
            AuthorityMode::Availability,
            None,
        );
        let first_snapshot = first.runtime.reconcile().unwrap();
        assert_eq!(first_snapshot.node_state, NodeState::RecoveryPending);
        let path = first.path.clone();
        drop(first);

        let mut restarted = test_runtime(
            [RawVipObservation::Present],
            [
                RawServiceObservation::Running,
                RawServiceObservation::Unavailable,
            ],
            [],
            AuthorityMode::Availability,
            None,
        );
        restarted.runtime.mutation_store = crate::node_mutation::NodeMutationStore::new(
            &path,
            ClusterId::new("cluster"),
            NodeId::new("node-a"),
        );
        let snapshot = restarted.runtime.reconcile().unwrap();
        assert_eq!(snapshot.node_state, NodeState::RecoveryPending);
        assert_eq!(snapshot.operation_phase, None);
        assert!(!snapshot.authority_present);
        assert!(
            restarted
                .runtime
                .ensure_lease_acquisition_eligible()
                .is_err()
        );
        cleanup_test_path(&path);
        cleanup_test_path(&restarted.path);
    }

    #[test]
    fn c2_d_relative_arping_path_is_rejected_without_path_search() {
        assert!(LinuxPlatformConfig::new("arping").is_err());
    }

    #[test]
    fn c2_e_invalid_absolute_arping_path_has_no_fallback() {
        let platform = LinuxPlatformConfig::new("/definitely/missing/arping").unwrap();
        let network = platform.network_config(&minimal_config()).unwrap();
        assert!(LinuxNetworkBackend::new(network).is_err());
    }

    #[test]
    fn absolute_platform_path_is_preserved_for_network_construction() {
        let config = LinuxPlatformConfig::new("/bin/true").unwrap();
        assert_eq!(config.arping_path, PathBuf::from("/bin/true"));
    }

    #[test]
    fn relative_platform_path_is_rejected_without_path_search() {
        let error = LinuxPlatformConfig::new("arping").unwrap_err();
        assert!(error.to_string().contains("absolute"));
    }

    #[test]
    fn empty_platform_path_is_rejected_without_fallback() {
        assert!(LinuxPlatformConfig::new("").is_err());
    }

    #[test]
    fn invalid_absolute_path_is_rejected_at_runtime_construction() {
        let platform = LinuxPlatformConfig::new("/definitely/missing/arping").unwrap();
        let network = platform.network_config(&minimal_config()).unwrap();
        assert!(LinuxNetworkBackend::new(network).is_err());
    }

    #[test]
    fn public_vip_schema_does_not_accept_arping_path() {
        let text = minimal_toml().replace(
            "interface = \"eth0\"",
            "interface = \"eth0\"\narping_path = \"/bin/true\"",
        );
        assert!(Config::parse_str(&text).is_err());
    }

    #[test]
    fn lease_acquisition_requires_reconciled_standby() {
        assert!(!lease_acquisition_allowed(NodeState::Init, false));
        assert!(!lease_acquisition_allowed(
            NodeState::RecoveryPending,
            false
        ));
        assert!(!lease_acquisition_allowed(NodeState::Standby, false));
        assert!(lease_acquisition_allowed(NodeState::Standby, true));
    }

    #[test]
    fn node_persistent_schema_has_no_platform_path() {
        let state = NodeMutationPersistentState {
            state_format_version: crate::node_mutation::NODE_MUTATION_STATE_FORMAT_VERSION,
            cluster_id: crate::protocol::ClusterId::new("cluster"),
            node_id: crate::protocol::NodeId::new("node-a"),
            initialization_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            highest_started_mutation_generation: 0,
            outstanding_mutation: None,
            release_obligation: None,
            highest_fencing_incident_seq: 0,
            fencing_incident: None,
        };
        let encoded = toml::to_string(&state).unwrap();
        assert!(!encoded.contains("arping_path"));
    }

    #[test]
    fn protocol_wire_schema_has_no_platform_path() {
        let envelope = UnsignedEnvelope {
            common: CommonFields {
                protocol_version: crate::protocol::PROTOCOL_VERSION,
                cluster_id: crate::protocol::ClusterId::new("cluster"),
                sender_node_id: crate::protocol::NodeId::new("node-a"),
                receiver_node_id: crate::protocol::NodeId::new("node-b"),
                session_id: SessionId::new("session"),
                sequence: Sequence(1),
                term: crate::protocol::Term(0),
                lease_id: None,
                request_id: None,
                operation_id: None,
            },
            message: ProtocolMessage::GetTerm,
        };
        let encoded = CborSerializer.serialize_unsigned(&envelope).unwrap();
        assert!(
            !encoded
                .windows(b"arping_path".len())
                .any(|w| w == b"arping_path")
        );
    }

    #[test]
    fn attack_bh_active_zero_resource_cannot_bypass_demotion() {
        let mut parts = test_runtime(
            [
                RawVipObservation::Absent,
                RawVipObservation::Absent,
                RawVipObservation::Present,
                RawVipObservation::Absent,
            ],
            [
                RawServiceObservation::Stopped,
                RawServiceObservation::Stopped,
                RawServiceObservation::Running,
                RawServiceObservation::Stopped,
                RawServiceObservation::Unavailable,
            ],
            [RawHealthObservation::Healthy],
            AuthorityMode::Availability,
            None,
        );
        reconcile_zero_resource(&mut parts);
        install_test_authority(&mut parts.runtime);
        assert_eq!(
            parts.runtime.promote().unwrap(),
            ExplicitOperationResult::Completed
        );
        assert_eq!(parts.runtime.state_machine.node_state(), NodeState::Active);
        assert!(!parts.runtime.shutdown_for_daemon(&|| true).unwrap());
        assert!(parts.actions.borrow().contains(&"service_stop"));
        assert_eq!(parts.runtime.state_machine.node_state(), NodeState::Failed);
        cleanup_test_path(&parts.path);
    }

    #[test]
    fn attack_bi_resource_owning_zero_resource_cannot_bypass_cleanup() {
        let mut parts = test_runtime(
            [RawVipObservation::Absent, RawVipObservation::Absent],
            [
                RawServiceObservation::Stopped,
                RawServiceObservation::Unavailable,
                RawServiceObservation::Running,
                RawServiceObservation::Running,
            ],
            [],
            AuthorityMode::Availability,
            None,
        );
        reconcile_zero_resource(&mut parts);
        parts.runtime.controller.mark_resource_ownership_started();
        assert!(parts.runtime.controller.resource_owning());
        assert!(!parts.runtime.shutdown_for_daemon(&|| true).unwrap());
        assert!(parts.actions.borrow().contains(&"service_stop"));
        cleanup_test_path(&parts.path);
    }

    #[test]
    fn attack_bj_non_active_non_owning_zero_resource_can_use_clean_shortcut() {
        let mut parts = test_runtime(
            [RawVipObservation::Absent],
            [RawServiceObservation::Stopped],
            [],
            AuthorityMode::Availability,
            None,
        );
        reconcile_zero_resource(&mut parts);
        assert!(parts.runtime.shutdown_for_daemon(&|| true).unwrap());
        assert!(parts.actions.borrow().is_empty());
        cleanup_test_path(&parts.path);
    }

    // -----------------------------------------------------------------
    // Stage 14 Phase 14.6 (DC-14.6-01 Option 1): pending-reap runtime
    // ownership. Real child processes stand in for a retained leader; the
    // tests themselves (never the runtime) create, signal and clean them up.
    // -----------------------------------------------------------------

    fn stage14_6_runtime() -> TestRuntimeParts {
        // The attack_bj fixture: Standby, zero resource, clean Revision 10
        // shutdown classification.
        let mut parts = test_runtime(
            [RawVipObservation::Absent],
            [RawServiceObservation::Stopped],
            [],
            AuthorityMode::Availability,
            None,
        );
        reconcile_zero_resource(&mut parts);
        parts
    }

    fn stage14_6_leader(program: &str, arguments: &[&str]) -> (std::process::Child, u32) {
        let child = std::process::Command::new(program)
            .args(arguments)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        (child, pid)
    }

    fn stage14_6_state(pid: u32) -> Option<char> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        stat.rsplit_once(") ")?.1.chars().next()
    }

    fn stage14_6_until_zombie(pid: u32) {
        let until = std::time::Instant::now() + Duration::from_secs(5);
        while stage14_6_state(pid) != Some('Z') {
            assert!(std::time::Instant::now() < until, "{pid} never exited");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn stage14_6_retain(
        runtime: &mut LinuxNodeRuntime<TestNetwork, TestService, TestClock>,
        leader: std::process::Child,
        pid: u32,
    ) {
        crate::fencing_backend::test_support::retain(
            runtime.fencing_backend_for_test(),
            leader,
            pid,
        )
        .expect("slot was empty");
    }

    fn stage14_6_view(
        runtime: &mut LinuxNodeRuntime<TestNetwork, TestService, TestClock>,
    ) -> Option<crate::fencing_backend::PendingReapView> {
        runtime
            .fencing_backend_for_test()
            .pending_reap_diagnostics()
    }

    /// The runtime owns exactly one backend with exactly one slot: it starts
    /// empty, and a second retained leader is refused as the §16.7.3
    /// invariant violation, never stored beside or over the first.
    #[test]
    fn stage14_6_runtime_owns_exactly_one_pending_reap_slot() {
        let mut parts = stage14_6_runtime();
        assert!(stage14_6_view(&mut parts.runtime).is_none());
        let (first, first_pid) = stage14_6_leader("/bin/sleep", &["30"]);
        stage14_6_retain(&mut parts.runtime, first, first_pid);
        let (second, second_pid) = stage14_6_leader("/bin/sleep", &["30"]);
        let violation = crate::fencing_backend::test_support::retain(
            parts.runtime.fencing_backend_for_test(),
            second,
            second_pid,
        )
        .unwrap_err();
        assert_eq!(violation.existing_pid, first_pid);
        assert!(
            violation
                .into_observation_invariant()
                .contains(&format!("rejected pid {second_pid}"))
        );
        assert_eq!(stage14_6_view(&mut parts.runtime).unwrap().pid, first_pid);
        for pid in [first_pid, second_pid] {
            unsafe { libc::kill(pid as i32, libc::SIGKILL) };
        }
        stage14_6_until_zombie(first_pid);
        parts.runtime.poll_pending_reap_foreground();
        assert!(stage14_6_view(&mut parts.runtime).is_none());
        let mut status = 0;
        unsafe { libc::waitpid(second_pid as i32, &mut status, 0) };
        cleanup_test_path(&parts.path);
    }

    /// §16.7.8 conjunct on the real owner (PR-07 runtime part):
    /// - empty slot: the unchanged Revision 10 result (clean here);
    /// - occupied by a running leader: never clean, one poll per shutdown
    ///   classification, and the leader is neither signalled nor waited on;
    /// - leader reapable: the shutdown poll clears the slot, and clean again;
    /// - poll error (ECHILD after an external reap): the slot stays and
    ///   shutdown stays non-clean (fail closed).
    #[test]
    fn stage14_6_shutdown_requires_an_empty_pending_reap_slot() {
        let mut parts = stage14_6_runtime();
        assert!(parts.runtime.shutdown_for_daemon(&|| true).unwrap());
        assert!(parts.actions.borrow().is_empty());

        let (leader, pid) = stage14_6_leader("/bin/sleep", &["30"]);
        stage14_6_retain(&mut parts.runtime, leader, pid);
        assert!(!parts.runtime.shutdown_for_daemon(&|| true).unwrap());
        assert!(!parts.runtime.shutdown_for_daemon(&|| true).unwrap());
        let view = stage14_6_view(&mut parts.runtime).unwrap();
        assert_eq!(view.pid, pid);
        assert_eq!(
            view.polls, 2,
            "exactly one poll per shutdown classification"
        );
        assert_eq!(view.last_poll, crate::fencing_backend::LastPoll::NotReaped);
        assert_eq!(
            stage14_6_state(pid).map(|state| state != 'Z'),
            Some(true),
            "not signalled"
        );
        assert!(parts.actions.borrow().is_empty());

        unsafe { libc::kill(pid as i32, libc::SIGKILL) };
        stage14_6_until_zombie(pid);
        assert!(parts.runtime.shutdown_for_daemon(&|| true).unwrap());
        assert!(stage14_6_view(&mut parts.runtime).is_none());
        assert_eq!(stage14_6_state(pid), None, "reaped by the shutdown poll");

        let (leader, pid) = stage14_6_leader("/bin/true", &[]);
        stage14_6_until_zombie(pid);
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid as i32, &mut status, 0) },
            pid as i32
        );
        stage14_6_retain(&mut parts.runtime, leader, pid);
        assert!(!parts.runtime.shutdown_for_daemon(&|| true).unwrap());
        let view = stage14_6_view(&mut parts.runtime).unwrap();
        assert_eq!(
            view.last_poll,
            crate::fencing_backend::LastPoll::Error(libc::ECHILD)
        );
        assert!(
            !parts.runtime.shutdown_for_daemon(&|| true).unwrap(),
            "never clean"
        );
        cleanup_test_path(&parts.path);
    }

    /// PR-07: the shutdown classification polls the slot exactly once even
    /// when a Revision 10 condition makes it non-clean early (here the
    /// attack_bi resource-owning fixture). A leader that became reapable is
    /// reaped by that poll; the verdict stays the Revision 10 non-clean one.
    #[test]
    fn stage14_6_shutdown_polls_even_when_revision_10_returns_early() {
        let mut parts = test_runtime(
            [RawVipObservation::Absent, RawVipObservation::Absent],
            [
                RawServiceObservation::Stopped,
                RawServiceObservation::Unavailable,
                RawServiceObservation::Running,
                RawServiceObservation::Running,
            ],
            [],
            AuthorityMode::Availability,
            None,
        );
        reconcile_zero_resource(&mut parts);
        parts.runtime.controller.mark_resource_ownership_started();
        let (leader, pid) = stage14_6_leader("/bin/true", &[]);
        stage14_6_until_zombie(pid);
        stage14_6_retain(&mut parts.runtime, leader, pid);
        assert!(!parts.runtime.shutdown_for_daemon(&|| true).unwrap());
        assert!(
            stage14_6_view(&mut parts.runtime).is_none(),
            "the shutdown poll ran before the Revision 10 early return"
        );
        assert_eq!(stage14_6_state(pid), None);
        cleanup_test_path(&parts.path);
    }

    const STAGE14_6_EMISSION_PROBE: &str = "MIKAGAMI_STAGE14_6_EMISSION_PROBE";

    /// Child half of `stage14_6_runtime_glue_emits_pending_reap_diagnostics`.
    /// The parent runs it in a separate process so that the production
    /// glue's real stderr lines can be read. It drives the three §16.7.8 /
    /// §28 lines through the real owner: a foreground clear (INFO), a
    /// foreground errno transition (WARN), and the shutdown occupied WARN.
    #[test]
    #[ignore = "child process of stage14_6_runtime_glue_emits_pending_reap_diagnostics"]
    fn stage14_6_emission_probe_child() {
        assert!(
            std::env::var_os(STAGE14_6_EMISSION_PROBE).is_some(),
            "run only by the parent test"
        );
        let mut parts = stage14_6_runtime();
        let (cleared, cleared_pid) = stage14_6_leader("/bin/true", &[]);
        stage14_6_until_zombie(cleared_pid);
        stage14_6_retain(&mut parts.runtime, cleared, cleared_pid);
        parts.runtime.poll_pending_reap_foreground();

        let (lost, lost_pid) = stage14_6_leader("/bin/true", &[]);
        stage14_6_until_zombie(lost_pid);
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(lost_pid as i32, &mut status, 0) },
            lost_pid as i32
        );
        stage14_6_retain(&mut parts.runtime, lost, lost_pid);
        parts.runtime.poll_pending_reap_foreground();
        assert!(!parts.runtime.shutdown_for_daemon(&|| true).unwrap());
        println!("stage14_6-probe cleared={cleared_pid} lost={lost_pid}");
        cleanup_test_path(&parts.path);
    }

    /// F14.6-02: the runtime glue emits every pending-reap diagnostic line
    /// the backend returns, in the daemon's `mikagami: ` log form, with the
    /// §16.7.8 identifying fields. It reads the real stderr of the child test.
    #[test]
    fn stage14_6_runtime_glue_emits_pending_reap_diagnostics() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "linux_node_runtime::tests::stage14_6_emission_probe_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(STAGE14_6_EMISSION_PROBE, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stdout}\n{stderr}");
        // libtest prints `test <name> ... ` without a newline under
        // --nocapture, so the marker can follow it on the same line.
        let probe = stdout
            .lines()
            .find_map(|line| line.split("stage14_6-probe ").nth(1))
            .unwrap_or_else(|| panic!("child probe did not run:\n{stdout}\n{stderr}"));
        let pid = |name: &str| -> u32 {
            probe
                .split(' ')
                .find_map(|pair| pair.strip_prefix(name))
                .unwrap()
                .parse()
                .unwrap()
        };
        let (cleared, lost) = (pid("cleared="), pid("lost="));
        let lines: Vec<&str> = stderr
            .lines()
            .filter(|line| line.contains("pending_reap"))
            .collect();
        assert_eq!(lines.len(), 3, "{stderr}");
        let common = "kind=Verify incident_seq=7 attempt_token=3";
        assert!(
            lines[0].starts_with(&format!(
                "mikagami: INFO pending_reap cleared: leader reaped with Code(0) (pending_present=false {common} pid={cleared} age_ms="
            )),
            "{}",
            lines[0]
        );
        assert!(
            lines[1].starts_with(&format!(
                "mikagami: WARN pending_reap poll error errno {}; the slot stays occupied (pending_present=true {common} pid={lost} age_ms=",
                libc::ECHILD
            )),
            "{}",
            lines[1]
        );
        assert!(
            lines[2].starts_with(&format!(
                "mikagami: WARN shutdown requires cleanup: pending_reap_occupied; the retained fencing leader is not reaped, so shutdown cannot be clean (pending_present=true {common} pid={lost} age_ms="
            )),
            "{}",
            lines[2]
        );
        for line in &lines[1..] {
            assert!(
                line.ends_with(&format!("last_poll=Error({}))", libc::ECHILD)),
                "{line}"
            );
        }
        for line in &lines {
            assert!(
                !line.contains("5f0c6a8e-3c1b-4c55-9a47-2f6f5e1d9b10"),
                "{line}"
            );
        }
    }

    /// PR-04 runtime part: each foreground call is one non-blocking poll; a
    /// running leader stays retained and unsignalled; an exited leader whose
    /// same-group descendant still runs is reaped (the slot owns only the
    /// leader; in a real step the Finalization group SIGKILL precedes any
    /// transfer).
    #[test]
    fn stage14_6_foreground_poll_on_the_real_owner() {
        let mut parts = stage14_6_runtime();
        for _ in 0..5 {
            parts.runtime.poll_pending_reap_foreground();
        }
        assert!(stage14_6_view(&mut parts.runtime).is_none());

        let (leader, pid) = stage14_6_leader("/bin/sleep", &["30"]);
        stage14_6_retain(&mut parts.runtime, leader, pid);
        for _ in 0..5 {
            parts.runtime.poll_pending_reap_foreground();
        }
        let view = stage14_6_view(&mut parts.runtime).unwrap();
        assert_eq!((view.pid, view.polls), (pid, 5));
        assert_ne!(stage14_6_state(pid), Some('Z'));
        unsafe { libc::kill(pid as i32, libc::SIGKILL) };
        stage14_6_until_zombie(pid);
        parts.runtime.poll_pending_reap_foreground();
        assert!(stage14_6_view(&mut parts.runtime).is_none());

        let pidfile =
            std::env::temp_dir().join(format!("mikagami-14.6-desc-{}", std::process::id()));
        let (leader, pid) = stage14_6_leader(
            "/bin/sh",
            &[
                "-c",
                "sleep 30 & echo $! > \"$1\"; exit 0",
                "leader",
                pidfile.to_str().unwrap(),
            ],
        );
        stage14_6_until_zombie(pid);
        let descendant: i32 = std::fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        stage14_6_retain(&mut parts.runtime, leader, pid);
        parts.runtime.poll_pending_reap_foreground();
        assert!(stage14_6_view(&mut parts.runtime).is_none());
        unsafe { libc::kill(descendant, libc::SIGKILL) };
        let _ = std::fs::remove_file(&pidfile);
        cleanup_test_path(&parts.path);
    }

    #[test]
    fn stage13_6_exact_retry_reuses_m_without_second_begin() {
        use crate::security::{MessageAuthenticator, Psk};
        use crate::session::ProcessSession;
        use crate::tcp::TcpConnection;
        use crate::witness_runtime::{
            WitnessConnection, WitnessResponseContext, send_witness_response_with_context,
        };
        use std::net::{TcpListener, TcpStream};
        use std::thread;

        let clock = Rc::new(Cell::new(0));
        let mut parts = test_runtime(
            [RawVipObservation::Absent],
            [RawServiceObservation::Stopped],
            [],
            AuthorityMode::Conservative,
            Some(clock),
        );
        reconcile_zero_resource(&mut parts);
        install_test_authority(&mut parts.runtime);
        parts.runtime.controller.mark_resource_ownership_started();
        parts
            .runtime
            .mutation_store
            .arm_release_obligation(Term(7), LeaseId::new("lease-1"))
            .unwrap();
        let first = parts
            .runtime
            .mutation_store
            .begin_lease_renew(Term(7), LeaseId::new("lease-1"))
            .unwrap();
        let calls = parts
            .runtime
            .mutation_store
            .lease_renew_begin_calls_for_test();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let node = WitnessConnection::new(
            NodeId::new("node-a"),
            NodeId::new("witness"),
            ClusterId::new("cluster"),
            SessionId::new("session-w"),
            TcpConnection::from_stream(client, Duration::from_secs(2), Duration::from_secs(2))
                .unwrap(),
        );
        let mut witness = WitnessConnection::new(
            NodeId::new("witness"),
            NodeId::new("node-a"),
            ClusterId::new("cluster"),
            SessionId::new("session-a"),
            TcpConnection::from_stream(server, Duration::from_secs(2), Duration::from_secs(2))
                .unwrap(),
        );
        let server_thread = thread::spawn(move || {
            let auth = MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32]));
            let pending = witness.receive_pending(&CborSerializer, &auth).unwrap();
            let request_id = pending
                .message()
                .unsigned()
                .common
                .request_id
                .clone()
                .unwrap();
            send_witness_response_with_context(
                &mut witness,
                &mut ProcessSession::from_session_id(SessionId::new("session-w")),
                request_id,
                ProtocolMessage::LeaseRenewed(LeaseGrantPayload {
                    term: Term(7),
                    lease_id: LeaseId::new("lease-1"),
                    holder_node_id: NodeId::new("node-a"),
                    lease_ttl_ms: DurationMs(10_000),
                    renew_after_ms: DurationMs(3_000),
                    lease_remaining_ms: DurationMs(10_000),
                }),
                WitnessResponseContext {
                    term: Term(7),
                    lease_id: Some(LeaseId::new("lease-1")),
                },
                &CborSerializer,
                &auth,
            )
            .unwrap();
        });
        let mut session = WitnessSession::new(
            node,
            ProcessSession::from_session_id(SessionId::new("session-a")),
            MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32])),
        );
        let result = parts
            .runtime
            .renew_lease_once(&mut session, || Ok(()))
            .unwrap();
        server_thread.join().unwrap();
        assert!(matches!(
            result,
            NodeWitnessMutationResult::AcceptedSuccess { .. }
        ));
        assert_eq!(
            parts
                .runtime
                .mutation_store
                .lease_renew_begin_calls_for_test(),
            calls,
            "second begin_lease_renew call count"
        );
        assert_eq!(parts.runtime.mutation_store.outstanding().unwrap(), None);
        assert_eq!(first.mutation_generation, 1);
        cleanup_test_path(&parts.path);
    }

    // ---- Stage 13.6 focused-remediation regression tests.
    //
    // These assert the Stage 13.6 focused remediation against the authoritative
    // contract `MIKAGAMI_STAGE_13_6_DESIGN.md` **Revision 10**.  The
    // `remediation` prefix names the remediation round, not a design revision;
    // there is no Design Revision 11.  Canonical Revision 10 test names are
    // deliberately left unchanged.

    /// A-1: the third LeaseRelease transmission path
    /// (`execute_durable_witness_mutation_once`) must re-verify trusted
    /// ZeroResource.  A real peer thread stands ready to answer, so a PASS
    /// cannot come from an unrelated early failure: if the gate were absent
    /// the fixture would receive and answer a real LeaseRelease and
    /// `saw_release` would be set.
    #[test]
    fn stage13_6_remediation_durable_release_send_requires_trusted_zero_resource() {
        use crate::security::{MessageAuthenticator, Psk};
        use crate::session::ProcessSession;
        use crate::tcp::TcpConnection;
        use crate::witness_runtime::WitnessConnection;
        use std::net::{TcpListener, TcpStream};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Duration;

        // VIP present and service running: local protected resources are NOT
        // ZeroResource, so trusted cleanup cannot verify absence and the gate
        // must fail closed.  The observation queues are left in that state so
        // no incidental reconcile can make the node look clean.
        let mut parts = test_runtime(
            [RawVipObservation::Present],
            [RawServiceObservation::Running],
            [],
            AuthorityMode::Conservative,
            None,
        );
        // A durable LeaseRelease for (Term 7, lease-1) already exists.
        parts
            .runtime
            .mutation_store
            .arm_release_obligation(Term(7), LeaseId::new("lease-1"))
            .unwrap();
        parts
            .runtime
            .mutation_store
            .begin_lease_release_for_test(Term(7), LeaseId::new("lease-1"), "a-1".into())
            .unwrap();
        let before = parts
            .runtime
            .mutation_store
            .outstanding()
            .unwrap()
            .expect("durable LeaseRelease must exist before the gated send");

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let saw_release = Arc::new(AtomicBool::new(false));
        let saw_flag = saw_release.clone();
        let server_thread = std::thread::spawn(move || {
            use crate::witness_runtime::WitnessResponseContext;
            use crate::witness_runtime::send_witness_response_with_context;
            let auth = MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32]));
            let mut witness = WitnessConnection::new(
                NodeId::new("witness"),
                NodeId::new("node-a"),
                ClusterId::new("cluster"),
                SessionId::new("session-a"),
                TcpConnection::from_stream(server, Duration::from_secs(2), Duration::from_secs(2))
                    .unwrap(),
            );
            // Block briefly: if the gate is absent a LeaseRelease arrives and
            // this records it; if the gate holds, nothing is ever sent.
            match witness.receive_pending(&CborSerializer, &auth) {
                Ok(pending) => {
                    let kind_is_release = matches!(
                        pending.message().unsigned().message,
                        ProtocolMessage::LeaseRelease { .. }
                    );
                    saw_flag.store(kind_is_release, Ordering::SeqCst);
                    if let Some(request_id) = pending.message().unsigned().common.request_id.clone()
                    {
                        let _ = send_witness_response_with_context(
                            &mut witness,
                            &mut ProcessSession::from_session_id(SessionId::new("session-w")),
                            request_id,
                            ProtocolMessage::LeaseReleased(crate::protocol::LeaseReleasedPayload {
                                term: Term(7),
                                lease_id: LeaseId::new("lease-1"),
                                result: "released".into(),
                            }),
                            WitnessResponseContext {
                                term: Term(7),
                                lease_id: Some(LeaseId::new("lease-1")),
                            },
                            &CborSerializer,
                            &auth,
                        );
                    }
                }
                Err(_) => {}
            }
        });

        let node = WitnessConnection::new(
            NodeId::new("node-a"),
            NodeId::new("witness"),
            ClusterId::new("cluster"),
            SessionId::new("session-w"),
            TcpConnection::from_stream(
                client,
                Duration::from_millis(500),
                Duration::from_millis(500),
            )
            .unwrap(),
        );
        let mut session = WitnessSession::new(
            node,
            ProcessSession::from_session_id(SessionId::new("session-a")),
            MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32])),
        );

        // Exactly the previously-ungated production path.
        let result = parts
            .runtime
            .execute_durable_witness_mutation_once(&mut session);
        assert!(
            matches!(
                result,
                Err(LinuxNodeRuntimeError::Authority(
                    AuthorityError::RecoveryBlocked
                ))
            ),
            "gate must fail closed with RecoveryBlocked, got {result:?}"
        );
        // No Release was transmitted, and no accepted response was fabricated.
        assert!(!session.request_in_flight());
        let _ = server_thread.join();
        // F-04: assert the fixture's own wire signal, not just the return type.
        // A live peer stood ready to receive and answer, so `saw_release`
        // staying false is a positive proof that no LeaseRelease frame reached
        // the wire — the same flag the A-2 resource-present test asserts. If the
        // ZeroResource gate were removed the peer would set this flag, so the
        // assertion is falsifying rather than decorative.
        assert!(
            !saw_release.load(Ordering::SeqCst),
            "no LeaseRelease may reach the wire while a protected resource is present"
        );

        // O and M are retained exactly; no second begin occurred.
        assert!(parts.runtime.release_obligation().unwrap().is_some());
        let after = parts
            .runtime
            .mutation_store
            .outstanding()
            .unwrap()
            .expect("durable LeaseRelease must be retained");
        assert_eq!(after.request_id, before.request_id);
        assert_eq!(after.mutation_generation, before.mutation_generation);
        assert_eq!(
            after.kind(),
            crate::node_mutation::MutationKind::LeaseRelease
        );
        cleanup_test_path(&parts.path);
    }

    #[test]
    fn stage13_6_remediation_release_requires_trusted_zero_resource() {
        use crate::security::{MessageAuthenticator, Psk};
        use crate::session::ProcessSession;
        use crate::tcp::TcpConnection;
        use crate::witness_runtime::WitnessConnection;
        use std::net::{TcpListener, TcpStream};
        use std::time::Duration;

        let mut parts = test_runtime(
            [RawVipObservation::Present],
            [RawServiceObservation::Running],
            [],
            AuthorityMode::Conservative,
            None,
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        drop(server);
        let node = WitnessConnection::new(
            NodeId::new("node-a"),
            NodeId::new("witness"),
            ClusterId::new("cluster"),
            SessionId::new("session-w"),
            TcpConnection::from_stream(client, Duration::from_secs(2), Duration::from_secs(2))
                .unwrap(),
        );
        let mut session = WitnessSession::new(
            node,
            ProcessSession::from_session_id(SessionId::new("session-a")),
            MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32])),
        );
        let result = parts.runtime.release_attempt_lease_once(
            &mut session,
            Term(7),
            LeaseId::new("lease-1"),
            "test".into(),
            None,
        );
        assert!(matches!(
            result,
            Err(LinuxNodeRuntimeError::Authority(
                AuthorityError::RecoveryBlocked
            ))
        ));
        assert!(parts.runtime.release_obligation().unwrap().is_none());
        assert!(
            parts
                .runtime
                .durable_witness_outstanding()
                .unwrap()
                .is_none()
        );
        cleanup_test_path(&parts.path);
    }

    #[test]
    fn stage13_6_remediation_arm_requires_trusted_zero_resource() {
        let mut parts = test_runtime(
            [RawVipObservation::Present],
            [RawServiceObservation::Running],
            [],
            AuthorityMode::Conservative,
            None,
        );
        install_test_authority(&mut parts.runtime);
        let authority = parts.runtime.take_installed_lease_authority().unwrap();
        let clearance = stage14_10_confirmed_clearance(&parts.runtime, Term(6));
        assert!(
            parts
                .runtime
                .arm_and_promote(authority, &clearance)
                .is_err()
        );
        assert!(parts.runtime.release_obligation().unwrap().is_none());
        assert!(
            parts
                .runtime
                .durable_witness_outstanding()
                .unwrap()
                .is_none()
        );
        assert!(parts.actions.borrow().is_empty());
        cleanup_test_path(&parts.path);
    }

    #[test]
    fn stage13_6_remediation_release_transport_error_retains_m_and_does_not_fail_lifecycle() {
        use crate::security::{MessageAuthenticator, Psk};
        use crate::session::ProcessSession;
        use crate::tcp::TcpConnection;
        use crate::witness_runtime::WitnessConnection;
        use std::net::{TcpListener, TcpStream};
        use std::time::Duration;

        let mut parts = test_runtime(
            [RawVipObservation::Absent],
            [RawServiceObservation::Stopped],
            [],
            AuthorityMode::Conservative,
            None,
        );
        parts.runtime.reconcile().unwrap();
        parts
            .runtime
            .state_machine
            .transition_to(NodeState::QuorumUnknown)
            .unwrap();
        parts
            .runtime
            .state_machine
            .transition_to(NodeState::Failed)
            .unwrap();
        parts.runtime.state_machine.reset_for_recovery().unwrap();
        parts
            .runtime
            .mutation_store
            .arm_release_obligation(Term(7), LeaseId::new("lease-1"))
            .unwrap();
        parts
            .runtime
            .mutation_store
            .begin_lease_release_for_test(Term(7), LeaseId::new("lease-1"), "test".into())
            .unwrap();
        parts
            .runtime
            .state_machine
            .begin_recovery_cleanup()
            .unwrap();
        for _ in 0..4 {
            parts.runtime.state_machine.advance_demotion().unwrap();
        }

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        drop(server);
        let node = WitnessConnection::new(
            NodeId::new("node-a"),
            NodeId::new("witness"),
            ClusterId::new("cluster"),
            SessionId::new("session-w"),
            TcpConnection::from_stream(client, Duration::from_secs(2), Duration::from_secs(2))
                .unwrap(),
        );
        let mut session = WitnessSession::new(
            node,
            ProcessSession::from_session_id(SessionId::new("session-a")),
            MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32])),
        );
        parts
            .runtime
            .drive_foreground_lifecycle(&mut session, &|| false, &|| true)
            .unwrap();
        assert!(parts.runtime.state_machine.operation_phase().is_some());
        assert!(parts.runtime.release_obligation().unwrap().is_some());
        assert!(
            parts
                .runtime
                .durable_witness_outstanding()
                .unwrap()
                .is_some()
        );
        cleanup_test_path(&parts.path);
    }

    #[test]
    fn stage13_6_remediation_release_clear_reconciles_controller_before_standby() {
        use crate::security::{MessageAuthenticator, Psk};
        use crate::session::ProcessSession;
        use crate::tcp::TcpConnection;
        use crate::witness_runtime::WitnessResponseContext;
        use crate::witness_runtime::{WitnessConnection, send_witness_response_with_context};
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        use std::time::Duration;

        let mut parts = test_runtime(
            [RawVipObservation::Absent],
            [RawServiceObservation::Stopped],
            [],
            AuthorityMode::Conservative,
            None,
        );
        parts.runtime.reconcile().unwrap();
        parts
            .runtime
            .state_machine
            .transition_to(NodeState::QuorumUnknown)
            .unwrap();
        parts
            .runtime
            .state_machine
            .transition_to(NodeState::Failed)
            .unwrap();
        parts.runtime.state_machine.reset_for_recovery().unwrap();
        parts
            .runtime
            .mutation_store
            .arm_release_obligation(Term(7), LeaseId::new("lease-1"))
            .unwrap();
        parts
            .runtime
            .mutation_store
            .begin_lease_release_for_test(Term(7), LeaseId::new("lease-1"), "test".into())
            .unwrap();
        parts
            .runtime
            .state_machine
            .begin_recovery_cleanup()
            .unwrap();
        for _ in 0..4 {
            parts.runtime.state_machine.advance_demotion().unwrap();
        }

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let mut witness = WitnessConnection::new(
            NodeId::new("witness"),
            NodeId::new("node-a"),
            ClusterId::new("cluster"),
            SessionId::new("session-a"),
            TcpConnection::from_stream(server, Duration::from_secs(2), Duration::from_secs(2))
                .unwrap(),
        );
        let server_thread = thread::spawn(move || {
            let auth = MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32]));
            let pending = witness.receive_pending(&CborSerializer, &auth).unwrap();
            let request_id = pending
                .message()
                .unsigned()
                .common
                .request_id
                .clone()
                .unwrap();
            send_witness_response_with_context(
                &mut witness,
                &mut ProcessSession::from_session_id(SessionId::new("session-w")),
                request_id,
                ProtocolMessage::LeaseReleased(crate::protocol::LeaseReleasedPayload {
                    term: Term(7),
                    lease_id: LeaseId::new("lease-1"),
                    result: "released".into(),
                }),
                WitnessResponseContext {
                    term: Term(7),
                    lease_id: Some(LeaseId::new("lease-1")),
                },
                &CborSerializer,
                &auth,
            )
            .unwrap();
        });
        let node = WitnessConnection::new(
            NodeId::new("node-a"),
            NodeId::new("witness"),
            ClusterId::new("cluster"),
            SessionId::new("session-w"),
            TcpConnection::from_stream(client, Duration::from_secs(2), Duration::from_secs(2))
                .unwrap(),
        );
        let mut session = WitnessSession::new(
            node,
            ProcessSession::from_session_id(SessionId::new("session-a")),
            MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32])),
        );
        parts
            .runtime
            .drive_foreground_lifecycle(&mut session, &|| false, &|| true)
            .unwrap();
        server_thread.join().unwrap();
        assert_eq!(parts.runtime.state_machine.node_state(), NodeState::Standby);
        assert!(parts.runtime.controller.recovery_reconciled());
        assert!(!parts.runtime.controller.demotion_required());
        assert!(parts.runtime.installed_lease_authority().is_none());
        assert!(parts.runtime.release_obligation().unwrap().is_none());
        assert!(
            parts
                .runtime
                .durable_witness_outstanding()
                .unwrap()
                .is_none()
        );
        assert!(parts.runtime.ensure_lease_acquisition_eligible().is_ok());
        cleanup_test_path(&parts.path);
    }

    /// F-01: the H4 post-CLEAR precondition is genuinely fail-closed.
    ///
    /// The independent re-audit proved (MUTATION D) that the existing
    /// `..._release_clear_reconciles_controller_before_standby` fixture could
    /// not falsify removal of the post-CLEAR precondition block, because
    /// `recovery_reconciled()` was already true before the code under test
    /// ran.  This fixture removes that blind spot:
    ///
    ///   * it begins with `recovery_reconciled() == false` — `reconcile()` is
    ///     never called, so the controller stays in `RecoveryState::Blocked`;
    ///   * the exact owned Release genuinely succeeds, so the durable atomic
    ///     CLEAR really does commit (this is not a transport failure);
    ///   * the post-CLEAR precondition is then made to FAIL, by handing the
    ///     second ZeroResource re-verification a service that refuses to stop.
    ///     `cleanup_local_resources_inner` consumes exactly one service and one
    ///     VIP observation per call, so the `[Stopped, Running]` service queue
    ///     makes the pre-transmission gate (line 1029) pass and the post-CLEAR
    ///     re-check (line 1041) fail.
    ///
    /// Design Revision 10 §7 requires controller ZeroResource reconciliation
    /// and Standby commit to *follow* CLEAR, and §14.1 UA-1 requires that an
    /// injected reconcile failure assert blocked/recovery behaviour "rather
    /// than inferred Standby".  Removing the post-CLEAR block makes this test
    /// reach `complete_demotion()` and publish Standby, so the assertions
    /// below genuinely falsify the omission.
    #[test]
    fn stage13_6_remediation_post_clear_reconcile_failure_never_infers_standby() {
        use crate::security::{MessageAuthenticator, Psk};
        use crate::session::ProcessSession;
        use crate::tcp::TcpConnection;
        use crate::witness_runtime::WitnessResponseContext;
        use crate::witness_runtime::{WitnessConnection, send_witness_response_with_context};
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        use std::time::Duration;

        // One observation per ZeroResource re-verification: the first is
        // consumed by the pre-transmission gate, the second by the post-CLEAR
        // re-check and is poisoned to force that check to fail closed.
        let mut parts = test_runtime(
            [RawVipObservation::Absent],
            [
                RawServiceObservation::Stopped,
                RawServiceObservation::Running,
            ],
            [],
            AuthorityMode::Conservative,
            None,
        );
        // Deliberately no `reconcile()`: the controller must still be
        // unreconciled when the post-CLEAR precondition is evaluated.
        assert!(
            !parts.runtime.controller.recovery_reconciled(),
            "fixture must begin unreconciled or it cannot falsify the omission"
        );
        // Reach the post-cleanup ReleaseLease phase without publishing Standby.
        parts
            .runtime
            .state_machine
            .transition_to(NodeState::RecoveryPending)
            .unwrap();
        parts
            .runtime
            .mutation_store
            .arm_release_obligation(Term(7), LeaseId::new("lease-1"))
            .unwrap();
        parts
            .runtime
            .mutation_store
            .begin_lease_release_for_test(Term(7), LeaseId::new("lease-1"), "f-01".into())
            .unwrap();
        parts
            .runtime
            .state_machine
            .begin_recovery_cleanup()
            .unwrap();
        for _ in 0..4 {
            parts.runtime.state_machine.advance_demotion().unwrap();
        }
        assert_eq!(
            parts.runtime.state_machine.operation_phase(),
            Some(OperationPhase::Demotion(
                crate::state_machine::DemotionPhase::ReleaseLease
            ))
        );
        assert!(!parts.runtime.controller.recovery_reconciled());

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let mut witness = WitnessConnection::new(
            NodeId::new("witness"),
            NodeId::new("node-a"),
            ClusterId::new("cluster"),
            SessionId::new("session-a"),
            TcpConnection::from_stream(server, Duration::from_secs(2), Duration::from_secs(2))
                .unwrap(),
        );
        let server_thread = thread::spawn(move || {
            let auth = MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32]));
            let pending = witness.receive_pending(&CborSerializer, &auth).unwrap();
            let request_id = pending
                .message()
                .unsigned()
                .common
                .request_id
                .clone()
                .unwrap();
            send_witness_response_with_context(
                &mut witness,
                &mut ProcessSession::from_session_id(SessionId::new("session-w")),
                request_id,
                ProtocolMessage::LeaseReleased(crate::protocol::LeaseReleasedPayload {
                    term: Term(7),
                    lease_id: LeaseId::new("lease-1"),
                    result: "released".into(),
                }),
                WitnessResponseContext {
                    term: Term(7),
                    lease_id: Some(LeaseId::new("lease-1")),
                },
                &CborSerializer,
                &auth,
            )
            .unwrap();
        });
        let node = WitnessConnection::new(
            NodeId::new("node-a"),
            NodeId::new("witness"),
            ClusterId::new("cluster"),
            SessionId::new("session-w"),
            TcpConnection::from_stream(
                client,
                Duration::from_millis(500),
                Duration::from_millis(500),
            )
            .unwrap(),
        );
        let mut session = WitnessSession::new(
            node,
            ProcessSession::from_session_id(SessionId::new("session-a")),
            MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32])),
        );

        let result = parts
            .runtime
            .execute_pending_witness_mutation_once(&mut session);
        server_thread.join().unwrap();

        // The Release itself genuinely succeeded, so the durable CLEAR is real
        // and is not being asserted away: this is not a transport-failure case.
        assert!(
            matches!(
                result,
                Ok(NodeWitnessMutationResult::AcceptedSuccess {
                    response: crate::node_lease_authority::node_witness_runtime::NodeWitnessSuccess::LeaseReleased(_),
                    ..
                })
            ),
            "the exact owned Release must succeed so the CLEAR really commits, got {result:?}"
        );
        assert!(parts.runtime.release_obligation().unwrap().is_none());
        assert!(
            parts
                .runtime
                .durable_witness_outstanding()
                .unwrap()
                .is_none()
        );

        // H4: the post-CLEAR precondition failed, so Standby must NOT be
        // inferred or published. This is the assertion that fails if the
        // post-CLEAR block is removed.
        assert_eq!(
            parts.runtime.state_machine.node_state(),
            NodeState::Failed,
            "a failed post-CLEAR precondition must block, never infer Standby"
        );
        assert_ne!(parts.runtime.state_machine.node_state(), NodeState::Standby);
        // Reconciliation is still not complete, so recovery stays blocked.
        assert!(
            !parts.runtime.controller.recovery_reconciled(),
            "recovery must remain unreconciled until controller reconciliation completes"
        );
        // No promotion eligibility may be exposed.
        assert!(
            parts.runtime.ensure_lease_acquisition_eligible().is_err(),
            "an unreconciled, failed lifecycle must not expose promotion eligibility"
        );
        // H6 is not weakened: this lifecycle is not cleanly shut down.
        assert!(!parts.runtime.shutdown_for_daemon(&|| true).unwrap());
        cleanup_test_path(&parts.path);
    }

    #[test]
    fn stage13_6_remediation_shutdown_with_unresolved_obligation_is_not_clean() {
        let mut parts = test_runtime(
            [RawVipObservation::Absent],
            [RawServiceObservation::Stopped],
            [],
            AuthorityMode::Conservative,
            None,
        );
        reconcile_zero_resource(&mut parts);
        parts
            .runtime
            .mutation_store
            .arm_release_obligation(Term(7), LeaseId::new("lease-1"))
            .unwrap();
        assert!(!parts.runtime.shutdown_for_daemon(&|| true).unwrap());
        assert!(parts.runtime.release_obligation().unwrap().is_some());
        cleanup_test_path(&parts.path);
    }

    #[test]
    fn stage13_6_remediation_shutdown_with_unresolved_mutation_is_not_clean() {
        let mut parts = test_runtime(
            [RawVipObservation::Absent],
            [RawServiceObservation::Stopped],
            [],
            AuthorityMode::Conservative,
            None,
        );
        reconcile_zero_resource(&mut parts);
        parts
            .runtime
            .mutation_store
            .begin_lease_request(Term(7), 100, DurationMs(10_000))
            .unwrap();
        assert!(!parts.runtime.shutdown_for_daemon(&|| true).unwrap());
        assert!(
            parts
                .runtime
                .durable_witness_outstanding()
                .unwrap()
                .is_some()
        );
        cleanup_test_path(&parts.path);
    }

    /// A-2 Test A: a durably-begun, eligible LeaseRelease plus shutdown.
    /// Exactly one bounded step runs, the exact Release completes, the
    /// controller reconciles, and only then may shutdown classify clean.
    #[test]
    fn stage13_6_remediation_shutdown_bounded_step_completes_eligible_release() {
        use crate::security::{MessageAuthenticator, Psk};
        use crate::session::ProcessSession;
        use crate::tcp::TcpConnection;
        use crate::witness_runtime::WitnessConnection;
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        use std::time::Duration;

        let mut parts = test_runtime(
            [RawVipObservation::Absent],
            [RawServiceObservation::Stopped],
            [],
            AuthorityMode::Conservative,
            None,
        );
        parts.runtime.reconcile().unwrap();
        parts
            .runtime
            .state_machine
            .transition_to(NodeState::QuorumUnknown)
            .unwrap();
        parts
            .runtime
            .state_machine
            .transition_to(NodeState::Failed)
            .unwrap();
        parts.runtime.state_machine.reset_for_recovery().unwrap();
        parts
            .runtime
            .mutation_store
            .arm_release_obligation(Term(7), LeaseId::new("lease-1"))
            .unwrap();
        let begun = parts
            .runtime
            .mutation_store
            .begin_lease_release_for_test(Term(7), LeaseId::new("lease-1"), "a-2".into())
            .unwrap();
        parts
            .runtime
            .state_machine
            .begin_recovery_cleanup()
            .unwrap();
        for _ in 0..4 {
            parts.runtime.state_machine.advance_demotion().unwrap();
        }
        assert_eq!(
            parts.runtime.state_machine.operation_phase(),
            Some(OperationPhase::Demotion(
                crate::state_machine::DemotionPhase::ReleaseLease
            ))
        );

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let mut witness = WitnessConnection::new(
            NodeId::new("witness"),
            NodeId::new("node-a"),
            ClusterId::new("cluster"),
            SessionId::new("session-a"),
            TcpConnection::from_stream(server, Duration::from_secs(2), Duration::from_secs(2))
                .unwrap(),
        );
        let server_thread = thread::spawn(move || {
            use crate::witness_runtime::WitnessResponseContext;
            use crate::witness_runtime::send_witness_response_with_context;
            let auth = MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32]));
            let pending = witness.receive_pending(&CborSerializer, &auth).unwrap();
            let request_id = pending
                .message()
                .unsigned()
                .common
                .request_id
                .clone()
                .unwrap();
            send_witness_response_with_context(
                &mut witness,
                &mut ProcessSession::from_session_id(SessionId::new("session-w")),
                request_id,
                ProtocolMessage::LeaseReleased(crate::protocol::LeaseReleasedPayload {
                    term: Term(7),
                    lease_id: LeaseId::new("lease-1"),
                    result: "released".into(),
                }),
                WitnessResponseContext {
                    term: Term(7),
                    lease_id: Some(LeaseId::new("lease-1")),
                },
                &CborSerializer,
                &auth,
            )
            .unwrap();
        });
        let node = WitnessConnection::new(
            NodeId::new("node-a"),
            NodeId::new("witness"),
            ClusterId::new("cluster"),
            SessionId::new("session-w"),
            TcpConnection::from_stream(client, Duration::from_secs(2), Duration::from_secs(2))
                .unwrap(),
        );
        let mut session = WitnessSession::new(
            node,
            ProcessSession::from_session_id(SessionId::new("session-a")),
            MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32])),
        );

        // Exactly one bounded step, and it is the only one permitted.
        assert!(
            parts
                .runtime
                .shutdown_bounded_step(&mut session, &|| true)
                .unwrap()
        );
        server_thread.join().unwrap();

        // The exact durable Release completed and the controller reconciled.
        assert_eq!(parts.runtime.state_machine.node_state(), NodeState::Standby);
        assert!(parts.runtime.controller.recovery_reconciled());
        assert!(!parts.runtime.controller.demotion_required());
        assert!(parts.runtime.release_obligation().unwrap().is_none());
        assert!(
            parts
                .runtime
                .durable_witness_outstanding()
                .unwrap()
                .is_none()
        );
        // The latch makes a second bounded step structurally impossible.
        assert!(
            !parts
                .runtime
                .shutdown_bounded_step(&mut session, &|| true)
                .unwrap()
        );
        // Only now may shutdown classify clean.
        assert!(parts.runtime.shutdown_for_daemon(&|| true).unwrap());
        cleanup_test_path(&parts.path);
    }

    /// A-2 Test B: a bounded step that cannot complete (real transport
    /// failure) must retain O and M, fabricate no CLEAR, and leave shutdown
    /// non-clean.  Repeated calls must not become a retry loop.
    #[test]
    fn stage13_6_remediation_shutdown_bounded_step_retains_m_on_transport_failure() {
        use crate::security::{MessageAuthenticator, Psk};
        use crate::session::ProcessSession;
        use crate::tcp::TcpConnection;
        use crate::witness_runtime::WitnessConnection;
        use std::net::{TcpListener, TcpStream};
        use std::time::Duration;

        let mut parts = test_runtime(
            [RawVipObservation::Absent],
            [RawServiceObservation::Stopped],
            [],
            AuthorityMode::Conservative,
            None,
        );
        parts.runtime.reconcile().unwrap();
        parts
            .runtime
            .state_machine
            .transition_to(NodeState::QuorumUnknown)
            .unwrap();
        parts
            .runtime
            .state_machine
            .transition_to(NodeState::Failed)
            .unwrap();
        parts.runtime.state_machine.reset_for_recovery().unwrap();
        parts
            .runtime
            .mutation_store
            .arm_release_obligation(Term(7), LeaseId::new("lease-1"))
            .unwrap();
        let begun = parts
            .runtime
            .mutation_store
            .begin_lease_release_for_test(Term(7), LeaseId::new("lease-1"), "a-2".into())
            .unwrap();
        parts
            .runtime
            .state_machine
            .begin_recovery_cleanup()
            .unwrap();
        for _ in 0..4 {
            parts.runtime.state_machine.advance_demotion().unwrap();
        }

        // A real connected-then-closed socket: a genuine transport failure.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        drop(server);
        let node = WitnessConnection::new(
            NodeId::new("node-a"),
            NodeId::new("witness"),
            ClusterId::new("cluster"),
            SessionId::new("session-w"),
            TcpConnection::from_stream(
                client,
                Duration::from_millis(500),
                Duration::from_millis(500),
            )
            .unwrap(),
        );
        let mut session = WitnessSession::new(
            node,
            ProcessSession::from_session_id(SessionId::new("session-a")),
            MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32])),
        );

        // One bounded attempt only.
        assert!(
            parts
                .runtime
                .shutdown_bounded_step(&mut session, &|| true)
                .unwrap()
        );
        // O and M are retained exactly; no false CLEAR, no second begin.
        let obligation = parts
            .runtime
            .release_obligation()
            .unwrap()
            .expect("O must be retained");
        assert_eq!(obligation.term, Term(7));
        let outstanding = parts
            .runtime
            .durable_witness_outstanding()
            .unwrap()
            .expect("M must be retained");
        assert_eq!(outstanding.request_id, begun.request_id);
        assert_eq!(outstanding.mutation_generation, begun.mutation_generation);
        // Further calls cannot retry: the latch holds, so no loop is possible.
        assert!(
            !parts
                .runtime
                .shutdown_bounded_step(&mut session, &|| true)
                .unwrap()
        );
        assert!(
            !parts
                .runtime
                .shutdown_bounded_step(&mut session, &|| true)
                .unwrap()
        );
        // H6 is not weakened: unresolved O/M keeps shutdown non-clean.
        assert!(!parts.runtime.shutdown_for_daemon(&|| true).unwrap());
        assert!(parts.runtime.release_obligation().unwrap().is_some());
        cleanup_test_path(&parts.path);
    }

    /// A-2 Test C: with a protected resource present at shutdown, the A-1/H2
    /// trusted-ZeroResource gate wins, no Release is transmitted, and shutdown
    /// stays non-clean.
    #[test]
    fn stage13_6_remediation_shutdown_bounded_step_blocked_by_resource_present() {
        use crate::security::{MessageAuthenticator, Psk};
        use crate::session::ProcessSession;
        use crate::tcp::TcpConnection;
        use crate::witness_runtime::WitnessConnection;
        use std::net::{TcpListener, TcpStream};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Duration;

        // Reach a clean reconciled Standby first, then re-introduce a
        // protected resource so that the post-cleanup demotion owner is owed a
        // Release while local resources are demonstrably not ZeroResource.
        let mut parts = test_runtime(
            [RawVipObservation::Absent],
            [RawServiceObservation::Stopped],
            [],
            AuthorityMode::Conservative,
            None,
        );
        parts.runtime.reconcile().unwrap();
        parts
            .runtime
            .state_machine
            .transition_to(NodeState::QuorumUnknown)
            .unwrap();
        parts
            .runtime
            .state_machine
            .transition_to(NodeState::Failed)
            .unwrap();
        parts.runtime.state_machine.reset_for_recovery().unwrap();
        parts
            .runtime
            .mutation_store
            .arm_release_obligation(Term(7), LeaseId::new("lease-1"))
            .unwrap();
        parts
            .runtime
            .mutation_store
            .begin_lease_release_for_test(Term(7), LeaseId::new("lease-1"), "a-2".into())
            .unwrap();
        parts
            .runtime
            .state_machine
            .begin_recovery_cleanup()
            .unwrap();
        for _ in 0..4 {
            parts.runtime.state_machine.advance_demotion().unwrap();
        }
        // A protected resource is now present: VIP stays Present and the
        // service refuses to stop, so trusted cleanup cannot verify absence.
        parts.vip.borrow_mut().clear();
        parts.vip.borrow_mut().push_back(RawVipObservation::Present);
        parts.service.borrow_mut().clear();
        parts
            .service
            .borrow_mut()
            .push_back(RawServiceObservation::Running);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let saw_release = Arc::new(AtomicBool::new(false));
        let saw_flag = saw_release.clone();
        let server_thread = std::thread::spawn(move || {
            use crate::witness_runtime::WitnessResponseContext;
            use crate::witness_runtime::send_witness_response_with_context;
            let auth = MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32]));
            let mut witness = WitnessConnection::new(
                NodeId::new("witness"),
                NodeId::new("node-a"),
                ClusterId::new("cluster"),
                SessionId::new("session-a"),
                TcpConnection::from_stream(
                    server,
                    Duration::from_millis(800),
                    Duration::from_millis(800),
                )
                .unwrap(),
            );
            if let Ok(pending) = witness.receive_pending(&CborSerializer, &auth) {
                let is_release = matches!(
                    pending.message().unsigned().message,
                    ProtocolMessage::LeaseRelease { .. }
                );
                saw_flag.store(is_release, Ordering::SeqCst);
                if is_release {
                    if let Some(id) = pending.message().unsigned().common.request_id.clone() {
                        let _ = send_witness_response_with_context(
                            &mut witness,
                            &mut ProcessSession::from_session_id(SessionId::new("session-w")),
                            id,
                            ProtocolMessage::LeaseReleased(crate::protocol::LeaseReleasedPayload {
                                term: Term(7),
                                lease_id: LeaseId::new("lease-1"),
                                result: "released".into(),
                            }),
                            WitnessResponseContext {
                                term: Term(7),
                                lease_id: Some(LeaseId::new("lease-1")),
                            },
                            &CborSerializer,
                            &auth,
                        );
                    }
                }
            }
        });
        let node = WitnessConnection::new(
            NodeId::new("node-a"),
            NodeId::new("witness"),
            ClusterId::new("cluster"),
            SessionId::new("session-w"),
            TcpConnection::from_stream(
                client,
                Duration::from_millis(800),
                Duration::from_millis(800),
            )
            .unwrap(),
        );
        let mut session = WitnessSession::new(
            node,
            ProcessSession::from_session_id(SessionId::new("session-a")),
            MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32])),
        );

        parts
            .runtime
            .shutdown_bounded_step(&mut session, &|| true)
            .unwrap();
        let _ = server_thread.join();

        // No LeaseRelease was ever transmitted.
        assert!(
            !saw_release.load(Ordering::SeqCst),
            "Release must not be transmitted while a protected resource is present"
        );
        // Durable state is retained and shutdown is non-clean.
        assert!(parts.runtime.release_obligation().unwrap().is_some());
        assert!(
            parts
                .runtime
                .durable_witness_outstanding()
                .unwrap()
                .is_some()
        );
        assert!(!parts.runtime.shutdown_for_daemon(&|| true).unwrap());
        cleanup_test_path(&parts.path);
    }

    /// A-2 Case 4/5: an incompatible durable mutation, and the no-eligible-work
    /// case, must not be overwritten and must not let shutdown classify clean.
    #[test]
    fn stage13_6_remediation_shutdown_bounded_step_incompatible_mutation_is_preserved() {
        use crate::security::{MessageAuthenticator, Psk};
        use crate::session::ProcessSession;
        use crate::tcp::TcpConnection;
        use crate::witness_runtime::WitnessConnection;
        use std::net::{TcpListener, TcpStream};
        use std::time::Duration;

        let mut parts = test_runtime(
            [RawVipObservation::Absent],
            [RawServiceObservation::Stopped],
            [],
            AuthorityMode::Conservative,
            None,
        );
        parts.runtime.reconcile().unwrap();
        // A LeaseRequest is the incompatible kind for a post-cleanup Release
        // owner. It must be preserved, never overwritten.
        parts
            .runtime
            .mutation_store
            .begin_lease_request(Term(7), 100, DurationMs(10_000))
            .unwrap();
        let before = parts
            .runtime
            .mutation_store
            .outstanding()
            .unwrap()
            .expect("incompatible durable mutation must exist");
        assert_eq!(
            before.kind(),
            crate::node_mutation::MutationKind::LeaseRequest
        );

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        drop(server);
        let node = WitnessConnection::new(
            NodeId::new("node-a"),
            NodeId::new("witness"),
            ClusterId::new("cluster"),
            SessionId::new("session-w"),
            TcpConnection::from_stream(
                client,
                Duration::from_millis(500),
                Duration::from_millis(500),
            )
            .unwrap(),
        );
        let mut session = WitnessSession::new(
            node,
            ProcessSession::from_session_id(SessionId::new("session-a")),
            MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32])),
        );

        // Case 5: no demotion phase and a compatible-looking owner, so nothing
        // is eligible.  No step runs and no work is invented.
        assert!(
            !parts
                .runtime
                .shutdown_bounded_step(&mut session, &|| true)
                .unwrap()
        );

        // Case 4: now the node *is* inside the post-cleanup demotion phase, so
        // the step is eligible — but the durable record is a LeaseRequest, not
        // this owner's Release/Renew.  It must not be overwritten, must not be
        // rewritten, and must not become a Release send.
        parts
            .runtime
            .state_machine
            .transition_to(NodeState::QuorumUnknown)
            .unwrap();
        parts
            .runtime
            .state_machine
            .transition_to(NodeState::Failed)
            .unwrap();
        parts.runtime.state_machine.reset_for_recovery().unwrap();
        parts
            .runtime
            .state_machine
            .begin_recovery_cleanup()
            .unwrap();
        for _ in 0..4 {
            parts.runtime.state_machine.advance_demotion().unwrap();
        }
        assert!(
            parts
                .runtime
                .shutdown_bounded_step(&mut session, &|| true)
                .unwrap()
        );

        // The incompatible record is untouched.
        let after = parts
            .runtime
            .mutation_store
            .outstanding()
            .unwrap()
            .expect("incompatible durable mutation must be preserved");
        assert_eq!(after.request_id, before.request_id);
        assert_eq!(after.mutation_generation, before.mutation_generation);
        assert_eq!(
            after.kind(),
            crate::node_mutation::MutationKind::LeaseRequest
        );
        assert!(!parts.runtime.shutdown_for_daemon(&|| true).unwrap());
        cleanup_test_path(&parts.path);
    }

    #[test]
    fn stage13_6_remediation_post_demotion_schedule_uses_ordinary_cadence_at_expired_deadline() {
        let clock = Rc::new(Cell::new(0));
        let mut parts = test_runtime(
            [RawVipObservation::Absent],
            [RawServiceObservation::Stopped],
            [],
            AuthorityMode::Conservative,
            Some(clock.clone()),
        );
        parts.runtime.reconcile().unwrap();
        install_test_authority(&mut parts.runtime);
        parts.runtime.controller.mark_resource_ownership_started();
        parts.runtime.controller.request_demotion();
        parts
            .runtime
            .state_machine
            .transition_to(NodeState::QuorumUnknown)
            .unwrap();
        parts
            .runtime
            .state_machine
            .transition_to(NodeState::Failed)
            .unwrap();
        parts.runtime.state_machine.reset_for_recovery().unwrap();
        parts
            .runtime
            .state_machine
            .begin_recovery_cleanup()
            .unwrap();
        for _ in 0..4 {
            parts.runtime.state_machine.advance_demotion().unwrap();
        }
        clock.set(9_000);
        assert_eq!(
            parts
                .runtime
                .active_schedule_delay(std::time::Duration::from_millis(500))
                .unwrap(),
            std::time::Duration::from_millis(500)
        );
        cleanup_test_path(&parts.path);
    }

    fn stage14_7_new(fencing: &str) -> Result<LinuxNodeRuntime, LinuxNodeRuntimeError> {
        let state = std::env::temp_dir().join(format!(
            "mikagami-stage14-7-{}-state.toml",
            std::process::id()
        ));
        let config = Config::parse_str(&format!(
            "{}\n[state]\npath = \"{}\"\n{fencing}",
            minimal_toml(),
            state.display()
        ))
        .unwrap();
        LinuxNodeRuntime::new(&config, LinuxPlatformConfig::new("/bin/true").unwrap())
    }

    fn stage14_7_command(fence: &str, verify: &str) -> String {
        format!(
            "[fencing]\nbackend = \"command\"\nfence = [\"{fence}\", \"--off\"]\n\
             verify = [\"{verify}\"]\nfence_timeout_sec = 60\nverify_timeout_sec = 30\n\
             verify_polls = 60\n"
        )
    }

    fn stage14_7_refusal(refusal: Option<LinuxNodeRuntimeError>) -> String {
        match refusal {
            Some(LinuxNodeRuntimeError::Configuration(message)) => message,
            Some(other) => panic!("expected a configuration refusal, got {other}"),
            None => panic!("the runtime owner was constructed"),
        }
    }

    /// Revision 5 §16.1/§16.2: the single runtime owner holds the validated,
    /// startup-trusted settings, and holding them runs nothing.
    #[test]
    fn stage14_7_owner_holds_validated_trusted_settings() {
        let Ok(mut runtime) = stage14_7_new(&stage14_7_command("/usr/bin/true", "/usr/bin/true"))
        else {
            panic!("trusted command settings must construct the owner");
        };
        let crate::fencing_backend::FencingSettings::Command(command) =
            runtime.fencing_settings_for_test().clone()
        else {
            panic!("expected command settings");
        };
        assert_eq!(command.fence, ["/usr/bin/true", "--off"]);
        assert_eq!(command.verify, ["/usr/bin/true"]);
        assert_eq!(command.fence_timeout.duration(), Duration::from_secs(60));
        assert_eq!(command.verify_timeout.duration(), Duration::from_secs(30));
        assert_eq!(command.verify_polls, 60);
        assert!(
            runtime
                .fencing_backend_for_test()
                .pending_reap_diagnostics()
                .is_none()
        );
    }

    #[test]
    fn stage14_7_absent_or_none_section_holds_backend_none() {
        for fencing in ["", "[fencing]\nbackend = \"none\"\n"] {
            let Ok(runtime) = stage14_7_new(fencing) else {
                panic!("backend none must construct the owner: {fencing:?}");
            };
            assert_eq!(
                runtime.fencing_settings_for_test(),
                &crate::fencing_backend::FencingSettings::None
            );
        }
    }

    /// §16.2 / acceptance 35: an untrusted `fence[0]` or `verify[0]`, or an
    /// out-of-range timeout, refuses owner construction (daemon startup).
    #[test]
    fn stage14_7_untrusted_or_invalid_settings_refuse_owner_construction() {
        let own =
            std::env::temp_dir().join(format!("mikagami-stage14-7-{}-own", std::process::id()));
        std::fs::write(&own, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&own, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let own = own.display().to_string();
        let fence = stage14_7_new(&stage14_7_command(&own, "/usr/bin/true")).err();
        let verify = stage14_7_new(&stage14_7_command("/usr/bin/true", &own)).err();
        std::fs::remove_file(&own).unwrap();
        let fence = stage14_7_refusal(fence);
        let verify = stage14_7_refusal(verify);
        assert!(fence.contains(&format!(
            "fencing.fence[0] {own} is not a trusted executable"
        )));
        assert!(verify.contains(&format!(
            "fencing.verify[0] {own} is not a trusted executable"
        )));

        let invalid = stage14_7_command("/usr/bin/true", "/usr/bin/true")
            .replace("fence_timeout_sec = 60", "fence_timeout_sec = 61");
        let config = format!("{}\n{invalid}", minimal_toml());
        assert!(Config::parse_str(&config).is_err());
    }

    // ---- Stage 14 Phase 14.8: §18.5 ingestion on the real runtime owner ----

    struct Stage148 {
        parts: TestRuntimeParts,
        dir: PathBuf,
        uid: u32,
    }

    impl Drop for Stage148 {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
            cleanup_test_path(&self.parts.path);
        }
    }

    /// Standby, zero resource, a private 0700 intent directory, and one open
    /// incident (seq 1, anchor 41, session `0123456789abcdef`, generation 1).
    fn stage14_8_runtime() -> Stage148 {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let mut parts = stage14_6_runtime();
        let dir = parts.path.with_extension("intent");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let uid = std::fs::metadata(&dir).unwrap().uid();
        parts.runtime.set_attestation_dir_for_test(dir.clone());
        Stage148 { parts, dir, uid }
    }

    fn stage14_8_open(fixture: &Stage148) -> crate::fencing::FencingIncident {
        fixture
            .parts
            .runtime
            .mutation_store
            .open_fencing_incident(crate::fencing::IncidentOpening {
                target_node_id: NodeId::new("node-b"),
                anchor_term: Term(41),
                observer_session_id: crate::protocol::SessionId::new("0123456789abcdef"),
                observer_loss_generation: 1,
                backend: crate::fencing::FencingBackend::None,
            })
            .unwrap()
    }

    fn stage14_8_intent(
        incident: &crate::fencing::FencingIncident,
        attestation_id: &str,
    ) -> crate::attestation::AttestationIntent {
        crate::attestation::AttestationIntent {
            attestation_format_version: crate::attestation::ATTESTATION_FORMAT_VERSION,
            attestation_id: crate::fencing::AttestationId::new(attestation_id),
            cluster_id: "cluster".into(),
            node_id: "node-a".into(),
            subject: "example.service".into(),
            target_node_id: "node-b".into(),
            incident_seq: incident.incident_seq,
            incident_id: incident.incident_id.clone(),
            statement: crate::attestation::ATTESTATION_STATEMENT.into(),
        }
    }

    fn stage14_8_evidence() -> Option<crate::failure_assessment::LocalLossEvidence> {
        let mut detector =
            crate::failure_assessment::PeerFailureDetector::new(Duration::from_secs(5)).unwrap();
        let peer_session = crate::protocol::SessionId::new("peer-session-1");
        let t0 = std::time::Instant::now();
        detector
            .observe_session_established(peer_session.clone(), t0)
            .unwrap();
        detector
            .observe_trusted_heartbeat(&peer_session, crate::protocol::Sequence(1), t0)
            .unwrap();
        detector.observe_transport_failure(t0).unwrap();
        detector.tick(t0 + Duration::from_secs(5)).unwrap();
        detector.loss_evidence()
    }

    fn stage14_8_ingest(
        fixture: &Stage148,
        session: &str,
        latest: Option<Term>,
    ) -> AttestationIngestion {
        let evidence = stage14_8_evidence();
        assert_eq!(evidence.as_ref().map(|e| e.generation()), Some(1));
        let (peer, session) = (
            NodeId::new("node-b"),
            crate::protocol::SessionId::new(session),
        );
        fixture
            .parts
            .runtime
            .ingest_attestation_as(
                &crate::fencing::ContinuityContext {
                    configured_peer: &peer,
                    current_session: &session,
                    live_episode: evidence.as_ref(),
                },
                latest,
                fixture.uid,
            )
            .unwrap()
    }

    fn stage14_8_trusted(fixture: &Stage148) -> crate::attestation::TrustedDir {
        crate::attestation::TrustedDir::open(&fixture.dir, fixture.uid).unwrap()
    }

    fn stage14_8_install(fixture: &Stage148, intent: &crate::attestation::AttestationIntent) {
        crate::attestation::install_intent(&stage14_8_trusted(fixture), intent).unwrap();
    }

    fn stage14_8_pending(fixture: &Stage148) -> bool {
        crate::attestation::intent_pending(&stage14_8_trusted(fixture)).unwrap()
    }

    fn stage14_8_state(fixture: &Stage148) -> Vec<u8> {
        std::fs::read(&fixture.parts.path).unwrap()
    }

    const STAGE14_8_ATTESTATION: &str = "66666666-7777-4888-9999-aaaaaaaaaaaa";

    /// §34.7 correct current intent → `CONFIRMED(operator)` through the exact
    /// CAS; M, O, and the sequence high-water unchanged; the file removed.
    /// A replay of the same `attestation_id` is a no-write no-op.
    #[test]
    fn stage14_8_ingestion_confirms_then_replay_is_a_no_op() {
        let fixture = stage14_8_runtime();
        let incident = stage14_8_open(&fixture);
        let intent = stage14_8_intent(&incident, STAGE14_8_ATTESTATION);
        stage14_8_install(&fixture, &intent);
        assert_eq!(
            stage14_8_ingest(&fixture, "0123456789abcdef", Some(Term(41))),
            AttestationIngestion::Confirmed {
                incident: incident.incident_ref(),
                removed: true,
            }
        );
        let state = fixture
            .parts
            .runtime
            .mutation_store
            .load_existing()
            .unwrap();
        let durable = state.fencing_incident.unwrap();
        assert_eq!(
            durable.state,
            crate::fencing::FencingState::Confirmed(crate::fencing::ConfirmedBy::Operator {
                attestation_id: crate::fencing::AttestationId::new(STAGE14_8_ATTESTATION),
            })
        );
        assert_eq!(durable.incident_ref(), incident.incident_ref());
        assert_eq!(state.highest_fencing_incident_seq, 1);
        assert!(state.outstanding_mutation.is_none());
        assert!(state.release_obligation.is_none());
        assert!(!stage14_8_pending(&fixture));

        let before = stage14_8_state(&fixture);
        stage14_8_install(&fixture, &intent);
        assert_eq!(
            stage14_8_ingest(&fixture, "0123456789abcdef", None),
            AttestationIngestion::AlreadyConfirmed { removed: true }
        );
        assert_eq!(stage14_8_state(&fixture), before);
        assert!(!stage14_8_pending(&fixture));
    }

    /// §18.5 Reject: a bad intent or a bad file never mutates fencing state;
    /// the file is removed.
    #[test]
    fn stage14_8_ingestion_rejections_never_mutate() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = stage14_8_runtime();
        let incident = stage14_8_open(&fixture);
        let before = stage14_8_state(&fixture);
        let mut wrong_seq = stage14_8_intent(&incident, STAGE14_8_ATTESTATION);
        wrong_seq.incident_seq = 2;
        let mut wrong_statement = stage14_8_intent(&incident, STAGE14_8_ATTESTATION);
        wrong_statement.statement = "confirm-fenced-v0".into();
        let mut wrong_subject = stage14_8_intent(&incident, STAGE14_8_ATTESTATION);
        wrong_subject.subject = "nginx.service".into();
        for (bad, mismatch) in [
            (wrong_seq, crate::attestation::IntentMismatch::Incident),
            (
                wrong_statement,
                crate::attestation::IntentMismatch::Statement,
            ),
            (wrong_subject, crate::attestation::IntentMismatch::Subject),
        ] {
            stage14_8_install(&fixture, &bad);
            assert_eq!(
                stage14_8_ingest(&fixture, "0123456789abcdef", None),
                AttestationIngestion::RejectedIntent {
                    mismatch,
                    removed: true,
                }
            );
            assert_eq!(stage14_8_state(&fixture), before);
        }
        let good = stage14_8_intent(&incident, STAGE14_8_ATTESTATION);
        stage14_8_install(&fixture, &good);
        let fixed = fixture
            .dir
            .join(crate::attestation::ATTESTATION_INTENT_FILE);
        std::fs::set_permissions(&fixed, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            stage14_8_ingest(&fixture, "0123456789abcdef", None),
            AttestationIngestion::RejectedFile {
                fault: crate::attestation::IntentFault::Mode,
                removed: true,
            }
        );
        assert_eq!(stage14_8_state(&fixture), before);
        assert!(!fixed.exists());
    }

    /// §34.7 / G7(a) and §26: a newer TermStatus term than `anchor_term`, a
    /// stale observer session, or a moved loss generation retires the exact
    /// incident (T9) and rejects the intent; the sequence high-water stays.
    #[test]
    fn stage14_8_ingestion_stale_continuity_retires() {
        let fixture = stage14_8_runtime();
        for (session, latest, violation) in [
            (
                "0123456789abcdef",
                Some(Term(42)),
                crate::fencing::ContinuityViolation::WitnessEpoch,
            ),
            (
                "fedcba9876543210",
                None,
                crate::fencing::ContinuityViolation::ObserverSession,
            ),
        ] {
            let incident = stage14_8_open(&fixture);
            stage14_8_install(
                &fixture,
                &stage14_8_intent(&incident, STAGE14_8_ATTESTATION),
            );
            assert_eq!(
                stage14_8_ingest(&fixture, session, latest),
                AttestationIngestion::Retired {
                    violation,
                    removed: true,
                }
            );
            let state = fixture
                .parts
                .runtime
                .mutation_store
                .load_existing()
                .unwrap();
            assert!(state.fencing_incident.is_none());
            assert_eq!(state.highest_fencing_incident_seq, incident.incident_seq);
        }
    }

    /// Eligibility and the in-progress cases: no incident → nothing is read
    /// (the file is untouched); no file → Absent; an install in progress →
    /// Deferred with no mutation and no unlink.
    #[test]
    fn stage14_8_ingestion_not_eligible_absent_and_deferred() {
        let fixture = stage14_8_runtime();
        let orphan = crate::attestation::AttestationIntent {
            incident_seq: 1,
            ..stage14_8_intent(
                &crate::fencing::FencingIncident {
                    incident_seq: 1,
                    incident_id: crate::fencing::IncidentId::new(
                        "11111111-2222-4333-8444-555555555555",
                    ),
                    target_node_id: NodeId::new("node-b"),
                    anchor_term: Term(41),
                    observer_session_id: crate::protocol::SessionId::new("0123456789abcdef"),
                    observer_loss_generation: 1,
                    attempt_token_high_water: 0,
                    state: crate::fencing::FencingState::Unknown(
                        crate::fencing::UnknownReason::NotAttempted {},
                    ),
                },
                STAGE14_8_ATTESTATION,
            )
        };
        stage14_8_install(&fixture, &orphan);
        assert_eq!(
            stage14_8_ingest(&fixture, "0123456789abcdef", None),
            AttestationIngestion::NotEligible
        );
        assert!(stage14_8_pending(&fixture));
        crate::attestation::remove_intent(&stage14_8_trusted(&fixture)).unwrap();

        let incident = stage14_8_open(&fixture);
        assert_eq!(
            stage14_8_ingest(&fixture, "0123456789abcdef", None),
            AttestationIngestion::Absent
        );
        stage14_8_install(
            &fixture,
            &stage14_8_intent(&incident, STAGE14_8_ATTESTATION),
        );
        let fixed = fixture
            .dir
            .join(crate::attestation::ATTESTATION_INTENT_FILE);
        let inflight = fixture.dir.join(format!(
            "{}.tmp-inflight",
            crate::attestation::ATTESTATION_INTENT_FILE
        ));
        std::fs::hard_link(&fixed, &inflight).unwrap();
        let before = stage14_8_state(&fixture);
        assert_eq!(
            stage14_8_ingest(&fixture, "0123456789abcdef", None),
            AttestationIngestion::Deferred
        );
        assert_eq!(stage14_8_state(&fixture), before);
        assert!(fixed.exists());
    }

    /// The production entry requires a root-owned intent directory: as a
    /// non-root user over a user-owned tree the intent is refused, never
    /// accepted, and neither the fencing state nor the untrusted directory is
    /// touched (F14.8-01: `removed: false`, the file stays).
    #[test]
    fn stage14_8_ingestion_production_entry_requires_root_owner() {
        let fixture = stage14_8_runtime();
        let incident = stage14_8_open(&fixture);
        stage14_8_install(
            &fixture,
            &stage14_8_intent(&incident, STAGE14_8_ATTESTATION),
        );
        let before = stage14_8_state(&fixture);
        let evidence = stage14_8_evidence();
        let (peer, session) = (
            NodeId::new("node-b"),
            crate::protocol::SessionId::new("0123456789abcdef"),
        );
        let outcome = fixture
            .parts
            .runtime
            .ingest_attestation(
                &crate::fencing::ContinuityContext {
                    configured_peer: &peer,
                    current_session: &session,
                    live_episode: evidence.as_ref(),
                },
                None,
            )
            .unwrap();
        if fixture.uid != crate::attestation::ROOT_UID {
            assert_eq!(
                outcome,
                AttestationIngestion::RejectedFile {
                    fault: crate::attestation::IntentFault::ParentOwner,
                    removed: false,
                }
            );
            assert_eq!(stage14_8_state(&fixture), before);
            assert!(stage14_8_pending(&fixture));
        }
    }

    /// F14.8-01: an unsafe (group/world-writable) intent directory is
    /// rejected before anything in it is read or removed, and no fencing
    /// state changes.
    #[test]
    fn stage14_8r_ingestion_unsafe_directory_is_not_touched() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = stage14_8_runtime();
        let incident = stage14_8_open(&fixture);
        stage14_8_install(
            &fixture,
            &stage14_8_intent(&incident, STAGE14_8_ATTESTATION),
        );
        let fixed = fixture
            .dir
            .join(crate::attestation::ATTESTATION_INTENT_FILE);
        let installed = std::fs::read(&fixed).unwrap();
        let before = stage14_8_state(&fixture);
        std::fs::set_permissions(&fixture.dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            stage14_8_ingest(&fixture, "0123456789abcdef", None),
            AttestationIngestion::RejectedFile {
                fault: crate::attestation::IntentFault::ParentWritable,
                removed: false,
            }
        );
        assert_eq!(std::fs::read(&fixed).unwrap(), installed);
        assert_eq!(stage14_8_state(&fixture), before);
        std::fs::set_permissions(&fixture.dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn minimal_config() -> Config {
        Config::parse_str(&minimal_toml()).unwrap()
    }

    fn minimal_toml() -> String {
        [
            "[cluster]",
            "id = \"cluster\"",
            "[node]",
            "id = \"node-a\"",
            "[peer]",
            "id = \"node-b\"",
            "address = \"127.0.0.1:7946\"",
            "[witness]",
            "id = \"witness-1\"",
            "address = \"127.0.0.1:7947\"",
            "[vip]",
            "address = \"192.0.2.50/24\"",
            "interface = \"eth0\"",
            "[service]",
            "manager = \"systemd\"",
            "unit = \"example.service\"",
            "[health]",
            "command = [\"/usr/bin/true\"]",
            "[security]",
            "psk_file = \"/tmp/psk\"",
        ]
        .join("\n")
    }

    // ---- Stage 14 Phase 14.9 (DC-14.9-01 Option B): fencing composition ----
    //
    // Real bounded processes through the one runtime-owned backend. Each
    // script appends its attempt token to a log file, so the log is the exact
    // spawn count. Every gate result is a block; `CONFIRMED` blocks too.

    struct Stage149 {
        fixture: Stage148,
        log: PathBuf,
        pid: PathBuf,
    }

    impl Drop for Stage149 {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.log);
            let _ = std::fs::remove_file(&self.pid);
        }
    }

    const STAGE14_9_SESSION: &str = "0123456789abcdef";

    fn stage14_9_bash(script: String) -> Vec<String> {
        vec![
            "/usr/bin/bash".to_string(),
            "-c".to_string(),
            script,
            "stage14-9".to_string(),
        ]
    }

    /// Standby, zero resource, a private intent directory owned by the test
    /// user, and `backend = "command"` with the given scripts. `{log}` and
    /// `{pid}` in a script name the spawn log and the descendant pid file.
    fn stage14_9_command(
        fence: &str,
        verify: &str,
        fence_timeout: u64,
        verify_timeout: u64,
        polls: u64,
    ) -> Stage149 {
        let mut fixture = stage14_8_runtime();
        let log = fixture.parts.path.with_extension("spawns");
        let pid = fixture.parts.path.with_extension("descendant");
        let state = fixture.parts.path.display().to_string();
        let expand = |script: &str| {
            script
                .replace("{log}", &log.display().to_string())
                .replace("{pid}", &pid.display().to_string())
                .replace("{state}", &state)
        };
        let settings = crate::fencing_backend::FencingSettings::from_config(Some(
            &crate::config::FencingConfig {
                backend: crate::config::FencingBackendKind::Command,
                fence: Some(stage14_9_bash(expand(fence))),
                verify: Some(stage14_9_bash(expand(verify))),
                fence_timeout_sec: Some(fence_timeout),
                verify_timeout_sec: Some(verify_timeout),
                verify_polls: Some(polls),
            },
        ))
        .unwrap();
        fixture
            .parts
            .runtime
            .set_fencing_settings_for_test(settings);
        fixture.parts.runtime.attestation_owner_for_test = Some(fixture.uid);
        Stage149 { fixture, log, pid }
    }

    fn stage14_9_none() -> Stage149 {
        let mut fixture = stage14_8_runtime();
        let log = fixture.parts.path.with_extension("spawns");
        let pid = fixture.parts.path.with_extension("descendant");
        fixture.parts.runtime.attestation_owner_for_test = Some(fixture.uid);
        Stage149 { fixture, log, pid }
    }

    const STAGE14_9_FENCE_OK: &str = "echo \"$MIKAGAMI_FENCE_ATTEMPT\" >> {log}; exit 0";
    const STAGE14_9_ISOLATED: &str =
        "echo \"verify $MIKAGAMI_FENCE_ATTEMPT\" >> {log}; echo isolated";
    const STAGE14_9_NOT_ISOLATED: &str =
        "echo \"verify $MIKAGAMI_FENCE_ATTEMPT\" >> {log}; echo not-isolated";

    fn stage14_9_context_parts(
        live: bool,
    ) -> (
        NodeId,
        crate::protocol::SessionId,
        Option<crate::failure_assessment::LocalLossEvidence>,
    ) {
        (
            NodeId::new("node-b"),
            crate::protocol::SessionId::new(STAGE14_9_SESSION),
            if live { stage14_8_evidence() } else { None },
        )
    }

    /// A blocking gate decision; a clearance here fails the test.
    fn stage14_9_gate_with(
        f: &mut Stage149,
        view: Term,
        shutdown: bool,
        live: bool,
    ) -> (FencingGateOutcome, u32) {
        match stage14_9_gate_decision_with(f, view, shutdown, live) {
            (FencingGateDecision::Block(outcome), voids) => (outcome, voids),
            (FencingGateDecision::Clear { incident, .. }, _) => {
                panic!("expected a block, the gate cleared {incident:?}")
            }
        }
    }

    fn stage14_9_gate_decision_with(
        f: &mut Stage149,
        view: Term,
        shutdown: bool,
        live: bool,
    ) -> (FencingGateDecision, u32) {
        let (peer, session, evidence) = stage14_9_context_parts(live);
        let context = crate::fencing::ContinuityContext {
            configured_peer: &peer,
            current_session: &session,
            live_episode: evidence.as_ref(),
        };
        let mut voids = 0;
        let outcome = f
            .fixture
            .parts
            .runtime
            .fencing_gate(view, &context, &|| shutdown, &mut || voids += 1)
            .unwrap();
        (outcome, voids)
    }

    fn stage14_9_gate(f: &mut Stage149, view: Term) -> (FencingGateOutcome, u32) {
        stage14_9_gate_with(f, view, false, true)
    }

    fn stage14_9_drive_with(
        f: &mut Stage149,
        record: Option<&IncidentTermRecord>,
        shutdown: bool,
        live: bool,
    ) -> (FencingStepOutcome, u32) {
        let (peer, session, evidence) = stage14_9_context_parts(live);
        let context = crate::fencing::ContinuityContext {
            configured_peer: &peer,
            current_session: &session,
            live_episode: evidence.as_ref(),
        };
        let mut voids = 0;
        let outcome = f
            .fixture
            .parts
            .runtime
            .drive_fencing_step(&context, record, &|| shutdown, &mut || voids += 1)
            .unwrap();
        (outcome, voids)
    }

    fn stage14_9_drive(
        f: &mut Stage149,
        record: Option<&IncidentTermRecord>,
    ) -> (FencingStepOutcome, u32) {
        stage14_9_drive_with(f, record, false, true)
    }

    fn stage14_9_incident(f: &Stage149) -> Option<crate::fencing::FencingIncident> {
        f.fixture
            .parts
            .runtime
            .mutation_store
            .load_existing()
            .unwrap()
            .fencing_incident
    }

    fn stage14_9_image(f: &Stage149) -> crate::node_mutation::NodeMutationPersistentState {
        f.fixture
            .parts
            .runtime
            .mutation_store
            .load_existing()
            .unwrap()
    }

    fn stage14_9_spawns(f: &Stage149) -> Vec<String> {
        std::fs::read_to_string(&f.log)
            .map(|log| log.lines().map(str::to_string).collect())
            .unwrap_or_default()
    }

    fn stage14_9_record(
        incident: &crate::fencing::FencingIncident,
        newest: Term,
    ) -> IncidentTermRecord {
        IncidentTermRecord {
            incident: incident.incident_ref(),
            anchor: incident.anchor_term,
            newest,
        }
    }

    /// Open `VERIFYING(1, reported-success)` through the real gate (one
    /// fence spawn) and return the incident.
    fn stage14_9_verifying(f: &mut Stage149) -> crate::fencing::FencingIncident {
        let (outcome, _) = stage14_9_gate(f, Term(41));
        assert_eq!(
            outcome.block,
            crate::fencing::FencingGateBlock::FencingInProgress
        );
        let incident = stage14_9_incident(f).unwrap();
        assert_eq!(
            incident.state,
            crate::fencing::FencingState::Verifying {
                attempt_token: 1,
                action_outcome: crate::fencing::ActionOutcome::ReportedSuccess,
            }
        );
        incident
    }

    fn stage14_9_assert_no_authority(f: &Stage149) {
        let image = stage14_9_image(f);
        assert!(image.release_obligation.is_none(), "no ARM / O");
        assert!(image.outstanding_mutation.is_none(), "no M");
        assert!(
            f.fixture
                .parts
                .runtime
                .controller
                .authority()
                .authority()
                .is_none()
        );
        assert_eq!(
            f.fixture.parts.runtime.state_machine.node_state(),
            NodeState::Standby
        );
    }

    /// A. No incident: G opens exactly one canonical incident bound to the
    /// fresh view (anchor), this session, the live episode, and the peer
    /// (T2), runs exactly one fence action after voiding the verified-listen
    /// window, and persists `VERIFYING(1, reported-success)` (T4). The
    /// action saw `REQUESTED(1)` already durable (the fence script copies
    /// the state file while it runs), so the exact durable sequence is
    /// none -> REQUESTED(1) -> VERIFYING(1). A successful action alone never
    /// confirms, and the gate still blocks.
    #[test]
    fn stage14_9_a_no_incident_opens_one_incident_and_runs_one_action() {
        use crate::fencing::{ActionOutcome, FencingGateBlock, FencingState};
        let fence = "/usr/bin/cp {state} {state}.during; echo \"$MIKAGAMI_FENCE_ATTEMPT\" >> {log}";
        let mut f = stage14_9_command(fence, STAGE14_9_ISOLATED, 10, 10, 3);
        let during = PathBuf::from(format!("{}.during", f.fixture.parts.path.display()));
        let (outcome, voids) = stage14_9_gate(&mut f, Term(41));
        let seen = crate::node_mutation::NodeMutationStore::new(
            &during,
            ClusterId::new("cluster"),
            NodeId::new("node-a"),
        )
        .load_existing()
        .unwrap()
        .fencing_incident
        .unwrap();
        let _ = std::fs::remove_file(&during);
        assert_eq!(seen.state, FencingState::Requested { attempt_token: 1 });
        let incident = stage14_9_incident(&f).unwrap();
        assert_eq!(outcome.block, FencingGateBlock::FencingInProgress);
        assert!(outcome.opened);
        assert_eq!(outcome.retired, None);
        assert_eq!(
            outcome.action,
            Some(FencingActionRecord {
                attempt_token: 1,
                outcome: ActionOutcome::ReportedSuccess,
                verifying_persisted: true,
            })
        );
        assert_eq!(
            outcome.incident,
            Some(stage14_9_record(&incident, Term(41)))
        );
        assert_eq!(voids, 1);
        assert_eq!(stage14_9_spawns(&f), ["1"]);
        assert_eq!(incident.incident_seq, 1);
        assert_eq!(incident.target_node_id, NodeId::new("node-b"));
        assert_eq!(incident.anchor_term, Term(41));
        assert_eq!(
            incident.observer_session_id,
            crate::protocol::SessionId::new(STAGE14_9_SESSION)
        );
        assert_eq!(incident.observer_loss_generation, 1);
        assert_eq!(incident.attempt_token_high_water, 1);
        assert_eq!(
            incident.state,
            FencingState::Verifying {
                attempt_token: 1,
                action_outcome: ActionOutcome::ReportedSuccess,
            }
        );
        assert_eq!(stage14_9_image(&f).highest_fencing_incident_seq, 1);
        stage14_9_assert_no_authority(&f);
    }

    /// A/B. `backend = "none"`: G opens `UNKNOWN(not-attempted)` (T1) and
    /// blocks `FencingRequired`; no process runs, no window is voided, and a
    /// later gate blocks `FencingUnconfirmed` with no write.
    #[test]
    fn stage14_9_a_none_backend_opens_unknown_and_runs_nothing() {
        use crate::fencing::{FencingGateBlock, FencingState, UnknownReason};
        let mut f = stage14_9_none();
        let (outcome, voids) = stage14_9_gate(&mut f, Term(41));
        assert_eq!(outcome.block, FencingGateBlock::FencingRequired);
        assert!(outcome.opened);
        assert_eq!(outcome.action, None);
        assert_eq!(voids, 0);
        assert_eq!(
            stage14_9_incident(&f).unwrap().state,
            FencingState::Unknown(UnknownReason::NotAttempted {})
        );
        let before = stage14_8_state(&f.fixture);
        let (again, voids) = stage14_9_gate(&mut f, Term(41));
        assert_eq!(again.block, FencingGateBlock::FencingUnconfirmed);
        assert!(!again.opened);
        assert_eq!(voids, 0);
        assert_eq!(stage14_8_state(&f.fixture), before);
        assert!(stage14_9_spawns(&f).is_empty());
        // Nothing to verify for `none`: the step reads, finds no intent, and
        // stops.
        let incident = stage14_9_incident(&f).unwrap();
        let (step, voids) = stage14_9_drive(&mut f, Some(&stage14_9_record(&incident, Term(41))));
        assert_eq!(step, FencingStepOutcome::NoAction);
        assert_eq!(voids, 0);
        assert_eq!(stage14_8_state(&f.fixture), before);
    }

    /// A. An existing incident is resumed, never reopened: `VERIFYING` blocks
    /// `FencingInProgress` with no write and no action; `FAILED(k)` with the
    /// command backend is re-requested as `REQUESTED(k+1)` (T3, the checked
    /// token increment) and runs one action for `k+1`.
    #[test]
    fn stage14_9_a_existing_incident_is_resumed_not_reopened() {
        use crate::fencing::{ActionOutcome, FencingGateBlock, FencingState};
        let mut f = stage14_9_command(STAGE14_9_FENCE_OK, STAGE14_9_NOT_ISOLATED, 10, 10, 3);
        let incident = stage14_9_verifying(&mut f);
        let before = stage14_8_state(&f.fixture);
        let (outcome, voids) = stage14_9_gate(&mut f, Term(41));
        assert_eq!(outcome.block, FencingGateBlock::FencingInProgress);
        assert!(!outcome.opened);
        assert_eq!(outcome.action, None);
        assert_eq!(voids, 0);
        assert_eq!(stage14_8_state(&f.fixture), before);
        assert_eq!(stage14_9_spawns(&f), ["1"]);

        let record = stage14_9_record(&incident, Term(41));
        let (step, _) = stage14_9_drive(&mut f, Some(&record));
        assert!(matches!(
            step,
            FencingStepOutcome::Polled {
                applied: VerifyApplied::Written(FencingState::Failed { attempt_token: 1 }),
                ..
            }
        ));
        let (outcome, voids) = stage14_9_gate(&mut f, Term(41));
        assert_eq!(outcome.block, FencingGateBlock::FencingInProgress);
        assert!(!outcome.opened);
        assert_eq!(outcome.action.as_ref().unwrap().attempt_token, 2);
        assert_eq!(voids, 1);
        let resumed = stage14_9_incident(&f).unwrap();
        assert_eq!(resumed.incident_ref(), incident.incident_ref());
        assert_eq!(resumed.attempt_token_high_water, 2);
        assert_eq!(
            resumed.state,
            FencingState::Verifying {
                attempt_token: 2,
                action_outcome: ActionOutcome::ReportedSuccess,
            }
        );
        assert_eq!(stage14_9_spawns(&f), ["1", "verify 1", "2"]);
        assert_eq!(stage14_9_image(&f).highest_fencing_incident_seq, 1);
    }

    /// A. A stale incident is retired (T9) at G against the fresh view — a
    /// different observer session (R2) or a moved Witness term (R4 at G) —
    /// and a new incident is opened in its place; without a live episode
    /// (R3) the stale incident is retired and nothing is opened.
    #[test]
    fn stage14_9_a_stale_incident_is_retired_then_reopened() {
        use crate::fencing::{ContinuityViolation, FencingGateBlock};
        let mut f = stage14_9_command(STAGE14_9_FENCE_OK, STAGE14_9_ISOLATED, 10, 10, 3);
        f.fixture
            .parts
            .runtime
            .mutation_store
            .open_fencing_incident(crate::fencing::IncidentOpening {
                target_node_id: NodeId::new("node-b"),
                anchor_term: Term(41),
                observer_session_id: crate::protocol::SessionId::new("fedcba9876543210"),
                observer_loss_generation: 1,
                backend: crate::fencing::FencingBackend::Command,
            })
            .unwrap();
        let (outcome, _) = stage14_9_gate(&mut f, Term(41));
        assert_eq!(outcome.retired, Some(ContinuityViolation::ObserverSession));
        assert!(outcome.opened);
        let second = stage14_9_incident(&f).unwrap();
        assert_eq!(second.incident_seq, 2);

        let (outcome, _) = stage14_9_gate(&mut f, Term(42));
        assert_eq!(outcome.retired, Some(ContinuityViolation::WitnessEpoch));
        assert!(outcome.opened);
        let third = stage14_9_incident(&f).unwrap();
        assert_eq!((third.incident_seq, third.anchor_term), (3, Term(42)));

        let (outcome, voids) = stage14_9_gate_with(&mut f, Term(42), false, false);
        assert_eq!(outcome.retired, Some(ContinuityViolation::Episode));
        assert_eq!(outcome.block, FencingGateBlock::FencingUnavailable);
        assert!(!outcome.opened);
        assert_eq!(voids, 0);
        assert_eq!(stage14_9_incident(&f), None);
        assert_eq!(
            stage14_9_spawns(&f),
            ["1", "1"],
            "one action per opened incident"
        );
    }

    /// A. Incident replacement during a blocking step is detected by the
    /// post-return rechecks (§27.2 step 3 / §17.2): the action outcome and
    /// the verify result for the replaced incident are discarded (C4), and
    /// the replacement is left exactly as written.
    #[test]
    fn stage14_9_a_replacement_during_a_step_is_never_written() {
        // Handshake, not timing: the running step marks `{state}.running`
        // and waits for `{state}.replaced`; the replacer waits for the first
        // marker, replaces the incident, then writes the second.
        let wait = "/usr/bin/touch {state}.running; \
                    while [ ! -e {state}.replaced ]; do /usr/bin/sleep 0.05; done";
        let fence = format!("echo \"$MIKAGAMI_FENCE_ATTEMPT\" >> {{log}}; {wait}; exit 0");
        let verify =
            format!("echo \"verify $MIKAGAMI_FENCE_ATTEMPT\" >> {{log}}; {wait}; echo isolated");
        let replace = |path: PathBuf| {
            std::thread::spawn(move || {
                let running = PathBuf::from(format!("{}.running", path.display()));
                let replaced = PathBuf::from(format!("{}.replaced", path.display()));
                let until = std::time::Instant::now() + Duration::from_secs(10);
                while !running.exists() {
                    assert!(std::time::Instant::now() < until, "the step never ran");
                    std::thread::sleep(Duration::from_millis(10));
                }
                let store = crate::node_mutation::NodeMutationStore::new(
                    &path,
                    ClusterId::new("cluster"),
                    NodeId::new("node-a"),
                );
                let current = store.load_existing().unwrap().fencing_incident.unwrap();
                store
                    .retire_fencing_incident(&current.incident_ref())
                    .unwrap();
                let replacement = store
                    .open_fencing_incident(crate::fencing::IncidentOpening {
                        target_node_id: NodeId::new("node-b"),
                        anchor_term: Term(41),
                        observer_session_id: crate::protocol::SessionId::new(STAGE14_9_SESSION),
                        observer_loss_generation: 1,
                        backend: crate::fencing::FencingBackend::None,
                    })
                    .unwrap();
                std::fs::write(&replaced, b"").unwrap();
                let _ = std::fs::remove_file(&running);
                replacement
            })
        };
        let markers = |path: &PathBuf| {
            let _ = std::fs::remove_file(format!("{}.replaced", path.display()));
        };

        let mut f = stage14_9_command(&fence, &verify, 10, 10, 3);
        let replacer = replace(f.fixture.parts.path.clone());
        let (outcome, _) = stage14_9_gate(&mut f, Term(41));
        let replacement = replacer.join().unwrap();
        markers(&f.fixture.parts.path);
        assert_eq!(
            outcome.action,
            Some(FencingActionRecord {
                attempt_token: 1,
                outcome: crate::fencing::ActionOutcome::ReportedSuccess,
                verifying_persisted: false,
            })
        );
        assert_eq!(stage14_9_incident(&f), Some(replacement));

        let mut f = stage14_9_command(STAGE14_9_FENCE_OK, &verify, 10, 10, 3);
        let incident = stage14_9_verifying(&mut f);
        let replacer = replace(f.fixture.parts.path.clone());
        let (step, _) = stage14_9_drive(&mut f, Some(&stage14_9_record(&incident, Term(41))));
        let replacement = replacer.join().unwrap();
        markers(&f.fixture.parts.path);
        assert_eq!(
            step,
            FencingStepOutcome::Polled {
                attempt_token: 1,
                result: crate::fencing_backend::VerifyOutcome::Isolated,
                applied: VerifyApplied::Discarded,
            }
        );
        assert_eq!(stage14_9_incident(&f), Some(replacement));
    }

    /// B. Action results are provenance only: a failing action, a timed-out
    /// action (bounded by `fence_timeout + 4.5 s`), and an untrusted
    /// executable (refused at the backend's pre-spawn trust check; nothing
    /// spawns) each persist `VERIFYING(1, outcome)` and block; none confirms.
    #[test]
    fn stage14_9_b_action_outcomes_are_provenance_only() {
        use crate::fencing::{ActionOutcome, FencingGateBlock, FencingState};
        for (fence, timeout, expected) in [
            (
                "echo \"$MIKAGAMI_FENCE_ATTEMPT\" >> {log}; exit 1".to_string(),
                10,
                ActionOutcome::ReportedFailure,
            ),
            (
                "echo \"$MIKAGAMI_FENCE_ATTEMPT\" >> {log}; exec /usr/bin/sleep 30".to_string(),
                1,
                ActionOutcome::TimedOut,
            ),
        ] {
            let mut f = stage14_9_command(&fence, STAGE14_9_ISOLATED, timeout, 10, 3);
            let started = std::time::Instant::now();
            let (outcome, voids) = stage14_9_gate(&mut f, Term(41));
            assert!(started.elapsed() <= Duration::from_millis(timeout * 1000 + 4500));
            assert_eq!(outcome.block, FencingGateBlock::FencingInProgress);
            assert_eq!(outcome.action.unwrap().outcome, expected);
            assert_eq!(voids, 1);
            assert_eq!(stage14_9_spawns(&f), ["1"]);
            assert_eq!(
                stage14_9_incident(&f).unwrap().state,
                FencingState::Verifying {
                    attempt_token: 1,
                    action_outcome: expected,
                }
            );
        }

        // Trust: a test-user-owned executable is refused before any spawn.
        let mut f = stage14_9_none();
        let own = f.fixture.parts.path.with_extension("fence");
        std::fs::write(&own, format!("#!/bin/sh\necho x >> {}\n", f.log.display())).unwrap();
        std::fs::set_permissions(&own, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let settings = crate::fencing_backend::FencingSettings::from_config(Some(
            &crate::config::FencingConfig {
                backend: crate::config::FencingBackendKind::Command,
                fence: Some(vec![own.display().to_string()]),
                verify: Some(vec![own.display().to_string()]),
                fence_timeout_sec: Some(10),
                verify_timeout_sec: Some(10),
                verify_polls: Some(1),
            },
        ))
        .unwrap();
        f.fixture
            .parts
            .runtime
            .set_fencing_settings_for_test(settings);
        let (outcome, _) = stage14_9_gate(&mut f, Term(41));
        std::fs::remove_file(&own).unwrap();
        assert_eq!(outcome.action.unwrap().outcome, ActionOutcome::SpawnFailed);
        assert!(stage14_9_spawns(&f).is_empty(), "nothing ran");
    }

    /// B. Pending-reap occupied: the §16.7.4 gate refuses the fence action
    /// without spawning (`spawn-failed` provenance), the slot keeps its
    /// leader, and the attempt still blocks.
    #[test]
    fn stage14_9_b_pending_reap_occupied_refuses_the_action() {
        use crate::fencing::{ActionOutcome, FencingGateBlock};
        let mut f = stage14_9_command(STAGE14_9_FENCE_OK, STAGE14_9_ISOLATED, 10, 10, 3);
        let (leader, pid) = stage14_6_leader("/usr/bin/sleep", &["30"]);
        stage14_6_retain(&mut f.fixture.parts.runtime, leader, pid);
        let (outcome, _) = stage14_9_gate(&mut f, Term(41));
        assert_eq!(outcome.block, FencingGateBlock::FencingInProgress);
        assert_eq!(outcome.action.unwrap().outcome, ActionOutcome::SpawnFailed);
        assert!(stage14_9_spawns(&f).is_empty());
        assert_eq!(
            stage14_6_view(&mut f.fixture.parts.runtime).unwrap().pid,
            pid
        );
        // The verify poll is refused the same way (inconclusive spawn-failed).
        let incident = stage14_9_incident(&f).unwrap();
        let (step, _) = stage14_9_drive(&mut f, Some(&stage14_9_record(&incident, Term(41))));
        assert!(matches!(
            step,
            FencingStepOutcome::Polled {
                result: crate::fencing_backend::VerifyOutcome::Inconclusive(
                    crate::fencing::InconclusiveKind::SpawnFailed
                ),
                ..
            }
        ));
        assert!(stage14_9_spawns(&f).is_empty());
        unsafe {
            libc::kill(pid as i32, libc::SIGKILL);
        }
        stage14_6_until_zombie(pid);
        f.fixture.parts.runtime.poll_pending_reap_foreground();
        assert!(stage14_6_view(&mut f.fixture.parts.runtime).is_none());
    }

    /// B / R7. Shutdown (and any non-eligible local state) runs nothing: no
    /// read-modify-write, no process, no void — at G and at the step.
    #[test]
    fn stage14_9_b_shutdown_and_ineligible_state_run_nothing() {
        use crate::fencing::FencingGateBlock;
        let mut f = stage14_9_command(STAGE14_9_FENCE_OK, STAGE14_9_ISOLATED, 10, 10, 3);
        let before = stage14_8_state(&f.fixture);
        let (outcome, voids) = stage14_9_gate_with(&mut f, Term(41), true, true);
        assert_eq!(outcome.block, FencingGateBlock::NotEligible);
        assert_eq!(voids, 0);
        assert_eq!(stage14_8_state(&f.fixture), before);

        let incident = stage14_9_verifying(&mut f);
        let record = stage14_9_record(&incident, Term(41));
        let before = stage14_8_state(&f.fixture);
        let (step, voids) = stage14_9_drive_with(&mut f, Some(&record), true, true);
        assert_eq!(step, FencingStepOutcome::NotEligible);
        assert_eq!(voids, 0);
        install_test_authority(&mut f.fixture.parts.runtime);
        let (outcome, _) = stage14_9_gate(&mut f, Term(41));
        assert_eq!(outcome.block, FencingGateBlock::NotEligible);
        let (step, _) = stage14_9_drive(&mut f, Some(&record));
        assert_eq!(step, FencingStepOutcome::NotEligible);
        assert_eq!(stage14_8_state(&f.fixture), before);
        assert_eq!(stage14_9_spawns(&f), ["1"]);
    }

    /// C. Verification: exactly `isolated` confirms by backend (T5, the
    /// verification mint site) after voiding the window; exactly
    /// `not-isolated` fails (T6). A `CONFIRMED` incident then blocks at G
    /// (`ConfirmedClearanceDeferred`) with no write and no action.
    #[test]
    fn stage14_9_c_verify_isolated_confirms_and_still_blocks() {
        use crate::fencing::{ConfirmedBy, FencingState};
        let mut f = stage14_9_command(STAGE14_9_FENCE_OK, STAGE14_9_ISOLATED, 10, 10, 3);
        let incident = stage14_9_verifying(&mut f);
        let record = stage14_9_record(&incident, Term(41));
        let (step, voids) = stage14_9_drive(&mut f, Some(&record));
        let confirmed = FencingState::Confirmed(ConfirmedBy::Backend { attempt_token: 1 });
        assert_eq!(
            step,
            FencingStepOutcome::Polled {
                attempt_token: 1,
                result: crate::fencing_backend::VerifyOutcome::Isolated,
                applied: VerifyApplied::Written(confirmed.clone()),
            }
        );
        assert_eq!(voids, 1);
        assert_eq!(stage14_9_incident(&f).unwrap().state, confirmed);
        // A later step against CONFIRMED does nothing.
        let before = stage14_8_state(&f.fixture);
        assert_eq!(
            stage14_9_drive(&mut f, Some(&record)).0,
            FencingStepOutcome::NoAction
        );
        // F (Phase 14.10). A valid CONFIRMED mints the clearance for the exact
        // durable incident at G — and only that: G writes nothing, runs
        // nothing, and creates no authority.
        let (decision, voids) = stage14_9_gate_decision_with(&mut f, Term(41), false, true);
        stage14_10_assert_cleared(decision, &incident, Term(41));
        assert_eq!(voids, 0);
        assert_eq!(stage14_8_state(&f.fixture), before);
        assert_eq!(stage14_9_spawns(&f), ["1", "verify 1"]);
        stage14_9_assert_no_authority(&f);
    }

    /// C. Inconclusive polls: with budget remaining the state is unchanged
    /// (no durable write); the last permitted poll writes
    /// `UNKNOWN(verify-inconclusive(kind))` (T7); after exhaustion nothing
    /// runs. A timed-out poll is bounded by `verify_timeout + 4.5 s`, and
    /// malformed output is inconclusive.
    #[test]
    fn stage14_9_c_inconclusive_polls_exhaust_the_budget() {
        use crate::fencing::{FencingState, InconclusiveKind, UnknownReason};
        use crate::fencing_backend::VerifyOutcome;
        for (verify, timeout, kind) in [
            (
                "echo \"verify $MIKAGAMI_FENCE_ATTEMPT\" >> {log}; exit 3",
                10,
                InconclusiveKind::NonzeroExit,
            ),
            (
                "echo \"verify $MIKAGAMI_FENCE_ATTEMPT\" >> {log}; exec /usr/bin/sleep 30",
                1,
                InconclusiveKind::Timeout,
            ),
            (
                "echo \"verify $MIKAGAMI_FENCE_ATTEMPT\" >> {log}; echo Isolated",
                10,
                InconclusiveKind::MalformedOutput,
            ),
        ] {
            let mut f = stage14_9_command(STAGE14_9_FENCE_OK, verify, 10, timeout, 2);
            let incident = stage14_9_verifying(&mut f);
            let record = stage14_9_record(&incident, Term(41));
            let before = stage14_8_state(&f.fixture);
            let started = std::time::Instant::now();
            let (first, _) = stage14_9_drive(&mut f, Some(&record));
            assert!(started.elapsed() <= Duration::from_millis(timeout * 1000 + 4500));
            assert_eq!(
                first,
                FencingStepOutcome::Polled {
                    attempt_token: 1,
                    result: VerifyOutcome::Inconclusive(kind),
                    applied: VerifyApplied::Unchanged,
                }
            );
            assert_eq!(stage14_8_state(&f.fixture), before, "no durable write");
            let (last, _) = stage14_9_drive(&mut f, Some(&record));
            let unknown = FencingState::Unknown(UnknownReason::VerifyInconclusive { kind });
            assert_eq!(
                last,
                FencingStepOutcome::Polled {
                    attempt_token: 1,
                    result: VerifyOutcome::Inconclusive(kind),
                    applied: VerifyApplied::Written(unknown.clone()),
                }
            );
            assert_eq!(stage14_9_incident(&f).unwrap().state, unknown);
            let (after, voids) = stage14_9_drive(&mut f, Some(&record));
            assert_eq!(after, FencingStepOutcome::NoAction);
            assert_eq!(voids, 0);
            assert_eq!(stage14_9_spawns(&f), ["1", "verify 1", "verify 1"]);
        }
    }

    /// C. The poll budget is the runtime-only counter of this process session,
    /// keyed by (incident, attempt token): once `verify_polls` polls ran for
    /// `VERIFYING(k)` — e.g. the last poll's result was discarded or not
    /// committed, so the state is still `VERIFYING(k)` — no further poll runs
    /// for that token. A counter for another token or incident does not
    /// apply; counting starts again at zero.
    #[test]
    fn stage14_9_c_poll_budget_counts_polls_per_token() {
        let mut f = stage14_9_command(
            STAGE14_9_FENCE_OK,
            "echo \"verify $MIKAGAMI_FENCE_ATTEMPT\" >> {log}; exit 3",
            10,
            10,
            3,
        );
        let incident = stage14_9_verifying(&mut f);
        let record = stage14_9_record(&incident, Term(41));
        f.fixture.parts.runtime.verify_poll_counter = Some((incident.incident_ref(), 1, 3));
        let before = stage14_8_state(&f.fixture);
        let (step, voids) = stage14_9_drive(&mut f, Some(&record));
        assert_eq!(step, FencingStepOutcome::NoAction);
        assert_eq!(voids, 0);
        assert_eq!(stage14_8_state(&f.fixture), before);
        assert_eq!(stage14_9_spawns(&f), ["1"], "no poll beyond the budget");
        let other_incident = crate::fencing::IncidentRef {
            incident_seq: incident.incident_seq + 1,
            incident_id: incident.incident_id.clone(),
        };
        for stale in [(incident.incident_ref(), 2, 3), (other_incident, 1, 3)] {
            f.fixture.parts.runtime.verify_poll_counter = Some(stale);
            let (step, _) = stage14_9_drive(&mut f, Some(&record));
            assert!(matches!(
                step,
                FencingStepOutcome::Polled {
                    applied: VerifyApplied::Unchanged,
                    ..
                }
            ));
            assert_eq!(
                f.fixture.parts.runtime.verify_poll_counter,
                Some((incident.incident_ref(), 1, 1))
            );
        }
        assert_eq!(stage14_9_spawns(&f), ["1", "verify 1", "verify 1"]);
    }

    /// D. Attestation through the step (§18.5 at its one production caller):
    /// a malformed intent and a wrong-incident intent change nothing and
    /// consume the iteration (no verify poll); a valid intent confirms by
    /// operator (T8); a replay is a no-op; G then blocks. With no intent the
    /// step proceeds to the verify poll.
    #[test]
    fn stage14_9_d_attestation_composes_through_the_step() {
        use crate::fencing::{ConfirmedBy, FencingState};
        let mut f = stage14_9_command(
            STAGE14_9_FENCE_OK,
            "echo \"verify $MIKAGAMI_FENCE_ATTEMPT\" >> {log}; exit 3",
            10,
            10,
            60,
        );
        let incident = stage14_9_verifying(&mut f);
        let record = stage14_9_record(&incident, Term(41));
        let before = stage14_8_state(&f.fixture);

        let malformed = f
            .fixture
            .dir
            .join(crate::attestation::ATTESTATION_INTENT_FILE);
        std::fs::write(&malformed, "not = [toml").unwrap();
        std::fs::set_permissions(
            &malformed,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
        let (step, voids) = stage14_9_drive(&mut f, Some(&record));
        assert!(matches!(
            step,
            FencingStepOutcome::Ingested(AttestationIngestion::RejectedFile { removed: true, .. })
        ));
        assert_eq!(voids, 0);
        assert_eq!(stage14_8_state(&f.fixture), before);

        let mut wrong = stage14_8_intent(&incident, STAGE14_8_ATTESTATION);
        wrong.incident_seq = 7;
        let mut statement = stage14_8_intent(&incident, STAGE14_8_ATTESTATION);
        statement.statement = "confirm-fenced".into();
        for (bad, mismatch) in [
            (wrong, crate::attestation::IntentMismatch::Incident),
            (statement, crate::attestation::IntentMismatch::Statement),
        ] {
            stage14_8_install(&f.fixture, &bad);
            let (step, _) = stage14_9_drive(&mut f, Some(&record));
            assert_eq!(
                step,
                FencingStepOutcome::Ingested(AttestationIngestion::RejectedIntent {
                    mismatch,
                    removed: true,
                })
            );
        }
        assert_eq!(stage14_8_state(&f.fixture), before);
        assert_eq!(stage14_9_spawns(&f), ["1"], "no verify poll ran");

        // No intent: the iteration goes on to the verify poll.
        let (step, _) = stage14_9_drive(&mut f, Some(&record));
        assert!(matches!(step, FencingStepOutcome::Polled { .. }));

        let intent = stage14_8_intent(&incident, STAGE14_8_ATTESTATION);
        stage14_8_install(&f.fixture, &intent);
        let (step, _) = stage14_9_drive(&mut f, Some(&record));
        assert_eq!(
            step,
            FencingStepOutcome::Ingested(AttestationIngestion::Confirmed {
                incident: incident.incident_ref(),
                removed: true,
            })
        );
        let confirmed = FencingState::Confirmed(ConfirmedBy::Operator {
            attestation_id: crate::fencing::AttestationId::new(STAGE14_8_ATTESTATION),
        });
        assert_eq!(stage14_9_incident(&f).unwrap().state, confirmed);
        stage14_8_install(&f.fixture, &intent);
        let (step, _) = stage14_9_drive(&mut f, Some(&record));
        assert_eq!(
            step,
            FencingStepOutcome::Ingested(AttestationIngestion::AlreadyConfirmed { removed: true })
        );
        let (decision, _) = stage14_9_gate_decision_with(&mut f, Term(41), false, true);
        stage14_10_assert_cleared(decision, &incident, Term(41));
        assert_eq!(stage14_9_spawns(&f), ["1", "verify 1"]);
        stage14_9_assert_no_authority(&f);
    }

    /// D / R1-R3. A continuity failure retires the incident (T9) before any
    /// ingestion or poll: the intent is not read and nothing runs. A stale
    /// intent for the retired incident then confirms nothing.
    #[test]
    fn stage14_9_d_continuity_failure_retires_before_ingestion() {
        let mut f = stage14_9_command(STAGE14_9_FENCE_OK, STAGE14_9_ISOLATED, 10, 10, 3);
        let incident = stage14_9_verifying(&mut f);
        let record = stage14_9_record(&incident, Term(41));
        let intent = stage14_8_intent(&incident, STAGE14_8_ATTESTATION);
        stage14_8_install(&f.fixture, &intent);
        let (step, voids) = stage14_9_drive_with(&mut f, Some(&record), false, false);
        assert_eq!(
            step,
            FencingStepOutcome::Retired(crate::fencing::ContinuityViolation::Episode)
        );
        assert_eq!(voids, 0);
        assert_eq!(stage14_9_incident(&f), None);
        assert!(stage14_8_pending(&f.fixture), "the intent was not read");
        // The stale intent can never confirm a later incident.
        let (outcome, _) = stage14_9_gate(&mut f, Term(41));
        let fresh = stage14_9_incident(&f).unwrap();
        assert_eq!(fresh.incident_seq, 2);
        assert_eq!(outcome.incident, Some(stage14_9_record(&fresh, Term(41))));
        let (step, _) = stage14_9_drive(&mut f, Some(&stage14_9_record(&fresh, Term(41))));
        assert!(matches!(
            step,
            FencingStepOutcome::Ingested(AttestationIngestion::RejectedIntent {
                removed: true,
                ..
            })
        ));
        assert!(matches!(
            stage14_9_incident(&f).unwrap().state,
            crate::fencing::FencingState::Verifying { .. }
        ));
    }

    /// E. R4 input. A missing record, or a record for another incident (a
    /// pre-incident or foreign term), fails closed with no mutation, no
    /// ingestion, and no process. A newer authenticated term than the anchor
    /// retires the incident. A term equal to the anchor proceeds. Once a
    /// different term is recorded, a later anchor-equal term cannot mask it.
    #[test]
    fn stage14_9_e_r4_term_record_is_incident_bound_and_fail_closed() {
        let mut f = stage14_9_command(STAGE14_9_FENCE_OK, STAGE14_9_ISOLATED, 10, 10, 3);
        let incident = stage14_9_verifying(&mut f);
        let intent = stage14_8_intent(&incident, STAGE14_8_ATTESTATION);
        stage14_8_install(&f.fixture, &intent);
        let before = stage14_8_state(&f.fixture);
        let foreign = IncidentTermRecord {
            incident: crate::fencing::IncidentRef {
                incident_seq: incident.incident_seq + 1,
                incident_id: incident.incident_id.clone(),
            },
            anchor: Term(41),
            newest: Term(41),
        };
        for record in [None, Some(&foreign)] {
            let (step, voids) = stage14_9_drive(&mut f, record);
            assert_eq!(step, FencingStepOutcome::R4EvidenceMissing);
            assert_eq!(voids, 0);
            assert_eq!(stage14_8_state(&f.fixture), before);
            assert!(stage14_8_pending(&f.fixture));
        }
        assert_eq!(stage14_9_spawns(&f), ["1"]);

        let mut record = stage14_9_record(&incident, Term(41));
        record.record_term(Term(42));
        record.record_term(Term(41));
        assert_eq!(record.newest, Term(42), "a divergent term is kept");
        let (step, _) = stage14_9_drive(&mut f, Some(&record));
        assert_eq!(
            step,
            FencingStepOutcome::Retired(crate::fencing::ContinuityViolation::WitnessEpoch)
        );
        assert_eq!(stage14_9_incident(&f), None);

        let mut f = stage14_9_command(STAGE14_9_FENCE_OK, STAGE14_9_ISOLATED, 10, 10, 3);
        let incident = stage14_9_verifying(&mut f);
        let mut record = stage14_9_record(&incident, Term(41));
        record.record_term(Term(41));
        let (step, _) = stage14_9_drive(&mut f, Some(&record));
        assert!(matches!(
            step,
            FencingStepOutcome::Polled {
                applied: VerifyApplied::Written(crate::fencing::FencingState::Confirmed(_)),
                ..
            }
        ));
    }

    // ---- G8-A / G8-B (§34.19): shutdown latency through the real loop ----

    /// The loop-level harness: the real `Daemon` and `run_observation_loop`
    /// over this runtime owner. G and the foreground step call the real
    /// runtime composition exactly as `LinuxDaemonRuntime` does; every
    /// post-G promotion method panics, so reaching H-L fails the test.
    struct Stage149Loop {
        f: Stage149,
        record: Option<IncidentTermRecord>,
        step_returned_at: Vec<std::time::Instant>,
        descendant_dead_within_1s: Vec<bool>,
    }

    impl Stage149Loop {
        fn context_parts(
            &self,
        ) -> (
            NodeId,
            crate::protocol::SessionId,
            Option<crate::failure_assessment::LocalLossEvidence>,
        ) {
            stage14_9_context_parts(true)
        }

        fn after_step(&mut self) {
            self.step_returned_at.push(std::time::Instant::now());
            if let Ok(pid) = std::fs::read_to_string(&self.f.pid) {
                let pid: u32 = pid.trim().parse().unwrap();
                let until = std::time::Instant::now() + Duration::from_secs(1);
                let mut dead = false;
                while std::time::Instant::now() < until {
                    if matches!(stage14_6_state(pid), None | Some('Z')) {
                        dead = true;
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                self.descendant_dead_within_1s.push(dead);
            }
        }
    }

    impl crate::daemon::DaemonRuntime for Stage149Loop {
        fn startup(&mut self) -> Result<crate::daemon::DaemonSnapshot, String> {
            Ok(stage14_9_standby())
        }

        fn observe(&mut self) -> Result<crate::daemon::DaemonSnapshot, String> {
            Ok(stage14_9_standby())
        }

        fn shutdown(
            &mut self,
            control_lock_safe: &dyn Fn() -> bool,
        ) -> Result<crate::daemon::ShutdownResult, String> {
            self.f
                .fixture
                .parts
                .runtime
                .shutdown_for_daemon(control_lock_safe)
                .map(|clean| {
                    if clean {
                        crate::daemon::ShutdownResult::Clean
                    } else {
                        crate::daemon::ShutdownResult::RequiresCleanup
                    }
                })
                .map_err(|error| error.to_string())
        }

        fn foreground_lifecycle_tick(
            &mut self,
            _shutdown_requested: &dyn Fn() -> bool,
            live_shutdown: &dyn Fn() -> bool,
            _control_lock_safe: &dyn Fn() -> bool,
        ) -> Result<(), String> {
            self.f.fixture.parts.runtime.poll_pending_reap_foreground();
            let (peer, session, evidence) = self.context_parts();
            let context = crate::fencing::ContinuityContext {
                configured_peer: &peer,
                current_session: &session,
                live_episode: evidence.as_ref(),
            };
            let outcome = self
                .f
                .fixture
                .parts
                .runtime
                .drive_fencing_step(&context, self.record.as_ref(), live_shutdown, &mut || {})
                .map_err(|error| error.to_string())?;
            if matches!(outcome, FencingStepOutcome::Polled { .. }) {
                self.after_step();
                stage14_9_trace(Stage149Traced::Step(outcome));
            }
            Ok(())
        }
    }

    impl crate::daemon::PromotionExecutionRuntime for Stage149Loop {
        fn begin_authority_observation(
            &mut self,
            _context: crate::daemon::DaemonIterationContext,
        ) -> Result<(), String> {
            Ok(())
        }

        fn evaluate_authority_attempt(
            &mut self,
            _context: crate::daemon::DaemonIterationContext,
        ) -> Result<Option<crate::daemon::AuthorityAttemptEvaluation>, String> {
            Ok(Some(
                crate::daemon::stage14_9_support::authorized_evaluation(),
            ))
        }

        fn fencing_gate(
            &mut self,
            evaluation: &crate::daemon::AuthorityAttemptEvaluation,
            shutdown_requested: &dyn Fn() -> bool,
        ) -> crate::daemon::FencingGate {
            let view = evaluation.observation().authority_view().term();
            let (peer, session, evidence) = self.context_parts();
            let context = crate::fencing::ContinuityContext {
                configured_peer: &peer,
                current_session: &session,
                live_episode: evidence.as_ref(),
            };
            let decision = self
                .f
                .fixture
                .parts
                .runtime
                .fencing_gate(view, &context, shutdown_requested, &mut || {})
                .unwrap();
            match decision {
                FencingGateDecision::Block(outcome) => {
                    if outcome.action.is_some() {
                        self.after_step();
                    }
                    stage14_9_trace(Stage149Traced::Gate(outcome.block, outcome.action.clone()));
                    self.record = outcome.incident.clone();
                    crate::daemon::FencingGate::Blocked(outcome.block)
                }
                FencingGateDecision::Clear {
                    incident,
                    clearance,
                } => {
                    stage14_9_trace(Stage149Traced::Cleared(incident.incident.clone()));
                    self.record = Some(incident);
                    crate::daemon::FencingGate::Cleared(clearance)
                }
            }
        }

        /// This harness has no Witness: H is recorded and fails, so the
        /// attempt blocks with no lease. The Phase 14.10 H-L composition is
        /// exercised by the `stage14_10_*` harness.
        fn acquire_attempt_lease_once(
            &mut self,
            term: Term,
        ) -> Result<
            crate::node_lease_authority::node_witness_runtime::NodeWitnessMutationResult,
            String,
        > {
            stage14_9_trace(Stage149Traced::LeaseRequest(term));
            Err("no Witness in the Phase 14.9 loop harness".into())
        }

        fn take_attempt_lease_authority(
            &mut self,
        ) -> Option<crate::node_lease_authority::RuntimeLeaseAuthority> {
            panic!("Phase 14.9: lease authority after G");
        }

        fn attempt_lease_usable(
            &self,
            _authority: &crate::node_lease_authority::RuntimeLeaseAuthority,
        ) -> bool {
            panic!("Phase 14.9: K after G");
        }

        fn shared_witness_outstanding(&self) -> bool {
            false
        }

        fn fencing_final_recheck(
            &mut self,
            _prerequisite: &crate::daemon::FencingPrerequisite,
            _grant_term: Term,
        ) -> Result<(), String> {
            panic!("Phase 14.9 harness: K without a grant");
        }

        fn release_attempt_lease(
            &mut self,
            _granted: Option<(Term, crate::protocol::LeaseId)>,
            _binding: Option<&crate::fencing::IncidentBinding>,
        ) -> Result<crate::daemon::AttemptCleanup, String> {
            panic!("Phase 14.9 harness: lease cleanup without a grant");
        }

        fn execute_attempt_promotion(
            &mut self,
            _lease: crate::daemon::AttemptBoundLeaseAuthority,
            _prerequisite: &crate::daemon::FencingPrerequisite,
        ) -> Result<crate::daemon::AttemptPromotionOutcome, String> {
            panic!("Phase 14.9 harness: L without a grant");
        }
    }

    fn stage14_9_standby() -> crate::daemon::DaemonSnapshot {
        crate::daemon::DaemonSnapshot {
            node_state: NodeState::Standby,
            health: crate::daemon::DaemonHealth::Healthy,
            vip: crate::daemon::DaemonVip::Absent,
            service: crate::daemon::DaemonService::Stopped,
            resource_owning: false,
            recovery_reconciled: true,
            unresolved_mutation: false,
        }
    }

    struct Stage149Latch(std::cell::Cell<bool>);

    /// What the loop harness's gate and verify polls returned, in order.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Stage149Traced {
        Gate(
            crate::fencing::FencingGateBlock,
            Option<FencingActionRecord>,
        ),
        /// G minted the clearance for this durable incident.
        Cleared(crate::fencing::IncidentRef),
        /// H: a LeaseRequest with this observed term was attempted.
        LeaseRequest(Term),
        Step(FencingStepOutcome),
    }

    thread_local! {
        /// A thread-local keeps `Stage149Loop`'s shape unchanged (the
        /// independent audit's Annex B probes build it literally); the loop
        /// runs on the test's own thread.
        static STAGE14_9_LOOP_TRACE: std::cell::RefCell<Vec<Stage149Traced>> =
            const { std::cell::RefCell::new(Vec::new()) };
    }

    fn stage14_9_trace(traced: Stage149Traced) {
        STAGE14_9_LOOP_TRACE.with(|trace| trace.borrow_mut().push(traced));
    }

    /// Take (and clear) this thread's loop trace.
    fn stage14_9_loop_trace() -> Vec<Stage149Traced> {
        STAGE14_9_LOOP_TRACE.with(|trace| std::mem::take(&mut *trace.borrow_mut()))
    }

    impl crate::daemon_run::PromotionIntentLatch for Stage149Latch {
        fn consume(&self) -> bool {
            self.0.replace(false)
        }
        fn discard(&self) {
            self.0.set(false);
        }
    }

    enum Stage149Step {
        Action,
        Verify,
    }

    /// Run the real loop with a 1 s interval. For `Action`, one SIGUSR1
    /// intent is set after the first wait (the attempt runs in iteration 2);
    /// for `Verify`, the incident is `VERIFYING(1)` and the first ordinary
    /// tick runs the poll. Shutdown is requested `shutdown_after` into the
    /// running step. Returns (exit, step start, shutdown time, exit time).
    fn stage14_9_g8(
        f: Stage149,
        step: Stage149Step,
        shutdown_after: Duration,
    ) -> (
        crate::daemon_run::LoopExit,
        Stage149Loop,
        std::time::Instant,
        std::time::Instant,
        std::time::Instant,
    ) {
        let mut harness = Stage149Loop {
            f,
            record: None,
            step_returned_at: Vec::new(),
            descendant_dead_within_1s: Vec::new(),
        };
        let verify = matches!(step, Stage149Step::Verify);
        let _ = stage14_9_loop_trace();
        if verify {
            let incident = stage14_9_verifying(&mut harness.f);
            std::fs::write(&harness.f.log, "").unwrap();
            let _ = std::fs::remove_file(&harness.f.pid);
            harness.record = Some(stage14_9_record(&incident, Term(41)));
        }
        let mut daemon = crate::daemon::Daemon::new(harness);
        daemon.start().unwrap();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        // As production does (F14.9-01): the Daemon reads the same latch the
        // loop's `should_stop` reads.
        let signal = stop.clone();
        daemon.attach_shutdown_signal(move || signal.load(std::sync::atomic::Ordering::SeqCst));
        let stopped_at = std::sync::Arc::new(std::sync::Mutex::new(None));
        let latch = Stage149Latch(std::cell::Cell::new(false));
        let started = std::cell::Cell::new(None);
        let mut waits = 0;
        let arm = |stop: &std::sync::Arc<std::sync::atomic::AtomicBool>,
                   stopped_at: &std::sync::Arc<std::sync::Mutex<Option<std::time::Instant>>>| {
            let (stop, stopped_at) = (stop.clone(), stopped_at.clone());
            std::thread::spawn(move || {
                std::thread::sleep(shutdown_after);
                *stopped_at.lock().unwrap() = Some(std::time::Instant::now());
                stop.store(true, std::sync::atomic::Ordering::SeqCst);
            });
        };
        if verify {
            started.set(Some(std::time::Instant::now()));
            arm(&stop, &stopped_at);
        }
        let exit = crate::daemon_run::run_observation_loop(
            &mut daemon,
            Duration::from_secs(1),
            || stop.load(std::sync::atomic::Ordering::SeqCst),
            |delay| {
                waits += 1;
                if !verify && waits == 1 {
                    latch.0.set(true);
                }
                std::thread::sleep(delay);
            },
            std::time::Instant::now,
            &latch,
            |_, _| {},
            |daemon| {
                started.set(Some(std::time::Instant::now()));
                arm(&stop, &stopped_at);
                let result = daemon.execute_promotion_attempt(
                    crate::promotion_attempt::PromotionExecutionRequest::new(
                        crate::promotion_attempt::PromotionRequestId::new("stage14-9-g8"),
                    ),
                );
                assert_eq!(
                    result,
                    crate::promotion_attempt::PromotionAttemptResult::BlockedBeforeMutation
                );
            },
        );
        let exited = std::time::Instant::now();
        let shutdown_at = stopped_at.lock().unwrap().expect("shutdown was requested");
        let started = started.get().expect("the step started");
        let harness = crate::daemon::stage14_9_support::into_runtime(daemon);
        (exit, harness, started, shutdown_at, exited)
    }

    /// The §34.19 bound: the loop exits within (the running step's
    /// `return_deadline` − shutdown time) + one iteration. `return_deadline`
    /// is at most `timeout + 4.5 s` after the step started (measured from
    /// before G/the step, so the check is conservative); one iteration is the
    /// 1 s cadence. The step also must not have returned before its
    /// execution deadline, and shutdown must not start a fresh timeout.
    fn stage14_9_assert_g8(
        (exit, mut harness, started, shutdown_at, exited): (
            crate::daemon_run::LoopExit,
            Stage149Loop,
            std::time::Instant,
            std::time::Instant,
            std::time::Instant,
        ),
        timeout: u64,
        expected_spawns: &[&str],
        descendant: bool,
    ) -> Stage149Loop {
        let return_deadline = started + Duration::from_millis(timeout * 1000 + 4500);
        let iteration = Duration::from_secs(1);
        assert_eq!(
            exit,
            crate::daemon_run::LoopExit::Clean,
            "classification unchanged"
        );
        assert!(
            exited.saturating_duration_since(shutdown_at)
                <= return_deadline.saturating_duration_since(shutdown_at) + iteration,
            "loop exit {:?} after shutdown exceeds the bound {:?}",
            exited.saturating_duration_since(shutdown_at),
            return_deadline.saturating_duration_since(shutdown_at) + iteration
        );
        assert_eq!(harness.step_returned_at.len(), 1, "exactly one step");
        let returned = harness.step_returned_at[0];
        eprintln!(
            "G8 timeout={timeout}s: step returned {:?} after start; shutdown {:?} after start; \
             loop exit {:?} after shutdown (bound {:?})",
            returned.saturating_duration_since(started),
            shutdown_at.saturating_duration_since(started),
            exited.saturating_duration_since(shutdown_at),
            return_deadline.saturating_duration_since(shutdown_at) + iteration
        );
        assert!(
            returned >= started + Duration::from_secs(timeout),
            "not before the execution deadline"
        );
        assert!(returned <= return_deadline + Duration::from_millis(200));
        assert!(shutdown_at < returned, "shutdown arrived during the step");
        assert_eq!(
            stage14_9_spawns(&harness.f),
            expected_spawns,
            "no step after shutdown"
        );
        if descendant {
            assert_eq!(harness.descendant_dead_within_1s, [true]);
        }
        assert!(stage14_6_view(&mut harness.f.fixture.parts.runtime).is_none());
        stage14_9_assert_no_authority(&harness.f);
        harness
    }

    /// G8-A: shutdown 30 s into a fence action at `fence_timeout_sec = 60`
    /// whose TERM-ignoring direct child runs until KILL. A shutdown-reset
    /// timeout would return after ≥ 90 s and fail the bound. The action
    /// returned after the shutdown, so its (`timed-out`) result is discarded
    /// (§27.2 step 3, F14.9-01): no T4, the incident stays `REQUESTED(1)`
    /// (restart retires it).
    #[test]
    fn stage14_9_g8a_shutdown_during_term_ignoring_action_at_maximum() {
        let f = stage14_9_command(
            "echo \"$MIKAGAMI_FENCE_ATTEMPT\" >> {log}; trap '' TERM; exec /usr/bin/sleep 600",
            STAGE14_9_ISOLATED,
            60,
            30,
            60,
        );
        let harness = stage14_9_assert_g8(
            stage14_9_g8(f, Stage149Step::Action, Duration::from_secs(30)),
            60,
            &["1"],
            false,
        );
        assert_eq!(
            stage14_9_incident(&harness.f).unwrap().state,
            crate::fencing::FencingState::Requested { attempt_token: 1 }
        );
        assert_eq!(stage14_9_loop_trace(), [stage14_9_g8_discarded_action()]);
    }

    /// The one gate of a G8 action run: a bounded `timed-out` action (never
    /// success) whose result was discarded because shutdown arrived.
    fn stage14_9_g8_discarded_action() -> Stage149Traced {
        Stage149Traced::Gate(
            crate::fencing::FencingGateBlock::FencingInProgress,
            Some(FencingActionRecord {
                attempt_token: 1,
                outcome: crate::fencing::ActionOutcome::TimedOut,
                verifying_persisted: false,
            }),
        )
    }

    fn stage14_9_g8b_script(stream: &str, verify: bool) -> String {
        let redirect = match stream {
            "stdout" => "2>/dev/null",
            "stderr" => ">/dev/null",
            _ => "",
        };
        let log = if verify {
            "echo \"verify $MIKAGAMI_FENCE_ATTEMPT\" >> {log}"
        } else {
            "echo \"$MIKAGAMI_FENCE_ATTEMPT\" >> {log}"
        };
        let output = if verify { "echo isolated; " } else { "" };
        format!("{log}; /usr/bin/sleep 600 {redirect} & echo $! > {{pid}}; {output}exit 0")
    }

    /// G8-B (action): the leader exits 0 at once while a same-group
    /// descendant holds stdout, stderr, or both; shutdown 30 s in. The step
    /// returns only after its execution deadline and by its return deadline,
    /// the outcome is `timed-out` (never success), and the descendant is dead
    /// within 1 s after the step returns. The result is discarded (no T4,
    /// F14.9-01): the incident stays `REQUESTED(1)`.
    #[test]
    fn stage14_9_g8b_shutdown_during_action_with_pipe_holding_descendant() {
        for stream in ["stdout", "stderr", "both"] {
            let f = stage14_9_command(
                &stage14_9_g8b_script(stream, false),
                STAGE14_9_ISOLATED,
                60,
                30,
                60,
            );
            let harness = stage14_9_assert_g8(
                stage14_9_g8(f, Stage149Step::Action, Duration::from_secs(30)),
                60,
                &["1"],
                true,
            );
            assert_eq!(
                stage14_9_incident(&harness.f).unwrap().state,
                crate::fencing::FencingState::Requested { attempt_token: 1 },
                "{stream}"
            );
            assert_eq!(
                stage14_9_loop_trace(),
                [stage14_9_g8_discarded_action()],
                "{stream}"
            );
        }
    }

    /// G8-B (verify poll): as above for the foreground verify poll at
    /// `verify_timeout_sec = 30`, shutdown 15 s in. The leader printed
    /// `isolated` and exited 0, yet the result is inconclusive `timeout`:
    /// no `CONFIRMED`.
    #[test]
    fn stage14_9_g8b_shutdown_during_verify_poll_with_pipe_holding_descendant() {
        for stream in ["stdout", "stderr", "both"] {
            let f = stage14_9_command(
                STAGE14_9_FENCE_OK,
                &stage14_9_g8b_script(stream, true),
                60,
                30,
                60,
            );
            let harness = stage14_9_assert_g8(
                stage14_9_g8(f, Stage149Step::Verify, Duration::from_secs(15)),
                30,
                &["verify 1"],
                true,
            );
            assert_eq!(
                stage14_9_incident(&harness.f).unwrap().state,
                crate::fencing::FencingState::Verifying {
                    attempt_token: 1,
                    action_outcome: crate::fencing::ActionOutcome::ReportedSuccess,
                },
                "{stream}: an inconclusive poll with budget left writes nothing"
            );
            assert_eq!(
                stage14_9_loop_trace(),
                [Stage149Traced::Step(FencingStepOutcome::Polled {
                    attempt_token: 1,
                    result: crate::fencing_backend::VerifyOutcome::Inconclusive(
                        crate::fencing::InconclusiveKind::Timeout
                    ),
                    applied: VerifyApplied::Discarded,
                })],
                "{stream}: the poll returned after the shutdown (F14.9-01)"
            );
        }
    }

    // ---- F14.9-01 (independent audit): shutdown is live at the step ----
    //
    // Rev5 §17.2 / §27.2 step 3: a step result applies only if there is no
    // shutdown after the child returned; §27.4: no step starts after shutdown
    // is observed; §18.5 / §26 R7: no ingestion while shutting down. The race
    // tests order "step running < shutdown < step returned" by a file
    // handshake, not by sleeps.

    /// The step's half of the handshake: touch `{pid}.started` once running,
    /// then wait (bounded by the step's own timeout) for `{pid}.release`.
    const STAGE14_9_F01_HOLD: &str = "/usr/bin/touch {pid}.started; \
         while [ ! -e {pid}.release ]; do /usr/bin/sleep 0.01; done";

    fn stage14_9_f01_marker(f: &Stage149, name: &str) -> PathBuf {
        PathBuf::from(format!("{}.{name}", f.pid.display()))
    }

    /// The test's half: once the running step touched `started`, raise the
    /// shutdown latch, then write `release`. Joining yields (step start
    /// observed, shutdown raised).
    fn stage14_9_f01_race(
        f: &Stage149,
    ) -> (
        std::sync::Arc<std::sync::atomic::AtomicBool>,
        std::thread::JoinHandle<(std::time::Instant, std::time::Instant)>,
    ) {
        let started = stage14_9_f01_marker(f, "started");
        let release = stage14_9_f01_marker(f, "release");
        let _ = std::fs::remove_file(&started);
        let _ = std::fs::remove_file(&release);
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let raise = stop.clone();
        let race = std::thread::spawn(move || {
            let until = std::time::Instant::now() + Duration::from_secs(20);
            while !started.exists() {
                assert!(std::time::Instant::now() < until, "the step never started");
                std::thread::sleep(Duration::from_millis(5));
            }
            let start_observed = std::time::Instant::now();
            raise.store(true, std::sync::atomic::Ordering::SeqCst);
            let shutdown_raised = std::time::Instant::now();
            std::fs::write(&release, "").unwrap();
            (start_observed, shutdown_raised)
        });
        (stop, race)
    }

    fn stage14_9_f01_order(
        what: &str,
        (start_observed, shutdown_raised): (std::time::Instant, std::time::Instant),
        returned: std::time::Instant,
    ) {
        eprintln!(
            "F14.9-01 {what}: operation start observed; shutdown raised +{:?}; \
             operation returned +{:?}",
            shutdown_raised.saturating_duration_since(start_observed),
            returned.saturating_duration_since(start_observed)
        );
        assert!(
            start_observed <= shutdown_raised,
            "{what}: running before shutdown"
        );
        assert!(
            shutdown_raised < returned,
            "{what}: shutdown before the return"
        );
    }

    fn stage14_9_f01_cleanup(f: &Stage149) {
        let _ = std::fs::remove_file(stage14_9_f01_marker(f, "started"));
        let _ = std::fs::remove_file(stage14_9_f01_marker(f, "release"));
    }

    fn stage14_9_f01_verify_script() -> String {
        format!(
            "echo \"verify $MIKAGAMI_FENCE_ATTEMPT\" >> {{log}}; {STAGE14_9_F01_HOLD}; echo isolated"
        )
    }

    fn stage14_9_f01_fence_script() -> String {
        format!("echo \"$MIKAGAMI_FENCE_ATTEMPT\" >> {{log}}; {STAGE14_9_F01_HOLD}; exit 0")
    }

    /// A shutdown query that answers `false` until its `n`-th sample, which
    /// pins the exact sample point a test targets.
    fn stage14_9_f01_from_sample(samples: &Cell<u32>, n: u32) -> impl Fn() -> bool + '_ {
        move || {
            let sample = samples.get() + 1;
            samples.set(sample);
            sample >= n
        }
    }

    /// F14.9-01 test 1 (§17.2; the audit's Annex B probe 1 with a handshake):
    /// shutdown is raised while a verify poll runs, and the poll then returns
    /// a successful `isolated`. The result is discarded: no T5, no
    /// `CONFIRMED`, nothing durable changes, and no later poll starts. The
    /// executed poll stays counted; the process was fully cleaned up.
    #[test]
    fn stage14_9_f01_shutdown_during_successful_verify_discards_it() {
        use crate::fencing::{ActionOutcome, FencingState};
        let mut f = stage14_9_command(
            STAGE14_9_FENCE_OK,
            &stage14_9_f01_verify_script(),
            10,
            10,
            3,
        );
        let incident = stage14_9_verifying(&mut f);
        let record = stage14_9_record(&incident, Term(41));
        let before = stage14_8_state(&f.fixture);
        let (stop, race) = stage14_9_f01_race(&f);
        let shutdown = || stop.load(std::sync::atomic::Ordering::SeqCst);
        let (peer, session, evidence) = stage14_9_context_parts(true);
        let context = crate::fencing::ContinuityContext {
            configured_peer: &peer,
            current_session: &session,
            live_episode: evidence.as_ref(),
        };
        let mut voids = 0;
        let step = f
            .fixture
            .parts
            .runtime
            .drive_fencing_step(&context, Some(&record), &shutdown, &mut || voids += 1)
            .unwrap();
        let returned = std::time::Instant::now();
        stage14_9_f01_order("verify", race.join().unwrap(), returned);
        assert_eq!(
            step,
            FencingStepOutcome::Polled {
                attempt_token: 1,
                result: crate::fencing_backend::VerifyOutcome::Isolated,
                applied: VerifyApplied::Discarded,
            }
        );
        assert_eq!(voids, 1);
        assert_eq!(stage14_8_state(&f.fixture), before, "no T5 persisted");
        assert_eq!(
            stage14_9_incident(&f).unwrap().state,
            FencingState::Verifying {
                attempt_token: 1,
                action_outcome: ActionOutcome::ReportedSuccess,
            }
        );
        assert!(
            stage14_6_view(&mut f.fixture.parts.runtime).is_none(),
            "process cleanup completed"
        );
        assert_eq!(
            f.fixture.parts.runtime.verify_poll_counter,
            Some((incident.incident_ref(), 1, 1)),
            "the executed poll stays counted"
        );
        // No later verify starts while shutdown holds.
        let (step, voids) = stage14_9_drive_with(&mut f, Some(&record), true, true);
        assert_eq!(step, FencingStepOutcome::NotEligible);
        assert_eq!(voids, 0);
        assert_eq!(stage14_9_spawns(&f), ["1", "verify 1"]);
        assert_eq!(stage14_8_state(&f.fixture), before);
        stage14_9_assert_no_authority(&f);
        stage14_9_f01_cleanup(&f);
    }

    /// F14.9-01 test 2 (§27.2 step 3): shutdown is raised while the fence
    /// action runs, and the action then reports success. The result is kept
    /// as provenance of this call only: no T4 (`REQUESTED(1)` stays), so no
    /// verify can begin, and nothing confirms. The process was cleaned up.
    #[test]
    fn stage14_9_f01_shutdown_during_successful_action_discards_it() {
        use crate::fencing::{ActionOutcome, FencingGateBlock, FencingState};
        let mut f = stage14_9_command(&stage14_9_f01_fence_script(), STAGE14_9_ISOLATED, 10, 10, 3);
        let (stop, race) = stage14_9_f01_race(&f);
        let shutdown = || stop.load(std::sync::atomic::Ordering::SeqCst);
        let (peer, session, evidence) = stage14_9_context_parts(true);
        let context = crate::fencing::ContinuityContext {
            configured_peer: &peer,
            current_session: &session,
            live_episode: evidence.as_ref(),
        };
        let mut voids = 0;
        let outcome = f
            .fixture
            .parts
            .runtime
            .fencing_gate(Term(41), &context, &shutdown, &mut || voids += 1)
            .unwrap();
        let FencingGateDecision::Block(outcome) = outcome else {
            panic!("a fence action frame never clears");
        };
        let returned = std::time::Instant::now();
        stage14_9_f01_order("action", race.join().unwrap(), returned);
        assert!(outcome.opened);
        assert_eq!(outcome.block, FencingGateBlock::FencingInProgress);
        assert_eq!(
            outcome.action,
            Some(FencingActionRecord {
                attempt_token: 1,
                outcome: ActionOutcome::ReportedSuccess,
                verifying_persisted: false,
            })
        );
        assert_eq!(voids, 1);
        assert_eq!(
            stage14_9_incident(&f).unwrap().state,
            FencingState::Requested { attempt_token: 1 },
            "no T4 after shutdown"
        );
        assert!(
            stage14_6_view(&mut f.fixture.parts.runtime).is_none(),
            "process cleanup completed"
        );
        let record = outcome.incident.clone().unwrap();
        let before = stage14_8_state(&f.fixture);
        assert_eq!(
            stage14_9_drive_with(&mut f, Some(&record), true, true).0,
            FencingStepOutcome::NotEligible
        );
        // Even after shutdown is gone, `REQUESTED` is never polled.
        assert_eq!(
            stage14_9_drive(&mut f, Some(&record)).0,
            FencingStepOutcome::NoAction
        );
        assert_eq!(stage14_9_spawns(&f), ["1"], "no verify began");
        assert_eq!(stage14_8_state(&f.fixture), before);
        stage14_9_assert_no_authority(&f);
        stage14_9_f01_cleanup(&f);
    }

    /// F14.9-01 (§27.4, §18.5, R7): shutdown observed at the live sample
    /// immediately before a spawn runs nothing — no spawn, no void, no
    /// provenance, no T4-T7, no poll used — and shutdown observed
    /// immediately before ingestion ingests nothing (no T8; the intent file
    /// stays for restart handling).
    #[test]
    fn stage14_9_f01_shutdown_seen_before_a_step_runs_nothing() {
        use crate::fencing::{ConfirmedBy, FencingGateBlock, FencingState};
        let context_parts = stage14_9_context_parts(true);
        let context = crate::fencing::ContinuityContext {
            configured_peer: &context_parts.0,
            current_session: &context_parts.1,
            live_episode: context_parts.2.as_ref(),
        };

        // Gate: sample 1 = eligibility, sample 2 = immediately before the
        // action (after `REQUESTED(1)` committed).
        let mut f = stage14_9_command(STAGE14_9_FENCE_OK, STAGE14_9_ISOLATED, 10, 10, 1);
        let samples = Cell::new(0);
        let mut voids = 0;
        let outcome = f
            .fixture
            .parts
            .runtime
            .fencing_gate(
                Term(41),
                &context,
                &stage14_9_f01_from_sample(&samples, 2),
                &mut || voids += 1,
            )
            .unwrap();
        let FencingGateDecision::Block(outcome) = outcome else {
            panic!("a fence action frame never clears");
        };
        assert_eq!(samples.get(), 2);
        assert_eq!(outcome.block, FencingGateBlock::NotEligible);
        assert_eq!(outcome.action, None);
        assert_eq!(voids, 0);
        assert!(stage14_9_spawns(&f).is_empty(), "no action spawned");
        assert_eq!(
            stage14_9_incident(&f).unwrap().state,
            FencingState::Requested { attempt_token: 1 }
        );

        // Verify: sample 1 = eligibility, 2 = before ingestion, 3 =
        // immediately before the verify.
        let mut f = stage14_9_command(STAGE14_9_FENCE_OK, STAGE14_9_ISOLATED, 10, 10, 1);
        let incident = stage14_9_verifying(&mut f);
        let record = stage14_9_record(&incident, Term(41));
        let before = stage14_8_state(&f.fixture);
        let samples = Cell::new(0);
        let mut voids = 0;
        let step = f
            .fixture
            .parts
            .runtime
            .drive_fencing_step(
                &context,
                Some(&record),
                &stage14_9_f01_from_sample(&samples, 3),
                &mut || voids += 1,
            )
            .unwrap();
        assert_eq!(samples.get(), 3);
        assert_eq!(step, FencingStepOutcome::NotEligible);
        assert_eq!(voids, 0);
        assert_eq!(stage14_9_spawns(&f), ["1"], "no verify spawned");
        assert_eq!(stage14_8_state(&f.fixture), before);
        assert_eq!(f.fixture.parts.runtime.verify_poll_counter, None);
        // No poll was used: with a budget of one, the poll still runs.
        assert_eq!(
            stage14_9_drive(&mut f, Some(&record)).0,
            FencingStepOutcome::Polled {
                attempt_token: 1,
                result: crate::fencing_backend::VerifyOutcome::Isolated,
                applied: VerifyApplied::Written(FencingState::Confirmed(ConfirmedBy::Backend {
                    attempt_token: 1
                })),
            }
        );

        // Ingestion: sample 2 = immediately before ingestion.
        let mut f = stage14_9_command(STAGE14_9_FENCE_OK, STAGE14_9_ISOLATED, 10, 10, 3);
        let incident = stage14_9_verifying(&mut f);
        let record = stage14_9_record(&incident, Term(41));
        stage14_8_install(
            &f.fixture,
            &stage14_8_intent(&incident, STAGE14_8_ATTESTATION),
        );
        let intent_file = f
            .fixture
            .dir
            .join(crate::attestation::ATTESTATION_INTENT_FILE);
        let before = stage14_8_state(&f.fixture);
        let samples = Cell::new(0);
        let step = f
            .fixture
            .parts
            .runtime
            .drive_fencing_step(
                &context,
                Some(&record),
                &stage14_9_f01_from_sample(&samples, 2),
                &mut || {},
            )
            .unwrap();
        assert_eq!(samples.get(), 2);
        assert_eq!(step, FencingStepOutcome::NotEligible);
        assert_eq!(stage14_8_state(&f.fixture), before, "no T8");
        assert!(intent_file.exists(), "the intent was not consumed");
        // The same intent was valid: it confirms once shutdown is gone.
        assert_eq!(
            stage14_9_drive(&mut f, Some(&record)).0,
            FencingStepOutcome::Ingested(AttestationIngestion::Confirmed {
                incident: incident.incident_ref(),
                removed: true,
            })
        );
        assert_eq!(stage14_9_spawns(&f), ["1"]);
    }

    /// F14.9-01 test 3 (the audit's Annex B probe 2): a stop first observed
    /// at the loop's pre-tick check reaches the Daemon before the tick, so an
    /// incident that would otherwise be polled gets no verify spawn.
    #[test]
    fn stage14_9_f01_stop_observed_before_tick_prevents_the_verify() {
        use crate::fencing::{ActionOutcome, FencingState};
        let mut f = stage14_9_command(STAGE14_9_FENCE_OK, STAGE14_9_ISOLATED, 10, 10, 3);
        let incident = stage14_9_verifying(&mut f);
        let record = Some(stage14_9_record(&incident, Term(41)));
        let harness = Stage149Loop {
            f,
            record,
            step_returned_at: Vec::new(),
            descendant_dead_within_1s: Vec::new(),
        };
        let mut daemon = crate::daemon::Daemon::new(harness);
        daemon.start().unwrap();
        let calls = Cell::new(0);
        let latch = Stage149Latch(Cell::new(false));
        let _ = stage14_9_loop_trace();
        let exit = crate::daemon_run::run_observation_loop(
            &mut daemon,
            Duration::from_secs(1),
            || {
                let n = calls.get() + 1;
                calls.set(n);
                n >= 2
            },
            |_| {},
            std::time::Instant::now,
            &latch,
            |_, _| {},
            |_| panic!("no intent"),
        );
        assert_eq!(exit, crate::daemon_run::LoopExit::Clean);
        assert_eq!(calls.get(), 2, "loop top, then the pre-tick check");
        let harness = crate::daemon::stage14_9_support::into_runtime(daemon);
        assert_eq!(stage14_9_spawns(&harness.f), ["1"], "no verify spawned");
        assert!(stage14_9_loop_trace().is_empty());
        assert_eq!(
            stage14_9_incident(&harness.f).unwrap().state,
            FencingState::Verifying {
                attempt_token: 1,
                action_outcome: ActionOutcome::ReportedSuccess,
            }
        );
        stage14_9_assert_no_authority(&harness.f);
    }

    /// Run the real loop over the harness with the shutdown latch attached to
    /// the Daemon as production attaches it, and the loop's `should_stop`
    /// reading the same latch. `on_wait` runs after each wait's count.
    fn stage14_9_f01_loop(
        harness: Stage149Loop,
        stop: &std::sync::Arc<std::sync::atomic::AtomicBool>,
        latch: &Stage149Latch,
        mut on_wait: impl FnMut(u32),
    ) -> (
        crate::daemon_run::LoopExit,
        Stage149Loop,
        Vec<crate::promotion_attempt::PromotionAttemptResult>,
    ) {
        let mut daemon = crate::daemon::Daemon::new(harness);
        daemon.start().unwrap();
        let signal = stop.clone();
        daemon.attach_shutdown_signal(move || signal.load(std::sync::atomic::Ordering::SeqCst));
        let mut waits = 0;
        let mut results = Vec::new();
        let _ = stage14_9_loop_trace();
        let exit = crate::daemon_run::run_observation_loop(
            &mut daemon,
            Duration::from_secs(1),
            || stop.load(std::sync::atomic::Ordering::SeqCst),
            |_| {
                waits += 1;
                on_wait(waits);
            },
            std::time::Instant::now,
            latch,
            |_, _| {},
            |daemon| {
                results.push(daemon.execute_promotion_attempt(
                    crate::promotion_attempt::PromotionExecutionRequest::new(
                        crate::promotion_attempt::PromotionRequestId::new("stage14-9-f01"),
                    ),
                ));
            },
        );
        (
            exit,
            crate::daemon::stage14_9_support::into_runtime(daemon),
            results,
        )
    }

    fn stage14_9_f01_harness(f: Stage149, record: Option<IncidentTermRecord>) -> Stage149Loop {
        Stage149Loop {
            f,
            record,
            step_returned_at: Vec::new(),
            descendant_dead_within_1s: Vec::new(),
        }
    }

    /// F14.9-01 test 1 through the real Daemon and loop (Annex B probe 1
    /// shape): the stop latch is raised while the ordinary tick's verify
    /// poll runs, and the poll returns `isolated` after it. The Daemon's
    /// tick handed the step the live query, so nothing is confirmed, no
    /// further step runs, and the loop exits clean.
    #[test]
    fn stage14_9_f01_successful_verify_during_stop_through_the_loop() {
        use crate::fencing::{ActionOutcome, FencingState};
        let mut f = stage14_9_command(
            STAGE14_9_FENCE_OK,
            &stage14_9_f01_verify_script(),
            10,
            10,
            3,
        );
        let incident = stage14_9_verifying(&mut f);
        let record = Some(stage14_9_record(&incident, Term(41)));
        let (stop, race) = stage14_9_f01_race(&f);
        let latch = Stage149Latch(Cell::new(false));
        let (exit, mut harness, results) =
            stage14_9_f01_loop(stage14_9_f01_harness(f, record), &stop, &latch, |_| {});
        assert_eq!(exit, crate::daemon_run::LoopExit::Clean);
        assert!(results.is_empty());
        assert_eq!(harness.step_returned_at.len(), 1, "exactly one step");
        stage14_9_f01_order(
            "verify through the loop",
            race.join().unwrap(),
            harness.step_returned_at[0],
        );
        assert_eq!(
            stage14_9_loop_trace(),
            [Stage149Traced::Step(FencingStepOutcome::Polled {
                attempt_token: 1,
                result: crate::fencing_backend::VerifyOutcome::Isolated,
                applied: VerifyApplied::Discarded,
            })]
        );
        assert_eq!(
            stage14_9_incident(&harness.f).unwrap().state,
            FencingState::Verifying {
                attempt_token: 1,
                action_outcome: ActionOutcome::ReportedSuccess,
            },
            "no CONFIRMED after shutdown"
        );
        assert_eq!(stage14_9_spawns(&harness.f), ["1", "verify 1"]);
        assert!(stage14_6_view(&mut harness.f.fixture.parts.runtime).is_none());
        stage14_9_assert_no_authority(&harness.f);
        stage14_9_f01_cleanup(&harness.f);
    }

    /// F14.9-01 test 2 through the real Daemon and loop: SIGUSR1 starts one
    /// attempt, the stop latch is raised while its fence action runs, and
    /// the action then reports success. The Daemon handed the gate the live
    /// query, so no T4 is written; the post-attempt check requests shutdown
    /// and the same iteration's tick is the shutdown tick (no verify).
    #[test]
    fn stage14_9_f01_successful_action_during_stop_through_the_loop() {
        use crate::fencing::{ActionOutcome, FencingGateBlock, FencingState};
        let f = stage14_9_command(&stage14_9_f01_fence_script(), STAGE14_9_ISOLATED, 10, 10, 3);
        let (stop, race) = stage14_9_f01_race(&f);
        let latch = Stage149Latch(Cell::new(false));
        let (exit, mut harness, results) =
            stage14_9_f01_loop(stage14_9_f01_harness(f, None), &stop, &latch, |waits| {
                if waits == 1 {
                    latch.0.set(true);
                }
            });
        assert_eq!(exit, crate::daemon_run::LoopExit::Clean);
        assert_eq!(
            results,
            [crate::promotion_attempt::PromotionAttemptResult::BlockedBeforeMutation]
        );
        assert_eq!(harness.step_returned_at.len(), 1, "exactly one step");
        stage14_9_f01_order(
            "action through the loop",
            race.join().unwrap(),
            harness.step_returned_at[0],
        );
        assert_eq!(
            stage14_9_loop_trace(),
            [Stage149Traced::Gate(
                FencingGateBlock::FencingInProgress,
                Some(FencingActionRecord {
                    attempt_token: 1,
                    outcome: ActionOutcome::ReportedSuccess,
                    verifying_persisted: false,
                }),
            )]
        );
        assert_eq!(
            stage14_9_incident(&harness.f).unwrap().state,
            FencingState::Requested { attempt_token: 1 },
            "no T4 after shutdown"
        );
        assert_eq!(stage14_9_spawns(&harness.f), ["1"], "no verify began");
        assert!(stage14_6_view(&mut harness.f.fixture.parts.runtime).is_none());
        stage14_9_assert_no_authority(&harness.f);
        stage14_9_f01_cleanup(&harness.f);
    }

    /// F14.9-01 test 4: with the live latch attached and never raised, the
    /// ordinary composition is unchanged through the real loop — SIGUSR1 ->
    /// G opens the incident and runs the action (T4) -> the tick's poll
    /// confirms (T5) -> only the next, fresh SIGUSR1's G mints the clearance
    /// and reaches H (Phase 14.10); this harness has no Witness, so H fails
    /// and the attempt blocks with no lease and no mutation.
    #[test]
    fn stage14_9_f01_live_shutdown_false_keeps_action_verify_confirm() {
        use crate::fencing::{ActionOutcome, ConfirmedBy, FencingGateBlock, FencingState};
        let f = stage14_9_command(STAGE14_9_FENCE_OK, STAGE14_9_ISOLATED, 10, 10, 3);
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let latch = Stage149Latch(Cell::new(false));
        let (exit, harness, results) = stage14_9_f01_loop(
            stage14_9_f01_harness(f, None),
            &stop,
            &latch,
            |waits| match waits {
                1 | 2 => latch.0.set(true),
                _ => stop.store(true, std::sync::atomic::Ordering::SeqCst),
            },
        );
        assert_eq!(exit, crate::daemon_run::LoopExit::Clean);
        let blocked = crate::promotion_attempt::PromotionAttemptResult::BlockedBeforeMutation;
        assert_eq!(results, [blocked.clone(), blocked]);
        let confirmed = FencingState::Confirmed(ConfirmedBy::Backend { attempt_token: 1 });
        assert_eq!(
            stage14_9_loop_trace(),
            [
                Stage149Traced::Gate(
                    FencingGateBlock::FencingInProgress,
                    Some(FencingActionRecord {
                        attempt_token: 1,
                        outcome: ActionOutcome::ReportedSuccess,
                        verifying_persisted: true,
                    }),
                ),
                Stage149Traced::Step(FencingStepOutcome::Polled {
                    attempt_token: 1,
                    result: crate::fencing_backend::VerifyOutcome::Isolated,
                    applied: VerifyApplied::Written(confirmed.clone()),
                }),
                Stage149Traced::Cleared(stage14_9_incident(&harness.f).unwrap().incident_ref()),
                Stage149Traced::LeaseRequest(Term(7)),
            ]
        );
        assert_eq!(stage14_9_incident(&harness.f).unwrap().state, confirmed);
        assert_eq!(stage14_9_spawns(&harness.f), ["1", "verify 1"]);
        stage14_9_assert_no_authority(&harness.f);
    }

    // ---- Stage 14 Phase 14.10 (Rev5 §24 G-L, §25, §25.1): the fencing
    // clearance through H, I, K, and the atomic ARM / abort cleanup ----
    //
    // The harness drives the real `Daemon::execute_promotion_attempt` over
    // the real `LinuxNodeRuntime` gate, K recheck, `arm_and_promote`, and
    // `release_attempt_lease_once`, with a real `WitnessSession` to a
    // scripted loopback Witness. Its trait methods compose the runtime
    // exactly as `LinuxDaemonRuntime` does (that composition is pinned by
    // the 017 guards); the fresh evaluation's view term is 7, so a valid
    // incident is anchored at 7 and only a grant of term 8 may ARM.

    const STAGE14_10_LEASE: &str = "lease-14-10";

    /// Open `UNKNOWN(not-attempted)` at `anchor` directly in the store (the
    /// current session, generation 1, target `node-b`) and confirm it by the
    /// operator (T8): a CONFIRMED incident without a fence action.
    fn stage14_10_confirmed_by_attestation(
        runtime: &LinuxNodeRuntime<TestNetwork, TestService, TestClock>,
        anchor: Term,
    ) -> crate::fencing::FencingIncident {
        let opened = runtime
            .mutation_store
            .open_fencing_incident(crate::fencing::IncidentOpening {
                target_node_id: NodeId::new("node-b"),
                anchor_term: anchor,
                observer_session_id: SessionId::new(STAGE14_9_SESSION),
                observer_loss_generation: 1,
                backend: crate::fencing::FencingBackend::None,
            })
            .unwrap();
        let crate::fencing::FencingEventOutcome::Transition(transition) = opened
            .confirm_by_attestation(crate::fencing::AttestationId::new(STAGE14_8_ATTESTATION))
            .unwrap()
        else {
            panic!("T8 from UNKNOWN is a transition");
        };
        runtime
            .mutation_store
            .apply_fencing_transition(transition)
            .unwrap()
    }

    /// A real clearance for a CONFIRMED(operator) incident anchored at
    /// `anchor`, minted by the only production path.
    fn stage14_10_confirmed_clearance(
        runtime: &LinuxNodeRuntime<TestNetwork, TestService, TestClock>,
        anchor: Term,
    ) -> crate::fencing::FencingClearance {
        let incident = stage14_10_confirmed_by_attestation(runtime, anchor);
        let (peer, session, evidence) = stage14_9_context_parts(true);
        runtime
            .mutation_store
            .mint_fencing_clearance(
                &incident.incident_ref(),
                &crate::fencing::ContinuityContext {
                    configured_peer: &peer,
                    current_session: &session,
                    live_episode: evidence.as_ref(),
                },
                anchor,
            )
            .unwrap()
    }

    /// G's pass: a clearance bound exactly to `incident` and the fresh view.
    fn stage14_10_assert_cleared(
        decision: FencingGateDecision,
        incident: &crate::fencing::FencingIncident,
        view: Term,
    ) {
        let FencingGateDecision::Clear {
            incident: record,
            clearance,
        } = decision
        else {
            panic!("a valid CONFIRMED clears at G: {decision:?}");
        };
        assert_eq!(clearance.incident(), &incident.incident_ref());
        assert_eq!(clearance.anchor_term(), incident.anchor_term);
        assert_eq!(clearance.anchor_term(), view);
        assert_eq!(clearance.target_node_id(), &incident.target_node_id);
        assert_eq!(
            clearance.observer_session_id(),
            &incident.observer_session_id
        );
        assert_eq!(
            clearance.observer_loss_generation(),
            incident.observer_loss_generation
        );
        assert_eq!(record.incident, incident.incident_ref());
        assert_eq!((record.anchor, record.newest), (view, view));
    }

    /// A live loss episode at `generation` (a peer that returned and was lost
    /// again `generation - 1` times).
    fn stage14_10_evidence(generation: u64) -> crate::failure_assessment::LocalLossEvidence {
        let mut detector =
            crate::failure_assessment::PeerFailureDetector::new(Duration::from_secs(5)).unwrap();
        let t0 = std::time::Instant::now();
        let mut at = t0;
        for round in 0..generation {
            let peer_session = SessionId::new(format!("peer-session-{round}"));
            detector
                .observe_session_established(peer_session.clone(), at)
                .unwrap();
            detector
                .observe_trusted_heartbeat(&peer_session, Sequence(1), at)
                .unwrap();
            detector.observe_transport_failure(at).unwrap();
            at += Duration::from_secs(5);
            detector.tick(at).unwrap();
            at += Duration::from_secs(1);
        }
        let evidence = detector.loss_evidence().unwrap();
        assert_eq!(evidence.generation(), generation);
        evidence
    }

    /// The scripted Witness: grants every LeaseRequest at `grant` with
    /// `STAGE14_10_LEASE`, releases every LeaseRelease exactly, and logs
    /// `(kind, term)` for each request it answered.
    struct Stage1410Witness {
        requests: std::sync::mpsc::Receiver<(&'static str, Term)>,
        join: std::thread::JoinHandle<()>,
    }

    /// Phase 14.12 PC-1: how the scripted Witness answers each GET_TERM. The
    /// queue is consumed in order; an exhausted queue answers `NoHolder`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Pc1TermReply {
        /// `TermStatus` at the view term with no lease holder.
        NoHolder,
        /// `TermStatus` at the view term naming the peer as the holder.
        PeerHolder,
        /// Receive the request, log it, never answer.
        Silent,
    }

    /// Phase 14.12 PC-1: how the scripted Witness answers a LeaseRequest.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Pc1LeaseReply {
        /// Grant at the script's grant term (the pre-existing behaviour).
        Grant,
        /// A deterministic policy reject.
        Reject,
        /// Log the request and close the connection without answering.
        Hangup,
    }

    #[derive(Clone, Debug)]
    struct Pc1WitnessScript {
        terms: VecDeque<Pc1TermReply>,
        lease: Pc1LeaseReply,
    }

    impl Default for Pc1WitnessScript {
        fn default() -> Self {
            Self {
                terms: VecDeque::new(),
                lease: Pc1LeaseReply::Grant,
            }
        }
    }

    /// The view term every scripted GET_TERM answers with (the fencing
    /// anchor of the Stage 14.10 fixtures).
    const PC1_VIEW_TERM: Term = Term(7);

    fn stage14_10_witness(grant: Term) -> (WitnessSession, Stage1410Witness) {
        stage14_10_witness_scripted(grant, Pc1WitnessScript::default())
    }

    fn stage14_10_witness_scripted(
        grant: Term,
        mut script: Pc1WitnessScript,
    ) -> (WitnessSession, Stage1410Witness) {
        use crate::security::{MessageAuthenticator, Psk};
        use crate::session::ProcessSession;
        use crate::tcp::TcpConnection;
        use crate::witness_runtime::WitnessConnection;
        use std::net::{TcpListener, TcpStream};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let (sender, requests) = std::sync::mpsc::channel();
        let join = std::thread::spawn(move || {
            use crate::witness_runtime::{
                WitnessResponseContext, send_witness_response_with_context,
            };
            let auth = MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32]));
            let mut witness = WitnessConnection::new(
                NodeId::new("witness"),
                NodeId::new("node-a"),
                ClusterId::new("cluster"),
                SessionId::new("session-a"),
                TcpConnection::from_stream(server, Duration::from_secs(5), Duration::from_secs(5))
                    .unwrap(),
            );
            let mut process = ProcessSession::from_session_id(SessionId::new("session-w"));
            while let Ok(pending) = witness.receive_pending(&CborSerializer, &auth) {
                let request_id = pending
                    .message()
                    .unsigned()
                    .common
                    .request_id
                    .clone()
                    .unwrap();
                let lease = LeaseId::new(STAGE14_10_LEASE);
                let mut lease_context = Some(lease.clone());
                let (kind, term, response) = match &pending.message().unsigned().message {
                    ProtocolMessage::GetTerm => {
                        let reply = script.terms.pop_front().unwrap_or(Pc1TermReply::NoHolder);
                        let _ = sender.send(("get_term", PC1_VIEW_TERM));
                        if reply == Pc1TermReply::Silent {
                            continue;
                        }
                        lease_context = None;
                        (
                            "get_term",
                            PC1_VIEW_TERM,
                            ProtocolMessage::TermStatus(crate::protocol::TermStatusPayload {
                                current_term: PC1_VIEW_TERM,
                                current_holder: (reply == Pc1TermReply::PeerHolder)
                                    .then(|| NodeId::new("node-b")),
                                current_lease_id: None,
                                lease_remaining_ms: None,
                            }),
                        )
                    }
                    ProtocolMessage::LeaseRequest(_) if script.lease == Pc1LeaseReply::Hangup => {
                        let _ = sender.send(("request", grant));
                        break;
                    }
                    ProtocolMessage::LeaseRequest(_) if script.lease == Pc1LeaseReply::Reject => (
                        "request",
                        grant,
                        ProtocolMessage::LeaseReject(crate::protocol::LeaseRejectPayload {
                            code: crate::protocol::WitnessMutationOutcomeCode::PolicyReject,
                            reason: "policy reject".into(),
                        }),
                    ),
                    ProtocolMessage::LeaseRequest(_) => (
                        "request",
                        grant,
                        ProtocolMessage::LeaseGrant(LeaseGrantPayload {
                            term: grant,
                            lease_id: lease.clone(),
                            holder_node_id: NodeId::new("node-a"),
                            lease_ttl_ms: DurationMs(crate::node_lease_authority::LEASE_TTL_MS),
                            renew_after_ms: DurationMs(3_000),
                            lease_remaining_ms: DurationMs(
                                crate::node_lease_authority::LEASE_TTL_MS,
                            ),
                        }),
                    ),
                    ProtocolMessage::LeaseRelease(payload) => (
                        "release",
                        payload.term,
                        ProtocolMessage::LeaseReleased(crate::protocol::LeaseReleasedPayload {
                            term: payload.term,
                            lease_id: payload.lease_id.clone(),
                            result: "released".into(),
                        }),
                    ),
                    other => panic!("scripted Witness: unexpected {other:?}"),
                };
                if kind != "get_term" {
                    let _ = sender.send((kind, term));
                }
                if send_witness_response_with_context(
                    &mut witness,
                    &mut process,
                    request_id,
                    response,
                    WitnessResponseContext {
                        term,
                        lease_id: lease_context,
                    },
                    &CborSerializer,
                    &auth,
                )
                .is_err()
                {
                    break;
                }
            }
        });
        let node = WitnessConnection::new(
            NodeId::new("node-a"),
            NodeId::new("witness"),
            ClusterId::new("cluster"),
            SessionId::new("session-w"),
            TcpConnection::from_stream(client, Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
        );
        let session = WitnessSession::new(
            node,
            ProcessSession::from_session_id(SessionId::new("session-a")),
            MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32])),
        );
        (session, Stage1410Witness { requests, join })
    }

    /// The Phase 14.10 attempt harness.
    struct Stage1410 {
        f: Stage149,
        session: Option<WitnessSession>,
        witness: Option<Stage1410Witness>,
        record: Option<IncidentTermRecord>,
        configured_peer: NodeId,
        current_session: SessionId,
        /// The live loss episode's generation (`None`: the peer returned).
        episode: Option<u64>,
        /// Overrides the view term the gate mints against (P10-05).
        gate_view: Option<Term>,
        slot_busy: bool,
        rechecks: Vec<Result<(), String>>,
        cleanups: Vec<Result<crate::daemon::AttemptCleanup, String>>,
        /// Stage 14 Phase 14.11 F2: force L to report this outcome instead of
        /// running the ARM (the bound authority is dropped, exactly as the
        /// runtime drops it on a rejected or non-committed ARM); the flag
        /// replaces the durable incident first, modelling a foreign incident
        /// at cleanup time.
        forced_arm: Option<(crate::daemon::AttemptPromotionOutcome, bool)>,
        /// Phase 14.12 PC-1: when set, the attempt runs the Production E3b
        /// observation step and the Production evaluation composition over
        /// the scripted Witness instead of the canned `Authorized` stub.
        pc1: Option<Pc1Observation>,
    }

    /// Phase 14.12 PC-1: the Production observation side of an attempt
    /// (adapter + peer failure detector), attached to the Stage 14.10 harness.
    struct Pc1Observation {
        observer: crate::evidence_fusion::adapter::WitnessEvidenceAdapter,
        /// A real `PeerFailureDetector` driven through the production
        /// lifecycle into `CommunicationLost` in the past.
        detector: crate::failure_assessment::PeerFailureDetector,
        /// Added to the evaluation clock: models time that passed between the
        /// observation and its evaluation without sleeping.
        evaluation_skew: Duration,
        steps: usize,
        evaluations: usize,
    }

    impl Stage1410 {
        fn context_parts(
            &self,
        ) -> (
            NodeId,
            SessionId,
            Option<crate::failure_assessment::LocalLossEvidence>,
        ) {
            let evidence = match &self.pc1 {
                // The same detector the evaluation reads: one peer truth.
                Some(pc1) => self.episode.and_then(|_| pc1.detector.loss_evidence()),
                None => self.episode.map(stage14_10_evidence),
            };
            (
                self.configured_peer.clone(),
                self.current_session.clone(),
                evidence,
            )
        }

        /// Close the Witness connection and return what it answered.
        fn witness_log(&mut self) -> Vec<(&'static str, Term)> {
            drop(self.session.take());
            let witness = self.witness.take().expect("the Witness is still attached");
            witness.join.join().unwrap();
            witness.requests.try_iter().collect()
        }

        /// Protected-resource mutations performed so far.
        fn mutations(&self) -> Vec<&'static str> {
            self.f
                .fixture
                .parts
                .actions
                .borrow()
                .iter()
                .copied()
                .filter(|action| matches!(*action, "vip_acquire" | "service_start" | "garp"))
                .collect()
        }

        fn image(&self) -> crate::node_mutation::NodeMutationPersistentState {
            stage14_9_image(&self.f)
        }

        /// Make the fake resources behave for a full Stage 11 promotion.
        fn resources_respond(&self) {
            let parts = &self.f.fixture.parts;
            parts
                .after_acquire
                .borrow_mut()
                .extend(std::iter::repeat_n(RawVipObservation::Present, 64));
            parts
                .after_start
                .borrow_mut()
                .extend(std::iter::repeat_n(RawServiceObservation::Running, 64));
            parts
                .health
                .borrow_mut()
                .extend(std::iter::repeat_n(RawHealthObservation::Healthy, 64));
        }
    }

    impl crate::daemon::DaemonRuntime for Stage1410 {
        fn startup(&mut self) -> Result<crate::daemon::DaemonSnapshot, String> {
            Ok(stage14_9_standby())
        }

        fn observe(&mut self) -> Result<crate::daemon::DaemonSnapshot, String> {
            Ok(stage14_9_standby())
        }

        fn shutdown(
            &mut self,
            _control_lock_safe: &dyn Fn() -> bool,
        ) -> Result<crate::daemon::ShutdownResult, String> {
            Ok(crate::daemon::ShutdownResult::Clean)
        }

        fn foreground_lifecycle_tick(
            &mut self,
            _shutdown_requested: &dyn Fn() -> bool,
            live_shutdown: &dyn Fn() -> bool,
            _control_lock_safe: &dyn Fn() -> bool,
        ) -> Result<(), String> {
            self.f.fixture.parts.runtime.poll_pending_reap_foreground();
            let (peer, session, evidence) = self.context_parts();
            let context = crate::fencing::ContinuityContext {
                configured_peer: &peer,
                current_session: &session,
                live_episode: evidence.as_ref(),
            };
            self.f
                .fixture
                .parts
                .runtime
                .drive_fencing_step(&context, self.record.as_ref(), live_shutdown, &mut || {})
                .map(|_| ())
                .map_err(|error| error.to_string())
        }
    }

    impl crate::daemon::PromotionExecutionRuntime for Stage1410 {
        fn begin_authority_observation(
            &mut self,
            _context: crate::daemon::DaemonIterationContext,
        ) -> Result<(), String> {
            Ok(())
        }

        /// Phase 14.12 PC-1: with `pc1` attached this is the Production E3b
        /// step (the adapter's `complete_attempt_observation`, exactly the
        /// call `LinuxDaemonRuntime` makes); otherwise it is the trait
        /// default the pre-PC-1 Stage 14.10 tests relied on.
        fn complete_attempt_observation(
            &mut self,
            shutdown_requested: &dyn Fn() -> bool,
        ) -> Result<(), &'static str> {
            let Some(pc1) = self.pc1.as_mut() else {
                return Ok(());
            };
            pc1.steps += 1;
            let authority = self.f.fixture.parts.runtime.installed_lease_authority();
            let expectation = crate::evidence_fusion::adapter::AuthorityViewExpectation::new(
                NodeId::new("node-a"),
                authority.map(|authority| authority.term()),
                authority.map(|authority| authority.lease_id().clone()),
            );
            let Some(session) = self.session.as_mut() else {
                return Err("Witness session is not configured");
            };
            pc1.observer
                .complete_attempt_observation(
                    session,
                    expectation,
                    shutdown_requested,
                    &mut std::time::Instant::now,
                    &mut std::thread::sleep,
                )
                .into_result()
        }

        fn evaluate_authority_attempt(
            &mut self,
            context: crate::daemon::DaemonIterationContext,
        ) -> Result<Option<crate::daemon::AuthorityAttemptEvaluation>, String> {
            let Some(pc1) = self.pc1.as_mut() else {
                return Ok(Some(
                    crate::daemon::stage14_9_support::authorized_evaluation(),
                ));
            };
            pc1.evaluations += 1;
            let local = self
                .f
                .fixture
                .parts
                .runtime
                .failover_local_safety_snapshot(context.shutdown_requested())
                .map_err(|error| error.to_string())?;
            let session = self.session.as_mut().ok_or("no session")?;
            crate::daemon::stage14_9_support::evaluate_observation(
                &mut pc1.observer,
                session,
                pc1.detector.assessment(),
                pc1.detector.loss_evidence(),
                local,
                context.now() + pc1.evaluation_skew,
            )
        }

        fn fencing_gate(
            &mut self,
            evaluation: &crate::daemon::AuthorityAttemptEvaluation,
            shutdown_requested: &dyn Fn() -> bool,
        ) -> crate::daemon::FencingGate {
            let view = self
                .gate_view
                .unwrap_or(evaluation.observation().authority_view().term());
            let (peer, session, evidence) = self.context_parts();
            let context = crate::fencing::ContinuityContext {
                configured_peer: &peer,
                current_session: &session,
                live_episode: evidence.as_ref(),
            };
            match self.f.fixture.parts.runtime.fencing_gate(
                view,
                &context,
                shutdown_requested,
                &mut || {},
            ) {
                Ok(FencingGateDecision::Block(outcome)) => {
                    // Mirrors the production glue: one blocked-attempt WARN.
                    self.f.fixture.parts.runtime.log_gate_block(&outcome);
                    self.record = outcome.incident.clone();
                    crate::daemon::FencingGate::Blocked(outcome.block)
                }
                Ok(FencingGateDecision::Clear {
                    incident,
                    clearance,
                }) => {
                    self.record = Some(incident);
                    crate::daemon::FencingGate::Cleared(clearance)
                }
                Err(error) => crate::daemon::FencingGate::Failed(error.to_string()),
            }
        }

        fn acquire_attempt_lease_once(
            &mut self,
            term: Term,
        ) -> Result<
            crate::node_lease_authority::node_witness_runtime::NodeWitnessMutationResult,
            String,
        > {
            let session = self.session.as_mut().ok_or("no session")?;
            self.f
                .fixture
                .parts
                .runtime
                .acquire_lease_once(session, term)
                .map_err(|error| error.to_string())
        }

        fn take_attempt_lease_authority(
            &mut self,
        ) -> Option<crate::node_lease_authority::RuntimeLeaseAuthority> {
            self.f
                .fixture
                .parts
                .runtime
                .take_installed_lease_authority()
        }

        fn attempt_lease_usable(
            &self,
            authority: &crate::node_lease_authority::RuntimeLeaseAuthority,
        ) -> bool {
            self.f.fixture.parts.runtime.attempt_lease_usable(authority)
        }

        fn shared_witness_outstanding(&self) -> bool {
            self.slot_busy
                || self
                    .session
                    .as_ref()
                    .is_some_and(|session| session.request_in_flight())
        }

        fn fencing_final_recheck(
            &mut self,
            prerequisite: &crate::daemon::FencingPrerequisite,
            grant_term: Term,
        ) -> Result<(), String> {
            let result = (|| {
                let clearance = prerequisite.clearance().ok_or("no fencing clearance")?;
                let (peer, session, evidence) = self.context_parts();
                let context = crate::fencing::ContinuityContext {
                    configured_peer: &peer,
                    current_session: &session,
                    live_episode: evidence.as_ref(),
                };
                match self
                    .f
                    .fixture
                    .parts
                    .runtime
                    .fencing_final_recheck(clearance, &context, grant_term)
                {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(failure)) => Err(format!("{failure:?}")),
                    Err(error) => Err(error.to_string()),
                }
            })();
            self.rechecks.push(result.clone());
            result
        }

        fn release_attempt_lease(
            &mut self,
            granted: Option<(Term, crate::protocol::LeaseId)>,
            binding: Option<&crate::fencing::IncidentBinding>,
        ) -> Result<crate::daemon::AttemptCleanup, String> {
            let result = (|| {
                let session = self.session.as_mut().ok_or("no session")?;
                let Some((term, lease_id)) = granted else {
                    return Ok(crate::daemon::AttemptCleanup::Released);
                };
                if self
                    .f
                    .fixture
                    .parts
                    .runtime
                    .durable_witness_outstanding()
                    .map_err(|error| error.to_string())?
                    .is_some()
                {
                    return Err("an outstanding mutation is preserved".to_string());
                }
                match self.f.fixture.parts.runtime.release_attempt_lease_once(
                    session,
                    term,
                    lease_id,
                    "stage 14.10 attempt abort".into(),
                    binding,
                ) {
                    Ok(AttemptLeaseRelease::Executed(_)) => {
                        Ok(crate::daemon::AttemptCleanup::Released)
                    }
                    Ok(AttemptLeaseRelease::CleanupNotCommitted(_)) => {
                        Ok(crate::daemon::AttemptCleanup::NotSent)
                    }
                    Ok(AttemptLeaseRelease::RecoveryBlocked(reason)) => {
                        Ok(crate::daemon::AttemptCleanup::RecoveryBlocked(reason))
                    }
                    Err(error) => Err(error.to_string()),
                }
            })();
            self.cleanups.push(result.clone());
            result
        }

        fn execute_attempt_promotion(
            &mut self,
            lease: crate::daemon::AttemptBoundLeaseAuthority,
            prerequisite: &crate::daemon::FencingPrerequisite,
        ) -> Result<crate::daemon::AttemptPromotionOutcome, String> {
            use crate::daemon::AttemptPromotionOutcome;
            let clearance = prerequisite.clearance().ok_or("no fencing clearance")?;
            if let Some((outcome, replace_incident)) = self.forced_arm.take() {
                drop(lease);
                if replace_incident {
                    let path = self.f.fixture.parts.path.clone();
                    stage14_10_rewrite(&path, |image| {
                        image.fencing_incident.as_mut().unwrap().incident_id =
                            crate::fencing::IncidentId::new("99999999-2222-4333-8444-555555555555");
                    });
                }
                return Ok(outcome);
            }
            match self
                .f
                .fixture
                .parts
                .runtime
                .arm_and_promote(lease.into_authority(), clearance)
            {
                Ok(FencedArmOutcome::Promoted(ExplicitOperationResult::Completed)) => {
                    Ok(AttemptPromotionOutcome::Promoted)
                }
                Ok(FencedArmOutcome::Promoted(_)) => Ok(AttemptPromotionOutcome::RolledBack),
                Ok(FencedArmOutcome::NotCommitted(_)) => {
                    Ok(AttemptPromotionOutcome::ArmNotCommitted)
                }
                Ok(FencedArmOutcome::Rejected(_)) => Ok(AttemptPromotionOutcome::ArmRejected),
                Ok(FencedArmOutcome::RecoveryBlocked(_)) => {
                    Ok(AttemptPromotionOutcome::RecoveryBlocked)
                }
                Err(error) => Err(error.to_string()),
            }
        }
    }

    /// Standby, zero resource, `backend = "command"` with `verify`, the
    /// current session and a live generation-1 episode, and a Witness that
    /// grants at `grant`.
    fn stage14_10(grant: Term, verify: &str) -> Stage1410 {
        let f = stage14_9_command(STAGE14_9_FENCE_OK, verify, 10, 10, 3);
        let (session, witness) = stage14_10_witness(grant);
        let (peer, current, _) = stage14_9_context_parts(true);
        Stage1410 {
            f,
            session: Some(session),
            witness: Some(witness),
            record: None,
            configured_peer: peer,
            current_session: current,
            episode: Some(1),
            gate_view: None,
            slot_busy: false,
            rechecks: Vec::new(),
            cleanups: Vec::new(),
            forced_arm: None,
            pc1: None,
        }
    }

    /// CONFIRMED through the real gate action and verify poll (T2, T4, T5),
    /// anchored at the fresh view term 7.
    fn stage14_10_confirmed_by_verification(h: &mut Stage1410) -> crate::fencing::FencingIncident {
        let (outcome, _) = stage14_9_gate(&mut h.f, Term(7));
        assert_eq!(
            outcome.block,
            crate::fencing::FencingGateBlock::FencingInProgress
        );
        let incident = stage14_9_incident(&h.f).unwrap();
        let record = stage14_9_record(&incident, Term(7));
        let (step, _) = stage14_9_drive(&mut h.f, Some(&record));
        assert!(matches!(
            step,
            FencingStepOutcome::Polled {
                applied: VerifyApplied::Written(crate::fencing::FencingState::Confirmed(_)),
                ..
            }
        ));
        stage14_9_incident(&h.f).unwrap()
    }

    fn stage14_10_daemon(h: Stage1410) -> crate::daemon::Daemon<Stage1410> {
        let mut daemon = crate::daemon::Daemon::new(h);
        daemon.start().unwrap();
        daemon
    }

    fn stage14_10_attempt(
        daemon: &mut crate::daemon::Daemon<Stage1410>,
    ) -> crate::promotion_attempt::PromotionAttemptResult {
        daemon.execute_promotion_attempt(crate::promotion_attempt::PromotionExecutionRequest::new(
            crate::promotion_attempt::PromotionRequestId::new("stage14-10"),
        ))
    }

    /// Queue a race at the post-lease boundary (after H, before I/K): the
    /// first hook (post-revalidation) is a no-op.
    fn stage14_10_race_after_grant(
        daemon: &mut crate::daemon::Daemon<Stage1410>,
        race: impl FnOnce(&mut crate::daemon::Daemon<Stage1410>) + 'static,
    ) {
        daemon.push_promotion_attempt_test_hook(|_| {});
        daemon.push_promotion_attempt_test_hook(race);
    }

    fn stage14_10_harness(daemon: &mut crate::daemon::Daemon<Stage1410>) -> &mut Stage1410 {
        crate::daemon::stage14_9_support::runtime_mut(daemon)
    }

    /// The clean image after a committed §25.1 cleanup and its exact
    /// Release (AcceptedSuccess -> atomic CLEAR): no incident, no O, no M,
    /// the incident high-water kept, Standby, and no resource touched.
    fn stage14_10_assert_cleaned_and_released(h: &mut Stage1410, high_water: u64) {
        let image = h.image();
        assert_eq!(image.fencing_incident, None, "incident retired");
        assert_eq!(image.release_obligation, None, "O cleared by the release");
        assert_eq!(image.outstanding_mutation, None);
        assert_eq!(image.highest_fencing_incident_seq, high_water);
        assert!(h.mutations().is_empty(), "no resource mutation");
        assert_eq!(
            h.f.fixture.parts.runtime.state_machine.node_state(),
            NodeState::Standby
        );
        assert_eq!(
            h.witness_log(),
            [("request", Term(8)), ("release", Term(8))],
            "one grant, one exact release"
        );
    }

    /// P10-01: every non-`CONFIRMED` state blocks at G with no LeaseRequest
    /// and no resource mutation.
    #[test]
    fn stage14_10_p01_non_confirmed_states_never_request_a_lease() {
        use crate::fencing::FencingState;
        for state in ["unknown", "requested", "verifying", "failed"] {
            let verify = if state == "failed" {
                STAGE14_9_NOT_ISOLATED
            } else {
                STAGE14_9_ISOLATED
            };
            let mut h = stage14_10(Term(8), verify);
            match state {
                "unknown" | "requested" => {
                    h.f.fixture
                        .parts
                        .runtime
                        .mutation_store
                        .open_fencing_incident(crate::fencing::IncidentOpening {
                            target_node_id: NodeId::new("node-b"),
                            anchor_term: Term(7),
                            observer_session_id: SessionId::new(STAGE14_9_SESSION),
                            observer_loss_generation: 1,
                            backend: if state == "unknown" {
                                crate::fencing::FencingBackend::None
                            } else {
                                crate::fencing::FencingBackend::Command
                            },
                        })
                        .unwrap();
                }
                _ => {
                    let _ = stage14_9_gate(&mut h.f, Term(7));
                    if state == "failed" {
                        let incident = stage14_9_incident(&h.f).unwrap();
                        let record = stage14_9_record(&incident, Term(7));
                        let _ = stage14_9_drive(&mut h.f, Some(&record));
                        assert!(matches!(
                            stage14_9_incident(&h.f).unwrap().state,
                            FencingState::Failed { .. }
                        ));
                    }
                }
            }
            let mut daemon = stage14_10_daemon(h);
            assert_eq!(
                stage14_10_attempt(&mut daemon),
                crate::promotion_attempt::PromotionAttemptResult::BlockedBeforeMutation,
                "{state}"
            );
            let mut h = crate::daemon::stage14_9_support::into_runtime(daemon);
            assert!(h.mutations().is_empty(), "{state}");
            assert!(h.image().release_obligation.is_none(), "{state}");
            assert!(h.witness_log().is_empty(), "{state}: no LeaseRequest");
        }
    }

    /// P10-02: a stale `CONFIRMED` (wrong anchor for the fresh view, or an old
    /// observer session) is retired at G (R4 / R2) and never requests a lease.
    #[test]
    fn stage14_10_p02_stale_confirmed_never_requests_a_lease() {
        for stale in ["anchor", "session"] {
            let mut h = stage14_10(Term(8), STAGE14_9_ISOLATED);
            let anchor = if stale == "anchor" { Term(6) } else { Term(7) };
            let old = stage14_10_confirmed_by_attestation(&h.f.fixture.parts.runtime, anchor);
            if stale == "session" {
                h.current_session = SessionId::new("fedcba9876543210");
            }
            let mut daemon = stage14_10_daemon(h);
            assert_eq!(
                stage14_10_attempt(&mut daemon),
                crate::promotion_attempt::PromotionAttemptResult::BlockedBeforeMutation
            );
            let mut h = crate::daemon::stage14_9_support::into_runtime(daemon);
            let image = h.image();
            assert_ne!(
                image
                    .fencing_incident
                    .map(|incident| incident.incident_ref()),
                Some(old.incident_ref()),
                "{stale}: the stale incident was retired"
            );
            assert!(h.mutations().is_empty());
            assert!(h.witness_log().is_empty(), "{stale}: no LeaseRequest");
        }
    }

    /// P10-03: a valid `CONFIRMED` never starts an attempt. N idle loop
    /// iterations make no LeaseRequest and no mutation; only one fresh
    /// SIGUSR1 makes exactly one attempt.
    #[test]
    fn stage14_10_p03_confirmed_never_auto_promotes() {
        let mut h = stage14_10(Term(8), STAGE14_9_ISOLATED);
        let incident = stage14_10_confirmed_by_verification(&mut h);
        h.record = Some(stage14_9_record(&incident, Term(7)));
        h.resources_respond();
        let mut daemon = stage14_10_daemon(h);
        let latch = Stage149Latch(Cell::new(false));
        let waits = Cell::new(0);
        let mut attempts = Vec::new();
        let exit = crate::daemon_run::run_observation_loop(
            &mut daemon,
            Duration::from_secs(1),
            || waits.get() >= 8,
            |_| {
                waits.set(waits.get() + 1);
                if waits.get() == 6 {
                    latch.0.set(true);
                }
            },
            std::time::Instant::now,
            &latch,
            |_, _| {},
            |daemon| attempts.push(stage14_10_attempt(daemon)),
        );
        assert_eq!(exit, crate::daemon_run::LoopExit::Clean);
        assert_eq!(
            attempts,
            [crate::promotion_attempt::PromotionAttemptResult::Succeeded],
            "only the one fresh SIGUSR1 attempted"
        );
        let mut h = crate::daemon::stage14_9_support::into_runtime(daemon);
        assert_eq!(h.witness_log(), [("request", Term(8))]);
    }

    /// P10-04 / P10-06 / P10-19 / P10-31: the full fencing-backed chain, for
    /// both `CONFIRMED` sources: G clears -> H at the anchor -> grant ==
    /// anchor+1 -> K -> trusted ZeroResource -> one atomic ARM consumes the
    /// incident and installs O -> authority restored -> Stage 11 promote.
    /// At the first protected resource mutation the durable image already
    /// holds O and no incident (the resource barrier).
    #[test]
    fn stage14_10_p19_success_arm_consumes_the_incident_before_any_mutation() {
        for source in ["verification", "attestation"] {
            let mut h = stage14_10(Term(8), STAGE14_9_ISOLATED);
            let incident = if source == "verification" {
                stage14_10_confirmed_by_verification(&mut h)
            } else {
                stage14_10_confirmed_by_attestation(&h.f.fixture.parts.runtime, Term(7))
            };
            let high_water = h.image().highest_fencing_incident_seq;
            h.resources_respond();
            *h.f.fixture.parts.barrier_probe.borrow_mut() =
                Some((h.f.fixture.parts.path.clone(), Vec::new()));
            let mut daemon = stage14_10_daemon(h);
            assert_eq!(
                stage14_10_attempt(&mut daemon),
                crate::promotion_attempt::PromotionAttemptResult::Succeeded,
                "{source}"
            );
            let mut h = crate::daemon::stage14_9_support::into_runtime(daemon);
            assert_eq!(h.rechecks, [Ok(())], "{source}: K passed once");
            let image = h.image();
            assert_eq!(image.fencing_incident, None, "{source}: consumed");
            assert_eq!(
                image.release_obligation,
                Some(crate::node_mutation::ReleaseObligation {
                    term: Term(8),
                    lease_id: LeaseId::new(STAGE14_10_LEASE),
                }),
                "{source}: exact O"
            );
            assert_eq!(image.highest_fencing_incident_seq, high_water);
            let (_, seen) = h.f.fixture.parts.barrier_probe.borrow_mut().take().unwrap();
            assert_eq!(seen.len(), 1, "{source}: one VIP acquisition");
            let at_barrier: crate::node_mutation::NodeMutationPersistentState =
                toml::from_str(&seen[0]).unwrap();
            assert_eq!(at_barrier.fencing_incident, None, "{source}");
            assert_eq!(at_barrier.release_obligation, image.release_obligation);
            assert_eq!(
                h.f.fixture.parts.runtime.state_machine.node_state(),
                NodeState::Active,
                "{source}"
            );
            assert!(h.mutations().contains(&"vip_acquire"));
            assert_eq!(h.witness_log(), [("request", Term(8))], "{source}");
            let _ = incident;
        }
    }

    /// P10-05: the clearance's anchor must equal the fresh view term used
    /// for H: a clearance anchored elsewhere requests no lease.
    #[test]
    fn stage14_10_p05_clearance_anchor_must_equal_the_view_term() {
        let mut h = stage14_10(Term(7), STAGE14_9_ISOLATED);
        stage14_10_confirmed_by_attestation(&h.f.fixture.parts.runtime, Term(6));
        h.gate_view = Some(Term(6));
        let mut daemon = stage14_10_daemon(h);
        assert_eq!(
            stage14_10_attempt(&mut daemon),
            crate::promotion_attempt::PromotionAttemptResult::BlockedBeforeMutation
        );
        let mut h = crate::daemon::stage14_9_support::into_runtime(daemon);
        assert!(h.image().fencing_incident.is_some(), "not consumed");
        assert!(h.witness_log().is_empty(), "no LeaseRequest");
    }

    /// P10-07: a grant term other than anchor+1 (the anchor itself, or
    /// beyond anchor+1) is a post-grant, pre-resource abort: the runtime
    /// authority is discarded, the §25.1 transaction retires the incident and
    /// arms the exact cleanup O in one write, and the exact Release clears
    /// it. No ARM, no resource mutation.
    #[test]
    fn stage14_10_p07_bad_grant_term_aborts_through_atomic_cleanup() {
        for grant in [Term(7), Term(9)] {
            let h = stage14_10(grant, STAGE14_9_ISOLATED);
            stage14_10_confirmed_by_attestation(&h.f.fixture.parts.runtime, Term(7));
            let high_water = h.image().highest_fencing_incident_seq;
            let mut daemon = stage14_10_daemon(h);
            assert_eq!(
                stage14_10_attempt(&mut daemon),
                crate::promotion_attempt::PromotionAttemptResult::BlockedBeforeMutation
            );
            let mut h = crate::daemon::stage14_9_support::into_runtime(daemon);
            assert!(h.rechecks.is_empty(), "I fails before K");
            assert_eq!(h.cleanups, [Ok(crate::daemon::AttemptCleanup::Released)]);
            let image = h.image();
            assert_eq!(image.fencing_incident, None);
            assert_eq!(image.release_obligation, None);
            assert_eq!(image.highest_fencing_incident_seq, high_water);
            assert!(h.mutations().is_empty());
            assert!(
                h.f.fixture
                    .parts
                    .runtime
                    .installed_lease_authority()
                    .is_none()
            );
            assert_eq!(
                h.witness_log(),
                [("request", grant), ("release", grant)],
                "the exact granted epoch is released"
            );
        }
    }

    /// P10-08..P10-12, P10-14..P10-16, P10-18: a race between G and K (after
    /// the grant) fails a K recheck. No ARM, no resource mutation, no
    /// promotion; the §25.1 transaction retires the incident with the
    /// clearance's durable binding (not the current episode, which may be
    /// the very cause) and arms the exact cleanup O; the exact Release
    /// follows.
    #[test]
    fn stage14_10_p08_to_p18_k_races_abort_through_atomic_cleanup() {
        use crate::promotion_attempt::PromotionAttemptResult;
        type Race = Box<dyn FnOnce(&mut crate::daemon::Daemon<Stage1410>)>;
        let races: Vec<(&str, Race, PromotionAttemptResult, Option<&str>)> = vec![
            (
                "P10-08 authenticated peer return",
                Box::new(|daemon| stage14_10_harness(daemon).episode = None),
                PromotionAttemptResult::BlockedBeforeMutation,
                Some("Episode"),
            ),
            (
                "P10-09 shutdown",
                Box::new(|daemon| daemon.request_shutdown().unwrap()),
                PromotionAttemptResult::BlockedBeforeMutation,
                None,
            ),
            (
                "P10-09b live shutdown signal, daemon still Running",
                Box::new(|daemon| daemon.attach_shutdown_signal(|| true)),
                PromotionAttemptResult::BlockedBeforeMutation,
                None,
            ),
            (
                "K2 daemon left Running without a shutdown request",
                Box::new(|daemon| daemon.force_state_for_test(crate::daemon::DaemonState::Failed)),
                PromotionAttemptResult::BlockedBeforeMutation,
                None,
            ),
            (
                "P10-10 cancellation",
                Box::new(|daemon| {
                    daemon.cancel_promotion_attempt().unwrap();
                }),
                PromotionAttemptResult::Cancelled,
                None,
            ),
            (
                "P10-11 lease unusable",
                Box::new(|daemon| {
                    stage14_10_harness(daemon)
                        .f
                        .fixture
                        .parts
                        .clock_failed
                        .set(true);
                }),
                PromotionAttemptResult::BlockedBeforeMutation,
                None,
            ),
            (
                "P10-12 session slot occupied",
                Box::new(|daemon| stage14_10_harness(daemon).slot_busy = true),
                PromotionAttemptResult::BlockedBeforeMutation,
                None,
            ),
            (
                "P10-14 state no longer CONFIRMED",
                Box::new(|daemon| {
                    let path = stage14_10_harness(daemon).f.fixture.parts.path.clone();
                    stage14_10_rewrite(&path, |image| {
                        let incident = image.fencing_incident.as_mut().unwrap();
                        incident.attempt_token_high_water = 1;
                        incident.state = crate::fencing::FencingState::Failed { attempt_token: 1 };
                    });
                }),
                PromotionAttemptResult::BlockedBeforeMutation,
                Some("NotConfirmed"),
            ),
            (
                "P10-15 observer session changed",
                Box::new(|daemon| {
                    stage14_10_harness(daemon).current_session = SessionId::new("fedcba9876543210");
                }),
                PromotionAttemptResult::BlockedBeforeMutation,
                Some("ObserverSession"),
            ),
            (
                "P10-16 loss generation changed",
                Box::new(|daemon| {
                    stage14_10_harness(daemon).episode = Some(2);
                }),
                PromotionAttemptResult::BlockedBeforeMutation,
                Some("Episode"),
            ),
            (
                "P10-18 target changed",
                Box::new(|daemon| {
                    stage14_10_harness(daemon).configured_peer = NodeId::new("node-c");
                }),
                PromotionAttemptResult::BlockedBeforeMutation,
                Some("Target"),
            ),
        ];
        for (name, race, expected, recheck) in races {
            let h = stage14_10(Term(8), STAGE14_9_ISOLATED);
            stage14_10_confirmed_by_attestation(&h.f.fixture.parts.runtime, Term(7));
            h.resources_respond();
            let high_water = h.image().highest_fencing_incident_seq;
            let mut daemon = stage14_10_daemon(h);
            stage14_10_race_after_grant(&mut daemon, race);
            assert_eq!(stage14_10_attempt(&mut daemon), expected, "{name}");
            let mut h = crate::daemon::stage14_9_support::into_runtime(daemon);
            h.f.fixture.parts.clock_failed.set(false);
            // Items 1-5 fail in the daemon before the runtime half runs;
            // items 6-14 fail in the runtime half with their own name.
            let expected_rechecks: Vec<Result<(), String>> = recheck
                .map(|failure| Err(failure.to_string()))
                .into_iter()
                .collect();
            assert_eq!(h.rechecks, expected_rechecks, "{name}");
            assert!(
                h.f.fixture
                    .parts
                    .runtime
                    .installed_lease_authority()
                    .is_none(),
                "{name}: the runtime authority was discarded"
            );
            assert_eq!(
                h.cleanups,
                [Ok(crate::daemon::AttemptCleanup::Released)],
                "{name}"
            );
            stage14_10_assert_cleaned_and_released(&mut h, high_water);
        }
    }

    /// Rewrite the Node document in place (test fixture only; bypasses the
    /// store to model a durable state the attempt did not write).
    fn stage14_10_rewrite(
        path: &std::path::Path,
        edit: impl FnOnce(&mut crate::node_mutation::NodeMutationPersistentState),
    ) {
        let mut image: crate::node_mutation::NodeMutationPersistentState =
            toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        edit(&mut image);
        std::fs::write(path, toml::to_string(&image).unwrap()).unwrap();
    }

    /// P10-13: the incident was replaced between G and K. K fails (no ARM),
    /// and the §25.1 cleanup's old-image validation rejects the foreign
    /// incident: no write, RecoveryBlocked, no Release (the lease expires),
    /// and the replacement is never retired or overwritten.
    #[test]
    fn stage14_10_p13_replaced_incident_blocks_recovery_without_release() {
        let h = stage14_10(Term(8), STAGE14_9_ISOLATED);
        stage14_10_confirmed_by_attestation(&h.f.fixture.parts.runtime, Term(7));
        let mut daemon = stage14_10_daemon(h);
        stage14_10_race_after_grant(&mut daemon, |daemon| {
            let runtime = &stage14_10_harness(daemon).f.fixture.parts.runtime;
            let current = runtime.mutation_store.load_existing().unwrap();
            runtime
                .mutation_store
                .retire_fencing_incident(&current.fencing_incident.unwrap().incident_ref())
                .unwrap();
            stage14_10_confirmed_by_attestation(runtime, Term(7));
        });
        assert_eq!(
            stage14_10_attempt(&mut daemon),
            crate::promotion_attempt::PromotionAttemptResult::BlockedBeforeMutation
        );
        assert_eq!(daemon.state(), crate::daemon::DaemonState::RecoveryBlocked);
        let mut h = crate::daemon::stage14_9_support::into_runtime(daemon);
        assert!(matches!(
            h.cleanups.as_slice(),
            [Ok(crate::daemon::AttemptCleanup::RecoveryBlocked(_))]
        ));
        assert_eq!(h.rechecks, [Err("Incident".to_string())], "K8 caught it");
        let image = h.image();
        assert_eq!(
            image.fencing_incident.unwrap().incident_seq,
            2,
            "replacement kept"
        );
        assert_eq!(image.release_obligation, None, "no cleanup O");
        assert!(h.mutations().is_empty());
        assert_eq!(h.witness_log(), [("request", Term(8))], "no Release");
    }

    /// P10-17 (K13) and the runtime half of K directly: the validated grant
    /// must be anchor+1; every item names its own failure.
    #[test]
    fn stage14_10_p17_k_recheck_items_are_each_enforced() {
        let mut h = stage14_10(Term(8), STAGE14_9_ISOLATED);
        let clearance = stage14_10_confirmed_clearance(&h.f.fixture.parts.runtime, Term(7));
        let runtime = &mut h.f.fixture.parts.runtime;
        let check = |runtime: &mut LinuxNodeRuntime<TestNetwork, TestService, TestClock>,
                     peer: &str,
                     session: &str,
                     generation: Option<u64>,
                     grant: u64| {
            let peer = NodeId::new(peer);
            let session = SessionId::new(session);
            let evidence = generation.map(stage14_10_evidence);
            runtime
                .fencing_final_recheck(
                    &clearance,
                    &crate::fencing::ContinuityContext {
                        configured_peer: &peer,
                        current_session: &session,
                        live_episode: evidence.as_ref(),
                    },
                    Term(grant),
                )
                .unwrap()
        };
        assert_eq!(
            check(runtime, "node-b", STAGE14_9_SESSION, Some(1), 8),
            Ok(())
        );
        for (grant, expected) in [
            (7, FencingRecheckFailure::WitnessTerm),
            (9, FencingRecheckFailure::WitnessTerm),
        ] {
            assert_eq!(
                check(runtime, "node-b", STAGE14_9_SESSION, Some(1), grant),
                Err(expected)
            );
        }
        assert_eq!(
            check(runtime, "node-c", STAGE14_9_SESSION, Some(1), 8),
            Err(FencingRecheckFailure::Target)
        );
        assert_eq!(
            check(runtime, "node-b", "fedcba9876543210", Some(1), 8),
            Err(FencingRecheckFailure::ObserverSession)
        );
        assert_eq!(
            check(runtime, "node-b", STAGE14_9_SESSION, None, 8),
            Err(FencingRecheckFailure::Episode)
        );
        assert_eq!(
            check(runtime, "node-b", STAGE14_9_SESSION, Some(2), 8),
            Err(FencingRecheckFailure::Episode)
        );
        // K7: O or M present.
        runtime
            .mutation_store
            .begin_lease_request(Term(7), 100, DurationMs(10_000))
            .unwrap();
        assert_eq!(
            check(runtime, "node-b", STAGE14_9_SESSION, Some(1), 8),
            Err(FencingRecheckFailure::ObligationOrMutation)
        );
        let outstanding = runtime.mutation_store.outstanding().unwrap().unwrap();
        runtime
            .mutation_store
            .complete(
                &outstanding.request_id,
                outstanding.mutation_generation,
                outstanding.kind(),
                crate::node_mutation::TerminalMutationDisposition::DeterministicReject,
            )
            .unwrap();
        // K6: resources present.
        h.f.fixture
            .parts
            .vip
            .borrow_mut()
            .push_back(RawVipObservation::Present);
        let runtime = &mut h.f.fixture.parts.runtime;
        assert_eq!(
            check(runtime, "node-b", STAGE14_9_SESSION, Some(1), 8),
            Err(FencingRecheckFailure::ZeroResource)
        );
        // K9 / K8 / K14.
        let path = h.f.fixture.parts.path.clone();
        stage14_10_rewrite(&path, |image| {
            let incident = image.fencing_incident.as_mut().unwrap();
            incident.state = crate::fencing::FencingState::Unknown(
                crate::fencing::UnknownReason::NotAttempted {},
            );
        });
        let runtime = &mut h.f.fixture.parts.runtime;
        assert_eq!(
            check(runtime, "node-b", STAGE14_9_SESSION, Some(1), 8),
            Err(FencingRecheckFailure::NotConfirmed)
        );
        let current = runtime.mutation_store.load_existing().unwrap();
        runtime
            .mutation_store
            .retire_fencing_incident(&current.fencing_incident.unwrap().incident_ref())
            .unwrap();
        assert_eq!(
            check(runtime, "node-b", STAGE14_9_SESSION, Some(1), 8),
            Err(FencingRecheckFailure::Incident)
        );
        // K6: an installed authority (or a non-Standby state) fails first.
        install_test_authority(runtime);
        assert_eq!(
            check(runtime, "node-b", STAGE14_9_SESSION, Some(1), 8),
            Err(FencingRecheckFailure::LocalState)
        );
        let _ = h.witness_log();
    }

    /// P10-20 / P10-21: the success ARM's durable outcomes. PreCommitFailure
    /// keeps the old image (CONFIRMED, no O) and sends no Release (Rev 10 §4;
    /// the incident is stale by term); uncertainty is RecoveryBlocked with no
    /// Release and classifies as exactly the old or the new image. No
    /// resource is ever touched.
    #[test]
    fn stage14_10_p20_p21_success_arm_precommit_and_uncertain_touch_nothing() {
        use crate::recovery::FaultPoint;
        for (fault, uncertain) in [
            (FaultPoint::CandidateTempFsync, false),
            (FaultPoint::CanonicalInstallBeforeMutation, false),
            (FaultPoint::CanonicalParentFsync, true),
        ] {
            let h = stage14_10(Term(8), STAGE14_9_ISOLATED);
            let incident = stage14_10_confirmed_by_attestation(&h.f.fixture.parts.runtime, Term(7));
            h.resources_respond();
            let path = h.f.fixture.parts.path.clone();
            let mut daemon = stage14_10_daemon(h);
            // The image the ARM starts from (after the grant completed M),
            // captured at the post-grant boundary; the next durable write
            // after this hook is the ARM itself.
            let before_arm = Rc::new(RefCell::new(Vec::new()));
            let captured = before_arm.clone();
            stage14_10_race_after_grant(&mut daemon, move |_| {
                *captured.borrow_mut() = std::fs::read(&path).unwrap();
                crate::recovery::inject_fault_once(fault)
            });
            assert_eq!(
                stage14_10_attempt(&mut daemon),
                crate::promotion_attempt::PromotionAttemptResult::BlockedBeforeMutation,
                "{fault:?}"
            );
            let expected_state = if uncertain {
                crate::daemon::DaemonState::RecoveryBlocked
            } else {
                crate::daemon::DaemonState::Running
            };
            assert_eq!(daemon.state(), expected_state, "{fault:?}");
            let mut h = crate::daemon::stage14_9_support::into_runtime(daemon);
            assert!(h.mutations().is_empty(), "{fault:?}: barrier");
            assert!(
                h.f.fixture
                    .parts
                    .runtime
                    .installed_lease_authority()
                    .is_none(),
                "{fault:?}: authority restored only after a committed ARM"
            );
            assert!(h.cleanups.is_empty(), "{fault:?}: no Release path");
            assert_eq!(
                h.witness_log(),
                [("request", Term(8))],
                "{fault:?}: no Release"
            );
            let path = h.f.fixture.parts.path.clone();
            let old = before_arm.borrow().clone();
            assert!(!old.is_empty());
            if uncertain {
                assert!(crate::recovery::marker_path(&path).exists());
                stage14_10_assert_old_or_new(&path, &old, &incident, Term(8));
            } else {
                assert_eq!(std::fs::read(&path).unwrap(), old, "{fault:?}: old image");
                assert!(!crate::recovery::marker_path(&path).exists());
            }
            let _ = std::fs::remove_dir_all(crate::recovery::marker_path(&path));
            let _ = std::fs::remove_file(crate::recovery::marker_path(&path));
        }
    }

    /// An uncertain incident/O transaction leaves exactly the old image
    /// (incident, no O) or exactly the new one (no incident, O = the granted
    /// epoch) — never a mixed image.
    fn stage14_10_assert_old_or_new(
        path: &std::path::Path,
        old: &[u8],
        incident: &crate::fencing::FencingIncident,
        term: Term,
    ) {
        let now = std::fs::read(path).unwrap();
        let image: crate::node_mutation::NodeMutationPersistentState =
            toml::from_str(std::str::from_utf8(&now).unwrap()).unwrap();
        if now == old {
            assert_eq!(image.fencing_incident.as_ref(), Some(incident));
            assert_eq!(image.release_obligation, None);
        } else {
            assert_eq!(image.fencing_incident, None, "new image: no incident");
            assert_eq!(
                image.release_obligation,
                Some(crate::node_mutation::ReleaseObligation {
                    term,
                    lease_id: LeaseId::new(STAGE14_10_LEASE),
                }),
                "new image: the exact O"
            );
        }
    }

    /// P10-22 / P10-28: the success ARM's own old-image validation. A
    /// clearance for incident A cannot consume incident B (or anything once A
    /// is gone): `Rejected`, nothing written, no resource touched, and the
    /// authority passed in is dropped.
    #[test]
    fn stage14_10_p22_p28_success_arm_rejects_a_foreign_incident() {
        let mut h = stage14_10(Term(8), STAGE14_9_ISOLATED);
        let clearance = stage14_10_confirmed_clearance(&h.f.fixture.parts.runtime, Term(7));
        let runtime = &mut h.f.fixture.parts.runtime;
        let a = runtime.mutation_store.load_existing().unwrap();
        runtime
            .mutation_store
            .retire_fencing_incident(&a.fencing_incident.unwrap().incident_ref())
            .unwrap();
        stage14_10_confirmed_by_attestation(runtime, Term(7));
        let before = std::fs::read(&h.f.fixture.parts.path).unwrap();
        let runtime = &mut h.f.fixture.parts.runtime;
        install_test_authority(runtime);
        let authority = runtime.take_installed_lease_authority().unwrap();
        assert!(matches!(
            runtime.arm_and_promote(authority, &clearance),
            Ok(FencedArmOutcome::Rejected(_))
        ));
        assert_eq!(std::fs::read(&h.f.fixture.parts.path).unwrap(), before);
        assert!(
            h.f.fixture
                .parts
                .runtime
                .installed_lease_authority()
                .is_none()
        );
        assert!(h.mutations().is_empty());
        let _ = h.witness_log();
    }

    /// P10-23..P10-27: `release_attempt_lease_once` routing and the §25.1
    /// outcomes, directly. With an incident, cleanup O is armed only by the
    /// atomic transaction with the clearance binding: committed -> exact
    /// Release -> AcceptedSuccess -> atomic CLEAR (Standby, reconciled);
    /// PreCommitFailure -> no Release; uncertain -> RecoveryBlocked, no
    /// Release; a wrong binding or incompatible M -> RecoveryBlocked, no
    /// write, M never overwritten; an incident without a binding is never
    /// released through the plain ARM. With no incident and no binding the
    /// unchanged Stage 13.6 plain path runs.
    #[test]
    fn stage14_10_p23_to_p27_release_routing_and_cleanup_outcomes() {
        use crate::recovery::FaultPoint;
        let lease = || LeaseId::new(STAGE14_10_LEASE);
        let released = |h: &mut Stage1410, grant: Term| -> AttemptLeaseRelease {
            let binding =
                h.f.fixture
                    .parts
                    .runtime
                    .mutation_store
                    .load_existing()
                    .unwrap()
                    .fencing_incident
                    .map(|incident| crate::fencing::IncidentBinding {
                        incident: incident.incident_ref(),
                        observer_session_id: incident.observer_session_id.clone(),
                        observer_loss_generation: incident.observer_loss_generation,
                    });
            let session = h.session.as_mut().unwrap();
            h.f.fixture
                .parts
                .runtime
                .release_attempt_lease_once(session, grant, lease(), "p10".into(), binding.as_ref())
                .unwrap()
        };

        // P10-23 committed.
        let mut h = stage14_10(Term(8), STAGE14_9_ISOLATED);
        stage14_10_confirmed_by_attestation(&h.f.fixture.parts.runtime, Term(7));
        assert!(matches!(
            released(&mut h, Term(8)),
            AttemptLeaseRelease::Executed(NodeWitnessMutationResult::AcceptedSuccess { .. })
        ));
        let image = h.image();
        assert_eq!(
            (
                image.fencing_incident,
                image.release_obligation,
                image.outstanding_mutation
            ),
            (None, None, None)
        );
        assert!(h.f.fixture.parts.runtime.controller.recovery_reconciled());
        assert_eq!(h.witness_log(), [("release", Term(8))]);

        // P10-24 PreCommitFailure / P10-25 uncertain.
        for (fault, uncertain) in [
            (FaultPoint::CandidateTempFsync, false),
            (FaultPoint::CanonicalParentFsync, true),
        ] {
            let mut h = stage14_10(Term(8), STAGE14_9_ISOLATED);
            let incident = stage14_10_confirmed_by_attestation(&h.f.fixture.parts.runtime, Term(7));
            let old = std::fs::read(&h.f.fixture.parts.path).unwrap();
            crate::recovery::inject_fault_once(fault);
            let result = released(&mut h, Term(8));
            let path = h.f.fixture.parts.path.clone();
            if uncertain {
                assert!(matches!(result, AttemptLeaseRelease::RecoveryBlocked(_)));
                stage14_10_assert_old_or_new(&path, &old, &incident, Term(8));
                let _ = std::fs::remove_dir_all(crate::recovery::marker_path(&path));
                let _ = std::fs::remove_file(crate::recovery::marker_path(&path));
            } else {
                assert!(matches!(
                    result,
                    AttemptLeaseRelease::CleanupNotCommitted(_)
                ));
                assert_eq!(std::fs::read(&path).unwrap(), old, "old image kept");
            }
            assert!(h.witness_log().is_empty(), "{fault:?}: no Release");
        }

        // P10-26 mismatch: wrong durable generation; then an incompatible M.
        let mut h = stage14_10(Term(8), STAGE14_9_ISOLATED);
        let incident = stage14_10_confirmed_by_attestation(&h.f.fixture.parts.runtime, Term(7));
        let wrong = crate::fencing::IncidentBinding {
            incident: incident.incident_ref(),
            observer_session_id: incident.observer_session_id.clone(),
            observer_loss_generation: 2,
        };
        let before = std::fs::read(&h.f.fixture.parts.path).unwrap();
        let session = h.session.as_mut().unwrap();
        assert!(matches!(
            h.f.fixture
                .parts
                .runtime
                .release_attempt_lease_once(session, Term(8), lease(), "p10".into(), Some(&wrong))
                .unwrap(),
            AttemptLeaseRelease::RecoveryBlocked(_)
        ));
        assert_eq!(std::fs::read(&h.f.fixture.parts.path).unwrap(), before);
        h.f.fixture
            .parts
            .runtime
            .mutation_store
            .begin_lease_request(Term(7), 100, DurationMs(10_000))
            .unwrap();
        let with_m = std::fs::read(&h.f.fixture.parts.path).unwrap();
        assert!(matches!(
            released(&mut h, Term(8)),
            AttemptLeaseRelease::RecoveryBlocked(_)
        ));
        assert_eq!(
            std::fs::read(&h.f.fixture.parts.path).unwrap(),
            with_m,
            "M is never overwritten"
        );
        // An incident without its binding is never released via plain ARM.
        let session = h.session.as_mut().unwrap();
        let mut probe = stage14_10(Term(8), STAGE14_9_ISOLATED);
        stage14_10_confirmed_by_attestation(&probe.f.fixture.parts.runtime, Term(7));
        let bytes = std::fs::read(&probe.f.fixture.parts.path).unwrap();
        let probe_session = probe.session.as_mut().unwrap();
        assert!(matches!(
            probe
                .f
                .fixture
                .parts
                .runtime
                .release_attempt_lease_once(probe_session, Term(8), lease(), "p10".into(), None)
                .unwrap(),
            AttemptLeaseRelease::RecoveryBlocked(_)
        ));
        assert_eq!(std::fs::read(&probe.f.fixture.parts.path).unwrap(), bytes);
        assert!(probe.witness_log().is_empty());
        let _ = session;
        assert!(h.witness_log().is_empty(), "no Release on a mismatch");

        // P10-27: no incident, no binding: the unchanged Stage 13.6 path.
        let mut h = stage14_10(Term(8), STAGE14_9_ISOLATED);
        let session = h.session.as_mut().unwrap();
        assert!(matches!(
            h.f.fixture
                .parts
                .runtime
                .release_attempt_lease_once(session, Term(8), lease(), "p10".into(), None)
                .unwrap(),
            AttemptLeaseRelease::Executed(NodeWitnessMutationResult::AcceptedSuccess { .. })
        ));
        assert_eq!(h.image().release_obligation, None);
        assert_eq!(h.witness_log(), [("release", Term(8))]);
    }

    /// P10-29 / P10-30 / cross-minting: a clearance from an old observer
    /// session or an old loss generation cannot consume the current
    /// incident, and a Witness grant never mints `CONFIRMED`: acquiring a
    /// lease with an `UNKNOWN` incident leaves it `UNKNOWN`.
    #[test]
    fn stage14_10_p29_p30_old_episode_clearance_and_grant_never_confirms() {
        use crate::fencing::{FencingState, UnknownReason};
        for field in ["session", "generation"] {
            let mut h = stage14_10(Term(8), STAGE14_9_ISOLATED);
            let clearance = stage14_10_confirmed_clearance(&h.f.fixture.parts.runtime, Term(7));
            let path = h.f.fixture.parts.path.clone();
            stage14_10_rewrite(&path, |image| {
                let incident = image.fencing_incident.as_mut().unwrap();
                if field == "session" {
                    incident.observer_session_id = SessionId::new("fedcba9876543210");
                } else {
                    incident.observer_loss_generation = 2;
                }
            });
            let before = std::fs::read(&path).unwrap();
            assert!(matches!(
                h.f.fixture
                    .parts
                    .runtime
                    .mutation_store
                    .arm_consuming_fencing(
                        Term(8),
                        LeaseId::new(STAGE14_10_LEASE),
                        &clearance,
                        &NodeId::new("node-b"),
                    ),
                Err(crate::node_mutation::NodeMutationError::FencingIncident(_))
            ));
            assert_eq!(std::fs::read(&path).unwrap(), before, "{field}");
            let _ = h.witness_log();
        }

        let mut h = stage14_10(Term(8), STAGE14_9_ISOLATED);
        h.f.fixture
            .parts
            .runtime
            .mutation_store
            .open_fencing_incident(crate::fencing::IncidentOpening {
                target_node_id: NodeId::new("node-b"),
                anchor_term: Term(7),
                observer_session_id: SessionId::new(STAGE14_9_SESSION),
                observer_loss_generation: 1,
                backend: crate::fencing::FencingBackend::None,
            })
            .unwrap();
        let session = h.session.as_mut().unwrap();
        assert!(matches!(
            h.f.fixture
                .parts
                .runtime
                .acquire_lease_once(session, Term(7))
                .unwrap(),
            NodeWitnessMutationResult::AcceptedSuccess { .. }
        ));
        assert_eq!(
            stage14_9_incident(&h.f).unwrap().state,
            FencingState::Unknown(UnknownReason::NotAttempted {}),
            "a grant never mints CONFIRMED"
        );
        let _ = h.witness_log();
    }

    /// P10-32: a SIGUSR1 delivered while an attempt is in flight creates no
    /// second attempt (the post-attempt intent discard).
    #[test]
    fn stage14_10_p32_sigusr1_during_the_attempt_is_discarded() {
        let h = stage14_10(Term(8), STAGE14_9_ISOLATED);
        stage14_10_confirmed_by_attestation(&h.f.fixture.parts.runtime, Term(7));
        h.resources_respond();
        let mut daemon = stage14_10_daemon(h);
        let latch = std::rc::Rc::new(Cell::new(false));
        struct RcLatch(std::rc::Rc<Cell<bool>>);
        impl crate::daemon_run::PromotionIntentLatch for RcLatch {
            fn consume(&self) -> bool {
                self.0.replace(false)
            }
            fn discard(&self) {
                self.0.set(false);
            }
        }
        let intent = RcLatch(latch.clone());
        let waits = Cell::new(0);
        let mut attempts = 0;
        let exit = crate::daemon_run::run_observation_loop(
            &mut daemon,
            Duration::from_secs(1),
            || waits.get() >= 4,
            |_| {
                waits.set(waits.get() + 1);
                if waits.get() == 1 {
                    latch.set(true);
                }
            },
            std::time::Instant::now,
            &intent,
            |_, _| {},
            |daemon| {
                attempts += 1;
                // A second SIGUSR1 arrives while this attempt runs.
                let during = latch.clone();
                stage14_10_race_after_grant(daemon, move |_| during.set(true));
                let _ = stage14_10_attempt(daemon);
            },
        );
        assert_eq!(exit, crate::daemon_run::LoopExit::Clean);
        assert_eq!(attempts, 1, "no second attempt");
        let mut h = crate::daemon::stage14_9_support::into_runtime(daemon);
        assert_eq!(h.witness_log(), [("request", Term(8))]);
    }

    // ------------------------------------------------------------------
    // Stage 14 Phase 14.11: F2 (exact binding), F3, and the §28 runtime log
    // lines.
    // ------------------------------------------------------------------

    /// F2 (Rev5 §25, §25.1): `ArmRejected` from L, with a REAL clearance and a
    /// real cleanup. K passed, the ARM was rejected, so the Daemon runs the
    /// §25.1 cleanup with the clearance's exact durable binding: the incident
    /// is retired together with the cleanup O in one write, the exact Release
    /// follows and clears O, and nothing was promoted.
    #[test]
    fn stage14_11_f2_arm_rejected_uses_the_exact_binding() {
        let mut h = stage14_10(Term(8), STAGE14_9_ISOLATED);
        stage14_10_confirmed_by_attestation(&h.f.fixture.parts.runtime, Term(7));
        h.resources_respond();
        h.forced_arm = Some((crate::daemon::AttemptPromotionOutcome::ArmRejected, false));
        let high_water = h.image().highest_fencing_incident_seq;
        let mut daemon = stage14_10_daemon(h);
        crate::operator_log::capture_start();
        assert_eq!(
            stage14_10_attempt(&mut daemon),
            crate::promotion_attempt::PromotionAttemptResult::BlockedBeforeMutation
        );
        let lines = crate::operator_log::capture_take();
        assert_eq!(daemon.state(), crate::daemon::DaemonState::Running);
        let mut h = crate::daemon::stage14_9_support::into_runtime(daemon);
        assert_eq!(h.rechecks, [Ok(())], "K passed; only the ARM was rejected");
        assert_eq!(h.cleanups, [Ok(crate::daemon::AttemptCleanup::Released)]);
        stage14_10_assert_cleaned_and_released(&mut h, high_water);
        assert!(
            lines.contains(
                &"mikagami: INFO fencing incident 1 (target node-b) consumed: abort cleanup (retired, release obligation armed)"
                    .to_string()
            ),
            "{lines:?}"
        );
        assert!(
            lines.contains(
                &"mikagami: WARN activation attempt blocked: ARM validation rejected".to_string()
            ),
            "{lines:?}"
        );
    }

    /// F2: if the durable incident is no longer the one the clearance was
    /// minted from at cleanup time, the exact binding does not match:
    /// RecoveryBlocked, no write over the foreign incident, no Release.
    #[test]
    fn stage14_11_f2_arm_rejected_with_a_replaced_incident_is_recovery_blocked() {
        let mut h = stage14_10(Term(8), STAGE14_9_ISOLATED);
        stage14_10_confirmed_by_attestation(&h.f.fixture.parts.runtime, Term(7));
        h.resources_respond();
        h.forced_arm = Some((crate::daemon::AttemptPromotionOutcome::ArmRejected, true));
        let mut daemon = stage14_10_daemon(h);
        assert_eq!(
            stage14_10_attempt(&mut daemon),
            crate::promotion_attempt::PromotionAttemptResult::BlockedBeforeMutation
        );
        assert_eq!(daemon.state(), crate::daemon::DaemonState::RecoveryBlocked);
        let mut h = crate::daemon::stage14_9_support::into_runtime(daemon);
        assert!(matches!(
            h.cleanups.as_slice(),
            [Ok(crate::daemon::AttemptCleanup::RecoveryBlocked(_))]
        ));
        let image = h.image();
        assert_eq!(
            image
                .fencing_incident
                .as_ref()
                .map(|incident| incident.incident_id.as_str()),
            Some("99999999-2222-4333-8444-555555555555"),
            "the foreign incident is neither retired nor overwritten"
        );
        assert_eq!(
            image.release_obligation, None,
            "no cleanup O without the exact binding"
        );
        assert!(h.mutations().is_empty());
        assert_eq!(h.witness_log(), [("request", Term(8))], "no Release");
    }

    /// F3 (Rev5 §25.1 validation mismatch, §16 routing): the attempt's
    /// incident is gone but its cleanup binding exists. The old image has no
    /// incident to retire, so the cleanup is a validation mismatch:
    /// RecoveryBlocked, nothing written, no plain ARM, no Release, no resource
    /// mutation, no authority restored.
    #[test]
    fn stage14_11_f3_no_incident_with_binding_is_recovery_blocked_without_release() {
        let mut h = stage14_10(Term(8), STAGE14_9_ISOLATED);
        let incident = stage14_10_confirmed_by_attestation(&h.f.fixture.parts.runtime, Term(7));
        let binding = crate::fencing::IncidentBinding {
            incident: incident.incident_ref(),
            observer_session_id: incident.observer_session_id.clone(),
            observer_loss_generation: incident.observer_loss_generation,
        };
        // The incident vanishes before the cleanup (a plain retirement).
        h.f.fixture
            .parts
            .runtime
            .mutation_store
            .retire_fencing_incident(&incident.incident_ref())
            .unwrap();
        let before = std::fs::read(&h.f.fixture.parts.path).unwrap();
        let image_before = h.image();
        assert_eq!(image_before.fencing_incident, None);
        let session = h.session.as_mut().unwrap();
        let outcome =
            h.f.fixture
                .parts
                .runtime
                .release_attempt_lease_once(
                    session,
                    Term(8),
                    LeaseId::new(STAGE14_10_LEASE),
                    "f3".into(),
                    Some(&binding),
                )
                .unwrap();
        let AttemptLeaseRelease::RecoveryBlocked(reason) = outcome else {
            panic!("expected RecoveryBlocked, got {outcome:?}");
        };
        assert!(reason.contains("incident is absent"), "{reason}");
        assert_eq!(
            std::fs::read(&h.f.fixture.parts.path).unwrap(),
            before,
            "nothing was written: no O, no incident, no M"
        );
        let image = h.image();
        assert_eq!(image.release_obligation, None, "no plain ARM");
        assert_eq!(image.outstanding_mutation, None);
        assert_eq!(
            image.highest_fencing_incident_seq,
            image_before.highest_fencing_incident_seq
        );
        assert!(h.mutations().is_empty(), "no resource mutation");
        assert!(
            h.f.fixture
                .parts
                .runtime
                .installed_lease_authority()
                .is_none(),
            "no authority restored"
        );
        assert!(h.witness_log().is_empty(), "no Release, no request");
    }

    /// §28: the gate's log lines carry the target, the incident sequence, the
    /// state, and a bounded reason; each durable transition writes one INFO;
    /// a stale incident's retirement names its reason.
    #[test]
    fn stage14_11_gate_and_step_write_the_operator_lines() {
        // B = command: open REQUESTED, the action returns, VERIFYING; blocked.
        let mut h = stage14_10(Term(8), STAGE14_9_ISOLATED);
        crate::operator_log::capture_start();
        let (outcome, _) = stage14_9_gate(&mut h.f, Term(7));
        h.f.fixture.parts.runtime.log_gate_block(&outcome);
        assert_eq!(
            outcome.block,
            crate::fencing::FencingGateBlock::FencingInProgress
        );
        assert_eq!(
            crate::operator_log::capture_take(),
            [
                "mikagami: INFO fencing incident 1 (target node-b) opened: REQUESTED",
                "mikagami: INFO fencing incident 1 (target node-b): REQUESTED -> VERIFYING",
                "mikagami: WARN activation attempt blocked: fencing in progress (target node-b, incident 1, state VERIFYING)",
            ]
        );
        // The verify poll confirms: one INFO for the durable transition.
        let incident = stage14_9_incident(&h.f).unwrap();
        let record = stage14_9_record(&incident, Term(7));
        crate::operator_log::capture_start();
        let (step, _) = stage14_9_drive(&mut h.f, Some(&record));
        assert!(matches!(step, FencingStepOutcome::Polled { .. }));
        assert_eq!(
            crate::operator_log::capture_take(),
            ["mikagami: INFO fencing incident 1 (target node-b): VERIFYING -> CONFIRMED"]
        );
        // A valid CONFIRMED passes the gate: no blocked-attempt line.
        crate::operator_log::capture_start();
        assert!(matches!(
            stage14_9_gate_decision_with(&mut h.f, Term(7), false, true).0,
            FencingGateDecision::Clear { .. }
        ));
        assert!(crate::operator_log::capture_take().is_empty());
        // The Witness term moved: the stale incident retires with its reason
        // and a new incident opens.
        crate::operator_log::capture_start();
        let (outcome, _) = stage14_9_gate(&mut h.f, Term(9));
        h.f.fixture.parts.runtime.log_gate_block(&outcome);
        let lines = crate::operator_log::capture_take();
        assert_eq!(
            outcome.block,
            crate::fencing::FencingGateBlock::FencingInProgress
        );
        assert_eq!(
            lines[0],
            "mikagami: INFO fencing incident 1 (target node-b) retired: Witness term moved"
        );
        assert_eq!(
            lines[1],
            "mikagami: INFO fencing incident 2 (target node-b) opened: REQUESTED"
        );
    }

    /// §28 (B = none): a new incident blocks with `fencing required`; the
    /// next attempt with the incident still UNKNOWN blocks with `fencing
    /// unconfirmed`. Each names the target, the sequence, and the state, so
    /// the operator can form the exact `recover` command.
    #[test]
    fn stage14_11_backend_none_block_names_the_incident_for_recover() {
        let mut h = stage14_10(Term(8), STAGE14_9_ISOLATED);
        h.f.fixture
            .parts
            .runtime
            .set_fencing_settings_for_test(crate::fencing_backend::FencingSettings::None);
        crate::operator_log::capture_start();
        let (outcome, _) = stage14_9_gate(&mut h.f, Term(7));
        h.f.fixture.parts.runtime.log_gate_block(&outcome);
        assert_eq!(
            outcome.block,
            crate::fencing::FencingGateBlock::FencingRequired
        );
        assert_eq!(
            crate::operator_log::capture_take(),
            [
                "mikagami: INFO fencing incident 1 (target node-b) opened: UNKNOWN",
                "mikagami: WARN activation attempt blocked: fencing required (target node-b, incident 1, state UNKNOWN)",
            ]
        );
        crate::operator_log::capture_start();
        let (outcome, _) = stage14_9_gate(&mut h.f, Term(7));
        h.f.fixture.parts.runtime.log_gate_block(&outcome);
        assert_eq!(
            outcome.block,
            crate::fencing::FencingGateBlock::FencingUnconfirmed
        );
        assert_eq!(
            crate::operator_log::capture_take(),
            [
                "mikagami: WARN activation attempt blocked: fencing unconfirmed (target node-b, incident 1, state UNKNOWN)"
            ]
        );
    }

    /// §28 (remediation): every rejected-intent path writes exactly one WARN
    /// with its bounded reason: a rejected intent FILE (here an unsafe intent
    /// directory) names the fault, and an intent whose T8 did not commit
    /// (`PreCommitFailure`, the old image kept) says so and writes no INFO.
    #[test]
    fn stage14_11_attestation_file_rejection_and_precommit_failure_each_warn_once() {
        use std::os::unix::fs::PermissionsExt;
        // The production entry (`ingest_attestation`) writes the lines.
        let ingest = |fixture: &mut Stage148, latest: Option<Term>| {
            fixture.parts.runtime.attestation_owner_for_test = Some(fixture.uid);
            let evidence = stage14_8_evidence();
            let (peer, session) = (
                NodeId::new("node-b"),
                crate::protocol::SessionId::new("0123456789abcdef"),
            );
            fixture
                .parts
                .runtime
                .ingest_attestation(
                    &crate::fencing::ContinuityContext {
                        configured_peer: &peer,
                        current_session: &session,
                        live_episode: evidence.as_ref(),
                    },
                    latest,
                )
                .unwrap()
        };
        let mut fixture = stage14_8_runtime();
        let incident = stage14_8_open(&fixture);
        stage14_8_install(
            &fixture,
            &stage14_8_intent(&incident, STAGE14_8_ATTESTATION),
        );
        std::fs::set_permissions(&fixture.dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        crate::operator_log::capture_start();
        let outcome = ingest(&mut fixture, None);
        let lines = crate::operator_log::capture_take();
        std::fs::set_permissions(&fixture.dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            outcome,
            AttestationIngestion::RejectedFile {
                fault: crate::attestation::IntentFault::ParentWritable,
                ..
            }
        ));
        assert_eq!(
            lines,
            ["mikagami: WARN attestation intent rejected: ParentWritable"]
        );

        let mut fixture = stage14_8_runtime();
        let incident = stage14_8_open(&fixture);
        stage14_8_install(
            &fixture,
            &stage14_8_intent(&incident, STAGE14_8_ATTESTATION),
        );
        let before = stage14_8_state(&fixture);
        crate::recovery::inject_fault_once(crate::recovery::FaultPoint::CandidateTempFsync);
        crate::operator_log::capture_start();
        let outcome = ingest(&mut fixture, Some(Term(41)));
        let lines = crate::operator_log::capture_take();
        assert!(
            matches!(outcome, AttestationIngestion::PreCommitFailure(_)),
            "{outcome:?}"
        );
        assert_eq!(stage14_8_state(&fixture), before, "the old image is kept");
        assert_eq!(
            lines,
            ["mikagami: WARN attestation intent rejected: not committed"],
            "one WARN, and no INFO for a transition that did not commit"
        );
    }

    /// §28: one WARN per rejected attestation intent with a bounded reason,
    /// one INFO for the committed T8, and the retirement INFO when the intent
    /// meets a stale incident.
    #[test]
    fn stage14_11_attestation_ingestion_writes_the_operator_lines() {
        let mut fixture = stage14_8_runtime();
        fixture.parts.runtime.attestation_owner_for_test = Some(fixture.uid);
        let incident = stage14_8_open(&fixture);
        let ingest = |fixture: &Stage148, session: &str, latest: Option<Term>| {
            let evidence = stage14_8_evidence();
            let (peer, session) = (
                NodeId::new("node-b"),
                crate::protocol::SessionId::new(session),
            );
            fixture
                .parts
                .runtime
                .ingest_attestation(
                    &crate::fencing::ContinuityContext {
                        configured_peer: &peer,
                        current_session: &session,
                        live_episode: evidence.as_ref(),
                    },
                    latest,
                )
                .unwrap()
        };
        let mut wrong_seq = stage14_8_intent(&incident, STAGE14_8_ATTESTATION);
        wrong_seq.incident_seq = 2;
        stage14_8_install(&fixture, &wrong_seq);
        crate::operator_log::capture_start();
        assert!(matches!(
            ingest(&fixture, "0123456789abcdef", None),
            AttestationIngestion::RejectedIntent { .. }
        ));
        assert_eq!(
            crate::operator_log::capture_take(),
            ["mikagami: WARN attestation intent rejected: Incident"]
        );
        stage14_8_install(
            &fixture,
            &stage14_8_intent(&incident, STAGE14_8_ATTESTATION),
        );
        crate::operator_log::capture_start();
        assert!(matches!(
            ingest(&fixture, "0123456789abcdef", Some(Term(41))),
            AttestationIngestion::Confirmed { .. }
        ));
        assert_eq!(
            crate::operator_log::capture_take(),
            ["mikagami: INFO fencing incident 1 (target node-b): UNKNOWN -> CONFIRMED"]
        );
        // A stale observer session at ingestion retires the incident.
        let fixture = stage14_8_runtime();
        let mut fixture = fixture;
        fixture.parts.runtime.attestation_owner_for_test = Some(fixture.uid);
        let incident = stage14_8_open(&fixture);
        stage14_8_install(
            &fixture,
            &stage14_8_intent(&incident, STAGE14_8_ATTESTATION),
        );
        crate::operator_log::capture_start();
        assert!(matches!(
            ingest(&fixture, "fedcba9876543210", None),
            AttestationIngestion::Retired { .. }
        ));
        assert_eq!(
            crate::operator_log::capture_take(),
            ["mikagami: INFO fencing incident 1 (target node-b) retired: observer session changed"]
        );
    }

    /// §28: the success ARM and the abort cleanup each write one INFO for the
    /// atomic consumption, after the commit.
    #[test]
    fn stage14_11_atomic_consumption_writes_one_info() {
        // Success ARM.
        let h = stage14_10(Term(8), STAGE14_9_ISOLATED);
        stage14_10_confirmed_by_attestation(&h.f.fixture.parts.runtime, Term(7));
        h.resources_respond();
        let mut daemon = stage14_10_daemon(h);
        crate::operator_log::capture_start();
        assert_eq!(
            stage14_10_attempt(&mut daemon),
            crate::promotion_attempt::PromotionAttemptResult::Succeeded
        );
        let lines = crate::operator_log::capture_take();
        assert_eq!(
            lines,
            [
                "mikagami: INFO fencing incident 1 (target node-b) consumed: success ARM (CONFIRMED -> none, release obligation armed)"
            ]
        );
        let mut h = crate::daemon::stage14_9_support::into_runtime(daemon);
        let _ = h.witness_log();
        // Grant term != anchor + 1: the §25.1 abort cleanup consumes it.
        let h = stage14_10(Term(9), STAGE14_9_ISOLATED);
        stage14_10_confirmed_by_attestation(&h.f.fixture.parts.runtime, Term(7));
        let mut daemon = stage14_10_daemon({
            h.resources_respond();
            h
        });
        crate::operator_log::capture_start();
        let _ = stage14_10_attempt(&mut daemon);
        let lines = crate::operator_log::capture_take();
        assert_eq!(
            lines,
            [
                "mikagami: WARN activation attempt blocked: Witness grant term is not the clearance anchor + 1",
                "mikagami: INFO fencing incident 1 (target node-b) consumed: abort cleanup (retired, release obligation armed)",
            ]
        );
        let mut h = crate::daemon::stage14_9_support::into_runtime(daemon);
        let _ = h.witness_log();
    }

    /// §28: the block line for an EXISTING incident names that incident's own
    /// state (not the state of one just opened): in progress on `VERIFYING`,
    /// unconfirmed on `FAILED` (B = none), and for `REQUESTED`.
    #[test]
    fn stage14_11_gate_block_names_the_existing_incident_state() {
        // VERIFYING: the first gate opens the incident and runs the action;
        // the second attempt meets the existing VERIFYING incident.
        let mut h = stage14_10(Term(8), STAGE14_9_ISOLATED);
        let _ = stage14_9_gate(&mut h.f, Term(7));
        assert!(matches!(
            stage14_9_incident(&h.f).unwrap().state,
            crate::fencing::FencingState::Verifying { .. }
        ));
        crate::operator_log::capture_start();
        let (outcome, _) = stage14_9_gate(&mut h.f, Term(7));
        h.f.fixture.parts.runtime.log_gate_block(&outcome);
        assert_eq!(
            crate::operator_log::capture_take(),
            [
                "mikagami: WARN activation attempt blocked: fencing in progress (target node-b, incident 1, state VERIFYING)"
            ]
        );
        // REQUESTED: the action was not persisted as returned (the incident
        // was left REQUESTED); the existing arm reports that state.
        let mut h = stage14_10(Term(8), STAGE14_9_ISOLATED);
        h.f.fixture
            .parts
            .runtime
            .mutation_store
            .open_fencing_incident(crate::fencing::IncidentOpening {
                target_node_id: NodeId::new("node-b"),
                anchor_term: Term(7),
                observer_session_id: SessionId::new(STAGE14_9_SESSION),
                observer_loss_generation: 1,
                backend: crate::fencing::FencingBackend::Command,
            })
            .unwrap();
        crate::operator_log::capture_start();
        let (outcome, _) = stage14_9_gate(&mut h.f, Term(7));
        h.f.fixture.parts.runtime.log_gate_block(&outcome);
        assert_eq!(
            crate::operator_log::capture_take(),
            [
                "mikagami: WARN activation attempt blocked: fencing in progress (target node-b, incident 1, state REQUESTED)"
            ]
        );
        // FAILED (the verifier reported not-isolated), then B = none: the
        // existing FAILED incident is unconfirmed and says so.
        let mut h = stage14_10(Term(8), STAGE14_9_NOT_ISOLATED);
        let _ = stage14_9_gate(&mut h.f, Term(7));
        let incident = stage14_9_incident(&h.f).unwrap();
        let record = stage14_9_record(&incident, Term(7));
        let _ = stage14_9_drive(&mut h.f, Some(&record));
        assert!(matches!(
            stage14_9_incident(&h.f).unwrap().state,
            crate::fencing::FencingState::Failed { .. }
        ));
        h.f.fixture
            .parts
            .runtime
            .set_fencing_settings_for_test(crate::fencing_backend::FencingSettings::None);
        crate::operator_log::capture_start();
        let (outcome, _) = stage14_9_gate(&mut h.f, Term(7));
        h.f.fixture.parts.runtime.log_gate_block(&outcome);
        assert_eq!(
            crate::operator_log::capture_take(),
            [
                "mikagami: WARN activation attempt blocked: fencing unconfirmed (target node-b, incident 1, state FAILED)"
            ]
        );
    }

    // ======================================================================
    // Phase 14.12 PC-1: the permanent E3b positive control through the
    // PRODUCTION fencing path.
    //
    // The Stage 13.2 fake (`daemon::tests::ExecFake`) reaches `Succeeded` by
    // returning the test-only `FencingGate::BypassedForStage13Test`, so its
    // E3b positive control never ran the fencing gate, the clearance, the K
    // recheck or the ARM. These tests close that gap. Every attempt below runs
    // the PRODUCTION `Daemon::execute_promotion_attempt` over:
    //   * the Production E3b step (`WitnessEvidenceAdapter::
    //     complete_attempt_observation`) against a scripted loopback Witness;
    //   * the Production observation/evaluation composition (`stage14_9_support::
    //     evaluate_observation`: observe_peer_at, poll_observation_at, the fresh
    //     `Safe` local-safety requirement and `AuthorityAttemptEvaluation::
    //     evaluate`) over a real `PeerFailureDetector` in confirmed loss and the
    //     real `LinuxNodeRuntime::failover_local_safety_snapshot`;
    //   * the Production `LinuxNodeRuntime::fencing_gate` (real bounded fence
    //     and verify processes, the real durable incident), `fencing_final_recheck`,
    //     `acquire_lease_once`, `release_attempt_lease_once`, `arm_and_promote`
    //     and the Stage 11 promotion over the fake resources.
    // Nothing returns `BypassedForStage13Test`: the attempt reaches `Succeeded`
    // only with a clearance minted by the gate from a durable CONFIRMED
    // incident. The fixture's remaining glue (`impl PromotionExecutionRuntime
    // for Stage1410`) mirrors the thin `LinuxDaemonRuntime` wrapper; the
    // Production binary is exercised by the lab, not here.
    // ======================================================================

    /// A real detector driven through the production lifecycle into
    /// `CommunicationLost`, `generation` times, entirely in the past (the
    /// loss evidence is fresh: its freshness reference is ~12 s old, the
    /// bound is 30 s).
    fn pc1_detector(generation: u64) -> crate::failure_assessment::PeerFailureDetector {
        let mut detector =
            crate::failure_assessment::PeerFailureDetector::new(Duration::from_secs(5)).unwrap();
        let mut at = std::time::Instant::now() - Duration::from_secs(6 * generation + 6);
        for round in 0..generation {
            let peer_session = SessionId::new(format!("peer-session-{round}"));
            detector
                .observe_session_established(peer_session.clone(), at)
                .unwrap();
            detector
                .observe_trusted_heartbeat(&peer_session, Sequence(1), at)
                .unwrap();
            detector.observe_transport_failure(at).unwrap();
            at += Duration::from_secs(5);
            detector.tick(at).unwrap();
            at += Duration::from_secs(1);
        }
        assert_eq!(
            detector.assessment(),
            crate::failure_assessment::PeerFailureAssessment::CommunicationLost
        );
        detector
    }

    /// The positive control's scripts record the target the daemon passed
    /// (`MIKAGAMI_FENCE_TARGET`, the configured peer) and the attempt token.
    const PC1_FENCE_LOGS_TARGET: &str =
        "echo \"$MIKAGAMI_FENCE_TARGET $MIKAGAMI_FENCE_ATTEMPT\" >> {log}; exit 0";
    const PC1_VERIFY_LOGS_TARGET: &str =
        "echo \"verify $MIKAGAMI_FENCE_TARGET $MIKAGAMI_FENCE_ATTEMPT\" >> {log}; echo isolated";
    const PC1_FENCE_FAILS: &str = "echo \"$MIKAGAMI_FENCE_ATTEMPT\" >> {log}; exit 3";
    const PC1_FENCE_HANGS: &str = "echo \"$MIKAGAMI_FENCE_ATTEMPT\" >> {log}; exec sleep 30";

    fn pc1_from(f: Stage149, script: Pc1WitnessScript) -> Stage1410 {
        pc1_from_grant(f, script, Term(8))
    }

    fn pc1_from_grant(f: Stage149, script: Pc1WitnessScript, grant: Term) -> Stage1410 {
        let (session, witness) = stage14_10_witness_scripted(grant, script);
        let (peer, current, _) = stage14_9_context_parts(true);
        Stage1410 {
            f,
            session: Some(session),
            witness: Some(witness),
            record: None,
            configured_peer: peer,
            current_session: current,
            episode: Some(1),
            gate_view: None,
            slot_busy: false,
            rechecks: Vec::new(),
            cleanups: Vec::new(),
            forced_arm: None,
            pc1: Some(Pc1Observation {
                observer: crate::evidence_fusion::adapter::WitnessEvidenceAdapter::new(
                    Duration::from_secs(2),
                )
                .unwrap(),
                detector: pc1_detector(1),
                evaluation_skew: Duration::ZERO,
                steps: 0,
                evaluations: 0,
            }),
        }
    }

    /// Standby, zero resource, `backend = "command"`, a generation-1 loss
    /// episode, a Witness that answers GET_TERM with no holder at term 7 and
    /// grants the lease at term 8.
    fn pc1_harness(fence: &str, verify: &str, fence_timeout: u64) -> Stage1410 {
        pc1_with(fence, verify, fence_timeout, Pc1WitnessScript::default())
    }

    fn pc1_with(
        fence: &str,
        verify: &str,
        fence_timeout: u64,
        script: Pc1WitnessScript,
    ) -> Stage1410 {
        let h = pc1_from(
            stage14_9_command(fence, verify, fence_timeout, 10, 3),
            script,
        );
        h.resources_respond();
        h
    }

    fn pc1_attempt(
        daemon: &mut crate::daemon::Daemon<Stage1410>,
        id: &str,
    ) -> crate::promotion_attempt::PromotionAttemptResult {
        daemon.execute_promotion_attempt(crate::promotion_attempt::PromotionExecutionRequest::new(
            crate::promotion_attempt::PromotionRequestId::new(id),
        ))
    }

    /// Attempt 1 opens the incident and runs the REAL fence action, blocking
    /// at the gate; the next foreground tick runs the REAL verify poll and
    /// durably records CONFIRMED. No lease was requested by either.
    fn pc1_confirm(daemon: &mut crate::daemon::Daemon<Stage1410>) {
        assert_eq!(
            pc1_attempt(daemon, "pc1-prime"),
            crate::promotion_attempt::PromotionAttemptResult::BlockedBeforeMutation
        );
        daemon.tick().unwrap();
        let h = stage14_10_harness(daemon);
        assert!(
            matches!(
                stage14_9_incident(&h.f).unwrap().state,
                crate::fencing::FencingState::Confirmed(_)
            ),
            "the real fence action + verify poll confirmed the incident"
        );
    }

    /// What one scenario left behind. Reading it consumes the Witness log.
    struct Pc1Facts {
        witness: Vec<(&'static str, Term)>,
        fence_actions: usize,
        verify_polls: usize,
        mutations: Vec<&'static str>,
        incident: Option<&'static str>,
        node: NodeState,
        image: crate::node_mutation::NodeMutationPersistentState,
        steps: usize,
        evaluations: usize,
    }

    impl Pc1Facts {
        fn get_terms(&self) -> usize {
            self.witness
                .iter()
                .filter(|(k, _)| *k == "get_term")
                .count()
        }
        fn kinds(&self) -> Vec<&'static str> {
            self.witness.iter().map(|(kind, _)| *kind).collect()
        }
        fn lease_requests(&self) -> usize {
            self.witness.iter().filter(|(k, _)| *k == "request").count()
        }
        fn releases(&self) -> usize {
            self.witness.iter().filter(|(k, _)| *k == "release").count()
        }
    }

    /// Collect the facts and print one `PC1-TRACE` line (the report's
    /// per-case record: expected vs actual transition, fence / lease /
    /// resource activity, authority-evidence state, final state).
    fn pc1_facts(
        case: &str,
        expected: &str,
        results: &[crate::promotion_attempt::PromotionAttemptResult],
        warns: &[String],
        h: &mut Stage1410,
    ) -> Pc1Facts {
        let log = std::fs::read_to_string(&h.f.log).unwrap_or_default();
        let verify_polls = log.lines().filter(|l| l.starts_with("verify")).count();
        let fence_actions = log.lines().filter(|l| !l.starts_with("verify")).count();
        let (observer, steps, evaluations) = match &h.pc1 {
            Some(pc1) => {
                let snapshot = pc1.observer.snapshot();
                (
                    format!(
                        "request_generation={} observation_generation={} pending={} completion={} witness_status={:?}",
                        snapshot.request_generation,
                        snapshot.observation_generation,
                        snapshot.pending.is_some(),
                        snapshot.last_completion.is_some(),
                        snapshot.fusion.witness_status,
                    ),
                    pc1.steps,
                    pc1.evaluations,
                )
            }
            None => (String::new(), 0, 0),
        };
        let image = h.image();
        let incident = stage14_9_incident(&h.f).map(|incident| incident.state.operator_name());
        let node = h.f.fixture.parts.runtime.state_machine.node_state();
        let mutations = h.mutations();
        let witness = h.witness_log();
        let facts = Pc1Facts {
            witness,
            fence_actions,
            verify_polls,
            mutations,
            incident,
            node,
            image,
            steps,
            evaluations,
        };
        eprintln!(
            "PC1-TRACE case=[{case}] expected=[{expected}] actual={results:?} \
             witness={:?} fence_actions={} verify_polls={} lease_requests={} releases={} \
             resource_mutations={:?} observer{{{observer}}} steps={} evaluations={} \
             incident={:?} release_obligation={} outstanding_mutation={} node={:?} warns={warns:?}",
            facts.kinds(),
            facts.fence_actions,
            facts.verify_polls,
            facts.lease_requests(),
            facts.releases(),
            facts.mutations,
            facts.steps,
            facts.evaluations,
            facts.incident,
            facts.image.release_obligation.is_some(),
            facts.image.outstanding_mutation.is_some(),
            facts.node,
        );
        facts
    }

    /// The invariant every blocked-before-lease scenario shares: nothing past
    /// the stopping stage ran.
    fn pc1_assert_no_lease_and_no_mutation(facts: &Pc1Facts, case: &str) {
        assert_eq!(facts.lease_requests(), 0, "{case}: no LeaseRequest");
        assert_eq!(facts.releases(), 0, "{case}: no Release (nothing granted)");
        assert!(facts.mutations.is_empty(), "{case}: no resource mutation");
        assert_eq!(facts.image.release_obligation, None, "{case}: no O");
        assert_eq!(facts.node, NodeState::Standby, "{case}: never Active");
    }

    const PC1_BLOCKED: crate::promotion_attempt::PromotionAttemptResult =
        crate::promotion_attempt::PromotionAttemptResult::BlockedBeforeMutation;

    /// PC-P01 .. PC-P10. Two SIGUSR1 intents through the PRODUCTION
    /// `run_observation_loop`:
    ///  1st: its own GET_TERM -> fresh evaluation -> authorization -> the real
    ///       fencing gate opens the incident and runs the real fence action
    ///       against the isolated target -> blocked at the gate, no lease. The
    ///       same iteration's foreground tick runs the real verify poll ->
    ///       CONFIRMED.
    ///  2nd: its own GET_TERM -> fresh evaluation -> authorization -> the gate
    ///       mints the clearance from the durable CONFIRMED incident -> exactly
    ///       one LeaseRequest at anchor+1 -> the K recheck against the live
    ///       continuity -> the atomic ARM consumes the incident and installs O
    ///       -> the Stage 11 promotion -> `Succeeded`.
    #[test]
    fn pc1_p01_to_p10_sigusr1_reaches_succeeded_through_the_real_fencing_path() {
        let h = pc1_harness(PC1_FENCE_LOGS_TARGET, PC1_VERIFY_LOGS_TARGET, 10);
        let mut daemon = stage14_10_daemon(h);
        let latch = Stage149Latch(Cell::new(false));
        let waits = Cell::new(0);
        let mut results = Vec::new();
        let mut raised = 0;
        crate::operator_log::capture_start();
        let exit = crate::daemon_run::run_observation_loop(
            &mut daemon,
            Duration::from_secs(1),
            || waits.get() >= 8,
            |_| {
                waits.set(waits.get() + 1);
                if waits.get() == 2 || waits.get() == 5 {
                    latch.0.set(true);
                    raised += 1;
                }
            },
            std::time::Instant::now,
            &latch,
            |_, _| {},
            |daemon| {
                let id = format!("pc1-sigusr1-{}", results.len() + 1);
                results.push(pc1_attempt(daemon, &id));
            },
        );
        let warns = crate::operator_log::capture_take();
        assert_eq!(exit, crate::daemon_run::LoopExit::Clean);
        // P01: one SIGUSR1 started exactly one attempt each.
        assert_eq!(raised, 2);
        assert_eq!(
            results,
            [
                crate::promotion_attempt::PromotionAttemptResult::BlockedBeforeMutation,
                crate::promotion_attempt::PromotionAttemptResult::Succeeded,
            ],
            "P01/P10: the first attempt stops at the gate, the second succeeds"
        );
        let mut h = crate::daemon::stage14_9_support::into_runtime(daemon);
        // P09: the exact ARM-backed durable image, read before the facts.
        assert_eq!(h.rechecks, [Ok(())], "P08: one K recheck, it passed");
        let facts = pc1_facts(
            "PC-P01..P10 positive",
            "Blocked(gate) then Succeeded",
            &results,
            &warns,
            &mut h,
        );
        // P02: one attempt-bound GET_TERM per attempt, issued by the E3b step.
        assert_eq!(facts.steps, 2);
        assert_eq!(facts.get_terms(), 2);
        // P03/P04: each attempt evaluated its own fresh observation once.
        assert_eq!(facts.evaluations, 2);
        // P05/P06/P07: the real fence action ran once, against the isolated
        // target, and the real verify poll confirmed it, all before the lease.
        assert_eq!(facts.fence_actions, 1);
        assert_eq!(facts.verify_polls, 1);
        let spawn_log = std::fs::read_to_string(&h.f.log).unwrap();
        let lines: Vec<&str> = spawn_log.lines().collect();
        assert_eq!(lines.len(), 2, "{lines:?}");
        let token = lines[0]
            .strip_prefix("node-b ")
            .expect("the fence action ran against the configured peer node-b");
        assert_eq!(
            lines[1],
            format!("verify node-b {token}"),
            "the verify poll polled the same target under the same attempt token"
        );
        // P09: exactly one LeaseRequest, after the confirmation, at anchor+1.
        assert_eq!(
            facts.witness,
            [
                ("get_term", Term(7)),
                ("get_term", Term(7)),
                ("request", Term(8))
            ],
            "the lease is requested only by the second attempt, after its own GET_TERM"
        );
        assert_eq!(facts.releases(), 0);
        assert!(
            warns
                .iter()
                .any(|line| line.contains("fencing in progress")),
            "the first attempt reported the gate block: {warns:?}"
        );
        // P08/P10: the ARM consumed the incident and installed the exact O.
        assert_eq!(facts.incident, None, "the incident was consumed by the ARM");
        assert_eq!(
            facts.image.release_obligation,
            Some(crate::node_mutation::ReleaseObligation {
                term: Term(8),
                lease_id: LeaseId::new(STAGE14_10_LEASE),
            })
        );
        assert!(facts.mutations.contains(&"vip_acquire"));
        assert_eq!(facts.node, NodeState::Active);
    }

    /// The pre-PC-1 negative control, now through the real gate fixture: a
    /// Witness that names the peer as the holder is refused at the evaluation,
    /// before the gate: no incident, no fence action, no lease.
    #[test]
    fn pc1_negative_control_a_peer_holder_is_refused_before_the_gate() {
        let h = pc1_with(
            STAGE14_9_FENCE_OK,
            STAGE14_9_ISOLATED,
            10,
            Pc1WitnessScript {
                terms: VecDeque::from([Pc1TermReply::PeerHolder]),
                ..Pc1WitnessScript::default()
            },
        );
        h.resources_respond();
        let mut daemon = stage14_10_daemon(h);
        crate::operator_log::capture_start();
        let result = pc1_attempt(&mut daemon, "pc1-holder");
        let warns = crate::operator_log::capture_take();
        let mut h = crate::daemon::stage14_9_support::into_runtime(daemon);
        let facts = pc1_facts(
            "negative control: peer holder",
            "Blocked before the gate",
            &[result.clone()],
            &warns,
            &mut h,
        );
        assert_eq!(result, PC1_BLOCKED);
        assert_eq!(facts.evaluations, 1);
        assert_eq!(facts.fence_actions, 0);
        assert_eq!(facts.incident, None, "the gate was never entered");
        assert_eq!(facts.kinds(), ["get_term"]);
        pc1_assert_no_lease_and_no_mutation(&facts, "peer holder");
    }

    /// PC-N01: every gate rejection stops before the lease.
    #[test]
    fn pc1_n01_gate_rejections_stop_before_the_lease() {
        // (a) No live loss episode at the gate: FencingUnavailable. The
        // evaluation still authorized (the detector is lost); the gate refuses.
        let mut h = pc1_harness(STAGE14_9_FENCE_OK, STAGE14_9_ISOLATED, 10);
        h.episode = None;
        let mut daemon = stage14_10_daemon(h);
        crate::operator_log::capture_start();
        let result = pc1_attempt(&mut daemon, "pc1-n01a");
        let warns = crate::operator_log::capture_take();
        let mut h = crate::daemon::stage14_9_support::into_runtime(daemon);
        let facts = pc1_facts(
            "PC-N01a no live episode",
            "Blocked at the gate (FencingUnavailable)",
            &[result.clone()],
            &warns,
            &mut h,
        );
        assert_eq!(result, PC1_BLOCKED);
        assert_eq!(facts.evaluations, 1, "the evaluation authorized");
        assert_eq!(facts.fence_actions, 0);
        assert_eq!(facts.incident, None);
        assert!(
            warns.iter().any(|l| l.contains("fencing unavailable")),
            "{warns:?}"
        );
        pc1_assert_no_lease_and_no_mutation(&facts, "N01a");

        // (b) B = none: the incident opens UNKNOWN(not-attempted) and blocks
        // (FencingRequired); nothing is fenced and nothing is leased.
        let h = pc1_from(stage14_9_none(), Pc1WitnessScript::default());
        h.resources_respond();
        let mut daemon = stage14_10_daemon(h);
        crate::operator_log::capture_start();
        let result = pc1_attempt(&mut daemon, "pc1-n01b");
        let warns = crate::operator_log::capture_take();
        let mut h = crate::daemon::stage14_9_support::into_runtime(daemon);
        let facts = pc1_facts(
            "PC-N01b backend none",
            "Blocked at the gate (FencingRequired)",
            &[result.clone()],
            &warns,
            &mut h,
        );
        assert_eq!(result, PC1_BLOCKED);
        assert_eq!(facts.incident, Some("UNKNOWN"));
        assert_eq!(facts.fence_actions, 0);
        assert!(
            warns.iter().any(|l| l.contains("fencing required")),
            "{warns:?}"
        );
        pc1_assert_no_lease_and_no_mutation(&facts, "N01b");
    }

    /// PC-N02: a fence action that fails or outlives its bound, with a
    /// verifier that therefore does not report isolation, never reaches the
    /// lease — in the attempt that ran the action or in the next one. (Rev 5
    /// §13/T4: the action's own outcome is recorded; CONFIRMED comes only from
    /// the verification, see the contract test below.)
    #[test]
    fn pc1_n02_a_failed_or_hung_fence_action_stops_before_the_lease() {
        for (case, fence, timeout) in [
            ("PC-N02a fence exits 3", PC1_FENCE_FAILS, 10),
            ("PC-N02b fence outlives its 1 s bound", PC1_FENCE_HANGS, 1),
        ] {
            let h = pc1_harness(fence, STAGE14_9_NOT_ISOLATED, timeout);
            let mut daemon = stage14_10_daemon(h);
            crate::operator_log::capture_start();
            let first = pc1_attempt(&mut daemon, "pc1-n02-1");
            daemon.tick().unwrap();
            let second = pc1_attempt(&mut daemon, "pc1-n02-2");
            let warns = crate::operator_log::capture_take();
            let mut h = crate::daemon::stage14_9_support::into_runtime(daemon);
            let facts = pc1_facts(
                case,
                "Blocked, Blocked: never CONFIRMED, never leased",
                &[first.clone(), second.clone()],
                &warns,
                &mut h,
            );
            assert_eq!((first, second), (PC1_BLOCKED, PC1_BLOCKED), "{case}");
            assert!(facts.fence_actions >= 1, "{case}: the real action ran");
            assert_ne!(facts.incident, Some("CONFIRMED"), "{case}");
            assert_eq!(facts.kinds(), ["get_term", "get_term"], "{case}");
            pc1_assert_no_lease_and_no_mutation(&facts, case);
        }
    }

    /// Contract characterization (Rev 5 §13.1 T4/T5, §16.6.5): the fence
    /// ACTION's outcome is recorded, not trusted. A failed action followed by
    /// a verification that reports `isolated` (the target IS isolated) is
    /// CONFIRMED and the next attempt promotes; it is the verification, never
    /// the action's exit status, that decides. This is the production
    /// behaviour the N02 cases above are built around.
    #[test]
    fn pc1_contract_the_verifier_not_the_action_exit_decides_confirmation() {
        let h = pc1_harness(PC1_FENCE_FAILS, STAGE14_9_ISOLATED, 10);
        let mut daemon = stage14_10_daemon(h);
        pc1_confirm(&mut daemon);
        crate::operator_log::capture_start();
        let result = pc1_attempt(&mut daemon, "pc1-contract");
        let warns = crate::operator_log::capture_take();
        let mut h = crate::daemon::stage14_9_support::into_runtime(daemon);
        let facts = pc1_facts(
            "contract: failed action, verified isolated",
            "CONFIRMED by the verifier, then Succeeded",
            &[result.clone()],
            &warns,
            &mut h,
        );
        assert_eq!(
            result,
            crate::promotion_attempt::PromotionAttemptResult::Succeeded
        );
        assert_eq!(facts.fence_actions, 1);
        assert_eq!(facts.verify_polls, 1);
        assert_eq!(facts.lease_requests(), 1);
    }

    /// PC-N03: a verifier that reports not-isolated never yields a clearance:
    /// the incident is FAILED, the next attempt re-requests the action and
    /// blocks again, and no lease is ever requested.
    #[test]
    fn pc1_n03_an_unconfirmed_fence_never_yields_a_clearance() {
        let h = pc1_harness(STAGE14_9_FENCE_OK, STAGE14_9_NOT_ISOLATED, 10);
        let mut daemon = stage14_10_daemon(h);
        crate::operator_log::capture_start();
        let first = pc1_attempt(&mut daemon, "pc1-n03-1");
        daemon.tick().unwrap();
        assert_eq!(
            stage14_9_incident(&stage14_10_harness(&mut daemon).f)
                .unwrap()
                .state
                .operator_name(),
            "FAILED",
            "the real verify poll said not-isolated"
        );
        let second = pc1_attempt(&mut daemon, "pc1-n03-2");
        let warns = crate::operator_log::capture_take();
        let mut h = crate::daemon::stage14_9_support::into_runtime(daemon);
        let facts = pc1_facts(
            "PC-N03 not-isolated",
            "Blocked, Blocked: FAILED, never leased",
            &[first.clone(), second.clone()],
            &warns,
            &mut h,
        );
        assert_eq!((first, second), (PC1_BLOCKED, PC1_BLOCKED));
        assert!(facts.verify_polls >= 1);
        assert_ne!(facts.incident, Some("CONFIRMED"));
        assert_eq!(facts.kinds(), ["get_term", "get_term"]);
        pc1_assert_no_lease_and_no_mutation(&facts, "N03");
    }

    /// PC-N04: the K recheck fails after the grant (the peer's loss episode
    /// ended between the gate and the ARM): no ARM, no resource mutation, no
    /// promotion; the lease is cleaned up through the atomic §25.1 cleanup and
    /// the exact Release.
    #[test]
    fn pc1_n04_a_failed_final_recheck_never_promotes() {
        let h = pc1_harness(STAGE14_9_FENCE_OK, STAGE14_9_ISOLATED, 10);
        let mut daemon = stage14_10_daemon(h);
        pc1_confirm(&mut daemon);
        stage14_10_race_after_grant(&mut daemon, |daemon| {
            stage14_10_harness(daemon).episode = None;
        });
        crate::operator_log::capture_start();
        let result = pc1_attempt(&mut daemon, "pc1-n04");
        let warns = crate::operator_log::capture_take();
        let mut h = crate::daemon::stage14_9_support::into_runtime(daemon);
        assert_eq!(h.rechecks.len(), 1, "the production K recheck ran once");
        assert!(
            h.rechecks[0].as_ref().is_err_and(|e| e.contains("Episode")),
            "{:?}",
            h.rechecks
        );
        assert_eq!(h.cleanups, [Ok(crate::daemon::AttemptCleanup::Released)]);
        let facts = pc1_facts(
            "PC-N04 final recheck fails",
            "BlockedBeforeMutation after the grant, exact Release",
            &[result.clone()],
            &warns,
            &mut h,
        );
        assert_eq!(result, PC1_BLOCKED);
        assert_eq!(
            facts.witness,
            [
                ("get_term", Term(7)),
                ("get_term", Term(7)),
                ("request", Term(8)),
                ("release", Term(8))
            ]
        );
        assert!(facts.mutations.is_empty(), "no resource mutation");
        assert_eq!(facts.incident, None, "the §25.1 cleanup retired it");
        assert_eq!(facts.image.release_obligation, None, "O cleared by Release");
        assert_eq!(facts.node, NodeState::Standby);
        assert!(
            warns.iter().any(|l| l.contains("final recheck failed")),
            "{warns:?}"
        );
    }

    /// PC-N05: the authority observation is expired when it is evaluated: the
    /// Witness-evidence bound is `WITNESS_EVIDENCE_TIMEOUT` (5 s, inclusive).
    /// One second inside the bound the attempt reaches the gate; one second
    /// past it the evaluation does not authorize, so the attempt stops before
    /// the fencing gate (no incident, no fence action, no lease).
    #[test]
    fn pc1_n05_an_expired_authority_observation_never_reaches_the_gate() {
        let bound = crate::evidence_fusion::WITNESS_EVIDENCE_TIMEOUT;
        // Control: inside the bound the very same attempt is evaluated as
        // authorized and reaches the gate (it blocks there, in progress).
        let mut h = pc1_harness(STAGE14_9_FENCE_OK, STAGE14_9_ISOLATED, 10);
        h.pc1.as_mut().unwrap().evaluation_skew = bound - Duration::from_secs(1);
        let mut daemon = stage14_10_daemon(h);
        let result = pc1_attempt(&mut daemon, "pc1-n05-inside");
        let mut h = crate::daemon::stage14_9_support::into_runtime(daemon);
        let facts = pc1_facts(
            "PC-N05 control: observation 4 s old",
            "evaluated authorized, reaches the gate",
            &[result.clone()],
            &[],
            &mut h,
        );
        assert_eq!(result, PC1_BLOCKED);
        assert_eq!(facts.fence_actions, 1, "the gate was entered");
        assert_eq!(facts.incident, Some("VERIFYING"));

        // Expired: 6 s old.
        let mut h = pc1_harness(STAGE14_9_FENCE_OK, STAGE14_9_ISOLATED, 10);
        h.pc1.as_mut().unwrap().evaluation_skew = bound + Duration::from_secs(1);
        let mut daemon = stage14_10_daemon(h);
        crate::operator_log::capture_start();
        let result = pc1_attempt(&mut daemon, "pc1-n05-expired");
        let warns = crate::operator_log::capture_take();
        let mut h = crate::daemon::stage14_9_support::into_runtime(daemon);
        let facts = pc1_facts(
            "PC-N05 expired observation (6 s old)",
            "Blocked before the gate",
            &[result.clone()],
            &warns,
            &mut h,
        );
        assert_eq!(result, PC1_BLOCKED);
        assert_eq!(facts.evaluations, 1);
        assert_eq!(facts.fence_actions, 0, "the gate was never entered");
        assert_eq!(facts.incident, None);
        pc1_assert_no_lease_and_no_mutation(&facts, "N05");
    }

    /// PC-N06: a GET_TERM that times out is completed as `Unavailable`; the
    /// attempt's one evaluation reports it (`no fresh authority observation`)
    /// and never authorizes, so the gate, the fence action and the lease are
    /// never reached, and a second attempt never reuses the first attempt's
    /// observation.
    #[test]
    fn pc1_n06_a_get_term_timeout_never_reaches_fencing() {
        // (a) Silent from the first attempt.
        let h = pc1_with(
            STAGE14_9_FENCE_OK,
            STAGE14_9_ISOLATED,
            10,
            Pc1WitnessScript {
                terms: VecDeque::from([Pc1TermReply::Silent]),
                ..Pc1WitnessScript::default()
            },
        );
        let mut daemon = stage14_10_daemon(h);
        let started = std::time::Instant::now();
        crate::operator_log::capture_start();
        let result = pc1_attempt(&mut daemon, "pc1-n06a");
        let warns = crate::operator_log::capture_take();
        let elapsed = started.elapsed();
        let mut h = crate::daemon::stage14_9_support::into_runtime(daemon);
        assert!(!h.session.as_ref().unwrap().request_in_flight());
        let facts = pc1_facts(
            "PC-N06a silent Witness",
            "Blocked at the 2 s deadline, one request, no retry",
            &[result.clone()],
            &warns,
            &mut h,
        );
        assert_eq!(result, PC1_BLOCKED);
        assert!(
            elapsed >= Duration::from_secs(2) && elapsed < Duration::from_secs(3),
            "{elapsed:?}"
        );
        assert_eq!(facts.kinds(), ["get_term"], "one request, no retry");
        assert_eq!(facts.evaluations, 1, "the evaluation reported Unavailable");
        assert!(
            warns
                .iter()
                .any(|l| l.contains("no fresh authority observation")),
            "{warns:?}"
        );
        assert_eq!(facts.fence_actions, 0);
        assert_eq!(facts.incident, None);
        pc1_assert_no_lease_and_no_mutation(&facts, "N06a");

        // (b) A successful attempt, then a silent one: the second must not
        // evaluate (or fence on) the first attempt's observation.
        let h = pc1_with(
            STAGE14_9_FENCE_OK,
            STAGE14_9_ISOLATED,
            10,
            Pc1WitnessScript {
                terms: VecDeque::from([Pc1TermReply::NoHolder, Pc1TermReply::Silent]),
                ..Pc1WitnessScript::default()
            },
        );
        let mut daemon = stage14_10_daemon(h);
        crate::operator_log::capture_start();
        let first = pc1_attempt(&mut daemon, "pc1-n06b-1");
        let second = pc1_attempt(&mut daemon, "pc1-n06b-2");
        let warns = crate::operator_log::capture_take();
        let mut h = crate::daemon::stage14_9_support::into_runtime(daemon);
        let facts = pc1_facts(
            "PC-N06b stale observation not reused",
            "Blocked (gate), Blocked (timeout: its evaluation reports Unavailable)",
            &[first.clone(), second.clone()],
            &warns,
            &mut h,
        );
        assert_eq!((first, second), (PC1_BLOCKED, PC1_BLOCKED));
        assert_eq!(facts.kinds(), ["get_term", "get_term"]);
        assert_eq!(facts.evaluations, 2);
        assert!(
            warns
                .iter()
                .any(|l| l.contains("no fresh authority observation")),
            "the second attempt saw its own timeout, not the first's evidence: {warns:?}"
        );
        assert_eq!(facts.fence_actions, 1, "the second never reached the gate");
        pc1_assert_no_lease_and_no_mutation(&facts, "N06b");
    }

    /// PC-N07: a shutdown requested at any stage performs no later mutation.
    #[test]
    fn pc1_n07_shutdown_stops_every_later_mutation() {
        // (a) While the step waits for a silent Witness. The live shutdown
        // signal is counted, not timed: it reads false until the step has read
        // it five times (before the request and at the top of three wait
        // slices) and true from then on, so the shutdown arrives mid-wait
        // whatever the scheduler does. The request stays pending: a timeout
        // would have completed it as Unavailable.
        let h = pc1_with(
            STAGE14_9_FENCE_OK,
            STAGE14_9_ISOLATED,
            10,
            Pc1WitnessScript {
                terms: VecDeque::from([Pc1TermReply::Silent]),
                ..Pc1WitnessScript::default()
            },
        );
        let mut daemon = stage14_10_daemon(h);
        let reads = Rc::new(Cell::new(0_u32));
        let counter = reads.clone();
        daemon.attach_shutdown_signal(move || {
            counter.set(counter.get() + 1);
            counter.get() > 4
        });
        let result = pc1_attempt(&mut daemon, "pc1-n07a");
        let mut h = crate::daemon::stage14_9_support::into_runtime(daemon);
        let snapshot = h.pc1.as_ref().unwrap().observer.snapshot();
        let facts = pc1_facts(
            "PC-N07a shutdown while waiting",
            "Blocked within a few slices, request still pending (not timed out)",
            &[result.clone()],
            &[],
            &mut h,
        );
        assert_eq!(result, PC1_BLOCKED);
        assert!(reads.get() >= 5, "the signal was read while waiting");
        assert!(snapshot.pending.is_some(), "interrupted, not timed out");
        assert!(snapshot.last_completion.is_none());
        assert_eq!(facts.evaluations, 0);
        assert_eq!(facts.fence_actions, 0);
        assert_eq!(facts.incident, None);
        pc1_assert_no_lease_and_no_mutation(&facts, "N07a");

        // (b) After the evaluation authorized, before the gate.
        let h = pc1_harness(STAGE14_9_FENCE_OK, STAGE14_9_ISOLATED, 10);
        let mut daemon = stage14_10_daemon(h);
        daemon.push_promotion_attempt_test_hook(|daemon| daemon.request_shutdown().unwrap());
        crate::operator_log::capture_start();
        let result = pc1_attempt(&mut daemon, "pc1-n07b");
        let warns = crate::operator_log::capture_take();
        let mut h = crate::daemon::stage14_9_support::into_runtime(daemon);
        let facts = pc1_facts(
            "PC-N07b shutdown after evaluation",
            "Blocked before the gate",
            &[result.clone()],
            &warns,
            &mut h,
        );
        assert_eq!(result, PC1_BLOCKED);
        assert_eq!(facts.evaluations, 1);
        assert_eq!(facts.fence_actions, 0, "no fence action after shutdown");
        assert_eq!(facts.incident, None);
        assert!(warns.iter().any(|l| l.contains("shutdown requested")));
        pc1_assert_no_lease_and_no_mutation(&facts, "N07b");

        // (c) After the grant, before the K recheck: the exact Release, no ARM.
        let h = pc1_harness(STAGE14_9_FENCE_OK, STAGE14_9_ISOLATED, 10);
        let mut daemon = stage14_10_daemon(h);
        pc1_confirm(&mut daemon);
        stage14_10_race_after_grant(&mut daemon, |daemon| daemon.request_shutdown().unwrap());
        crate::operator_log::capture_start();
        let result = pc1_attempt(&mut daemon, "pc1-n07c");
        let warns = crate::operator_log::capture_take();
        let mut h = crate::daemon::stage14_9_support::into_runtime(daemon);
        assert!(h.rechecks.is_empty(), "shutdown short-circuits the recheck");
        let facts = pc1_facts(
            "PC-N07c shutdown after the grant",
            "Blocked, exact Release, no ARM",
            &[result.clone()],
            &warns,
            &mut h,
        );
        assert_eq!(result, PC1_BLOCKED);
        assert_eq!(facts.lease_requests(), 1);
        assert_eq!(facts.releases(), 1);
        assert!(facts.mutations.is_empty());
        assert_eq!(facts.image.release_obligation, None);
        assert_eq!(facts.node, NodeState::Standby);

        // (c2) The live shutdown signal rises after the grant while the daemon
        // is still Running (the process latch, not a requested shutdown): the
        // K check reads it live, so it blocks before the recheck all the same.
        let h = pc1_harness(STAGE14_9_FENCE_OK, STAGE14_9_ISOLATED, 10);
        let mut daemon = stage14_10_daemon(h);
        pc1_confirm(&mut daemon);
        stage14_10_race_after_grant(&mut daemon, |daemon| {
            daemon.attach_shutdown_signal(|| true);
        });
        let result = pc1_attempt(&mut daemon, "pc1-n07c2");
        let mut h = crate::daemon::stage14_9_support::into_runtime(daemon);
        assert!(
            h.rechecks.is_empty(),
            "the live signal short-circuits the recheck"
        );
        let facts = pc1_facts(
            "PC-N07c2 live shutdown signal after the grant, daemon Running",
            "Blocked, exact Release, no ARM",
            &[result.clone()],
            &[],
            &mut h,
        );
        assert_eq!(result, PC1_BLOCKED);
        assert_eq!(facts.lease_requests(), 1);
        assert_eq!(facts.releases(), 1);
        assert!(facts.mutations.is_empty());
        assert_eq!(facts.image.release_obligation, None);
        assert_eq!(facts.node, NodeState::Standby);

        // (d) Requested before the attempt: rejected, nothing at all runs.
        let h = pc1_harness(STAGE14_9_FENCE_OK, STAGE14_9_ISOLATED, 10);
        let mut daemon = stage14_10_daemon(h);
        daemon.request_shutdown().unwrap();
        let result = pc1_attempt(&mut daemon, "pc1-n07d");
        let mut h = crate::daemon::stage14_9_support::into_runtime(daemon);
        let facts = pc1_facts(
            "PC-N07d shutdown before the attempt",
            "Rejected, nothing runs",
            &[result.clone()],
            &[],
            &mut h,
        );
        assert!(matches!(
            result,
            crate::promotion_attempt::PromotionAttemptResult::Rejected(_)
        ));
        assert_eq!(facts.steps, 0);
        assert!(facts.witness.is_empty(), "not even a GET_TERM");
        assert_eq!(facts.fence_actions, 0);
        pc1_assert_no_lease_and_no_mutation(&facts, "N07d");
    }

    /// PC-N08: the peer changes after fencing completed. The attempt
    /// re-evaluates under the existing contract: a returned peer is not
    /// authorized (no gate, no lease, the stale CONFIRMED stays unconsumed);
    /// a peer lost again (new episode) retires the stale incident at the gate,
    /// opens a new one, and fences again — never reusing the old clearance.
    #[test]
    fn pc1_n08_a_peer_that_changes_after_fencing_is_reevaluated() {
        // (a) The peer returned: authenticated contact makes it Healthy.
        let h = pc1_harness(STAGE14_9_FENCE_OK, STAGE14_9_ISOLATED, 10);
        let mut daemon = stage14_10_daemon(h);
        pc1_confirm(&mut daemon);
        {
            let h = stage14_10_harness(&mut daemon);
            h.episode = None;
            let detector = &mut h.pc1.as_mut().unwrap().detector;
            let now = std::time::Instant::now();
            let session = SessionId::new("peer-session-returned");
            detector
                .observe_session_established(session.clone(), now)
                .unwrap();
            detector
                .observe_trusted_heartbeat(&session, Sequence(1), now)
                .unwrap();
            assert_ne!(
                detector.assessment(),
                crate::failure_assessment::PeerFailureAssessment::CommunicationLost
            );
        }
        crate::operator_log::capture_start();
        let result = pc1_attempt(&mut daemon, "pc1-n08a");
        let warns = crate::operator_log::capture_take();
        let mut h = crate::daemon::stage14_9_support::into_runtime(daemon);
        let facts = pc1_facts(
            "PC-N08a peer returned after fencing",
            "Blocked before the gate; CONFIRMED left unconsumed",
            &[result.clone()],
            &warns,
            &mut h,
        );
        assert_eq!(result, PC1_BLOCKED);
        assert_eq!(facts.kinds(), ["get_term", "get_term"]);
        assert_eq!(facts.fence_actions, 1, "no second fence action");
        assert_eq!(facts.incident, Some("CONFIRMED"), "unconsumed, unused");
        pc1_assert_no_lease_and_no_mutation(&facts, "N08a");

        // (b) The peer returned and was lost again: a new episode.
        let h = pc1_harness(STAGE14_9_FENCE_OK, STAGE14_9_ISOLATED, 10);
        let mut daemon = stage14_10_daemon(h);
        pc1_confirm(&mut daemon);
        stage14_10_harness(&mut daemon)
            .pc1
            .as_mut()
            .unwrap()
            .detector = pc1_detector(2);
        crate::operator_log::capture_start();
        let result = pc1_attempt(&mut daemon, "pc1-n08b");
        let warns = crate::operator_log::capture_take();
        let mut h = crate::daemon::stage14_9_support::into_runtime(daemon);
        let facts = pc1_facts(
            "PC-N08b new loss episode after fencing",
            "Blocked at the gate: stale incident retired, fenced again",
            &[result.clone()],
            &warns,
            &mut h,
        );
        assert_eq!(result, PC1_BLOCKED);
        assert_eq!(facts.evaluations, 2);
        assert_eq!(facts.fence_actions, 2, "the new episode is fenced again");
        assert_eq!(facts.image.highest_fencing_incident_seq, 2);
        assert_ne!(facts.incident, Some("CONFIRMED"), "no clearance was reused");
        assert_eq!(facts.kinds(), ["get_term", "get_term"]);
        pc1_assert_no_lease_and_no_mutation(&facts, "N08b");
    }

    /// PC-N09: a lease that is not granted never makes the node Active.
    #[test]
    fn pc1_n09_a_lease_that_is_not_granted_never_activates() {
        for (case, lease) in [
            ("PC-N09a LeaseReject", Pc1LeaseReply::Reject),
            (
                "PC-N09b Witness hangs up on the LeaseRequest",
                Pc1LeaseReply::Hangup,
            ),
        ] {
            let h = pc1_with(
                STAGE14_9_FENCE_OK,
                STAGE14_9_ISOLATED,
                10,
                Pc1WitnessScript {
                    lease,
                    ..Pc1WitnessScript::default()
                },
            );
            let mut daemon = stage14_10_daemon(h);
            pc1_confirm(&mut daemon);
            crate::operator_log::capture_start();
            let result = pc1_attempt(&mut daemon, "pc1-n09");
            let warns = crate::operator_log::capture_take();
            let mut h = crate::daemon::stage14_9_support::into_runtime(daemon);
            assert!(h.rechecks.is_empty(), "{case}: K is never reached");
            let facts = pc1_facts(
                case,
                "Blocked at H: no grant, no K, no ARM, no promotion",
                &[result.clone()],
                &warns,
                &mut h,
            );
            assert_eq!(result, PC1_BLOCKED, "{case}");
            assert_eq!(facts.lease_requests(), 1, "{case}: exactly one request");
            assert!(facts.mutations.is_empty(), "{case}");
            assert_eq!(facts.image.release_obligation, None, "{case}: no O");
            assert_eq!(facts.node, NodeState::Standby, "{case}");
            assert_eq!(
                facts.incident,
                Some("CONFIRMED"),
                "{case}: the incident was not consumed by a failed lease"
            );
            assert!(
                warns.iter().any(|l| l.contains("lease not granted")),
                "{case}: {warns:?}"
            );
        }
    }

    /// PC-N10: a further SIGUSR1 never bypasses a safety condition: an attempt
    /// immediately after the one that ran the fence action (no verify yet)
    /// finds the incident in progress, runs no second action and requests no
    /// lease; and a request made while an attempt is in flight is rejected
    /// without a GET_TERM of its own.
    #[test]
    fn pc1_n10_an_extra_sigusr1_cannot_bypass_the_attempt() {
        // (a) Back-to-back attempts with no verify tick between them.
        let h = pc1_harness(STAGE14_9_FENCE_OK, STAGE14_9_ISOLATED, 10);
        let mut daemon = stage14_10_daemon(h);
        crate::operator_log::capture_start();
        let first = pc1_attempt(&mut daemon, "pc1-n10a-1");
        let second = pc1_attempt(&mut daemon, "pc1-n10a-2");
        let warns = crate::operator_log::capture_take();
        let mut h = crate::daemon::stage14_9_support::into_runtime(daemon);
        let facts = pc1_facts(
            "PC-N10a back-to-back SIGUSR1",
            "Blocked, Blocked: one fence action, no lease",
            &[first.clone(), second.clone()],
            &warns,
            &mut h,
        );
        assert_eq!((first, second), (PC1_BLOCKED, PC1_BLOCKED));
        assert_eq!(facts.get_terms(), 2, "each attempt observed for itself");
        assert_eq!(facts.fence_actions, 1, "no second fence action");
        assert_ne!(facts.incident, Some("CONFIRMED"));
        pc1_assert_no_lease_and_no_mutation(&facts, "N10a");

        // (b) A request while an attempt is in flight.
        let h = pc1_harness(STAGE14_9_FENCE_OK, STAGE14_9_ISOLATED, 10);
        let mut daemon = stage14_10_daemon(h);
        pc1_confirm(&mut daemon);
        let inner = std::rc::Rc::new(RefCell::new(None));
        let sink = inner.clone();
        daemon.push_promotion_attempt_test_hook(move |daemon| {
            *sink.borrow_mut() = Some(pc1_attempt(daemon, "pc1-n10b-second"));
        });
        let outer = pc1_attempt(&mut daemon, "pc1-n10b-first");
        let rejected = inner.borrow_mut().take().unwrap();
        let mut h = crate::daemon::stage14_9_support::into_runtime(daemon);
        let facts = pc1_facts(
            "PC-N10b request during an in-flight attempt",
            "the second is Rejected, the first still reaches Succeeded",
            &[outer.clone(), rejected.clone()],
            &[],
            &mut h,
        );
        assert_eq!(
            rejected,
            crate::promotion_attempt::PromotionAttemptResult::Rejected(
                crate::promotion_attempt::PromotionAttemptRejection::AlreadyInProgress
            )
        );
        assert_eq!(
            outer,
            crate::promotion_attempt::PromotionAttemptResult::Succeeded
        );
        assert_eq!(
            facts.get_terms(),
            2,
            "prime + first; the rejected one issued none"
        );
        assert_eq!(
            facts.lease_requests(),
            1,
            "exactly one lease for two requests"
        );
    }

    /// PC-N11: the clearance and the grant are tied to the attempt's FRESH
    /// observation. (a) A clearance anchored at a term other than the term this
    /// attempt's own GET_TERM reported requests no lease. (b) A grant that is
    /// not exactly anchor + 1 is a post-grant, pre-resource abort: no K, no
    /// ARM, no resource mutation; the §25.1 cleanup and the exact Release.
    #[test]
    fn pc1_n11_clearance_anchor_and_grant_term_are_tied_to_the_fresh_observation() {
        // (a) CONFIRMED at anchor 6 (view 6 at the gate), GET_TERM says 7.
        let mut h = pc1_harness(STAGE14_9_FENCE_OK, STAGE14_9_ISOLATED, 10);
        stage14_10_confirmed_by_attestation(&h.f.fixture.parts.runtime, Term(6));
        h.gate_view = Some(Term(6));
        let mut daemon = stage14_10_daemon(h);
        crate::operator_log::capture_start();
        let result = pc1_attempt(&mut daemon, "pc1-n11a");
        let warns = crate::operator_log::capture_take();
        let mut h = crate::daemon::stage14_9_support::into_runtime(daemon);
        let facts = pc1_facts(
            "PC-N11a clearance anchor != fresh term",
            "Blocked before the LeaseRequest",
            &[result.clone()],
            &warns,
            &mut h,
        );
        assert_eq!(result, PC1_BLOCKED);
        assert_eq!(facts.kinds(), ["get_term"]);
        assert!(
            warns
                .iter()
                .any(|l| l.contains("clearance anchor differs from the fresh Witness term")),
            "{warns:?}"
        );
        assert_eq!(facts.incident, Some("CONFIRMED"), "not consumed");
        pc1_assert_no_lease_and_no_mutation(&facts, "N11a");

        // (b) The Witness grants at 9, the anchor is 7: not anchor + 1.
        let h = pc1_from_grant(
            stage14_9_command(STAGE14_9_FENCE_OK, STAGE14_9_ISOLATED, 10, 10, 3),
            Pc1WitnessScript::default(),
            Term(9),
        );
        h.resources_respond();
        let mut daemon = stage14_10_daemon(h);
        pc1_confirm(&mut daemon);
        crate::operator_log::capture_start();
        let result = pc1_attempt(&mut daemon, "pc1-n11b");
        let warns = crate::operator_log::capture_take();
        let mut h = crate::daemon::stage14_9_support::into_runtime(daemon);
        assert!(h.rechecks.is_empty(), "I fails before K");
        let facts = pc1_facts(
            "PC-N11b grant term != anchor + 1",
            "Blocked after the grant, atomic cleanup, exact Release",
            &[result.clone()],
            &warns,
            &mut h,
        );
        assert_eq!(result, PC1_BLOCKED);
        assert_eq!(
            facts.witness,
            [
                ("get_term", Term(7)),
                ("get_term", Term(7)),
                ("request", Term(9)),
                ("release", Term(9)),
            ]
        );
        assert!(facts.mutations.is_empty(), "no resource mutation");
        assert_eq!(facts.incident, None, "the §25.1 cleanup retired it");
        assert_eq!(facts.image.release_obligation, None);
        assert_eq!(facts.node, NodeState::Standby);
        assert!(
            warns
                .iter()
                .any(|l| l.contains("grant term is not the clearance anchor + 1")),
            "{warns:?}"
        );
    }

    // --- J18-B: SessionClosed remediation candidate (option A) -------------
    //
    // v0.6 reports a clean EOF, and every operation after a latched loss, as
    // `SessionClosed`. These tests drive the production foreground lifecycle
    // against a real authenticated Witness peer that loses the session in
    // four ways, and check the lease timeline: the node keeps the exact M,
    // sends nothing more on the lost session, and demotes exactly at the
    // local safe deadline, which is at least the 2000 ms margin before the
    // Witness-side expiry of the last grant it holds.
    mod j18_session_closed_candidate {
        use super::*;
        use crate::security::{MessageAuthenticator, Psk};
        use crate::session::ProcessSession;
        use crate::tcp::TcpConnection;
        use crate::witness_runtime::{
            WitnessConnection, WitnessResponseContext, send_witness_response_with_context,
        };
        use std::io::Write;
        use std::net::{Shutdown, TcpListener, TcpStream};
        use std::os::fd::AsRawFd;
        use std::sync::Arc;
        use std::sync::atomic::AtomicUsize;
        use std::thread;
        use std::time::Duration;

        const LEASE_REMAINING_MS: u64 = 10_000;
        const RENEW_AFTER_MS: u64 = 3_000;
        /// The v0.6 contract (C-3), written out rather than imported so that
        /// a weakened `SAFETY_MARGIN_MS` fails these tests.
        const REQUIRED_MARGIN_MS: u64 = 2_000;

        #[derive(Clone, Copy, Debug, PartialEq)]
        enum Loss {
            /// The Witness shuts its write side: the node reads a clean EOF.
            CleanEof,
            /// The Witness aborts with SO_LINGER 0: the node reads a reset.
            Reset,
            /// The Witness writes half a length prefix, then EOF.
            Truncated,
            /// The Witness reads the Renew and never answers (outcome UNKNOWN).
            ReadThenClose,
        }

        struct Tick {
            at_ms: u64,
            active: bool,
            lost: bool,
        }

        struct Run {
            trace: Vec<Tick>,
            served: usize,
            session: Option<WitnessSession>,
            parts: TestRuntimeParts,
            /// Returns the requests the Witness received after it failed the
            /// session (`None` after a reset: the Witness socket is gone).
            server: Option<thread::JoinHandle<Option<usize>>>,
        }

        fn set_abortive_close(stream: &TcpStream) {
            let linger = libc::linger {
                l_onoff: 1,
                l_linger: 0,
            };
            let rc = unsafe {
                libc::setsockopt(
                    stream.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_LINGER,
                    (&linger as *const libc::linger).cast(),
                    std::mem::size_of::<libc::linger>() as libc::socklen_t,
                )
            };
            assert_eq!(rc, 0, "SO_LINGER");
        }

        /// The Witness serves `rounds` LeaseRenew requests (each grant gives
        /// `LEASE_REMAINING_MS`), then loses the session as `loss` says, then
        /// counts any further request until the node closes its end.
        fn run(loss: Loss, rounds: usize, iterations: usize) -> Run {
            let clock = Rc::new(Cell::new(0u64));
            let mut parts = stage14_11_l1_active_parts(&clock);
            parts
                .runtime
                .mutation_store
                .arm_release_obligation(Term(7), LeaseId::new("lease-1"))
                .unwrap();

            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (server, _) = listener.accept().unwrap();
            let raw = server.try_clone().unwrap();
            let node = WitnessConnection::new(
                NodeId::new("node-a"),
                NodeId::new("witness"),
                ClusterId::new("cluster"),
                SessionId::new("session-w"),
                TcpConnection::from_stream(client, Duration::from_secs(2), Duration::from_secs(2))
                    .unwrap(),
            );
            let mut witness = WitnessConnection::new(
                NodeId::new("witness"),
                NodeId::new("node-a"),
                ClusterId::new("cluster"),
                SessionId::new("session-a"),
                TcpConnection::from_stream(server, Duration::from_secs(5), Duration::from_secs(5))
                    .unwrap(),
            );
            let served = Arc::new(AtomicUsize::new(0));
            let served_in_thread = served.clone();
            let server = thread::spawn(move || -> Option<usize> {
                let auth = MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32]));
                let mut process = ProcessSession::from_session_id(SessionId::new("session-w"));
                for _ in 0..rounds {
                    let pending = witness.receive_pending(&CborSerializer, &auth).ok()?;
                    let request_id = pending
                        .message()
                        .unsigned()
                        .common
                        .request_id
                        .clone()
                        .unwrap();
                    send_witness_response_with_context(
                        &mut witness,
                        &mut process,
                        request_id,
                        ProtocolMessage::LeaseRenewed(LeaseGrantPayload {
                            term: Term(7),
                            lease_id: LeaseId::new("lease-1"),
                            holder_node_id: NodeId::new("node-a"),
                            lease_ttl_ms: DurationMs(10_000),
                            renew_after_ms: DurationMs(RENEW_AFTER_MS),
                            lease_remaining_ms: DurationMs(LEASE_REMAINING_MS),
                        }),
                        WitnessResponseContext {
                            term: Term(7),
                            lease_id: Some(LeaseId::new("lease-1")),
                        },
                        &CborSerializer,
                        &auth,
                    )
                    .unwrap();
                    served_in_thread.fetch_add(1, Ordering::SeqCst);
                }
                match loss {
                    Loss::CleanEof => raw.shutdown(Shutdown::Write).unwrap(),
                    Loss::Reset => {
                        set_abortive_close(&raw);
                        drop(witness);
                        drop(raw);
                        return None;
                    }
                    Loss::Truncated => {
                        (&raw).write_all(&[0x00, 0x00]).unwrap();
                        raw.shutdown(Shutdown::Write).unwrap();
                    }
                    Loss::ReadThenClose => {
                        // The Renew reaches the Witness; its outcome is never
                        // reported to the node.
                        witness.receive_pending(&CborSerializer, &auth).ok()?;
                        raw.shutdown(Shutdown::Write).unwrap();
                    }
                }
                let mut after = 0;
                while witness.receive_pending(&CborSerializer, &auth).is_ok() {
                    after += 1;
                }
                Some(after)
            });
            let mut session = WitnessSession::new(
                node,
                ProcessSession::from_session_id(SessionId::new("session-a")),
                MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32])),
            );
            let mut trace = Vec::new();
            for _ in 0..iterations {
                let at = clock.get();
                parts
                    .runtime
                    .drive_foreground_lifecycle(&mut session, &|| false, &|| true)
                    .unwrap();
                let delay = parts
                    .runtime
                    .active_schedule_delay(ms(1_000))
                    .unwrap()
                    .as_millis() as u64;
                let active = parts.runtime.state_machine.node_state() == NodeState::Active
                    && parts.runtime.state_machine.operation_phase().is_none();
                trace.push(Tick {
                    at_ms: at,
                    active,
                    lost: session.lost(),
                });
                clock.set(at + delay);
                if !active {
                    break;
                }
            }
            Run {
                trace,
                served: served.load(Ordering::SeqCst),
                session: Some(session),
                parts,
                server: Some(server),
            }
        }

        /// Close the node end, so the Witness thread stops counting, and
        /// return its count.
        fn finish(run: &mut Run) -> Option<usize> {
            drop(run.session.take());
            run.server.take().unwrap().join().unwrap()
        }

        /// The timeline property. `origin_ms` is the controller time at which
        /// the last accepted grant's request was sent (the node's deadline
        /// origin); the Witness measured the same grant from a later instant,
        /// so its expiry is at least `origin_ms + LEASE_REMAINING_MS`.
        fn assert_timeline(run: &Run, after_loss: Option<usize>, origin_ms: u64, label: &str) {
            let local_deadline = origin_ms + LEASE_REMAINING_MS - REQUIRED_MARGIN_MS;
            let witness_expiry_lower_bound = origin_ms + LEASE_REMAINING_MS;
            let last = run.trace.last().unwrap();
            println!(
                "J18B {label}: origin={origin_ms} demoted_at={} local_deadline={local_deadline} \
                 witness_expiry>={witness_expiry_lower_bound} served={} after_loss={:?} ticks={}",
                last.at_ms,
                run.served,
                after_loss,
                run.trace.len()
            );
            for tick in &run.trace[..run.trace.len() - 1] {
                assert!(tick.active, "{label}: demoted early at {}", tick.at_ms);
                assert!(
                    tick.at_ms < local_deadline,
                    "{label}: Active at {}",
                    tick.at_ms
                );
            }
            assert!(!last.active, "{label}: never demoted");
            assert_eq!(last.at_ms, local_deadline, "{label}: demotion tick");
            assert!(
                last.at_ms + REQUIRED_MARGIN_MS <= witness_expiry_lower_bound,
                "{label}: demotion is not before the Witness expiry by the margin"
            );
            assert!(
                !run.parts.runtime.controller.resource_owning(),
                "{label}: resources still owned after the demotion"
            );
            assert!(
                run.trace.iter().any(|tick| tick.lost),
                "{label}: the session loss was never latched"
            );
            // The latch never clears: the session is never usable again.
            let first_lost = run.trace.iter().position(|tick| tick.lost).unwrap();
            assert!(
                run.trace[first_lost..].iter().all(|tick| tick.lost),
                "{label}: the lost latch cleared"
            );
            // The old grant can authorize no further conservative step.
            assert!(
                run.parts.runtime.controller.authority().demotion_latched(),
                "{label}: the old authority is still usable after the demotion"
            );
        }

        fn check(loss: Loss, rounds: usize, origin_ms: u64, max_after: usize) {
            let label = format!("{loss:?}/rounds={rounds}");
            let mut run = run(loss, rounds, 40);
            let after_loss = finish(&mut run);
            assert_eq!(run.served, rounds, "{label}: grants served");
            assert_timeline(&run, after_loss, origin_ms, &label);
            if loss != Loss::Reset {
                let after = after_loss.expect("the Witness kept counting");
                assert!(
                    after <= max_after,
                    "{label}: {after} requests after the loss (max {max_after})"
                );
            }
            cleanup_test_path(&run.parts.path);
        }

        #[test]
        fn j18b_clean_eof_retains_m_and_demotes_at_the_deadline() {
            check(Loss::CleanEof, 0, 0, 1);
            check(Loss::CleanEof, 1, RENEW_AFTER_MS, 1);
        }

        #[test]
        fn j18b_reset_retains_m_and_demotes_at_the_deadline() {
            check(Loss::Reset, 0, 0, 0);
            check(Loss::Reset, 1, RENEW_AFTER_MS, 0);
        }

        #[test]
        fn j18b_truncated_frame_retains_m_and_demotes_at_the_deadline() {
            check(Loss::Truncated, 0, 0, 1);
            check(Loss::Truncated, 1, RENEW_AFTER_MS, 1);
        }

        /// The Renew reached the Witness and its outcome is unknown: the
        /// Witness may have extended the lease, so its expiry is only later;
        /// the node still demotes at the old deadline and sends nothing more.
        #[test]
        fn j18b_renew_unknown_sends_nothing_more_and_demotes_at_the_old_deadline() {
            check(Loss::ReadThenClose, 0, 0, 0);
            check(Loss::ReadThenClose, 1, RENEW_AFTER_MS, 0);
        }

        /// Retained-Renew reconciliation on the lost session (the second arm):
        /// after the demotion at the deadline the node is in the ReleaseLease
        /// phase with the UNKNOWN Renew still durable. Reconciliation on the
        /// lost session must keep that phase (not latch a cleanup failure),
        /// send nothing, and leave the daemon's v0.6 A-1 restart path open.
        #[test]
        fn j18b_retained_renew_reconciliation_on_a_lost_session_keeps_the_phase() {
            let mut run = run(Loss::ReadThenClose, 0, 40);
            let last = run.trace.last().unwrap();
            assert!(!last.active);
            assert_eq!(last.at_ms, LEASE_REMAINING_MS - REQUIRED_MARGIN_MS);
            let release_phase = Some(OperationPhase::Demotion(
                crate::state_machine::DemotionPhase::ReleaseLease,
            ));
            assert_eq!(
                run.parts.runtime.state_machine.operation_phase(),
                release_phase
            );
            assert!(
                run.parts
                    .runtime
                    .durable_witness_outstanding()
                    .unwrap()
                    .is_some()
            );
            for _ in 0..3 {
                run.parts
                    .runtime
                    .drive_foreground_lifecycle(run.session.as_mut().unwrap(), &|| false, &|| true)
                    .unwrap();
                assert_eq!(
                    run.parts.runtime.state_machine.operation_phase(),
                    release_phase,
                    "a lost session must not latch a cleanup failure"
                );
                assert_ne!(
                    run.parts.runtime.state_machine.node_state(),
                    NodeState::Failed
                );
            }
            assert!(
                run.parts
                    .runtime
                    .durable_witness_outstanding()
                    .unwrap()
                    .is_some()
            );
            assert!(run.parts.runtime.witness_loss_stop_allowed());
            assert!(
                run.session.as_ref().unwrap().lost(),
                "the lost latch cleared"
            );
            assert_eq!(finish(&mut run), Some(0), "no request after the loss");
            cleanup_test_path(&run.parts.path);
        }

        /// Diagnostic only (asserts nothing): the state after the UNKNOWN
        /// Renew, the demotion at the deadline and three more lifecycle steps
        /// on the lost session, printed for v0.6 and for the candidate.
        #[test]
        fn j18b_diag_state_after_a_lost_session() {
            let mut run = run(Loss::ReadThenClose, 0, 40);
            for _ in 0..3 {
                let _ = run.parts.runtime.drive_foreground_lifecycle(
                    run.session.as_mut().unwrap(),
                    &|| false,
                    &|| true,
                );
            }
            println!(
                "J18B-DIAG demoted_at={} node_state={:?} phase={:?} \
                 renew_outstanding={} release_obligation={} witness_loss_stop_allowed={}",
                run.trace.last().unwrap().at_ms,
                run.parts.runtime.state_machine.node_state(),
                run.parts.runtime.state_machine.operation_phase(),
                run.parts
                    .runtime
                    .durable_witness_outstanding()
                    .unwrap()
                    .is_some(),
                run.parts.runtime.release_obligation().unwrap().is_some(),
                run.parts.runtime.witness_loss_stop_allowed()
            );
            let _ = finish(&mut run);
            cleanup_test_path(&run.parts.path);
        }

        /// LeaseRelease on a lost session (the third arm): the release request
        /// reaches the Witness and is never answered; later reconciliation on
        /// the latched session keeps M, the obligation and the phase.
        #[test]
        fn j18b_release_on_a_lost_session_keeps_m_and_the_phase() {
            let mut parts = test_runtime(
                [RawVipObservation::Absent],
                [RawServiceObservation::Stopped],
                [],
                AuthorityMode::Conservative,
                None,
            );
            parts.runtime.reconcile().unwrap();
            parts
                .runtime
                .state_machine
                .transition_to(NodeState::QuorumUnknown)
                .unwrap();
            parts
                .runtime
                .state_machine
                .transition_to(NodeState::Failed)
                .unwrap();
            parts.runtime.state_machine.reset_for_recovery().unwrap();
            parts
                .runtime
                .mutation_store
                .arm_release_obligation(Term(7), LeaseId::new("lease-1"))
                .unwrap();
            parts
                .runtime
                .mutation_store
                .begin_lease_release_for_test(Term(7), LeaseId::new("lease-1"), "test".into())
                .unwrap();
            parts
                .runtime
                .state_machine
                .begin_recovery_cleanup()
                .unwrap();
            for _ in 0..4 {
                parts.runtime.state_machine.advance_demotion().unwrap();
            }
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (server, _) = listener.accept().unwrap();
            let raw = server.try_clone().unwrap();
            let mut witness = WitnessConnection::new(
                NodeId::new("witness"),
                NodeId::new("node-a"),
                ClusterId::new("cluster"),
                SessionId::new("session-a"),
                TcpConnection::from_stream(server, Duration::from_secs(5), Duration::from_secs(5))
                    .unwrap(),
            );
            let server = thread::spawn(move || -> Option<usize> {
                let auth = MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32]));
                witness.receive_pending(&CborSerializer, &auth).ok()?;
                raw.shutdown(Shutdown::Write).unwrap();
                let mut after = 0;
                while witness.receive_pending(&CborSerializer, &auth).is_ok() {
                    after += 1;
                }
                Some(after)
            });
            let node = WitnessConnection::new(
                NodeId::new("node-a"),
                NodeId::new("witness"),
                ClusterId::new("cluster"),
                SessionId::new("session-w"),
                TcpConnection::from_stream(client, Duration::from_secs(2), Duration::from_secs(2))
                    .unwrap(),
            );
            let mut session = WitnessSession::new(
                node,
                ProcessSession::from_session_id(SessionId::new("session-a")),
                MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32])),
            );
            for round in 0..3 {
                parts
                    .runtime
                    .drive_foreground_lifecycle(&mut session, &|| false, &|| true)
                    .unwrap();
                assert!(
                    parts.runtime.state_machine.operation_phase().is_some(),
                    "round {round}: the phase was latched as a cleanup failure"
                );
                assert!(parts.runtime.release_obligation().unwrap().is_some());
                assert!(
                    parts
                        .runtime
                        .durable_witness_outstanding()
                        .unwrap()
                        .is_some()
                );
            }
            assert!(session.lost());
            drop(session);
            assert_eq!(server.join().unwrap(), Some(0), "no request after the loss");
            cleanup_test_path(&parts.path);
        }
    }

    // ---- Phase 1-J29 TEST-ONLY begin: B1 / C1 through the real gate and fencing step ----

    /// The trigger's inputs for a lost Active peer, with the real runtime's facts.
    fn j29_inputs(f: &Stage149, now_ms: u64, generation: u64) -> crate::auto_failover::AutoInputs {
        let runtime = &f.fixture.parts.runtime;
        crate::auto_failover::AutoInputs {
            now_ms,
            uptime_ms: now_ms + 60_000,
            running: true,
            shutdown: false,
            attempt_in_flight: false,
            standby_safe: true,
            node_state: NodeState::Standby,
            backend_is_command: runtime.fencing_backend_is_command(),
            assessment: crate::failure_assessment::PeerFailureAssessment::CommunicationLost,
            loss: Some(crate::auto_failover::LossEpisode {
                observer_session: STAGE14_9_SESSION.into(),
                generation,
                fresh: true,
            }),
            peer_active_confirmed: true,
            peer_node_state: None,
            incident: runtime.auto_incident_facts().unwrap(),
            activity: runtime.auto_fence_activity(),
            bootstrap_session_open: false,
            bootstrap_session_attested: false,
        }
    }

    fn j29_config(max_fence_actions: u32) -> crate::auto_failover::AutoConfig {
        crate::auto_failover::AutoConfig {
            enabled: true,
            preferred: false,
            dwell_ms: 10_000,
            bootstrap_dwell_ms: 20_000,
            bootstrap_defer_ms: 15_000,
            max_fence_actions,
            cycle_timeout_ms: 120_000,
        }
    }

    fn j29_fence_spawns(f: &Stage149) -> usize {
        stage14_9_spawns(f)
            .iter()
            .filter(|line| !line.starts_with("verify"))
            .count()
    }

    /// B1 on the real runtime: the gate's fence action is counted where it runs; an R4
    /// retirement (moved Witness term) before the next poll leaves the incident facts exactly as
    /// before the attempt (the information the facts-only trigger lost) and keeps the count; a
    /// gate that only retires (R3, no live episode) runs nothing and counts nothing.
    #[test]
    fn j29_b1_real_gate_counts_the_action_and_a_retirement_keeps_it() {
        use crate::fencing::{ContinuityViolation, FencingGateBlock};
        let mut f = stage14_9_command(STAGE14_9_FENCE_OK, STAGE14_9_ISOLATED, 10, 10, 3);
        let runtime_facts = |f: &Stage149| f.fixture.parts.runtime.auto_incident_facts().unwrap();
        let activity = |f: &Stage149| f.fixture.parts.runtime.auto_fence_activity();
        assert_eq!(activity(&f), crate::auto_failover::FenceActivity::default());
        let before = runtime_facts(&f);
        let (outcome, _) = stage14_9_gate(&mut f, Term(41));
        assert!(outcome.opened && outcome.action.is_some());
        assert_eq!(activity(&f).actions_run, 1);
        let incident = stage14_9_incident(&f).unwrap();
        let (step, _) = stage14_9_drive(&mut f, Some(&stage14_9_record(&incident, Term(42))));
        assert_eq!(
            step,
            FencingStepOutcome::Retired(ContinuityViolation::WitnessEpoch)
        );
        assert_eq!(
            runtime_facts(&f),
            before,
            "the facts are as before the fence action"
        );
        assert_eq!(
            activity(&f).actions_run,
            1,
            "the retirement keeps the count"
        );
        // A new incident and action, then a gate that only retires it (R3) and opens nothing.
        let (outcome, _) = stage14_9_gate(&mut f, Term(42));
        assert!(outcome.opened);
        assert_eq!(activity(&f).actions_run, 2);
        let facts_with_incident = runtime_facts(&f);
        let (outcome, voids) = stage14_9_gate_with(&mut f, Term(42), false, false);
        assert_eq!(outcome.retired, Some(ContinuityViolation::Episode));
        assert_eq!(outcome.block, FencingGateBlock::FencingUnavailable);
        assert_eq!(voids, 0);
        assert_ne!(runtime_facts(&f), facts_with_incident, "the facts changed");
        assert_eq!(
            activity(&f).actions_run,
            2,
            "no action ran, none is counted"
        );
        assert_eq!(activity(&f).not_isolated_verdicts, 0);
        assert_eq!(j29_fence_spawns(&f), 2);
    }

    /// B1 end to end on the real runtime: every automatic attempt opens an incident and fences
    /// (T2), and the incident is retired by R4 at the start of the next iteration (the fencing step
    /// runs before the trigger's poll). The episode fences exactly `max_fence_actions` times; a
    /// facts-only trigger fences on every request until the cycle ends.
    #[test]
    fn j29_b1_real_runtime_episode_is_capped_although_every_incident_is_retired() {
        let mut f = stage14_9_command(STAGE14_9_FENCE_OK, STAGE14_9_ISOLATED, 10, 10, 3);
        let mut machine = crate::auto_failover::AutoFailover::new(j29_config(2));
        let mut term = 41;
        let mut stop = None;
        for step in 0..200u64 {
            // The iteration's fencing step first: the Witness term moved since the gate.
            if let Some(incident) = stage14_9_incident(&f) {
                let record = stage14_9_record(&incident, Term(term + 1));
                let (outcome, _) = stage14_9_drive(&mut f, Some(&record));
                assert!(
                    matches!(outcome, FencingStepOutcome::Retired(_)),
                    "{outcome:?}"
                );
                term += 1;
            }
            match machine.poll(&j29_inputs(&f, step * 1_000, 1)) {
                crate::auto_failover::AutoDecision::Request { .. } => {
                    let (outcome, _) = stage14_9_gate(&mut f, Term(term));
                    assert!(outcome.opened && outcome.action.is_some());
                }
                crate::auto_failover::AutoDecision::Exhausted(reason) => {
                    assert!(stop.is_none());
                    stop = Some(reason);
                }
                _ => {}
            }
        }
        assert_eq!(
            j29_fence_spawns(&f),
            2,
            "exactly max_fence_actions fence actions"
        );
        assert!(stop.unwrap().contains("fence action budget"));
    }

    /// C1 end to end on the real runtime: the verify commits `FAILED`, the trigger's poll does not
    /// run on that iteration (its facts were unavailable), and the next iteration's fencing step
    /// retires the incident (R3: the episode ended by an unauthenticated arrival). New episodes
    /// follow. The verdict was counted where it was written, so no second fence action runs.
    #[test]
    fn j29_c1_real_runtime_failed_retired_before_any_poll_still_holds() {
        let mut f = stage14_9_command(STAGE14_9_FENCE_OK, STAGE14_9_NOT_ISOLATED, 10, 10, 3);
        let mut machine = crate::auto_failover::AutoFailover::new(j29_config(2));
        let mut requests = 0;
        let mut stops = Vec::new();
        let mut phase = 0; // 0: until the first fence; 1: verify; 2: retire; 3: new episodes
        for step in 0..400u64 {
            let mut generation = 1;
            match phase {
                1 => {
                    let incident = stage14_9_incident(&f).unwrap();
                    let (outcome, _) =
                        stage14_9_drive(&mut f, Some(&stage14_9_record(&incident, Term(41))));
                    assert!(
                        matches!(outcome, FencingStepOutcome::Polled { .. }),
                        "{outcome:?}"
                    );
                    assert_eq!(
                        f.fixture
                            .parts
                            .runtime
                            .auto_fence_activity()
                            .not_isolated_verdicts,
                        1
                    );
                    phase = 2;
                    continue; // no poll on this iteration
                }
                2 => {
                    let incident = stage14_9_incident(&f).unwrap();
                    let (outcome, _) = stage14_9_drive_with(
                        &mut f,
                        Some(&stage14_9_record(&incident, Term(41))),
                        false,
                        false,
                    );
                    assert!(
                        matches!(outcome, FencingStepOutcome::Retired(_)),
                        "{outcome:?}"
                    );
                    assert_eq!(stage14_9_incident(&f), None);
                    phase = 3;
                }
                3 => generation = 2 + step / 100,
                _ => {}
            }
            match machine.poll(&j29_inputs(&f, step * 1_000, generation)) {
                crate::auto_failover::AutoDecision::Request { .. } => {
                    requests += 1;
                    let (outcome, _) = stage14_9_gate(&mut f, Term(41));
                    assert!(outcome.action.is_some());
                    if phase == 0 {
                        phase = 1;
                    }
                }
                crate::auto_failover::AutoDecision::Exhausted(reason) => stops.push(reason),
                _ => {}
            }
        }
        assert_eq!(requests, 1, "no automatic fence after the FAILED verdict");
        assert_eq!(j29_fence_spawns(&f), 1);
        assert!(!stops.is_empty());
        assert!(
            stops.iter().all(|reason| reason.contains("not isolated")),
            "{stops:?}"
        );
    }

    // ---- Phase 1-J29 TEST-ONLY end ----

    // ---- J35 (cf30, Amendment C): in-process C-a(1), AC-8, C-d, C-c ----
    mod j35_cf30 {
        use super::*;
        use crate::protocol::{RequestId, WitnessMutationOutcomeCode};
        use crate::security::{MessageAuthenticator, Psk};
        use crate::session::ProcessSession;
        use crate::tcp::TcpConnection;
        use crate::witness_runtime::{
            WitnessConnection, WitnessResponseContext, send_witness_response_with_context,
        };
        use std::net::{TcpListener, TcpStream};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::thread;

        /// What the scripted Witness does with one received request.
        #[derive(Clone)]
        enum Plan {
            /// Answer with this message, its header at this term.
            Reply(ProtocolMessage, u64),
            /// Five authenticated answers with foreign request ids (one more
            /// than D-tol allows), and nothing for the request itself.
            Flood,
            /// Read the request and never answer.
            Silent,
        }

        struct Witness {
            requests: Arc<AtomicUsize>,
            join: thread::JoinHandle<()>,
        }

        /// A node session and a Witness thread serving `plans`, one per
        /// request, in order. `lose_before_reply` flips to "lost" just before
        /// each answer is sent (E-8 / R-17).
        fn witness(
            plans: Vec<Plan>,
            node_timeout: Duration,
            lose_before_reply: Option<Arc<AtomicBool>>,
        ) -> (WitnessSession, Witness) {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (server, _) = listener.accept().unwrap();
            let mut witness = WitnessConnection::new(
                NodeId::new("witness"),
                NodeId::new("node-a"),
                ClusterId::new("cluster"),
                SessionId::new("session-a"),
                TcpConnection::from_stream(server, Duration::from_secs(10), Duration::from_secs(2))
                    .unwrap(),
            );
            let requests = Arc::new(AtomicUsize::new(0));
            let seen = Arc::clone(&requests);
            let join = thread::spawn(move || {
                let auth = MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32]));
                let mut process = ProcessSession::from_session_id(SessionId::new("session-w"));
                for plan in plans {
                    let Ok(pending) = witness.receive_pending(&CborSerializer, &auth) else {
                        return;
                    };
                    seen.fetch_add(1, Ordering::SeqCst);
                    let request_id = pending
                        .message()
                        .unsigned()
                        .common
                        .request_id
                        .clone()
                        .unwrap();
                    match plan {
                        Plan::Silent => {}
                        Plan::Flood => {
                            for n in 0..5u8 {
                                let _ = send_witness_response_with_context(
                                    &mut witness,
                                    &mut process,
                                    RequestId::new(format!(
                                        "00000000-0000-4000-8000-0000000002{n:02x}"
                                    )),
                                    ProtocolMessage::LeaseReject(
                                        crate::protocol::LeaseRejectPayload {
                                            code: WitnessMutationOutcomeCode::PolicyReject,
                                            reason: "foreign".into(),
                                        },
                                    ),
                                    WitnessResponseContext {
                                        term: Term(7),
                                        lease_id: None,
                                    },
                                    &CborSerializer,
                                    &auth,
                                );
                            }
                        }
                        Plan::Reply(message, term) => {
                            if let Some(lost) = &lose_before_reply {
                                lost.store(true, Ordering::SeqCst);
                            }
                            let _ = send_witness_response_with_context(
                                &mut witness,
                                &mut process,
                                request_id,
                                message,
                                WitnessResponseContext {
                                    term: Term(term),
                                    lease_id: None,
                                },
                                &CborSerializer,
                                &auth,
                            );
                        }
                    }
                }
                // Keep the connection open until the node is done.
                let _ = witness.receive_pending(&CborSerializer, &auth);
            });
            let node = WitnessConnection::new(
                NodeId::new("node-a"),
                NodeId::new("witness"),
                ClusterId::new("cluster"),
                SessionId::new("session-w"),
                TcpConnection::from_stream(client, node_timeout, Duration::from_secs(2)).unwrap(),
            );
            let session = WitnessSession::new(
                node,
                ProcessSession::from_session_id(SessionId::new("session-a")),
                MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32])),
            );
            (session, Witness { requests, join })
        }

        fn reject(code: WitnessMutationOutcomeCode) -> ProtocolMessage {
            ProtocolMessage::LeaseReject(crate::protocol::LeaseRejectPayload {
                code,
                reason: "scripted".into(),
            })
        }

        /// A demotion in its ReleaseLease phase with `O = (7, lease-1)` and a
        /// retained exact `M` (a Release, or a Renew), as after a partition.
        fn post_cleanup_parts(
            renew: bool,
            vip: impl IntoIterator<Item = RawVipObservation>,
            service: impl IntoIterator<Item = RawServiceObservation>,
        ) -> TestRuntimeParts {
            let mut parts = test_runtime(vip, service, [], AuthorityMode::Conservative, None);
            parts.runtime.reconcile().unwrap();
            parts
                .runtime
                .state_machine
                .transition_to(NodeState::QuorumUnknown)
                .unwrap();
            parts
                .runtime
                .state_machine
                .transition_to(NodeState::Failed)
                .unwrap();
            parts.runtime.state_machine.reset_for_recovery().unwrap();
            parts
                .runtime
                .mutation_store
                .arm_release_obligation(Term(7), LeaseId::new("lease-1"))
                .unwrap();
            if renew {
                parts
                    .runtime
                    .mutation_store
                    .begin_lease_renew(Term(7), LeaseId::new("lease-1"))
                    .unwrap();
            } else {
                parts
                    .runtime
                    .mutation_store
                    .begin_lease_release_for_test(Term(7), LeaseId::new("lease-1"), "test".into())
                    .unwrap();
            }
            parts
                .runtime
                .state_machine
                .begin_recovery_cleanup()
                .unwrap();
            for _ in 0..4 {
                parts.runtime.state_machine.advance_demotion().unwrap();
            }
            parts
        }

        fn absent() -> [RawVipObservation; 4] {
            [RawVipObservation::Absent; 4]
        }

        fn stopped() -> [RawServiceObservation; 4] {
            [RawServiceObservation::Stopped; 4]
        }

        fn o_and_m(parts: &TestRuntimeParts) -> (bool, bool) {
            (
                parts.runtime.release_obligation().unwrap().is_some(),
                parts
                    .runtime
                    .mutation_store
                    .outstanding()
                    .unwrap()
                    .is_some(),
            )
        }

        /// C-a(1): a correlated PolicyReject of the exact owned Release, with
        /// a header term at or above term_o, settles M and O atomically and
        /// the node becomes an ordinary Standby without a restart: no
        /// authority, never promotion, never a release.
        #[test]
        fn j35_ca1_settles_a_policy_reject_without_a_restart() {
            for term in [7, 8] {
                let mut parts = post_cleanup_parts(false, absent(), stopped());
                let (mut session, witness) = witness(
                    vec![Plan::Reply(
                        reject(WitnessMutationOutcomeCode::PolicyReject),
                        term,
                    )],
                    Duration::from_secs(2),
                    None,
                );
                parts
                    .runtime
                    .drive_foreground_lifecycle(&mut session, &|| false, &|| true)
                    .unwrap();
                drop(session);
                witness.join.join().unwrap();
                assert_eq!(
                    parts.runtime.state_machine.node_state(),
                    NodeState::Standby,
                    "{term}"
                );
                assert_eq!(o_and_m(&parts), (false, false), "{term}");
                assert!(parts.runtime.installed_lease_authority().is_none());
                assert!(parts.runtime.controller.recovery_reconciled());
                cleanup_test_path(&parts.path);
            }
        }

        /// C-a(1) fails closed into the existing latch, keeping M and O:
        /// E-5 (an older header term), E-7 (ZeroResource not re-established
        /// before the settle) and AC-8 (RetiredStale, Conflict, GenerationGap
        /// in-process).
        #[test]
        fn j35_ca1_keeps_m_and_o_when_the_evidence_is_incomplete() {
            let cases: Vec<(ProtocolMessage, u64, bool)> = vec![
                (reject(WitnessMutationOutcomeCode::PolicyReject), 6, true),
                (reject(WitnessMutationOutcomeCode::PolicyReject), 7, false),
                (reject(WitnessMutationOutcomeCode::RetiredStale), 9, true),
                (reject(WitnessMutationOutcomeCode::Conflict), 9, true),
                (reject(WitnessMutationOutcomeCode::GenerationGap), 9, true),
            ];
            for (message, term, zero_resource_again) in cases {
                let service: Vec<RawServiceObservation> = if zero_resource_again {
                    stopped().to_vec()
                } else {
                    // One observation each: the fixture's reconcile, the
                    // pre-send gate (passes), then the re-check before the
                    // settle (fails). The request must reach the Witness.
                    vec![
                        RawServiceObservation::Stopped,
                        RawServiceObservation::Stopped,
                        RawServiceObservation::Running,
                        RawServiceObservation::Running,
                    ]
                };
                let mut parts = post_cleanup_parts(false, absent(), service);
                if !zero_resource_again {
                    // Set the queue right before the exchange: the pre-send
                    // gate sees Stopped, the re-check before the settle sees
                    // Running. The request must reach the Witness.
                    let mut queue = parts.service.borrow_mut();
                    queue.clear();
                    queue.extend([
                        RawServiceObservation::Stopped,
                        RawServiceObservation::Running,
                        RawServiceObservation::Running,
                    ]);
                }
                let (mut session, witness) = witness(
                    vec![Plan::Reply(message.clone(), term)],
                    Duration::from_secs(2),
                    None,
                );
                parts
                    .runtime
                    .drive_foreground_lifecycle(&mut session, &|| false, &|| true)
                    .unwrap();
                assert_eq!(
                    witness.requests.load(Ordering::SeqCst),
                    1,
                    "{message:?} {term} {zero_resource_again}: the exact Release was sent"
                );
                drop(session);
                witness.join.join().unwrap();
                assert_eq!(
                    parts.runtime.state_machine.node_state(),
                    NodeState::Failed,
                    "{message:?} {term} {zero_resource_again}"
                );
                assert_eq!(o_and_m(&parts), (true, true), "{message:?} {term}");
                assert!(parts.runtime.installed_lease_authority().is_none());
                cleanup_test_path(&parts.path);
            }
        }

        /// E-8 / R-17: a control-lock loss while the reject is in flight is
        /// never a settle; M and O stay.
        #[test]
        fn j35_ca1_never_settles_after_a_live_lock_loss() {
            let mut parts = post_cleanup_parts(false, absent(), stopped());
            let lost = Arc::new(AtomicBool::new(false));
            let (mut session, witness) = witness(
                vec![Plan::Reply(
                    reject(WitnessMutationOutcomeCode::PolicyReject),
                    7,
                )],
                Duration::from_secs(2),
                Some(Arc::clone(&lost)),
            );
            let result = parts
                .runtime
                .drive_foreground_lifecycle(&mut session, &|| false, &|| {
                    !lost.load(Ordering::SeqCst)
                });
            drop(session);
            witness.join.join().unwrap();
            assert!(
                matches!(result, Err(LinuxNodeRuntimeError::ControlLockLost)),
                "{result:?}"
            );
            assert_eq!(o_and_m(&parts), (true, true));
            cleanup_test_path(&parts.path);
        }

        /// C-d on the post-cleanup Release and Renew: two consecutive
        /// exhausted correlations keep M and O and are retried on the next
        /// iteration; the third falls back to the existing latch. A
        /// correlated answer in between resets the count.
        #[test]
        fn j35_cd_retries_two_exhausted_correlations_then_latches() {
            for renew in [false, true] {
                let mut parts = post_cleanup_parts(renew, absent(), stopped());
                let exact_m = parts.runtime.mutation_store.outstanding().unwrap().unwrap();
                let (mut session, witness) =
                    witness(vec![Plan::Flood; 3], Duration::from_secs(2), None);
                for attempt in 1..=3 {
                    parts
                        .runtime
                        .drive_foreground_lifecycle(&mut session, &|| false, &|| true)
                        .unwrap();
                    assert_eq!(
                        parts.runtime.state_machine.node_state() == NodeState::Failed,
                        attempt == 3,
                        "renew={renew} attempt {attempt}"
                    );
                    assert_eq!(
                        o_and_m(&parts),
                        (true, true),
                        "renew={renew} attempt {attempt}"
                    );
                    // L-4: every retry re-sends the same exact durable M.
                    let current = parts.runtime.mutation_store.outstanding().unwrap().unwrap();
                    assert_eq!(current, exact_m, "renew={renew} attempt {attempt}");
                    // T-07: the count is memory-only; the durable state is the
                    // same as before the retries, so a restart starts again
                    // from it (for a Release: the SOR candidate with M).
                    if !renew {
                        assert!(
                            parts
                                .runtime
                                .sor_candidate()
                                .unwrap()
                                .unwrap()
                                .release_pending,
                            "attempt {attempt}"
                        );
                    }
                }
                assert_eq!(witness.requests.load(Ordering::SeqCst), 3);
                drop(session);
                witness.join.join().unwrap();
                cleanup_test_path(&parts.path);
            }
            // Reset: two exhaustions, a correlated answer, two more: no latch.
            let mut parts = post_cleanup_parts(true, absent(), stopped());
            let renewed = ProtocolMessage::LeaseReject(crate::protocol::LeaseRejectPayload {
                code: WitnessMutationOutcomeCode::TemporarilyUnavailable,
                reason: "busy".into(),
            });
            let (mut session, witness) = witness(
                vec![
                    Plan::Flood,
                    Plan::Flood,
                    Plan::Reply(renewed, 7),
                    Plan::Flood,
                    Plan::Flood,
                ],
                Duration::from_secs(2),
                None,
            );
            for _ in 0..5 {
                parts
                    .runtime
                    .drive_foreground_lifecycle(&mut session, &|| false, &|| true)
                    .unwrap();
                assert_ne!(parts.runtime.state_machine.node_state(), NodeState::Failed);
            }
            assert_eq!(witness.requests.load(Ordering::SeqCst), 5);
            assert_eq!(o_and_m(&parts), (true, true));
            drop(session);
            witness.join.join().unwrap();
            cleanup_test_path(&parts.path);
        }

        /// C-d on the Active renewal: below the limit an exhausted
        /// correlation keeps Active with the exact M and the unchanged safe
        /// deadline; at the limit the existing demotion follows.
        #[test]
        fn j35_cd_active_renewal_keeps_the_safe_deadline_then_demotes() {
            let clock = Rc::new(Cell::new(0u64));
            let mut parts = stage14_11_l1_active_parts(&clock);
            parts
                .runtime
                .mutation_store
                .arm_release_obligation(Term(7), LeaseId::new("lease-1"))
                .unwrap();
            clock.set(3_000);
            let before = parts
                .runtime
                .installed_lease_authority()
                .map(|authority| authority.safe_deadline());
            let (mut session, witness) =
                witness(vec![Plan::Flood; 3], Duration::from_secs(2), None);
            let mut first_m = None;
            for attempt in 1..=2 {
                parts
                    .runtime
                    .drive_foreground_lifecycle(&mut session, &|| false, &|| true)
                    .unwrap();
                assert_eq!(
                    parts.runtime.state_machine.node_state(),
                    NodeState::Active,
                    "{attempt}"
                );
                assert_eq!(
                    witness.requests.load(Ordering::SeqCst),
                    attempt,
                    "{attempt}: sent"
                );
                assert_eq!(
                    parts
                        .runtime
                        .installed_lease_authority()
                        .map(|authority| authority.safe_deadline()),
                    before,
                    "{attempt}: the safe deadline never moves"
                );
                assert!(
                    parts
                        .runtime
                        .mutation_store
                        .outstanding()
                        .unwrap()
                        .is_some()
                );
                let current = parts.runtime.mutation_store.outstanding().unwrap().unwrap();
                if let Some(first) = &first_m {
                    assert_eq!(
                        &current, first,
                        "{attempt}: the same exact Renew is re-sent"
                    );
                }
                first_m = Some(current);
            }
            parts
                .runtime
                .drive_foreground_lifecycle(&mut session, &|| false, &|| true)
                .unwrap();
            // The existing demotion has begun (a pending demotion keeps the
            // Active node state with a demotion phase).
            assert!(
                parts.runtime.state_machine.node_state() != NodeState::Active
                    || parts.runtime.state_machine.operation_phase().is_some()
            );
            assert_eq!(witness.requests.load(Ordering::SeqCst), 3);
            drop(session);
            witness.join.join().unwrap();
            cleanup_test_path(&parts.path);
        }

        /// C-c: after a timeout of the retained Renew on the same session,
        /// the next due iterations are skipped 1, then 2 times; the exact M
        /// and O stay throughout and nothing else is sent.
        #[test]
        fn j35_cc_spaces_retained_renew_retries_after_timeouts() {
            let mut parts = post_cleanup_parts(true, absent(), stopped());
            let (mut session, witness) = witness(
                vec![Plan::Silent, Plan::Silent, Plan::Silent],
                Duration::from_millis(300),
                None,
            );
            let mut sent_after = Vec::new();
            for _ in 0..6 {
                parts
                    .runtime
                    .drive_foreground_lifecycle(&mut session, &|| false, &|| true)
                    .unwrap();
                sent_after.push(witness.requests.load(Ordering::SeqCst));
                assert_eq!(o_and_m(&parts), (true, true));
                assert_ne!(parts.runtime.state_machine.node_state(), NodeState::Failed);
            }
            // Sends on iterations 1, 3 and 6.
            assert_eq!(sent_after, [1, 1, 2, 2, 2, 3]);
            drop(session);
            witness.join.join().unwrap();
            cleanup_test_path(&parts.path);
        }

        /// A restarted node with `O = (7, lease-1)` and its exact Release `M`.
        fn startup_parts() -> TestRuntimeParts {
            let parts = test_runtime(absent(), stopped(), [], AuthorityMode::Conservative, None);
            parts
                .runtime
                .mutation_store
                .arm_release_obligation(Term(7), LeaseId::new("lease-1"))
                .unwrap();
            parts
                .runtime
                .mutation_store
                .begin_lease_release_for_test(Term(7), LeaseId::new("lease-1"), "crash".into())
                .unwrap();
            parts
        }

        /// A-13 / T-05: the daemon's live lock predicate reaches the startup
        /// reconciliation. A predicate that is already false stops before
        /// anything is sent; one that turns false while the reply is in
        /// flight makes the fresh ZeroResource before the settle fail, for
        /// A-4d and for C-l. M and O stay in every case.
        #[test]
        fn j35_startup_reconciliation_follows_the_live_lock_predicate() {
            let mut parts = startup_parts();
            let (mut session, idle) = witness(vec![], Duration::from_secs(2), None);
            let result = parts.runtime.reconcile_startup_obligation_guarded(
                &mut session,
                None,
                &|| false,
                &mut |_| panic!("no view without a replay"),
            );
            assert!(
                matches!(result, Err(LinuxNodeRuntimeError::ControlLockLost)),
                "{result:?}"
            );
            assert_eq!(idle.requests.load(Ordering::SeqCst), 0);
            assert_eq!(o_and_m(&parts), (true, true));
            drop(session);
            idle.join.join().unwrap();
            cleanup_test_path(&parts.path);

            for code in [
                WitnessMutationOutcomeCode::PolicyReject,
                WitnessMutationOutcomeCode::RetiredStale,
            ] {
                let mut parts = startup_parts();
                let lost = Arc::new(AtomicBool::new(false));
                let (mut session, witness) = witness(
                    vec![Plan::Reply(reject(code), 7)],
                    Duration::from_secs(2),
                    Some(Arc::clone(&lost)),
                );
                let result = parts.runtime.reconcile_startup_obligation_guarded(
                    &mut session,
                    None,
                    &|| !lost.load(Ordering::SeqCst),
                    &mut |_| {
                        Ok((
                            Term(9),
                            crate::evidence_fusion::adapter::AuthorityViewCompatibility::ConflictingHolder,
                        ))
                    },
                );
                assert!(
                    matches!(result, Ok(SorOutcome::Blocked(_))),
                    "{code:?}: {result:?}"
                );
                assert_eq!(witness.requests.load(Ordering::SeqCst), 1, "{code:?}");
                assert_eq!(o_and_m(&parts), (true, true), "{code:?}");
                drop(session);
                witness.join.join().unwrap();
                cleanup_test_path(&parts.path);
            }
        }

        /// C-a(1) E-4 / E-5 / E-8 in isolation: `settle_not_releasable_once`
        /// refuses a missing or different sent record, an older header term,
        /// an unsafe lock and a lost session, and settles nothing.
        #[test]
        fn j35_ca1_settle_refuses_each_missing_condition() {
            let mut parts = post_cleanup_parts(false, absent(), stopped());
            let exact = parts.runtime.mutation_store.outstanding().unwrap().unwrap();
            let mut other = exact.clone();
            other.mutation_generation += 1;
            let mut other_request = exact.clone();
            other_request.request_id = RequestId::new("00000000-0000-4000-8000-0000000003a1");
            let (session, witness) = witness(vec![], Duration::from_secs(2), None);
            for (sent, term, lock) in [
                (None, 7, true),
                (Some(&other), 7, true),
                (Some(&other_request), 7, true),
                (Some(&exact), 6, true),
                (Some(&exact), 7, false),
            ] {
                let settled = parts
                    .runtime
                    .settle_not_releasable_once(&session, sent, Term(term), "test", &|| lock)
                    .unwrap();
                assert!(!settled, "{sent:?} {term} {lock}");
                assert_eq!(o_and_m(&parts), (true, true));
            }
            drop(session);
            witness.join.join().unwrap();
            // A lost session (EOF from the Witness) is refused too.
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (server, _) = listener.accept().unwrap();
            drop(server);
            let mut lost = WitnessSession::new(
                WitnessConnection::new(
                    NodeId::new("node-a"),
                    NodeId::new("witness"),
                    ClusterId::new("cluster"),
                    SessionId::new("session-w"),
                    TcpConnection::from_stream(
                        client,
                        Duration::from_secs(2),
                        Duration::from_secs(2),
                    )
                    .unwrap(),
                ),
                ProcessSession::from_session_id(SessionId::new("session-a")),
                MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32])),
            );
            let _ = lost.receive_pending();
            assert!(lost.lost());
            let settled = parts
                .runtime
                .settle_not_releasable_once(&lost, Some(&exact), Term(7), "test", &|| true)
                .unwrap();
            assert!(!settled);
            assert_eq!(o_and_m(&parts), (true, true));
            cleanup_test_path(&parts.path);
        }
    }
}
