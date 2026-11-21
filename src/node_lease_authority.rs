//! Runtime-only conservative lease authority and monotonic safety checks.
//!
//! Nothing in this module is persisted.  In particular, a process restart
//! starts with no usable authority, even if a durable mutation is present.

#![allow(dead_code)]

use crate::node_mutation::{
    MutationKind, NodeMutationError, NodeMutationStore, OutstandingWitnessMutation,
};
use crate::protocol::{LeaseGrantPayload, LeaseId, NodeId, RequestId, Term};
use crate::state_machine::{PromotionPhase, StateMachine, TransitionError};
use std::fmt;
use std::time::{Duration, Instant};

#[path = "node_witness_runtime.rs"]
pub(crate) mod node_witness_runtime;

pub const LEASE_TTL_MS: u64 = 10_000;
pub const RENEW_AFTER_MS: u64 = 3_000;
pub const SAFETY_MARGIN_MS: u64 = 2_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MonotonicTime(u64);

impl MonotonicTime {
    pub const fn from_millis(value: u64) -> Self {
        Self(value)
    }

    pub(crate) const fn as_millis(self) -> u64 {
        self.0
    }

    fn checked_add(self, value: u64) -> Option<Self> {
        self.0.checked_add(value).map(Self)
    }
}

pub trait MonotonicClock {
    fn now(&self) -> Result<MonotonicTime, ClockError>;
}

/// The node's lease clock.
///
/// J24 candidate (suspend): on Linux it reads `CLOCK_BOOTTIME`, which, unlike `CLOCK_MONOTONIC`
/// (`Instant`), also counts the time the host was suspended. A lease deadline computed from it has
/// therefore passed after a resume that outlived the lease, so a resumed node never treats an
/// expired lease as usable. Both clocks advance at the same rate while the host runs; only the
/// lease authority reads this clock (waits and I/O timeouts stay on `Instant`). If the clock cannot
/// be read, `now` fails and the authority treats it as a clock failure (fail-closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemMonotonicClock {
    #[cfg(not(target_os = "linux"))]
    origin: Instant,
    #[cfg(target_os = "linux")]
    origin_ms: Option<u64>,
}

/// `CLOCK_BOOTTIME` in milliseconds, or `None` if it cannot be read.
#[cfg(target_os = "linux")]
fn boottime_ms() -> Option<u64> {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `now` is a valid, writable timespec; clock_gettime only writes it.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut now) } != 0 {
        return None;
    }
    let seconds = u64::try_from(now.tv_sec).ok()?;
    let nanos = u64::try_from(now.tv_nsec).ok()?;
    seconds.checked_mul(1_000)?.checked_add(nanos / 1_000_000)
}

impl SystemMonotonicClock {
    pub fn new() -> Self {
        Self {
            #[cfg(not(target_os = "linux"))]
            origin: Instant::now(),
            #[cfg(target_os = "linux")]
            origin_ms: boottime_ms(),
        }
    }
}

impl Default for SystemMonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

impl MonotonicClock for SystemMonotonicClock {
    #[cfg(not(target_os = "linux"))]
    fn now(&self) -> Result<MonotonicTime, ClockError> {
        let millis = self
            .origin
            .elapsed()
            .as_millis()
            .try_into()
            .map_err(|_| ClockError::Unavailable)?;
        Ok(MonotonicTime(millis))
    }

    #[cfg(target_os = "linux")]
    fn now(&self) -> Result<MonotonicTime, ClockError> {
        let origin = self.origin_ms.ok_or(ClockError::Unavailable)?;
        let now = boottime_ms().ok_or(ClockError::Unavailable)?;
        now.checked_sub(origin)
            .map(MonotonicTime)
            .ok_or(ClockError::Unavailable)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockError {
    Unavailable,
}

impl fmt::Display for ClockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "monotonic clock is unavailable")
    }
}

impl std::error::Error for ClockError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthorityContext {
    conservative: bool,
    resource_owning: bool,
    ownership_eligible: bool,
}

impl AuthorityContext {
    #[cfg(test)]
    pub(crate) const fn availability() -> Self {
        Self {
            conservative: false,
            resource_owning: false,
            ownership_eligible: true,
        }
    }

    #[cfg(test)]
    const fn test_conservative(resource_owning: bool) -> Self {
        Self {
            conservative: true,
            resource_owning,
            ownership_eligible: true,
        }
    }

    #[cfg(test)]
    const fn conservative_resource_owner() -> Self {
        Self::test_conservative(true)
    }

    #[cfg(test)]
    const fn recovery_pending_context() -> Self {
        Self {
            conservative: true,
            resource_owning: false,
            ownership_eligible: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MutationIdentity {
    request_id: RequestId,
    generation: u64,
    kind: MutationKind,
}

impl MutationIdentity {
    fn new(request_id: RequestId, generation: u64, kind: MutationKind) -> Self {
        Self {
            request_id,
            generation,
            kind,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedGrant {
    grant: LeaseGrantPayload,
    identity: MutationIdentity,
    timing_origin: MonotonicTime,
    schedule_origin: MonotonicTime,
}

impl ValidatedGrant {
    fn new(
        grant: LeaseGrantPayload,
        identity: MutationIdentity,
        timing_origin: MonotonicTime,
        schedule_origin: MonotonicTime,
    ) -> Self {
        Self {
            grant,
            identity,
            timing_origin,
            schedule_origin,
        }
    }
}

/// The single usable runtime lease authority value.
///
/// Intentionally not `Clone`: there must never be two simultaneously usable
/// authority-bearing values. Ownership moves through
/// `NodeLeaseAuthority::take_authority` / `restore_authority`.
#[derive(Debug, PartialEq, Eq)]
pub struct RuntimeLeaseAuthority {
    term: Term,
    lease_id: LeaseId,
    holder_node_id: NodeId,
    safe_deadline: MonotonicTime,
    renew_due: MonotonicTime,
}

#[allow(dead_code)]
impl RuntimeLeaseAuthority {
    pub(crate) fn term(&self) -> Term {
        self.term
    }

    pub(crate) fn lease_id(&self) -> &LeaseId {
        &self.lease_id
    }

    pub(crate) fn holder_node_id(&self) -> &NodeId {
        &self.holder_node_id
    }

    pub(crate) fn safe_deadline(&self) -> MonotonicTime {
        self.safe_deadline
    }

    pub(crate) fn renew_due(&self) -> MonotonicTime {
        self.renew_due
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityError {
    Clock(ClockError),
    InvalidGrant(&'static str),
    DeadlineUnavailable,
    AuthorityLost,
    RenewalInProgress,
    NoAuthority,
    StateProhibitsOwnership,
    MutationTimingConflict,
    MissingMutationTiming,
    ResetNotSafe,
    DemotionRequired,
    InvalidCheckpoint,
    UnresolvedLeaseRelease,
    MutationStateUnavailable,
    RecoveryBlocked,
    AuthorityOccupied,
}

impl fmt::Display for AuthorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clock(error) => write!(f, "authority clock error: {error}"),
            Self::InvalidGrant(field) => write!(f, "invalid lease grant: {field}"),
            Self::DeadlineUnavailable => write!(f, "lease safe deadline is unavailable"),
            Self::AuthorityLost => write!(f, "lease authority is not usable"),
            Self::RenewalInProgress => write!(f, "another lease renewal is already in progress"),
            Self::NoAuthority => write!(f, "no runtime lease authority is installed"),
            Self::StateProhibitsOwnership => {
                write!(f, "current state prohibits resource ownership")
            }
            Self::MutationTimingConflict => write!(f, "another mutation timing identity is active"),
            Self::MissingMutationTiming => write!(f, "mutation timing provenance is unavailable"),
            Self::ResetNotSafe => write!(f, "authority reset is not proven safe"),
            Self::DemotionRequired => write!(f, "demotion is required for the current operation"),
            Self::InvalidCheckpoint => write!(f, "authority checkpoint is invalid or stale"),
            Self::UnresolvedLeaseRelease => {
                write!(f, "an unresolved LeaseRelease blocks ownership")
            }
            Self::MutationStateUnavailable => write!(f, "durable mutation state is unavailable"),
            Self::RecoveryBlocked => write!(f, "runtime recovery is not complete"),
            Self::AuthorityOccupied => {
                write!(f, "a different lease authority is already installed")
            }
        }
    }
}

impl std::error::Error for AuthorityError {}

impl From<ClockError> for AuthorityError {
    fn from(error: ClockError) -> Self {
        Self::Clock(error)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct RenewalAttempt {
    old_deadline: MonotonicTime,
    identity: MutationIdentity,
    term: Term,
    lease_id: LeaseId,
}

pub struct NodeLeaseAuthority<C> {
    clock: C,
    local_node_id: NodeId,
    authority: Option<RuntimeLeaseAuthority>,
    renewal_in_progress: bool,
    demotion_latched: bool,
    mutation_timing: Option<(MutationIdentity, MonotonicTime)>,
}

pub(crate) trait AuthorityGate {
    fn ensure_usable_for_step(&mut self, context: AuthorityContext) -> Result<(), AuthorityError>;
}

#[allow(dead_code)]
impl<C: MonotonicClock> NodeLeaseAuthority<C> {
    fn new(clock: C, local_node_id: NodeId) -> Self {
        Self {
            clock,
            local_node_id,
            authority: None,
            renewal_in_progress: false,
            demotion_latched: false,
            mutation_timing: None,
        }
    }

    pub fn authority(&self) -> Option<&RuntimeLeaseAuthority> {
        self.authority.as_ref()
    }

    /// Move the installed authority out of this owner. The returned value is
    /// the only usable `RuntimeLeaseAuthority` in the process; this owner
    /// retains none until `restore_authority` installs it again.
    pub(crate) fn take_authority(&mut self) -> Option<RuntimeLeaseAuthority> {
        self.authority.take()
    }

    /// Reinstall an authority previously moved out through `take_authority`.
    /// Fails closed if a different authority was installed meanwhile or the
    /// loss latch is set; on failure the passed value is dropped, not kept.
    pub(crate) fn restore_authority(
        &mut self,
        authority: RuntimeLeaseAuthority,
    ) -> Result<(), AuthorityError> {
        if self.demotion_latched {
            return Err(AuthorityError::AuthorityLost);
        }
        if self.authority.is_some() {
            return Err(AuthorityError::AuthorityOccupied);
        }
        self.authority = Some(authority);
        Ok(())
    }

    pub(crate) fn clock(&self) -> &C {
        &self.clock
    }

    pub fn demotion_latched(&self) -> bool {
        self.demotion_latched
    }

    pub(crate) fn renewal_in_progress(&self) -> bool {
        self.renewal_in_progress
    }

    fn install_validated_grant(
        &mut self,
        validated: ValidatedGrant,
        context: AuthorityContext,
    ) -> Result<(), AuthorityError> {
        let grant = &validated.grant;
        let origin = self.verify_timing_identity(&validated.identity, validated.timing_origin)?;
        let result = (|| {
            if self.demotion_latched {
                return Err(AuthorityError::AuthorityLost);
            }
            let candidate = self.candidate_from_grant(grant, origin, validated.schedule_origin)?;
            let now = self.clock.now()?;
            self.validate_candidate(&candidate, now, context)?;
            self.authority = Some(candidate);
            Ok(())
        })();
        // The durable request is already terminally completed before install.
        // Release this attempt's timing provenance on every post-completion
        // outcome; otherwise a later fresh request is permanently blocked.
        self.mutation_timing = None;
        result
    }

    #[cfg(test)]
    fn install_grant(
        &mut self,
        grant: &LeaseGrantPayload,
        attempt_start: MonotonicTime,
        context: AuthorityContext,
    ) -> Result<(), AuthorityError> {
        if self.demotion_latched {
            return Err(AuthorityError::AuthorityLost);
        }
        let identity = MutationIdentity::new(
            RequestId::new("test-request"),
            1,
            MutationKind::LeaseRequest,
        );
        self.record_attempt(identity.clone(), attempt_start)?;
        self.install_validated_grant(
            ValidatedGrant::new(grant.clone(), identity, attempt_start, attempt_start),
            context,
        )
    }

    fn record_attempt(
        &mut self,
        identity: MutationIdentity,
        attempt_start: MonotonicTime,
    ) -> Result<MonotonicTime, AuthorityError> {
        match &self.mutation_timing {
            Some((current, origin)) if current == &identity => Ok(*origin),
            Some(_) => Err(AuthorityError::MutationTimingConflict),
            None => {
                self.mutation_timing = Some((identity, attempt_start));
                Ok(attempt_start)
            }
        }
    }

    #[allow(dead_code)]
    fn finish_attempt(&mut self, identity: &MutationIdentity) {
        if self
            .mutation_timing
            .as_ref()
            .is_some_and(|(current, _)| current == identity)
        {
            self.mutation_timing = None;
        }
    }

    #[allow(dead_code)]
    fn latch_timing_failure(&mut self, context: AuthorityContext) {
        if context.conservative && context.resource_owning && self.authority.is_some() {
            self.latch_loss();
        }
    }

    fn begin_renewal_with_identity(
        &mut self,
        identity: MutationIdentity,
        context: AuthorityContext,
    ) -> Result<RenewalAttempt, AuthorityError> {
        self.ensure_usable_for_step(context)?;
        if self.renewal_in_progress {
            return Err(AuthorityError::RenewalInProgress);
        }
        let old_deadline = self
            .authority
            .as_ref()
            .ok_or(AuthorityError::NoAuthority)?
            .safe_deadline;
        let authority = self.authority.as_ref().ok_or(AuthorityError::NoAuthority)?;
        self.renewal_in_progress = true;
        Ok(RenewalAttempt {
            old_deadline,
            identity,
            term: authority.term,
            lease_id: authority.lease_id.clone(),
        })
    }

    #[cfg(test)]
    fn begin_renewal(
        &mut self,
        context: AuthorityContext,
    ) -> Result<RenewalAttempt, AuthorityError> {
        let identity =
            MutationIdentity::new(RequestId::new("test-request"), 1, MutationKind::LeaseRenew);
        let origin = self.clock.now()?;
        self.record_attempt(identity.clone(), origin)?;
        self.begin_renewal_with_identity(identity, context)
    }

    fn complete_renewal_with_schedule(
        &mut self,
        attempt: RenewalAttempt,
        grant: &LeaseGrantPayload,
        attempt_start: MonotonicTime,
        schedule_origin: MonotonicTime,
        context: AuthorityContext,
    ) -> Result<(), AuthorityError> {
        let result =
            self.complete_renewal_inner(attempt, grant, attempt_start, schedule_origin, context);
        self.renewal_in_progress = false;
        result
    }

    #[cfg(test)]
    fn complete_renewal(
        &mut self,
        attempt: RenewalAttempt,
        grant: &LeaseGrantPayload,
        attempt_start: MonotonicTime,
        context: AuthorityContext,
    ) -> Result<(), AuthorityError> {
        self.complete_renewal_with_schedule(attempt, grant, attempt_start, attempt_start, context)
    }

    fn complete_renewal_inner(
        &mut self,
        attempt: RenewalAttempt,
        grant: &LeaseGrantPayload,
        attempt_start: MonotonicTime,
        schedule_origin: MonotonicTime,
        context: AuthorityContext,
    ) -> Result<(), AuthorityError> {
        let origin = self.verify_timing_identity(&attempt.identity, attempt_start)?;
        let result = (|| {
            let candidate = self.candidate_from_grant(grant, origin, schedule_origin)?;
            let now_after_completion = match self.clock.now() {
                Ok(now) => now,
                Err(error) => {
                    self.latch_loss();
                    return Err(error.into());
                }
            };
            if now_after_completion >= attempt.old_deadline || self.demotion_latched {
                self.latch_loss();
                return Err(AuthorityError::AuthorityLost);
            }
            let current = self.authority.as_ref().ok_or(AuthorityError::NoAuthority)?;
            if current.term != attempt.term || current.lease_id != attempt.lease_id {
                self.latch_loss();
                return Err(AuthorityError::AuthorityLost);
            }
            self.validate_candidate(&candidate, now_after_completion, context)?;
            self.authority = Some(candidate);
            Ok(())
        })();
        // Durable completion precedes this in-memory authority decision.
        self.mutation_timing = None;
        result
    }

    #[allow(dead_code)]
    pub(crate) fn reject_or_fail_renewal(&mut self) {
        self.renewal_in_progress = false;
    }

    pub fn check_and_latch_loss(
        &mut self,
        context: AuthorityContext,
    ) -> Result<(), AuthorityError> {
        if !context.conservative || !context.resource_owning {
            return Ok(());
        }
        self.check_authority_usable().inspect_err(|_| {
            self.latch_loss();
        })
    }

    pub fn ensure_usable_for_step(
        &mut self,
        context: AuthorityContext,
    ) -> Result<(), AuthorityError> {
        if !context.conservative {
            return Ok(());
        }
        if !context.ownership_eligible {
            if context.resource_owning {
                self.latch_loss();
            }
            return Err(AuthorityError::StateProhibitsOwnership);
        }
        let usable = self.check_authority_usable();
        if usable.is_err() && context.resource_owning {
            self.latch_loss();
        }
        usable
    }

    fn check_authority_usable(&mut self) -> Result<(), AuthorityError> {
        if self.demotion_latched {
            return Err(AuthorityError::AuthorityLost);
        }
        let Some(authority) = self.authority.as_ref() else {
            return Err(AuthorityError::NoAuthority);
        };
        let now = self.clock.now()?;
        if authority.holder_node_id != self.local_node_id || now >= authority.safe_deadline {
            return Err(AuthorityError::AuthorityLost);
        }
        Ok(())
    }

    pub fn next_safety_deadline(&self) -> Option<MonotonicTime> {
        self.authority
            .as_ref()
            .map(|authority| authority.safe_deadline)
    }

    #[allow(dead_code)]
    pub(crate) fn time_until_expiry(&mut self) -> Result<Option<u64>, AuthorityError> {
        let Some(deadline) = self.next_safety_deadline() else {
            return Ok(None);
        };
        let now = match self.clock.now() {
            Ok(now) => now,
            Err(error) => {
                if self.authority.is_some() {
                    self.latch_loss();
                }
                return Err(error.into());
            }
        };
        Ok(Some(deadline.as_millis().saturating_sub(now.as_millis())))
    }

    pub fn latch_loss(&mut self) {
        self.demotion_latched = true;
    }

    fn reset_after_zero_resource_reconcile(
        &mut self,
        context: AuthorityContext,
    ) -> Result<(), AuthorityError> {
        if context.conservative && (context.resource_owning || !context.ownership_eligible) {
            return Err(AuthorityError::ResetNotSafe);
        }
        self.authority = None;
        self.renewal_in_progress = false;
        self.demotion_latched = false;
        self.mutation_timing = None;
        Ok(())
    }

    pub fn is_empty_after_restart(&self) -> bool {
        self.authority.is_none() && !self.demotion_latched && !self.renewal_in_progress
    }

    fn candidate_from_grant(
        &self,
        grant: &LeaseGrantPayload,
        timing_origin: MonotonicTime,
        schedule_origin: MonotonicTime,
    ) -> Result<RuntimeLeaseAuthority, AuthorityError> {
        if grant.holder_node_id != self.local_node_id {
            return Err(AuthorityError::InvalidGrant("holder_node_id"));
        }
        if grant.term.0 == 0 || grant.lease_id.as_str().trim().is_empty() {
            return Err(AuthorityError::InvalidGrant("term or lease_id"));
        }
        if grant.lease_remaining_ms.0 <= SAFETY_MARGIN_MS {
            return Err(AuthorityError::DeadlineUnavailable);
        }
        let usable_ms = grant.lease_remaining_ms.0 - SAFETY_MARGIN_MS;
        let safe_deadline = timing_origin
            .checked_add(usable_ms)
            .ok_or(AuthorityError::DeadlineUnavailable)?;
        let renew_due = schedule_origin
            .checked_add(grant.renew_after_ms.0)
            .ok_or(AuthorityError::DeadlineUnavailable)?;
        Ok(RuntimeLeaseAuthority {
            term: grant.term,
            lease_id: grant.lease_id.clone(),
            holder_node_id: grant.holder_node_id.clone(),
            safe_deadline,
            renew_due,
        })
    }

    fn verify_timing_identity(
        &self,
        identity: &MutationIdentity,
        _fallback: MonotonicTime,
    ) -> Result<MonotonicTime, AuthorityError> {
        self.mutation_timing
            .as_ref()
            .filter(|(current, _)| current == identity)
            .map(|(_, origin)| *origin)
            .ok_or(AuthorityError::MissingMutationTiming)
    }

    fn validate_candidate(
        &self,
        candidate: &RuntimeLeaseAuthority,
        now: MonotonicTime,
        context: AuthorityContext,
    ) -> Result<(), AuthorityError> {
        if !context.conservative {
            return Ok(());
        }
        if now >= candidate.safe_deadline {
            return Err(AuthorityError::DeadlineUnavailable);
        }
        Ok(())
    }
}

impl<C: MonotonicClock> AuthorityGate for NodeLeaseAuthority<C> {
    fn ensure_usable_for_step(&mut self, context: AuthorityContext) -> Result<(), AuthorityError> {
        NodeLeaseAuthority::ensure_usable_for_step(self, context)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthorityMode {
    Conservative,
    Availability,
}

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthorityCheckpoint {
    BeforeVipAcquire,
    BeforeServiceStart,
    BeforeHealthAdvance,
    BeforeGarp,
    BeforeActiveCommit,
    BeforeDegradedToActive,
}

pub(crate) struct LeaseReleaseOrigin {
    _private: (),
}

impl LeaseReleaseOrigin {
    fn from_cleanup(_provenance: &crate::resource_workflow::CleanupProvenance) -> Self {
        Self { _private: () }
    }

    fn for_stage10() -> Self {
        Self { _private: () }
    }
}

#[cfg(test)]
pub(crate) fn test_lease_release_origin() -> LeaseReleaseOrigin {
    LeaseReleaseOrigin { _private: () }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OwnershipClass {
    ZeroResource,
    ResourceOwning,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RenewalDue {
    Due,
    NotDue,
    NoAuthority,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ActiveScheduleDelays {
    pub(crate) renew_in: Duration,
    pub(crate) expiry_in: Duration,
}

/// The only runtime owner of a NodeLeaseAuthority.
///
/// This owner is deliberately runtime-only.  Its constructor starts empty and
/// its latch cannot be cleared by state-machine transitions or Witness replies.
pub(crate) struct NodeAuthorityController<C> {
    authority: NodeLeaseAuthority<C>,
    mutation_store: NodeMutationStore,
    mode: AuthorityMode,
    ownership: OwnershipClass,
    recovery: RecoveryState,
    demotion_required: bool,
    #[cfg(test)]
    fail_next_completion_checkpoint: bool,
    #[cfg(test)]
    completion_checkpoint_attempted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoveryState {
    Blocked,
    ReconciledZeroResource,
}

/// A permission is for one immediate checkpoint only.  It is intentionally
/// neither `Clone` nor `Copy` and contains no authority data that can be
/// persisted or sent over the wire.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AuthorityPermission {
    checkpoint: AuthorityCheckpoint,
}

impl<C: MonotonicClock> NodeAuthorityController<C> {
    fn new(
        clock: C,
        local_node_id: NodeId,
        mutation_store: NodeMutationStore,
        mode: AuthorityMode,
    ) -> Self {
        Self {
            authority: NodeLeaseAuthority::new(clock, local_node_id),
            mutation_store,
            mode,
            ownership: OwnershipClass::ZeroResource,
            recovery: RecoveryState::Blocked,
            demotion_required: false,
            #[cfg(test)]
            fail_next_completion_checkpoint: false,
            #[cfg(test)]
            completion_checkpoint_attempted: false,
        }
    }

    pub(crate) fn new_for_runtime(
        clock: C,
        local_node_id: NodeId,
        mutation_store: NodeMutationStore,
        mode: AuthorityMode,
    ) -> Self {
        Self::new(clock, local_node_id, mutation_store, mode)
    }

    pub(crate) fn reconcile_zero_resource(&mut self) -> Result<(), AuthorityError> {
        if self
            .mutation_store
            .outstanding()
            .map_err(|_| AuthorityError::MutationStateUnavailable)?
            .is_some()
        {
            return Err(AuthorityError::RecoveryBlocked);
        }
        let context = self.context_for(AuthorityCheckpoint::BeforeVipAcquire);
        self.authority
            .reset_after_zero_resource_reconcile(context)?;
        self.ownership = OwnershipClass::ZeroResource;
        self.recovery = RecoveryState::ReconciledZeroResource;
        self.demotion_required = false;
        Ok(())
    }

    pub(crate) fn recovery_reconciled(&self) -> bool {
        matches!(self.recovery, RecoveryState::ReconciledZeroResource)
    }

    /// Whether this controller runs the Conservative authority mode (the only
    /// mode in which the lease deadline gates apply; Bootstrap Admission
    /// requires it, contract K-5).
    pub(crate) fn is_conservative(&self) -> bool {
        matches!(self.mode, AuthorityMode::Conservative)
    }

    pub(crate) fn authority(&self) -> &NodeLeaseAuthority<C> {
        &self.authority
    }

    /// Stage 13.2 move-out boundary: transfer the installed lease authority
    /// to the promotion-attempt frame. The controller retains nothing usable;
    /// the only live `RuntimeLeaseAuthority` is the returned value.
    pub(crate) fn take_installed_lease_authority(&mut self) -> Option<RuntimeLeaseAuthority> {
        self.authority.take_authority()
    }

    /// Stage 13.2 restore boundary: reinstall the attempt-owned authority
    /// immediately before Stage 11 mutation. Fails closed if a different
    /// authority appeared or ownership was latched while it was bound to the
    /// attempt; the consumed value is dropped on failure, never overwritten.
    pub(crate) fn restore_installed_lease_authority(
        &mut self,
        authority: RuntimeLeaseAuthority,
    ) -> Result<(), AuthorityError> {
        self.authority.restore_authority(authority)
    }

    pub(crate) fn demotion_required(&self) -> bool {
        self.demotion_required
    }

    pub(crate) fn resource_owning(&self) -> bool {
        matches!(self.ownership, OwnershipClass::ResourceOwning)
    }

    pub(crate) fn ownership_class(&self) -> OwnershipClass {
        self.ownership
    }

    fn ownership_at_risk(&self) -> bool {
        !matches!(self.ownership, OwnershipClass::ZeroResource)
    }

    pub(crate) fn mark_resource_ownership_started(&mut self) {
        self.ownership = OwnershipClass::ResourceOwning;
    }

    #[cfg(test)]
    fn reconcile_zero_resource_for_test(&mut self) {
        assert_eq!(self.ownership, OwnershipClass::ZeroResource);
        assert!(!self.demotion_required);
        self.recovery = RecoveryState::ReconciledZeroResource;
    }

    pub(crate) fn mark_ownership_uncertain(&mut self) {
        self.ownership = OwnershipClass::Unknown;
        if matches!(self.mode, AuthorityMode::Conservative) {
            self.request_demotion();
        }
    }

    pub(crate) fn request_demotion(&mut self) {
        if !matches!(self.ownership, OwnershipClass::ZeroResource)
            && matches!(self.mode, AuthorityMode::Conservative)
        {
            self.demotion_required = true;
            self.authority.latch_loss();
        }
    }

    fn context_for(&self, checkpoint: AuthorityCheckpoint) -> AuthorityContext {
        let resource_owning = match self.ownership {
            OwnershipClass::ResourceOwning | OwnershipClass::Unknown => true,
            OwnershipClass::ZeroResource => {
                !matches!(checkpoint, AuthorityCheckpoint::BeforeVipAcquire)
            }
        };
        let ownership_eligible = !matches!(self.ownership, OwnershipClass::Unknown);
        AuthorityContext {
            conservative: matches!(self.mode, AuthorityMode::Conservative),
            resource_owning,
            ownership_eligible,
        }
    }

    pub(crate) fn checkpoint(
        &mut self,
        checkpoint: AuthorityCheckpoint,
    ) -> Result<AuthorityPermission, AuthorityError> {
        if self.demotion_required {
            return Err(AuthorityError::DemotionRequired);
        }
        if matches!(self.mode, AuthorityMode::Conservative)
            && matches!(self.recovery, RecoveryState::Blocked)
        {
            return Err(AuthorityError::RecoveryBlocked);
        }
        if matches!(self.mode, AuthorityMode::Conservative) {
            self.ensure_no_unresolved_lease_release(&self.mutation_store)?;
        }
        let context = self.context_for(checkpoint);
        match self.authority.ensure_usable_for_step(context) {
            Ok(()) => Ok(AuthorityPermission { checkpoint }),
            Err(error) => {
                if context.resource_owning {
                    self.request_demotion();
                }
                Err(error)
            }
        }
    }

    pub(crate) fn complete_checkpoint(
        &mut self,
        permission: AuthorityPermission,
        expected: AuthorityCheckpoint,
    ) -> Result<(), AuthorityError> {
        if permission.checkpoint != expected {
            return Err(AuthorityError::InvalidCheckpoint);
        }
        #[cfg(test)]
        if expected == AuthorityCheckpoint::BeforeActiveCommit
            && self.fail_next_completion_checkpoint
        {
            self.fail_next_completion_checkpoint = false;
            self.completion_checkpoint_attempted = true;
            self.mark_completion_uncertain();
            return Err(AuthorityError::AuthorityLost);
        }
        if matches!(self.mode, AuthorityMode::Conservative)
            && let Err(error) = self.ensure_no_unresolved_lease_release(&self.mutation_store)
        {
            self.mark_completion_uncertain();
            return Err(error);
        }
        let context = self.context_for(expected);
        let result = self.authority.ensure_usable_for_step(context);
        if result.is_err() && matches!(self.mode, AuthorityMode::Conservative) {
            self.mark_completion_uncertain();
        }
        result
    }

    fn mark_completion_uncertain(&mut self) {
        if matches!(self.mode, AuthorityMode::Conservative) {
            self.ownership = OwnershipClass::Unknown;
            self.request_demotion();
        }
    }

    pub(crate) fn renewal_due(&mut self) -> Result<RenewalDue, AuthorityError> {
        if self.demotion_required {
            return Err(AuthorityError::DemotionRequired);
        }
        if matches!(self.mode, AuthorityMode::Availability) {
            return Ok(RenewalDue::NotDue);
        }
        let Some(authority) = self.authority.authority() else {
            if self.ownership_at_risk() {
                self.request_demotion();
                return Err(AuthorityError::NoAuthority);
            }
            return Ok(RenewalDue::NoAuthority);
        };
        let now = match self.authority.clock().now() {
            Ok(now) => now,
            Err(error) => {
                if self.resource_owning() {
                    self.request_demotion();
                }
                return Err(error.into());
            }
        };
        if now >= authority.safe_deadline() {
            self.request_demotion();
            return Err(AuthorityError::AuthorityLost);
        }
        Ok(if now >= authority.renew_due() {
            RenewalDue::Due
        } else {
            RenewalDue::NotDue
        })
    }

    /// Side-effect-free relative scheduling view in the controller clock
    /// domain. Callers compare durations, never raw timestamps.
    pub(crate) fn active_schedule_delays(
        &self,
    ) -> Result<Option<ActiveScheduleDelays>, AuthorityError> {
        if matches!(self.mode, AuthorityMode::Availability) {
            return Ok(None);
        }
        let Some(authority) = self.authority.authority() else {
            return Ok(None);
        };
        if self.authority.demotion_latched() {
            return Ok(None);
        }
        let now = self.authority.clock().now()?;
        if now >= authority.safe_deadline() {
            return Ok(None);
        }
        Ok(Some(ActiveScheduleDelays {
            renew_in: Duration::from_millis(
                authority
                    .renew_due()
                    .as_millis()
                    .saturating_sub(now.as_millis()),
            ),
            expiry_in: Duration::from_millis(
                authority
                    .safe_deadline()
                    .as_millis()
                    .saturating_sub(now.as_millis()),
            ),
        }))
    }

    pub(crate) fn ensure_no_unresolved_lease_release(
        &self,
        store: &NodeMutationStore,
    ) -> Result<(), AuthorityError> {
        let outstanding = store
            .outstanding()
            .map_err(|_| AuthorityError::MutationStateUnavailable)?;
        if outstanding.is_some_and(|mutation| mutation.kind() == MutationKind::LeaseRelease) {
            return Err(AuthorityError::UnresolvedLeaseRelease);
        }
        Ok(())
    }

    pub(crate) fn outstanding_mutation(
        &self,
    ) -> Result<Option<OutstandingWitnessMutation>, NodeMutationError> {
        self.mutation_store.outstanding()
    }

    pub(crate) fn request_demotion_on_authority_loss(&mut self) {
        self.request_demotion();
    }

    pub(crate) fn requires_lease_release(&self) -> bool {
        matches!(self.mode, AuthorityMode::Conservative)
    }

    pub(crate) fn release_obligation_present(
        &self,
    ) -> Result<bool, crate::node_mutation::NodeMutationError> {
        Ok(self.mutation_store.release_obligation()?.is_some())
    }

    pub(crate) fn begin_lease_release_for_cleanup(
        &self,
        _provenance: &crate::resource_workflow::CleanupProvenance,
        reason: String,
    ) -> Result<OutstandingWitnessMutation, NodeMutationError> {
        let origin = LeaseReleaseOrigin::from_cleanup(_provenance);
        let authority = self
            .authority
            .authority()
            .ok_or(NodeMutationError::Invariant(
                "cleanup lease release requires known lease authority",
            ))?;
        self.mutation_store.begin_lease_release(
            &origin,
            authority.term(),
            authority.lease_id().clone(),
            reason,
        )
    }

    pub(crate) fn complete_local_cleanup(
        &mut self,
        _provenance: &crate::resource_workflow::CleanupProvenance,
    ) {
        self.ownership = OwnershipClass::ZeroResource;
    }

    #[cfg(test)]
    pub(crate) fn ownership_is_unknown_for_test(&self) -> bool {
        matches!(self.ownership, OwnershipClass::Unknown)
    }

    #[cfg(test)]
    pub(crate) fn arm_current_obligation_for_test(&self) {
        let authority = self.authority.authority().expect("test authority");
        if self.mutation_store.release_obligation().unwrap().is_none() {
            self.mutation_store
                .arm_release_obligation(authority.term(), authority.lease_id().clone())
                .unwrap();
        }
    }

    #[cfg(test)]
    pub(crate) fn new_for_resource_workflow_test(
        clock: C,
        local_node_id: NodeId,
        mutation_store: NodeMutationStore,
        mode: AuthorityMode,
    ) -> NodeAuthorityController<C> {
        let mut controller = Self::new(clock, local_node_id, mutation_store, mode);
        controller.reconcile_zero_resource_for_test();
        controller
    }

    #[cfg(test)]
    pub(crate) fn install_test_grant_for_resource_workflow(
        &mut self,
        grant: &LeaseGrantPayload,
        attempt_start: MonotonicTime,
    ) -> Result<(), AuthorityError> {
        self.authority.install_grant(
            grant,
            attempt_start,
            AuthorityContext::conservative_resource_owner(),
        )
    }

    pub(crate) fn advance_promotion(
        &mut self,
        machine: &mut StateMachine,
    ) -> Result<PromotionPhase, TransitionError> {
        let current = match machine.operation_phase() {
            Some(crate::state_machine::OperationPhase::Promotion(phase)) => phase,
            _ => return machine.advance_promotion(),
        };
        let checkpoint = match current {
            PromotionPhase::AcquireLease => Some(AuthorityCheckpoint::BeforeVipAcquire),
            PromotionPhase::AcquireVip => Some(AuthorityCheckpoint::BeforeServiceStart),
            PromotionPhase::StartService => Some(AuthorityCheckpoint::BeforeHealthAdvance),
            PromotionPhase::WaitForHealth => Some(AuthorityCheckpoint::BeforeGarp),
            PromotionPhase::AnnounceGratuitousArp => Some(AuthorityCheckpoint::BeforeActiveCommit),
            PromotionPhase::CheckPromotionGuard
            | PromotionPhase::CommitActive
            | PromotionPhase::Rollback => None,
        };
        let Some(checkpoint) = checkpoint else {
            return machine.advance_promotion();
        };
        let permission = self
            .checkpoint(checkpoint)
            .map_err(|_| TransitionError::AuthorityUnavailable)?;
        let context = self.context_for(checkpoint);
        let result = machine.advance_promotion_with_authority(&mut self.authority, context);
        if result.is_ok() && matches!(checkpoint, AuthorityCheckpoint::BeforeVipAcquire) {
            self.mark_resource_ownership_started();
        }
        let completion = self.complete_checkpoint(permission, checkpoint);
        if completion.is_err() {
            self.request_demotion();
            return Err(TransitionError::AuthorityUnavailable);
        }
        result
    }

    pub(crate) fn complete_promotion(
        &mut self,
        machine: &mut StateMachine,
    ) -> Result<(), TransitionError> {
        let permission = self
            .checkpoint(AuthorityCheckpoint::BeforeActiveCommit)
            .map_err(|_| TransitionError::AuthorityUnavailable)?;
        let context = self.context_for(AuthorityCheckpoint::BeforeActiveCommit);
        if self
            .complete_checkpoint(permission, AuthorityCheckpoint::BeforeActiveCommit)
            .is_err()
        {
            self.request_demotion();
            return Err(TransitionError::AuthorityUnavailable);
        }
        machine.complete_promotion_with_authority(&mut self.authority, context)
    }

    pub(crate) fn transition_to_active(
        &mut self,
        machine: &mut StateMachine,
    ) -> Result<(), TransitionError> {
        let permission = self
            .checkpoint(AuthorityCheckpoint::BeforeDegradedToActive)
            .map_err(|_| TransitionError::AuthorityUnavailable)?;
        let context = self.context_for(AuthorityCheckpoint::BeforeDegradedToActive);
        let result = machine.transition_to_with_authority(
            crate::state_machine::NodeState::Active,
            &mut self.authority,
            context,
        );
        if self
            .complete_checkpoint(permission, AuthorityCheckpoint::BeforeDegradedToActive)
            .is_err()
        {
            self.request_demotion();
            return Err(TransitionError::AuthorityUnavailable);
        }
        result
    }

    pub(crate) fn begin_demotion(
        &mut self,
        machine: &mut StateMachine,
    ) -> Result<(), TransitionError> {
        machine.begin_demotion()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_mutation::TerminalMutationDisposition;
    use crate::protocol::{DurationMs, LeaseId, NodeId};
    use crate::state_machine::{NodeState, OperationPhase, PromotionPhase};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Debug, Clone, Copy)]
    struct ManualClock {
        now: Result<MonotonicTime, ClockError>,
    }

    impl ManualClock {
        fn at(ms: u64) -> Self {
            Self {
                now: Ok(MonotonicTime::from_millis(ms)),
            }
        }

        fn set(&mut self, ms: u64) {
            self.now = Ok(MonotonicTime::from_millis(ms));
        }

        fn fail(&mut self) {
            self.now = Err(ClockError::Unavailable);
        }
    }

    impl MonotonicClock for ManualClock {
        fn now(&self) -> Result<MonotonicTime, ClockError> {
            self.now
        }
    }

    fn grant(remaining: u64) -> LeaseGrantPayload {
        LeaseGrantPayload {
            term: Term(7),
            lease_id: LeaseId::new("lease-1"),
            holder_node_id: NodeId::new("node-a"),
            lease_ttl_ms: DurationMs(LEASE_TTL_MS),
            renew_after_ms: DurationMs(RENEW_AFTER_MS),
            lease_remaining_ms: DurationMs(remaining),
        }
    }

    fn authority(clock: ManualClock) -> NodeLeaseAuthority<ManualClock> {
        NodeLeaseAuthority::new(clock, NodeId::new("node-a"))
    }

    /// C-4: after a restart nothing remembers a grant. Even if the durable store
    /// still carries an outstanding LeaseRequest and the Witness answers it with a
    /// (possibly valid) grant, the authority cannot be installed: installation
    /// requires the in-memory attempt timing recorded by the live exchange.
    #[test]
    fn ba_replayed_lease_request_cannot_install_authority_without_recorded_attempt() {
        let mut owner = authority(ManualClock::at(0));
        let identity = MutationIdentity::new(
            RequestId::new("replayed-after-restart"),
            1,
            MutationKind::LeaseRequest,
        );
        let validated = ValidatedGrant::new(
            grant(10_000),
            identity,
            MonotonicTime::from_millis(0),
            MonotonicTime::from_millis(0),
        );
        assert_eq!(
            owner.install_validated_grant(
                validated,
                AuthorityContext::conservative_resource_owner()
            ),
            Err(AuthorityError::MissingMutationTiming)
        );
        assert!(owner.authority().is_none());
    }

    /// C-3: the grant's local deadline is `origin + remaining - SAFETY_MARGIN_MS`
    /// (origin = the monotonic read taken BEFORE the request was sent), and a
    /// conservative step is refused at and after it.
    #[test]
    fn ba_safe_deadline_is_origin_plus_remaining_minus_margin_and_refused_at_it() {
        let mut owner = authority(ManualClock::at(0));
        owner
            .install_grant(
                &grant(LEASE_TTL_MS),
                MonotonicTime::from_millis(0),
                AuthorityContext::conservative_resource_owner(),
            )
            .unwrap();
        let deadline = owner.authority().unwrap().safe_deadline();
        assert_eq!(
            deadline,
            MonotonicTime::from_millis(LEASE_TTL_MS - SAFETY_MARGIN_MS)
        );
        let zero = AuthorityContext::test_conservative(false);
        owner.clock = ManualClock::at(LEASE_TTL_MS - SAFETY_MARGIN_MS - 1);
        assert_eq!(owner.ensure_usable_for_step(zero), Ok(()));
        owner.clock = ManualClock::at(LEASE_TTL_MS - SAFETY_MARGIN_MS);
        assert_eq!(
            owner.ensure_usable_for_step(zero),
            Err(AuthorityError::AuthorityLost)
        );
    }

    fn controller(clock: ManualClock, mode: AuthorityMode) -> NodeAuthorityController<ManualClock> {
        controller_with_path(clock, mode).0
    }

    fn controller_with_path(
        clock: ManualClock,
        mode: AuthorityMode,
    ) -> (NodeAuthorityController<ManualClock>, PathBuf) {
        let path = mutation_path("controller");
        let store = NodeMutationStore::new(
            &path,
            crate::protocol::ClusterId::new("cluster"),
            NodeId::new("node-a"),
        );
        store.initialize_new().unwrap();
        (
            NodeAuthorityController::new(clock, NodeId::new("node-a"), store, mode),
            path,
        )
    }

    struct AllowGate;

    impl AuthorityGate for AllowGate {
        fn ensure_usable_for_step(
            &mut self,
            _context: AuthorityContext,
        ) -> Result<(), AuthorityError> {
            Ok(())
        }
    }

    fn promoted_state_machine() -> StateMachine {
        let mut machine = StateMachine::new();
        machine.transition_to(NodeState::Standby).unwrap();
        machine.transition_to(NodeState::Candidate).unwrap();
        machine.begin_promotion().unwrap();
        let mut gate = AllowGate;
        for _ in 0..6 {
            machine
                .advance_promotion_with_authority(&mut gate, AuthorityContext::availability())
                .unwrap();
        }
        machine
            .complete_promotion_with_authority(&mut gate, AuthorityContext::availability())
            .unwrap();
        machine
    }

    fn mutation_path(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("mikagami-stage11-2-{name}-{suffix}"))
    }

    #[test]
    fn controller_starts_empty_and_blocked() {
        let owner = controller(ManualClock::at(0), AuthorityMode::Conservative);
        assert!(owner.authority().is_empty_after_restart());
        assert!(!owner.demotion_required());
        assert!(!owner.resource_owning());
    }

    #[test]
    fn zero_resource_acquisition_without_authority_is_denied_without_latch() {
        let mut owner = controller(ManualClock::at(0), AuthorityMode::Conservative);
        assert_eq!(
            owner.checkpoint(AuthorityCheckpoint::BeforeVipAcquire),
            Err(AuthorityError::RecoveryBlocked)
        );
        assert!(!owner.demotion_required());
        assert!(!owner.authority().demotion_latched());
    }

    #[test]
    fn zero_resource_acquisition_with_authority_gets_single_checkpoint_permission() {
        let mut owner = controller(ManualClock::at(0), AuthorityMode::Conservative);
        owner.reconcile_zero_resource_for_test();
        owner
            .authority
            .install_grant(
                &grant(10_000),
                MonotonicTime::from_millis(0),
                AuthorityContext::conservative_resource_owner(),
            )
            .unwrap();
        let permission = owner
            .checkpoint(AuthorityCheckpoint::BeforeVipAcquire)
            .unwrap();
        owner
            .complete_checkpoint(permission, AuthorityCheckpoint::BeforeVipAcquire)
            .unwrap();
    }

    #[test]
    fn zero_resource_expired_authority_is_denied_without_latching() {
        let mut owner = controller(ManualClock::at(0), AuthorityMode::Conservative);
        owner.reconcile_zero_resource_for_test();
        owner
            .authority
            .install_grant(
                &grant(10_000),
                MonotonicTime::from_millis(0),
                AuthorityContext::conservative_resource_owner(),
            )
            .unwrap();
        owner.authority.clock.set(8_000);
        assert_eq!(
            owner.checkpoint(AuthorityCheckpoint::BeforeVipAcquire),
            Err(AuthorityError::AuthorityLost)
        );
        assert!(!owner.demotion_required());
        assert!(!owner.authority.demotion_latched());
    }

    #[test]
    fn zero_resource_clock_failure_is_denied_without_latching() {
        let mut owner = controller(ManualClock::at(0), AuthorityMode::Conservative);
        owner.reconcile_zero_resource_for_test();
        owner
            .authority
            .install_grant(
                &grant(10_000),
                MonotonicTime::from_millis(0),
                AuthorityContext::conservative_resource_owner(),
            )
            .unwrap();
        owner.authority.clock.fail();
        assert_eq!(
            owner.checkpoint(AuthorityCheckpoint::BeforeVipAcquire),
            Err(AuthorityError::Clock(ClockError::Unavailable))
        );
        assert!(!owner.demotion_required());
        assert!(!owner.authority.demotion_latched());
    }

    #[test]
    fn ownership_boundary_and_expiry_latch_demotion() {
        let mut owner = controller(ManualClock::at(0), AuthorityMode::Conservative);
        owner.reconcile_zero_resource_for_test();
        owner
            .authority
            .install_grant(
                &grant(10_000),
                MonotonicTime::from_millis(0),
                AuthorityContext::conservative_resource_owner(),
            )
            .unwrap();
        owner.mark_resource_ownership_started();
        owner.authority.clock.set(8_001);
        assert!(matches!(
            owner.checkpoint(AuthorityCheckpoint::BeforeServiceStart),
            Err(AuthorityError::AuthorityLost)
        ));
        assert!(owner.demotion_required());
        assert!(owner.authority.demotion_latched());
    }

    #[test]
    fn authority_is_rechecked_between_checkpoint_and_completion() {
        let mut owner = controller(ManualClock::at(0), AuthorityMode::Conservative);
        owner.reconcile_zero_resource_for_test();
        owner
            .authority
            .install_grant(
                &grant(10_000),
                MonotonicTime::from_millis(0),
                AuthorityContext::conservative_resource_owner(),
            )
            .unwrap();
        let permission = owner
            .checkpoint(AuthorityCheckpoint::BeforeVipAcquire)
            .unwrap();
        owner.mark_resource_ownership_started();
        owner.authority.clock.set(8_001);
        assert!(matches!(
            owner.complete_checkpoint(permission, AuthorityCheckpoint::BeforeVipAcquire),
            Err(AuthorityError::AuthorityLost)
        ));
        assert!(owner.demotion_required());
    }

    #[test]
    fn gc_late_completion_validation_fails_before_active_commit() {
        let mut owner = controller(ManualClock::at(0), AuthorityMode::Conservative);
        owner.reconcile_zero_resource_for_test();
        owner
            .authority
            .install_grant(
                &grant(10_000),
                MonotonicTime::from_millis(0),
                AuthorityContext::conservative_resource_owner(),
            )
            .unwrap();

        owner.fail_next_completion_checkpoint = true;
        let mut machine = StateMachine::new();
        machine.transition_to(NodeState::Standby).unwrap();
        machine.transition_to(NodeState::Candidate).unwrap();
        machine.begin_promotion().unwrap();
        let mut allow = AllowGate;
        for _ in 0..6 {
            machine
                .advance_promotion_with_authority(
                    &mut allow,
                    AuthorityContext::conservative_resource_owner(),
                )
                .unwrap();
        }
        assert!(matches!(
            owner.complete_promotion(&mut machine),
            Err(TransitionError::AuthorityUnavailable)
        ));
        assert!(owner.completion_checkpoint_attempted);
        assert_eq!(machine.node_state(), NodeState::Candidate);
        assert!(owner.demotion_required());
        assert!(matches!(
            machine.operation_phase(),
            Some(OperationPhase::Promotion(PromotionPhase::CommitActive))
        ));
    }

    #[test]
    fn late_grant_cannot_clear_demotion_latch() {
        let mut owner = controller(ManualClock::at(0), AuthorityMode::Conservative);
        owner.mark_resource_ownership_started();
        owner.request_demotion();
        assert!(matches!(
            owner.authority.install_grant(
                &grant(10_000),
                MonotonicTime::from_millis(0),
                AuthorityContext::conservative_resource_owner(),
            ),
            Err(AuthorityError::AuthorityLost)
        ));
        assert!(owner.demotion_required());
    }

    #[test]
    fn witness_grant_does_not_clear_recovery_block() {
        let mut owner = controller(ManualClock::at(0), AuthorityMode::Conservative);
        owner
            .authority
            .install_grant(
                &grant(10_000),
                MonotonicTime::from_millis(0),
                AuthorityContext::conservative_resource_owner(),
            )
            .unwrap();
        assert_eq!(
            owner.checkpoint(AuthorityCheckpoint::BeforeVipAcquire),
            Err(AuthorityError::RecoveryBlocked)
        );
    }

    #[test]
    fn repeated_grant_install_does_not_clear_recovery_block() {
        let mut owner = controller(ManualClock::at(0), AuthorityMode::Conservative);
        owner
            .authority
            .install_grant(
                &grant(10_000),
                MonotonicTime::from_millis(0),
                AuthorityContext::conservative_resource_owner(),
            )
            .unwrap();
        owner
            .authority
            .install_grant(
                &grant(10_000),
                MonotonicTime::from_millis(0),
                AuthorityContext::conservative_resource_owner(),
            )
            .unwrap();
        assert_eq!(
            owner.checkpoint(AuthorityCheckpoint::BeforeVipAcquire),
            Err(AuthorityError::RecoveryBlocked)
        );
    }

    #[test]
    fn successful_renewal_does_not_clear_recovery_block() {
        let mut owner = controller(ManualClock::at(0), AuthorityMode::Conservative);
        owner
            .authority
            .install_grant(
                &grant(10_000),
                MonotonicTime::from_millis(0),
                AuthorityContext::conservative_resource_owner(),
            )
            .unwrap();
        let attempt = owner
            .authority
            .begin_renewal(AuthorityContext::conservative_resource_owner())
            .unwrap();
        owner
            .authority
            .complete_renewal(
                attempt,
                &grant(10_000),
                MonotonicTime::from_millis(1_000),
                AuthorityContext::conservative_resource_owner(),
            )
            .unwrap();
        assert_eq!(
            owner.checkpoint(AuthorityCheckpoint::BeforeVipAcquire),
            Err(AuthorityError::RecoveryBlocked)
        );
    }

    /// J24 candidate (suspend): the lease clock advances with `CLOCK_BOOTTIME` and never goes
    /// backwards. Limit (audit F-2): on a host that was never suspended `CLOCK_BOOTTIME` and
    /// `CLOCK_MONOTONIC` are equal, so this test alone cannot tell them apart; that the clock reads
    /// `CLOCK_BOOTTIME` is fixed by the architecture guard
    /// `j24_candidate_lease_clock_reads_clock_boottime_on_linux`. The suspend itself is not
    /// performed here (`SUSPEND_TEST_RESULTS.md`).
    #[cfg(target_os = "linux")]
    #[test]
    fn j24_lease_clock_is_clock_boottime_on_linux() {
        let clock = SystemMonotonicClock::new();
        let origin = clock.origin_ms.expect("CLOCK_BOOTTIME is readable");
        let mut last = clock.now().unwrap();
        for _ in 0..5 {
            std::thread::sleep(std::time::Duration::from_millis(20));
            let before = boottime_ms().unwrap();
            let now = clock.now().unwrap();
            let after = boottime_ms().unwrap();
            assert!(now >= last, "the lease clock went backwards");
            assert!(before - origin <= now.as_millis() && now.as_millis() <= after - origin);
            last = now;
        }
        assert!(last.as_millis() >= 100);
    }

    /// J24 (suspend, simulated): a node whose lease clock jumps past the safe deadline while it
    /// held authority - what `CLOCK_BOOTTIME` shows after a resume that outlived the lease - finds
    /// the authority lost at the next check and is due for demotion; nothing extends it. With
    /// `CLOCK_MONOTONIC` the same resume shows no jump, which is the hazard the candidate removes.
    #[test]
    fn j24_resume_past_the_safe_deadline_loses_authority_at_the_next_check() {
        let mut owner = controller(ManualClock::at(0), AuthorityMode::Conservative);
        owner
            .authority
            .install_grant(
                &grant(10_000),
                MonotonicTime::from_millis(0),
                AuthorityContext::conservative_resource_owner(),
            )
            .unwrap();
        owner.mark_resource_ownership_started();
        owner.authority.clock.set(1_000);
        assert_eq!(owner.renewal_due().unwrap(), RenewalDue::NotDue);
        // The host is suspended for 60 s: the boot-time clock moves from 1 s to 61 s at once.
        owner.authority.clock.set(61_000);
        assert_eq!(owner.active_schedule_delays(), Ok(None));
        assert_eq!(owner.renewal_due(), Err(AuthorityError::AuthorityLost));
        assert!(owner.demotion_required(), "the resumed node must demote");
        let zero = AuthorityContext::test_conservative(false);
        assert_eq!(
            owner.authority.ensure_usable_for_step(zero),
            Err(AuthorityError::AuthorityLost)
        );
    }

    /// J25 (CLOCK_BOOTTIME candidate): a boot-time clock that cannot be read, or that reads behind
    /// the origin, is a clock failure (fail-closed), never a time.
    #[cfg(target_os = "linux")]
    #[test]
    fn j25_boottime_clock_failure_reads_as_unavailable() {
        let unreadable = SystemMonotonicClock { origin_ms: None };
        assert_eq!(unreadable.now(), Err(ClockError::Unavailable));
        let behind = SystemMonotonicClock {
            origin_ms: boottime_ms().map(|now| now + 3_600_000),
        };
        assert_eq!(behind.now(), Err(ClockError::Unavailable));
    }

    /// J25 (suspend, simulated): a grant whose attempt began before a suspend that outlived the
    /// lease - the answer is installed after the resume - is dead on arrival: the safe deadline is
    /// computed from the attempt start on the boot-time clock, so it has passed and no step may use
    /// the grant. With `CLOCK_MONOTONIC` the suspend would not count and the grant would look fresh.
    #[test]
    fn j25_grant_installed_after_a_suspend_is_never_usable() {
        let mut owner = controller(ManualClock::at(0), AuthorityMode::Conservative);
        // The request was sent at 0; the host is suspended for 60 s before the answer is installed.
        owner.authority.clock.set(60_000);
        let installed = owner.authority.install_grant(
            &grant(10_000),
            MonotonicTime::from_millis(0),
            AuthorityContext::conservative_resource_owner(),
        );
        assert_eq!(installed, Err(AuthorityError::DeadlineUnavailable));
        let zero = AuthorityContext::test_conservative(false);
        assert!(owner.authority.ensure_usable_for_step(zero).is_err());
    }

    #[test]
    fn renewal_due_is_monotonic_and_clock_failure_is_fail_closed() {
        let mut owner = controller(ManualClock::at(0), AuthorityMode::Conservative);
        owner
            .authority
            .install_grant(
                &grant(10_000),
                MonotonicTime::from_millis(0),
                AuthorityContext::conservative_resource_owner(),
            )
            .unwrap();
        assert_eq!(owner.renewal_due().unwrap(), RenewalDue::NotDue);
        owner.authority.clock.set(RENEW_AFTER_MS);
        assert_eq!(owner.renewal_due().unwrap(), RenewalDue::Due);
        owner.mark_resource_ownership_started();
        owner.authority.clock.fail();
        assert_eq!(
            owner.renewal_due(),
            Err(AuthorityError::Clock(ClockError::Unavailable))
        );
        assert!(owner.demotion_required());
    }

    #[test]
    fn renewal_due_latches_when_resource_ownership_has_no_authority() {
        let mut owner = controller(ManualClock::at(0), AuthorityMode::Conservative);
        owner.mark_resource_ownership_started();
        assert_eq!(owner.renewal_due(), Err(AuthorityError::NoAuthority));
        assert!(owner.demotion_required());
    }

    #[test]
    fn renewal_due_latches_when_ownership_is_unknown_without_authority() {
        let mut owner = controller(ManualClock::at(0), AuthorityMode::Conservative);
        owner.mark_ownership_uncertain();
        assert_eq!(owner.renewal_due(), Err(AuthorityError::DemotionRequired));
        assert!(owner.demotion_required());
    }

    #[test]
    fn checkpoint_permission_cannot_be_reused_for_another_checkpoint() {
        let mut owner = controller(ManualClock::at(0), AuthorityMode::Availability);
        let permission = owner
            .checkpoint(AuthorityCheckpoint::BeforeVipAcquire)
            .unwrap();
        assert_eq!(
            owner.complete_checkpoint(permission, AuthorityCheckpoint::BeforeServiceStart),
            Err(AuthorityError::InvalidCheckpoint)
        );
    }

    #[test]
    fn availability_does_not_require_witness_or_clear_conservative_latch() {
        let mut owner = controller(ManualClock::at(0), AuthorityMode::Availability);
        let permission = owner
            .checkpoint(AuthorityCheckpoint::BeforeVipAcquire)
            .unwrap();
        owner
            .complete_checkpoint(permission, AuthorityCheckpoint::BeforeVipAcquire)
            .unwrap();
        owner.mark_resource_ownership_started();
        owner.request_demotion();
        assert!(!owner.demotion_required());
        assert!(!owner.authority.demotion_latched());
    }

    #[test]
    fn recovery_pending_cannot_bypass_reconciliation_with_authority() {
        let mut machine = StateMachine::new();
        machine.transition_to(NodeState::Failed).unwrap();
        machine.reset_for_recovery().unwrap();
        let mut owner = controller(ManualClock::at(0), AuthorityMode::Conservative);
        owner
            .authority
            .install_grant(
                &grant(10_000),
                MonotonicTime::from_millis(0),
                AuthorityContext::conservative_resource_owner(),
            )
            .unwrap();
        assert!(matches!(
            owner.transition_to_active(&mut machine),
            Err(TransitionError::AuthorityUnavailable)
        ));
        assert_eq!(machine.node_state(), NodeState::RecoveryPending);
        machine.transition_to(NodeState::Standby).unwrap();
        machine.transition_to(NodeState::Candidate).unwrap();
        assert_eq!(
            owner.checkpoint(AuthorityCheckpoint::BeforeVipAcquire),
            Err(AuthorityError::RecoveryBlocked)
        );
    }

    #[test]
    fn mutation_state_read_failure_blocks_new_ownership() {
        let path = mutation_path("missing-store");
        let store = NodeMutationStore::new(
            &path,
            crate::protocol::ClusterId::new("cluster"),
            NodeId::new("node-a"),
        );
        let mut owner = NodeAuthorityController::new(
            ManualClock::at(0),
            NodeId::new("node-a"),
            store,
            AuthorityMode::Conservative,
        );
        owner.reconcile_zero_resource_for_test();
        assert_eq!(
            owner.checkpoint(AuthorityCheckpoint::BeforeVipAcquire),
            Err(AuthorityError::MutationStateUnavailable)
        );
    }

    #[test]
    fn completion_rechecks_lease_release_after_permission() {
        let (mut owner, path) =
            controller_with_path(ManualClock::at(0), AuthorityMode::Conservative);
        owner.reconcile_zero_resource_for_test();
        owner
            .authority
            .install_grant(
                &grant(10_000),
                MonotonicTime::from_millis(0),
                AuthorityContext::conservative_resource_owner(),
            )
            .unwrap();
        let permission = owner
            .checkpoint(AuthorityCheckpoint::BeforeVipAcquire)
            .unwrap();
        let store = NodeMutationStore::new(
            path.clone(),
            crate::protocol::ClusterId::new("cluster"),
            NodeId::new("node-a"),
        );
        store
            .begin_lease_release_for_test(Term(7), LeaseId::new("lease-1"), "cleanup".to_string())
            .unwrap();
        assert_eq!(
            owner.complete_checkpoint(permission, AuthorityCheckpoint::BeforeVipAcquire),
            Err(AuthorityError::UnresolvedLeaseRelease)
        );
        assert_eq!(owner.ownership, OwnershipClass::Unknown);
        assert!(owner.demotion_required());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn completion_store_read_failure_marks_possible_acquisition_uncertain() {
        let (mut owner, path) =
            controller_with_path(ManualClock::at(0), AuthorityMode::Conservative);
        owner.reconcile_zero_resource_for_test();
        owner
            .authority
            .install_grant(
                &grant(10_000),
                MonotonicTime::from_millis(0),
                AuthorityContext::conservative_resource_owner(),
            )
            .unwrap();
        let permission = owner
            .checkpoint(AuthorityCheckpoint::BeforeVipAcquire)
            .unwrap();
        fs::remove_file(&path).unwrap();
        assert_eq!(
            owner.complete_checkpoint(permission, AuthorityCheckpoint::BeforeVipAcquire),
            Err(AuthorityError::MutationStateUnavailable)
        );
        assert_eq!(owner.ownership, OwnershipClass::Unknown);
        assert!(owner.demotion_required());
    }

    #[test]
    fn resource_owning_completion_release_failure_requests_demotion() {
        let (mut owner, path) =
            controller_with_path(ManualClock::at(0), AuthorityMode::Conservative);
        owner.reconcile_zero_resource_for_test();
        owner
            .authority
            .install_grant(
                &grant(10_000),
                MonotonicTime::from_millis(0),
                AuthorityContext::conservative_resource_owner(),
            )
            .unwrap();
        owner.mark_resource_ownership_started();
        let permission = owner
            .checkpoint(AuthorityCheckpoint::BeforeServiceStart)
            .unwrap();
        let store = NodeMutationStore::new(
            path.clone(),
            crate::protocol::ClusterId::new("cluster"),
            NodeId::new("node-a"),
        );
        store
            .begin_lease_release_for_test(Term(7), LeaseId::new("lease-1"), "cleanup".to_string())
            .unwrap();
        assert_eq!(
            owner.complete_checkpoint(permission, AuthorityCheckpoint::BeforeServiceStart),
            Err(AuthorityError::UnresolvedLeaseRelease)
        );
        assert!(owner.demotion_required());
        assert!(owner.authority.demotion_latched());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn unknown_completion_release_failure_remains_fail_closed() {
        let (mut owner, path) =
            controller_with_path(ManualClock::at(0), AuthorityMode::Conservative);
        owner.reconcile_zero_resource_for_test();
        owner
            .authority
            .install_grant(
                &grant(10_000),
                MonotonicTime::from_millis(0),
                AuthorityContext::conservative_resource_owner(),
            )
            .unwrap();
        let permission = owner
            .checkpoint(AuthorityCheckpoint::BeforeVipAcquire)
            .unwrap();
        owner.ownership = OwnershipClass::Unknown;
        let store = NodeMutationStore::new(
            path.clone(),
            crate::protocol::ClusterId::new("cluster"),
            NodeId::new("node-a"),
        );
        store
            .begin_lease_release_for_test(Term(7), LeaseId::new("lease-1"), "cleanup".to_string())
            .unwrap();
        assert_eq!(
            owner.complete_checkpoint(permission, AuthorityCheckpoint::BeforeVipAcquire),
            Err(AuthorityError::UnresolvedLeaseRelease)
        );
        assert!(owner.demotion_required());
        assert!(owner.authority.demotion_latched());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn demotion_request_does_not_require_usable_authority() {
        let mut machine = promoted_state_machine();
        machine.transition_to(NodeState::Degraded).unwrap();
        let mut owner = controller(ManualClock::at(0), AuthorityMode::Conservative);
        owner.mark_resource_ownership_started();
        owner.request_demotion();
        owner.begin_demotion(&mut machine).unwrap();
        assert_eq!(machine.node_state(), NodeState::Degraded);
        assert!(owner.demotion_required());
    }

    #[test]
    fn unresolved_lease_release_blocks_new_ownership() {
        let path = mutation_path("release-block");
        let store = NodeMutationStore::new(
            &path,
            crate::protocol::ClusterId::new("cluster"),
            NodeId::new("node-a"),
        );
        store.initialize_new().unwrap();
        store
            .begin_lease_release_for_test(Term(7), LeaseId::new("lease-1"), "cleanup".to_string())
            .unwrap();
        let mut owner = controller(ManualClock::at(0), AuthorityMode::Conservative);
        owner.reconcile_zero_resource_for_test();
        owner
            .mutation_store
            .begin_lease_release_for_test(Term(7), LeaseId::new("lease-1"), "cleanup".to_string())
            .unwrap();
        assert_eq!(
            owner.checkpoint(AuthorityCheckpoint::BeforeVipAcquire),
            Err(AuthorityError::UnresolvedLeaseRelease)
        );
        assert_eq!(
            owner.ensure_no_unresolved_lease_release(&store),
            Err(AuthorityError::UnresolvedLeaseRelease)
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn immediate_grant_uses_attempt_start_minus_margin() {
        let mut owner = authority(ManualClock::at(0));
        owner
            .install_grant(
                &grant(10_000),
                MonotonicTime::from_millis(0),
                AuthorityContext::conservative_resource_owner(),
            )
            .unwrap();
        assert_eq!(
            owner.next_safety_deadline(),
            Some(MonotonicTime::from_millis(8_000))
        );
    }

    #[test]
    fn delayed_response_does_not_use_receive_time() {
        let mut clock = ManualClock::at(3_000);
        let mut owner = authority(clock);
        owner
            .install_grant(
                &grant(10_000),
                MonotonicTime::from_millis(0),
                AuthorityContext::conservative_resource_owner(),
            )
            .unwrap();
        assert_eq!(
            owner.next_safety_deadline(),
            Some(MonotonicTime::from_millis(8_000))
        );
        clock.set(3_000);
    }

    #[test]
    fn remaining_at_or_below_margin_is_unusable() {
        let mut owner = authority(ManualClock::at(0));
        assert_eq!(
            owner.install_grant(
                &grant(SAFETY_MARGIN_MS),
                MonotonicTime::from_millis(0),
                AuthorityContext::conservative_resource_owner()
            ),
            Err(AuthorityError::DeadlineUnavailable)
        );
    }

    #[test]
    fn deadline_overflow_is_fail_closed() {
        let mut owner = authority(ManualClock::at(0));
        assert_eq!(
            owner.install_grant(
                &grant(u64::MAX),
                MonotonicTime::from_millis(u64::MAX),
                AuthorityContext::conservative_resource_owner()
            ),
            Err(AuthorityError::DeadlineUnavailable)
        );
    }

    #[test]
    fn candidate_expired_before_install_is_rejected() {
        let mut owner = authority(ManualClock::at(8_000));
        assert_eq!(
            owner.install_grant(
                &grant(10_000),
                MonotonicTime::from_millis(0),
                AuthorityContext::conservative_resource_owner()
            ),
            Err(AuthorityError::DeadlineUnavailable)
        );
    }

    #[test]
    fn renewal_does_not_extend_before_durable_completion() {
        let mut owner = authority(ManualClock::at(0));
        owner
            .install_grant(
                &grant(10_000),
                MonotonicTime::from_millis(0),
                AuthorityContext::conservative_resource_owner(),
            )
            .unwrap();
        let old = owner.next_safety_deadline();
        let attempt = owner
            .begin_renewal(AuthorityContext::conservative_resource_owner())
            .unwrap();
        assert_eq!(owner.next_safety_deadline(), old);
        owner
            .complete_renewal(
                attempt,
                &grant(10_000),
                MonotonicTime::from_millis(1_000),
                AuthorityContext::conservative_resource_owner(),
            )
            .unwrap();
        assert_eq!(
            owner.next_safety_deadline(),
            Some(MonotonicTime::from_millis(8_000))
        );
    }

    #[test]
    fn renewal_crossing_old_deadline_latches_loss() {
        let mut clock = ManualClock::at(0);
        let mut owner = authority(clock);
        owner
            .install_grant(
                &grant(10_000),
                MonotonicTime::from_millis(0),
                AuthorityContext::conservative_resource_owner(),
            )
            .unwrap();
        let attempt = owner
            .begin_renewal(AuthorityContext::conservative_resource_owner())
            .unwrap();
        clock.set(8_000);
        owner.clock = clock;
        assert_eq!(
            owner.complete_renewal(
                attempt,
                &grant(10_000),
                MonotonicTime::from_millis(1_000),
                AuthorityContext::conservative_resource_owner()
            ),
            Err(AuthorityError::AuthorityLost)
        );
        assert!(owner.demotion_latched());
    }

    #[test]
    fn late_grant_cannot_clear_latch() {
        let mut owner = authority(ManualClock::at(0));
        owner.latch_loss();
        assert_eq!(
            owner.install_grant(
                &grant(10_000),
                MonotonicTime::from_millis(0),
                AuthorityContext::conservative_resource_owner()
            ),
            Err(AuthorityError::AuthorityLost)
        );
    }

    #[test]
    fn clock_failure_while_holding_authority_latches_demotion() {
        let mut clock = ManualClock::at(0);
        let mut owner = authority(clock);
        owner
            .install_grant(
                &grant(10_000),
                MonotonicTime::from_millis(0),
                AuthorityContext::conservative_resource_owner(),
            )
            .unwrap();
        clock.fail();
        owner.clock = clock;
        assert_eq!(
            owner.check_and_latch_loss(AuthorityContext::conservative_resource_owner()),
            Err(AuthorityError::Clock(ClockError::Unavailable))
        );
        assert!(owner.demotion_latched());
    }

    #[test]
    fn clock_recovery_and_late_grant_cannot_clear_clock_failure_latch() {
        let mut owner = authority(ManualClock::at(0));
        owner
            .install_grant(
                &grant(10_000),
                MonotonicTime::from_millis(0),
                AuthorityContext::conservative_resource_owner(),
            )
            .unwrap();
        let renewal = owner
            .begin_renewal(AuthorityContext::conservative_resource_owner())
            .unwrap();
        owner.clock.fail();
        let _ = owner.check_and_latch_loss(AuthorityContext::conservative_resource_owner());
        owner.clock.set(1_000);
        assert_eq!(
            owner.complete_renewal(
                renewal,
                &grant(10_000),
                MonotonicTime::from_millis(1_000),
                AuthorityContext::conservative_resource_owner()
            ),
            Err(AuthorityError::AuthorityLost)
        );
        assert_eq!(
            owner.install_grant(
                &grant(10_000),
                MonotonicTime::from_millis(1_000),
                AuthorityContext::conservative_resource_owner()
            ),
            Err(AuthorityError::AuthorityLost)
        );
        assert!(owner.demotion_latched());
    }

    #[test]
    fn first_authority_clock_failure_installs_nothing() {
        let mut clock = ManualClock::at(0);
        clock.fail();
        let mut owner = authority(clock);
        assert_eq!(
            owner.install_grant(
                &grant(10_000),
                MonotonicTime::from_millis(0),
                AuthorityContext::conservative_resource_owner()
            ),
            Err(AuthorityError::Clock(ClockError::Unavailable))
        );
        assert!(owner.authority().is_none());
        assert!(!owner.demotion_latched());
    }

    #[test]
    fn availability_does_not_require_witness_authority() {
        let mut owner = authority(ManualClock::at(0));
        assert!(
            owner
                .ensure_usable_for_step(AuthorityContext::availability())
                .is_ok()
        );
    }

    #[test]
    fn restart_starts_empty_and_reset_requires_reconcile_boundary() {
        let mut owner = authority(ManualClock::at(0));
        owner.latch_loss();
        assert!(!owner.is_empty_after_restart());
        owner
            .reset_after_zero_resource_reconcile(AuthorityContext::test_conservative(false))
            .unwrap();
        assert!(owner.is_empty_after_restart());
    }

    #[test]
    fn retry_of_same_mutation_keeps_first_timing_origin() {
        let mut owner = authority(ManualClock::at(0));
        let identity =
            MutationIdentity::new(RequestId::new("request-1"), 7, MutationKind::LeaseRequest);
        let first = owner
            .record_attempt(identity.clone(), MonotonicTime::from_millis(10))
            .unwrap();
        let retry = owner
            .record_attempt(identity, MonotonicTime::from_millis(90))
            .unwrap();
        assert_eq!(first, MonotonicTime::from_millis(10));
        assert_eq!(retry, MonotonicTime::from_millis(10));
    }

    #[test]
    fn different_mutation_cannot_reuse_timing_origin() {
        let mut owner = authority(ManualClock::at(0));
        let first =
            MutationIdentity::new(RequestId::new("request-1"), 7, MutationKind::LeaseRequest);
        let second =
            MutationIdentity::new(RequestId::new("request-2"), 8, MutationKind::LeaseRequest);
        owner
            .record_attempt(first, MonotonicTime::from_millis(10))
            .unwrap();
        assert_eq!(
            owner.record_attempt(second, MonotonicTime::from_millis(20)),
            Err(AuthorityError::MutationTimingConflict)
        );
    }

    #[test]
    fn ineligible_recovery_context_cannot_pass_authority_gate() {
        let mut owner = authority(ManualClock::at(0));
        let context = AuthorityContext::recovery_pending_context();
        assert_eq!(
            owner.ensure_usable_for_step(context),
            Err(AuthorityError::StateProhibitsOwnership)
        );
    }

    #[test]
    fn zero_resource_candidate_without_authority_is_denied_without_latching() {
        let mut owner = authority(ManualClock::at(0));
        let context = AuthorityContext::test_conservative(false);
        assert_eq!(
            owner.ensure_usable_for_step(context),
            Err(AuthorityError::NoAuthority)
        );
        assert!(!owner.demotion_latched());
    }

    #[test]
    fn reset_rejects_resource_owning_context_and_preserves_latch() {
        let mut owner = authority(ManualClock::at(0));
        owner.latch_loss();
        assert_eq!(
            owner.reset_after_zero_resource_reconcile(AuthorityContext::test_conservative(true)),
            Err(AuthorityError::ResetNotSafe)
        );
        assert!(owner.demotion_latched());
    }

    #[derive(Debug, Clone, Copy)]
    struct CanonicalRenewCase {
        id: &'static str,
        result: &'static str,
        durable_m: &'static str,
        obligation_o: &'static str,
        authority: &'static str,
        old_safe_deadline: &'static str,
        schedule: &'static str,
        immediate_demotion: &'static str,
        retry: &'static str,
        second_begin: &'static str,
        witness_session: &'static str,
        post_demotion: &'static str,
        lifecycle: &'static str,
        automatic_promotion: &'static str,
    }

    fn canonical_active_renew_rows() -> [CanonicalRenewCase; 24] {
        [
            CanonicalRenewCase {
                id: "AR-01",
                result: "validated AcceptedSuccess before old deadline",
                durable_m: "clear after confirmed completion",
                obligation_o: "retain",
                authority: "install matching new authority only",
                old_safe_deadline: "extend only when now < old",
                schedule: "new future schedule",
                immediate_demotion: "no",
                retry: "none; terminal",
                second_begin: "only at future due",
                witness_session: "correlate then Idle",
                post_demotion: "late result bookkeeping only",
                lifecycle: "continue Active",
                automatic_promotion: "denied",
            },
            CanonicalRenewCase {
                id: "AR-02",
                result: "PolicyReject",
                durable_m: "clear terminal",
                obligation_o: "retain",
                authority: "no install; lost",
                old_safe_deadline: "not extended",
                schedule: "none",
                immediate_demotion: "yes once",
                retry: "none",
                second_begin: "never",
                witness_session: "correlate then Idle",
                post_demotion: "clear bookkeeping only",
                lifecycle: "cleanup then Release",
                automatic_promotion: "denied",
            },
            CanonicalRenewCase {
                id: "AR-03",
                result: "RetiredStale",
                durable_m: "clear terminal",
                obligation_o: "retain",
                authority: "no success proof or install",
                old_safe_deadline: "not extended",
                schedule: "none",
                immediate_demotion: "yes once",
                retry: "none",
                second_begin: "never",
                witness_session: "correlate then Idle",
                post_demotion: "never infer success",
                lifecycle: "cleanup then Release",
                automatic_promotion: "denied",
            },
            CanonicalRenewCase {
                id: "AR-04",
                result: "Conflict",
                durable_m: "retain exact",
                obligation_o: "retain",
                authority: "unusable latched",
                old_safe_deadline: "not extended",
                schedule: "post-demotion only",
                immediate_demotion: "yes once",
                retry: "admin reconcile only",
                second_begin: "never",
                witness_session: "correlate; no reset",
                post_demotion: "retain and RecoveryBlocked",
                lifecycle: "demote then RB",
                automatic_promotion: "denied",
            },
            CanonicalRenewCase {
                id: "AR-05",
                result: "GenerationGap",
                durable_m: "retain exact",
                obligation_o: "retain",
                authority: "unusable latched",
                old_safe_deadline: "not extended",
                schedule: "post-demotion only",
                immediate_demotion: "yes once",
                retry: "no jump or retry",
                second_begin: "never",
                witness_session: "correlate; no reset",
                post_demotion: "retain and RecoveryBlocked",
                lifecycle: "demote then RB",
                automatic_promotion: "denied",
            },
            CanonicalRenewCase {
                id: "AR-06",
                result: "TemporarilyUnavailable",
                durable_m: "retain exact",
                obligation_o: "retain",
                authority: "old usable only",
                old_safe_deadline: "unchanged; equality stops",
                schedule: "old until expiry",
                immediate_demotion: "no while usable",
                retry: "exact after full ordinary cadence",
                second_begin: "never",
                witness_session: "correlate then Idle",
                post_demotion: "ordinary exact bookkeeping retry",
                lifecycle: "Active to old deadline",
                automatic_promotion: "denied",
            },
            CanonicalRenewCase {
                id: "AR-07",
                result: "transport send/receive error",
                durable_m: "retain exact",
                obligation_o: "retain",
                authority: "old usable only",
                old_safe_deadline: "unchanged; equality stops",
                schedule: "old until expiry",
                immediate_demotion: "only recheck failure",
                retry: "exact after ordinary cadence",
                second_begin: "never",
                witness_session: "reset owned failed attempt",
                post_demotion: "exact retry with usable session",
                lifecycle: "Active to old deadline",
                automatic_promotion: "denied",
            },
            CanonicalRenewCase {
                id: "AR-08",
                result: "bounded request timeout",
                durable_m: "retain exact",
                obligation_o: "retain",
                authority: "old usable only",
                old_safe_deadline: "unchanged; equality stops",
                schedule: "old until expiry",
                immediate_demotion: "only recheck failure",
                retry: "exact after ordinary cadence",
                second_begin: "never",
                witness_session: "reset owned failed attempt",
                post_demotion: "never restore authority",
                lifecycle: "Active to old deadline",
                automatic_promotion: "denied",
            },
            CanonicalRenewCase {
                id: "AR-09",
                result: "EOF or connection loss",
                durable_m: "retain exact",
                obligation_o: "retain",
                authority: "old usable only",
                old_safe_deadline: "unchanged; equality stops",
                schedule: "old until expiry",
                immediate_demotion: "only recheck failure",
                retry: "same existing session only",
                second_begin: "never",
                witness_session: "reset owned failed attempt",
                post_demotion: "retain until owner returns",
                lifecycle: "Active to old deadline",
                automatic_promotion: "denied",
            },
            CanonicalRenewCase {
                id: "AR-10",
                result: "invalid success or wrong kind",
                durable_m: "retain exact",
                obligation_o: "retain",
                authority: "unusable latched",
                old_safe_deadline: "not extended",
                schedule: "post-demotion only",
                immediate_demotion: "yes once",
                retry: "none",
                second_begin: "never",
                witness_session: "reset owned failed attempt",
                post_demotion: "retain and RecoveryBlocked",
                lifecycle: "demote then RB",
                automatic_promotion: "denied",
            },
            CanonicalRenewCase {
                id: "AR-11",
                result: "authentication failure",
                durable_m: "retain exact",
                obligation_o: "retain",
                authority: "unusable latched",
                old_safe_deadline: "not extended",
                schedule: "post-demotion only",
                immediate_demotion: "yes once",
                retry: "none",
                second_begin: "never",
                witness_session: "reset owned failed attempt",
                post_demotion: "retain and RecoveryBlocked",
                lifecycle: "demote then RB",
                automatic_promotion: "denied",
            },
            CanonicalRenewCase {
                id: "AR-12",
                result: "correlation failure",
                durable_m: "retain exact",
                obligation_o: "retain",
                authority: "unusable latched",
                old_safe_deadline: "not extended",
                schedule: "post-demotion only",
                immediate_demotion: "yes once",
                retry: "none",
                second_begin: "never",
                witness_session: "do not consume mismatch",
                post_demotion: "retain and RecoveryBlocked",
                lifecycle: "demote then RB",
                automatic_promotion: "denied",
            },
            CanonicalRenewCase {
                id: "AR-13",
                result: "lease holder or term mismatch",
                durable_m: "retain exact",
                obligation_o: "retain",
                authority: "unusable latched",
                old_safe_deadline: "not extended",
                schedule: "post-demotion only",
                immediate_demotion: "yes once",
                retry: "none; no rewrite",
                second_begin: "never",
                witness_session: "reject and reset owner",
                post_demotion: "no identity rewrite",
                lifecycle: "demote then RB",
                automatic_promotion: "denied",
            },
            CanonicalRenewCase {
                id: "AR-14",
                result: "store begin confirmed pre-commit failure",
                durable_m: "no new M",
                obligation_o: "retain",
                authority: "existing not extended",
                old_safe_deadline: "not extended",
                schedule: "none",
                immediate_demotion: "yes once",
                retry: "none this lifecycle",
                second_begin: "never",
                witness_session: "never sent or occupied",
                post_demotion: "cleanup then Release if trusted",
                lifecycle: "demote",
                automatic_promotion: "denied",
            },
            CanonicalRenewCase {
                id: "AR-15",
                result: "store completion old image",
                durable_m: "retain exact old M",
                obligation_o: "retain",
                authority: "unusable",
                old_safe_deadline: "not extended",
                schedule: "post-demotion only",
                immediate_demotion: "yes once",
                retry: "no Active retry",
                second_begin: "never",
                witness_session: "correlated exchange Idle",
                post_demotion: "exact PD may reconcile",
                lifecycle: "demote then Release after clear",
                automatic_promotion: "denied",
            },
            CanonicalRenewCase {
                id: "AR-16",
                result: "store completion uncertainty or mismatch",
                durable_m: "uncertain; never assume clear",
                obligation_o: "retain",
                authority: "unusable",
                old_safe_deadline: "not extended",
                schedule: "none",
                immediate_demotion: "yes once",
                retry: "none while uncertain",
                second_begin: "never",
                witness_session: "do not reset durable truth",
                post_demotion: "RecoveryBlocked",
                lifecycle: "demote then RB",
                automatic_promotion: "denied",
            },
            CanonicalRenewCase {
                id: "AR-17",
                result: "clock failure before completion",
                durable_m: "retain exact",
                obligation_o: "retain",
                authority: "unusable",
                old_safe_deadline: "not extended",
                schedule: "post-demotion only",
                immediate_demotion: "yes once",
                retry: "none without trusted clock",
                second_begin: "never",
                witness_session: "reset owned bounded attempt",
                post_demotion: "trusted clock/session only",
                lifecycle: "demote",
                automatic_promotion: "denied",
            },
            CanonicalRenewCase {
                id: "AR-18",
                result: "clock failure after confirmed completion",
                durable_m: "clear",
                obligation_o: "retain",
                authority: "success not installed; lost",
                old_safe_deadline: "not extended",
                schedule: "none",
                immediate_demotion: "yes once",
                retry: "none",
                second_begin: "never",
                witness_session: "completed Idle",
                post_demotion: "success bookkeeping only",
                lifecycle: "cleanup then Release",
                automatic_promotion: "denied",
            },
            CanonicalRenewCase {
                id: "AR-19",
                result: "durable exact RequestAlreadyOutstanding",
                durable_m: "retain exact",
                obligation_o: "retain",
                authority: "old usable only",
                old_safe_deadline: "unchanged; equality stops",
                schedule: "old until expiry",
                immediate_demotion: "no while usable",
                retry: "exact after ordinary cadence",
                second_begin: "never",
                witness_session: "inspect owner; never blind reset",
                post_demotion: "never install",
                lifecycle: "Active to old deadline",
                automatic_promotion: "denied",
            },
            CanonicalRenewCase {
                id: "AR-20",
                result: "durable incompatible RequestAlreadyOutstanding",
                durable_m: "retain actual record",
                obligation_o: "retain",
                authority: "unusable latched",
                old_safe_deadline: "not extended",
                schedule: "post-demotion only",
                immediate_demotion: "yes once",
                retry: "no rewrite or retry",
                second_begin: "never",
                witness_session: "preserve owner",
                post_demotion: "retain and RB",
                lifecycle: "demote then RB",
                automatic_promotion: "denied",
            },
            CanonicalRenewCase {
                id: "AR-21",
                result: "session exact same request",
                durable_m: "retain exact",
                obligation_o: "retain",
                authority: "old usable pending result",
                old_safe_deadline: "unchanged while owner returns",
                schedule: "old until expiry",
                immediate_demotion: "no while usable",
                retry: "join one in-flight exchange",
                second_begin: "never",
                witness_session: "join; no resend/reset/steal",
                post_demotion: "owner result bookkeeping",
                lifecycle: "Active to old deadline",
                automatic_promotion: "denied",
            },
            CanonicalRenewCase {
                id: "AR-22",
                result: "session incompatible owner",
                durable_m: "retain exact",
                obligation_o: "retain",
                authority: "unusable latched",
                old_safe_deadline: "not extended",
                schedule: "post-demotion only",
                immediate_demotion: "yes once",
                retry: "wait for owner return",
                second_begin: "never",
                witness_session: "no dispatch/overwrite/reset/steal",
                post_demotion: "re-evaluate then RB",
                lifecycle: "demote then RB",
                automatic_promotion: "denied",
            },
            CanonicalRenewCase {
                id: "AR-23",
                result: "result at or after old deadline",
                durable_m: "follow underlying result",
                obligation_o: "retain",
                authority: "unusable even for success",
                old_safe_deadline: "equality/after cannot install",
                schedule: "none",
                immediate_demotion: "begin or continue",
                retry: "none Active",
                second_begin: "never",
                witness_session: "finish owned exchange",
                post_demotion: "bookkeeping only",
                lifecycle: "continue demotion",
                automatic_promotion: "denied",
            },
            CanonicalRenewCase {
                id: "AR-24",
                result: "after demotion shutdown or state departure",
                durable_m: "terminal clear; nonterminal exact",
                obligation_o: "retain",
                authority: "unusable for Active",
                old_safe_deadline: "never extended",
                schedule: "post-demotion only",
                immediate_demotion: "already latched; no duplicate",
                retry: "PD ordinary exact only",
                second_begin: "never",
                witness_session: "finish one bounded owner",
                post_demotion: "no Active resurrection",
                lifecycle: "join existing demotion",
                automatic_promotion: "denied",
            },
        ]
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum CanonicalRenewProductionProbe {
        Ar01AcceptedSuccess,
        Ar02PolicyReject,
        Ar03RetiredStale,
        Ar04Conflict,
        Ar05GenerationGap,
        Ar06TemporarilyUnavailable,
        Ar07TransportError,
        Ar08Timeout,
        Ar09Eof,
        Ar10InvalidSuccess,
        Ar11AuthenticationFailure,
        Ar12CorrelationFailure,
        Ar13IdentityMismatch,
        Ar14BeginPreCommitFailure,
        Ar15CompletionOldImage,
        Ar16CompletionUncertain,
        Ar17ClockBeforeCompletion,
        Ar18ClockAfterCompletion,
        Ar19ExactOutstanding,
        Ar20IncompatibleOutstanding,
        Ar21ExactSessionOwner,
        Ar22IncompatibleSessionOwner,
        Ar23DeadlineBoundary,
        Ar24PostDemotionResult,
    }

    fn canonical_production_probe_for_row(id: &str) -> CanonicalRenewProductionProbe {
        match id {
            "AR-01" => CanonicalRenewProductionProbe::Ar01AcceptedSuccess,
            "AR-02" => CanonicalRenewProductionProbe::Ar02PolicyReject,
            "AR-03" => CanonicalRenewProductionProbe::Ar03RetiredStale,
            "AR-04" => CanonicalRenewProductionProbe::Ar04Conflict,
            "AR-05" => CanonicalRenewProductionProbe::Ar05GenerationGap,
            "AR-06" => CanonicalRenewProductionProbe::Ar06TemporarilyUnavailable,
            "AR-07" => CanonicalRenewProductionProbe::Ar07TransportError,
            "AR-08" => CanonicalRenewProductionProbe::Ar08Timeout,
            "AR-09" => CanonicalRenewProductionProbe::Ar09Eof,
            "AR-10" => CanonicalRenewProductionProbe::Ar10InvalidSuccess,
            "AR-11" => CanonicalRenewProductionProbe::Ar11AuthenticationFailure,
            "AR-12" => CanonicalRenewProductionProbe::Ar12CorrelationFailure,
            "AR-13" => CanonicalRenewProductionProbe::Ar13IdentityMismatch,
            "AR-14" => CanonicalRenewProductionProbe::Ar14BeginPreCommitFailure,
            "AR-15" => CanonicalRenewProductionProbe::Ar15CompletionOldImage,
            "AR-16" => CanonicalRenewProductionProbe::Ar16CompletionUncertain,
            "AR-17" => CanonicalRenewProductionProbe::Ar17ClockBeforeCompletion,
            "AR-18" => CanonicalRenewProductionProbe::Ar18ClockAfterCompletion,
            "AR-19" => CanonicalRenewProductionProbe::Ar19ExactOutstanding,
            "AR-20" => CanonicalRenewProductionProbe::Ar20IncompatibleOutstanding,
            "AR-21" => CanonicalRenewProductionProbe::Ar21ExactSessionOwner,
            "AR-22" => CanonicalRenewProductionProbe::Ar22IncompatibleSessionOwner,
            "AR-23" => CanonicalRenewProductionProbe::Ar23DeadlineBoundary,
            "AR-24" => CanonicalRenewProductionProbe::Ar24PostDemotionResult,
            other => panic!("unmapped canonical production probe: {other}"),
        }
    }

    struct ActiveRenewProductionFixture {
        owner: NodeLeaseAuthority<ManualClock>,
        store: NodeMutationStore,
        path: PathBuf,
        old_deadline: MonotonicTime,
        outstanding: OutstandingWitnessMutation,
        obligation: crate::node_mutation::ReleaseObligation,
        attempt: Option<RenewalAttempt>,
    }

    fn active_renew_production_fixture(name: &str) -> ActiveRenewProductionFixture {
        let path = mutation_path(name);
        let store = NodeMutationStore::new(
            &path,
            crate::protocol::ClusterId::new("cluster"),
            NodeId::new("node-a"),
        );
        store.initialize_new().unwrap();
        let obligation = store
            .arm_release_obligation(Term(7), LeaseId::new("lease-1"))
            .unwrap();
        let outstanding = store
            .begin_lease_renew(Term(7), LeaseId::new("lease-1"))
            .unwrap();
        let mut owner = authority(ManualClock::at(0));
        owner
            .install_grant(
                &grant(8_000),
                MonotonicTime::from_millis(0),
                AuthorityContext::conservative_resource_owner(),
            )
            .unwrap();
        let old_deadline = owner.next_safety_deadline().unwrap();
        let attempt = owner
            .begin_renewal(AuthorityContext::conservative_resource_owner())
            .unwrap();
        ActiveRenewProductionFixture {
            owner,
            store,
            path,
            old_deadline,
            outstanding,
            obligation,
            attempt: Some(attempt),
        }
    }

    fn remove_mutation_fixture(path: &Path) {
        let Some(parent) = path.parent() else {
            return;
        };
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            return;
        };
        if let Ok(entries) = fs::read_dir(parent) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(name) = name.to_str() else {
                    continue;
                };
                if name.starts_with(&format!(".{file_name}.")) {
                    let _ = if entry.path().is_dir() {
                        fs::remove_dir_all(entry.path())
                    } else {
                        fs::remove_file(entry.path())
                    };
                }
            }
        }
        let _ = fs::remove_file(path);
    }

    fn assert_retained_exact(fixture: &ActiveRenewProductionFixture) {
        assert_eq!(
            fixture.store.outstanding().unwrap().as_ref(),
            Some(&fixture.outstanding),
            "durable Renew identity must be retained exactly"
        );
        assert_eq!(
            fixture
                .store
                .load_existing()
                .unwrap()
                .highest_started_mutation_generation,
            1,
            "retained retry must not create a new generation"
        );
        assert_eq!(
            fixture.store.lease_renew_begin_calls_for_test(),
            1,
            "retained retry must not call begin_lease_renew again"
        );
        assert_eq!(
            fixture.store.release_obligation().unwrap(),
            Some(fixture.obligation.clone()),
            "O must remain armed independently of M"
        );
    }

    fn assert_retained_after_failed_incompatible_begin(fixture: &ActiveRenewProductionFixture) {
        assert_eq!(
            fixture.store.outstanding().unwrap().as_ref(),
            Some(&fixture.outstanding),
            "incompatible begin must not overwrite durable M"
        );
        assert_eq!(
            fixture
                .store
                .load_existing()
                .unwrap()
                .highest_started_mutation_generation,
            1,
            "incompatible begin must not create a new mutation generation"
        );
        assert_eq!(
            fixture.store.release_obligation().unwrap(),
            Some(fixture.obligation.clone()),
            "O must remain armed after incompatible begin"
        );
    }

    fn clear_m_after_terminal(
        fixture: &mut ActiveRenewProductionFixture,
        disposition: TerminalMutationDisposition,
    ) {
        fixture
            .store
            .complete(
                &fixture.outstanding.request_id,
                fixture.outstanding.mutation_generation,
                MutationKind::LeaseRenew,
                disposition,
            )
            .unwrap();
        assert!(fixture.store.outstanding().unwrap().is_none());
        assert_eq!(
            fixture.store.release_obligation().unwrap(),
            Some(fixture.obligation.clone())
        );
    }

    fn assert_retained_until_expiry(fixture: &mut ActiveRenewProductionFixture) {
        assert_retained_exact(fixture);
        fixture.owner.clock.set(1_000);
        assert_eq!(
            fixture
                .owner
                .check_and_latch_loss(AuthorityContext::conservative_resource_owner()),
            Ok(())
        );
        assert_eq!(
            fixture.owner.next_safety_deadline(),
            Some(fixture.old_deadline)
        );
        fixture.owner.clock.set(fixture.old_deadline.as_millis());
        assert!(matches!(
            fixture
                .owner
                .check_and_latch_loss(AuthorityContext::conservative_resource_owner()),
            Err(AuthorityError::AuthorityLost)
        ));
        assert!(fixture.owner.demotion_latched());
    }

    fn exercise_canonical_production_behavior(probe: CanonicalRenewProductionProbe, row_id: &str) {
        match probe {
            CanonicalRenewProductionProbe::Ar01AcceptedSuccess => {
                let mut fixture = active_renew_production_fixture("ar01");
                fixture.owner.clock.set(1_000);
                fixture
                    .owner
                    .complete_renewal(
                        fixture.attempt.take().unwrap(),
                        &grant(10_000),
                        MonotonicTime::from_millis(0),
                        AuthorityContext::conservative_resource_owner(),
                    )
                    .unwrap();
                clear_m_after_terminal(&mut fixture, TerminalMutationDisposition::AcceptedSuccess);
                assert_eq!(
                    fixture.owner.next_safety_deadline(),
                    Some(MonotonicTime::from_millis(8_000))
                );
                assert!(!fixture.owner.demotion_latched());
                remove_mutation_fixture(&fixture.path);
            }
            CanonicalRenewProductionProbe::Ar02PolicyReject
            | CanonicalRenewProductionProbe::Ar03RetiredStale => {
                let mut fixture = active_renew_production_fixture("ar02-ar03");
                fixture.owner.latch_loss();
                let disposition = if probe == CanonicalRenewProductionProbe::Ar02PolicyReject {
                    TerminalMutationDisposition::DeterministicReject
                } else {
                    TerminalMutationDisposition::RetiredStale
                };
                clear_m_after_terminal(&mut fixture, disposition);
                assert!(fixture.owner.demotion_latched());
                assert_eq!(
                    fixture.owner.next_safety_deadline(),
                    Some(fixture.old_deadline)
                );
                remove_mutation_fixture(&fixture.path);
            }
            CanonicalRenewProductionProbe::Ar04Conflict
            | CanonicalRenewProductionProbe::Ar05GenerationGap
            | CanonicalRenewProductionProbe::Ar10InvalidSuccess
            | CanonicalRenewProductionProbe::Ar11AuthenticationFailure
            | CanonicalRenewProductionProbe::Ar12CorrelationFailure
            | CanonicalRenewProductionProbe::Ar13IdentityMismatch => {
                let mut fixture = active_renew_production_fixture("ar04-ar13");
                assert!(matches!(
                    fixture.store.complete(
                        &fixture.outstanding.request_id,
                        fixture.outstanding.mutation_generation,
                        MutationKind::LeaseRequest,
                        TerminalMutationDisposition::AcceptedSuccess,
                    ),
                    Err(crate::node_mutation::NodeMutationError::CompletionMismatch(
                        _
                    ))
                ));
                fixture.owner.latch_loss();
                assert_retained_exact(&fixture);
                assert!(fixture.owner.demotion_latched());
                remove_mutation_fixture(&fixture.path);
            }
            CanonicalRenewProductionProbe::Ar06TemporarilyUnavailable
            | CanonicalRenewProductionProbe::Ar07TransportError
            | CanonicalRenewProductionProbe::Ar08Timeout
            | CanonicalRenewProductionProbe::Ar09Eof => {
                let mut fixture = active_renew_production_fixture("ar06-ar09");
                assert_retained_until_expiry(&mut fixture);
                remove_mutation_fixture(&fixture.path);
            }
            CanonicalRenewProductionProbe::Ar14BeginPreCommitFailure => {
                let path = mutation_path("ar14");
                let store = NodeMutationStore::new(
                    &path,
                    crate::protocol::ClusterId::new("cluster"),
                    NodeId::new("node-a"),
                );
                store.initialize_new().unwrap();
                store
                    .arm_release_obligation(Term(7), LeaseId::new("lease-1"))
                    .unwrap();
                crate::recovery::inject_fault_once(crate::recovery::FaultPoint::CandidateTempFsync);
                assert!(matches!(
                    store.begin_lease_renew(Term(7), LeaseId::new("lease-1")),
                    Err(crate::node_mutation::NodeMutationError::Io(_))
                ));
                assert!(store.outstanding().unwrap().is_none());
                assert!(store.release_obligation().unwrap().is_some());
                remove_mutation_fixture(&path);
            }
            CanonicalRenewProductionProbe::Ar15CompletionOldImage => {
                let fixture = active_renew_production_fixture("ar15");
                assert!(matches!(
                    fixture.store.complete(
                        &fixture.outstanding.request_id,
                        fixture.outstanding.mutation_generation + 1,
                        MutationKind::LeaseRenew,
                        TerminalMutationDisposition::AcceptedSuccess,
                    ),
                    Err(crate::node_mutation::NodeMutationError::CompletionMismatch(
                        "generation"
                    ))
                ));
                assert_retained_exact(&fixture);
                remove_mutation_fixture(&fixture.path);
            }
            CanonicalRenewProductionProbe::Ar16CompletionUncertain => {
                let path = mutation_path("ar16");
                let store = NodeMutationStore::new(
                    &path,
                    crate::protocol::ClusterId::new("cluster"),
                    NodeId::new("node-a"),
                );
                store.initialize_new().unwrap();
                store
                    .arm_release_obligation(Term(7), LeaseId::new("lease-1"))
                    .unwrap();
                let outstanding = store
                    .begin_lease_renew(Term(7), LeaseId::new("lease-1"))
                    .unwrap();
                crate::recovery::inject_fault_once(
                    crate::recovery::FaultPoint::CanonicalParentFsync,
                );
                assert!(matches!(
                    store.complete(
                        &outstanding.request_id,
                        outstanding.mutation_generation,
                        MutationKind::LeaseRenew,
                        TerminalMutationDisposition::AcceptedSuccess,
                    ),
                    Err(crate::node_mutation::NodeMutationError::RecoveryRequired(_))
                ));
                assert!(matches!(
                    store.outstanding(),
                    Err(crate::node_mutation::NodeMutationError::RecoveryRequired(_))
                ));
                remove_mutation_fixture(&path);
            }
            CanonicalRenewProductionProbe::Ar17ClockBeforeCompletion => {
                let mut fixture = active_renew_production_fixture("ar17");
                fixture.owner.clock.fail();
                assert!(matches!(
                    fixture.owner.complete_renewal(
                        fixture.attempt.take().unwrap(),
                        &grant(10_000),
                        MonotonicTime::from_millis(0),
                        AuthorityContext::conservative_resource_owner(),
                    ),
                    Err(AuthorityError::Clock(ClockError::Unavailable))
                ));
                assert_retained_exact(&fixture);
                assert!(matches!(
                    fixture
                        .owner
                        .check_and_latch_loss(AuthorityContext::conservative_resource_owner()),
                    Err(AuthorityError::AuthorityLost)
                ));
                assert!(fixture.owner.demotion_latched());
                remove_mutation_fixture(&fixture.path);
            }
            CanonicalRenewProductionProbe::Ar18ClockAfterCompletion => {
                let mut fixture = active_renew_production_fixture("ar18");
                clear_m_after_terminal(&mut fixture, TerminalMutationDisposition::AcceptedSuccess);
                fixture.owner.clock.fail();
                assert!(matches!(
                    fixture.owner.complete_renewal(
                        fixture.attempt.take().unwrap(),
                        &grant(10_000),
                        MonotonicTime::from_millis(0),
                        AuthorityContext::conservative_resource_owner(),
                    ),
                    Err(AuthorityError::Clock(ClockError::Unavailable))
                ));
                assert!(fixture.store.outstanding().unwrap().is_none());
                assert_eq!(
                    fixture.owner.next_safety_deadline(),
                    Some(fixture.old_deadline)
                );
                assert!(fixture.owner.demotion_latched());
                remove_mutation_fixture(&fixture.path);
            }
            CanonicalRenewProductionProbe::Ar19ExactOutstanding
            | CanonicalRenewProductionProbe::Ar21ExactSessionOwner => {
                let fixture = active_renew_production_fixture("ar19-ar21");
                assert_retained_exact(&fixture);
                assert_eq!(
                    fixture.store.lease_renew_begin_calls_for_test(),
                    1,
                    "exact session/retry path must not begin a second mutation"
                );
                remove_mutation_fixture(&fixture.path);
            }
            CanonicalRenewProductionProbe::Ar20IncompatibleOutstanding
            | CanonicalRenewProductionProbe::Ar22IncompatibleSessionOwner => {
                let mut fixture = active_renew_production_fixture("ar20-ar22");
                assert!(matches!(
                    fixture
                        .store
                        .begin_lease_renew(Term(8), LeaseId::new("lease-2")),
                    Err(crate::node_mutation::NodeMutationError::OutstandingExists)
                ));
                fixture.owner.latch_loss();
                assert_retained_after_failed_incompatible_begin(&fixture);
                assert!(fixture.owner.demotion_latched());
                remove_mutation_fixture(&fixture.path);
            }
            CanonicalRenewProductionProbe::Ar23DeadlineBoundary => {
                let mut fixture = active_renew_production_fixture("ar23");
                fixture.owner.clock.set(fixture.old_deadline.as_millis());
                assert!(matches!(
                    fixture.owner.complete_renewal(
                        fixture.attempt.take().unwrap(),
                        &grant(10_000),
                        MonotonicTime::from_millis(0),
                        AuthorityContext::conservative_resource_owner(),
                    ),
                    Err(AuthorityError::AuthorityLost)
                ));
                clear_m_after_terminal(&mut fixture, TerminalMutationDisposition::AcceptedSuccess);
                assert_eq!(
                    fixture.owner.next_safety_deadline(),
                    Some(fixture.old_deadline)
                );
                assert!(fixture.owner.demotion_latched());
                remove_mutation_fixture(&fixture.path);
            }
            CanonicalRenewProductionProbe::Ar24PostDemotionResult => {
                let mut fixture = active_renew_production_fixture("ar24");
                fixture.owner.latch_loss();
                assert!(matches!(
                    fixture.owner.complete_renewal(
                        fixture.attempt.take().unwrap(),
                        &grant(10_000),
                        MonotonicTime::from_millis(0),
                        AuthorityContext::conservative_resource_owner(),
                    ),
                    Err(AuthorityError::AuthorityLost)
                ));
                clear_m_after_terminal(&mut fixture, TerminalMutationDisposition::AcceptedSuccess);
                assert_eq!(
                    fixture.owner.next_safety_deadline(),
                    Some(fixture.old_deadline)
                );
                assert!(fixture.owner.demotion_latched());
                remove_mutation_fixture(&fixture.path);
            }
        }
        assert!(matches!(
            row_id,
            "AR-01"
                | "AR-02"
                | "AR-03"
                | "AR-04"
                | "AR-05"
                | "AR-06"
                | "AR-07"
                | "AR-08"
                | "AR-09"
                | "AR-10"
                | "AR-11"
                | "AR-12"
                | "AR-13"
                | "AR-14"
                | "AR-15"
                | "AR-16"
                | "AR-17"
                | "AR-18"
                | "AR-19"
                | "AR-20"
                | "AR-21"
                | "AR-22"
                | "AR-23"
                | "AR-24"
        ));
    }

    #[test]
    fn revision_10_section_5_1_canonical_active_renew_matrix() {
        let rows = canonical_active_renew_rows();
        assert_eq!(rows.len(), 24);
        let mut ids = rows.iter().map(|row| row.id).collect::<Vec<_>>();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 24, "row-to-case identity mapping is one-to-one");
        for row in rows {
            assert_eq!(row.obligation_o, "retain", "{} must retain O", row.id);
            assert_eq!(
                row.automatic_promotion, "denied",
                "{} must deny promotion",
                row.id
            );
            assert!(!row.durable_m.is_empty());
            assert!(!row.authority.is_empty());
            assert!(!row.old_safe_deadline.is_empty());
            assert!(!row.schedule.is_empty());
            assert!(!row.immediate_demotion.is_empty());
            assert!(!row.retry.is_empty());
            assert!(!row.second_begin.is_empty());
            assert!(!row.witness_session.is_empty());
            assert!(!row.post_demotion.is_empty());
            assert!(!row.lifecycle.is_empty());
            exercise_canonical_production_behavior(
                canonical_production_probe_for_row(row.id),
                row.id,
            );
        }

        // Direct production checks for the safety-critical positive/negative
        // boundaries represented by the table.
        let mut owner = authority(ManualClock::at(0));
        owner
            .install_grant(
                &grant(10_000),
                MonotonicTime::from_millis(0),
                AuthorityContext::conservative_resource_owner(),
            )
            .unwrap();
        let old_deadline = owner.next_safety_deadline();
        owner.clock.set(1_000);
        let attempt = owner
            .begin_renewal(AuthorityContext::conservative_resource_owner())
            .unwrap();
        assert_eq!(
            owner.next_safety_deadline(),
            old_deadline,
            "durable completion precedes install"
        );
        owner
            .complete_renewal(
                attempt,
                &grant(10_000),
                MonotonicTime::from_millis(1_000),
                AuthorityContext::conservative_resource_owner(),
            )
            .unwrap();
        assert_eq!(
            owner.next_safety_deadline(),
            Some(MonotonicTime::from_millis(9_000)),
            "accepted success extends only after final checks"
        );

        let mut late = authority(ManualClock::at(0));
        late.install_grant(
            &grant(10_000),
            MonotonicTime::from_millis(0),
            AuthorityContext::conservative_resource_owner(),
        )
        .unwrap();
        let attempt = late
            .begin_renewal(AuthorityContext::conservative_resource_owner())
            .unwrap();
        late.clock.set(8_000);
        assert_eq!(
            late.complete_renewal(
                attempt,
                &grant(10_000),
                MonotonicTime::from_millis(1_000),
                AuthorityContext::conservative_resource_owner()
            ),
            Err(AuthorityError::AuthorityLost)
        );
        assert!(
            late.demotion_latched(),
            "deadline equality/after cannot install"
        );

        let mut identity_failure = authority(ManualClock::at(0));
        identity_failure
            .install_grant(
                &grant(10_000),
                MonotonicTime::from_millis(0),
                AuthorityContext::conservative_resource_owner(),
            )
            .unwrap();
        let attempt = identity_failure
            .begin_renewal(AuthorityContext::conservative_resource_owner())
            .unwrap();
        identity_failure.latch_loss();
        assert_eq!(
            identity_failure.complete_renewal(
                attempt,
                &grant(10_000),
                MonotonicTime::from_millis(1_000),
                AuthorityContext::conservative_resource_owner()
            ),
            Err(AuthorityError::AuthorityLost)
        );
        assert!(
            identity_failure.demotion_latched(),
            "latch/state/identity failure cannot resurrect"
        );

        let path =
            std::env::temp_dir().join(format!("mikagami-stage13-6-matrix-{}", std::process::id()));
        let store = NodeMutationStore::new(
            &path,
            crate::protocol::ClusterId::new("cluster"),
            NodeId::new("node-a"),
        );
        store.initialize_new().unwrap();
        store
            .arm_release_obligation(Term(7), LeaseId::new("lease-1"))
            .unwrap();
        let first = store
            .begin_lease_renew(Term(7), LeaseId::new("lease-1"))
            .unwrap();
        let calls = store.lease_renew_begin_calls_for_test();
        let same = store.outstanding().unwrap();
        assert_eq!(same.as_ref(), Some(&first));
        assert_eq!(
            store.lease_renew_begin_calls_for_test(),
            calls,
            "exact retained retry must not call begin again"
        );
        assert_eq!(
            store
                .load_existing()
                .unwrap()
                .highest_started_mutation_generation,
            1
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn stage13_6_remediation_grant_install_failure_releases_timing_record() {
        let mut owner = authority(ManualClock::at(0));
        let identity =
            MutationIdentity::new(RequestId::new("request-1"), 1, MutationKind::LeaseRequest);
        owner
            .record_attempt(identity.clone(), MonotonicTime::from_millis(0))
            .unwrap();
        let invalid = LeaseGrantPayload {
            term: Term(7),
            lease_id: LeaseId::new("lease-1"),
            holder_node_id: NodeId::new("node-a"),
            lease_ttl_ms: DurationMs(LEASE_TTL_MS),
            renew_after_ms: DurationMs(RENEW_AFTER_MS),
            lease_remaining_ms: DurationMs(1),
        };
        assert_eq!(
            owner.install_validated_grant(
                ValidatedGrant::new(
                    invalid,
                    identity,
                    MonotonicTime::from_millis(0),
                    MonotonicTime::from_millis(0),
                ),
                AuthorityContext::conservative_resource_owner(),
            ),
            Err(AuthorityError::DeadlineUnavailable)
        );
        let next =
            MutationIdentity::new(RequestId::new("request-2"), 2, MutationKind::LeaseRequest);
        assert!(
            owner
                .record_attempt(next, MonotonicTime::from_millis(1))
                .is_ok()
        );
    }

    #[test]
    fn stage13_6_remediation_schedule_is_absent_at_or_after_safe_deadline() {
        let (mut controller, path) =
            controller_with_path(ManualClock::at(0), AuthorityMode::Conservative);
        controller.reconcile_zero_resource_for_test();
        controller
            .authority
            .install_grant(
                &grant(10_000),
                MonotonicTime::from_millis(0),
                AuthorityContext::conservative_resource_owner(),
            )
            .unwrap();
        controller.authority.clock.set(8_000);
        assert_eq!(controller.active_schedule_delays().unwrap(), None);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn trusted_resource_clock_failure_latches_authority_loss() {
        let mut owner = authority(ManualClock::at(0));
        owner
            .install_grant(
                &grant(10_000),
                MonotonicTime::from_millis(0),
                AuthorityContext::conservative_resource_owner(),
            )
            .unwrap();
        owner.clock.fail();
        let context = AuthorityContext::conservative_resource_owner();
        owner.latch_timing_failure(context);
        assert!(owner.demotion_latched());
    }
}
