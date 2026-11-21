//! One-shot Node-side execution of a durable Witness mutation.

#![allow(dead_code)]

use crate::node_lease_authority::{
    AuthorityCheckpoint, AuthorityContext, AuthorityError, ClockError, MonotonicClock,
    MonotonicTime, MutationIdentity, NodeAuthorityController, NodeLeaseAuthority,
    SystemMonotonicClock, ValidatedGrant,
};
use crate::node_mutation::{
    DurableWitnessMutation, MutationKind, NodeMutationError, NodeMutationStore,
    OutstandingWitnessMutation, TerminalMutationDisposition,
};
#[cfg(test)]
use crate::protocol::CborSerializer;
use crate::protocol::{
    DurationMs, LeaseGrantPayload, LeaseId, LeaseReleasedPayload, NodeId, ProtocolMessage, Term,
    WitnessMutationOutcomeCode,
};
#[cfg(test)]
use crate::security::MessageAuthenticator;
#[cfg(test)]
use crate::session::ProcessSession;
#[cfg(test)]
use crate::witness_runtime::WitnessConnection;
use crate::witness_runtime::{PendingWitnessMessage, WitnessResponseObservation, WitnessSession};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeWitnessMutationResult {
    AcceptedSuccess {
        kind: MutationKind,
        response: NodeWitnessSuccess,
    },
    DeterministicReject {
        kind: MutationKind,
        reason: String,
        /// The Witness term carried by the rejecting response. A reject only
        /// proves something about this attempt when the Witness is at or ahead
        /// of the attempt's term; a Witness behind it may simply not know the
        /// lease any more (persistence loss / rollback).
        witness_term: Term,
    },
    RetiredStale {
        kind: MutationKind,
        reason: String,
    },
    Conflict {
        kind: MutationKind,
        reason: String,
    },
    GenerationGap {
        kind: MutationKind,
        reason: String,
    },
    TemporarilyUnavailable {
        kind: MutationKind,
        reason: String,
    },
}

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeWitnessSuccess {
    LeaseGrant(LeaseGrantPayload),
    LeaseRenewed(LeaseGrantPayload),
    LeaseReleased(LeaseReleasedPayload),
}

#[derive(Debug)]
pub enum NodeWitnessRuntimeError {
    NodeMutation(NodeMutationError),
    Witness(crate::witness_runtime::WitnessRuntimeError),
    NoOutstanding,
    InvalidSuccess(&'static str),
    Clock(ClockError),
    Authority(AuthorityError),
}

impl fmt::Display for NodeWitnessRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NodeMutation(error) => write!(f, "Node mutation runtime error: {error}"),
            Self::Witness(error) => write!(f, "Witness runtime error: {error}"),
            Self::NoOutstanding => write!(f, "no durable Witness mutation is outstanding"),
            Self::InvalidSuccess(field) => {
                write!(
                    f,
                    "Witness success response failed semantic validation: {field}"
                )
            }
            Self::Clock(error) => write!(f, "Witness mutation timing error: {error}"),
            Self::Authority(error) => write!(f, "Witness authority integration error: {error}"),
        }
    }
}

impl std::error::Error for NodeWitnessRuntimeError {}

impl From<NodeMutationError> for NodeWitnessRuntimeError {
    fn from(error: NodeMutationError) -> Self {
        Self::NodeMutation(error)
    }
}

impl From<crate::witness_runtime::WitnessRuntimeError> for NodeWitnessRuntimeError {
    fn from(error: crate::witness_runtime::WitnessRuntimeError) -> Self {
        Self::Witness(error)
    }
}

impl From<ClockError> for NodeWitnessRuntimeError {
    fn from(error: ClockError) -> Self {
        Self::Clock(error)
    }
}

impl From<AuthorityError> for NodeWitnessRuntimeError {
    fn from(error: AuthorityError) -> Self {
        Self::Authority(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimedNodeWitnessMutationResult {
    pub attempt_start: MonotonicTime,
    pub validated_at: MonotonicTime,
    pub result: NodeWitnessMutationResult,
}

pub struct NodeWitnessMutationRuntime<'a> {
    store: &'a NodeMutationStore,
    node_id: NodeId,
}

impl<'a> NodeWitnessMutationRuntime<'a> {
    pub fn new(store: &'a NodeMutationStore, node_id: NodeId) -> Self {
        Self { store, node_id }
    }

    pub fn begin_and_execute_lease_request_once(
        &self,
        session: &mut WitnessSession,
        observed_term: Term,
        priority: i32,
        requested_ttl: DurationMs,
    ) -> Result<NodeWitnessMutationResult, NodeWitnessRuntimeError> {
        self.store
            .begin_lease_request(observed_term, priority, requested_ttl)?;
        self.execute_outstanding_once(session)
    }

    pub fn begin_and_execute_lease_renew_once(
        &self,
        session: &mut WitnessSession,
        term: Term,
        lease_id: LeaseId,
    ) -> Result<NodeWitnessMutationResult, NodeWitnessRuntimeError> {
        self.store.begin_lease_renew(term, lease_id)?;
        self.execute_outstanding_once(session)
    }

    pub(crate) fn begin_and_execute_lease_release_once(
        &self,
        session: &mut WitnessSession,
        term: Term,
        lease_id: LeaseId,
        reason: String,
    ) -> Result<NodeWitnessMutationResult, NodeWitnessRuntimeError> {
        let origin = super::LeaseReleaseOrigin::for_stage10();
        self.store
            .begin_lease_release(&origin, term, lease_id, reason)?;
        self.execute_outstanding_once(session)
    }

    pub fn retry_outstanding_once(
        &self,
        session: &mut WitnessSession,
    ) -> Result<NodeWitnessMutationResult, NodeWitnessRuntimeError> {
        if self.store.outstanding()?.is_none() {
            return Err(NodeWitnessRuntimeError::NoOutstanding);
        }
        self.execute_outstanding_once(session)
    }

    /// J23 (OD-J22-1, C-F): send the generation fence of a retained LeaseRequest once and classify
    /// the answer.
    ///
    /// This is a dedicated send path with its own contract, not a Release obligation: the fence is
    /// derived from the durable request (`generation_fence_of`), is never persisted and never
    /// completes or begins a durable record here, so nothing in the node store changes. Its only
    /// valid answers are LEASE_REJECT outcomes: a success (above all a LEASE_RELEASED) would mean
    /// the fence matched a lease, which the term-0 / non-UUID contract excludes, so it fails closed.
    pub(crate) fn exchange_generation_fence_once(
        &self,
        session: &mut WitnessSession,
        fence: &OutstandingWitnessMutation,
    ) -> Result<NodeWitnessMutationResult, NodeWitnessRuntimeError> {
        let ProtocolMessage::LeaseRelease(payload) = fence.to_protocol_message() else {
            return Err(NodeWitnessRuntimeError::InvalidSuccess(
                "generation fence kind",
            ));
        };
        // Defense in depth: the fence can match no lease twice over (term 0, the fixed lease id).
        if payload.term != Term(0) || payload.lease_id.as_str() != GENERATION_FENCE_LEASE_ID {
            return Err(NodeWitnessRuntimeError::InvalidSuccess(
                "generation fence identity",
            ));
        }
        session.send_lease_release(fence.request_id.clone(), payload)?;
        let outcome = (|| {
            let pending = self.correlated_response(session, fence)?;
            let rejected = matches!(
                pending.message().unsigned().message,
                ProtocolMessage::LeaseReject(_)
            );
            let observation = session.handle_pending_response(&pending)?;
            if !rejected {
                return Err(NodeWitnessRuntimeError::InvalidSuccess(
                    "a generation fence must be rejected, never accepted",
                ));
            }
            self.classify(
                MutationKind::LeaseRelease,
                fence,
                pending.message(),
                observation,
            )
        })();
        if outcome.is_err() {
            // Our send occupied the shared slot; clear it (as `execute_outstanding_once_timed`).
            session.reset_outstanding();
        }
        outcome
    }

    pub fn execute_outstanding_once(
        &self,
        session: &mut WitnessSession,
    ) -> Result<NodeWitnessMutationResult, NodeWitnessRuntimeError> {
        let clock = SystemMonotonicClock::new();
        Ok(self.execute_outstanding_once_timed(session, &clock)?.result)
    }

    /// Execute one Stage 10 transport attempt through the shared
    /// `WitnessSession` and expose the runtime-only monotonic timestamp
    /// captured immediately before the send path.  The session's single
    /// outstanding slot serializes this mutation against observation traffic;
    /// only this borrower consumes the corresponding completion.
    pub fn execute_outstanding_once_timed<C: MonotonicClock>(
        &self,
        session: &mut WitnessSession,
        clock: &C,
    ) -> Result<TimedNodeWitnessMutationResult, NodeWitnessRuntimeError> {
        let outstanding = self
            .store
            .outstanding()?
            .ok_or(NodeWitnessRuntimeError::NoOutstanding)?;
        let kind = outstanding.kind();
        let request_id = outstanding.request_id.clone();
        let message = outstanding.to_protocol_message();
        let attempt_start = clock.now()?;

        match message {
            ProtocolMessage::LeaseRequest(payload) => {
                session.send_lease_request(request_id, payload)?
            }
            ProtocolMessage::LeaseRenew(payload) => {
                session.send_lease_renew(request_id, payload)?
            }
            ProtocolMessage::LeaseRelease(payload) => {
                session.send_lease_release(request_id, payload)?
            }
            _ => return Err(NodeWitnessRuntimeError::InvalidSuccess("mutation kind")),
        }

        let outcome = self.complete_outstanding_exchange(session, kind, &outstanding);
        if outcome.is_err() {
            // Our send occupied the shared slot; clear it so a later durable
            // retry is not blocked by a request whose transport already failed.
            session.reset_outstanding();
        }
        let result = outcome?;
        let validated_at = clock.now()?;
        Ok(TimedNodeWitnessMutationResult {
            attempt_start,
            validated_at,
            result,
        })
    }

    /// Receive, correlate, classify, and durably commit the response for one
    /// already-sent outstanding mutation through the borrowed session.
    fn complete_outstanding_exchange(
        &self,
        session: &mut WitnessSession,
        kind: MutationKind,
        outstanding: &OutstandingWitnessMutation,
    ) -> Result<NodeWitnessMutationResult, NodeWitnessRuntimeError> {
        let pending = self.correlated_response(session, outstanding)?;
        validate_success_before_commit(&self.node_id, kind, outstanding, pending.message())?;
        let observation = session.handle_pending_response(&pending)?;
        let result = self.classify(kind, outstanding, pending.message(), observation)?;
        if is_terminal(&result) {
            let owned_release = if kind == MutationKind::LeaseRelease {
                match (&outstanding.mutation, self.store.release_obligation()?) {
                    (
                        DurableWitnessMutation::LeaseRelease { term, lease_id, .. },
                        Some(obligation),
                    ) if obligation.term == *term && obligation.lease_id == *lease_id => {
                        Some((*term, lease_id.clone()))
                    }
                    _ => None,
                }
            } else {
                None
            };
            if let (
                Some((term, lease_id)),
                NodeWitnessMutationResult::AcceptedSuccess {
                    response: NodeWitnessSuccess::LeaseReleased(_),
                    ..
                },
            ) = (&owned_release, &result)
            {
                self.store.complete_owned_release(
                    &outstanding.request_id,
                    outstanding.mutation_generation,
                    *term,
                    lease_id,
                )?;
                return Ok(result);
            }
            // An owned release obligation is cleared only by the atomic
            // AcceptedSuccess path above.  Terminal queue outcomes are not
            // release proof and retain the exact Release record.
            if owned_release.is_some() {
                return Ok(result);
            }
            let disposition = match &result {
                NodeWitnessMutationResult::AcceptedSuccess { .. } => {
                    TerminalMutationDisposition::AcceptedSuccess
                }
                NodeWitnessMutationResult::DeterministicReject { .. } => {
                    TerminalMutationDisposition::DeterministicReject
                }
                NodeWitnessMutationResult::RetiredStale { .. } => {
                    TerminalMutationDisposition::RetiredStale
                }
                _ => unreachable!(),
            };
            self.store.complete(
                &outstanding.request_id,
                outstanding.mutation_generation,
                outstanding.kind(),
                disposition,
            )?;
        }
        Ok(result)
    }

    pub fn execute_lease_request_once_with_authority<C: MonotonicClock>(
        &self,
        session: &mut WitnessSession,
        authority: &mut NodeLeaseAuthority<C>,
        context: AuthorityContext,
    ) -> Result<TimedNodeWitnessMutationResult, NodeWitnessRuntimeError> {
        let outstanding = self
            .store
            .outstanding()?
            .ok_or(NodeWitnessRuntimeError::NoOutstanding)?;
        let identity = MutationIdentity::new(
            outstanding.request_id.clone(),
            outstanding.mutation_generation,
            outstanding.kind(),
        );
        let origin = authority.clock().now()?;
        authority.record_attempt(identity.clone(), origin)?;
        let timed = self.execute_outstanding_once_timed(session, authority.clock())?;
        if let NodeWitnessMutationResult::AcceptedSuccess {
            response: NodeWitnessSuccess::LeaseGrant(grant),
            ..
        } = &timed.result
        {
            authority.install_validated_grant(
                ValidatedGrant::new(grant.clone(), identity, origin, timed.validated_at),
                context,
            )?;
        } else if is_terminal(&timed.result) {
            authority.finish_attempt(&identity);
        }
        Ok(timed)
    }

    pub fn execute_lease_renew_once_with_authority<C: MonotonicClock>(
        &self,
        session: &mut WitnessSession,
        authority: &mut NodeLeaseAuthority<C>,
        context: AuthorityContext,
    ) -> Result<TimedNodeWitnessMutationResult, NodeWitnessRuntimeError> {
        self.execute_lease_renew_once_with_authority_guarded(session, authority, context, || Ok(()))
    }

    fn execute_lease_renew_once_with_authority_guarded<C, F>(
        &self,
        session: &mut WitnessSession,
        authority: &mut NodeLeaseAuthority<C>,
        context: AuthorityContext,
        before_authority_install: F,
    ) -> Result<TimedNodeWitnessMutationResult, NodeWitnessRuntimeError>
    where
        C: MonotonicClock,
        F: FnOnce() -> Result<(), AuthorityError>,
    {
        let outstanding = self
            .store
            .outstanding()?
            .ok_or(NodeWitnessRuntimeError::NoOutstanding)?;
        let identity = MutationIdentity::new(
            outstanding.request_id.clone(),
            outstanding.mutation_generation,
            outstanding.kind(),
        );
        let renewal = authority.begin_renewal_with_identity(identity.clone(), context)?;
        let origin = match authority.clock().now() {
            Ok(now) => now,
            Err(error) => {
                authority.latch_timing_failure(context);
                authority.reject_or_fail_renewal();
                return Err(error.into());
            }
        };
        if let Err(error) = authority.record_attempt(identity.clone(), origin) {
            authority.reject_or_fail_renewal();
            return Err(error.into());
        }
        let timed = match self.execute_outstanding_once_timed(session, authority.clock()) {
            Ok(timed) => timed,
            Err(error) => {
                authority.reject_or_fail_renewal();
                return Err(error);
            }
        };
        match &timed.result {
            NodeWitnessMutationResult::AcceptedSuccess {
                response: NodeWitnessSuccess::LeaseRenewed(grant),
                ..
            } => {
                before_authority_install().map_err(|error| {
                    authority.reject_or_fail_renewal();
                    error
                })?;
                authority.complete_renewal_with_schedule(
                    renewal,
                    grant,
                    origin,
                    timed.validated_at,
                    context,
                )?
            }
            _ => {
                if is_terminal(&timed.result) {
                    authority.finish_attempt(&identity);
                }
                authority.reject_or_fail_renewal()
            }
        }
        Ok(timed)
    }

    /// Renewal entry point for the single production authority owner.  The
    /// controller, not this runtime, supplies the ownership classification.
    pub(crate) fn execute_lease_renew_once_with_controller<C, F>(
        &self,
        session: &mut WitnessSession,
        controller: &mut NodeAuthorityController<C>,
        before_authority_install: F,
    ) -> Result<TimedNodeWitnessMutationResult, NodeWitnessRuntimeError>
    where
        C: MonotonicClock,
        F: FnOnce() -> Result<(), AuthorityError>,
    {
        if !controller.resource_owning() {
            return Err(NodeWitnessRuntimeError::Authority(
                AuthorityError::StateProhibitsOwnership,
            ));
        }
        let context = controller.context_for(AuthorityCheckpoint::BeforeServiceStart);
        self.execute_lease_renew_once_with_authority_guarded(
            session,
            &mut controller.authority,
            context,
            before_authority_install,
        )
    }

    /// Initial acquisition through the same long-lived authority owner.  A
    /// zero-resource node may ask the Witness without already holding a
    /// lease; the returned grant is still installed only by the trusted
    /// authority path.
    pub(crate) fn execute_lease_request_once_with_controller<C: MonotonicClock>(
        &self,
        session: &mut WitnessSession,
        controller: &mut NodeAuthorityController<C>,
    ) -> Result<TimedNodeWitnessMutationResult, NodeWitnessRuntimeError> {
        let context = controller.context_for(AuthorityCheckpoint::BeforeVipAcquire);
        let result = self.execute_lease_request_once_with_authority(
            session,
            &mut controller.authority,
            context,
        );
        if result.is_err() && controller.resource_owning() {
            controller.request_demotion_on_authority_loss();
        }
        result
    }

    /// Read the response of exactly this durable request.
    ///
    /// A response for an earlier request can be delivered late (the request
    /// timed out, its answer arrived afterwards, and it is still queued in the
    /// single connection). It is authenticated for this session but owns no
    /// slot any more, so it is discarded (sequence advanced, no observation)
    /// and the next frame is read. Bounded (D-tol): up to
    /// `MAX_DISCARDED_RESPONSES` (4) foreign frames may precede the correlated
    /// one; the fifth foreign frame read and discarded ends the exchange as
    /// `UncorrelatedResponsesExhausted`. That is an unknown outcome
    /// (OD-J31-4), never a lease outcome: the durable record stays, and the
    /// in-process callers resend the same exact request on a later iteration
    /// up to `UNCORRELATED_RETRY_LIMIT` consecutive times (C-d) before they
    /// fall back to RecoveryBlocked.
    ///
    /// This cannot accept a wrong answer as this request's answer: the
    /// correlated frame keeps its full validation, and a discarded frame never
    /// reaches `classify`.
    fn correlated_response(
        &self,
        session: &mut WitnessSession,
        outstanding: &OutstandingWitnessMutation,
    ) -> Result<PendingWitnessMessage, NodeWitnessRuntimeError> {
        const MAX_DISCARDED_RESPONSES: usize = 4;
        for _ in 0..=MAX_DISCARDED_RESPONSES {
            let pending = session.receive_pending()?;
            let id = pending.message().unsigned().common.request_id.clone();
            if id.as_ref() == Some(&outstanding.request_id) {
                return Ok(pending);
            }
            session.discard_stale_response(&pending)?;
        }
        Err(NodeWitnessRuntimeError::Witness(
            crate::witness_runtime::WitnessRuntimeError::UncorrelatedResponsesExhausted,
        ))
    }

    fn classify(
        &self,
        kind: MutationKind,
        outstanding: &OutstandingWitnessMutation,
        pending: &crate::receive::AuthenticatedMessage,
        observation: WitnessResponseObservation,
    ) -> Result<NodeWitnessMutationResult, NodeWitnessRuntimeError> {
        match observation {
            WitnessResponseObservation::LeaseGrant(payload) => {
                if kind != MutationKind::LeaseRequest {
                    return Err(NodeWitnessRuntimeError::InvalidSuccess("response kind"));
                }
                validate_grant(pending, &self.node_id, &payload)?;
                Ok(NodeWitnessMutationResult::AcceptedSuccess {
                    kind,
                    response: NodeWitnessSuccess::LeaseGrant(payload),
                })
            }
            WitnessResponseObservation::LeaseRenewed(payload) => {
                if kind != MutationKind::LeaseRenew {
                    return Err(NodeWitnessRuntimeError::InvalidSuccess("response kind"));
                }
                let DurableWitnessMutation::LeaseRenew { term, lease_id } = &outstanding.mutation
                else {
                    return Err(NodeWitnessRuntimeError::InvalidSuccess("renew mutation"));
                };
                validate_grant(pending, &self.node_id, &payload)?;
                if payload.term != *term || payload.lease_id != *lease_id {
                    return Err(NodeWitnessRuntimeError::InvalidSuccess("renew identity"));
                }
                Ok(NodeWitnessMutationResult::AcceptedSuccess {
                    kind,
                    response: NodeWitnessSuccess::LeaseRenewed(payload),
                })
            }
            WitnessResponseObservation::LeaseReleased(payload) => {
                if kind != MutationKind::LeaseRelease {
                    return Err(NodeWitnessRuntimeError::InvalidSuccess("response kind"));
                }
                let DurableWitnessMutation::LeaseRelease { term, lease_id, .. } =
                    &outstanding.mutation
                else {
                    return Err(NodeWitnessRuntimeError::InvalidSuccess("release mutation"));
                };
                if payload.term != *term
                    || payload.lease_id != *lease_id
                    || payload.result != "released"
                {
                    return Err(NodeWitnessRuntimeError::InvalidSuccess("release identity"));
                }
                Ok(NodeWitnessMutationResult::AcceptedSuccess {
                    kind,
                    response: NodeWitnessSuccess::LeaseReleased(payload),
                })
            }
            WitnessResponseObservation::LeaseReject(payload) => Ok(match payload.code {
                WitnessMutationOutcomeCode::PolicyReject => {
                    NodeWitnessMutationResult::DeterministicReject {
                        kind,
                        reason: payload.reason,
                        witness_term: pending.unsigned().common.term,
                    }
                }
                WitnessMutationOutcomeCode::RetiredStale => {
                    NodeWitnessMutationResult::RetiredStale {
                        kind,
                        reason: payload.reason,
                    }
                }
                WitnessMutationOutcomeCode::Conflict => NodeWitnessMutationResult::Conflict {
                    kind,
                    reason: payload.reason,
                },
                WitnessMutationOutcomeCode::GenerationGap => {
                    NodeWitnessMutationResult::GenerationGap {
                        kind,
                        reason: payload.reason,
                    }
                }
                WitnessMutationOutcomeCode::TemporarilyUnavailable => {
                    NodeWitnessMutationResult::TemporarilyUnavailable {
                        kind,
                        reason: payload.reason,
                    }
                }
            }),
            WitnessResponseObservation::TermStatus(_) => {
                Err(NodeWitnessRuntimeError::InvalidSuccess("response kind"))
            }
        }
    }
}

/// J23 (OD-J22-1, C-F): the lease id of every generation fence. It is not UUID-shaped, so it can
/// never equal a lease id the Witness generates (UUIDv4); together with term 0 (no grant has term
/// 0) a fence can never match, and so never release, a lease: two independent mismatches.
///
/// NEVER CHANGE this value, `linux_node_runtime::GENERATION_FENCE_REASON` or the id derivation of
/// `generation_fence_request_id`
/// without a migration: they are part of the fence's fingerprint at the Witness. A fence committed
/// by an earlier version and still in the journal would then be a Conflict to the new fence, and
/// the node would stay blocked (pinned by `j23_generation_fence_values_are_pinned`).
pub(crate) const GENERATION_FENCE_LEASE_ID: &str = "mikagami-generation-fence";

/// J23 (OD-J22-1, C-F): the request id of the generation fence of the retained request
/// `request_id` at `generation`: SHA-256 over a fixed domain, the request id and the generation,
/// shaped as a canonical UUIDv4. A pure function of its arguments (no clock, no randomness, no
/// store), so the fence is identical after any restart and needs no durable record.
pub(crate) fn generation_fence_request_id(
    request_id: &crate::protocol::RequestId,
    generation: u64,
) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"mikagami generation fence v1\0");
    hasher.update(request_id.as_str().as_bytes());
    hasher.update([0u8]);
    hasher.update(generation.to_be_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn is_terminal(result: &NodeWitnessMutationResult) -> bool {
    matches!(
        result,
        NodeWitnessMutationResult::AcceptedSuccess { .. }
            | NodeWitnessMutationResult::DeterministicReject { .. }
            | NodeWitnessMutationResult::RetiredStale { .. }
    )
}

fn validate_success_before_commit(
    node_id: &NodeId,
    kind: MutationKind,
    outstanding: &OutstandingWitnessMutation,
    pending: &crate::receive::AuthenticatedMessage,
) -> Result<(), NodeWitnessRuntimeError> {
    match &pending.unsigned().message {
        ProtocolMessage::LeaseGrant(payload) if kind == MutationKind::LeaseRequest => {
            validate_grant(pending, node_id, payload)?;
        }
        ProtocolMessage::LeaseRenewed(payload) if kind == MutationKind::LeaseRenew => {
            let DurableWitnessMutation::LeaseRenew { term, lease_id } = &outstanding.mutation
            else {
                return Err(NodeWitnessRuntimeError::InvalidSuccess("renew mutation"));
            };
            validate_grant(pending, node_id, payload)?;
            if payload.term != *term || payload.lease_id != *lease_id {
                return Err(NodeWitnessRuntimeError::InvalidSuccess("renew identity"));
            }
        }
        ProtocolMessage::LeaseReleased(payload) if kind == MutationKind::LeaseRelease => {
            let DurableWitnessMutation::LeaseRelease { term, lease_id, .. } = &outstanding.mutation
            else {
                return Err(NodeWitnessRuntimeError::InvalidSuccess("release mutation"));
            };
            if payload.term != *term
                || payload.lease_id != *lease_id
                || payload.result != "released"
            {
                return Err(NodeWitnessRuntimeError::InvalidSuccess("release identity"));
            }
        }
        ProtocolMessage::LeaseReject(_) => {}
        _ => {}
    }
    Ok(())
}

fn validate_grant(
    pending: &crate::receive::AuthenticatedMessage,
    node_id: &NodeId,
    payload: &LeaseGrantPayload,
) -> Result<(), NodeWitnessRuntimeError> {
    if payload.holder_node_id != *node_id
        || payload.lease_ttl_ms.0 == 0
        || payload.renew_after_ms.0 == 0
        || payload.renew_after_ms.0 >= payload.lease_ttl_ms.0
        || payload.lease_remaining_ms.0 == 0
        || pending.unsigned().common.term != payload.term
        || pending.unsigned().common.lease_id.as_ref() != Some(&payload.lease_id)
    {
        return Err(NodeWitnessRuntimeError::InvalidSuccess("lease grant"));
    }
    Ok(())
}

/// C-d (OD-J31-2, D-retry): consecutive `UncorrelatedResponsesExhausted`
/// outcomes of one retained mutation after which the caller falls back to
/// RecoveryBlocked.
pub(crate) const UNCORRELATED_RETRY_LIMIT: u32 = 3;

/// C-c (OD-J31-2): no retained Renew waits longer than this between two
/// attempts, however many due iterations it skipped.
pub(crate) const RENEW_RETRY_INTERVAL_CAP: std::time::Duration = std::time::Duration::from_secs(60);

/// What a caller does after an `UncorrelatedResponsesExhausted`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UncorrelatedRetry {
    /// Unknown outcome: keep `M` (and `O`) and resend the same exact request
    /// on the next iteration.
    Retry,
    /// The limit is reached: the caller's existing RecoveryBlocked path.
    Exhausted,
}

/// C-d / OD-J31-4: the memory-only count of consecutive exhausted
/// correlations of one retained mutation `(request id, generation)`.
///
/// Any correlated response of that mutation resets it; another mutation
/// starts again at one. It is never persisted: a restart begins at zero and
/// the startup reconciliation (or, for another kind of `M`, the existing
/// recovery contract) applies. It decides nothing about the lease and never
/// moves a safe deadline.
#[derive(Debug, Default)]
pub(crate) struct UncorrelatedRetryCounter {
    current: Option<(crate::protocol::RequestId, u64, u32)>,
}

impl UncorrelatedRetryCounter {
    pub(crate) fn record_exhausted(
        &mut self,
        request_id: &crate::protocol::RequestId,
        generation: u64,
    ) -> UncorrelatedRetry {
        let count = match &self.current {
            Some((id, current_generation, count))
                if id == request_id && *current_generation == generation =>
            {
                count.saturating_add(1)
            }
            _ => 1,
        };
        self.current = Some((request_id.clone(), generation, count));
        if count >= UNCORRELATED_RETRY_LIMIT {
            UncorrelatedRetry::Exhausted
        } else {
            UncorrelatedRetry::Retry
        }
    }

    /// A response correlated to `(request_id, generation)` was read.
    pub(crate) fn record_correlated(
        &mut self,
        request_id: &crate::protocol::RequestId,
        generation: u64,
    ) {
        if matches!(&self.current, Some((id, current_generation, _))
            if id == request_id && *current_generation == generation)
        {
            self.current = None;
        }
    }

    #[cfg(test)]
    pub(crate) fn count(&self) -> u32 {
        self.current.as_ref().map_or(0, |(_, _, count)| *count)
    }
}

/// C-c (OD-J31-2): spacing of the post-demotion retries of one retained exact
/// Renew whose previous attempt timed out on the same session.
///
/// After such a timeout the next due iterations are skipped 1, 2, 4, ...
/// times (doubling), so a half-open connection does not accumulate duplicate
/// sends; once `RENEW_RETRY_INTERVAL_CAP` has passed since the last attempt
/// the next iteration sends anyway. Any other outcome, another session or
/// another mutation clears the spacing. The receive path and the slot reset
/// after a timeout are unchanged, and nothing here extends authority.
#[derive(Debug, Default)]
pub(crate) struct RenewRetryBackoff {
    current: Option<RenewBackoffState>,
}

#[derive(Debug)]
struct RenewBackoffState {
    session: std::sync::Weak<()>,
    request_id: crate::protocol::RequestId,
    generation: u64,
    last_attempt: std::time::Instant,
    skips_left: u32,
    next_skips: u32,
}

/// The upper bound of the doubling skip count (the time cap binds first at
/// any realistic cadence).
const RENEW_RETRY_MAX_SKIPS: u32 = 64;

impl RenewRetryBackoff {
    fn matches(
        state: &RenewBackoffState,
        session: &std::sync::Arc<()>,
        request_id: &crate::protocol::RequestId,
        generation: u64,
    ) -> bool {
        std::sync::Weak::ptr_eq(&state.session, &std::sync::Arc::downgrade(session))
            && &state.request_id == request_id
            && state.generation == generation
    }

    /// Whether this due iteration sends the retained Renew.
    pub(crate) fn may_send(
        &mut self,
        session: &std::sync::Arc<()>,
        request_id: &crate::protocol::RequestId,
        generation: u64,
        now: std::time::Instant,
    ) -> bool {
        let Some(state) = self.current.as_mut() else {
            return true;
        };
        if !Self::matches(state, session, request_id, generation) {
            self.current = None;
            return true;
        }
        if now.saturating_duration_since(state.last_attempt) >= RENEW_RETRY_INTERVAL_CAP {
            return true;
        }
        if state.skips_left > 0 {
            state.skips_left -= 1;
            return false;
        }
        true
    }

    /// The attempt sent at `now` timed out on `session`.
    pub(crate) fn record_timeout(
        &mut self,
        session: &std::sync::Arc<()>,
        request_id: &crate::protocol::RequestId,
        generation: u64,
        now: std::time::Instant,
    ) {
        let next_skips = match &self.current {
            Some(state) if Self::matches(state, session, request_id, generation) => {
                state.next_skips
            }
            _ => 1,
        };
        self.current = Some(RenewBackoffState {
            session: std::sync::Arc::downgrade(session),
            request_id: request_id.clone(),
            generation,
            last_attempt: now,
            skips_left: next_skips,
            next_skips: next_skips.saturating_mul(2).min(RENEW_RETRY_MAX_SKIPS),
        });
    }

    /// Any outcome other than a timeout clears the spacing.
    pub(crate) fn clear(&mut self) {
        self.current = None;
    }
}

/// C-c: whether a Witness exchange error is a timeout of the attempt. A
/// blocking read reports it as `Transport(Io(..))` (`tcp.rs`
/// `read_timeout_is_applied_to_connection`); the readability wait as `Io(..)`.
pub(crate) fn is_timeout(error: &NodeWitnessRuntimeError) -> bool {
    let NodeWitnessRuntimeError::Witness(crate::witness_runtime::WitnessRuntimeError::Tcp(tcp)) =
        error
    else {
        return false;
    };
    let io = match tcp {
        crate::tcp::TcpError::Io(io)
        | crate::tcp::TcpError::Transport(crate::transport::TransportError::Io(io)) => io,
        _ => return false,
    };
    matches!(
        io.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{ClusterId, RequestId, SessionId};
    use crate::security::Psk;
    use crate::tcp::TcpConnection;
    use crate::witness_runtime::{WitnessResponseContext, send_witness_response_with_context};
    use std::fs;
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    fn test_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "mikagami-node-witness-{name}-{}",
            std::process::id()
        ))
    }

    fn connection_pair() -> (WitnessConnection, WitnessConnection) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let client =
            TcpConnection::from_stream(client, Duration::from_secs(2), Duration::from_secs(2))
                .unwrap();
        let server =
            TcpConnection::from_stream(server, Duration::from_secs(2), Duration::from_secs(2))
                .unwrap();
        (
            WitnessConnection::new(
                NodeId::new("node-a"),
                NodeId::new("witness"),
                ClusterId::new("cluster"),
                SessionId::new("session-w"),
                client,
            ),
            WitnessConnection::new(
                NodeId::new("witness"),
                NodeId::new("node-a"),
                ClusterId::new("cluster"),
                SessionId::new("session-a"),
                server,
            ),
        )
    }

    fn session_from(connection: WitnessConnection) -> WitnessSession {
        WitnessSession::new(
            connection,
            ProcessSession::from_session_id(SessionId::new("session-a")),
            MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32])),
        )
    }

    fn serve_response(witness: WitnessConnection, code: WitnessMutationOutcomeCode) {
        serve_response_with_reason(witness, code, "arbitrary diagnostic wording");
    }

    fn serve_response_with_reason(
        mut witness: WitnessConnection,
        code: WitnessMutationOutcomeCode,
        reason: &str,
    ) {
        let mut process = ProcessSession::from_session_id(SessionId::new("session-w"));
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
            &mut process,
            request_id,
            ProtocolMessage::LeaseReject(crate::protocol::LeaseRejectPayload {
                code,
                reason: reason.to_string(),
            }),
            WitnessResponseContext {
                term: Term(0),
                lease_id: None,
            },
            &CborSerializer,
            &auth,
        )
        .unwrap();
    }

    fn serve_grant(mut witness: WitnessConnection) {
        let mut process = ProcessSession::from_session_id(SessionId::new("session-w"));
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
            &mut process,
            request_id,
            ProtocolMessage::LeaseGrant(crate::protocol::LeaseGrantPayload {
                term: Term(1),
                lease_id: LeaseId::new("lease-1"),
                holder_node_id: NodeId::new("node-a"),
                lease_ttl_ms: DurationMs(10_000),
                renew_after_ms: DurationMs(3_000),
                lease_remaining_ms: DurationMs(10_000),
            }),
            WitnessResponseContext {
                term: Term(1),
                lease_id: Some(LeaseId::new("lease-1")),
            },
            &CborSerializer,
            &auth,
        )
        .unwrap();
    }

    fn serve_custom_response(
        mut witness: WitnessConnection,
        response_id: Option<RequestId>,
        message: ProtocolMessage,
        context: WitnessResponseContext,
        observed: Option<mpsc::Sender<(RequestId, u64, ProtocolMessage)>>,
    ) {
        let auth = MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32]));
        let pending = witness.receive_pending(&CborSerializer, &auth).unwrap();
        let request_id = pending
            .message()
            .unsigned()
            .common
            .request_id
            .clone()
            .unwrap();
        let generation = match &pending.message().unsigned().message {
            ProtocolMessage::LeaseRequest(payload) => payload.mutation_generation,
            ProtocolMessage::LeaseRenew(payload) => payload.mutation_generation,
            ProtocolMessage::LeaseRelease(payload) => payload.mutation_generation,
            _ => 0,
        };
        if let Some(sender) = observed {
            sender
                .send((
                    request_id.clone(),
                    generation,
                    pending.message().unsigned().message.clone(),
                ))
                .unwrap();
        }
        let mut process = ProcessSession::from_session_id(SessionId::new("session-w"));
        send_witness_response_with_context(
            &mut witness,
            &mut process,
            response_id.unwrap_or(request_id),
            message,
            context,
            &CborSerializer,
            &auth,
        )
        .unwrap();
    }

    fn discard_request(mut witness: WitnessConnection) {
        let auth = MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32]));
        let _ = witness.receive_pending(&CborSerializer, &auth).unwrap();
    }

    fn renewed_payload(term: Term, lease_id: LeaseId) -> LeaseGrantPayload {
        LeaseGrantPayload {
            term,
            lease_id,
            holder_node_id: NodeId::new("node-a"),
            lease_ttl_ms: DurationMs(10_000),
            renew_after_ms: DurationMs(3_000),
            lease_remaining_ms: DurationMs(10_000),
        }
    }

    fn serve_released(
        mut witness: WitnessConnection,
        historical_term: Term,
        historical_lease: LeaseId,
        current_term: Term,
        current_lease: Option<LeaseId>,
    ) {
        let mut process = ProcessSession::from_session_id(SessionId::new("session-w"));
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
            &mut process,
            request_id,
            ProtocolMessage::LeaseReleased(LeaseReleasedPayload {
                term: historical_term,
                lease_id: historical_lease,
                result: "released".to_string(),
            }),
            WitnessResponseContext {
                term: current_term,
                lease_id: current_lease,
            },
            &CborSerializer,
            &auth,
        )
        .unwrap();
    }
    #[test]
    fn result_classification_does_not_parse_reason() {
        let result = NodeWitnessMutationResult::DeterministicReject {
            kind: MutationKind::LeaseRequest,
            reason: "arbitrary wording".to_string(),
            witness_term: Term(0),
        };
        assert!(matches!(
            result,
            NodeWitnessMutationResult::DeterministicReject { reason, .. }
                if reason == "arbitrary wording"
        ));
    }

    #[test]
    fn real_tcp_typed_rejects_clear_only_terminal_outcomes() {
        let cases = [
            (WitnessMutationOutcomeCode::PolicyReject, true),
            (WitnessMutationOutcomeCode::RetiredStale, true),
            (WitnessMutationOutcomeCode::Conflict, false),
            (WitnessMutationOutcomeCode::GenerationGap, false),
            (WitnessMutationOutcomeCode::TemporarilyUnavailable, false),
        ];
        for (index, (code, clears)) in cases.into_iter().enumerate() {
            let path = test_path(&format!("reject-{index}"));
            let store =
                NodeMutationStore::new(&path, ClusterId::new("cluster"), NodeId::new("node-a"));
            store.initialize_new().unwrap();
            let runtime = NodeWitnessMutationRuntime::new(&store, NodeId::new("node-a"));
            let (node, witness) = connection_pair();
            let server = thread::spawn(move || serve_response(witness, code));
            let result = runtime
                .begin_and_execute_lease_request_once(
                    &mut session_from(node),
                    Term(0),
                    100,
                    DurationMs(10_000),
                )
                .unwrap();
            server.join().unwrap();
            assert_eq!(
                matches!(
                    result,
                    NodeWitnessMutationResult::DeterministicReject { .. }
                        | NodeWitnessMutationResult::RetiredStale { .. }
                ),
                clears
            );
            assert_eq!(
                store
                    .load_existing()
                    .unwrap()
                    .outstanding_mutation
                    .is_some(),
                !clears
            );
            let _ = fs::remove_file(path);
        }
    }

    #[test]
    fn real_tcp_success_completes_after_durable_response_processing() {
        let path = test_path("success");
        let store = NodeMutationStore::new(&path, ClusterId::new("cluster"), NodeId::new("node-a"));
        store.initialize_new().unwrap();
        let runtime = NodeWitnessMutationRuntime::new(&store, NodeId::new("node-a"));
        let (node, witness) = connection_pair();
        let server = thread::spawn(move || serve_grant(witness));
        let result = runtime
            .begin_and_execute_lease_request_once(
                &mut session_from(node),
                Term(0),
                100,
                DurationMs(10_000),
            )
            .unwrap();
        server.join().unwrap();
        assert!(matches!(
            result,
            NodeWitnessMutationResult::AcceptedSuccess {
                response: NodeWitnessSuccess::LeaseGrant(_),
                ..
            }
        ));
        assert!(
            store
                .load_existing()
                .unwrap()
                .outstanding_mutation
                .is_none()
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn stage10_lease_renew_success_completes_exact_outstanding() {
        let path = test_path("renew-success");
        let store = NodeMutationStore::new(&path, ClusterId::new("cluster"), NodeId::new("node-a"));
        store.initialize_new().unwrap();
        store
            .arm_release_obligation(Term(7), LeaseId::new("lease-1"))
            .unwrap();
        let runtime = NodeWitnessMutationRuntime::new(&store, NodeId::new("node-a"));
        let (node, witness) = connection_pair();
        let server = thread::spawn(move || {
            serve_custom_response(
                witness,
                None,
                ProtocolMessage::LeaseRenewed(renewed_payload(Term(7), LeaseId::new("lease-1"))),
                WitnessResponseContext {
                    term: Term(7),
                    lease_id: Some(LeaseId::new("lease-1")),
                },
                None,
            )
        });
        let result = runtime
            .begin_and_execute_lease_renew_once(
                &mut session_from(node),
                Term(7),
                LeaseId::new("lease-1"),
            )
            .unwrap();
        server.join().unwrap();
        assert!(matches!(
            result,
            NodeWitnessMutationResult::AcceptedSuccess {
                kind: MutationKind::LeaseRenew,
                response: NodeWitnessSuccess::LeaseRenewed(_),
            }
        ));
        assert!(
            store
                .load_existing()
                .unwrap()
                .outstanding_mutation
                .is_none()
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn stage10_lease_release_success_completes_fresh_outstanding() {
        let path = test_path("release-success");
        let store = NodeMutationStore::new(&path, ClusterId::new("cluster"), NodeId::new("node-a"));
        store.initialize_new().unwrap();
        store
            .arm_release_obligation(Term(7), LeaseId::new("lease-1"))
            .unwrap();
        let runtime = NodeWitnessMutationRuntime::new(&store, NodeId::new("node-a"));
        let (node, witness) = connection_pair();
        let server = thread::spawn(move || {
            serve_custom_response(
                witness,
                None,
                ProtocolMessage::LeaseReleased(LeaseReleasedPayload {
                    term: Term(7),
                    lease_id: LeaseId::new("lease-1"),
                    result: "released".to_string(),
                }),
                WitnessResponseContext {
                    term: Term(7),
                    lease_id: None,
                },
                None,
            )
        });
        let result = runtime
            .begin_and_execute_lease_release_once(
                &mut session_from(node),
                Term(7),
                LeaseId::new("lease-1"),
                "cleanup".to_string(),
            )
            .unwrap();
        server.join().unwrap();
        assert!(matches!(
            result,
            NodeWitnessMutationResult::AcceptedSuccess {
                kind: MutationKind::LeaseRelease,
                response: NodeWitnessSuccess::LeaseReleased(_),
            }
        ));
        assert!(
            store
                .load_existing()
                .unwrap()
                .outstanding_mutation
                .is_none()
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn stage10_restart_retries_exact_durable_mutation() {
        let path = test_path("restart-retry");
        let store = NodeMutationStore::new(&path, ClusterId::new("cluster"), NodeId::new("node-a"));
        store.initialize_new().unwrap();
        let original = store
            .begin_lease_request(Term(0), 100, DurationMs(10_000))
            .unwrap();
        let restarted_store =
            NodeMutationStore::new(&path, ClusterId::new("cluster"), NodeId::new("node-a"));
        let (node, witness) = connection_pair();
        let (sender, receiver) = mpsc::channel();
        let server = thread::spawn(move || {
            serve_custom_response(
                witness,
                None,
                ProtocolMessage::LeaseGrant(LeaseGrantPayload {
                    term: Term(1),
                    lease_id: LeaseId::new("lease-1"),
                    holder_node_id: NodeId::new("node-a"),
                    lease_ttl_ms: DurationMs(10_000),
                    renew_after_ms: DurationMs(3_000),
                    lease_remaining_ms: DurationMs(10_000),
                }),
                WitnessResponseContext {
                    term: Term(1),
                    lease_id: Some(LeaseId::new("lease-1")),
                },
                Some(sender),
            )
        });
        let result = NodeWitnessMutationRuntime::new(&restarted_store, NodeId::new("node-a"))
            .retry_outstanding_once(&mut session_from(node))
            .unwrap();
        let observed = receiver.recv().unwrap();
        server.join().unwrap();
        assert!(matches!(
            result,
            NodeWitnessMutationResult::AcceptedSuccess { .. }
        ));
        assert_eq!(observed.0, original.request_id);
        assert_eq!(observed.1, original.mutation_generation);
        assert_eq!(
            observed.2,
            ProtocolMessage::LeaseRequest(match original.mutation {
                DurableWitnessMutation::LeaseRequest {
                    observed_term,
                    priority,
                    requested_ttl,
                } => crate::protocol::LeaseRequestPayload {
                    mutation_generation: original.mutation_generation,
                    observed_term,
                    priority,
                    requested_ttl,
                },
                _ => unreachable!(),
            })
        );
        assert!(
            restarted_store
                .load_existing()
                .unwrap()
                .outstanding_mutation
                .is_none()
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn stage10_response_loss_retries_duplicate_logical_mutation() {
        let path = test_path("response-loss");
        let store = NodeMutationStore::new(&path, ClusterId::new("cluster"), NodeId::new("node-a"));
        store.initialize_new().unwrap();
        let (first_node, first_witness) = connection_pair();
        let first_server = thread::spawn(move || discard_request(first_witness));
        let first = NodeWitnessMutationRuntime::new(&store, NodeId::new("node-a"))
            .begin_and_execute_lease_request_once(
                &mut session_from(first_node),
                Term(0),
                100,
                DurationMs(10_000),
            );
        first_server.join().unwrap();
        assert!(first.is_err());
        let outstanding = store.load_existing().unwrap().outstanding_mutation.unwrap();
        let (retry_node, retry_witness) = connection_pair();
        let server = thread::spawn(move || serve_grant(retry_witness));
        let result = NodeWitnessMutationRuntime::new(&store, NodeId::new("node-a"))
            .retry_outstanding_once(&mut session_from(retry_node))
            .unwrap();
        server.join().unwrap();
        assert!(matches!(
            result,
            NodeWitnessMutationResult::AcceptedSuccess { .. }
        ));
        let state = store.load_existing().unwrap();
        assert!(state.outstanding_mutation.is_none());
        assert_eq!(
            state.highest_started_mutation_generation,
            outstanding.mutation_generation
        );
        let _ = fs::remove_file(path);
    }

    /// v0.6 A-3: a response for an earlier (timed-out) request that was still
    /// queued on the connection must not consume the new attempt's slot. It is
    /// discarded and the correlated answer is used.
    #[test]
    fn a_late_response_of_an_older_request_is_discarded_not_fatal() {
        let path = test_path("late-response-discarded");
        let store = NodeMutationStore::new(&path, ClusterId::new("cluster"), NodeId::new("node-a"));
        store.initialize_new().unwrap();
        let (node, witness) = connection_pair();
        let server = thread::spawn(move || {
            use crate::witness_runtime::{
                WitnessResponseContext, send_witness_response_with_context,
            };
            let auth = MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32]));
            let mut witness = witness;
            let mut process = ProcessSession::from_session_id(SessionId::new("session-w"));
            let pending = witness.receive_pending(&CborSerializer, &auth).unwrap();
            let request_id = pending
                .message()
                .unsigned()
                .common
                .request_id
                .clone()
                .unwrap();
            // A late answer of an older generation arrives first.
            send_witness_response_with_context(
                &mut witness,
                &mut process,
                RequestId::new("00000000-0000-4000-8000-0000000000aa"),
                ProtocolMessage::LeaseReject(crate::protocol::LeaseRejectPayload {
                    code: WitnessMutationOutcomeCode::PolicyReject,
                    reason: "older generation".to_string(),
                }),
                WitnessResponseContext {
                    term: Term(0),
                    lease_id: None,
                },
                &CborSerializer,
                &auth,
            )
            .unwrap();
            send_witness_response_with_context(
                &mut witness,
                &mut process,
                request_id,
                ProtocolMessage::LeaseGrant(LeaseGrantPayload {
                    term: Term(1),
                    lease_id: LeaseId::new("lease-1"),
                    holder_node_id: NodeId::new("node-a"),
                    lease_ttl_ms: DurationMs(10_000),
                    renew_after_ms: DurationMs(3_000),
                    lease_remaining_ms: DurationMs(10_000),
                }),
                WitnessResponseContext {
                    term: Term(1),
                    lease_id: Some(LeaseId::new("lease-1")),
                },
                &CborSerializer,
                &auth,
            )
            .unwrap();
        });
        let result = NodeWitnessMutationRuntime::new(&store, NodeId::new("node-a"))
            .begin_and_execute_lease_request_once(
                &mut session_from(node),
                Term(0),
                100,
                DurationMs(10_000),
            )
            .unwrap();
        server.join().unwrap();
        assert!(
            matches!(
                result,
                NodeWitnessMutationResult::AcceptedSuccess {
                    response: NodeWitnessSuccess::LeaseGrant(_),
                    ..
                }
            ),
            "the correlated grant must be used, not the late reject: {result:?}"
        );
        assert!(
            store
                .load_existing()
                .unwrap()
                .outstanding_mutation
                .is_none()
        );
        let _ = fs::remove_file(path);
    }

    /// The bound is real: a stream of foreign responses never completes the
    /// request and the durable record is retained.
    #[test]
    fn too_many_uncorrelated_responses_retain_the_record() {
        let path = test_path("late-response-exhausted");
        let store = NodeMutationStore::new(&path, ClusterId::new("cluster"), NodeId::new("node-a"));
        store.initialize_new().unwrap();
        let (node, witness) = connection_pair();
        let server = thread::spawn(move || {
            use crate::witness_runtime::{
                WitnessResponseContext, send_witness_response_with_context,
            };
            let auth = MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32]));
            let mut witness = witness;
            let mut process = ProcessSession::from_session_id(SessionId::new("session-w"));
            let _ = witness.receive_pending(&CborSerializer, &auth).unwrap();
            for n in 0..6u8 {
                send_witness_response_with_context(
                    &mut witness,
                    &mut process,
                    RequestId::new(format!("00000000-0000-4000-8000-0000000000{n:02x}")),
                    ProtocolMessage::LeaseReject(crate::protocol::LeaseRejectPayload {
                        code: WitnessMutationOutcomeCode::PolicyReject,
                        reason: "foreign".to_string(),
                    }),
                    WitnessResponseContext {
                        term: Term(0),
                        lease_id: None,
                    },
                    &CborSerializer,
                    &auth,
                )
                .unwrap();
            }
            std::thread::sleep(Duration::from_millis(100));
        });
        let result = NodeWitnessMutationRuntime::new(&store, NodeId::new("node-a"))
            .begin_and_execute_lease_request_once(
                &mut session_from(node),
                Term(0),
                100,
                DurationMs(10_000),
            );
        server.join().unwrap();
        assert!(
            matches!(
                result,
                Err(NodeWitnessRuntimeError::Witness(
                    crate::witness_runtime::WitnessRuntimeError::UncorrelatedResponsesExhausted
                ))
            ),
            "{result:?}"
        );
        assert!(
            store
                .load_existing()
                .unwrap()
                .outstanding_mutation
                .is_some()
        );
        let _ = fs::remove_file(path);
    }

    /// v0.6 A-3 changes the surface, not the contract: a response for a
    /// different request id is never accepted. It is discarded and the read
    /// continues, so the attempt ends without an answer (the scripted peer
    /// then closes) and the durable record is retained.
    #[test]
    fn stage10_wrong_request_id_retains_outstanding() {
        let path = test_path("wrong-request-id");
        let store = NodeMutationStore::new(&path, ClusterId::new("cluster"), NodeId::new("node-a"));
        store.initialize_new().unwrap();
        let (node, witness) = connection_pair();
        let wrong_id = RequestId::new("00000000-0000-4000-8000-000000000004");
        let server = thread::spawn(move || {
            serve_custom_response(
                witness,
                Some(wrong_id),
                ProtocolMessage::LeaseGrant(LeaseGrantPayload {
                    term: Term(1),
                    lease_id: LeaseId::new("lease-1"),
                    holder_node_id: NodeId::new("node-a"),
                    lease_ttl_ms: DurationMs(10_000),
                    renew_after_ms: DurationMs(3_000),
                    lease_remaining_ms: DurationMs(10_000),
                }),
                WitnessResponseContext {
                    term: Term(1),
                    lease_id: Some(LeaseId::new("lease-1")),
                },
                None,
            )
        });
        let result = NodeWitnessMutationRuntime::new(&store, NodeId::new("node-a"))
            .begin_and_execute_lease_request_once(
                &mut session_from(node),
                Term(0),
                100,
                DurationMs(10_000),
            );
        server.join().unwrap();
        assert!(
            matches!(
                result,
                Err(NodeWitnessRuntimeError::Witness(
                    crate::witness_runtime::WitnessRuntimeError::SessionClosed
                        | crate::witness_runtime::WitnessRuntimeError::UncorrelatedResponsesExhausted
                ))
            ),
            "a foreign request id must never be accepted: {result:?}"
        );
        assert!(
            store
                .load_existing()
                .unwrap()
                .outstanding_mutation
                .is_some()
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn stage10_wrong_response_kind_retains_outstanding() {
        let path = test_path("wrong-response-kind");
        let store = NodeMutationStore::new(&path, ClusterId::new("cluster"), NodeId::new("node-a"));
        store.initialize_new().unwrap();
        let (node, witness) = connection_pair();
        let server = thread::spawn(move || {
            serve_custom_response(
                witness,
                None,
                ProtocolMessage::LeaseRenewed(renewed_payload(Term(1), LeaseId::new("lease-1"))),
                WitnessResponseContext {
                    term: Term(1),
                    lease_id: Some(LeaseId::new("lease-1")),
                },
                None,
            )
        });
        let result = NodeWitnessMutationRuntime::new(&store, NodeId::new("node-a"))
            .begin_and_execute_lease_request_once(
                &mut session_from(node),
                Term(0),
                100,
                DurationMs(10_000),
            );
        server.join().unwrap();
        assert!(matches!(
            result,
            Err(NodeWitnessRuntimeError::Witness(
                crate::witness_runtime::WitnessRuntimeError::ResponseKindMismatch { .. }
            ))
        ));
        assert!(
            store
                .load_existing()
                .unwrap()
                .outstanding_mutation
                .is_some()
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn stage10_malformed_success_fields_retain_each_kind() {
        let cases = [
            ("grant", MutationKind::LeaseRequest),
            ("renewed", MutationKind::LeaseRenew),
            ("released", MutationKind::LeaseRelease),
        ];
        for (name, kind) in cases {
            let path = test_path(&format!("malformed-{name}"));
            let store =
                NodeMutationStore::new(&path, ClusterId::new("cluster"), NodeId::new("node-a"));
            store.initialize_new().unwrap();
            if kind != MutationKind::LeaseRequest {
                store
                    .arm_release_obligation(Term(7), LeaseId::new("lease-1"))
                    .unwrap();
            }
            let (node, witness) = connection_pair();
            let server = thread::spawn(move || {
                let message = match kind {
                    MutationKind::LeaseRequest => ProtocolMessage::LeaseGrant(LeaseGrantPayload {
                        term: Term(1),
                        lease_id: LeaseId::new("lease-1"),
                        holder_node_id: NodeId::new("wrong-node"),
                        lease_ttl_ms: DurationMs(10_000),
                        renew_after_ms: DurationMs(3_000),
                        lease_remaining_ms: DurationMs(10_000),
                    }),
                    MutationKind::LeaseRenew => ProtocolMessage::LeaseRenewed(renewed_payload(
                        Term(8),
                        LeaseId::new("lease-1"),
                    )),
                    MutationKind::LeaseRelease => {
                        ProtocolMessage::LeaseReleased(LeaseReleasedPayload {
                            term: Term(8),
                            lease_id: LeaseId::new("lease-1"),
                            result: "released".to_string(),
                        })
                    }
                };
                serve_custom_response(
                    witness,
                    None,
                    message,
                    WitnessResponseContext {
                        term: Term(8),
                        lease_id: Some(LeaseId::new("lease-1")),
                    },
                    None,
                );
            });
            let result = match kind {
                MutationKind::LeaseRequest => {
                    NodeWitnessMutationRuntime::new(&store, NodeId::new("node-a"))
                        .begin_and_execute_lease_request_once(
                            &mut session_from(node),
                            Term(0),
                            100,
                            DurationMs(10_000),
                        )
                }
                MutationKind::LeaseRenew => {
                    NodeWitnessMutationRuntime::new(&store, NodeId::new("node-a"))
                        .begin_and_execute_lease_renew_once(
                            &mut session_from(node),
                            Term(7),
                            LeaseId::new("lease-1"),
                        )
                }
                MutationKind::LeaseRelease => {
                    NodeWitnessMutationRuntime::new(&store, NodeId::new("node-a"))
                        .begin_and_execute_lease_release_once(
                            &mut session_from(node),
                            Term(7),
                            LeaseId::new("lease-1"),
                            "cleanup".to_string(),
                        )
                }
            };
            server.join().unwrap();
            assert!(matches!(
                result,
                Err(NodeWitnessRuntimeError::InvalidSuccess(_))
            ));
            assert!(
                store
                    .load_existing()
                    .unwrap()
                    .outstanding_mutation
                    .is_some()
            );
            let _ = fs::remove_file(path);
        }
    }

    #[test]
    fn stage10_delayed_old_response_cannot_complete_new_generation() {
        let path = test_path("delayed-old-response");
        let store = NodeMutationStore::new(&path, ClusterId::new("cluster"), NodeId::new("node-a"));
        store.initialize_new().unwrap();
        let (first_node, first_witness) = connection_pair();
        let (sender, receiver) = mpsc::channel();
        let first_server = thread::spawn(move || {
            serve_custom_response(
                first_witness,
                None,
                ProtocolMessage::LeaseGrant(LeaseGrantPayload {
                    term: Term(1),
                    lease_id: LeaseId::new("lease-1"),
                    holder_node_id: NodeId::new("node-a"),
                    lease_ttl_ms: DurationMs(10_000),
                    renew_after_ms: DurationMs(3_000),
                    lease_remaining_ms: DurationMs(10_000),
                }),
                WitnessResponseContext {
                    term: Term(1),
                    lease_id: Some(LeaseId::new("lease-1")),
                },
                Some(sender),
            )
        });
        NodeWitnessMutationRuntime::new(&store, NodeId::new("node-a"))
            .begin_and_execute_lease_request_once(
                &mut session_from(first_node),
                Term(0),
                100,
                DurationMs(10_000),
            )
            .unwrap();
        let old_request_id = receiver.recv().unwrap().0;
        first_server.join().unwrap();
        let next = store
            .begin_lease_renew_for_test(Term(1), LeaseId::new("lease-1"))
            .unwrap();
        let (node, witness) = connection_pair();
        let server = thread::spawn(move || {
            serve_custom_response(
                witness,
                Some(old_request_id),
                ProtocolMessage::LeaseRenewed(renewed_payload(Term(1), LeaseId::new("lease-1"))),
                WitnessResponseContext {
                    term: Term(1),
                    lease_id: Some(LeaseId::new("lease-1")),
                },
                None,
            )
        });
        let result = NodeWitnessMutationRuntime::new(&store, NodeId::new("node-a"))
            .execute_outstanding_once(&mut session_from(node));
        server.join().unwrap();
        assert!(
            matches!(
                result,
                Err(NodeWitnessRuntimeError::Witness(
                    crate::witness_runtime::WitnessRuntimeError::SessionClosed
                        | crate::witness_runtime::WitnessRuntimeError::UncorrelatedResponsesExhausted
                ))
            ),
            "the delayed old response must not complete the new generation: {result:?}"
        );
        let state = store.load_existing().unwrap();
        assert_eq!(state.outstanding_mutation.unwrap(), next);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn stage10_completion_ambiguity_does_not_clear_outstanding() {
        let path = test_path("completion-ambiguity");
        let store = NodeMutationStore::new(&path, ClusterId::new("cluster"), NodeId::new("node-a"));
        store.initialize_new().unwrap();
        store
            .begin_lease_request(Term(0), 100, DurationMs(10_000))
            .unwrap();
        let (node, witness) = connection_pair();
        let server = thread::spawn(move || serve_grant(witness));
        crate::recovery::inject_fault_once(crate::recovery::FaultPoint::CanonicalParentFsync);
        let result = NodeWitnessMutationRuntime::new(&store, NodeId::new("node-a"))
            .execute_outstanding_once(&mut session_from(node));
        server.join().unwrap();
        assert!(matches!(
            result,
            Err(NodeWitnessRuntimeError::NodeMutation(
                NodeMutationError::RecoveryRequired(_)
            ))
        ));
        assert!(matches!(
            store.load_existing(),
            Err(NodeMutationError::RecoveryRequired(_))
        ));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(crate::recovery::marker_path(&path));
    }

    #[test]
    fn stage10_recovery_marker_blocks_new_mutation_send() {
        let path = test_path("recovery-gating");
        let store = NodeMutationStore::new(&path, ClusterId::new("cluster"), NodeId::new("node-a"));
        store.initialize_new().unwrap();
        fs::write(
            crate::recovery::marker_path(&path),
            "invalid recovery metadata",
        )
        .unwrap();
        let (node, _witness) = connection_pair();
        let result = NodeWitnessMutationRuntime::new(&store, NodeId::new("node-a"))
            .begin_and_execute_lease_request_once(
                &mut session_from(node),
                Term(0),
                100,
                DurationMs(10_000),
            );
        assert!(matches!(
            result,
            Err(NodeWitnessRuntimeError::NodeMutation(
                NodeMutationError::RecoveryRequired(_)
            ))
        ));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(crate::recovery::marker_path(&path));
    }

    #[test]
    fn stage10_reason_text_does_not_change_typed_classification() {
        let mut results = Vec::new();
        for reason in ["generation gap", "ordinary temporary outage"] {
            let path = test_path(&format!("reason-{reason:?}"));
            let store =
                NodeMutationStore::new(&path, ClusterId::new("cluster"), NodeId::new("node-a"));
            store.initialize_new().unwrap();
            let runtime = NodeWitnessMutationRuntime::new(&store, NodeId::new("node-a"));
            let (node, witness) = connection_pair();
            let server = thread::spawn(move || {
                serve_response_with_reason(
                    witness,
                    WitnessMutationOutcomeCode::TemporarilyUnavailable,
                    reason,
                )
            });
            let result = runtime
                .begin_and_execute_lease_request_once(
                    &mut session_from(node),
                    Term(0),
                    100,
                    DurationMs(10_000),
                )
                .unwrap();
            server.join().unwrap();
            results.push(result);
            assert!(
                store
                    .load_existing()
                    .unwrap()
                    .outstanding_mutation
                    .is_some()
            );
            let _ = fs::remove_file(path);
        }
        assert!(results.iter().all(|result| matches!(
            result,
            NodeWitnessMutationResult::TemporarilyUnavailable { .. }
        )));
    }

    #[test]
    fn historical_release_success_accepts_newer_current_authority_context() {
        let path = test_path("historical-release");
        let store = NodeMutationStore::new(&path, ClusterId::new("cluster"), NodeId::new("node-a"));
        store.initialize_new().unwrap();
        store
            .begin_lease_release_for_test(Term(7), LeaseId::new("lease-1"), "cleanup".to_string())
            .unwrap();
        let runtime = NodeWitnessMutationRuntime::new(&store, NodeId::new("node-a"));
        let (node, witness) = connection_pair();
        let server = thread::spawn(move || {
            serve_released(
                witness,
                Term(7),
                LeaseId::new("lease-1"),
                Term(8),
                Some(LeaseId::new("lease-2")),
            )
        });
        let result = runtime
            .retry_outstanding_once(&mut session_from(node))
            .unwrap();
        server.join().unwrap();
        assert!(matches!(
            result,
            NodeWitnessMutationResult::AcceptedSuccess {
                response: NodeWitnessSuccess::LeaseReleased(_),
                ..
            }
        ));
        assert!(
            store
                .load_existing()
                .unwrap()
                .outstanding_mutation
                .is_none()
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn send_failure_after_begin_keeps_exact_outstanding() {
        let path = test_path("send-failure");
        let store = NodeMutationStore::new(&path, ClusterId::new("cluster"), NodeId::new("node-a"));
        store.initialize_new().unwrap();
        let runtime = NodeWitnessMutationRuntime::new(&store, NodeId::new("node-a"));
        let (node, witness) = connection_pair();
        drop(witness);
        let result = runtime.begin_and_execute_lease_request_once(
            &mut session_from(node),
            Term(0),
            100,
            DurationMs(10_000),
        );
        assert!(result.is_err());
        let outstanding = store.load_existing().unwrap().outstanding_mutation.unwrap();
        assert_eq!(outstanding.mutation_generation, 1);
        assert_eq!(outstanding.kind(), MutationKind::LeaseRequest);
        let _ = fs::remove_file(path);
    }

    // ---- J35 (cf30, Amendment C): D-tol, C-d, C-c ----

    /// D-tol: up to four foreign frames may precede the correlated answer;
    /// the fifth foreign frame ends the exchange as exhausted, and the
    /// durable record stays (cf29 behaviour, now pinned at the boundary).
    fn j35_discard_run(foreign: u8) -> Result<NodeWitnessMutationResult, NodeWitnessRuntimeError> {
        let path = test_path(&format!("j35-discard-{foreign}"));
        let store = NodeMutationStore::new(&path, ClusterId::new("cluster"), NodeId::new("node-a"));
        store.initialize_new().unwrap();
        let (node, witness) = connection_pair();
        let server = thread::spawn(move || {
            let auth = MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32]));
            let mut witness = witness;
            let mut process = ProcessSession::from_session_id(SessionId::new("session-w"));
            let pending = witness.receive_pending(&CborSerializer, &auth).unwrap();
            let request_id = pending
                .message()
                .unsigned()
                .common
                .request_id
                .clone()
                .unwrap();
            for n in 0..foreign {
                let _ = send_witness_response_with_context(
                    &mut witness,
                    &mut process,
                    RequestId::new(format!("00000000-0000-4000-8000-0000000000{n:02x}")),
                    ProtocolMessage::LeaseReject(crate::protocol::LeaseRejectPayload {
                        code: WitnessMutationOutcomeCode::PolicyReject,
                        reason: "foreign".to_string(),
                    }),
                    WitnessResponseContext {
                        term: Term(0),
                        lease_id: None,
                    },
                    &CborSerializer,
                    &auth,
                );
            }
            let _ = send_witness_response_with_context(
                &mut witness,
                &mut process,
                request_id,
                ProtocolMessage::LeaseGrant(LeaseGrantPayload {
                    term: Term(1),
                    lease_id: LeaseId::new("lease-1"),
                    holder_node_id: NodeId::new("node-a"),
                    lease_ttl_ms: DurationMs(10_000),
                    renew_after_ms: DurationMs(3_000),
                    lease_remaining_ms: DurationMs(10_000),
                }),
                WitnessResponseContext {
                    term: Term(1),
                    lease_id: Some(LeaseId::new("lease-1")),
                },
                &CborSerializer,
                &auth,
            );
            std::thread::sleep(Duration::from_millis(100));
        });
        let result = NodeWitnessMutationRuntime::new(&store, NodeId::new("node-a"))
            .begin_and_execute_lease_request_once(
                &mut session_from(node),
                Term(0),
                100,
                DurationMs(10_000),
            );
        server.join().unwrap();
        let retained = store
            .load_existing()
            .unwrap()
            .outstanding_mutation
            .is_some();
        let _ = fs::remove_file(path);
        assert_eq!(
            retained,
            !matches!(
                result,
                Ok(NodeWitnessMutationResult::AcceptedSuccess { .. })
            ),
            "foreign={foreign}: {result:?}"
        );
        result
    }

    #[test]
    fn j35_discard_bound_is_four_foreign_frames() {
        for foreign in [0u8, 4] {
            assert!(
                matches!(
                    j35_discard_run(foreign),
                    Ok(NodeWitnessMutationResult::AcceptedSuccess { .. })
                ),
                "foreign={foreign}"
            );
        }
        for foreign in [5u8, 6] {
            assert!(
                matches!(
                    j35_discard_run(foreign),
                    Err(NodeWitnessRuntimeError::Witness(
                        crate::witness_runtime::WitnessRuntimeError::UncorrelatedResponsesExhausted
                    ))
                ),
                "foreign={foreign}"
            );
        }
    }

    /// C-d: two consecutive exhausted correlations of one mutation are
    /// retried, the third reaches the limit; a correlated response of that
    /// mutation resets the count, another mutation starts again at one, and
    /// a correlated response of another mutation does not reset it.
    #[test]
    fn j35_uncorrelated_retry_counter_counts_consecutive_exhaustions() {
        let a = RequestId::new("00000000-0000-4000-8000-0000000000a1");
        let b = RequestId::new("00000000-0000-4000-8000-0000000000b1");
        let mut counter = UncorrelatedRetryCounter::default();
        assert_eq!(UNCORRELATED_RETRY_LIMIT, 3);
        assert_eq!(counter.record_exhausted(&a, 4), UncorrelatedRetry::Retry);
        assert_eq!(counter.record_exhausted(&a, 4), UncorrelatedRetry::Retry);
        assert_eq!(
            counter.record_exhausted(&a, 4),
            UncorrelatedRetry::Exhausted
        );
        assert_eq!(
            counter.record_exhausted(&a, 4),
            UncorrelatedRetry::Exhausted
        );
        counter.record_correlated(&a, 4);
        assert_eq!(counter.count(), 0);
        assert_eq!(counter.record_exhausted(&a, 4), UncorrelatedRetry::Retry);
        counter.record_correlated(&b, 4);
        counter.record_correlated(&a, 5);
        assert_eq!(
            counter.count(),
            1,
            "another mutation's response does not reset"
        );
        assert_eq!(counter.record_exhausted(&a, 4), UncorrelatedRetry::Retry);
        // Same request id, another generation, or another request: a new count.
        assert_eq!(counter.record_exhausted(&a, 5), UncorrelatedRetry::Retry);
        assert_eq!(counter.count(), 1);
        assert_eq!(counter.record_exhausted(&b, 5), UncorrelatedRetry::Retry);
        assert_eq!(counter.count(), 1);
    }

    /// C-c: after a timeout the next due iterations are skipped 1, 2, 4, ...
    /// times; the 60 s cap since the last attempt always lets one through;
    /// another session or mutation, or any other outcome, clears it.
    #[test]
    fn j35_renew_retry_backoff_skips_doubling_iterations_within_the_cap() {
        let session = std::sync::Arc::new(());
        let other_session = std::sync::Arc::new(());
        let id = RequestId::new("00000000-0000-4000-8000-0000000000c1");
        let t0 = std::time::Instant::now();
        let at = |seconds: u64| t0 + Duration::from_secs(seconds);
        let mut backoff = RenewRetryBackoff::default();
        assert!(backoff.may_send(&session, &id, 7, at(0)));
        // Pattern of sends over consecutive 1 s iterations after timeouts.
        let mut sends = Vec::new();
        let mut now = 0;
        backoff.record_timeout(&session, &id, 7, at(now));
        for _ in 0..12 {
            now += 1;
            if backoff.may_send(&session, &id, 7, at(now)) {
                sends.push(now);
                backoff.record_timeout(&session, &id, 7, at(now));
            }
        }
        // Skips of 1, 2, 4, 8: sends at 2, 5, 10.
        assert_eq!(sends, [2, 5, 10]);
        // The cap: however many skips remain, 60 s after the last attempt the
        // next iteration sends.
        let mut capped = RenewRetryBackoff::default();
        for i in 0..10 {
            capped.record_timeout(&session, &id, 7, at(i));
        }
        assert!(!capped.may_send(&session, &id, 7, at(10)));
        assert!(capped.may_send(&session, &id, 7, at(9 + 60)));
        assert_eq!(RENEW_RETRY_INTERVAL_CAP, Duration::from_secs(60));
        // Another session or mutation is not spaced.
        let mut keyed = RenewRetryBackoff::default();
        keyed.record_timeout(&session, &id, 7, at(0));
        assert!(keyed.may_send(&other_session, &id, 7, at(1)));
        keyed.record_timeout(&session, &id, 7, at(1));
        assert!(keyed.may_send(&session, &id, 8, at(2)));
        keyed.record_timeout(&session, &id, 7, at(2));
        keyed.clear();
        assert!(keyed.may_send(&session, &id, 7, at(3)));
    }

    /// C-c: only a timeout of the attempt counts as a timeout.
    #[test]
    fn j35_only_an_io_timeout_is_a_timeout() {
        let timeout = |kind| {
            NodeWitnessRuntimeError::Witness(crate::witness_runtime::WitnessRuntimeError::Tcp(
                crate::tcp::TcpError::Io(std::io::Error::new(kind, "x")),
            ))
        };
        assert!(is_timeout(&timeout(std::io::ErrorKind::TimedOut)));
        assert!(is_timeout(&timeout(std::io::ErrorKind::WouldBlock)));
        assert!(!is_timeout(&timeout(std::io::ErrorKind::ConnectionReset)));
        let read_timeout = |kind| {
            NodeWitnessRuntimeError::Witness(crate::witness_runtime::WitnessRuntimeError::Tcp(
                crate::tcp::TcpError::Transport(crate::transport::TransportError::Io(
                    std::io::Error::new(kind, "x"),
                )),
            ))
        };
        assert!(is_timeout(&read_timeout(std::io::ErrorKind::TimedOut)));
        assert!(is_timeout(&read_timeout(std::io::ErrorKind::WouldBlock)));
        assert!(!is_timeout(&read_timeout(
            std::io::ErrorKind::ConnectionReset
        )));
        assert!(!is_timeout(&NodeWitnessRuntimeError::Witness(
            crate::witness_runtime::WitnessRuntimeError::Tcp(crate::tcp::TcpError::Transport(
                crate::transport::TransportError::TruncatedPayload
            ))
        )));
        assert!(!is_timeout(&NodeWitnessRuntimeError::Witness(
            crate::witness_runtime::WitnessRuntimeError::SessionClosed
        )));
        assert!(!is_timeout(&NodeWitnessRuntimeError::Witness(
            crate::witness_runtime::WitnessRuntimeError::UncorrelatedResponsesExhausted
        )));
    }
}
