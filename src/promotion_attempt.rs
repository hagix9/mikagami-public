//! Stage 13.1 promotion attempt lifecycle (inert).
//!
//! This module is lifecycle plumbing only. It represents
//! `no attempt -> explicit request accepted -> one attempt in progress ->
//! completed / cancelled -> no attempt` for a single explicit local promotion
//! attempt owned by `Daemon` (the single shutdown-truth owner). It is
//! process-local: nothing here is persisted, journaled, serialized, or sent
//! on the wire.
//!
//! The lifecycle deliberately stores only the in-flight `PromotionRequestId`.
//! It has no field capable of holding an `AuthorityAttemptEvaluation`, a
//! `WitnessAuthorityViewEvidence`, a `RuntimeLeaseAuthority`, an `AuthorityPermission`,
//! a resource handle, or a callback, and it exposes no method that can reach
//! promotion, lease, VIP, service, GARP, fencing, or Active-commit mutation.
//! `Authorized` remains an inert decision result and is never stored for
//! later consumption; fresh revalidation and lease handoff are Stage 13.2's
//! responsibility, so an in-flight attempt grants no future execution
//! authority.

/// Local, ephemeral identity of one explicit promotion-attempt request.
///
/// Distinct from the peer-wire `OperationId` (promotion/demotion message
/// correlation), the Witness `RequestId`/`SessionId`, the `LeaseId`, peer
/// sequence numbers, and `WitnessAuthorityViewEvidence`: reusing any of those for a
/// local operator attempt would be ambiguous. The identity is meaningful only
/// for the process lifetime of the owning `Daemon`; it is not persisted and
/// carries no authority — knowing an id grants nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PromotionRequestId(String);

impl PromotionRequestId {
    pub(crate) fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// An explicit request to open the single promotion-attempt slot.
///
/// Carries only the request identity. It contains no authorization, term,
/// evidence, lease, permission, resource handle, or callback, so accepting it
/// cannot transitively grant mutation capability.
#[derive(Debug)]
pub(crate) struct PromotionExecutionRequest {
    request_id: PromotionRequestId,
}

impl PromotionExecutionRequest {
    pub(crate) const fn new(request_id: PromotionRequestId) -> Self {
        Self { request_id }
    }

    pub(crate) const fn request_id(&self) -> &PromotionRequestId {
        &self.request_id
    }

    /// Consume the request into its identity.
    pub(crate) fn into_request_id(self) -> PromotionRequestId {
        self.request_id
    }
}

/// Why an explicit promotion-attempt request was not accepted.
///
/// Rejection is total: the request changes nothing and the in-flight attempt
/// (if any) is left untouched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PromotionAttemptRejection {
    /// The single attempt slot is occupied. Applies uniformly whether the new
    /// request's identity is fresh or a duplicate of the in-flight identity:
    /// the in-flight identity is never replaced.
    AlreadyInProgress,
    /// The authoritative `Daemon`-owned shutdown state is requested. New
    /// attempts are not accepted for the remainder of this process lifetime.
    RejectedShutdown,
}

/// Stage 13.2 endpoint classification for one explicit promotion attempt.
///
/// This type is inert: it reports what the execution driver concluded, never
/// carries authority. It contains no `WitnessAuthorityViewEvidence`, no
/// `RuntimeLeaseAuthority`, no `AuthorityAttemptEvaluation`, no callback, and
/// no resource handle, so holding a result grants nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PromotionAttemptResult {
    /// The request was never accepted into the single attempt slot. Nothing
    /// ran: no revalidation, no lease request, no mutation.
    Rejected(PromotionAttemptRejection),
    /// The approved Stage 11 success boundary was reached and the attempt
    /// was retired. `Authorized`, a lease grant, or a workflow entry alone
    /// never produces this variant.
    Succeeded,
    /// The attempt was accepted but stopped before any Stage 11 resource
    /// mutation began: fresh revalidation failed, the lease was not granted,
    /// a shutdown was observed, or a final pre-mutation check failed.
    BlockedBeforeMutation,
    /// Stage 11 mutation began but did not reach its success boundary. Stage
    /// 11 owns rollback/resource cleanup; this stage only reports it.
    MutationFailed,
    /// The accepted attempt was cancelled before Stage 11 mutation began. A
    /// late authorization or lease completion cannot resurrect it.
    Cancelled,
}

/// Stage 13.1 lifecycle of one explicit local promotion attempt.
///
/// Only `Idle` and `InFlight` are states; `completed` and `cancelled` are
/// transitions back to `Idle`, not retained states — no stale attempt or
/// authorization survives to be reused later. There is no `Promoted`,
/// `Prepared`, or executing state: this stage ends at inert plumbing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PromotionAttemptLifecycle {
    /// No attempt exists. The slot is free.
    Idle,
    /// One explicit attempt is in progress, identified only by its request
    /// id. No authorization, term, evidence, or capability is attached.
    InFlight(PromotionRequestId),
}

impl PromotionAttemptLifecycle {
    /// The restart/default state: no attempt.
    pub(crate) const fn idle() -> Self {
        Self::Idle
    }

    /// The in-flight attempt's request identity, if any.
    pub(crate) const fn in_flight_id(&self) -> Option<&PromotionRequestId> {
        match self {
            Self::Idle => None,
            Self::InFlight(request_id) => Some(request_id),
        }
    }

    /// Accept an explicit request into the empty slot. Fails closed while an
    /// attempt is in flight — including a duplicate of the in-flight id — so
    /// the in-flight identity can never be replaced or aliased. Shutdown
    /// rejection is applied by the `Daemon` owner before this call.
    pub(crate) fn accept(
        &mut self,
        request: PromotionExecutionRequest,
    ) -> Result<PromotionRequestId, PromotionAttemptRejection> {
        match self {
            Self::Idle => {
                let request_id = request.into_request_id();
                *self = Self::InFlight(request_id.clone());
                Ok(request_id)
            }
            Self::InFlight(_) => Err(PromotionAttemptRejection::AlreadyInProgress),
        }
    }

    /// Retire the in-flight attempt, if any, returning its identity.
    /// `Idle` is a no-op. Used by both the complete and cancel transitions.
    fn retire(&mut self) -> Option<PromotionRequestId> {
        match std::mem::replace(self, Self::Idle) {
            Self::InFlight(request_id) => Some(request_id),
            Self::Idle => None,
        }
    }

    /// Complete the in-flight attempt: `InFlight -> Idle`, returning the
    /// retired identity. On `Idle` this is a no-op (`None`). Completion is
    /// inert bookkeeping only — it performs and implies no promotion.
    pub(crate) fn finish(&mut self) -> Option<PromotionRequestId> {
        self.retire()
    }

    /// Cancel the in-flight attempt: `InFlight -> Idle`, returning the
    /// retired identity. On `Idle` this is a no-op (`None`).
    pub(crate) fn cancel(&mut self) -> Option<PromotionRequestId> {
        self.retire()
    }
}
