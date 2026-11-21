//! Witness authority projections and the Stage 4 LEASE_REQUEST operation.

use crate::protocol::{
    DurationMs, LeaseGrantPayload, LeaseId, LeaseRejectPayload, LeaseReleasedPayload, NodeId,
    ProtocolMessage, RequestId, Term, TermStatusPayload, UnsignedEnvelope,
    WitnessMutationOutcomeCode,
};
use crate::session::ProcessSession;
use crate::witness_journal::{self, CommittedSemanticResult, JournalClassification, JournalError};
use crate::witness_runtime::{
    PendingWitnessMessage, WitnessConnection, WitnessRequestObservation, WitnessResponseContext,
    handle_pending_witness_request,
};
use crate::witness_state::{
    BootIdProvider, LeaseState, MonotonicClock, WitnessNotReadyReason, WitnessReadiness,
    WitnessStateError, WitnessStateStore,
};

const LEASE_TTL_MS: u64 = 10_000;
const RENEW_AFTER_MS: u64 = 3_000;

static AUTHORITY_MUTATION_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseExpiryResult {
    NotExpired,
    Expired,
}

fn lock_authority_mutation(
    lock: &std::sync::Mutex<()>,
) -> Result<std::sync::MutexGuard<'_, ()>, WitnessAuthorityError> {
    lock.lock()
        .map_err(|_| WitnessAuthorityError::AuthorityLockPoisoned)
}

fn authority_mutation_guard() -> Result<std::sync::MutexGuard<'static, ()>, WitnessAuthorityError> {
    lock_authority_mutation(&AUTHORITY_MUTATION_LOCK)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedTermStatus {
    pub request_id: RequestId,
    pub requester: NodeId,
    pub payload: TermStatusPayload,
    pub context: WitnessResponseContext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedLeaseResponse {
    pub request_id: RequestId,
    pub message: ProtocolMessage,
    pub context: WitnessResponseContext,
}

#[derive(Debug)]
pub enum WitnessAuthorityError {
    NotReady(WitnessNotReadyReason),
    UnknownLease,
    NotLeaseRequest,
    NotLeaseRenew,
    NotLeaseRelease,
    AuthorityLockPoisoned,
    Journal(JournalError),
    LeaseIdGeneration,
    DeadlineOverflow,
    AuthorityInvariant(&'static str),
    State(WitnessStateError),
    Runtime(crate::witness_runtime::WitnessRuntimeError),
    NotGetTerm,
}

impl std::fmt::Display for WitnessAuthorityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "witness authority error: {self:?}")
    }
}

impl std::error::Error for WitnessAuthorityError {}

pub fn handle_get_term_authority<B, C>(
    connection: &mut WitnessConnection,
    pending: &PendingWitnessMessage,
    store: &WitnessStateStore<B, C>,
) -> Result<PreparedTermStatus, WitnessAuthorityError>
where
    B: BootIdProvider,
    C: MonotonicClock,
{
    let observation = handle_pending_witness_request(connection, pending)
        .map_err(WitnessAuthorityError::Runtime)?;
    prepare_get_term_response(store, &observation)
}

pub fn handle_lease_request_authority<B, C>(
    connection: &mut WitnessConnection,
    pending: &PendingWitnessMessage,
    store: &WitnessStateStore<B, C>,
) -> Result<PreparedLeaseResponse, WitnessAuthorityError>
where
    B: BootIdProvider,
    C: MonotonicClock,
{
    let observation = handle_pending_witness_request(connection, pending)
        .map_err(WitnessAuthorityError::Runtime)?;
    prepare_lease_request_authority(store, &observation, pending.message().unsigned())
}

pub fn handle_lease_renew_authority<B, C>(
    connection: &mut WitnessConnection,
    pending: &PendingWitnessMessage,
    store: &WitnessStateStore<B, C>,
) -> Result<PreparedLeaseResponse, WitnessAuthorityError>
where
    B: BootIdProvider,
    C: MonotonicClock,
{
    let observation = handle_pending_witness_request(connection, pending)
        .map_err(WitnessAuthorityError::Runtime)?;
    prepare_lease_renew_authority(store, &observation, pending.message().unsigned())
}

pub fn handle_lease_release_authority<B, C>(
    connection: &mut WitnessConnection,
    pending: &PendingWitnessMessage,
    store: &WitnessStateStore<B, C>,
) -> Result<PreparedLeaseResponse, WitnessAuthorityError>
where
    B: BootIdProvider,
    C: MonotonicClock,
{
    let observation = handle_pending_witness_request(connection, pending)
        .map_err(WitnessAuthorityError::Runtime)?;
    prepare_lease_release_authority(store, &observation, pending.message().unsigned())
}

pub fn prepare_lease_release_authority<B, C>(
    store: &WitnessStateStore<B, C>,
    observation: &WitnessRequestObservation,
    request: &UnsignedEnvelope,
) -> Result<PreparedLeaseResponse, WitnessAuthorityError>
where
    B: BootIdProvider,
    C: MonotonicClock,
{
    let _mutation_guard = authority_mutation_guard()?;
    let WitnessRequestObservation::LeaseRelease {
        request_id,
        sender_node_id,
        payload,
        ..
    } = observation
    else {
        return Err(WitnessAuthorityError::NotLeaseRelease);
    };
    let ProtocolMessage::LeaseRelease(request_payload) = &request.message else {
        return Err(WitnessAuthorityError::NotLeaseRelease);
    };
    if request.common.request_id.as_ref() != Some(request_id)
        || request.common.sender_node_id.as_str() != sender_node_id.as_str()
        || request_payload != payload
    {
        return Err(WitnessAuthorityError::AuthorityInvariant(
            "LEASE_RELEASE observation does not match pending request",
        ));
    }

    let recovery = store.load();
    if recovery.readiness != WitnessReadiness::Ready {
        let WitnessReadiness::NotReady(reason) = recovery.readiness else {
            unreachable!();
        };
        return Err(WitnessAuthorityError::NotReady(reason));
    }
    let state = recovery.state.ok_or(WitnessAuthorityError::NotReady(
        WitnessNotReadyReason::StateCorrupt,
    ))?;
    let expected_old =
        recovery
            .expected_old
            .clone()
            .ok_or(WitnessAuthorityError::AuthorityInvariant(
                "missing snapshot provenance",
            ))?;

    match witness_journal::classify(&state, request).map_err(WitnessAuthorityError::Journal)? {
        JournalClassification::Duplicate { result } => {
            return reconstruct_duplicate_lease_release(&state, request_id, result);
        }
        JournalClassification::Conflict => {
            return Ok(outcome_reject_response(
                request_id,
                state.current_term,
                state.active_lease_id.clone(),
                WitnessMutationOutcomeCode::Conflict,
                "LEASE_RELEASE journal identity conflict",
            ));
        }
        JournalClassification::RetiredStale => {
            return Ok(outcome_reject_response(
                request_id,
                state.current_term,
                state.active_lease_id.clone(),
                WitnessMutationOutcomeCode::RetiredStale,
                "LEASE_RELEASE generation is retired or stale",
            ));
        }
        JournalClassification::GenerationGap => {
            return Ok(outcome_reject_response(
                request_id,
                state.current_term,
                state.active_lease_id.clone(),
                WitnessMutationOutcomeCode::GenerationGap,
                "LEASE_RELEASE generation gap",
            ));
        }
        JournalClassification::NewEligible => {}
    }

    if matches!(state.lease_state, LeaseState::Unknown) {
        return Err(WitnessAuthorityError::UnknownLease);
    }

    let reject_reason = if matches!(state.lease_state, LeaseState::None) {
        Some("there is no active lease to release")
    } else if state.current_term != payload.term {
        Some("release term does not match current Witness term")
    } else if state.active_lease_id.as_ref() != Some(&payload.lease_id) {
        Some("release lease_id does not match the active lease")
    } else if state.holder_node_id.as_ref() != Some(sender_node_id) {
        Some("only the current lease holder may release")
    } else if state.lease_ttl_ms.is_none()
        || state.lease_deadline_monotonic_ms.is_none()
        || state.active_lease_id.is_none()
        || state.holder_node_id.is_none()
    {
        return Err(WitnessAuthorityError::AuthorityInvariant(
            "active lease metadata is incomplete",
        ));
    } else {
        None
    };

    if let Some(reason) = reject_reason {
        return commit_release_reject(store, &state, request, request_id, reason, &expected_old);
    }

    let lease_id =
        state
            .active_lease_id
            .clone()
            .ok_or(WitnessAuthorityError::AuthorityInvariant(
                "active lease ID is missing",
            ))?;
    let released = LeaseReleasedPayload {
        term: state.current_term,
        lease_id: lease_id.clone(),
        result: "released".to_string(),
    };
    let mut authority_candidate = state.clone();
    authority_candidate.active_lease_id = None;
    authority_candidate.holder_node_id = None;
    authority_candidate.lease_ttl_ms = None;
    authority_candidate.lease_deadline_monotonic_ms = None;
    authority_candidate.lease_state = LeaseState::None;
    let candidate = witness_journal::commit_candidate(
        &authority_candidate,
        request,
        CommittedSemanticResult::LeaseReleased(released.clone()),
    )
    .map_err(WitnessAuthorityError::Journal)?;
    store
        .commit_candidate(&candidate, &expected_old)
        .map_err(WitnessAuthorityError::State)?;
    Ok(prepared_response(
        request_id.clone(),
        ProtocolMessage::LeaseReleased(released),
        state.current_term,
        None,
    ))
}

pub fn expire_lease_if_needed<B, C>(
    store: &WitnessStateStore<B, C>,
) -> Result<LeaseExpiryResult, WitnessAuthorityError>
where
    B: BootIdProvider,
    C: MonotonicClock,
{
    let _mutation_guard = authority_mutation_guard()?;
    let recovery = store.load();
    if recovery.readiness != WitnessReadiness::Ready {
        let WitnessReadiness::NotReady(reason) = recovery.readiness else {
            unreachable!();
        };
        return Err(WitnessAuthorityError::NotReady(reason));
    }
    let state = recovery.state.ok_or(WitnessAuthorityError::NotReady(
        WitnessNotReadyReason::StateCorrupt,
    ))?;
    let expected_old =
        recovery
            .expected_old
            .clone()
            .ok_or(WitnessAuthorityError::AuthorityInvariant(
                "missing snapshot provenance",
            ))?;
    match state.lease_state {
        LeaseState::None => return Ok(LeaseExpiryResult::NotExpired),
        LeaseState::Unknown => return Err(WitnessAuthorityError::UnknownLease),
        LeaseState::Active => {}
    }
    if state.active_lease_id.is_none()
        || state.holder_node_id.is_none()
        || state.lease_ttl_ms.is_none_or(|value| value.0 == 0)
        || state.lease_deadline_monotonic_ms.is_none()
    {
        return Err(WitnessAuthorityError::AuthorityInvariant(
            "active lease metadata is incomplete",
        ));
    }
    let deadline = state.lease_deadline_monotonic_ms.expect("checked above");
    let now = store
        .current_monotonic_ms()
        .map_err(WitnessAuthorityError::State)?;
    if now < deadline {
        return Ok(LeaseExpiryResult::NotExpired);
    }

    let mut candidate = state.clone();
    candidate.active_lease_id = None;
    candidate.holder_node_id = None;
    candidate.lease_ttl_ms = None;
    candidate.lease_deadline_monotonic_ms = None;
    candidate.lease_state = LeaseState::None;
    store
        .commit_candidate(&candidate, &expected_old)
        .map_err(WitnessAuthorityError::State)?;
    Ok(LeaseExpiryResult::Expired)
}

fn outcome_reject_response(
    request_id: &RequestId,
    term: Term,
    lease_id: Option<LeaseId>,
    code: WitnessMutationOutcomeCode,
    reason: &str,
) -> PreparedLeaseResponse {
    prepared_response(
        request_id.clone(),
        ProtocolMessage::LeaseReject(LeaseRejectPayload {
            code,
            reason: reason.to_string(),
        }),
        term,
        lease_id,
    )
}

fn commit_release_reject<B, C>(
    store: &WitnessStateStore<B, C>,
    state: &crate::witness_state::WitnessPersistentState,
    request: &UnsignedEnvelope,
    request_id: &RequestId,
    reason: &str,
    expected_old: &crate::recovery::ExpectedOldToken,
) -> Result<PreparedLeaseResponse, WitnessAuthorityError>
where
    B: BootIdProvider,
    C: MonotonicClock,
{
    let result = CommittedSemanticResult::LeaseReject(LeaseRejectPayload {
        code: WitnessMutationOutcomeCode::PolicyReject,
        reason: reason.to_string(),
    });
    let candidate = witness_journal::commit_candidate(state, request, result.clone())
        .map_err(WitnessAuthorityError::Journal)?;
    store
        .commit_candidate(&candidate, expected_old)
        .map_err(WitnessAuthorityError::State)?;
    let CommittedSemanticResult::LeaseReject(payload) = result else {
        unreachable!();
    };
    Ok(prepared_response(
        request_id.clone(),
        ProtocolMessage::LeaseReject(payload),
        state.current_term,
        state.active_lease_id.clone(),
    ))
}

fn reconstruct_duplicate_lease_release(
    state: &crate::witness_state::WitnessPersistentState,
    request_id: &RequestId,
    result: CommittedSemanticResult,
) -> Result<PreparedLeaseResponse, WitnessAuthorityError> {
    match result {
        CommittedSemanticResult::LeaseReleased(payload) => Ok(prepared_response(
            request_id.clone(),
            ProtocolMessage::LeaseReleased(payload),
            state.current_term,
            state.active_lease_id.clone(),
        )),
        CommittedSemanticResult::LeaseReject(payload) => Ok(prepared_response(
            request_id.clone(),
            ProtocolMessage::LeaseReject(payload),
            state.current_term,
            state.active_lease_id.clone(),
        )),
        _ => Err(WitnessAuthorityError::AuthorityInvariant(
            "LEASE_RELEASE journal result kind mismatch",
        )),
    }
}

pub fn prepare_lease_renew_authority<B, C>(
    store: &WitnessStateStore<B, C>,
    observation: &WitnessRequestObservation,
    request: &UnsignedEnvelope,
) -> Result<PreparedLeaseResponse, WitnessAuthorityError>
where
    B: BootIdProvider,
    C: MonotonicClock,
{
    let _mutation_guard = authority_mutation_guard()?;
    let WitnessRequestObservation::LeaseRenew {
        request_id,
        sender_node_id,
        payload,
        ..
    } = observation
    else {
        return Err(WitnessAuthorityError::NotLeaseRenew);
    };
    let ProtocolMessage::LeaseRenew(request_payload) = &request.message else {
        return Err(WitnessAuthorityError::NotLeaseRenew);
    };
    if request.common.request_id.as_ref() != Some(request_id)
        || request.common.sender_node_id.as_str() != sender_node_id.as_str()
        || request_payload != payload
    {
        return Err(WitnessAuthorityError::AuthorityInvariant(
            "LEASE_RENEW observation does not match pending request",
        ));
    }

    let recovery = store.load();
    if recovery.readiness != WitnessReadiness::Ready {
        let WitnessReadiness::NotReady(reason) = recovery.readiness else {
            unreachable!();
        };
        return Err(WitnessAuthorityError::NotReady(reason));
    }
    let state = recovery.state.ok_or(WitnessAuthorityError::NotReady(
        WitnessNotReadyReason::StateCorrupt,
    ))?;
    let expected_old =
        recovery
            .expected_old
            .clone()
            .ok_or(WitnessAuthorityError::AuthorityInvariant(
                "missing snapshot provenance",
            ))?;

    match witness_journal::classify(&state, request).map_err(WitnessAuthorityError::Journal)? {
        JournalClassification::Duplicate { result } => {
            return reconstruct_duplicate_lease_renewal(store, &state, request_id, result);
        }
        JournalClassification::Conflict => {
            return Ok(outcome_reject_response(
                request_id,
                state.current_term,
                state.active_lease_id.clone(),
                WitnessMutationOutcomeCode::Conflict,
                "LEASE_RENEW journal identity conflict",
            ));
        }
        JournalClassification::RetiredStale => {
            return Ok(outcome_reject_response(
                request_id,
                state.current_term,
                state.active_lease_id.clone(),
                WitnessMutationOutcomeCode::RetiredStale,
                "LEASE_RENEW generation is retired or stale",
            ));
        }
        JournalClassification::GenerationGap => {
            return Ok(outcome_reject_response(
                request_id,
                state.current_term,
                state.active_lease_id.clone(),
                WitnessMutationOutcomeCode::GenerationGap,
                "LEASE_RENEW generation gap",
            ));
        }
        JournalClassification::NewEligible => {}
    }

    if matches!(state.lease_state, LeaseState::Unknown) {
        return Err(WitnessAuthorityError::UnknownLease);
    }

    let reject_reason = if matches!(state.lease_state, LeaseState::None) {
        Some("there is no active lease to renew")
    } else if payload.term != state.current_term {
        Some("renewal term does not match current Witness term")
    } else if state.active_lease_id.as_ref() != Some(&payload.lease_id) {
        Some("renewal lease_id does not match the active lease")
    } else if state.holder_node_id.as_ref() != Some(sender_node_id) {
        Some("only the current lease holder may renew")
    } else if state.lease_ttl_ms != Some(DurationMs(LEASE_TTL_MS)) {
        Some("current lease TTL is not 10000 milliseconds")
    } else {
        None
    };

    if let Some(reason) = reject_reason {
        return commit_renewal_reject(store, &state, request, request_id, reason, &expected_old);
    }

    let old_deadline =
        state
            .lease_deadline_monotonic_ms
            .ok_or(WitnessAuthorityError::AuthorityInvariant(
                "active lease deadline is missing",
            ))?;
    let now = store
        .current_monotonic_ms()
        .map_err(WitnessAuthorityError::State)?;
    if now >= old_deadline {
        return commit_renewal_reject(
            store,
            &state,
            request,
            request_id,
            "current lease deadline has expired",
            &expected_old,
        );
    }
    let new_deadline = now
        .checked_add(LEASE_TTL_MS)
        .ok_or(WitnessAuthorityError::DeadlineOverflow)?;
    let holder = state
        .holder_node_id
        .clone()
        .ok_or(WitnessAuthorityError::AuthorityInvariant(
            "active lease holder is missing",
        ))?;
    let lease_id =
        state
            .active_lease_id
            .clone()
            .ok_or(WitnessAuthorityError::AuthorityInvariant(
                "active lease ID is missing",
            ))?;
    let renewed = LeaseGrantPayload {
        term: state.current_term,
        lease_id: lease_id.clone(),
        holder_node_id: holder.clone(),
        lease_ttl_ms: DurationMs(LEASE_TTL_MS),
        renew_after_ms: DurationMs(RENEW_AFTER_MS),
        lease_remaining_ms: DurationMs(LEASE_TTL_MS),
    };
    let result = CommittedSemanticResult::LeaseRenewed(renewed.clone());
    let mut authority_candidate = state.clone();
    authority_candidate.lease_deadline_monotonic_ms = Some(new_deadline);
    let candidate = witness_journal::commit_candidate(&authority_candidate, request, result)
        .map_err(WitnessAuthorityError::Journal)?;
    store
        .commit_candidate(&candidate, &expected_old)
        .map_err(WitnessAuthorityError::State)?;
    Ok(prepared_response(
        request_id.clone(),
        ProtocolMessage::LeaseRenewed(renewed),
        state.current_term,
        Some(lease_id),
    ))
}

fn commit_renewal_reject<B, C>(
    store: &WitnessStateStore<B, C>,
    state: &crate::witness_state::WitnessPersistentState,
    request: &UnsignedEnvelope,
    request_id: &RequestId,
    reason: &str,
    expected_old: &crate::recovery::ExpectedOldToken,
) -> Result<PreparedLeaseResponse, WitnessAuthorityError>
where
    B: BootIdProvider,
    C: MonotonicClock,
{
    let result = CommittedSemanticResult::LeaseReject(LeaseRejectPayload {
        code: WitnessMutationOutcomeCode::PolicyReject,
        reason: reason.to_string(),
    });
    let candidate = witness_journal::commit_candidate(state, request, result.clone())
        .map_err(WitnessAuthorityError::Journal)?;
    store
        .commit_candidate(&candidate, expected_old)
        .map_err(WitnessAuthorityError::State)?;
    let CommittedSemanticResult::LeaseReject(payload) = result else {
        unreachable!();
    };
    Ok(prepared_response(
        request_id.clone(),
        ProtocolMessage::LeaseReject(payload),
        state.current_term,
        state.active_lease_id.clone(),
    ))
}

fn reconstruct_duplicate_lease_renewal<B, C>(
    store: &WitnessStateStore<B, C>,
    state: &crate::witness_state::WitnessPersistentState,
    request_id: &RequestId,
    result: CommittedSemanticResult,
) -> Result<PreparedLeaseResponse, WitnessAuthorityError>
where
    B: BootIdProvider,
    C: MonotonicClock,
{
    let CommittedSemanticResult::LeaseRenewed(stored) = result else {
        let CommittedSemanticResult::LeaseReject(reject) = result else {
            return Err(WitnessAuthorityError::AuthorityInvariant(
                "LEASE_RENEW journal result kind mismatch",
            ));
        };
        return Ok(prepared_response(
            request_id.clone(),
            ProtocolMessage::LeaseReject(reject),
            state.current_term,
            state.active_lease_id.clone(),
        ));
    };
    // J20 (F-J19-01): the journal record proves a historical commit only. The renewal is the
    // current authority only while the very lease it renewed is still the active lease with time
    // remaining; then the existing idempotent answer is reconstructed. A lease that has since
    // expired, been released or been superseded by a later term is answered with a deterministic
    // RetiredStale outcome that commits nothing: the journal record, the current lease and the
    // watermark stay as they are and no authority is restored. States that lease expiry or a
    // later lease cannot explain stay fail-closed.
    if matches!(state.lease_state, LeaseState::Unknown) {
        return Err(WitnessAuthorityError::UnknownLease);
    }
    if state.current_term.0 < stored.term.0 {
        return Err(WitnessAuthorityError::AuthorityInvariant(
            "duplicate LeaseRenewed term is ahead of the Witness term",
        ));
    }
    let same_lease = matches!(state.lease_state, LeaseState::Active)
        && state.current_term == stored.term
        && state.active_lease_id.as_ref() == Some(&stored.lease_id);
    if !same_lease {
        // A later term with the same lease id, or the same term with another lease id, cannot
        // come from expiry or a later grant (each grant takes the next term and a new lease id).
        if matches!(state.lease_state, LeaseState::Active)
            && (state.current_term == stored.term
                || state.active_lease_id.as_ref() == Some(&stored.lease_id))
        {
            return Err(WitnessAuthorityError::AuthorityInvariant(
                "duplicate LeaseRenewed does not match current authority",
            ));
        }
        return Ok(retired_duplicate_lease_renewal(state, request_id));
    }
    if state.holder_node_id.as_ref() != Some(&stored.holder_node_id)
        || state.lease_ttl_ms != Some(stored.lease_ttl_ms)
    {
        return Err(WitnessAuthorityError::AuthorityInvariant(
            "duplicate LeaseRenewed does not match current authority",
        ));
    }
    let deadline =
        state
            .lease_deadline_monotonic_ms
            .ok_or(WitnessAuthorityError::AuthorityInvariant(
                "active lease deadline is missing",
            ))?;
    let now = store
        .current_monotonic_ms()
        .map_err(WitnessAuthorityError::State)?;
    let remaining = deadline.saturating_sub(now);
    if remaining == 0 {
        return Ok(retired_duplicate_lease_renewal(state, request_id));
    }
    let renewed = LeaseGrantPayload {
        lease_remaining_ms: DurationMs(remaining),
        ..stored
    };
    Ok(prepared_response(
        request_id.clone(),
        ProtocolMessage::LeaseRenewed(renewed),
        state.current_term,
        state.active_lease_id.clone(),
    ))
}

/// J20: the answer to an exact LEASE_RENEW replay whose renewed lease is no longer the current
/// authority (expired, released or superseded). Nothing is committed; the reason says that the
/// request was committed earlier, so the historical commit is never reported as uncommitted.
fn retired_duplicate_lease_renewal(
    state: &crate::witness_state::WitnessPersistentState,
    request_id: &RequestId,
) -> PreparedLeaseResponse {
    outcome_reject_response(
        request_id,
        state.current_term,
        state.active_lease_id.clone(),
        WitnessMutationOutcomeCode::RetiredStale,
        "LEASE_RENEW was committed earlier, but the lease it renewed is no longer the current \
         authority (expired, released or superseded); nothing was renewed",
    )
}

pub fn prepare_lease_request_authority<B, C>(
    store: &WitnessStateStore<B, C>,
    observation: &WitnessRequestObservation,
    request: &UnsignedEnvelope,
) -> Result<PreparedLeaseResponse, WitnessAuthorityError>
where
    B: BootIdProvider,
    C: MonotonicClock,
{
    let _mutation_guard = authority_mutation_guard()?;
    let WitnessRequestObservation::LeaseRequest {
        request_id,
        sender_node_id,
        payload,
        ..
    } = observation
    else {
        return Err(WitnessAuthorityError::NotLeaseRequest);
    };
    let ProtocolMessage::LeaseRequest(request_payload) = &request.message else {
        return Err(WitnessAuthorityError::NotLeaseRequest);
    };
    if request.common.request_id.as_ref() != Some(request_id)
        || request.common.sender_node_id.as_str() != sender_node_id.as_str()
        || request_payload != payload
    {
        return Err(WitnessAuthorityError::AuthorityInvariant(
            "LEASE_REQUEST observation does not match pending request",
        ));
    }

    let recovery = store.load();
    if recovery.readiness != WitnessReadiness::Ready {
        let WitnessReadiness::NotReady(reason) = recovery.readiness else {
            unreachable!();
        };
        return Err(WitnessAuthorityError::NotReady(reason));
    }
    let state = recovery.state.ok_or(WitnessAuthorityError::NotReady(
        WitnessNotReadyReason::StateCorrupt,
    ))?;
    let expected_old =
        recovery
            .expected_old
            .clone()
            .ok_or(WitnessAuthorityError::AuthorityInvariant(
                "missing snapshot provenance",
            ))?;

    match witness_journal::classify(&state, request).map_err(WitnessAuthorityError::Journal)? {
        JournalClassification::Duplicate { result } => {
            return reconstruct_duplicate_lease_response(store, &state, request_id, result);
        }
        JournalClassification::Conflict => {
            return Ok(outcome_reject_response(
                request_id,
                state.current_term,
                state.active_lease_id.clone(),
                WitnessMutationOutcomeCode::Conflict,
                "LEASE_REQUEST journal identity conflict",
            ));
        }
        JournalClassification::RetiredStale => {
            return Ok(outcome_reject_response(
                request_id,
                state.current_term,
                state.active_lease_id.clone(),
                WitnessMutationOutcomeCode::RetiredStale,
                "LEASE_REQUEST generation is retired or stale",
            ));
        }
        JournalClassification::GenerationGap => {
            return Ok(outcome_reject_response(
                request_id,
                state.current_term,
                state.active_lease_id.clone(),
                WitnessMutationOutcomeCode::GenerationGap,
                "LEASE_REQUEST generation gap",
            ));
        }
        JournalClassification::NewEligible => {}
    }

    if matches!(state.lease_state, LeaseState::Unknown) {
        return Err(WitnessAuthorityError::UnknownLease);
    }

    let reject_reason = if payload.observed_term != state.current_term {
        Some("observed_term does not match current Witness term")
    } else if payload.requested_ttl.0 != LEASE_TTL_MS {
        Some("requested_ttl must be 10000 milliseconds")
    } else if matches!(state.lease_state, LeaseState::Active) {
        Some("an active lease cannot be preempted by LEASE_REQUEST")
    } else if state.current_term.0 == u64::MAX {
        Some("Witness term is exhausted")
    } else {
        None
    };

    if let Some(reason) = reject_reason {
        let result = CommittedSemanticResult::LeaseReject(LeaseRejectPayload {
            code: WitnessMutationOutcomeCode::PolicyReject,
            reason: reason.to_string(),
        });
        let candidate = witness_journal::commit_candidate(&state, request, result.clone())
            .map_err(WitnessAuthorityError::Journal)?;
        store
            .commit_candidate(&candidate, &expected_old)
            .map_err(WitnessAuthorityError::State)?;
        return Ok(prepared_response(
            request_id.clone(),
            ProtocolMessage::LeaseReject(match result {
                CommittedSemanticResult::LeaseReject(payload) => payload,
                _ => unreachable!(),
            }),
            state.current_term,
            state.active_lease_id.clone(),
        ));
    }

    let now = store
        .current_monotonic_ms()
        .map_err(WitnessAuthorityError::State)?;
    let deadline = now
        .checked_add(LEASE_TTL_MS)
        .ok_or(WitnessAuthorityError::DeadlineOverflow)?;
    let lease_id = generate_lease_id().ok_or(WitnessAuthorityError::LeaseIdGeneration)?;
    let new_term = Term(
        state
            .current_term
            .0
            .checked_add(1)
            .ok_or(WitnessAuthorityError::AuthorityInvariant("term overflow"))?,
    );
    let grant = LeaseGrantPayload {
        term: new_term,
        lease_id: lease_id.clone(),
        holder_node_id: sender_node_id.clone(),
        lease_ttl_ms: DurationMs(LEASE_TTL_MS),
        renew_after_ms: DurationMs(RENEW_AFTER_MS),
        lease_remaining_ms: DurationMs(LEASE_TTL_MS),
    };
    let result = CommittedSemanticResult::LeaseGrant(grant.clone());
    let mut authority_candidate = state.clone();
    authority_candidate.current_term = new_term;
    authority_candidate.active_lease_id = Some(lease_id.clone());
    authority_candidate.holder_node_id = Some(sender_node_id.clone());
    authority_candidate.lease_ttl_ms = Some(DurationMs(LEASE_TTL_MS));
    authority_candidate.lease_deadline_monotonic_ms = Some(deadline);
    authority_candidate.lease_state = LeaseState::Active;
    let candidate = witness_journal::commit_candidate(&authority_candidate, request, result)
        .map_err(WitnessAuthorityError::Journal)?;
    store
        .commit_candidate(&candidate, &expected_old)
        .map_err(WitnessAuthorityError::State)?;
    Ok(prepared_response(
        request_id.clone(),
        ProtocolMessage::LeaseGrant(grant),
        new_term,
        Some(lease_id),
    ))
}

fn reconstruct_duplicate_lease_response<B, C>(
    store: &WitnessStateStore<B, C>,
    state: &crate::witness_state::WitnessPersistentState,
    request_id: &RequestId,
    result: CommittedSemanticResult,
) -> Result<PreparedLeaseResponse, WitnessAuthorityError>
where
    B: BootIdProvider,
    C: MonotonicClock,
{
    let CommittedSemanticResult::LeaseGrant(stored) = result else {
        let CommittedSemanticResult::LeaseReject(reject) = result else {
            return Err(WitnessAuthorityError::AuthorityInvariant(
                "LEASE_REQUEST journal result kind mismatch",
            ));
        };
        return Ok(prepared_response(
            request_id.clone(),
            ProtocolMessage::LeaseReject(reject),
            state.current_term,
            state.active_lease_id.clone(),
        ));
    };
    // J21 (OD-J20-6): the journal record proves a historical grant only. It is the current
    // authority only while the very lease it created is still the active lease with time
    // remaining; then the existing idempotent answer is reconstructed (never extended). A lease
    // that has since expired, been released or been superseded by a later grant is answered with
    // a deterministic RetiredStale outcome that commits nothing: no new grant is created, the
    // journal record, the current lease, the term and the watermark stay as they are. States that
    // expiry, release or a later grant cannot explain stay fail-closed.
    if matches!(state.lease_state, LeaseState::Unknown) {
        return Err(WitnessAuthorityError::UnknownLease);
    }
    if state.current_term.0 < stored.term.0 {
        return Err(WitnessAuthorityError::AuthorityInvariant(
            "duplicate LeaseGrant term is ahead of the Witness term",
        ));
    }
    let same_lease = matches!(state.lease_state, LeaseState::Active)
        && state.current_term == stored.term
        && state.active_lease_id.as_ref() == Some(&stored.lease_id);
    if !same_lease {
        // A later term with the same lease id, or the same term with another lease id, cannot
        // come from expiry, release or a later grant (each grant takes the next term and a new
        // lease id).
        if matches!(state.lease_state, LeaseState::Active)
            && (state.current_term == stored.term
                || state.active_lease_id.as_ref() == Some(&stored.lease_id))
        {
            return Err(WitnessAuthorityError::AuthorityInvariant(
                "duplicate LeaseGrant does not match current authority",
            ));
        }
        return Ok(retired_duplicate_lease_grant(state, request_id));
    }
    if state.holder_node_id.as_ref() != Some(&stored.holder_node_id)
        || state.lease_ttl_ms != Some(stored.lease_ttl_ms)
    {
        return Err(WitnessAuthorityError::AuthorityInvariant(
            "duplicate LeaseGrant does not match current authority",
        ));
    }
    let deadline =
        state
            .lease_deadline_monotonic_ms
            .ok_or(WitnessAuthorityError::AuthorityInvariant(
                "active lease deadline is missing",
            ))?;
    let now = store
        .current_monotonic_ms()
        .map_err(WitnessAuthorityError::State)?;
    let remaining = deadline.saturating_sub(now);
    if remaining == 0 {
        return Ok(retired_duplicate_lease_grant(state, request_id));
    }
    let grant = LeaseGrantPayload {
        lease_remaining_ms: DurationMs(remaining),
        ..stored
    };
    Ok(prepared_response(
        request_id.clone(),
        ProtocolMessage::LeaseGrant(grant),
        state.current_term,
        state.active_lease_id.clone(),
    ))
}

/// J21: the answer to an exact LEASE_REQUEST replay whose granted lease is no longer the current
/// authority (expired, released or superseded). Nothing is committed and no lease is granted; the
/// reason says that the request was granted earlier, so the historical grant is never reported
/// as ungranted.
fn retired_duplicate_lease_grant(
    state: &crate::witness_state::WitnessPersistentState,
    request_id: &RequestId,
) -> PreparedLeaseResponse {
    outcome_reject_response(
        request_id,
        state.current_term,
        state.active_lease_id.clone(),
        WitnessMutationOutcomeCode::RetiredStale,
        "LEASE_REQUEST was granted earlier, but that lease is no longer the current authority \
         (expired, released or superseded); no lease was granted by this replay",
    )
}

fn prepared_response(
    request_id: RequestId,
    message: ProtocolMessage,
    term: Term,
    lease_id: Option<LeaseId>,
) -> PreparedLeaseResponse {
    PreparedLeaseResponse {
        request_id,
        message,
        context: WitnessResponseContext { term, lease_id },
    }
}

fn generate_lease_id() -> Option<LeaseId> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).ok()?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Some(LeaseId::new(format_uuid(bytes)))
}

fn format_uuid(bytes: [u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

pub fn send_prepared_lease_response(
    connection: &mut WitnessConnection,
    process: &mut ProcessSession,
    prepared: PreparedLeaseResponse,
    serializer: &crate::protocol::CborSerializer,
    authenticator: &crate::security::MessageAuthenticator,
) -> Result<(), crate::witness_runtime::WitnessRuntimeError> {
    crate::witness_runtime::send_witness_response_with_context(
        connection,
        process,
        prepared.request_id,
        prepared.message,
        prepared.context,
        serializer,
        authenticator,
    )
}

pub fn prepare_get_term_response<B, C>(
    store: &WitnessStateStore<B, C>,
    observation: &WitnessRequestObservation,
) -> Result<PreparedTermStatus, WitnessAuthorityError>
where
    B: BootIdProvider,
    C: MonotonicClock,
{
    let WitnessRequestObservation::GetTerm {
        request_id,
        sender_node_id,
        ..
    } = observation
    else {
        return Err(WitnessAuthorityError::NotGetTerm);
    };
    let recovery = store.load();
    if recovery.readiness != WitnessReadiness::Ready {
        let WitnessReadiness::NotReady(reason) = recovery.readiness else {
            unreachable!();
        };
        return Err(WitnessAuthorityError::NotReady(reason));
    }
    let state = recovery.state.ok_or(WitnessAuthorityError::NotReady(
        WitnessNotReadyReason::StateCorrupt,
    ))?;
    let (current_holder, current_lease_id, lease_remaining_ms) = match state.lease_state {
        LeaseState::None => (None, None, None),
        LeaseState::Unknown => return Err(WitnessAuthorityError::UnknownLease),
        LeaseState::Active => {
            let holder = state
                .holder_node_id
                .clone()
                .ok_or(WitnessAuthorityError::UnknownLease)?;
            let lease_id = state
                .active_lease_id
                .clone()
                .ok_or(WitnessAuthorityError::UnknownLease)?;
            let deadline = state
                .lease_deadline_monotonic_ms
                .ok_or(WitnessAuthorityError::UnknownLease)?;
            let now = store
                .current_monotonic_ms()
                .map_err(WitnessAuthorityError::State)?;
            (
                Some(holder),
                Some(lease_id),
                Some(DurationMs(deadline.saturating_sub(now))),
            )
        }
    };
    Ok(PreparedTermStatus {
        request_id: request_id.clone(),
        requester: sender_node_id.clone(),
        payload: TermStatusPayload {
            current_term: state.current_term,
            current_holder,
            current_lease_id: current_lease_id.clone(),
            lease_remaining_ms,
        },
        context: WitnessResponseContext {
            term: state.current_term,
            lease_id: current_lease_id,
        },
    })
}

pub fn send_prepared_term_status(
    connection: &mut WitnessConnection,
    process: &mut ProcessSession,
    prepared: PreparedTermStatus,
    serializer: &crate::protocol::CborSerializer,
    authenticator: &crate::security::MessageAuthenticator,
) -> Result<(), crate::witness_runtime::WitnessRuntimeError> {
    crate::witness_runtime::send_witness_response_with_context(
        connection,
        process,
        prepared.request_id,
        crate::protocol::ProtocolMessage::TermStatus(prepared.payload),
        prepared.context,
        serializer,
        authenticator,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        ClusterId, CommonFields, DurationMs, LeaseId, LeaseReleasePayload, LeaseRequestPayload,
        NodeId, PROTOCOL_VERSION, ProtocolMessage, RequestId, Sequence, SessionId, Term,
        UnsignedEnvelope,
    };
    use crate::security::{MessageAuthenticator, Psk};
    use crate::tcp::TcpConnection;
    use crate::witness_state::{BootId, LeaseState, WitnessPersistentState};
    use std::fs;
    use std::net::{TcpListener, TcpStream};
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    use std::os::fd::AsRawFd;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Duration;

    #[derive(Clone)]
    struct Boot;
    impl BootIdProvider for Boot {
        fn current_boot_id(&self) -> Result<BootId, WitnessStateError> {
            Ok(BootId::new("boot-a"))
        }
    }

    #[derive(Clone, Copy)]
    struct Clock(u64);
    impl MonotonicClock for Clock {
        fn now_ms(&self) -> Result<u64, WitnessStateError> {
            Ok(self.0)
        }
    }

    struct FailedClock;
    impl MonotonicClock for FailedClock {
        fn now_ms(&self) -> Result<u64, WitnessStateError> {
            Err(WitnessStateError::Clock(std::io::Error::other(
                "test clock failure",
            )))
        }
    }

    fn path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("mikagami-stage3-{name}-{}", std::process::id()))
    }

    fn store<C: MonotonicClock>(path: &Path, clock: C) -> WitnessStateStore<Boot, C> {
        WitnessStateStore::with_providers(path, ClusterId::new("cluster"), Boot, clock)
    }

    fn observation() -> WitnessRequestObservation {
        WitnessRequestObservation::GetTerm {
            request_id: RequestId::new("request-1"),
            sender_node_id: NodeId::new("node-a"),
            term: Term(0),
        }
    }

    fn active() -> WitnessPersistentState {
        WitnessPersistentState {
            state_format_version: 2,
            cluster_id: ClusterId::new("cluster"),
            current_term: Term(7),
            active_lease_id: Some(LeaseId::new("lease-1")),
            holder_node_id: Some(NodeId::new("node-a")),
            lease_ttl_ms: Some(crate::protocol::DurationMs(10_000)),
            lease_deadline_monotonic_ms: Some(10_000),
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
        requested_ttl: u64,
    ) -> (UnsignedEnvelope, WitnessRequestObservation) {
        let request_id = RequestId::new(request_id);
        let payload = LeaseRequestPayload {
            mutation_generation: generation,
            observed_term: Term(observed_term),
            priority: 100,
            requested_ttl: DurationMs(requested_ttl),
        };
        let request = UnsignedEnvelope {
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
        };
        let observation = WitnessRequestObservation::LeaseRequest {
            request_id,
            sender_node_id: NodeId::new("node-a"),
            term: Term(0),
            lease_id: None,
            payload,
        };
        (request, observation)
    }

    fn lease_renew(
        request_id: &str,
        generation: u64,
        term: u64,
        lease_id: &str,
    ) -> (UnsignedEnvelope, WitnessRequestObservation) {
        let request_id = RequestId::new(request_id);
        let payload = crate::protocol::LeaseRenewPayload {
            mutation_generation: generation,
            term: Term(term),
            lease_id: LeaseId::new(lease_id),
        };
        let request = UnsignedEnvelope {
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
        };
        let observation = WitnessRequestObservation::LeaseRenew {
            request_id,
            sender_node_id: NodeId::new("node-a"),
            term: Term(0),
            lease_id: None,
            payload,
        };
        (request, observation)
    }

    fn lease_release(
        request_id: &str,
        generation: u64,
        term: u64,
        lease_id: &str,
    ) -> (UnsignedEnvelope, WitnessRequestObservation) {
        let request_id = RequestId::new(request_id);
        let payload = LeaseReleasePayload {
            mutation_generation: generation,
            term: Term(term),
            lease_id: LeaseId::new(lease_id),
            reason: "test release".to_string(),
        };
        let request = UnsignedEnvelope {
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
        };
        let observation = WitnessRequestObservation::LeaseRelease {
            request_id,
            sender_node_id: NodeId::new("node-a"),
            term: Term(0),
            lease_id: None,
            payload,
        };
        (request, observation)
    }

    // Witness-side CAS for the "anchor-before / grant-after" races. In these tests
    // `node-a` is the node that holds the old grant G0 (state `active()`: term 7,
    // lease-1, deadline 10_000) and `node-b` is the evaluator that anchors.

    fn ba_request(
        sender: &str,
        request_id: &str,
        generation: u64,
        observed_term: u64,
    ) -> (UnsignedEnvelope, WitnessRequestObservation) {
        let (mut request, mut observation) =
            lease_request(request_id, generation, observed_term, 10_000);
        request.common.sender_node_id = NodeId::new(sender);
        if let WitnessRequestObservation::LeaseRequest { sender_node_id, .. } = &mut observation {
            *sender_node_id = NodeId::new(sender);
        }
        (request, observation)
    }

    fn ba_renew(
        sender: &str,
        request_id: &str,
        generation: u64,
        term: u64,
        lease_id: &str,
    ) -> (UnsignedEnvelope, WitnessRequestObservation) {
        let (mut request, mut observation) = lease_renew(request_id, generation, term, lease_id);
        request.common.sender_node_id = NodeId::new(sender);
        if let WitnessRequestObservation::LeaseRenew { sender_node_id, .. } = &mut observation {
            *sender_node_id = NodeId::new(sender);
        }
        (request, observation)
    }

    fn ba_reject_reason(prepared: &PreparedLeaseResponse) -> Option<String> {
        match &prepared.message {
            ProtocolMessage::LeaseReject(payload) => {
                Some(format!("{:?}: {}", payload.code, payload.reason))
            }
            _ => None,
        }
    }

    fn ba_is_grant(prepared: &PreparedLeaseResponse) -> bool {
        matches!(prepared.message, ProtocolMessage::LeaseGrant(_))
    }

    /// Variant X: the evaluator (node-b) wins the CAS on the anchored term after
    /// the old holder's lease expired. The old holder's later requests (a stale
    /// LeaseRequest carrying the pre-anchor observation, and a renew of its old
    /// lease) are refused: the old grant G0 gives it nothing.
    #[test]
    fn ba_witness_old_grant_cannot_be_used_after_anchor_cas() {
        let file = path("ba-audit-x");
        store(&file, Clock(9_000)).save(&active()).unwrap();
        // before expiry: no preemption (the anchor cannot even form)
        let (req, obs) = ba_request("node-b", "00000000-0000-4000-8000-0000000000a1", 1, 7);
        let early =
            prepare_lease_request_authority(&store(&file, Clock(9_000)), &obs, &req).unwrap();
        assert!(
            ba_reject_reason(&early).unwrap().contains("active lease"),
            "{early:?}"
        );
        // expiry processed: holder none, term unchanged (the anchor view)
        assert_eq!(
            expire_lease_if_needed(&store(&file, Clock(10_000))).unwrap(),
            LeaseExpiryResult::Expired
        );
        let anchor = store(&file, Clock(10_000)).load().state.unwrap();
        assert_eq!(
            (anchor.current_term, anchor.holder_node_id.clone()),
            (Term(7), None)
        );
        // A (node-b) CAS on the anchored term wins
        let (req, obs) = ba_request("node-b", "00000000-0000-4000-8000-0000000000a2", 2, 7);
        let won =
            prepare_lease_request_authority(&store(&file, Clock(10_001)), &obs, &req).unwrap();
        assert!(ba_is_grant(&won));
        assert_eq!(
            store(&file, Clock(10_001))
                .load()
                .state
                .unwrap()
                .current_term,
            Term(8)
        );
        // B (node-a) resumes with the observation it had before the anchor
        let (req, obs) = ba_request("node-a", "00000000-0000-4000-8000-0000000000a3", 1, 7);
        let late =
            prepare_lease_request_authority(&store(&file, Clock(10_002)), &obs, &req).unwrap();
        let reason = ba_reject_reason(&late).expect("stale observed_term must not be granted");
        assert!(reason.contains("observed_term"), "{reason}");
        // ... or renews its expired G0
        let (req, obs) = ba_renew(
            "node-a",
            "00000000-0000-4000-8000-0000000000a4",
            2,
            7,
            "lease-1",
        );
        let renew = prepare_lease_renew_authority(&store(&file, Clock(10_003)), &obs, &req);
        assert!(
            !matches!(renew, Ok(ref prepared) if matches!(prepared.message, ProtocolMessage::LeaseRenewed(_))),
            "an expired, superseded lease must not be renewed: {renew:?}"
        );
        let final_state = store(&file, Clock(10_004)).load().state.unwrap();
        assert_eq!(final_state.current_term, Term(8));
        assert_eq!(final_state.holder_node_id, Some(NodeId::new("node-b")));
        let _ = fs::remove_file(file);
    }

    /// Variant Y: the old holder (node-a) wins the CAS first (a fresh request
    /// after the expiry); the evaluator's anchored request is then refused, so
    /// the anchor can never turn into a second grant for the same term.
    #[test]
    fn ba_witness_anchor_cas_loses_if_another_grant_came_first() {
        let file = path("ba-audit-y");
        store(&file, Clock(9_000)).save(&active()).unwrap();
        assert_eq!(
            expire_lease_if_needed(&store(&file, Clock(10_000))).unwrap(),
            LeaseExpiryResult::Expired
        );
        let (req, obs) = ba_request("node-a", "00000000-0000-4000-8000-0000000000b1", 1, 7);
        let first =
            prepare_lease_request_authority(&store(&file, Clock(10_001)), &obs, &req).unwrap();
        assert!(ba_is_grant(&first));
        let (req, obs) = ba_request("node-b", "00000000-0000-4000-8000-0000000000b2", 1, 7);
        let second =
            prepare_lease_request_authority(&store(&file, Clock(10_002)), &obs, &req).unwrap();
        let reason =
            ba_reject_reason(&second).expect("second grant on the same anchor must be refused");
        assert!(
            reason.contains("observed_term") || reason.contains("active lease"),
            "{reason}"
        );
        let final_state = store(&file, Clock(10_003)).load().state.unwrap();
        assert_eq!(final_state.current_term, Term(8));
        assert_eq!(final_state.holder_node_id, Some(NodeId::new("node-a")));
        let _ = fs::remove_file(file);
    }

    /// Variant Z: the evaluator's CAS is bound to the anchored term even when the
    /// term moved and the new lease then expired too (term 8, holder none): a
    /// request that still carries the old anchor 7 is refused.
    #[test]
    fn ba_witness_cas_is_bound_to_the_anchored_term_after_a_full_cycle() {
        let file = path("ba-audit-z");
        store(&file, Clock(9_000)).save(&active()).unwrap();
        assert_eq!(
            expire_lease_if_needed(&store(&file, Clock(10_000))).unwrap(),
            LeaseExpiryResult::Expired
        );
        let (req, obs) = ba_request("node-a", "00000000-0000-4000-8000-0000000000c1", 1, 7);
        assert!(ba_is_grant(
            &prepare_lease_request_authority(&store(&file, Clock(10_001)), &obs, &req).unwrap()
        ));
        // the new lease (deadline 20_001) expires as well
        assert_eq!(
            expire_lease_if_needed(&store(&file, Clock(20_001))).unwrap(),
            LeaseExpiryResult::Expired
        );
        let view = store(&file, Clock(20_002)).load().state.unwrap();
        assert_eq!(
            (view.current_term, view.holder_node_id.clone()),
            (Term(8), None)
        );
        let (req, obs) = ba_request("node-b", "00000000-0000-4000-8000-0000000000c2", 1, 7);
        let stale_anchor =
            prepare_lease_request_authority(&store(&file, Clock(20_003)), &obs, &req).unwrap();
        let reason = ba_reject_reason(&stale_anchor).expect("anchor 7 must not win at term 8");
        assert!(reason.contains("observed_term"), "{reason}");
        let (req, obs) = ba_request("node-b", "00000000-0000-4000-8000-0000000000c3", 2, 8);
        assert!(ba_is_grant(
            &prepare_lease_request_authority(&store(&file, Clock(20_004)), &obs, &req).unwrap()
        ));
        let _ = fs::remove_file(file);
    }

    fn pair() -> (WitnessConnection, WitnessConnection) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        (
            WitnessConnection::new(
                NodeId::new("node-a"),
                NodeId::new("witness"),
                ClusterId::new("cluster"),
                crate::protocol::SessionId::new("session-w"),
                TcpConnection::from_stream(client, Duration::from_secs(2), Duration::from_secs(2))
                    .unwrap(),
            ),
            WitnessConnection::new(
                NodeId::new("witness"),
                NodeId::new("node-a"),
                ClusterId::new("cluster"),
                crate::protocol::SessionId::new("session-a"),
                TcpConnection::from_stream(server, Duration::from_secs(2), Duration::from_secs(2))
                    .unwrap(),
            ),
        )
    }

    #[test]
    fn prepares_none_and_active_term_status_without_mutating_state() {
        let file = path("mapping");
        let store = store(&file, Clock(7_000));
        let mut none =
            WitnessPersistentState::new(ClusterId::new("cluster"), BootId::new("boot-a"));
        none.current_term = Term(7);
        store.save(&none).unwrap();
        let before = fs::read(&file).unwrap();
        let prepared = prepare_get_term_response(&store, &observation()).unwrap();
        assert_eq!(prepared.payload.current_term, Term(7));
        assert_eq!(prepared.payload.current_holder, None);
        assert_eq!(prepared.payload.current_lease_id, None);
        assert_eq!(prepared.payload.lease_remaining_ms, None);
        assert_eq!(prepared.context.term, Term(7));
        assert_eq!(prepared.context.lease_id, None);
        assert_eq!(fs::read(&file).unwrap(), before);

        store.save(&active()).unwrap();
        let before = fs::read(&file).unwrap();
        let prepared = prepare_get_term_response(&store, &observation()).unwrap();
        assert_eq!(prepared.payload.current_holder, Some(NodeId::new("node-a")));
        assert_eq!(
            prepared.payload.current_lease_id,
            Some(LeaseId::new("lease-1"))
        );
        assert_eq!(
            prepared.payload.lease_remaining_ms,
            Some(crate::protocol::DurationMs(3_000))
        );
        assert_eq!(prepared.context.term, Term(7));
        assert_eq!(prepared.context.lease_id, Some(LeaseId::new("lease-1")));
        assert_eq!(fs::read(&file).unwrap(), before);
        let _ = fs::remove_file(file);
    }

    #[test]
    fn zero_remaining_is_reported_without_expiry_transition() {
        let file = path("zero");
        let store = store(&file, Clock(10_001));
        store.save(&active()).unwrap();
        let before = fs::read(&file).unwrap();
        let prepared = prepare_get_term_response(&store, &observation()).unwrap();
        assert_eq!(
            prepared.payload.lease_remaining_ms,
            Some(crate::protocol::DurationMs(0))
        );
        assert_eq!(store.load().state.unwrap().lease_state, LeaseState::Active);
        assert_eq!(fs::read(&file).unwrap(), before);
        let _ = fs::remove_file(file);
    }

    #[test]
    fn expiry_uses_exact_deadline_and_preserves_non_authority_state() {
        for (name, now, expected) in [
            ("before", 9_999, LeaseExpiryResult::NotExpired),
            ("at", 10_000, LeaseExpiryResult::Expired),
            ("after", 10_001, LeaseExpiryResult::Expired),
        ] {
            let file = path(&format!("stage7-{name}"));
            let store = store(&file, Clock(now));
            let mut state = active();
            state.journal.push(crate::witness_journal::JournalRecord {
                request_id: RequestId::new("00000000-0000-4000-8000-000000000030"),
                requester_node_id: "node-a".to_string(),
                request_kind: crate::protocol::MessageType::LeaseRelease,
                mutation_generation: 1,
                semantic_fingerprint: [0; 32],
                result: CommittedSemanticResult::LeaseReleased(LeaseReleasedPayload {
                    term: Term(7),
                    lease_id: LeaseId::new("lease-1"),
                    result: "released".to_string(),
                }),
            });
            state.generation_watermarks.insert("node-a".to_string(), 1);
            store.save(&state).unwrap();

            assert_eq!(expire_lease_if_needed(&store).unwrap(), expected);
            let persisted = store.load().state.unwrap();
            if expected == LeaseExpiryResult::Expired {
                assert_eq!(persisted.lease_state, LeaseState::None);
                assert_eq!(persisted.current_term, Term(7));
                assert_eq!(persisted.active_lease_id, None);
                assert_eq!(persisted.holder_node_id, None);
                assert_eq!(persisted.lease_ttl_ms, None);
                assert_eq!(persisted.lease_deadline_monotonic_ms, None);
            } else {
                assert_eq!(persisted.lease_state, LeaseState::Active);
            }
            assert_eq!(persisted.journal.len(), 1);
            assert_eq!(persisted.generation_watermarks.get("node-a"), Some(&1));
            let _ = fs::remove_file(file);
        }
    }

    #[test]
    fn expiry_is_fail_closed_for_unknown_and_clock_failure() {
        let unknown_file = path("stage7-unknown");
        let unknown_store = store(&unknown_file, Clock(10_000));
        let unknown = WitnessPersistentState {
            lease_state: LeaseState::Unknown,
            ..WitnessPersistentState::new(ClusterId::new("cluster"), BootId::new("boot-a"))
        };
        unknown_store.save(&unknown).unwrap();
        assert!(matches!(
            expire_lease_if_needed(&unknown_store),
            Err(WitnessAuthorityError::UnknownLease)
        ));
        let _ = fs::remove_file(unknown_file);

        let clock_file = path("stage7-clock");
        let clock_store = store(&clock_file, FailedClock);
        clock_store.save(&active()).unwrap();
        assert!(matches!(
            expire_lease_if_needed(&clock_store),
            Err(WitnessAuthorityError::State(WitnessStateError::Clock(_)))
        ));
        assert_eq!(
            clock_store.load().state.unwrap().lease_state,
            LeaseState::Active
        );
        let _ = fs::remove_file(clock_file);
    }

    #[test]
    fn expiry_does_not_implicitly_expire_active_lease_request() {
        let file = path("stage7-request");
        let store = store(&file, Clock(10_000));
        store.save(&active()).unwrap();
        let (request, observation) =
            lease_request("00000000-0000-4000-8000-000000000031", 1, 7, 10_000);
        let prepared = prepare_lease_request_authority(&store, &observation, &request).unwrap();
        assert!(matches!(prepared.message, ProtocolMessage::LeaseReject(_)));
        assert_eq!(store.load().state.unwrap().lease_state, LeaseState::Active);
        assert_eq!(
            expire_lease_if_needed(&store).unwrap(),
            LeaseExpiryResult::Expired
        );
        let (next, next_observation) =
            lease_request("00000000-0000-4000-8000-000000000032", 2, 7, 10_000);
        let grant = prepare_lease_request_authority(&store, &next_observation, &next).unwrap();
        assert!(matches!(grant.message, ProtocolMessage::LeaseGrant(_)));
        assert_eq!(store.load().state.unwrap().current_term, Term(8));
        let _ = fs::remove_file(file);
    }

    #[test]
    fn concurrent_renew_and_expiry_have_no_stale_candidate_commit() {
        let file = path("stage71-renew-expiry");
        let initial = store(&file, Clock(1_000));
        initial.save(&active()).unwrap();
        let barrier = Arc::new(Barrier::new(3));

        let renew_barrier = Arc::clone(&barrier);
        let renew_file = file.clone();
        let renew = thread::spawn(move || {
            let store = store(&renew_file, Clock(5_000));
            let (request, observation) =
                lease_renew("00000000-0000-4000-8000-000000000040", 1, 7, "lease-1");
            renew_barrier.wait();
            prepare_lease_renew_authority(&store, &observation, &request)
        });

        let expiry_barrier = Arc::clone(&barrier);
        let expiry_file = file.clone();
        let expiry = thread::spawn(move || {
            let store = store(&expiry_file, Clock(10_000));
            expiry_barrier.wait();
            expire_lease_if_needed(&store)
        });
        barrier.wait();
        let renew_result = renew.join().unwrap();
        let expiry_result = expiry.join().unwrap();
        assert!(
            renew_result.is_ok()
                || matches!(renew_result, Err(WitnessAuthorityError::UnknownLease))
        );
        assert!(expiry_result.is_ok());

        let final_state = initial.load().state.unwrap();
        assert_eq!(final_state.current_term, Term(7));
        match final_state.lease_state {
            LeaseState::None => {
                assert_eq!(final_state.active_lease_id, None);
                assert_eq!(final_state.lease_deadline_monotonic_ms, None);
            }
            LeaseState::Active => {
                assert_eq!(final_state.active_lease_id, Some(LeaseId::new("lease-1")));
                assert_eq!(final_state.lease_deadline_monotonic_ms, Some(15_000));
            }
            LeaseState::Unknown => panic!("authority must not become Unknown"),
        }
        let _ = fs::remove_file(file);
    }

    #[test]
    fn concurrent_release_and_expiry_leave_none_with_consistent_history() {
        let file = path("stage71-release-expiry");
        let initial = store(&file, Clock(1_000));
        initial.save(&active()).unwrap();
        let barrier = Arc::new(Barrier::new(3));

        let release_barrier = Arc::clone(&barrier);
        let release_file = file.clone();
        let release = thread::spawn(move || {
            let store = store(&release_file, Clock(10_000));
            let (request, observation) =
                lease_release("00000000-0000-4000-8000-000000000041", 1, 7, "lease-1");
            release_barrier.wait();
            prepare_lease_release_authority(&store, &observation, &request)
        });

        let expiry_barrier = Arc::clone(&barrier);
        let expiry_file = file.clone();
        let expiry = thread::spawn(move || {
            let store = store(&expiry_file, Clock(10_000));
            expiry_barrier.wait();
            expire_lease_if_needed(&store)
        });
        barrier.wait();
        assert!(release.join().unwrap().is_ok());
        assert!(expiry.join().unwrap().is_ok());

        let final_state = initial.load().state.unwrap();
        assert_eq!(final_state.current_term, Term(7));
        assert_eq!(final_state.lease_state, LeaseState::None);
        assert_eq!(final_state.active_lease_id, None);
        assert_eq!(final_state.holder_node_id, None);
        assert_eq!(final_state.lease_ttl_ms, None);
        assert_eq!(final_state.lease_deadline_monotonic_ms, None);
        assert!(final_state.journal.len() <= 1);
        assert_eq!(final_state.generation_watermarks.get("node-a"), Some(&1));
        let _ = fs::remove_file(file);
    }

    #[test]
    fn poisoned_mutation_lock_fails_closed_without_recovery() {
        let lock = Arc::new(std::sync::Mutex::new(()));
        let poison_lock = Arc::clone(&lock);
        let _ = thread::spawn(move || {
            let _guard = poison_lock.lock().unwrap();
            panic!("intentional test poison");
        })
        .join();
        assert!(matches!(
            lock_authority_mutation(&lock),
            Err(WitnessAuthorityError::AuthorityLockPoisoned)
        ));
    }

    #[test]
    fn matching_release_clears_authority_without_reading_clock() {
        let file = path("stage6-release");
        let store = store(&file, FailedClock);
        store.save(&active()).unwrap();
        let (request, observation) =
            lease_release("00000000-0000-4000-8000-000000000017", 1, 7, "lease-1");

        let prepared = prepare_lease_release_authority(&store, &observation, &request).unwrap();
        let ProtocolMessage::LeaseReleased(payload) = prepared.message else {
            panic!("expected LeaseReleased");
        };
        assert_eq!(payload.term, Term(7));
        assert_eq!(payload.lease_id, LeaseId::new("lease-1"));
        assert_eq!(payload.result, "released");
        assert_eq!(prepared.context.term, Term(7));
        assert_eq!(prepared.context.lease_id, None);

        let persisted = store.load().state.unwrap();
        assert_eq!(persisted.current_term, Term(7));
        assert_eq!(persisted.lease_state, LeaseState::None);
        assert_eq!(persisted.active_lease_id, None);
        assert_eq!(persisted.holder_node_id, None);
        assert_eq!(persisted.lease_ttl_ms, None);
        assert_eq!(persisted.lease_deadline_monotonic_ms, None);
        assert_eq!(persisted.generation_watermarks.get("node-a"), Some(&1));
        assert!(matches!(
            persisted.journal[0].result,
            CommittedSemanticResult::LeaseReleased(_)
        ));
        let _ = fs::remove_file(file);
    }

    #[test]
    fn expired_matching_release_is_allowed_and_duplicate_does_not_mutate() {
        let file = path("stage6-expired-duplicate");
        let store = store(&file, Clock(10_000));
        store.save(&active()).unwrap();
        let (request, observation) =
            lease_release("00000000-0000-4000-8000-000000000018", 1, 7, "lease-1");
        let first = prepare_lease_release_authority(&store, &observation, &request).unwrap();
        assert!(matches!(first.message, ProtocolMessage::LeaseReleased(_)));
        let before = store.load().state.unwrap();

        let duplicate = prepare_lease_release_authority(&store, &observation, &request).unwrap();
        assert!(matches!(
            duplicate.message,
            ProtocolMessage::LeaseReleased(_)
        ));
        assert_eq!(duplicate.context.term, Term(7));
        assert_eq!(duplicate.context.lease_id, None);
        assert_eq!(store.load().state.unwrap(), before);
        let _ = fs::remove_file(file);
    }

    #[test]
    fn old_release_duplicate_cannot_clear_newer_lease() {
        let file = path("stage6-aba");
        let store = store(&file, Clock(1_000));
        store.save(&active()).unwrap();
        let (old_request, old_observation) =
            lease_release("00000000-0000-4000-8000-000000000019", 1, 7, "lease-1");
        prepare_lease_release_authority(&store, &old_observation, &old_request).unwrap();

        let (request, observation) =
            lease_request("00000000-0000-4000-8000-000000000020", 2, 7, 10_000);
        let grant = prepare_lease_request_authority(&store, &observation, &request).unwrap();
        let lease_2 = match grant.message {
            ProtocolMessage::LeaseGrant(payload) => payload.lease_id,
            _ => panic!("expected LeaseGrant"),
        };
        let current = store.load().state.unwrap();
        assert_eq!(current.current_term, Term(8));
        assert_eq!(current.lease_state, LeaseState::Active);

        let duplicate =
            prepare_lease_release_authority(&store, &old_observation, &old_request).unwrap();
        assert!(matches!(
            duplicate.message,
            ProtocolMessage::LeaseReleased(_)
        ));
        assert_eq!(store.load().state.unwrap().current_term, Term(8));
        let after = store.load().state.unwrap();
        assert_eq!(after.lease_state, LeaseState::Active);
        assert_eq!(after.active_lease_id, Some(lease_2));
        assert_eq!(after.holder_node_id, Some(NodeId::new("node-a")));
        assert_eq!(after.lease_ttl_ms, Some(DurationMs(10_000)));
        assert_eq!(after.lease_deadline_monotonic_ms, Some(11_000));
        assert_eq!(after.generation_watermarks.get("node-a"), Some(&2));
        let _ = fs::remove_file(file);
    }

    #[test]
    fn release_none_is_deterministic_reject_and_retry_is_duplicate() {
        let file = path("stage6-none");
        let store = store(&file, FailedClock);
        store
            .save(&WitnessPersistentState::new(
                ClusterId::new("cluster"),
                BootId::new("boot-a"),
            ))
            .unwrap();
        let (request, observation) =
            lease_release("00000000-0000-4000-8000-000000000021", 1, 7, "lease-1");
        let first = prepare_lease_release_authority(&store, &observation, &request).unwrap();
        assert!(matches!(first.message, ProtocolMessage::LeaseReject(_)));
        let before = store.load().state.unwrap();
        let duplicate = prepare_lease_release_authority(&store, &observation, &request).unwrap();
        assert!(matches!(duplicate.message, ProtocolMessage::LeaseReject(_)));
        assert_eq!(store.load().state.unwrap(), before);
        let _ = fs::remove_file(file);
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn response_send_failure_does_not_rollback_durable_release() {
        let file = path("stage6-send-failure");
        let store = store(&file, FailedClock);
        store.save(&active()).unwrap();
        let (request, observation) =
            lease_release("00000000-0000-4000-8000-000000000022", 1, 7, "lease-1");
        let prepared = prepare_lease_release_authority(&store, &observation, &request).unwrap();
        let mut connection = disconnected_connection();
        let mut process = ProcessSession::from_session_id(SessionId::new("session-w"));
        let result = send_prepared_lease_response(
            &mut connection,
            &mut process,
            prepared,
            &crate::protocol::CborSerializer,
            &MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32])),
        );
        assert!(result.is_err());
        let persisted = store.load().state.unwrap();
        assert_eq!(persisted.current_term, Term(7));
        assert_eq!(persisted.lease_state, LeaseState::None);
        assert_eq!(persisted.active_lease_id, None);
        assert_eq!(persisted.generation_watermarks.get("node-a"), Some(&1));
        assert!(matches!(
            persisted.journal[0].result,
            CommittedSemanticResult::LeaseReleased(_)
        ));
        let _ = fs::remove_file(file);
    }

    #[test]
    fn release_rejects_stale_term_wrong_lease_and_wrong_holder() {
        let cases = [
            (
                "00000000-0000-4000-8000-000000000023",
                6,
                "lease-1",
                "node-a",
            ),
            (
                "00000000-0000-4000-8000-000000000024",
                7,
                "lease-2",
                "node-a",
            ),
            (
                "00000000-0000-4000-8000-000000000025",
                7,
                "lease-1",
                "node-b",
            ),
        ];
        for (index, (request_id, term, lease_id, holder)) in cases.into_iter().enumerate() {
            let file = path(&format!("stage6-reject-{index}"));
            let store = store(&file, FailedClock);
            store.save(&active()).unwrap();
            let (mut request, mut observation) = lease_release(request_id, 1, term, lease_id);
            if holder != "node-a" {
                if let WitnessRequestObservation::LeaseRelease { sender_node_id, .. } =
                    &mut observation
                {
                    *sender_node_id = NodeId::new(holder);
                }
                request.common.sender_node_id = NodeId::new(holder);
            }
            let prepared = prepare_lease_release_authority(&store, &observation, &request).unwrap();
            assert!(matches!(prepared.message, ProtocolMessage::LeaseReject(_)));
            let persisted = store.load().state.unwrap();
            assert_eq!(persisted.lease_state, LeaseState::Active);
            let watermark_node = if holder == "node-a" {
                "node-a"
            } else {
                "node-b"
            };
            assert_eq!(
                persisted.generation_watermarks.get(watermark_node),
                Some(&1)
            );
            let _ = fs::remove_file(file);
        }
    }

    #[test]
    fn unknown_not_ready_and_clock_failure_are_fail_closed() {
        let file = path("closed");
        let unknown_store = store(&file, Clock(1));
        let state = WitnessPersistentState {
            lease_state: LeaseState::Unknown,
            ..WitnessPersistentState::new(ClusterId::new("cluster"), BootId::new("boot-a"))
        };
        unknown_store.save(&state).unwrap();
        assert!(matches!(
            prepare_get_term_response(&unknown_store, &observation()),
            Err(WitnessAuthorityError::UnknownLease)
        ));
        let missing = store(&path("missing"), Clock(1));
        assert!(matches!(
            prepare_get_term_response(&missing, &observation()),
            Err(WitnessAuthorityError::NotReady(_))
        ));
        let clock_file = path("clock");
        let clock_store = store(&clock_file, FailedClock);
        clock_store.save(&active()).unwrap();
        assert!(matches!(
            prepare_get_term_response(&clock_store, &observation()),
            Err(WitnessAuthorityError::State(WitnessStateError::Clock(_)))
        ));
        let _ = fs::remove_file(file);
        let _ = fs::remove_file(clock_file);
    }

    #[test]
    fn get_term_commits_request_before_reading_and_sending_ready_state() {
        let file = path("lifecycle");
        let store = store(&file, Clock(7_000));
        let mut state =
            WitnessPersistentState::new(ClusterId::new("cluster"), BootId::new("boot-a"));
        state.current_term = Term(7);
        store.save(&state).unwrap();
        let (mut node, mut witness) = pair();
        let auth = MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32]));
        let serializer = crate::protocol::CborSerializer;
        let mut process =
            ProcessSession::from_session_id(crate::protocol::SessionId::new("session-a"));
        let mut outstanding = crate::witness_runtime::WitnessRequestOutstanding::new();
        crate::witness_runtime::send_get_term(
            &mut node,
            &mut process,
            &mut outstanding,
            RequestId::new("request-1"),
            &serializer,
            &auth,
        )
        .unwrap();
        let pending = witness.receive_pending(&serializer, &auth).unwrap();
        assert_eq!(witness.highest_sequence(), Sequence(0));
        let prepared = handle_get_term_authority(&mut witness, &pending, &store).unwrap();
        assert_eq!(witness.highest_sequence(), Sequence(1));
        assert_eq!(prepared.payload.current_term, Term(7));
        send_prepared_term_status(
            &mut witness,
            &mut ProcessSession::from_session_id(crate::protocol::SessionId::new("session-w")),
            prepared,
            &serializer,
            &auth,
        )
        .unwrap();
        let response = node.receive_pending(&serializer, &auth).unwrap();
        assert_eq!(
            response.message().unsigned().common.request_id,
            Some(RequestId::new("request-1"))
        );
        let _ = fs::remove_file(file);
    }

    #[test]
    fn lease_request_grant_atomically_commits_authority_journal_and_watermark() {
        let file = path("stage4-grant");
        let store = store(&file, Clock(1_000));
        let mut state =
            WitnessPersistentState::new(ClusterId::new("cluster"), BootId::new("boot-a"));
        state.current_term = Term(7);
        store.save(&state).unwrap();
        let (request, observation) =
            lease_request("00000000-0000-4000-8000-000000000001", 1, 7, 10_000);

        let prepared = prepare_lease_request_authority(&store, &observation, &request).unwrap();
        let ProtocolMessage::LeaseGrant(grant) = prepared.message else {
            panic!("expected grant");
        };
        assert_eq!(grant.term, Term(8));
        assert_eq!(grant.holder_node_id, NodeId::new("node-a"));
        assert_eq!(grant.lease_ttl_ms, DurationMs(10_000));
        assert_eq!(grant.renew_after_ms, DurationMs(3_000));
        assert_eq!(grant.lease_remaining_ms, DurationMs(10_000));
        assert!(is_uuid_v4(grant.lease_id.as_str()));
        assert_ne!(
            grant.lease_id.as_str(),
            "00000000-0000-4000-8000-000000000001"
        );

        let persisted = store.load().state.unwrap();
        assert_eq!(persisted.current_term, Term(8));
        assert_eq!(persisted.lease_state, LeaseState::Active);
        assert_eq!(persisted.active_lease_id, Some(grant.lease_id));
        assert_eq!(persisted.holder_node_id, Some(NodeId::new("node-a")));
        assert_eq!(persisted.lease_deadline_monotonic_ms, Some(11_000));
        assert_eq!(persisted.generation_watermarks.get("node-a"), Some(&1));
        assert_eq!(persisted.journal.len(), 1);
        let _ = fs::remove_file(file);
    }

    #[test]
    fn lease_renew_updates_only_deadline_and_commits_renewed_result() {
        let file = path("stage5-renew");
        let store = store(&file, Clock(5_000));
        store.save(&active()).unwrap();
        let (request, observation) =
            lease_renew("00000000-0000-4000-8000-000000000009", 1, 7, "lease-1");
        let prepared = prepare_lease_renew_authority(&store, &observation, &request).unwrap();
        let ProtocolMessage::LeaseRenewed(renewed) = prepared.message else {
            panic!("expected renewed response");
        };
        assert_eq!(renewed.term, Term(7));
        assert_eq!(renewed.lease_id, LeaseId::new("lease-1"));
        assert_eq!(renewed.holder_node_id, NodeId::new("node-a"));
        assert_eq!(renewed.lease_ttl_ms, DurationMs(10_000));
        assert_eq!(renewed.renew_after_ms, DurationMs(3_000));
        assert_eq!(renewed.lease_remaining_ms, DurationMs(10_000));
        let persisted = store.load().state.unwrap();
        assert_eq!(persisted.current_term, Term(7));
        assert_eq!(persisted.lease_deadline_monotonic_ms, Some(15_000));
        assert_eq!(persisted.generation_watermarks.get("node-a"), Some(&1));
        assert!(matches!(
            persisted.journal[0].result,
            CommittedSemanticResult::LeaseRenewed(_)
        ));
        let _ = fs::remove_file(file);
    }

    #[test]
    fn duplicate_renewal_uses_current_deadline_without_extending_it() {
        let file = path("stage5-duplicate");
        let initial = store(&file, Clock(5_000));
        initial.save(&active()).unwrap();
        let (request, observation) =
            lease_renew("00000000-0000-4000-8000-000000000010", 1, 7, "lease-1");
        prepare_lease_renew_authority(&initial, &observation, &request).unwrap();
        let later = store(&file, Clock(6_000));
        let duplicate = prepare_lease_renew_authority(&later, &observation, &request).unwrap();
        let ProtocolMessage::LeaseRenewed(renewed) = duplicate.message else {
            panic!("expected duplicate renewal");
        };
        assert_eq!(renewed.lease_remaining_ms, DurationMs(9_000));
        assert_eq!(
            later.load().state.unwrap().lease_deadline_monotonic_ms,
            Some(15_000)
        );
        let _ = fs::remove_file(file);
    }

    #[test]
    fn later_renewal_then_older_duplicate_uses_later_current_deadline() {
        let file = path("stage5-later");
        let initial = store(&file, Clock(5_000));
        initial.save(&active()).unwrap();
        let (old_request, old_observation) =
            lease_renew("00000000-0000-4000-8000-000000000011", 1, 7, "lease-1");
        prepare_lease_renew_authority(&initial, &old_observation, &old_request).unwrap();
        let later = store(&file, Clock(7_000));
        let (new_request, new_observation) =
            lease_renew("00000000-0000-4000-8000-000000000012", 2, 7, "lease-1");
        prepare_lease_renew_authority(&later, &new_observation, &new_request).unwrap();
        let current = store(&file, Clock(8_000));
        let duplicate =
            prepare_lease_renew_authority(&current, &old_observation, &old_request).unwrap();
        let ProtocolMessage::LeaseRenewed(renewed) = duplicate.message else {
            panic!("expected old duplicate renewal");
        };
        assert_eq!(renewed.lease_remaining_ms, DurationMs(9_000));
        assert_eq!(
            current.load().state.unwrap().lease_deadline_monotonic_ms,
            Some(17_000)
        );
        let _ = fs::remove_file(file);
    }

    #[test]
    fn expired_renewal_is_rejected_without_clearing_active_lease() {
        let file = path("stage5-expired");
        let store = store(&file, Clock(10_000));
        store.save(&active()).unwrap();
        let (request, observation) =
            lease_renew("00000000-0000-4000-8000-000000000013", 1, 7, "lease-1");
        let prepared = prepare_lease_renew_authority(&store, &observation, &request).unwrap();
        assert!(matches!(prepared.message, ProtocolMessage::LeaseReject(_)));
        let persisted = store.load().state.unwrap();
        assert_eq!(persisted.lease_state, LeaseState::Active);
        assert_eq!(persisted.lease_deadline_monotonic_ms, Some(10_000));
        assert_eq!(persisted.generation_watermarks.get("node-a"), Some(&1));
        let _ = fs::remove_file(file);
    }

    /// J20: commit one renewal of lease-1 (term 7) at t=5000, so its deadline is 15000.
    fn j20_committed_renewal(name: &str) -> (PathBuf, UnsignedEnvelope, WitnessRequestObservation) {
        let file = path(&format!("j20-{name}"));
        let initial = store(&file, Clock(5_000));
        initial.save(&active()).unwrap();
        let (request, observation) =
            lease_renew("00000000-0000-4000-8000-000000002001", 1, 7, "lease-1");
        let first = prepare_lease_renew_authority(&initial, &observation, &request).unwrap();
        assert!(matches!(first.message, ProtocolMessage::LeaseRenewed(_)));
        (file, request, observation)
    }

    fn j20_retired_code(prepared: &PreparedLeaseResponse) -> Option<WitnessMutationOutcomeCode> {
        match &prepared.message {
            ProtocolMessage::LeaseReject(payload) => Some(payload.code),
            _ => None,
        }
    }

    #[test]
    fn j20_replay_after_expiry_is_retired_and_keeps_history_and_state() {
        let (file, request, observation) = j20_committed_renewal("expired");
        let expiring = store(&file, Clock(15_000));
        assert_eq!(
            expire_lease_if_needed(&expiring).unwrap(),
            LeaseExpiryResult::Expired
        );
        let before = expiring.load().state.unwrap();
        assert_eq!(before.lease_state, LeaseState::None);
        for now in [15_500, 40_000] {
            let later = store(&file, Clock(now));
            let replay = prepare_lease_renew_authority(&later, &observation, &request).unwrap();
            assert_eq!(
                j20_retired_code(&replay),
                Some(WitnessMutationOutcomeCode::RetiredStale)
            );
            let ProtocolMessage::LeaseReject(payload) = &replay.message else {
                panic!("expected a reject");
            };
            assert!(
                payload.reason.contains("committed earlier")
                    && payload.reason.contains("nothing was renewed"),
                "the reason must keep the historical commit visible: {}",
                payload.reason
            );
            let after = later.load().state.unwrap();
            assert_eq!(after, before, "a retired replay commits nothing");
            assert_eq!(after.journal.len(), 1);
            assert!(matches!(
                after.journal[0].result,
                CommittedSemanticResult::LeaseRenewed(_)
            ));
            assert_eq!(after.generation_watermarks.get("node-a"), Some(&1));
            assert_eq!(after.current_term, Term(7));
            assert_eq!(after.holder_node_id, None);
        }
        let _ = fs::remove_file(file);
    }

    #[test]
    fn j20_replay_with_valid_lease_keeps_the_idempotent_answer() {
        let (file, request, observation) = j20_committed_renewal("valid");
        let later = store(&file, Clock(14_999));
        let replay = prepare_lease_renew_authority(&later, &observation, &request).unwrap();
        let ProtocolMessage::LeaseRenewed(renewed) = replay.message else {
            panic!("a replay inside the lease keeps the committed answer");
        };
        assert_eq!(renewed.lease_remaining_ms, DurationMs(1));
        assert_eq!(
            later.load().state.unwrap().lease_deadline_monotonic_ms,
            Some(15_000)
        );
        let _ = fs::remove_file(file);
    }

    #[test]
    fn j20_replay_at_and_after_the_deadline_before_expiry_is_retired() {
        for (name, now) in [("at", 15_000), ("after", 15_001)] {
            let (file, request, observation) = j20_committed_renewal(name);
            let later = store(&file, Clock(now));
            let before = later.load().state.unwrap();
            assert_eq!(before.lease_state, LeaseState::Active);
            let replay = prepare_lease_renew_authority(&later, &observation, &request).unwrap();
            assert_eq!(
                j20_retired_code(&replay),
                Some(WitnessMutationOutcomeCode::RetiredStale)
            );
            assert_eq!(later.load().state.unwrap(), before);
            let _ = fs::remove_file(file);
        }
    }

    #[test]
    fn j20_replay_with_another_holder_active_never_changes_that_lease() {
        let (file, request, observation) = j20_committed_renewal("other-holder");
        let later = store(&file, Clock(20_000));
        let mut state = later.load().state.unwrap();
        state.current_term = Term(8);
        state.active_lease_id = Some(LeaseId::new("lease-2"));
        state.holder_node_id = Some(NodeId::new("node-b"));
        state.lease_deadline_monotonic_ms = Some(29_000);
        later.save(&state).unwrap();
        let before = later.load().state.unwrap();
        let replay = prepare_lease_renew_authority(&later, &observation, &request).unwrap();
        assert_eq!(
            j20_retired_code(&replay),
            Some(WitnessMutationOutcomeCode::RetiredStale)
        );
        let after = later.load().state.unwrap();
        assert_eq!(after, before);
        assert_eq!(after.holder_node_id, Some(NodeId::new("node-b")));
        assert_eq!(after.active_lease_id, Some(LeaseId::new("lease-2")));
        assert_eq!(after.current_term, Term(8));
        let _ = fs::remove_file(file);
    }

    #[test]
    fn j20_same_request_id_with_another_payload_is_a_conflict() {
        let (file, _request, _observation) = j20_committed_renewal("conflict");
        let later = store(&file, Clock(6_000));
        let before = later.load().state.unwrap();
        let (other, other_observation) =
            lease_renew("00000000-0000-4000-8000-000000002001", 1, 7, "lease-x");
        let replay = prepare_lease_renew_authority(&later, &other_observation, &other).unwrap();
        assert_eq!(
            j20_retired_code(&replay),
            Some(WitnessMutationOutcomeCode::Conflict)
        );
        assert_eq!(later.load().state.unwrap(), before);
        let _ = fs::remove_file(file);
    }

    #[test]
    fn j20_unknown_request_id_is_a_new_request() {
        let (file, _request, _observation) = j20_committed_renewal("new-id");
        let later = store(&file, Clock(6_000));
        let (next, next_observation) =
            lease_renew("00000000-0000-4000-8000-000000002002", 2, 7, "lease-1");
        let renewed = prepare_lease_renew_authority(&later, &next_observation, &next).unwrap();
        assert!(matches!(renewed.message, ProtocolMessage::LeaseRenewed(_)));
        let after = later.load().state.unwrap();
        assert_eq!(after.lease_deadline_monotonic_ms, Some(16_000));
        assert_eq!(after.journal.len(), 2);
        assert_eq!(after.generation_watermarks.get("node-a"), Some(&2));
        let _ = fs::remove_file(file);
    }

    #[test]
    fn j20_unknown_lease_and_term_rollback_and_corrupt_metadata_stay_fail_closed() {
        let (file, request, observation) = j20_committed_renewal("unknown");
        let later = store(&file, Clock(16_000));
        let mut state = later.load().state.unwrap();
        state.lease_state = LeaseState::Unknown;
        later.save(&state).unwrap();
        assert!(matches!(
            prepare_lease_renew_authority(&later, &observation, &request),
            Err(WitnessAuthorityError::UnknownLease)
        ));
        let _ = fs::remove_file(file);

        let (file, request, observation) = j20_committed_renewal("rollback");
        let later = store(&file, Clock(16_000));
        let mut state = later.load().state.unwrap();
        state.current_term = Term(6);
        state.lease_state = LeaseState::None;
        state.active_lease_id = None;
        state.holder_node_id = None;
        state.lease_ttl_ms = None;
        state.lease_deadline_monotonic_ms = None;
        later.save(&state).unwrap();
        assert!(matches!(
            prepare_lease_renew_authority(&later, &observation, &request),
            Err(WitnessAuthorityError::AuthorityInvariant(_))
        ));
        let _ = fs::remove_file(file);

        for (name, holder, lease, term) in [
            ("holder", "node-b", "lease-1", 7),
            ("same-term-other-lease", "node-a", "lease-9", 7),
            ("later-term-same-lease", "node-a", "lease-1", 8),
        ] {
            let (file, request, observation) = j20_committed_renewal(name);
            let later = store(&file, Clock(6_000));
            let mut state = later.load().state.unwrap();
            state.current_term = Term(term);
            state.holder_node_id = Some(NodeId::new(holder));
            state.active_lease_id = Some(LeaseId::new(lease));
            later.save(&state).unwrap();
            let before = later.load().state.unwrap();
            assert!(matches!(
                prepare_lease_renew_authority(&later, &observation, &request),
                Err(WitnessAuthorityError::AuthorityInvariant(_))
            ));
            assert_eq!(later.load().state.unwrap(), before);
            let _ = fs::remove_file(file);
        }
    }

    #[test]
    fn j20_missing_journal_record_or_state_never_restores_authority() {
        let (file, request, observation) = j20_committed_renewal("record-missing");
        let later = store(&file, Clock(16_000));
        assert_eq!(
            expire_lease_if_needed(&later).unwrap(),
            LeaseExpiryResult::Expired
        );
        let mut state = later.load().state.unwrap();
        state.journal.clear();
        later.save(&state).unwrap();
        let before = later.load().state.unwrap();
        let replay = prepare_lease_renew_authority(&later, &observation, &request).unwrap();
        assert_eq!(
            j20_retired_code(&replay),
            Some(WitnessMutationOutcomeCode::RetiredStale)
        );
        assert_eq!(later.load().state.unwrap(), before);
        let _ = fs::remove_file(&file);

        let (file, request, observation) = j20_committed_renewal("state-missing");
        fs::remove_file(&file).unwrap();
        let later = store(&file, Clock(16_000));
        assert!(prepare_lease_renew_authority(&later, &observation, &request).is_err());
        assert!(!file.exists());

        let (file, request, observation) = j20_committed_renewal("state-corrupt");
        fs::write(&file, b"not a witness state").unwrap();
        let later = store(&file, Clock(16_000));
        assert!(prepare_lease_renew_authority(&later, &observation, &request).is_err());
        assert_eq!(fs::read(&file).unwrap(), b"not a witness state");
        let _ = fs::remove_file(file);
    }

    #[test]
    fn j20_retired_replay_is_deterministic_and_after_restart() {
        let (file, request, observation) = j20_committed_renewal("restart");
        let expiring = store(&file, Clock(15_000));
        expire_lease_if_needed(&expiring).unwrap();
        let first =
            prepare_lease_renew_authority(&store(&file, Clock(16_000)), &observation, &request)
                .unwrap();
        let second =
            prepare_lease_renew_authority(&store(&file, Clock(90_000)), &observation, &request)
                .unwrap();
        assert_eq!(first.message, second.message);
        assert_eq!(first.context.term, Term(7));
        let _ = fs::remove_file(file);
    }

    /// J21: grant lease to node-a at t=1000 (term 0 -> 1, deadline 11000) and return the request
    /// and the granted lease id.
    fn j21_committed_grant(
        name: &str,
    ) -> (
        PathBuf,
        UnsignedEnvelope,
        WitnessRequestObservation,
        LeaseId,
    ) {
        let file = path(&format!("j21-{name}"));
        let initial = store(&file, Clock(1_000));
        initial
            .save(&WitnessPersistentState::new(
                ClusterId::new("cluster"),
                BootId::new("boot-a"),
            ))
            .unwrap();
        let (request, observation) =
            lease_request("00000000-0000-4000-8000-000000003001", 1, 0, 10_000);
        let first = prepare_lease_request_authority(&initial, &observation, &request).unwrap();
        let ProtocolMessage::LeaseGrant(grant) = first.message else {
            panic!("expected the first grant");
        };
        assert_eq!(grant.term, Term(1));
        (file, request, observation, grant.lease_id)
    }

    fn j21_reject(
        prepared: &PreparedLeaseResponse,
    ) -> Option<(WitnessMutationOutcomeCode, String)> {
        match &prepared.message {
            ProtocolMessage::LeaseReject(payload) => Some((payload.code, payload.reason.clone())),
            _ => None,
        }
    }

    fn j22_fresh(name: &str, state: WitnessPersistentState) -> PathBuf {
        let file = path(&format!("j22-{name}"));
        store(&file, Clock(1_000)).save(&state).unwrap();
        file
    }

    fn j22_empty() -> WitnessPersistentState {
        WitnessPersistentState::new(ClusterId::new("cluster"), BootId::new("boot-a"))
    }

    /// J22: an Active lease of `holder` at `term` (deadline 20000, TTL 10000).
    fn j22_active(term: u64, holder: &str, lease: &str) -> WitnessPersistentState {
        let mut state = j22_empty();
        state.current_term = Term(term);
        state.active_lease_id = Some(LeaseId::new(lease));
        state.holder_node_id = Some(NodeId::new(holder));
        state.lease_ttl_ms = Some(DurationMs(10_000));
        state.lease_deadline_monotonic_ms = Some(20_000);
        state.lease_state = LeaseState::Active;
        state
    }

    /// The authority part of a Witness state (everything but the journal and the watermarks).
    fn j22_authority(
        state: &WitnessPersistentState,
    ) -> (
        Term,
        Option<LeaseId>,
        Option<NodeId>,
        Option<DurationMs>,
        Option<u64>,
        LeaseState,
    ) {
        (
            state.current_term,
            state.active_lease_id.clone(),
            state.holder_node_id.clone(),
            state.lease_ttl_ms,
            state.lease_deadline_monotonic_ms,
            state.lease_state.clone(),
        )
    }

    const J22_FENCE_ID: &str = "00000000-0000-4000-8000-000000004f01";
    /// The fence's lease id is not UUID-shaped, so it can never equal a lease id the Witness
    /// generates (UUIDv4, `generate_lease_id`).
    const J22_FENCE_LEASE: &str = "j22-generation-fence";

    /// J22 (OD-J21-3, design A): the replay of a retained request that never reached the Witness is
    /// its first delivery: it commits a new grant - the term advances and node-a becomes the holder
    /// - although the node never uses it.
    #[test]
    fn j22_first_delivery_of_a_retained_request_commits_a_new_grant() {
        let file = j22_fresh("first-delivery", j22_empty());
        let witness = store(&file, Clock(1_000));
        let (request, observation) =
            lease_request("00000000-0000-4000-8000-000000004001", 1, 0, 10_000);
        let first = prepare_lease_request_authority(&witness, &observation, &request).unwrap();
        let ProtocolMessage::LeaseGrant(grant) = first.message else {
            panic!("the first delivery is a new request");
        };
        let after = witness.load().state.unwrap();
        assert_eq!(grant.term, Term(1));
        assert_eq!(after.current_term, Term(1), "the term advanced");
        assert_eq!(after.holder_node_id, Some(NodeId::new("node-a")));
        assert_eq!(after.generation_watermarks.get("node-a"), Some(&1));
        let _ = fs::remove_file(file);
    }

    /// J22 (design B): GET_TERM cannot prove that a retained request is uncommitted. (1) The view it
    /// gives before a late delivery equals the view of a request that never arrived, and the late
    /// delivery then commits a grant (TOCTOU). (2) A request committed as a reject leaves, once the
    /// other lease expired, the same view as one that never arrived.
    #[test]
    fn j22_get_term_cannot_prove_a_retained_request_uncommitted() {
        let file = j22_fresh("toctou", j22_empty());
        let witness = store(&file, Clock(1_000));
        let view = prepare_get_term_response(&witness, &observation())
            .unwrap()
            .payload;
        assert_eq!((view.current_term, view.current_holder), (Term(0), None));
        let (request, late) = lease_request("00000000-0000-4000-8000-000000004011", 1, 0, 10_000);
        assert!(
            matches!(
                prepare_lease_request_authority(&witness, &late, &request)
                    .unwrap()
                    .message,
                ProtocolMessage::LeaseGrant(_)
            ),
            "the late delivery commits a grant after the check"
        );
        let _ = fs::remove_file(file);

        let file = j22_fresh("toctou-reject", j22_active(3, "node-b", "lease-b"));
        let witness = store(&file, Clock(1_000));
        let (request, observation_3) =
            lease_request("00000000-0000-4000-8000-000000004012", 1, 3, 10_000);
        let rejected = prepare_lease_request_authority(&witness, &observation_3, &request).unwrap();
        assert!(matches!(rejected.message, ProtocolMessage::LeaseReject(_)));
        let expired = store(&file, Clock(20_000));
        assert_eq!(
            expire_lease_if_needed(&expired).unwrap(),
            LeaseExpiryResult::Expired
        );
        let view = prepare_get_term_response(&expired, &observation())
            .unwrap()
            .payload;
        assert_eq!(
            (view.current_term, view.current_holder),
            (Term(3), None),
            "the same view as a request that never arrived"
        );
        assert_eq!(
            expired
                .load()
                .state
                .unwrap()
                .generation_watermarks
                .get("node-a"),
            Some(&1),
            "yet the request is committed"
        );
        let _ = fs::remove_file(file);
    }

    /// J22 (design C): an absent journal record is not proof that a request is uncommitted. The
    /// bounded journal (64 records) evicts committed records; only the requester's generation
    /// watermark still shows the commit.
    #[test]
    fn j22_absent_journal_record_is_not_proof_of_no_commit() {
        let file = j22_fresh("evicted", j22_empty());
        let witness = store(&file, Clock(1_000));
        let (request, observation) =
            lease_request("00000000-0000-4000-8000-000000004021", 1, 0, 10_000);
        prepare_lease_request_authority(&witness, &observation, &request).unwrap();
        for generation in 2..=65u64 {
            let id = format!("00000000-0000-4000-8000-{:012x}", 0x4100 + generation);
            let (filler, filler_observation) = lease_release(&id, generation, 0, "j22-filler");
            prepare_lease_release_authority(&witness, &filler_observation, &filler).unwrap();
        }
        let state = witness.load().state.unwrap();
        assert_eq!(
            state.journal.len(),
            crate::witness_journal::JOURNAL_CAPACITY
        );
        assert!(
            state
                .journal
                .iter()
                .all(|record| record.request_id.as_str() != "00000000-0000-4000-8000-000000004021"),
            "the committed record is evicted"
        );
        assert_eq!(state.generation_watermarks.get("node-a"), Some(&65));
        let replay = prepare_lease_request_authority(&witness, &observation, &request).unwrap();
        assert_eq!(
            j21_reject(&replay).map(|r| r.0),
            Some(WitnessMutationOutcomeCode::RetiredStale),
            "absent, yet committed: the watermark covers it"
        );
        assert_eq!(witness.load().state.unwrap(), state);
        let _ = fs::remove_file(file);
    }

    /// J22 (design C-F, generation fence): a LEASE_RELEASE at the retained request's generation with
    /// term 0 can never match a lease (every grant has a term of at least 1), so it commits a
    /// PolicyReject that changes no authority - with no lease, another holder's lease or node-a's
    /// own - and it fills the generation: the original request can then never commit, however late
    /// it arrives.
    #[test]
    fn j22_generation_fence_retires_an_undelivered_request_without_authority_change() {
        let mut empty = j22_empty();
        empty.current_term = Term(4);
        for (name, mut state) in [
            ("none", empty),
            ("other", j22_active(5, "node-b", "lease-b")),
            ("own", j22_active(6, "node-a", "lease-a")),
        ] {
            state.generation_watermarks.insert("node-a".to_string(), 3);
            let file = j22_fresh(&format!("fence-{name}"), state);
            let witness = store(&file, Clock(2_000));
            let before = witness.load().state.unwrap();
            let (fence, fence_observation) = lease_release(J22_FENCE_ID, 4, 0, J22_FENCE_LEASE);
            let fenced =
                prepare_lease_release_authority(&witness, &fence_observation, &fence).unwrap();
            assert_eq!(
                j21_reject(&fenced).map(|r| r.0),
                Some(WitnessMutationOutcomeCode::PolicyReject),
                "{name}"
            );
            let after = witness.load().state.unwrap();
            assert_eq!(j22_authority(&after), j22_authority(&before), "{name}");
            assert_eq!(
                after.generation_watermarks.get("node-a"),
                Some(&4),
                "{name}"
            );
            assert_eq!(after.journal.len(), before.journal.len() + 1, "{name}");
            let (late, late_observation) = lease_request(
                "00000000-0000-4000-8000-000000004031",
                4,
                before.current_term.0,
                10_000,
            );
            let retired =
                prepare_lease_request_authority(&witness, &late_observation, &late).unwrap();
            assert_eq!(
                j21_reject(&retired).map(|r| r.0),
                Some(WitnessMutationOutcomeCode::RetiredStale),
                "{name}: the late original can no longer commit"
            );
            assert_eq!(witness.load().state.unwrap(), after, "{name}");
            let _ = fs::remove_file(file);
        }
    }

    /// J22 (C-F): after a committed request the fence is RetiredStale and commits nothing; the exact
    /// replay of the request then takes the J21 duplicate path.
    #[test]
    fn j22_generation_fence_after_a_committed_request_defers_to_the_exact_replay() {
        let (file, request, observation, lease) = j21_committed_grant("j22-fence-after");
        let witness = store(&file, Clock(2_000));
        let before = witness.load().state.unwrap();
        let (fence, fence_observation) = lease_release(J22_FENCE_ID, 1, 0, J22_FENCE_LEASE);
        let fenced = prepare_lease_release_authority(&witness, &fence_observation, &fence).unwrap();
        assert_eq!(
            j21_reject(&fenced).map(|r| r.0),
            Some(WitnessMutationOutcomeCode::RetiredStale)
        );
        assert_eq!(witness.load().state.unwrap(), before);
        let replay = prepare_lease_request_authority(&witness, &observation, &request).unwrap();
        let ProtocolMessage::LeaseGrant(grant) = replay.message else {
            panic!("the exact replay of a current grant keeps its answer");
        };
        assert_eq!(grant.lease_id, lease);
        assert_eq!(witness.load().state.unwrap(), before);
        let _ = fs::remove_file(file);
    }

    /// J22 (C-F): the fence is idempotent; with an UNKNOWN lease it fails closed and with a gap it
    /// is refused - in both cases nothing is committed.
    #[test]
    fn j22_generation_fence_is_idempotent_and_fails_closed() {
        let file = j22_fresh("fence-idem", j22_empty());
        let witness = store(&file, Clock(1_000));
        let (fence, fence_observation) = lease_release(J22_FENCE_ID, 1, 0, J22_FENCE_LEASE);
        let first = prepare_lease_release_authority(&witness, &fence_observation, &fence).unwrap();
        let committed = witness.load().state.unwrap();
        let again = prepare_lease_release_authority(&witness, &fence_observation, &fence).unwrap();
        assert_eq!(again.message, first.message);
        assert_eq!(witness.load().state.unwrap(), committed);
        let _ = fs::remove_file(file);

        let mut unknown = j22_empty();
        unknown.lease_state = LeaseState::Unknown;
        let file = j22_fresh("fence-unknown", unknown);
        let witness = store(&file, Clock(1_000));
        let before = witness.load().state.unwrap();
        assert!(matches!(
            prepare_lease_release_authority(&witness, &fence_observation, &fence),
            Err(WitnessAuthorityError::UnknownLease)
        ));
        assert_eq!(witness.load().state.unwrap(), before);
        let _ = fs::remove_file(file);

        let file = j22_fresh("fence-gap", j22_empty());
        let witness = store(&file, Clock(1_000));
        let before = witness.load().state.unwrap();
        let (gap, gap_observation) = lease_release(J22_FENCE_ID, 3, 0, J22_FENCE_LEASE);
        let refused = prepare_lease_release_authority(&witness, &gap_observation, &gap).unwrap();
        assert_eq!(
            j21_reject(&refused).map(|r| r.0),
            Some(WitnessMutationOutcomeCode::GenerationGap)
        );
        assert_eq!(witness.load().state.unwrap(), before);
        let _ = fs::remove_file(file);
    }

    /// J22 (IA-J22-01): the fence does not rely on the term alone. A corrupt state that the structure
    /// check accepts (an Active lease at term 0) is still not released, because the fence's lease id
    /// is not UUID-shaped and can never equal a generated lease id: two independent mismatches.
    #[test]
    fn j22_generation_fence_relies_on_term_and_lease_id_mismatch() {
        let mut corrupt = j22_active(0, "node-a", "4d1e2f3a-0000-4000-8000-00000000c0de");
        corrupt
            .generation_watermarks
            .insert("node-a".to_string(), 3);
        let file = j22_fresh("fence-corrupt", corrupt);
        let witness = store(&file, Clock(2_000));
        let before = witness.load().state.unwrap();
        assert_eq!(before.current_term, Term(0));
        assert_eq!(before.lease_state, LeaseState::Active);
        let (fence, fence_observation) = lease_release(J22_FENCE_ID, 4, 0, J22_FENCE_LEASE);
        let fenced = prepare_lease_release_authority(&witness, &fence_observation, &fence).unwrap();
        assert_eq!(
            j21_reject(&fenced).map(|r| r.0),
            Some(WitnessMutationOutcomeCode::PolicyReject)
        );
        assert_eq!(
            j22_authority(&witness.load().state.unwrap()),
            j22_authority(&before),
            "the term-0 lease is not released"
        );
        assert!(!crate::protocol::is_valid_mutating_request_id(
            J22_FENCE_LEASE
        ));
        let _ = fs::remove_file(file);
    }

    /// J22 (B-3, TTL mismatch): a duplicate grant whose recorded TTL no longer matches the state
    /// is an invariant (fail-closed), not an answer.
    #[test]
    fn j22_duplicate_grant_with_a_ttl_mismatch_is_an_invariant() {
        let (file, request, observation, _lease) = j21_committed_grant("j22-ttl");
        let witness = store(&file, Clock(2_000));
        let mut state = witness.load().state.unwrap();
        state.lease_ttl_ms = Some(DurationMs(5_000));
        witness.save(&state).unwrap();
        let before = witness.load().state.unwrap();
        assert!(matches!(
            prepare_lease_request_authority(&witness, &observation, &request),
            Err(WitnessAuthorityError::AuthorityInvariant(_))
        ));
        assert_eq!(witness.load().state.unwrap(), before);
        let _ = fs::remove_file(file);
    }

    /// J22 (B-3, a new holder): a late first delivery while another holder's lease is active commits
    /// a reject only; that lease is unchanged and the exact replay repeats the reject.
    #[test]
    fn j22_late_first_delivery_competing_with_a_new_holder_commits_only_a_reject() {
        let file = j22_fresh("competing", j22_active(5, "node-b", "lease-b"));
        let witness = store(&file, Clock(2_000));
        let before = witness.load().state.unwrap();
        let (request, observation) =
            lease_request("00000000-0000-4000-8000-000000004041", 1, 4, 10_000);
        let first = prepare_lease_request_authority(&witness, &observation, &request).unwrap();
        assert_eq!(
            j21_reject(&first).map(|r| r.0),
            Some(WitnessMutationOutcomeCode::PolicyReject)
        );
        let after = witness.load().state.unwrap();
        assert_eq!(j22_authority(&after), j22_authority(&before));
        let replay = prepare_lease_request_authority(&witness, &observation, &request).unwrap();
        assert_eq!(replay.message, first.message);
        assert_eq!(witness.load().state.unwrap(), after);
        let _ = fs::remove_file(file);
    }

    #[test]
    fn j21_grant_replay_while_current_keeps_the_answer_without_extension() {
        let (file, request, observation, lease) = j21_committed_grant("current");
        let later = store(&file, Clock(10_999));
        let before = later.load().state.unwrap();
        let replay = prepare_lease_request_authority(&later, &observation, &request).unwrap();
        let ProtocolMessage::LeaseGrant(grant) = replay.message else {
            panic!("a replay of the current grant keeps the committed answer");
        };
        assert_eq!(grant.lease_id, lease);
        assert_eq!(grant.term, Term(1));
        assert_eq!(grant.lease_remaining_ms, DurationMs(1));
        assert_eq!(
            later.load().state.unwrap(),
            before,
            "no extension, no new grant"
        );
        let _ = fs::remove_file(file);
    }

    #[test]
    fn j21_grant_replay_after_expiry_is_retired_and_creates_nothing() {
        let (file, request, observation, _lease) = j21_committed_grant("expired");
        let expiring = store(&file, Clock(11_000));
        assert_eq!(
            expire_lease_if_needed(&expiring).unwrap(),
            LeaseExpiryResult::Expired
        );
        let before = expiring.load().state.unwrap();
        for now in [11_500, 60_000] {
            let later = store(&file, Clock(now));
            let replay = prepare_lease_request_authority(&later, &observation, &request).unwrap();
            let (code, reason) = j21_reject(&replay).expect("a reject");
            assert_eq!(code, WitnessMutationOutcomeCode::RetiredStale);
            assert!(
                reason.contains("granted earlier") && reason.contains("no lease was granted"),
                "{reason}"
            );
            let after = later.load().state.unwrap();
            assert_eq!(after, before, "a retired replay commits nothing");
            assert_eq!(after.current_term, Term(1));
            assert_eq!(after.lease_state, LeaseState::None);
            assert_eq!(after.journal.len(), 1);
            assert!(matches!(
                after.journal[0].result,
                CommittedSemanticResult::LeaseGrant(_)
            ));
            assert_eq!(after.generation_watermarks.get("node-a"), Some(&1));
        }
        let _ = fs::remove_file(file);
    }

    #[test]
    fn j21_grant_replay_at_and_after_the_deadline_before_expiry_is_retired() {
        for (name, now) in [("at", 11_000), ("after", 11_001)] {
            let (file, request, observation, _lease) = j21_committed_grant(name);
            let later = store(&file, Clock(now));
            let before = later.load().state.unwrap();
            let replay = prepare_lease_request_authority(&later, &observation, &request).unwrap();
            assert_eq!(
                j21_reject(&replay).map(|r| r.0),
                Some(WitnessMutationOutcomeCode::RetiredStale)
            );
            assert_eq!(later.load().state.unwrap(), before);
            let _ = fs::remove_file(file);
        }
    }

    #[test]
    fn j21_grant_replay_after_release_creates_no_new_grant() {
        let (file, request, observation, lease) = j21_committed_grant("released");
        let releasing = store(&file, Clock(2_000));
        let (release, release_observation) =
            lease_release("00000000-0000-4000-8000-000000003002", 2, 1, lease.as_str());
        let released =
            prepare_lease_release_authority(&releasing, &release_observation, &release).unwrap();
        assert!(matches!(
            released.message,
            ProtocolMessage::LeaseReleased(_)
        ));
        let before = releasing.load().state.unwrap();
        assert_eq!(before.lease_state, LeaseState::None);
        let later = store(&file, Clock(3_000));
        let replay = prepare_lease_request_authority(&later, &observation, &request).unwrap();
        assert_eq!(
            j21_reject(&replay).map(|r| r.0),
            Some(WitnessMutationOutcomeCode::RetiredStale)
        );
        let after = later.load().state.unwrap();
        assert_eq!(after, before);
        assert_eq!(
            after.current_term,
            Term(1),
            "no new term, no implicit grant"
        );
        let _ = fs::remove_file(file);
    }

    #[test]
    fn j21_grant_replay_with_another_holder_never_changes_that_lease() {
        let (file, request, observation, _lease) = j21_committed_grant("other-holder");
        let later = store(&file, Clock(20_000));
        let mut state = later.load().state.unwrap();
        state.current_term = Term(2);
        state.active_lease_id = Some(LeaseId::new("lease-b"));
        state.holder_node_id = Some(NodeId::new("node-b"));
        state.lease_deadline_monotonic_ms = Some(29_000);
        later.save(&state).unwrap();
        let before = later.load().state.unwrap();
        let replay = prepare_lease_request_authority(&later, &observation, &request).unwrap();
        assert_eq!(
            j21_reject(&replay).map(|r| r.0),
            Some(WitnessMutationOutcomeCode::RetiredStale)
        );
        let after = later.load().state.unwrap();
        assert_eq!(after, before);
        assert_eq!(after.holder_node_id, Some(NodeId::new("node-b")));
        assert_eq!(after.current_term, Term(2));
        let _ = fs::remove_file(file);
    }

    #[test]
    fn j21_grant_request_id_reused_with_another_payload_is_a_conflict() {
        let (file, _request, _observation, _lease) = j21_committed_grant("conflict");
        let later = store(&file, Clock(2_000));
        let before = later.load().state.unwrap();
        let (other, other_observation) =
            lease_request("00000000-0000-4000-8000-000000003001", 1, 5, 10_000);
        let replay = prepare_lease_request_authority(&later, &other_observation, &other).unwrap();
        assert_eq!(
            j21_reject(&replay).map(|r| r.0),
            Some(WitnessMutationOutcomeCode::Conflict)
        );
        assert_eq!(later.load().state.unwrap(), before);
        let _ = fs::remove_file(file);
    }

    #[test]
    fn j21_grant_replay_unknown_rollback_and_inconsistent_states_stay_fail_closed() {
        let (file, request, observation, _lease) = j21_committed_grant("unknown");
        let later = store(&file, Clock(5_000));
        let mut state = later.load().state.unwrap();
        state.lease_state = LeaseState::Unknown;
        later.save(&state).unwrap();
        assert!(matches!(
            prepare_lease_request_authority(&later, &observation, &request),
            Err(WitnessAuthorityError::UnknownLease)
        ));
        let _ = fs::remove_file(file);

        let (file, request, observation, _lease) = j21_committed_grant("rollback");
        let later = store(&file, Clock(12_000));
        expire_lease_if_needed(&later).unwrap();
        let mut state = later.load().state.unwrap();
        state.current_term = Term(0);
        later.save(&state).unwrap();
        assert!(matches!(
            prepare_lease_request_authority(&later, &observation, &request),
            Err(WitnessAuthorityError::AuthorityInvariant(_))
        ));
        let _ = fs::remove_file(file);

        for (name, holder, lease_override, term) in [
            ("holder", "node-b", None, 1),
            ("same-term-other-lease", "node-a", Some("lease-9"), 1),
            ("later-term-same-lease", "node-a", None, 2),
        ] {
            let (file, request, observation, lease) = j21_committed_grant(name);
            let later = store(&file, Clock(5_000));
            let mut state = later.load().state.unwrap();
            state.current_term = Term(term);
            state.holder_node_id = Some(NodeId::new(holder));
            state.active_lease_id = Some(match lease_override {
                Some(other) => LeaseId::new(other),
                None => lease.clone(),
            });
            later.save(&state).unwrap();
            let before = later.load().state.unwrap();
            assert!(matches!(
                prepare_lease_request_authority(&later, &observation, &request),
                Err(WitnessAuthorityError::AuthorityInvariant(_))
            ));
            assert_eq!(later.load().state.unwrap(), before);
            let _ = fs::remove_file(file);
        }
    }

    #[test]
    fn j21_grant_replay_with_missing_record_or_state_never_grants() {
        let (file, request, observation, _lease) = j21_committed_grant("record-missing");
        let later = store(&file, Clock(12_000));
        expire_lease_if_needed(&later).unwrap();
        let mut state = later.load().state.unwrap();
        state.journal.clear();
        later.save(&state).unwrap();
        let before = later.load().state.unwrap();
        let replay = prepare_lease_request_authority(&later, &observation, &request).unwrap();
        assert_eq!(
            j21_reject(&replay).map(|r| r.0),
            Some(WitnessMutationOutcomeCode::RetiredStale)
        );
        assert_eq!(later.load().state.unwrap(), before);
        let _ = fs::remove_file(&file);

        let (file, request, observation, _lease) = j21_committed_grant("state-missing");
        fs::remove_file(&file).unwrap();
        assert!(
            prepare_lease_request_authority(&store(&file, Clock(5_000)), &observation, &request)
                .is_err()
        );
        assert!(!file.exists());

        let (file, request, observation, _lease) = j21_committed_grant("state-corrupt");
        fs::write(&file, b"not a witness state").unwrap();
        assert!(
            prepare_lease_request_authority(&store(&file, Clock(5_000)), &observation, &request)
                .is_err()
        );
        assert_eq!(fs::read(&file).unwrap(), b"not a witness state");
        let _ = fs::remove_file(file);
    }

    #[test]
    fn j21_grant_replay_is_deterministic_across_restarts() {
        let (file, request, observation, _lease) = j21_committed_grant("restart");
        expire_lease_if_needed(&store(&file, Clock(11_000))).unwrap();
        let first =
            prepare_lease_request_authority(&store(&file, Clock(12_000)), &observation, &request)
                .unwrap();
        let second =
            prepare_lease_request_authority(&store(&file, Clock(90_000)), &observation, &request)
                .unwrap();
        assert_eq!(first.message, second.message);
        let _ = fs::remove_file(file);
    }

    #[test]
    fn renewal_rejects_wrong_identity_and_none_without_mutating_authority() {
        let active_file = path("stage5-identity");
        let active_store = store(&active_file, Clock(1_000));
        active_store.save(&active()).unwrap();
        let (request, observation) =
            lease_renew("00000000-0000-4000-8000-000000000014", 1, 6, "lease-1");
        let prepared =
            prepare_lease_renew_authority(&active_store, &observation, &request).unwrap();
        assert!(matches!(prepared.message, ProtocolMessage::LeaseReject(_)));
        let persisted = active_store.load().state.unwrap();
        assert_eq!(persisted.current_term, Term(7));
        assert_eq!(persisted.active_lease_id, Some(LeaseId::new("lease-1")));
        assert_eq!(persisted.generation_watermarks.get("node-a"), Some(&1));
        let _ = fs::remove_file(active_file);

        let none_file = path("stage5-none");
        let none_store = store(&none_file, Clock(1_000));
        none_store
            .save(&WitnessPersistentState::new(
                ClusterId::new("cluster"),
                BootId::new("boot-a"),
            ))
            .unwrap();
        let (request, observation) =
            lease_renew("00000000-0000-4000-8000-000000000015", 1, 0, "lease-1");
        let prepared = prepare_lease_renew_authority(&none_store, &observation, &request).unwrap();
        assert!(matches!(prepared.message, ProtocolMessage::LeaseReject(_)));
        assert_eq!(
            none_store
                .load()
                .state
                .unwrap()
                .generation_watermarks
                .get("node-a"),
            Some(&1)
        );
        let _ = fs::remove_file(none_file);
    }

    #[test]
    fn deterministic_reject_is_committed_and_retry_is_duplicate() {
        let file = path("stage4-reject");
        let store = store(&file, Clock(1_000));
        let mut state =
            WitnessPersistentState::new(ClusterId::new("cluster"), BootId::new("boot-a"));
        state.current_term = Term(7);
        store.save(&state).unwrap();
        let (request, observation) =
            lease_request("00000000-0000-4000-8000-000000000002", 1, 6, 10_000);
        let prepared = prepare_lease_request_authority(&store, &observation, &request).unwrap();
        assert!(matches!(prepared.message, ProtocolMessage::LeaseReject(_)));
        let persisted = store.load().state.unwrap();
        assert_eq!(persisted.current_term, Term(7));
        assert_eq!(persisted.generation_watermarks.get("node-a"), Some(&1));

        let (retry, retry_observation) =
            lease_request("00000000-0000-4000-8000-000000000002", 1, 6, 10_000);
        let duplicate =
            prepare_lease_request_authority(&store, &retry_observation, &retry).unwrap();
        assert!(matches!(duplicate.message, ProtocolMessage::LeaseReject(_)));
        assert_eq!(store.load().state.unwrap().current_term, Term(7));
        let _ = fs::remove_file(file);
    }

    #[test]
    fn journal_outcomes_are_returned_as_typed_rejects_without_mutation() {
        let retired_file = path("stage9-retired-outcome");
        let retired_store = store(&retired_file, FailedClock);
        let mut retired_state =
            WitnessPersistentState::new(ClusterId::new("cluster"), BootId::new("boot-a"));
        retired_state
            .generation_watermarks
            .insert("node-a".to_string(), 1);
        retired_store.save(&retired_state).unwrap();
        let (retired_request, retired_observation) =
            lease_request("00000000-0000-4000-8000-000000000030", 1, 0, 10_000);
        let retired =
            prepare_lease_request_authority(&retired_store, &retired_observation, &retired_request)
                .unwrap();
        let ProtocolMessage::LeaseReject(retired_payload) = retired.message else {
            panic!("expected RetiredStale reject");
        };
        assert_eq!(
            retired_payload.code,
            WitnessMutationOutcomeCode::RetiredStale
        );
        assert_eq!(retired_store.load().state.unwrap(), retired_state);
        let _ = fs::remove_file(retired_file);

        let conflict_file = path("stage9-conflict-outcome");
        let conflict_store = store(&conflict_file, FailedClock);
        conflict_store.save(&active()).unwrap();
        let (original, original_observation) =
            lease_request("00000000-0000-4000-8000-000000000031", 1, 7, 10_000);
        prepare_lease_request_authority(&conflict_store, &original_observation, &original).unwrap();
        let (mut conflicting, mut conflicting_observation) =
            lease_request("00000000-0000-4000-8000-000000000031", 1, 7, 10_000);
        if let ProtocolMessage::LeaseRequest(payload) = &mut conflicting.message {
            payload.priority = 101;
        }
        if let WitnessRequestObservation::LeaseRequest { payload, .. } =
            &mut conflicting_observation
        {
            payload.priority = 101;
        }
        let before_conflict = conflict_store.load().state.unwrap();
        let conflict = prepare_lease_request_authority(
            &conflict_store,
            &conflicting_observation,
            &conflicting,
        )
        .unwrap();
        let ProtocolMessage::LeaseReject(conflict_payload) = conflict.message else {
            panic!("expected Conflict reject");
        };
        assert_eq!(conflict_payload.code, WitnessMutationOutcomeCode::Conflict);
        assert_eq!(conflict_store.load().state.unwrap(), before_conflict);
        let _ = fs::remove_file(conflict_file);

        let gap_file = path("stage9-generation-gap-outcome");
        let gap_store = store(&gap_file, FailedClock);
        let mut gap_state =
            WitnessPersistentState::new(ClusterId::new("cluster"), BootId::new("boot-a"));
        gap_state
            .generation_watermarks
            .insert("node-a".to_string(), 1);
        gap_store.save(&gap_state).unwrap();
        let (gap_request, gap_observation) =
            lease_request("00000000-0000-4000-8000-000000000032", 3, 0, 10_000);
        let gap =
            prepare_lease_request_authority(&gap_store, &gap_observation, &gap_request).unwrap();
        let ProtocolMessage::LeaseReject(gap_payload) = gap.message else {
            panic!("expected GenerationGap reject");
        };
        assert_eq!(gap_payload.code, WitnessMutationOutcomeCode::GenerationGap);
        assert_eq!(gap_store.load().state.unwrap(), gap_state);
        let _ = fs::remove_file(gap_file);
    }

    #[test]
    fn active_lease_rejects_without_preemption_even_for_higher_priority() {
        let file = path("stage4-active");
        let store = store(&file, Clock(1_000));
        store.save(&active()).unwrap();
        let (mut request, mut observation) =
            lease_request("00000000-0000-4000-8000-000000000004", 1, 7, 10_000);
        if let WitnessRequestObservation::LeaseRequest { payload, .. } = &mut observation {
            payload.priority = i32::MAX;
        }
        if let ProtocolMessage::LeaseRequest(payload) = &mut request.message {
            payload.priority = i32::MAX;
        }
        let result = prepare_lease_request_authority(&store, &observation, &request).unwrap();
        assert!(matches!(result.message, ProtocolMessage::LeaseReject(_)));
        let persisted = store.load().state.unwrap();
        assert_eq!(persisted.current_term, Term(7));
        assert_eq!(persisted.active_lease_id, Some(LeaseId::new("lease-1")));
        assert_eq!(persisted.generation_watermarks.get("node-a"), Some(&1));
        let _ = fs::remove_file(file);
    }

    #[test]
    fn duplicate_grant_reconstructs_remaining_without_extending_deadline() {
        let file = path("stage4-duplicate-grant");
        let store = store(&file, Clock(1_000));
        let mut state =
            WitnessPersistentState::new(ClusterId::new("cluster"), BootId::new("boot-a"));
        state.current_term = Term(7);
        store.save(&state).unwrap();
        let (request, observation) =
            lease_request("00000000-0000-4000-8000-000000000005", 1, 7, 10_000);
        let first = prepare_lease_request_authority(&store, &observation, &request).unwrap();
        let first_grant = match first.message {
            ProtocolMessage::LeaseGrant(grant) => grant,
            _ => panic!("expected grant"),
        };
        let duplicate = prepare_lease_request_authority(&store, &observation, &request).unwrap();
        let duplicate_grant = match duplicate.message {
            ProtocolMessage::LeaseGrant(grant) => grant,
            _ => panic!("expected duplicate grant"),
        };
        assert_eq!(duplicate_grant.lease_id, first_grant.lease_id);
        assert_eq!(duplicate_grant.term, first_grant.term);
        assert_eq!(duplicate_grant.lease_remaining_ms, DurationMs(10_000));
        assert_eq!(store.load().state.unwrap().current_term, Term(8));

        let _ = fs::remove_file(file);
    }

    #[test]
    fn term_exhaustion_and_deadline_overflow_do_not_commit() {
        let exhaustion_file = path("stage4-term-exhaustion");
        let exhaustion_store = store(&exhaustion_file, Clock(1_000));
        let mut exhaustion =
            WitnessPersistentState::new(ClusterId::new("cluster"), BootId::new("boot-a"));
        exhaustion.current_term = Term(u64::MAX);
        exhaustion_store.save(&exhaustion).unwrap();
        let (request, observation) =
            lease_request("00000000-0000-4000-8000-000000000006", 1, u64::MAX, 10_000);
        let result = prepare_lease_request_authority(&exhaustion_store, &observation, &request);
        let result = result.unwrap();
        assert!(matches!(result.message, ProtocolMessage::LeaseReject(_)));
        assert_eq!(
            exhaustion_store.load().state.unwrap().current_term,
            Term(u64::MAX)
        );
        let _ = fs::remove_file(exhaustion_file);

        let overflow_file = path("stage4-deadline-overflow");
        let overflow_store = store(&overflow_file, Clock(u64::MAX));
        let mut state =
            WitnessPersistentState::new(ClusterId::new("cluster"), BootId::new("boot-a"));
        state.current_term = Term(7);
        overflow_store.save(&state).unwrap();
        let (request, observation) =
            lease_request("00000000-0000-4000-8000-000000000007", 1, 7, 10_000);
        assert!(matches!(
            prepare_lease_request_authority(&overflow_store, &observation, &request),
            Err(WitnessAuthorityError::DeadlineOverflow)
        ));
        let persisted = overflow_store.load().state.unwrap();
        assert_eq!(persisted.current_term, Term(7));
        assert!(persisted.journal.is_empty());
        assert!(persisted.generation_watermarks.is_empty());
        let _ = fs::remove_file(overflow_file);
    }

    #[test]
    fn unknown_lease_does_not_consume_generation() {
        let file = path("stage4-unknown");
        let store = store(&file, Clock(1_000));
        let state = WitnessPersistentState {
            lease_state: LeaseState::Unknown,
            ..WitnessPersistentState::new(ClusterId::new("cluster"), BootId::new("boot-a"))
        };
        store.save(&state).unwrap();
        let (request, observation) =
            lease_request("00000000-0000-4000-8000-000000000003", 1, 0, 10_000);
        assert!(matches!(
            prepare_lease_request_authority(&store, &observation, &request),
            Err(WitnessAuthorityError::UnknownLease)
        ));
        let persisted = store.load().state.unwrap();
        assert!(persisted.journal.is_empty());
        assert!(persisted.generation_watermarks.is_empty());
        let _ = fs::remove_file(file);
    }

    fn is_uuid_v4(value: &str) -> bool {
        let bytes = value.as_bytes();
        bytes.len() == 36
            && [8, 13, 18, 23]
                .into_iter()
                .all(|index| bytes[index] == b'-')
            && bytes.iter().enumerate().all(|(index, byte)| {
                [8, 13, 18, 23].contains(&index)
                    || byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
            })
            && bytes[14] == b'4'
            && matches!(bytes[19], b'8'..=b'9' | b'a'..=b'b')
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn disconnected_connection() -> WitnessConnection {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let connection =
            TcpConnection::from_stream(client, Duration::from_secs(2), Duration::from_secs(2))
                .unwrap();
        #[repr(C)]
        struct Linger {
            onoff: i32,
            linger: i32,
        }
        unsafe extern "C" {
            fn setsockopt(
                socket: i32,
                level: i32,
                option: i32,
                value: *const std::ffi::c_void,
                value_len: u32,
            ) -> i32;
        }
        let linger = Linger {
            onoff: 1,
            linger: 0,
        };
        #[cfg(target_os = "macos")]
        let (level, option) = (0xffff, 0x0080);
        #[cfg(target_os = "linux")]
        let (level, option) = (1, 13);
        let result = unsafe {
            setsockopt(
                server.as_raw_fd(),
                level,
                option,
                (&linger as *const Linger).cast(),
                std::mem::size_of::<Linger>() as u32,
            )
        };
        assert_eq!(result, 0);
        drop(server);
        WitnessConnection::new(
            NodeId::new("witness"),
            NodeId::new("node-a"),
            ClusterId::new("cluster"),
            SessionId::new("session-a"),
            connection,
        )
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn response_send_failure_does_not_rollback_durable_grant() {
        let file = path("stage4-send-failure");
        let store = store(&file, Clock(1_000));
        store
            .save(&WitnessPersistentState::new(
                ClusterId::new("cluster"),
                BootId::new("boot-a"),
            ))
            .unwrap();
        let (request, observation) =
            lease_request("00000000-0000-4000-8000-000000000008", 1, 0, 10_000);
        let prepared = prepare_lease_request_authority(&store, &observation, &request).unwrap();
        let mut connection = disconnected_connection();
        let mut process = ProcessSession::from_session_id(SessionId::new("session-w"));
        let result = send_prepared_lease_response(
            &mut connection,
            &mut process,
            prepared,
            &crate::protocol::CborSerializer,
            &MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32])),
        );
        assert!(result.is_err());
        let persisted = store.load().state.unwrap();
        assert_eq!(persisted.current_term, Term(1));
        assert_eq!(persisted.lease_state, LeaseState::Active);
        assert_eq!(persisted.journal.len(), 1);
        assert_eq!(persisted.generation_watermarks.get("node-a"), Some(&1));
        let _ = fs::remove_file(file);
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn response_send_failure_does_not_rollback_durable_renewal() {
        let file = path("stage5-send-failure");
        let store = store(&file, Clock(5_000));
        store.save(&active()).unwrap();
        let (request, observation) =
            lease_renew("00000000-0000-4000-8000-000000000016", 1, 7, "lease-1");
        let prepared = prepare_lease_renew_authority(&store, &observation, &request).unwrap();
        let mut connection = disconnected_connection();
        let mut process = ProcessSession::from_session_id(SessionId::new("session-w"));
        let result = send_prepared_lease_response(
            &mut connection,
            &mut process,
            prepared,
            &crate::protocol::CborSerializer,
            &MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32])),
        );
        assert!(result.is_err());
        let persisted = store.load().state.unwrap();
        assert_eq!(persisted.current_term, Term(7));
        assert_eq!(persisted.lease_deadline_monotonic_ms, Some(15_000));
        assert_eq!(persisted.generation_watermarks.get("node-a"), Some(&1));
        assert!(matches!(
            persisted.journal[0].result,
            CommittedSemanticResult::LeaseRenewed(_)
        ));
        let _ = fs::remove_file(file);
    }
}
