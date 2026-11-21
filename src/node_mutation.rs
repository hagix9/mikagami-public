//! Durable Node-local identity for mutating Witness requests.

use crate::fencing::{
    ClearanceRefusal, ConfirmedBy, ContinuityContext, FencingClearance, FencingIncident,
    FencingState, FencingTransition, IncidentBinding, IncidentId, IncidentOpening, IncidentRef,
    UnknownReason,
};
use crate::protocol::{
    ClusterId, DurationMs, LeaseId, LeaseReleasePayload, LeaseRenewPayload, LeaseRequestPayload,
    NodeId, ProtocolMessage, RequestId, Term,
};
use crate::recovery::{
    self, CommitResult, ExpectedOldToken, Inspection, LoadedSnapshot, StoreKind,
};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::cell::Cell;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

pub const NODE_MUTATION_STATE_FORMAT_VERSION: u32 = 3;

/// Stage 13.6 native format, read-compatible only (Stage 14 §20). It is never
/// written: every save emits `NODE_MUTATION_STATE_FORMAT_VERSION`.
const NODE_MUTATION_STATE_FORMAT_VERSION_V2: u32 = 2;

static NODE_MUTATION_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum DurableWitnessMutation {
    LeaseRequest {
        observed_term: Term,
        priority: i32,
        requested_ttl: DurationMs,
    },
    LeaseRenew {
        term: Term,
        lease_id: LeaseId,
    },
    LeaseRelease {
        term: Term,
        lease_id: LeaseId,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutstandingWitnessMutation {
    pub request_id: RequestId,
    pub mutation_generation: u64,
    pub mutation: DurableWitnessMutation,
}

impl OutstandingWitnessMutation {
    pub fn kind(&self) -> MutationKind {
        self.mutation.kind()
    }

    pub fn to_protocol_message(&self) -> ProtocolMessage {
        match &self.mutation {
            DurableWitnessMutation::LeaseRequest {
                observed_term,
                priority,
                requested_ttl,
            } => ProtocolMessage::LeaseRequest(LeaseRequestPayload {
                mutation_generation: self.mutation_generation,
                observed_term: *observed_term,
                priority: *priority,
                requested_ttl: *requested_ttl,
            }),
            DurableWitnessMutation::LeaseRenew { term, lease_id } => {
                ProtocolMessage::LeaseRenew(LeaseRenewPayload {
                    mutation_generation: self.mutation_generation,
                    term: *term,
                    lease_id: lease_id.clone(),
                })
            }
            DurableWitnessMutation::LeaseRelease {
                term,
                lease_id,
                reason,
            } => ProtocolMessage::LeaseRelease(LeaseReleasePayload {
                mutation_generation: self.mutation_generation,
                term: *term,
                lease_id: lease_id.clone(),
                reason: reason.clone(),
            }),
        }
    }

    fn validate(&self) -> Result<(), NodeMutationError> {
        if !is_canonical_uuid_v4(self.request_id.as_str()) {
            return Err(NodeMutationError::Invariant(
                "outstanding request_id is not a canonical UUIDv4",
            ));
        }
        if self.mutation_generation == 0 {
            return Err(NodeMutationError::Invariant(
                "outstanding mutation_generation must be greater than zero",
            ));
        }
        self.mutation.validate()
    }
}

impl DurableWitnessMutation {
    fn kind(&self) -> MutationKind {
        match self {
            Self::LeaseRequest { .. } => MutationKind::LeaseRequest,
            Self::LeaseRenew { .. } => MutationKind::LeaseRenew,
            Self::LeaseRelease { .. } => MutationKind::LeaseRelease,
        }
    }

    fn validate(&self) -> Result<(), NodeMutationError> {
        match self {
            Self::LeaseRequest { requested_ttl, .. } if requested_ttl.0 != 10_000 => {
                Err(NodeMutationError::Invariant(
                    "LEASE_REQUEST requested_ttl must be 10000 milliseconds",
                ))
            }
            Self::LeaseRequest { .. } => Ok(()),
            Self::LeaseRenew { lease_id, .. } => validate_lease_id(lease_id),
            Self::LeaseRelease { lease_id, .. } => validate_lease_id(lease_id),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationKind {
    LeaseRequest,
    LeaseRenew,
    LeaseRelease,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalMutationDisposition {
    AcceptedSuccess,
    DeterministicReject,
    RetiredStale,
}

/// Crash-stable responsibility for releasing exactly one lease epoch after
/// this node crossed the protected-resource boundary.  This is metadata, not
/// a second executable mutation slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseObligation {
    pub term: Term,
    pub lease_id: LeaseId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeMutationPersistentState {
    pub state_format_version: u32,
    pub cluster_id: ClusterId,
    pub node_id: NodeId,
    pub initialization_id: String,
    pub highest_started_mutation_generation: u64,
    pub outstanding_mutation: Option<OutstandingWitnessMutation>,
    pub release_obligation: Option<ReleaseObligation>,
    pub highest_fencing_incident_seq: u64,
    pub fencing_incident: Option<FencingIncident>,
}

impl NodeMutationPersistentState {
    fn validate(&self, cluster: &ClusterId, node: &NodeId) -> Result<(), NodeMutationError> {
        if self.state_format_version != NODE_MUTATION_STATE_FORMAT_VERSION {
            return Err(NodeMutationError::UnsupportedVersion(
                self.state_format_version,
            ));
        }
        if self.cluster_id.as_str().trim().is_empty() {
            return Err(NodeMutationError::Invariant("cluster_id must not be empty"));
        }
        if &self.cluster_id != cluster {
            return Err(NodeMutationError::IdentityMismatch("cluster_id"));
        }
        if self.node_id.as_str().trim().is_empty() {
            return Err(NodeMutationError::Invariant("node_id must not be empty"));
        }
        if &self.node_id != node {
            return Err(NodeMutationError::IdentityMismatch("node_id"));
        }
        if !is_canonical_uuid_v4(&self.initialization_id) {
            return Err(NodeMutationError::Invariant(
                "initialization_id is not a canonical UUIDv4",
            ));
        }
        if let Some(outstanding) = &self.outstanding_mutation {
            outstanding.validate()?;
            if outstanding.mutation_generation != self.highest_started_mutation_generation {
                return Err(NodeMutationError::Invariant(
                    "outstanding generation must equal highest started generation",
                ));
            }
        }
        if let Some(obligation) = &self.release_obligation {
            if obligation.term.0 == 0 {
                return Err(NodeMutationError::Invariant(
                    "release obligation term must be greater than zero",
                ));
            }
            validate_lease_id(&obligation.lease_id)?;
        }
        match (&self.release_obligation, &self.outstanding_mutation) {
            (Some(_), Some(outstanding)) if outstanding.kind() == MutationKind::LeaseRequest => {
                return Err(NodeMutationError::Invariant(
                    "release obligation cannot coexist with LeaseRequest",
                ));
            }
            (None, Some(outstanding))
                if matches!(
                    outstanding.kind(),
                    MutationKind::LeaseRenew | MutationKind::LeaseRelease
                ) =>
            {
                return Err(NodeMutationError::Invariant(
                    "LeaseRenew/LeaseRelease requires a release obligation",
                ));
            }
            (Some(obligation), Some(outstanding)) => match &outstanding.mutation {
                DurableWitnessMutation::LeaseRenew { term, lease_id }
                | DurableWitnessMutation::LeaseRelease { term, lease_id, .. }
                    if *term != obligation.term || lease_id != &obligation.lease_id =>
                {
                    return Err(NodeMutationError::Invariant(
                        "outstanding mutation does not match release obligation",
                    ));
                }
                _ => {}
            },
            _ => {}
        }
        if let Some(incident) = &self.fencing_incident {
            if self.highest_fencing_incident_seq == 0 {
                return Err(NodeMutationError::Invariant(
                    "fencing incident requires highest_fencing_incident_seq >= 1",
                ));
            }
            if incident.incident_seq != self.highest_fencing_incident_seq {
                return Err(NodeMutationError::Invariant(
                    "fencing incident_seq must equal highest_fencing_incident_seq",
                ));
            }
            validate_fencing_incident(incident, node)?;
            // Stage 14 §19.2: an incident coexists only with O=None and either
            // M=None or the in-flight LeaseRequest (C10).
            if self.release_obligation.is_some() {
                return Err(NodeMutationError::Invariant(
                    "fencing incident cannot coexist with a release obligation",
                ));
            }
            if matches!(
                self.outstanding_mutation
                    .as_ref()
                    .map(OutstandingWitnessMutation::kind),
                Some(MutationKind::LeaseRenew | MutationKind::LeaseRelease)
            ) {
                return Err(NodeMutationError::Invariant(
                    "fencing incident cannot coexist with LeaseRenew/LeaseRelease",
                ));
            }
        }
        Ok(())
    }
}

/// Stage 14 §19.2 incident validation. Structural only: it establishes that
/// the durable record is well formed and grants nothing.
fn validate_fencing_incident(
    incident: &FencingIncident,
    node: &NodeId,
) -> Result<(), NodeMutationError> {
    if !is_canonical_uuid_v4(incident.incident_id.as_str()) {
        return Err(NodeMutationError::Invariant(
            "fencing incident_id is not a canonical UUIDv4",
        ));
    }
    if incident.target_node_id.as_str().trim().is_empty() {
        return Err(NodeMutationError::Invariant(
            "fencing target_node_id must not be empty",
        ));
    }
    if &incident.target_node_id == node {
        return Err(NodeMutationError::Invariant(
            "fencing target_node_id must differ from node_id",
        ));
    }
    let session = incident.observer_session_id.as_str();
    if session.is_empty()
        || !session
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(NodeMutationError::Invariant(
            "fencing observer_session_id must be non-empty lowercase hex",
        ));
    }
    if incident.observer_loss_generation == 0 {
        return Err(NodeMutationError::Invariant(
            "fencing observer_loss_generation must be greater than zero",
        ));
    }
    let high_water = incident.attempt_token_high_water;
    match &incident.state {
        FencingState::Requested { attempt_token }
        | FencingState::Verifying { attempt_token, .. } => {
            if *attempt_token == 0 || *attempt_token != high_water {
                return Err(NodeMutationError::Invariant(
                    "requested/verifying attempt_token must equal a high-water >= 1",
                ));
            }
        }
        // Backend tokens are issued from 1 (§12.2, §13.2 T2/T3), so a
        // recorded backend token of 0 names no request.
        FencingState::Failed { attempt_token }
        | FencingState::Confirmed(ConfirmedBy::Backend { attempt_token }) => {
            if *attempt_token == 0 || *attempt_token > high_water {
                return Err(NodeMutationError::Invariant(
                    "failed/confirmed(backend) attempt_token must be within the high-water",
                ));
            }
        }
        FencingState::Unknown(UnknownReason::NotAttempted {}) => {
            if high_water != 0 {
                return Err(NodeMutationError::Invariant(
                    "unknown(not-attempted) requires attempt_token_high_water == 0",
                ));
            }
        }
        FencingState::Unknown(UnknownReason::VerifyInconclusive { .. }) => {
            if high_water == 0 {
                return Err(NodeMutationError::Invariant(
                    "unknown(verify-inconclusive) requires attempt_token_high_water >= 1",
                ));
            }
        }
        FencingState::Confirmed(ConfirmedBy::Operator { attestation_id }) => {
            if !is_canonical_uuid_v4(attestation_id.as_str()) {
                return Err(NodeMutationError::Invariant(
                    "confirmed(operator) attestation_id is not a canonical UUIDv4",
                ));
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeMutationError {
    StateMissing,
    AlreadyExists,
    Io(String),
    Parse(String),
    Path(String),
    Invariant(&'static str),
    IdentityMismatch(&'static str),
    UnsupportedVersion(u32),
    OutstandingExists,
    GenerationExhausted,
    RequestIdGeneration,
    CompletionMismatch(&'static str),
    MutexPoisoned,
    RecoveryRequired(String),
    /// Stage 14 §12-§13: an incident write does not match the durable
    /// incident, or no incident can be opened now. Nothing was written.
    FencingIncident(&'static str),
    /// Stage 14 §24 G: the current durable incident cannot mint a clearance.
    FencingClearanceRefused(ClearanceRefusal),
}

impl fmt::Display for NodeMutationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StateMissing => write!(f, "Node mutation state is missing"),
            Self::AlreadyExists => write!(f, "Node mutation state already exists"),
            Self::Io(error) => write!(f, "Node mutation state I/O failed: {error}"),
            Self::Parse(error) => write!(f, "Node mutation state parse failed: {error}"),
            Self::Path(error) => write!(f, "Node mutation state path rejected: {error}"),
            Self::Invariant(error) => write!(f, "Node mutation state invariant failed: {error}"),
            Self::IdentityMismatch(field) => {
                write!(f, "Node mutation state identity mismatch: {field}")
            }
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported Node mutation state version: {version}")
            }
            Self::OutstandingExists => write!(f, "a Witness mutation is already outstanding"),
            Self::GenerationExhausted => write!(f, "Node mutation generation is exhausted"),
            Self::RequestIdGeneration => write!(f, "request_id generation failed"),
            Self::CompletionMismatch(field) => {
                write!(f, "terminal completion does not match {field}")
            }
            Self::MutexPoisoned => write!(f, "Node mutation lock is poisoned"),
            Self::RecoveryRequired(reason) => {
                write!(f, "Node mutation recovery required: {reason}")
            }
            Self::FencingIncident(reason) => write!(f, "fencing incident write refused: {reason}"),
            Self::FencingClearanceRefused(refusal) => {
                write!(f, "fencing clearance refused: {refusal:?}")
            }
        }
    }
}

impl std::error::Error for NodeMutationError {}

/// What the result of the plain ARM (`arm_release_obligation`) allows the
/// Bootstrap Admission hand-off to do next (contract K-4, guard BG-12).
///
/// Only `Committed` lets the caller restore the lease authority and promote;
/// every other value is a refusal the caller returns without touching a
/// resource. The mapping lives here, as a pure function, so that it can be
/// exercised on every host; the Linux runtime has to route the ARM result
/// through it and may continue only on `Committed`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ArmGate {
    /// The ARM committed: O is armed durably.
    Committed,
    /// The write did not commit (I/O): the old image stands, nothing was armed.
    NotCommitted(String),
    /// The old image did not match: nothing was written.
    Rejected(String),
    /// Anything else, including an uncertain persistence outcome.
    RecoveryBlocked(String),
}

/// Map an ARM result to its gate. Fail-closed by construction: a result is
/// `Committed` only for `Ok`, and an error variant that is not named here is
/// `RecoveryBlocked`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn plain_arm_gate<T>(result: Result<T, NodeMutationError>) -> ArmGate {
    match result {
        Ok(_) => ArmGate::Committed,
        Err(NodeMutationError::Io(reason)) => ArmGate::NotCommitted(reason),
        Err(error @ (NodeMutationError::OutstandingExists | NodeMutationError::Invariant(_))) => {
            ArmGate::Rejected(error.to_string())
        }
        Err(error) => ArmGate::RecoveryBlocked(error.to_string()),
    }
}

/// Stage 14 §24 G / F-01: the incident inside a Node image that
/// `NodeMutationStore` has just loaded and validated under its mutation guard.
/// It is the only input `FencingClearance::mint` accepts. Only
/// `NodeMutationStore::mint_fencing_clearance` constructs it, it borrows that
/// load, and no operation returns it, so it cannot be synthesized from
/// serialized or copied `FencingIncident` values and cannot outlive the
/// durable read it proves. No derives.
///
/// L-01: it also borrows the held Node mutation guard, so that guard cannot
/// be released while the proof exists — no incident writer can interleave
/// between the validated load and the completed clearance mint.
pub struct DurableIncident<'a> {
    incident: &'a FencingIncident,
    _guard: &'a MutexGuard<'static, ()>,
}

impl<'a> DurableIncident<'a> {
    pub fn incident(&self) -> &'a FencingIncident {
        self.incident
    }
}

pub struct NodeMutationStore {
    path: PathBuf,
    configured_cluster: ClusterId,
    configured_node: NodeId,
    #[cfg(test)]
    lease_renew_begin_calls: Cell<u64>,
    /// J22: the `n`th `save_locked` from now (1 = the next one) fails before anything is written.
    #[cfg(test)]
    fail_nth_save: Cell<u32>,
}

impl NodeMutationStore {
    pub fn new(
        path: impl Into<PathBuf>,
        configured_cluster: ClusterId,
        configured_node: NodeId,
    ) -> Self {
        let input = path.into();
        let resolved = recovery::resolve_store_path(&input)
            .map(|value| value.canonical_io_path().to_path_buf())
            .unwrap_or(input);
        Self {
            path: resolved,
            configured_cluster,
            configured_node,
            #[cfg(test)]
            lease_renew_begin_calls: Cell::new(0),
            #[cfg(test)]
            fail_nth_save: Cell::new(0),
        }
    }

    pub fn load_existing(&self) -> Result<NodeMutationPersistentState, NodeMutationError> {
        Ok(self.load_existing_snapshot()?.parsed_state)
    }

    fn load_existing_snapshot(
        &self,
    ) -> Result<LoadedSnapshot<NodeMutationPersistentState>, NodeMutationError> {
        if recovery::is_uncertain(&self.path) {
            return Err(NodeMutationError::RecoveryRequired(
                "persistence outcome is uncertain".into(),
            ));
        }
        match recovery::inspect(
            &self.path,
            StoreKind::Node,
            self.configured_cluster.as_str(),
            self.configured_node.as_str(),
        ) {
            Inspection::Absent => {}
            Inspection::Active(_) => {
                return Err(NodeMutationError::RecoveryRequired(
                    "active recovery metadata".into(),
                ));
            }
            Inspection::Invalid(reason) => return Err(NodeMutationError::RecoveryRequired(reason)),
        }
        let loaded = read_state(
            &self.path,
            self.configured_cluster.as_str(),
            self.configured_node.as_str(),
        )?;
        loaded
            .parsed_state
            .validate(&self.configured_cluster, &self.configured_node)?;
        Ok(loaded)
    }

    pub fn initialize_new(&self) -> Result<NodeMutationPersistentState, NodeMutationError> {
        let _guard = mutation_guard()?;
        reject_unsafe_final(&self.path)?;
        if self.path.exists() {
            return Err(NodeMutationError::AlreadyExists);
        }
        let state = NodeMutationPersistentState {
            state_format_version: NODE_MUTATION_STATE_FORMAT_VERSION,
            cluster_id: self.configured_cluster.clone(),
            node_id: self.configured_node.clone(),
            initialization_id: generate_uuid().ok_or(NodeMutationError::RequestIdGeneration)?,
            highest_started_mutation_generation: 0,
            outstanding_mutation: None,
            release_obligation: None,
            highest_fencing_incident_seq: 0,
            fencing_incident: None,
        };
        state.validate(&self.configured_cluster, &self.configured_node)?;
        self.install_new(&state)?;
        Ok(state)
    }

    pub fn outstanding(&self) -> Result<Option<OutstandingWitnessMutation>, NodeMutationError> {
        Ok(self.load_existing()?.outstanding_mutation)
    }

    pub fn release_obligation(&self) -> Result<Option<ReleaseObligation>, NodeMutationError> {
        Ok(self.load_existing()?.release_obligation)
    }

    /// Durable ARM linearization.  The caller may cross the first protected
    /// resource boundary only after this returns successfully.
    pub fn arm_release_obligation(
        &self,
        term: Term,
        lease_id: LeaseId,
    ) -> Result<ReleaseObligation, NodeMutationError> {
        let _guard = mutation_guard()?;
        // Phase 1-J24 TEST-ONLY (feature `j24-fault-injection`): report the ARM write as failed
        // before the store is touched (the "Release stopped before it was sent" case).
        #[cfg(feature = "j24-fault-injection")]
        if crate::j24_fault_injection::fire("arm-release-obligation") {
            return Err(NodeMutationError::Io(
                "J24 test-only fault injection: the release obligation was not written".to_string(),
            ));
        }
        let loaded = self.load_existing_snapshot()?;
        let mut state = loaded.parsed_state.clone();
        if state.outstanding_mutation.is_some() {
            return Err(NodeMutationError::OutstandingExists);
        }
        if state.release_obligation.is_some() {
            return Err(NodeMutationError::Invariant(
                "release obligation is already armed",
            ));
        }
        let obligation = ReleaseObligation { term, lease_id };
        state.release_obligation = Some(obligation.clone());
        self.save_locked(&state, &loaded)?;
        Ok(obligation)
    }

    /// Complete an owned LeaseRelease and clear its obligation in one
    /// canonical document transaction.
    pub fn complete_owned_release(
        &self,
        request_id: &RequestId,
        mutation_generation: u64,
        term: Term,
        lease_id: &LeaseId,
    ) -> Result<(), NodeMutationError> {
        let _guard = mutation_guard()?;
        let loaded = self.load_existing_snapshot()?;
        let mut state = loaded.parsed_state.clone();
        let obligation = state
            .release_obligation
            .as_ref()
            .ok_or(NodeMutationError::CompletionMismatch("release obligation"))?;
        if obligation.term != term || &obligation.lease_id != lease_id {
            return Err(NodeMutationError::CompletionMismatch(
                "release obligation identity",
            ));
        }
        let outstanding =
            state
                .outstanding_mutation
                .as_ref()
                .ok_or(NodeMutationError::CompletionMismatch(
                    "outstanding mutation",
                ))?;
        if &outstanding.request_id != request_id
            || outstanding.mutation_generation != mutation_generation
            || !matches!(&outstanding.mutation,
                DurableWitnessMutation::LeaseRelease { term: current_term, lease_id: current_id, .. }
                    if *current_term == term && current_id == lease_id)
        {
            return Err(NodeMutationError::CompletionMismatch(
                "owned release mutation identity",
            ));
        }
        state.outstanding_mutation = None;
        state.release_obligation = None;
        self.save_locked(&state, &loaded)
    }

    /// Amendment C (C-a(1), C-m', AC-2 / AC-6): settle an owned LeaseRelease
    /// that the Witness rejected as not releasable (startup A-4d or the
    /// in-process C-a(1) settle). It is not release proof; see
    /// `settle_owned_release_without_proof`.
    pub fn settle_rejected_owned_release(
        &self,
        request_id: &RequestId,
        mutation_generation: u64,
        term: Term,
        lease_id: &LeaseId,
    ) -> Result<(), NodeMutationError> {
        self.settle_owned_release_without_proof(request_id, mutation_generation, term, lease_id)
    }

    /// C-l (CL-10, AC-10): settle an owned LeaseRelease whose exact replay
    /// was answered RetiredStale at startup and whose lease a new GET_TERM
    /// view shows superseded. It is not release proof; see
    /// `settle_owned_release_without_proof`.
    pub fn settle_retired_owned_release(
        &self,
        request_id: &RequestId,
        mutation_generation: u64,
        term: Term,
        lease_id: &LeaseId,
    ) -> Result<(), NodeMutationError> {
        self.settle_owned_release_without_proof(request_id, mutation_generation, term, lease_id)
    }

    /// The one replacement behind every exceptional clear of an owned
    /// Release (A-4d, C-a(1), C-l). Inside one mutation guard and one loaded
    /// image it checks that no fencing incident is present, the exact `O`
    /// and the exact `M` (request id, generation, term and lease), then
    /// removes exactly `M` and `O` with one save. Unlike
    /// `complete_owned_release` (the accepted-release path) it refuses an
    /// open incident. Anything else is refused and nothing is written.
    fn settle_owned_release_without_proof(
        &self,
        request_id: &RequestId,
        mutation_generation: u64,
        term: Term,
        lease_id: &LeaseId,
    ) -> Result<(), NodeMutationError> {
        let _guard = mutation_guard()?;
        let loaded = self.load_existing_snapshot()?;
        let mut state = loaded.parsed_state.clone();
        if state.fencing_incident.is_some() {
            return Err(NodeMutationError::FencingIncident(
                "a fencing incident is present",
            ));
        }
        let obligation = state
            .release_obligation
            .as_ref()
            .ok_or(NodeMutationError::CompletionMismatch("release obligation"))?;
        if obligation.term != term || &obligation.lease_id != lease_id {
            return Err(NodeMutationError::CompletionMismatch(
                "release obligation identity",
            ));
        }
        let outstanding =
            state
                .outstanding_mutation
                .as_ref()
                .ok_or(NodeMutationError::CompletionMismatch(
                    "outstanding mutation",
                ))?;
        if &outstanding.request_id != request_id
            || outstanding.mutation_generation != mutation_generation
            || !matches!(&outstanding.mutation,
                DurableWitnessMutation::LeaseRelease { term: current_term, lease_id: current_id, .. }
                    if *current_term == term && current_id == lease_id)
        {
            return Err(NodeMutationError::CompletionMismatch(
                "owned release mutation identity",
            ));
        }
        state.outstanding_mutation = None;
        state.release_obligation = None;
        self.save_locked(&state, &loaded)
    }

    /// Startup Obligation Reconciliation (contract A-4, SOR-2 (ii)/(iii)):
    /// clear a release obligation whose lease the Witness has shown can no
    /// longer be held. One canonical single-candidate replacement, like
    /// `complete_owned_release`. Only the exact `O = (term, lease_id)` with no
    /// outstanding mutation and no fencing incident is cleared; anything else
    /// is refused and nothing is written. The caller has already established
    /// the Witness-side condition and trusted ZeroResource.
    pub fn clear_superseded_obligation(
        &self,
        term: Term,
        lease_id: &LeaseId,
    ) -> Result<(), NodeMutationError> {
        let _guard = mutation_guard()?;
        let loaded = self.load_existing_snapshot()?;
        let mut state = loaded.parsed_state.clone();
        let obligation = state
            .release_obligation
            .as_ref()
            .ok_or(NodeMutationError::CompletionMismatch("release obligation"))?;
        if obligation.term != term || &obligation.lease_id != lease_id {
            return Err(NodeMutationError::CompletionMismatch(
                "release obligation identity",
            ));
        }
        if state.outstanding_mutation.is_some() {
            return Err(NodeMutationError::OutstandingExists);
        }
        if state.fencing_incident.is_some() {
            return Err(NodeMutationError::FencingIncident(
                "a fencing incident is present",
            ));
        }
        state.release_obligation = None;
        self.save_locked(&state, &loaded)
    }

    /// Stage 14 §12.4 / §13.2 T1-T2: open the one fencing incident with the
    /// next never-reused sequence number and a fresh UUIDv4. Only from local
    /// Safe (no incident, `O = None`, `M = None`); a stale incident must be
    /// retired first. One candidate; M, O, generation, and identity unchanged.
    pub fn open_fencing_incident(
        &self,
        opening: IncidentOpening,
    ) -> Result<FencingIncident, NodeMutationError> {
        let _guard = mutation_guard()?;
        let loaded = self.load_existing_snapshot()?;
        let mut state = loaded.parsed_state.clone();
        if state.fencing_incident.is_some() {
            return Err(NodeMutationError::FencingIncident(
                "an incident is already open",
            ));
        }
        if state.release_obligation.is_some() {
            return Err(NodeMutationError::FencingIncident(
                "a release obligation is armed",
            ));
        }
        if state.outstanding_mutation.is_some() {
            return Err(NodeMutationError::OutstandingExists);
        }
        let incident_seq = state.highest_fencing_incident_seq.checked_add(1).ok_or(
            NodeMutationError::FencingIncident("incident sequence exhausted"),
        )?;
        let incident_id =
            IncidentId::generated(generate_uuid().ok_or(NodeMutationError::RequestIdGeneration)?);
        let incident = FencingIncident::open(incident_seq, incident_id, opening);
        state.highest_fencing_incident_seq = incident_seq;
        state.fencing_incident = Some(incident.clone());
        self.save_locked(&state, &loaded)?;
        Ok(incident)
    }

    /// Stage 14 §13.2 T3-T8: persist one legal transition, only while the
    /// durable incident still equals the transition's source exactly (a stale
    /// or replayed transition writes nothing). One candidate; M, O,
    /// generation, the sequence high-water, and identity unchanged.
    pub fn apply_fencing_transition(
        &self,
        transition: FencingTransition,
    ) -> Result<FencingIncident, NodeMutationError> {
        let _guard = mutation_guard()?;
        let loaded = self.load_existing_snapshot()?;
        let mut state = loaded.parsed_state.clone();
        if state.fencing_incident.as_ref() != Some(transition.from()) {
            return Err(NodeMutationError::FencingIncident(
                "the durable incident differs from the transition source",
            ));
        }
        state.fencing_incident = Some(transition.to().clone());
        self.save_locked(&state, &loaded)?;
        Ok(transition.to().clone())
    }

    /// Stage 14 §12.5 / §13.2 T9: plain retirement of the exact incident
    /// `(incident_seq, incident_id)`. The sequence high-water, M, O,
    /// generation, and identity are unchanged. A post-grant abort must use
    /// the §25.1 transaction (`retire_incident_and_arm_cleanup_obligation`)
    /// instead.
    pub fn retire_fencing_incident(&self, incident: &IncidentRef) -> Result<(), NodeMutationError> {
        let _guard = mutation_guard()?;
        let loaded = self.load_existing_snapshot()?;
        let mut state = loaded.parsed_state.clone();
        if state
            .fencing_incident
            .as_ref()
            .map(FencingIncident::incident_ref)
            .as_ref()
            != Some(incident)
        {
            return Err(NodeMutationError::FencingIncident(
                "the durable incident differs from the retirement target",
            ));
        }
        state.fencing_incident = None;
        self.save_locked(&state, &loaded)
    }

    /// Stage 14 §24 G / §26 (F-01): mint the `FencingClearance` for the exact
    /// current durable incident `(incident_seq, incident_id)`. The incident is
    /// the store's own validated load under the mutation guard, never a
    /// caller-supplied value; it must be `CONFIRMED` and pass R1-R4 against the
    /// fresh `Authorized` view term. Reads only; writes nothing.
    pub fn mint_fencing_clearance(
        &self,
        incident: &IncidentRef,
        context: &ContinuityContext<'_>,
        view_term: Term,
    ) -> Result<FencingClearance, NodeMutationError> {
        let guard = mutation_guard()?;
        let loaded = self.load_existing_snapshot()?;
        let Some(current) = loaded
            .parsed_state
            .fencing_incident
            .as_ref()
            .filter(|current| &current.incident_ref() == incident)
        else {
            return Err(NodeMutationError::FencingIncident(
                "the durable incident differs from the clearance target",
            ));
        };
        let durable = DurableIncident {
            incident: current,
            _guard: &guard,
        };
        FencingClearance::mint(&durable, context, view_term)
            .map_err(NodeMutationError::FencingClearanceRefused)
    }

    /// Stage 14 §25: the success ARM of a fencing-backed promotion. It
    /// replaces `arm_release_obligation` only in `arm_and_promote`. One
    /// whole-document candidate, validated against the old image under the
    /// mutation guard:
    ///
    /// - old: the exact current incident `(seq, id)` of the clearance, state
    ///   `CONFIRMED`, the clearance episode (`observer_session_id`,
    ///   `observer_loss_generation`) and anchor, `anchor_term + 1 == term`,
    ///   target = the configured peer, `O = None`, `M = None`;
    /// - new: incident absent and `O = (term, lease_id)`; M, generation,
    ///   `highest_fencing_incident_seq`, and identity unchanged.
    ///
    /// Linearization happens only at `ConfirmedCommitted`: no image ever
    /// holds a consumed incident without O, or a reusable `CONFIRMED` with O.
    /// Any old-image mismatch writes nothing (`FencingIncident`).
    pub fn arm_consuming_fencing(
        &self,
        term: Term,
        lease_id: LeaseId,
        clearance: &FencingClearance,
        configured_peer: &NodeId,
    ) -> Result<ReleaseObligation, NodeMutationError> {
        let _guard = mutation_guard()?;
        let loaded = self.load_existing_snapshot()?;
        let mut state = loaded.parsed_state.clone();
        let Some(incident) = state.fencing_incident.as_ref() else {
            return Err(NodeMutationError::FencingIncident(
                "no durable incident to consume",
            ));
        };
        if &incident.incident_ref() != clearance.incident() {
            return Err(NodeMutationError::FencingIncident(
                "the durable incident differs from the clearance",
            ));
        }
        if !matches!(incident.state, FencingState::Confirmed(_)) {
            return Err(NodeMutationError::FencingIncident(
                "the durable incident is not CONFIRMED",
            ));
        }
        if &incident.observer_session_id != clearance.observer_session_id()
            || incident.observer_loss_generation != clearance.observer_loss_generation()
        {
            return Err(NodeMutationError::FencingIncident(
                "the durable episode differs from the clearance",
            ));
        }
        if incident.anchor_term != clearance.anchor_term()
            || incident.anchor_term.0.checked_add(1) != Some(term.0)
        {
            return Err(NodeMutationError::FencingIncident(
                "the granted term is not the clearance anchor_term + 1",
            ));
        }
        if &incident.target_node_id != configured_peer
            || clearance.target_node_id() != configured_peer
        {
            return Err(NodeMutationError::FencingIncident(
                "the incident target is not the configured peer",
            ));
        }
        if state.release_obligation.is_some() {
            return Err(NodeMutationError::FencingIncident(
                "a release obligation is already armed",
            ));
        }
        if state.outstanding_mutation.is_some() {
            return Err(NodeMutationError::FencingIncident(
                "an outstanding mutation is incompatible with ARM",
            ));
        }
        let obligation = ReleaseObligation { term, lease_id };
        state.fencing_incident = None;
        state.release_obligation = Some(obligation.clone());
        self.save_locked(&state, &loaded)?;
        Ok(obligation)
    }

    /// Stage 14 §25.1: the atomic abort-cleanup transaction, for every
    /// post-grant, pre-resource abort while an incident exists. One
    /// whole-document candidate, validated against the old image under the
    /// mutation guard:
    ///
    /// - old: the incident present with `(seq, id)`, `observer_session_id`,
    ///   and `observer_loss_generation` exactly those of `incident_ref` (the
    ///   durable binding, not the current episode), target = the configured
    ///   peer, `O = None`, `M = None`; the incident may be in any state;
    /// - new: incident absent and `O = (term, lease_id)`, the exact granted
    ///   epoch; M, generation, `highest_fencing_incident_seq`, and identity
    ///   unchanged.
    ///
    /// Retirement and arming are the same write: no image ever holds a live
    /// incident with cleanup O, or a retired incident without the required
    /// cleanup O. Any old-image mismatch writes nothing (`FencingIncident`)
    /// and never overwrites M.
    pub fn retire_incident_and_arm_cleanup_obligation(
        &self,
        term: Term,
        lease_id: LeaseId,
        incident_ref: &IncidentBinding,
        configured_peer: &NodeId,
    ) -> Result<ReleaseObligation, NodeMutationError> {
        let _guard = mutation_guard()?;
        let loaded = self.load_existing_snapshot()?;
        let mut state = loaded.parsed_state.clone();
        let Some(incident) = state.fencing_incident.as_ref() else {
            return Err(NodeMutationError::FencingIncident(
                "no durable incident to retire",
            ));
        };
        if incident.incident_ref() != incident_ref.incident {
            return Err(NodeMutationError::FencingIncident(
                "the durable incident differs from the cleanup binding",
            ));
        }
        if incident.observer_session_id != incident_ref.observer_session_id
            || incident.observer_loss_generation != incident_ref.observer_loss_generation
        {
            return Err(NodeMutationError::FencingIncident(
                "the durable episode differs from the cleanup binding",
            ));
        }
        if &incident.target_node_id != configured_peer {
            return Err(NodeMutationError::FencingIncident(
                "the incident target is not the configured peer",
            ));
        }
        if state.release_obligation.is_some() {
            return Err(NodeMutationError::FencingIncident(
                "a release obligation is already armed",
            ));
        }
        if state.outstanding_mutation.is_some() {
            return Err(NodeMutationError::FencingIncident(
                "an outstanding mutation is incompatible with the cleanup",
            ));
        }
        let obligation = ReleaseObligation { term, lease_id };
        state.fencing_incident = None;
        state.release_obligation = Some(obligation.clone());
        self.save_locked(&state, &loaded)?;
        Ok(obligation)
    }

    pub fn begin_lease_request(
        &self,
        observed_term: Term,
        priority: i32,
        requested_ttl: DurationMs,
    ) -> Result<OutstandingWitnessMutation, NodeMutationError> {
        self.begin(DurableWitnessMutation::LeaseRequest {
            observed_term,
            priority,
            requested_ttl,
        })
    }

    pub fn begin_lease_renew(
        &self,
        term: Term,
        lease_id: LeaseId,
    ) -> Result<OutstandingWitnessMutation, NodeMutationError> {
        #[cfg(test)]
        self.lease_renew_begin_calls
            .set(self.lease_renew_begin_calls.get() + 1);
        self.begin(DurableWitnessMutation::LeaseRenew { term, lease_id })
    }

    /// J22: make the `n`th durable write from now fail before anything is written (a
    /// pre-commit persistence fault at one chosen step of a multi-write sequence). Used by the
    /// Linux-only runtime tests.
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn fail_nth_save_for_test(&self, n: u32) {
        self.fail_nth_save.set(n);
    }

    /// J22: the canonical path of this store (to corrupt it in a Linux-only runtime test).
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn path_for_test(&self) -> PathBuf {
        self.path.clone()
    }

    #[cfg(test)]
    pub(crate) fn lease_renew_begin_calls_for_test(&self) -> u64 {
        self.lease_renew_begin_calls.get()
    }

    #[cfg(test)]
    pub(crate) fn begin_lease_renew_for_test(
        &self,
        term: Term,
        lease_id: LeaseId,
    ) -> Result<OutstandingWitnessMutation, NodeMutationError> {
        if self.release_obligation()?.is_none() {
            self.arm_release_obligation(term, lease_id.clone())?;
        }
        self.begin_lease_renew(term, lease_id)
    }

    pub(crate) fn begin_lease_release(
        &self,
        _origin: &crate::node_lease_authority::LeaseReleaseOrigin,
        term: Term,
        lease_id: LeaseId,
        reason: String,
    ) -> Result<OutstandingWitnessMutation, NodeMutationError> {
        self.begin(DurableWitnessMutation::LeaseRelease {
            term,
            lease_id,
            reason,
        })
    }

    #[cfg(test)]
    pub(crate) fn begin_lease_release_for_test(
        &self,
        term: Term,
        lease_id: LeaseId,
        reason: String,
    ) -> Result<OutstandingWitnessMutation, NodeMutationError> {
        if self.release_obligation()?.is_none() {
            self.arm_release_obligation(term, lease_id.clone())?;
        }
        let origin = crate::node_lease_authority::test_lease_release_origin();
        self.begin_lease_release(&origin, term, lease_id, reason)
    }

    pub fn complete(
        &self,
        request_id: &RequestId,
        mutation_generation: u64,
        mutation_kind: MutationKind,
        _disposition: TerminalMutationDisposition,
    ) -> Result<(), NodeMutationError> {
        let _guard = mutation_guard()?;
        let loaded = self.load_existing_snapshot()?;
        let mut state = loaded.parsed_state.clone();
        let Some(outstanding) = state.outstanding_mutation.as_ref() else {
            return Err(NodeMutationError::CompletionMismatch(
                "outstanding mutation",
            ));
        };
        if &outstanding.request_id != request_id {
            return Err(NodeMutationError::CompletionMismatch("request_id"));
        }
        if outstanding.mutation_generation != mutation_generation {
            return Err(NodeMutationError::CompletionMismatch("generation"));
        }
        if outstanding.kind() != mutation_kind {
            return Err(NodeMutationError::CompletionMismatch("mutation kind"));
        }
        state.outstanding_mutation = None;
        self.save_locked(&state, &loaded)
    }

    fn begin(
        &self,
        mutation: DurableWitnessMutation,
    ) -> Result<OutstandingWitnessMutation, NodeMutationError> {
        let _guard = mutation_guard()?;
        mutation.validate()?;
        let loaded = self.load_existing_snapshot()?;
        let mut state = loaded.parsed_state.clone();
        if state.outstanding_mutation.is_some() {
            return Err(NodeMutationError::OutstandingExists);
        }
        let generation = state
            .highest_started_mutation_generation
            .checked_add(1)
            .ok_or(NodeMutationError::GenerationExhausted)?;
        let outstanding = OutstandingWitnessMutation {
            request_id: RequestId::new(
                generate_uuid().ok_or(NodeMutationError::RequestIdGeneration)?,
            ),
            mutation_generation: generation,
            mutation,
        };
        outstanding.validate()?;
        state.highest_started_mutation_generation = generation;
        state.outstanding_mutation = Some(outstanding.clone());
        self.save_locked(&state, &loaded)?;
        Ok(outstanding)
    }

    fn save_locked(
        &self,
        state: &NodeMutationPersistentState,
        loaded: &LoadedSnapshot<NodeMutationPersistentState>,
    ) -> Result<(), NodeMutationError> {
        #[cfg(test)]
        {
            let n = self.fail_nth_save.get();
            if n > 0 {
                self.fail_nth_save.set(n - 1);
                if n == 1 {
                    return Err(NodeMutationError::Io(
                        "J22 injected persistence fault".to_string(),
                    ));
                }
            }
        }
        state.validate(&self.configured_cluster, &self.configured_node)?;
        // Stage 14 §12.2/§12.3: the incident sequence high-water never
        // decreases, so a sequence number can never be reused.
        if state.highest_fencing_incident_seq < loaded.parsed_state.highest_fencing_incident_seq {
            return Err(NodeMutationError::Invariant(
                "highest_fencing_incident_seq must never decrease",
            ));
        }
        save_state(&self.path, state, &loaded.expected_old)
    }

    fn install_new(&self, state: &NodeMutationPersistentState) -> Result<(), NodeMutationError> {
        let bytes =
            toml::to_string(state).map_err(|error| NodeMutationError::Parse(error.to_string()))?;
        match recovery::persist(
            &self.path,
            StoreKind::Node,
            self.configured_cluster.as_str(),
            self.configured_node.as_str(),
            "initialization",
            &[],
            bytes.as_bytes(),
            true,
        )
        .map_err(|e| NodeMutationError::Io(e.0))?
        {
            CommitResult::ConfirmedCommitted => Ok(()),
            CommitResult::PreCommitFailure(reason) => Err(NodeMutationError::Io(reason)),
            CommitResult::CommitOutcomeUnknown(reason)
            | CommitResult::CleanupOutcomeUnknown(reason) => {
                Err(NodeMutationError::RecoveryRequired(reason))
            }
        }
    }
}

fn mutation_guard() -> Result<MutexGuard<'static, ()>, NodeMutationError> {
    NODE_MUTATION_LOCK
        .lock()
        .map_err(|_| NodeMutationError::MutexPoisoned)
}

fn read_state(
    path: &Path,
    cluster: &str,
    node: &str,
) -> Result<LoadedSnapshot<NodeMutationPersistentState>, NodeMutationError> {
    let loaded = crate::recovery::read_snapshot_with_token(path, StoreKind::Node, cluster, node)
        .map_err(|error| NodeMutationError::RecoveryRequired(error.0))?
        .ok_or(NodeMutationError::StateMissing)?;
    let content = String::from_utf8(loaded.parsed_state)
        .map_err(|error| NodeMutationError::Parse(error.to_string()))?;
    Ok(LoadedSnapshot {
        parsed_state: parse_state(&content)?,
        expected_old: loaded.expected_old,
    })
}

/// Parse one canonical Node document (Stage 14 §19.2, §20).
///
/// - v3 is parsed strictly; `highest_fencing_incident_seq` is mandatory
///   (missing is not `None` in v3).
/// - native v2 is read as `highest_fencing_incident_seq = 0` and no incident;
///   a v2 document carrying either Stage 14 field is rejected. The result is
///   the v3 in-memory state, so every later save emits v3.
/// - every other version fails closed.
///
/// Parsing reconstructs durable data only; it grants no authority.
fn parse_state(content: &str) -> Result<NodeMutationPersistentState, NodeMutationError> {
    /// Reads only the version and whether the Stage 14 keys are present;
    /// every other key is left to the strict typed parse below. This is a
    /// presence probe, not a second incident slot.
    #[derive(Deserialize)]
    struct FormatProbe {
        state_format_version: u32,
        #[serde(rename = "highest_fencing_incident_seq")]
        high_water_key: Option<serde::de::IgnoredAny>,
        #[serde(rename = "fencing_incident")]
        incident_key: Option<serde::de::IgnoredAny>,
    }

    let parse_error = |error: toml::de::Error| NodeMutationError::Parse(error.to_string());
    let probe: FormatProbe = toml::from_str(content).map_err(parse_error)?;
    let has_stage14_fields = probe.high_water_key.is_some() || probe.incident_key.is_some();
    match probe.state_format_version {
        NODE_MUTATION_STATE_FORMAT_VERSION => toml::from_str(content).map_err(parse_error),
        NODE_MUTATION_STATE_FORMAT_VERSION_V2 => {
            if has_stage14_fields {
                return Err(NodeMutationError::Invariant(
                    "Node v2 state must not contain Stage 14 fencing fields",
                ));
            }
            // A root-level key placed before the first table header stays in
            // the root table, and the probe proved it is absent.
            let mut state: NodeMutationPersistentState =
                toml::from_str(&format!("highest_fencing_incident_seq = 0\n{content}"))
                    .map_err(parse_error)?;
            state.state_format_version = NODE_MUTATION_STATE_FORMAT_VERSION;
            Ok(state)
        }
        other => Err(NodeMutationError::UnsupportedVersion(other)),
    }
}

fn save_state(
    path: &Path,
    state: &NodeMutationPersistentState,
    expected_old: &ExpectedOldToken,
) -> Result<(), NodeMutationError> {
    reject_unsafe_final(path)?;
    let new =
        toml::to_string(state).map_err(|error| NodeMutationError::Parse(error.to_string()))?;
    match recovery::persist_with_expected_old(
        path,
        StoreKind::Node,
        state.cluster_id.as_str(),
        state.node_id.as_str(),
        "mutation",
        expected_old,
        new.as_bytes(),
        false,
    )
    .map_err(|e| NodeMutationError::Io(e.0))?
    {
        CommitResult::ConfirmedCommitted => Ok(()),
        CommitResult::PreCommitFailure(reason) => Err(NodeMutationError::Io(reason)),
        CommitResult::CommitOutcomeUnknown(reason)
        | CommitResult::CleanupOutcomeUnknown(reason) => {
            Err(NodeMutationError::RecoveryRequired(reason))
        }
    }
}

fn reject_unsafe_final(path: &Path) -> Result<(), NodeMutationError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(NodeMutationError::Path(
            "state must not be a symlink".to_string(),
        )),
        Ok(metadata) if !metadata.file_type().is_file() => Err(NodeMutationError::Path(
            "state must be a regular file".to_string(),
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(error)),
    }
}

fn io_error(error: io::Error) -> NodeMutationError {
    NodeMutationError::Io(error.to_string())
}

fn validate_lease_id(lease_id: &LeaseId) -> Result<(), NodeMutationError> {
    if lease_id.as_str().trim().is_empty() {
        Err(NodeMutationError::Invariant("lease_id must not be empty"))
    } else {
        Ok(())
    }
}

pub(crate) fn generate_uuid() -> Option<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).ok()?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Some(format_uuid(bytes))
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

pub(crate) fn is_canonical_uuid_v4(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && [8, 13, 18, 23]
            .into_iter()
            .all(|index| bytes[index] == b'-')
        && bytes.iter().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                true
            } else {
                byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
            }
        })
        && bytes[14] == b'4'
        && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn path(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("mikagami-node-mutation-{name}-{suffix}"))
    }

    fn store(path: &Path) -> NodeMutationStore {
        NodeMutationStore::new(path, ClusterId::new("cluster"), NodeId::new("node-a"))
    }

    fn initialized(path: &Path) -> NodeMutationStore {
        let store = store(path);
        store.initialize_new().unwrap();
        store
    }

    #[test]
    fn explicit_initialization_creates_v3_and_stable_identity() {
        let file = path("init");
        let store = initialized(&file);
        let first = store.load_existing().unwrap();
        assert_eq!(first.state_format_version, 3);
        assert_eq!(first.highest_started_mutation_generation, 0);
        assert_eq!(first.outstanding_mutation, None);
        assert_eq!(first.highest_fencing_incident_seq, 0);
        assert_eq!(first.fencing_incident, None);
        let bytes = fs::read_to_string(&file).unwrap();
        assert!(bytes.contains("state_format_version = 3"));
        assert!(bytes.contains("highest_fencing_incident_seq = 0"));
        assert!(is_canonical_uuid_v4(&first.initialization_id));
        assert_eq!(store.load_existing().unwrap(), first);
        assert!(matches!(
            store.initialize_new(),
            Err(NodeMutationError::AlreadyExists)
        ));
        let _ = fs::remove_file(file);
    }

    #[test]
    fn missing_state_is_not_auto_initialized() {
        let file = path("missing");
        let store = store(&file);
        assert!(matches!(
            store.load_existing(),
            Err(NodeMutationError::StateMissing)
        ));
        assert!(!file.exists());
    }

    #[test]
    fn each_mutation_kind_starts_at_generation_one_and_reconstructs_exactly() {
        let cases = [("request", 0), ("renew", 1), ("release", 2)];
        for (name, kind) in cases {
            let file = path(name);
            let store = initialized(&file);
            let outstanding = match kind {
                0 => store
                    .begin_lease_request(Term(7), 100, DurationMs(10_000))
                    .unwrap(),
                1 => store
                    .begin_lease_renew_for_test(Term(7), LeaseId::new("lease-1"))
                    .unwrap(),
                _ => store
                    .begin_lease_release_for_test(
                        Term(7),
                        LeaseId::new("lease-1"),
                        "cleanup".to_string(),
                    )
                    .unwrap(),
            };
            assert_eq!(outstanding.mutation_generation, 1);
            match (kind, outstanding.to_protocol_message()) {
                (
                    0,
                    ProtocolMessage::LeaseRequest(LeaseRequestPayload {
                        mutation_generation: 1,
                        observed_term: Term(7),
                        priority: 100,
                        requested_ttl: DurationMs(10_000),
                    }),
                ) => {}
                (
                    1,
                    ProtocolMessage::LeaseRenew(LeaseRenewPayload {
                        mutation_generation: 1,
                        term: Term(7),
                        lease_id,
                    }),
                ) if lease_id == LeaseId::new("lease-1") => {}
                (
                    2,
                    ProtocolMessage::LeaseRelease(LeaseReleasePayload {
                        mutation_generation: 1,
                        term: Term(7),
                        lease_id,
                        reason,
                    }),
                ) if lease_id == LeaseId::new("lease-1") && reason == "cleanup" => {}
                _ => panic!("durable mutation payload was not reconstructed exactly"),
            }
            let recovered = store.load_existing().unwrap().outstanding_mutation.unwrap();
            assert_eq!(recovered, outstanding);
            let _ = fs::remove_file(file);
        }
    }

    #[test]
    fn one_outstanding_blocks_all_other_kinds() {
        let file = path("one-outstanding");
        let store = initialized(&file);
        store
            .begin_lease_renew_for_test(Term(7), LeaseId::new("lease-1"))
            .unwrap();
        assert!(matches!(
            store.begin_lease_release_for_test(
                Term(7),
                LeaseId::new("lease-1"),
                "cleanup".to_string()
            ),
            Err(NodeMutationError::OutstandingExists)
        ));
        let _ = fs::remove_file(file);
    }

    #[test]
    fn stage13_6_v2_obligation_matrix_and_legacy_fail_closed() {
        let file = path("stage13-6-v2");
        let mutation_store = initialized(&file);
        let obligation = mutation_store
            .arm_release_obligation(Term(7), LeaseId::new("lease-1"))
            .unwrap();
        assert_eq!(obligation.term, Term(7));
        assert_eq!(
            mutation_store.release_obligation().unwrap(),
            Some(obligation)
        );
        assert!(matches!(
            mutation_store.begin_lease_request(Term(7), 100, DurationMs(10_000)),
            Err(NodeMutationError::Invariant(_)) | Err(NodeMutationError::OutstandingExists)
        ));
        let renew = mutation_store
            .begin_lease_renew(Term(7), LeaseId::new("lease-1"))
            .unwrap();
        assert!(matches!(
            renew.mutation,
            DurableWitnessMutation::LeaseRenew { .. }
        ));
        let _ = fs::remove_file(file);

        let legacy = path("stage13-6-v1");
        fs::write(
            &legacy,
            "state_format_version = 1\ncluster_id = \"cluster\"\nnode_id = \"node-a\"\ninitialization_id = \"00000000-0000-4000-8000-000000000001\"\nhighest_started_mutation_generation = 0\n",
        )
        .unwrap();
        assert!(matches!(
            store(&legacy).load_existing(),
            Err(NodeMutationError::UnsupportedVersion(1))
        ));
        let _ = fs::remove_file(legacy);
    }

    #[test]
    fn stage13_6_owned_release_success_clears_mutation_and_obligation_atomically() {
        let file = path("stage13-6-clear");
        let store = initialized(&file);
        store
            .arm_release_obligation(Term(9), LeaseId::new("lease-9"))
            .unwrap();
        let release = store
            .begin_lease_release_for_test(
                Term(9),
                LeaseId::new("lease-9"),
                "verified cleanup".into(),
            )
            .unwrap();
        store
            .complete_owned_release(
                &release.request_id,
                release.mutation_generation,
                Term(9),
                &LeaseId::new("lease-9"),
            )
            .unwrap();
        let state = store.load_existing().unwrap();
        assert!(state.outstanding_mutation.is_none());
        assert!(state.release_obligation.is_none());
        assert_eq!(state.highest_started_mutation_generation, 1);
        let _ = fs::remove_file(file);
    }

    #[test]
    fn completion_requires_exact_identity_and_preserves_generation() {
        let file = path("completion");
        let store = initialized(&file);
        let outstanding = store
            .begin_lease_request(Term(7), 100, DurationMs(10_000))
            .unwrap();
        assert!(matches!(
            store.complete(
                &RequestId::new("00000000-0000-4000-8000-000000000001"),
                1,
                MutationKind::LeaseRequest,
                TerminalMutationDisposition::AcceptedSuccess,
            ),
            Err(NodeMutationError::CompletionMismatch("request_id"))
        ));
        store
            .complete(
                &outstanding.request_id,
                outstanding.mutation_generation,
                outstanding.kind(),
                TerminalMutationDisposition::RetiredStale,
            )
            .unwrap();
        let state = store.load_existing().unwrap();
        assert_eq!(state.highest_started_mutation_generation, 1);
        assert_eq!(state.outstanding_mutation, None);
        let next = store
            .begin_lease_release_for_test(Term(7), LeaseId::new("lease-1"), "cleanup".to_string())
            .unwrap();
        assert_eq!(next.mutation_generation, 2);
        let _ = fs::remove_file(file);
    }

    #[test]
    fn max_generation_is_legal_but_does_not_wrap() {
        let file = path("max");
        let initialized_store = initialized(&file);
        let mut state = initialized_store.load_existing().unwrap();
        state.highest_started_mutation_generation = u64::MAX - 1;
        initialized_store.save_for_test(&state).unwrap();
        let max = initialized_store
            .begin_lease_request(Term(7), 100, DurationMs(10_000))
            .unwrap();
        assert_eq!(max.mutation_generation, u64::MAX);
        initialized_store
            .complete(
                &max.request_id,
                u64::MAX,
                max.kind(),
                TerminalMutationDisposition::AcceptedSuccess,
            )
            .unwrap();
        assert!(matches!(
            initialized_store.begin_lease_request(Term(7), 100, DurationMs(10_000)),
            Err(NodeMutationError::GenerationExhausted)
        ));
        let _ = fs::remove_file(file);
    }

    #[test]
    fn ambiguous_node_commit_poisoning_blocks_second_handle() {
        let file = path("ambiguous-commit");
        let initialized_store = initialized(&file);
        let mut state = initialized_store.load_existing().unwrap();
        state.highest_started_mutation_generation = 1;
        crate::recovery::inject_fault_once(crate::recovery::FaultPoint::CanonicalParentFsync);
        assert!(matches!(
            initialized_store.save_for_test(&state),
            Err(NodeMutationError::RecoveryRequired(_))
        ));
        assert!(matches!(
            initialized_store.load_existing(),
            Err(NodeMutationError::RecoveryRequired(_))
        ));
        assert!(matches!(
            store(&file).load_existing(),
            Err(NodeMutationError::RecoveryRequired(_))
        ));
        let _ = fs::remove_file(&file);
        let _ = fs::remove_file(crate::recovery::marker_path(&file));
    }

    #[test]
    fn precanonical_node_failure_keeps_second_handle_retryable() {
        let file = path("precanonical-second-handle");
        let first = initialized(&file);
        let state = first.load_existing().unwrap();
        crate::recovery::inject_fault_once(crate::recovery::FaultPoint::CandidateTempFsync);
        assert!(matches!(
            first.save_for_test(&state),
            Err(NodeMutationError::Io(_))
        ));
        assert!(!crate::recovery::marker_path(&file).exists());
        assert_eq!(store(&file).load_existing().unwrap(), state);
        store(&file).save_for_test(&state).unwrap();
        let _ = fs::remove_file(file);
    }

    #[test]
    fn malformed_state_and_identity_mismatch_fail_closed() {
        let file = path("invalid");
        fs::write(
            &file,
            "state_format_version = 99\ncluster_id = \"cluster\"\nnode_id = \"node-a\"\ninitialization_id = \"00000000-0000-4000-8000-000000000001\"\nhighest_started_mutation_generation = 0\n",
        )
        .unwrap();
        assert!(matches!(
            store(&file).load_existing(),
            Err(NodeMutationError::UnsupportedVersion(99))
        ));
        fs::write(
            &file,
            "state_format_version = 2\ncluster_id = \"cluster\"\nnode_id = \"node-b\"\ninitialization_id = \"00000000-0000-4000-8000-000000000001\"\nhighest_started_mutation_generation = 0\n",
        )
        .unwrap();
        assert!(matches!(
            store(&file).load_existing(),
            Err(NodeMutationError::IdentityMismatch("node_id"))
        ));
        let _ = fs::remove_file(file);
    }

    #[test]
    fn concurrent_begin_operations_cannot_allocate_the_same_generation() {
        let file = path("concurrent-begin");
        let initialized_store = initialized(&file);
        drop(initialized_store);
        let barrier = Arc::new(Barrier::new(3));
        let first_barrier = Arc::clone(&barrier);
        let first_file = file.clone();
        let first = std::thread::spawn(move || {
            first_barrier.wait();
            store(&first_file).begin_lease_request(Term(7), 100, DurationMs(10_000))
        });
        let second_barrier = Arc::clone(&barrier);
        let second_file = file.clone();
        let second = std::thread::spawn(move || {
            second_barrier.wait();
            store(&second_file).begin_lease_request(Term(7), 100, DurationMs(10_000))
        });
        barrier.wait();
        let first = first.join().unwrap();
        let second = second.join().unwrap();
        assert_eq!(
            [first.is_ok(), second.is_ok()]
                .into_iter()
                .filter(|value| *value)
                .count(),
            1
        );
        assert!(matches!(
            if first.is_err() { first } else { second },
            Err(NodeMutationError::OutstandingExists)
        ));
        assert_eq!(
            store(&file)
                .load_existing()
                .unwrap()
                .highest_started_mutation_generation,
            1
        );
        let _ = fs::remove_file(file);
    }

    // ---------------------------------------------------------------------
    // Stage 14 Phase 14.1: Node v3 persistence and pure fencing types
    // (Design Revision 4 §12.2, §13.1, §19, §20, §34.5).
    // ---------------------------------------------------------------------

    use crate::fencing::{
        ActionOutcome, AttestationId, ConfirmedBy, FencingIncident, FencingState, IncidentId,
        InconclusiveKind, UnknownReason,
    };
    use crate::protocol::SessionId;

    const INCIDENT_UUID: &str = "11111111-2222-4333-8444-555555555555";
    const ATTESTATION_UUID: &str = "66666666-7777-4888-9999-aaaaaaaaaaaa";
    const V2_BASE: &str = "state_format_version = 2\ncluster_id = \"cluster\"\nnode_id = \"node-a\"\ninitialization_id = \"00000000-0000-4000-8000-000000000001\"\nhighest_started_mutation_generation = 0\n";

    fn cluster() -> ClusterId {
        ClusterId::new("cluster")
    }

    fn node() -> NodeId {
        NodeId::new("node-a")
    }

    fn incident(high_water: u64, state: FencingState) -> FencingIncident {
        FencingIncident {
            incident_seq: 7,
            incident_id: IncidentId::new(INCIDENT_UUID),
            target_node_id: NodeId::new("node-b"),
            anchor_term: Term(41),
            observer_session_id: SessionId::new("0123456789abcdef"),
            observer_loss_generation: 3,
            attempt_token_high_water: high_water,
            state,
        }
    }

    fn v3_state(fencing_incident: Option<FencingIncident>) -> NodeMutationPersistentState {
        NodeMutationPersistentState {
            state_format_version: NODE_MUTATION_STATE_FORMAT_VERSION,
            cluster_id: cluster(),
            node_id: node(),
            initialization_id: "00000000-0000-4000-8000-000000000001".into(),
            highest_started_mutation_generation: 0,
            outstanding_mutation: None,
            release_obligation: None,
            highest_fencing_incident_seq: 7,
            fencing_incident,
        }
    }

    /// Every stored state shape (§13.1, §19.1), each paired with a valid
    /// attempt-token high-water (§19.2).
    fn every_valid_state() -> Vec<(u64, FencingState)> {
        let mut states = vec![
            (0, FencingState::Unknown(UnknownReason::NotAttempted {})),
            (1, FencingState::Requested { attempt_token: 1 }),
            (3, FencingState::Failed { attempt_token: 2 }),
            (
                2,
                FencingState::Confirmed(ConfirmedBy::Backend { attempt_token: 2 }),
            ),
            (
                0,
                FencingState::Confirmed(ConfirmedBy::Operator {
                    attestation_id: AttestationId::new(ATTESTATION_UUID),
                }),
            ),
        ];
        for kind in [
            InconclusiveKind::Timeout,
            InconclusiveKind::NonzeroExit,
            InconclusiveKind::Signal,
            InconclusiveKind::SpawnFailed,
            InconclusiveKind::OutputOverflow,
            InconclusiveKind::MalformedOutput,
            InconclusiveKind::Integrity,
        ] {
            states.push((
                1,
                FencingState::Unknown(UnknownReason::VerifyInconclusive { kind }),
            ));
        }
        for action_outcome in [
            ActionOutcome::ReportedSuccess,
            ActionOutcome::ReportedFailure,
            ActionOutcome::TimedOut,
            ActionOutcome::SpawnFailed,
            ActionOutcome::Signal,
        ] {
            states.push((
                4,
                FencingState::Verifying {
                    attempt_token: 4,
                    action_outcome,
                },
            ));
        }
        states
    }

    fn invariant(state: &NodeMutationPersistentState) -> NodeMutationError {
        state
            .validate(&cluster(), &node())
            .expect_err("state must be rejected")
    }

    #[test]
    fn stage14_v3_round_trip_is_exact_and_deterministic_for_every_state() {
        for (high_water, fencing_state) in every_valid_state() {
            let state = v3_state(Some(incident(high_water, fencing_state)));
            state.validate(&cluster(), &node()).unwrap();
            let encoded = toml::to_string(&state).unwrap();
            assert_eq!(toml::to_string(&state).unwrap(), encoded);
            let decoded = parse_state(&encoded).unwrap();
            assert_eq!(decoded, state);
            assert_eq!(toml::to_string(&decoded).unwrap(), encoded);
        }
        let empty = v3_state(None);
        let encoded = toml::to_string(&empty).unwrap();
        assert_eq!(parse_state(&encoded).unwrap(), empty);
    }

    #[test]
    fn stage14_v3_document_shape_is_exact() {
        let mut state = v3_state(Some(incident(
            2,
            FencingState::Verifying {
                attempt_token: 2,
                action_outcome: ActionOutcome::TimedOut,
            },
        )));
        let expected = "state_format_version = 3\ncluster_id = \"cluster\"\nnode_id = \"node-a\"\ninitialization_id = \"00000000-0000-4000-8000-000000000001\"\nhighest_started_mutation_generation = 0\nhighest_fencing_incident_seq = 7\n\n[fencing_incident]\nincident_seq = 7\nincident_id = \"11111111-2222-4333-8444-555555555555\"\ntarget_node_id = \"node-b\"\nanchor_term = 41\nobserver_session_id = \"0123456789abcdef\"\nobserver_loss_generation = 3\nattempt_token_high_water = 2\n\n[fencing_incident.state.verifying]\nattempt_token = 2\naction_outcome = \"timed-out\"\n";
        assert_eq!(toml::to_string(&state).unwrap(), expected);

        state.fencing_incident = Some(incident(
            1,
            FencingState::Unknown(UnknownReason::VerifyInconclusive {
                kind: InconclusiveKind::NonzeroExit,
            }),
        ));
        let encoded = toml::to_string(&state).unwrap();
        assert!(encoded.contains(
            "[fencing_incident.state.unknown]\nreason = \"verify-inconclusive\"\nkind = \"nonzero-exit\"\n"
        ));
        state.fencing_incident = Some(incident(
            0,
            FencingState::Unknown(UnknownReason::NotAttempted {}),
        ));
        assert!(
            toml::to_string(&state)
                .unwrap()
                .ends_with("[fencing_incident.state.unknown]\nreason = \"not-attempted\"\n")
        );
        state.fencing_incident = Some(incident(
            0,
            FencingState::Confirmed(ConfirmedBy::Operator {
                attestation_id: AttestationId::new(ATTESTATION_UUID),
            }),
        ));
        assert!(toml::to_string(&state).unwrap().ends_with(
            "[fencing_incident.state.confirmed]\nby = \"operator\"\nattestation_id = \"66666666-7777-4888-9999-aaaaaaaaaaaa\"\n"
        ));
        state.fencing_incident = Some(incident(
            2,
            FencingState::Confirmed(ConfirmedBy::Backend { attempt_token: 2 }),
        ));
        assert!(toml::to_string(&state).unwrap().ends_with(
            "[fencing_incident.state.confirmed]\nby = \"backend\"\nattempt_token = 2\n"
        ));
    }

    #[test]
    fn stage14_native_v2_is_read_as_no_incident_and_first_write_emits_v3() {
        let file = path("v2-compat");
        fs::write(&file, V2_BASE).unwrap();
        let store = store(&file);
        let loaded = store.load_existing().unwrap();
        assert_eq!(loaded.state_format_version, 3);
        assert_eq!(loaded.highest_fencing_incident_seq, 0);
        assert_eq!(loaded.fencing_incident, None);
        assert_eq!(loaded.highest_started_mutation_generation, 0);
        assert_eq!(
            loaded.initialization_id,
            "00000000-0000-4000-8000-000000000001"
        );
        // Reading never rewrites the document.
        assert_eq!(fs::read_to_string(&file).unwrap(), V2_BASE);

        // The first write (here an ordinary Stage 13.6 mutation) emits v3.
        let outstanding = store
            .begin_lease_request(Term(7), 100, DurationMs(10_000))
            .unwrap();
        let bytes = fs::read_to_string(&file).unwrap();
        assert!(bytes.starts_with("state_format_version = 3\n"));
        assert!(bytes.contains("highest_fencing_incident_seq = 0\n"));
        assert!(!bytes.contains("fencing_incident]"));
        let reloaded = store.load_existing().unwrap();
        assert_eq!(reloaded.outstanding_mutation, Some(outstanding));
        assert_eq!(reloaded.highest_fencing_incident_seq, 0);
        assert_eq!(reloaded.fencing_incident, None);
        let _ = fs::remove_file(file);
    }

    #[test]
    fn stage14_native_v2_with_obligation_and_mutation_reads_unchanged() {
        let document = format!(
            "{V2_BASE}[outstanding_mutation]\nrequest_id = \"00000000-0000-4000-8000-000000000002\"\nmutation_generation = 0\n"
        )
        .replace(
            "highest_started_mutation_generation = 0",
            "highest_started_mutation_generation = 3",
        )
        .replace("mutation_generation = 0\n", "mutation_generation = 3\n")
            + "\n[outstanding_mutation.mutation.LeaseRelease]\nterm = 9\nlease_id = \"lease-9\"\nreason = \"cleanup\"\n\n[release_obligation]\nterm = 9\nlease_id = \"lease-9\"\n";
        let state = parse_state(&document).unwrap();
        state.validate(&cluster(), &node()).unwrap();
        assert_eq!(state.state_format_version, 3);
        assert_eq!(state.highest_started_mutation_generation, 3);
        assert_eq!(
            state.release_obligation,
            Some(ReleaseObligation {
                term: Term(9),
                lease_id: LeaseId::new("lease-9"),
            })
        );
        assert_eq!(
            state
                .outstanding_mutation
                .as_ref()
                .map(|value| value.kind()),
            Some(MutationKind::LeaseRelease)
        );
        assert_eq!(state.highest_fencing_incident_seq, 0);
        assert_eq!(state.fencing_incident, None);
    }

    #[test]
    fn stage14_native_v2_keeps_the_full_u64_generation_range() {
        let document = V2_BASE.replace(
            "highest_started_mutation_generation = 0",
            "highest_started_mutation_generation = 18446744073709551614",
        );
        let state = parse_state(&document).unwrap();
        assert_eq!(state.highest_started_mutation_generation, u64::MAX - 1);
        assert_eq!(state.state_format_version, 3);
    }

    #[test]
    fn stage14_v2_carrying_stage14_fields_fails_closed() {
        for extra in [
            "highest_fencing_incident_seq = 0\n",
            "highest_fencing_incident_seq = 1\n\n[fencing_incident]\nincident_seq = 1\n",
        ] {
            let document = format!("{V2_BASE}{extra}");
            assert!(matches!(
                parse_state(&document),
                Err(NodeMutationError::Invariant(_))
            ));
        }
    }

    #[test]
    fn stage14_unsupported_missing_and_malformed_versions_fail_closed() {
        for version in [0, 1, 4, 99] {
            let document = V2_BASE.replace(
                "state_format_version = 2",
                &format!("state_format_version = {version}"),
            );
            assert_eq!(
                parse_state(&document),
                Err(NodeMutationError::UnsupportedVersion(version))
            );
        }
        for document in [
            V2_BASE.replace("state_format_version = 2\n", ""),
            V2_BASE.replace("state_format_version = 2", "state_format_version = \"3\""),
            V2_BASE.replace("state_format_version = 2", "state_format_version = -3"),
            "not toml = = =".to_string(),
        ] {
            assert!(matches!(
                parse_state(&document),
                Err(NodeMutationError::Parse(_))
            ));
        }
        // The store path fails closed on the same input.
        let file = path("v4");
        fs::write(
            &file,
            V2_BASE.replace("state_format_version = 2", "state_format_version = 4"),
        )
        .unwrap();
        assert_eq!(
            store(&file).load_existing(),
            Err(NodeMutationError::UnsupportedVersion(4))
        );
        let _ = fs::remove_file(file);
    }

    #[test]
    fn stage14_v3_missing_high_water_is_not_absence() {
        let document = toml::to_string(&v3_state(None))
            .unwrap()
            .replace("highest_fencing_incident_seq = 7\n", "");
        assert!(!document.contains("highest_fencing_incident_seq"));
        assert!(matches!(
            parse_state(&document),
            Err(NodeMutationError::Parse(_))
        ));
    }

    #[test]
    fn stage14_unknown_fields_and_tags_fail_closed() {
        let base = toml::to_string(&v3_state(Some(incident(
            2,
            FencingState::Verifying {
                attempt_token: 2,
                action_outcome: ActionOutcome::TimedOut,
            },
        ))))
        .unwrap();
        let cases = [
            // unknown top-level field
            base.replace(
                "highest_fencing_incident_seq = 7\n",
                "highest_fencing_incident_seq = 7\nfencing_mode = \"x\"\n",
            ),
            // unknown incident field
            base.replace(
                "attempt_token_high_water = 2\n",
                "attempt_token_high_water = 2\ntarget_boot_id = \"x\"\n",
            ),
            // unknown or removed state tags
            base.replace("state.verifying]", "state.notrequired]"),
            base.replace("state.verifying]", "state.not_required]"),
            base.replace("state.verifying]", "state.fenced]"),
            // unknown action outcome
            base.replace("\"timed-out\"", "\"isolated\""),
            // unknown field inside a state variant
            base.replace(
                "action_outcome = \"timed-out\"\n",
                "action_outcome = \"timed-out\"\npoll_count = 1\n",
            ),
            // missing required incident field
            base.replace("anchor_term = 41\n", ""),
            // two states at once
            format!("{base}\n[fencing_incident.state.failed]\nattempt_token = 2\n"),
        ];
        for document in cases {
            assert!(
                matches!(parse_state(&document), Err(NodeMutationError::Parse(_))),
                "accepted: {document}"
            );
        }

        let unknown = base.replace(
            "[fencing_incident.state.verifying]\nattempt_token = 2\naction_outcome = \"timed-out\"\n",
            "[fencing_incident.state.unknown]\n",
        );
        for body in [
            "reason = \"not-attempted\"\nkind = \"timeout\"\n",
            "reason = \"verify-inconclusive\"\n",
            "reason = \"verify-inconclusive\"\nkind = \"slow\"\n",
            "reason = \"not-required\"\n",
            "kind = \"timeout\"\n",
        ] {
            let document = format!("{unknown}{body}");
            assert!(
                matches!(parse_state(&document), Err(NodeMutationError::Parse(_))),
                "accepted: {document}"
            );
        }

        let confirmed = base.replace(
            "[fencing_incident.state.verifying]\nattempt_token = 2\naction_outcome = \"timed-out\"\n",
            "[fencing_incident.state.confirmed]\n",
        );
        for body in [
            "by = \"exit-status\"\nattempt_token = 2\n",
            "by = \"backend\"\n",
            "by = \"backend\"\nattempt_token = 2\nattestation_id = \"66666666-7777-4888-9999-aaaaaaaaaaaa\"\n",
            "by = \"operator\"\n",
            "attempt_token = 2\n",
        ] {
            let document = format!("{confirmed}{body}");
            assert!(
                matches!(parse_state(&document), Err(NodeMutationError::Parse(_))),
                "accepted: {document}"
            );
        }
    }

    #[test]
    fn stage14_incident_sequence_high_water_rules() {
        // highest > 0 without an incident is valid (all past incidents closed).
        v3_state(None).validate(&cluster(), &node()).unwrap();

        let open = incident(0, FencingState::Unknown(UnknownReason::NotAttempted {}));
        let mut state = v3_state(Some(open.clone()));
        state.highest_fencing_incident_seq = 8;
        assert!(matches!(invariant(&state), NodeMutationError::Invariant(_)));
        state.highest_fencing_incident_seq = 6;
        assert!(matches!(invariant(&state), NodeMutationError::Invariant(_)));

        let mut zero = open;
        zero.incident_seq = 0;
        let mut state = v3_state(Some(zero));
        state.highest_fencing_incident_seq = 0;
        assert!(matches!(invariant(&state), NodeMutationError::Invariant(_)));
    }

    #[test]
    fn stage14_incident_high_water_never_decreases_across_a_write() {
        let file = path("high-water-decrease");
        let initialized_store = initialized(&file);
        let mut state = initialized_store.load_existing().unwrap();
        state.highest_fencing_incident_seq = 7;
        initialized_store.save_for_test(&state).unwrap();

        let loaded = initialized_store.load_existing_snapshot().unwrap();
        let before = fs::read(&file).unwrap();
        let mut lowered = loaded.parsed_state.clone();
        lowered.highest_fencing_incident_seq = 6;
        assert!(matches!(
            initialized_store.save_locked(&lowered, &loaded),
            Err(NodeMutationError::Invariant(_))
        ));
        assert_eq!(fs::read(&file).unwrap(), before);

        // Equal and increasing high-water values are accepted.
        let mut raised = loaded.parsed_state.clone();
        raised.highest_fencing_incident_seq = 8;
        initialized_store.save_locked(&raised, &loaded).unwrap();
        assert_eq!(
            initialized_store
                .load_existing()
                .unwrap()
                .highest_fencing_incident_seq,
            8
        );
        let _ = fs::remove_file(file);
    }

    #[test]
    fn stage14_incident_identity_fields_are_validated() {
        let base = incident(1, FencingState::Requested { attempt_token: 1 });
        let mutations: Vec<fn(&mut FencingIncident)> = vec![
            |value| value.incident_id = IncidentId::new("not-a-uuid"),
            |value| value.incident_id = IncidentId::new("11111111-2222-3333-8444-555555555555"),
            |value| value.incident_id = IncidentId::new("11111111-2222-4333-8444-55555555555A"),
            |value| value.target_node_id = NodeId::new(" "),
            |value| value.target_node_id = NodeId::new("node-a"),
            |value| value.observer_session_id = SessionId::new(""),
            |value| value.observer_session_id = SessionId::new("0123ABCD"),
            |value| value.observer_session_id = SessionId::new("session-a"),
            |value| value.observer_loss_generation = 0,
        ];
        for mutate in mutations {
            let mut value = base.clone();
            mutate(&mut value);
            assert!(matches!(
                invariant(&v3_state(Some(value))),
                NodeMutationError::Invariant(_)
            ));
        }
        // anchor_term is any Term.
        let mut any_term = base;
        any_term.anchor_term = Term(0);
        v3_state(Some(any_term))
            .validate(&cluster(), &node())
            .unwrap();
    }

    #[test]
    fn stage14_attempt_token_rules_are_enforced() {
        let rejected = [
            (0, FencingState::Requested { attempt_token: 0 }),
            (2, FencingState::Requested { attempt_token: 1 }),
            (
                1,
                FencingState::Verifying {
                    attempt_token: 2,
                    action_outcome: ActionOutcome::ReportedSuccess,
                },
            ),
            (2, FencingState::Failed { attempt_token: 3 }),
            (2, FencingState::Failed { attempt_token: 0 }),
            (
                1,
                FencingState::Confirmed(ConfirmedBy::Backend { attempt_token: 2 }),
            ),
            (
                0,
                FencingState::Confirmed(ConfirmedBy::Backend { attempt_token: 0 }),
            ),
            (1, FencingState::Unknown(UnknownReason::NotAttempted {})),
            (
                0,
                FencingState::Unknown(UnknownReason::VerifyInconclusive {
                    kind: InconclusiveKind::Timeout,
                }),
            ),
            (
                0,
                FencingState::Confirmed(ConfirmedBy::Operator {
                    attestation_id: AttestationId::new("attestation"),
                }),
            ),
        ];
        for (high_water, fencing_state) in rejected {
            let state = v3_state(Some(incident(high_water, fencing_state.clone())));
            assert!(
                matches!(invariant(&state), NodeMutationError::Invariant(_)),
                "accepted {fencing_state:?} with high-water {high_water}"
            );
        }
        // Earlier tokens stay valid for failed/confirmed(backend); operator
        // confirmation is valid at any high-water.
        for (high_water, fencing_state) in [
            (5, FencingState::Failed { attempt_token: 1 }),
            (
                5,
                FencingState::Confirmed(ConfirmedBy::Backend { attempt_token: 5 }),
            ),
            (
                3,
                FencingState::Confirmed(ConfirmedBy::Operator {
                    attestation_id: AttestationId::new(ATTESTATION_UUID),
                }),
            ),
        ] {
            v3_state(Some(incident(high_water, fencing_state)))
                .validate(&cluster(), &node())
                .unwrap();
        }
    }

    #[test]
    fn stage14_incident_obligation_and_mutation_coexistence() {
        let open = || Some(incident(1, FencingState::Requested { attempt_token: 1 }));
        let request = OutstandingWitnessMutation {
            request_id: RequestId::new("00000000-0000-4000-8000-000000000002"),
            mutation_generation: 1,
            mutation: DurableWitnessMutation::LeaseRequest {
                observed_term: Term(41),
                priority: 100,
                requested_ttl: DurationMs(10_000),
            },
        };
        let obligation = ReleaseObligation {
            term: Term(42),
            lease_id: LeaseId::new("lease-42"),
        };

        // C10: incident + M=LeaseRequest + O=None is valid.
        let mut state = v3_state(open());
        state.highest_started_mutation_generation = 1;
        state.outstanding_mutation = Some(request);
        state.validate(&cluster(), &node()).unwrap();

        // Incident + any O is invalid.
        let mut state = v3_state(open());
        state.release_obligation = Some(obligation.clone());
        assert!(matches!(invariant(&state), NodeMutationError::Invariant(_)));

        // Incident + M=Renew/Release (with its O) is invalid.
        for mutation in [
            DurableWitnessMutation::LeaseRenew {
                term: Term(42),
                lease_id: LeaseId::new("lease-42"),
            },
            DurableWitnessMutation::LeaseRelease {
                term: Term(42),
                lease_id: LeaseId::new("lease-42"),
                reason: "cleanup".into(),
            },
        ] {
            let mut state = v3_state(open());
            state.highest_started_mutation_generation = 1;
            state.release_obligation = Some(obligation.clone());
            state.outstanding_mutation = Some(OutstandingWitnessMutation {
                request_id: RequestId::new("00000000-0000-4000-8000-000000000003"),
                mutation_generation: 1,
                mutation,
            });
            assert!(matches!(invariant(&state), NodeMutationError::Invariant(_)));
        }

        // O without an incident stays a valid Stage 13.6 image.
        let mut state = v3_state(None);
        state.release_obligation = Some(obligation);
        state.validate(&cluster(), &node()).unwrap();
    }

    #[test]
    fn stage14_stage13_6_writes_preserve_incident_and_plain_arm_is_refused() {
        let file = path("preserve-incident");
        let initialized_store = initialized(&file);
        let mut state = initialized_store.load_existing().unwrap();
        let open = incident(
            2,
            FencingState::Verifying {
                attempt_token: 2,
                action_outcome: ActionOutcome::ReportedFailure,
            },
        );
        state.highest_fencing_incident_seq = 7;
        state.fencing_incident = Some(open.clone());
        initialized_store.save_for_test(&state).unwrap();

        // The plain Stage 13.6 ARM is invalid while an incident exists (§25):
        // validation refuses it and the durable image is unchanged.
        let before = fs::read(&file).unwrap();
        assert!(matches!(
            initialized_store.arm_release_obligation(Term(42), LeaseId::new("lease-42")),
            Err(NodeMutationError::Invariant(_))
        ));
        assert_eq!(fs::read(&file).unwrap(), before);

        // An existing M write (the C10 LeaseRequest) and its completion
        // preserve the incident and the incident high-water exactly.
        let request = initialized_store
            .begin_lease_request(Term(41), 100, DurationMs(10_000))
            .unwrap();
        let during = initialized_store.load_existing().unwrap();
        assert_eq!(during.fencing_incident.as_ref(), Some(&open));
        assert_eq!(during.highest_fencing_incident_seq, 7);
        initialized_store
            .complete(
                &request.request_id,
                request.mutation_generation,
                request.kind(),
                TerminalMutationDisposition::AcceptedSuccess,
            )
            .unwrap();
        let after = initialized_store.load_existing().unwrap();
        assert_eq!(after.fencing_incident, Some(open));
        assert_eq!(after.highest_fencing_incident_seq, 7);
        assert_eq!(after.highest_started_mutation_generation, 1);
        let _ = fs::remove_file(file);
    }

    #[test]
    fn stage14_loading_a_confirmed_incident_grants_nothing() {
        let file = path("confirmed-grants-nothing");
        let initialized_store = initialized(&file);
        let mut state = initialized_store.load_existing().unwrap();
        state.highest_fencing_incident_seq = 7;
        state.fencing_incident = Some(incident(
            0,
            FencingState::Confirmed(ConfirmedBy::Operator {
                attestation_id: AttestationId::new(ATTESTATION_UUID),
            }),
        ));
        initialized_store.save_for_test(&state).unwrap();
        let before = fs::read(&file).unwrap();
        let loaded = store(&file).load_existing().unwrap();
        assert_eq!(loaded, state);
        // Parsing reconstructs data only: no O, no M, no generation change,
        // and no write.
        assert_eq!(loaded.release_obligation, None);
        assert_eq!(loaded.outstanding_mutation, None);
        assert_eq!(loaded.highest_started_mutation_generation, 0);
        assert_eq!(store(&file).release_obligation().unwrap(), None);
        assert_eq!(store(&file).outstanding().unwrap(), None);
        assert_eq!(fs::read(&file).unwrap(), before);
        let _ = fs::remove_file(file);
    }

    /// §20: a v3 image read by the Stage 13.6 (v2) binary fails closed. This
    /// replicates the baseline v2 document schema (`deny_unknown_fields`,
    /// `state_format_version == 2`) from `HEAD:src/node_mutation.rs`.
    #[test]
    fn stage14_v2_validator_rejects_a_v3_fixture() {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        #[allow(dead_code)]
        struct BaselineV2Document {
            state_format_version: u32,
            cluster_id: ClusterId,
            node_id: NodeId,
            initialization_id: String,
            highest_started_mutation_generation: u64,
            outstanding_mutation: Option<OutstandingWitnessMutation>,
            release_obligation: Option<ReleaseObligation>,
        }
        let baseline_v2_accepts = |document: &str| {
            toml::from_str::<BaselineV2Document>(document)
                .map(|parsed| parsed.state_format_version == 2)
                .unwrap_or(false)
        };
        assert!(baseline_v2_accepts(V2_BASE));
        let empty_v3 = toml::to_string(&v3_state(None)).unwrap();
        assert!(!baseline_v2_accepts(&empty_v3));
        let without_new_fields = empty_v3.replace("highest_fencing_incident_seq = 7\n", "");
        assert!(!baseline_v2_accepts(&without_new_fields));
    }

    // ---------------------------------------------------------------------
    // Stage 14 Phase 14.4: fencing incident persistence (Design Revision 5
    // §12.3-§12.5, §13.2, §19.2, §19.3, §20, §22, §34.5).
    // ---------------------------------------------------------------------

    use crate::fencing::{
        ContinuityContext, ContinuityViolation, FencingBackend, FencingClearance,
        FencingEventOutcome, IncidentOpening, IncidentRef, WitnessEpoch,
    };

    const OBSERVER: &str = "0123456789abcdef";

    fn opening(backend: FencingBackend) -> IncidentOpening {
        IncidentOpening {
            target_node_id: NodeId::new("node-b"),
            anchor_term: Term(41),
            observer_session_id: SessionId::new(OBSERVER),
            observer_loss_generation: 3,
            backend,
        }
    }

    fn applied(outcome: FencingEventOutcome) -> FencingTransition {
        match outcome {
            FencingEventOutcome::Transition(transition) => transition,
            FencingEventOutcome::NoOp => panic!("expected a transition"),
        }
    }

    /// The whole document except the incident: M, O, the mutation generation,
    /// the incident high-water, and the enclosing identity.
    fn without_incident(state: &NodeMutationPersistentState) -> NodeMutationPersistentState {
        let mut rest = state.clone();
        rest.fencing_incident = None;
        rest
    }

    /// §12.2 / T1 / T2: open allocates the next never-reused sequence number
    /// and a fresh canonical UUIDv4, and changes nothing else.
    #[test]
    fn stage14_4_open_allocates_the_next_sequence_and_a_fresh_identity() {
        let file = path("fencing-open");
        let store = initialized(&file);
        let before = store.load_existing().unwrap();

        let first = store
            .open_fencing_incident(opening(FencingBackend::None))
            .unwrap();
        assert_eq!(first.incident_seq, 1);
        assert!(is_canonical_uuid_v4(first.incident_id.as_str()));
        assert_eq!(
            first.state,
            FencingState::Unknown(UnknownReason::NotAttempted {})
        );
        assert_eq!(first.attempt_token_high_water, 0);
        let after = store.load_existing().unwrap();
        assert_eq!(after.fencing_incident.as_ref(), Some(&first));
        assert_eq!(after.highest_fencing_incident_seq, 1);
        let mut expected_rest = without_incident(&before);
        expected_rest.highest_fencing_incident_seq = 1;
        assert_eq!(without_incident(&after), expected_rest);
        assert!(
            fs::read_to_string(&file)
                .unwrap()
                .starts_with("state_format_version = 3\n")
        );

        store
            .retire_fencing_incident(&first.incident_ref())
            .unwrap();
        let second = store
            .open_fencing_incident(opening(FencingBackend::Command))
            .unwrap();
        assert_eq!(second.incident_seq, 2);
        assert_ne!(second.incident_id, first.incident_id);
        assert_eq!(second.state, FencingState::Requested { attempt_token: 1 });
        assert_eq!(second.attempt_token_high_water, 1);
        let _ = fs::remove_file(file);
    }

    /// §12.4 / §24 B: an incident opens only from local Safe (no incident,
    /// `O = None`, `M = None`) and never wraps the sequence. Every refusal
    /// leaves the document byte-identical.
    #[test]
    fn stage14_4_open_is_refused_without_a_write_outside_local_safe() {
        let refused = |store: &NodeMutationStore, file: &Path| {
            let bytes = fs::read(file).unwrap();
            assert!(
                store
                    .open_fencing_incident(opening(FencingBackend::None))
                    .is_err()
            );
            assert_eq!(fs::read(file).unwrap(), bytes);
        };

        let file = path("fencing-open-open");
        let store = initialized(&file);
        store
            .open_fencing_incident(opening(FencingBackend::None))
            .unwrap();
        refused(&store, &file);
        let _ = fs::remove_file(file);

        let file = path("fencing-open-m");
        let store = initialized(&file);
        store
            .begin_lease_request(Term(41), 100, DurationMs(10_000))
            .unwrap();
        refused(&store, &file);
        let _ = fs::remove_file(file);

        let file = path("fencing-open-o");
        let store = initialized(&file);
        store
            .arm_release_obligation(Term(42), LeaseId::new("lease-a"))
            .unwrap();
        refused(&store, &file);
        let _ = fs::remove_file(file);

        let file = path("fencing-open-exhausted");
        let store = initialized(&file);
        let mut exhausted = store.load_existing().unwrap();
        exhausted.highest_fencing_incident_seq = u64::MAX;
        store.save_for_test(&exhausted).unwrap();
        refused(&store, &file);
        let _ = fs::remove_file(file);
    }

    /// §13.2 T3-T8 and §19.3: each transition is one candidate that preserves
    /// M (including the C10 in-flight LeaseRequest), O, the generation, the
    /// sequence high-water, and identity byte-for-byte.
    #[test]
    fn stage14_4_transitions_persist_exactly_and_preserve_everything_else() {
        let file = path("fencing-transitions");
        let store = initialized(&file);
        let opened = store
            .open_fencing_incident(opening(FencingBackend::None))
            .unwrap();
        // C10: an incident may coexist with the in-flight LeaseRequest.
        store
            .begin_lease_request(Term(41), 100, DurationMs(10_000))
            .unwrap();
        let rest = without_incident(&store.load_existing().unwrap());

        let mut current = opened;
        let steps: Vec<Box<dyn Fn(&FencingIncident) -> FencingTransition>> = vec![
            Box::new(|incident| incident.request_again(FencingBackend::Command).unwrap()),
            Box::new(|incident| {
                incident
                    .action_returned(1, ActionOutcome::ReportedFailure)
                    .unwrap()
            }),
            Box::new(|incident| applied(incident.verification_not_isolated(1).unwrap())),
            Box::new(|incident| incident.request_again(FencingBackend::Command).unwrap()),
            Box::new(|incident| {
                incident
                    .action_returned(2, ActionOutcome::TimedOut)
                    .unwrap()
            }),
            Box::new(|incident| {
                applied(
                    incident
                        .verification_inconclusive(2, InconclusiveKind::Timeout, true)
                        .unwrap(),
                )
            }),
            Box::new(|incident| incident.request_again(FencingBackend::Command).unwrap()),
            Box::new(|incident| {
                incident
                    .action_returned(3, ActionOutcome::ReportedSuccess)
                    .unwrap()
            }),
            Box::new(|incident| applied(incident.confirm_by_verification(3).unwrap())),
        ];
        let expected = [
            FencingState::Requested { attempt_token: 1 },
            FencingState::Verifying {
                attempt_token: 1,
                action_outcome: ActionOutcome::ReportedFailure,
            },
            FencingState::Failed { attempt_token: 1 },
            FencingState::Requested { attempt_token: 2 },
            FencingState::Verifying {
                attempt_token: 2,
                action_outcome: ActionOutcome::TimedOut,
            },
            FencingState::Unknown(UnknownReason::VerifyInconclusive {
                kind: InconclusiveKind::Timeout,
            }),
            FencingState::Requested { attempt_token: 3 },
            FencingState::Verifying {
                attempt_token: 3,
                action_outcome: ActionOutcome::ReportedSuccess,
            },
            FencingState::Confirmed(ConfirmedBy::Backend { attempt_token: 3 }),
        ];
        for (step, expected_state) in steps.iter().zip(expected) {
            let written = store.apply_fencing_transition(step(&current)).unwrap();
            let loaded = store.load_existing().unwrap();
            assert_eq!(written.state, expected_state);
            assert_eq!(loaded.fencing_incident.as_ref(), Some(&written));
            assert_eq!(without_incident(&loaded), rest);
            assert_eq!(written.incident_ref(), current.incident_ref());
            assert_eq!(written.observer_session_id, current.observer_session_id);
            assert_eq!(
                written.observer_loss_generation,
                current.observer_loss_generation
            );
            assert_eq!(written.anchor_term, current.anchor_term);
            current = written;
        }
        assert_eq!(current.attempt_token_high_water, 3);

        // A later result against CONFIRMED is a no-op: nothing to write.
        assert!(matches!(
            current.confirm_by_verification(3).unwrap(),
            FencingEventOutcome::NoOp
        ));
        assert!(matches!(
            current
                .confirm_by_attestation(AttestationId::new(ATTESTATION_UUID))
                .unwrap(),
            FencingEventOutcome::NoOp
        ));
        let _ = fs::remove_file(file);
    }

    /// MF-24 / §13.3 stale-result behavior: a transition applies only while
    /// the durable incident equals its source exactly. Replays, transitions
    /// derived before another write, and transitions for a retired incident
    /// write nothing.
    #[test]
    fn stage14_4_stale_or_replayed_transitions_write_nothing() {
        let file = path("fencing-stale");
        let store = initialized(&file);
        let opened = store
            .open_fencing_incident(opening(FencingBackend::Command))
            .unwrap();
        store
            .apply_fencing_transition(
                opened
                    .action_returned(1, ActionOutcome::ReportedSuccess)
                    .unwrap(),
            )
            .unwrap();
        let unchanged = |transition: FencingTransition| {
            let bytes = fs::read(&file).unwrap();
            assert!(matches!(
                store.apply_fencing_transition(transition),
                Err(NodeMutationError::FencingIncident(_))
            ));
            assert_eq!(fs::read(&file).unwrap(), bytes);
        };
        // Replay of the already-applied T4.
        unchanged(
            opened
                .action_returned(1, ActionOutcome::ReportedSuccess)
                .unwrap(),
        );
        // T8 derived from the pre-T4 image.
        unchanged(applied(
            opened
                .confirm_by_attestation(AttestationId::new(ATTESTATION_UUID))
                .unwrap(),
        ));
        // A result for a retired incident never reaches its successor.
        let verifying = store.load_existing().unwrap().fencing_incident.unwrap();
        store
            .retire_fencing_incident(&verifying.incident_ref())
            .unwrap();
        store
            .open_fencing_incident(opening(FencingBackend::Command))
            .unwrap();
        unchanged(applied(verifying.confirm_by_verification(1).unwrap()));
        let _ = fs::remove_file(file);
    }

    /// §12.5 / T9: retirement removes only the exact `(seq, id)` incident and
    /// preserves the sequence high-water, M, O, generation, and identity.
    #[test]
    fn stage14_4_retirement_is_exact_and_never_reuses_the_sequence() {
        let file = path("fencing-retire");
        let store = initialized(&file);
        let opened = store
            .open_fencing_incident(opening(FencingBackend::None))
            .unwrap();
        store
            .begin_lease_request(Term(41), 100, DurationMs(10_000))
            .unwrap();
        let before = store.load_existing().unwrap();

        for wrong in [
            IncidentRef {
                incident_seq: opened.incident_seq + 1,
                incident_id: opened.incident_id.clone(),
            },
            IncidentRef {
                incident_seq: opened.incident_seq,
                incident_id: IncidentId::new(INCIDENT_UUID),
            },
        ] {
            let bytes = fs::read(&file).unwrap();
            assert!(matches!(
                store.retire_fencing_incident(&wrong),
                Err(NodeMutationError::FencingIncident(_))
            ));
            assert_eq!(fs::read(&file).unwrap(), bytes);
        }

        store
            .retire_fencing_incident(&opened.incident_ref())
            .unwrap();
        let after = store.load_existing().unwrap();
        assert_eq!(after.fencing_incident, None);
        assert_eq!(after.highest_fencing_incident_seq, 1);
        assert_eq!(without_incident(&after), without_incident(&before));
        assert!(
            store
                .retire_fencing_incident(&opened.incident_ref())
                .is_err()
        );
        let _ = fs::remove_file(file);
    }

    /// §20: the first incident write on a native v2 image emits v3.
    #[test]
    fn stage14_4_first_incident_write_on_native_v2_emits_v3() {
        let file = path("fencing-v2");
        fs::write(&file, V2_BASE).unwrap();
        let store = store(&file);
        let opened = store
            .open_fencing_incident(opening(FencingBackend::None))
            .unwrap();
        assert_eq!(opened.incident_seq, 1);
        let bytes = fs::read_to_string(&file).unwrap();
        assert!(bytes.starts_with("state_format_version = 3\n"));
        assert!(bytes.contains("highest_fencing_incident_seq = 1\n"));
        assert_eq!(
            store.load_existing().unwrap().initialization_id,
            "00000000-0000-4000-8000-000000000001"
        );
        let _ = fs::remove_file(file);
    }

    /// §22 / C16 / MF-16: after a restart the durable incident is still
    /// present but stale (observer-session mismatch), cannot mint a clearance,
    /// and retires cleanly.
    #[test]
    fn stage14_4_restart_leaves_the_incident_stale_and_retirable() {
        let file = path("fencing-restart");
        let store = initialized(&file);
        let opened = store
            .open_fencing_incident(opening(FencingBackend::None))
            .unwrap();
        let confirmed = applied(
            opened
                .confirm_by_attestation(AttestationId::new(ATTESTATION_UUID))
                .unwrap(),
        );
        store.apply_fencing_transition(confirmed).unwrap();
        drop(store);

        let restarted = self::store(&file);
        let durable = restarted.load_existing().unwrap().fencing_incident.unwrap();
        let evidence = crate::failure_assessment::LocalLossEvidence::new_for_test(
            3,
            std::time::Instant::now(),
        );
        let peer = NodeId::new("node-b");
        let new_session = SessionId::new("fedcba9876543210");
        let context = ContinuityContext {
            configured_peer: &peer,
            current_session: &new_session,
            live_episode: Some(&evidence),
        };
        assert_eq!(
            durable.check_continuity(&context, WitnessEpoch::GateView(Term(41))),
            Err(ContinuityViolation::ObserverSession)
        );
        assert_eq!(
            restarted
                .mint_fencing_clearance(&durable.incident_ref(), &context, Term(41))
                .unwrap_err(),
            NodeMutationError::FencingClearanceRefused(ClearanceRefusal::Continuity(
                ContinuityViolation::ObserverSession
            ))
        );
        restarted
            .retire_fencing_incident(&durable.incident_ref())
            .unwrap();
        let after = restarted.load_existing().unwrap();
        assert_eq!(after.fencing_incident, None);
        assert_eq!(after.highest_fencing_incident_seq, 1);
        let _ = fs::remove_file(file);
    }

    /// §19.2 / §19.3: the store validates every incident image before any
    /// write, and a plain ARM can never coexist with (or silently drop) an
    /// incident.
    #[test]
    fn stage14_4_store_validates_every_incident_image() {
        let file = path("fencing-validate");
        let store = initialized(&file);
        for invalid in [
            IncidentOpening {
                target_node_id: NodeId::new("node-a"),
                ..opening(FencingBackend::None)
            },
            IncidentOpening {
                observer_loss_generation: 0,
                ..opening(FencingBackend::None)
            },
            IncidentOpening {
                observer_session_id: SessionId::new("Not-Hex"),
                ..opening(FencingBackend::None)
            },
        ] {
            let bytes = fs::read(&file).unwrap();
            assert!(matches!(
                store.open_fencing_incident(invalid),
                Err(NodeMutationError::Invariant(_))
            ));
            assert_eq!(fs::read(&file).unwrap(), bytes);
        }

        let opened = store
            .open_fencing_incident(opening(FencingBackend::None))
            .unwrap();
        let bytes = fs::read(&file).unwrap();
        let bad_attestation = applied(
            opened
                .confirm_by_attestation(AttestationId::new("not-a-uuid"))
                .unwrap(),
        );
        assert!(matches!(
            store.apply_fencing_transition(bad_attestation),
            Err(NodeMutationError::Invariant(_))
        ));
        assert!(
            store
                .arm_release_obligation(Term(42), LeaseId::new("lease-a"))
                .is_err()
        );
        assert_eq!(fs::read(&file).unwrap(), bytes);
        let _ = fs::remove_file(file);
    }

    // ---------------------------------------------------------------------
    // Stage 14 Phase 14.4 F-01 remediation: the clearance is minted only from
    // the store's current durable incident (Design Revision 5 §24 G, §26).
    // ---------------------------------------------------------------------

    use crate::failure_assessment::PeerFailureDetector;
    use crate::protocol::Sequence;

    /// A real detector in a confirmed loss episode (generation 1), as
    /// production code would hold it.
    fn live_detector() -> PeerFailureDetector {
        let mut detector = PeerFailureDetector::new(std::time::Duration::from_secs(5)).unwrap();
        let peer_session = SessionId::new("peer-session-1");
        let t0 = std::time::Instant::now();
        detector
            .observe_session_established(peer_session.clone(), t0)
            .unwrap();
        assert!(
            detector
                .observe_trusted_heartbeat(&peer_session, Sequence(1), t0)
                .unwrap()
        );
        detector.observe_transport_failure(t0).unwrap();
        detector
            .tick(t0 + std::time::Duration::from_secs(5))
            .unwrap();
        assert_eq!(detector.loss_evidence().unwrap().generation(), 1);
        detector
    }

    fn opening_gen1(backend: FencingBackend) -> IncidentOpening {
        IncidentOpening {
            observer_loss_generation: 1,
            ..opening(backend)
        }
    }

    /// Mint through the only production path with the matching live context.
    fn mint(
        store: &NodeMutationStore,
        detector: &PeerFailureDetector,
        incident: &IncidentRef,
    ) -> Result<FencingClearance, NodeMutationError> {
        let evidence = detector.loss_evidence();
        let peer = NodeId::new("node-b");
        let current = SessionId::new(OBSERVER);
        store.mint_fencing_clearance(
            incident,
            &ContinuityContext {
                configured_peer: &peer,
                current_session: &current,
                live_episode: evidence.as_ref(),
            },
            Term(41),
        )
    }

    fn synthetic_confirmed(incident_seq: u64, incident_id: &str) -> FencingIncident {
        toml::from_str(&format!(
            "incident_seq = {incident_seq}\n\
             incident_id = \"{incident_id}\"\n\
             target_node_id = \"node-b\"\n\
             anchor_term = 41\n\
             observer_session_id = \"{OBSERVER}\"\n\
             observer_loss_generation = 1\n\
             attempt_token_high_water = 0\n\
             [state.confirmed]\n\
             by = \"operator\"\n\
             attestation_id = \"{ATTESTATION_UUID}\"\n"
        ))
        .unwrap()
    }

    /// F-01 attack A: a synthetic CONFIRMED incident deserialized from the
    /// public durable schema, with every provenance field matching the live
    /// context and even the durable `(seq, id)`, cannot mint a clearance.
    /// `FencingClearance::mint` accepts only a store-built `DurableIncident`,
    /// and the store mints from its own durable image, not the caller's value.
    #[test]
    fn stage14_4r_f01_synthetic_deserialized_confirmed_cannot_mint() {
        let detector = live_detector();
        let file = path("f01-synthetic");
        let store = initialized(&file);

        // No durable incident at all.
        let synthetic = synthetic_confirmed(1, INCIDENT_UUID);
        assert!(matches!(
            mint(&store, &detector, &synthetic.incident_ref()),
            Err(NodeMutationError::FencingIncident(_))
        ));

        // A durable UNKNOWN incident; the synthetic copy claims its exact
        // identity with CONFIRMED.
        let durable = store
            .open_fencing_incident(opening_gen1(FencingBackend::None))
            .unwrap();
        let forged = synthetic_confirmed(durable.incident_seq, durable.incident_id.as_str());
        assert_eq!(forged.incident_ref(), durable.incident_ref());
        let bytes = fs::read(&file).unwrap();
        assert_eq!(
            mint(&store, &detector, &forged.incident_ref()).unwrap_err(),
            NodeMutationError::FencingClearanceRefused(ClearanceRefusal::NotConfirmed)
        );
        // An unrelated synthetic identity.
        assert!(matches!(
            mint(
                &store,
                &detector,
                &synthetic_confirmed(99, ATTESTATION_UUID).incident_ref()
            ),
            Err(NodeMutationError::FencingIncident(_))
        ));
        // Minting is read-only.
        assert_eq!(fs::read(&file).unwrap(), bytes);
        let _ = fs::remove_file(file);
    }

    /// F-01 attack B: a genuine durable incident copied out of the store (and
    /// edited through its public fields) is not proof: the store mints only
    /// from its current durable image.
    #[test]
    fn stage14_4r_f01_copied_durable_incident_cannot_mint() {
        let detector = live_detector();
        let file = path("f01-copied");
        let store = initialized(&file);
        store
            .open_fencing_incident(opening_gen1(FencingBackend::None))
            .unwrap();
        let mut copy = store.load_existing().unwrap().fencing_incident.unwrap();
        copy.state = FencingState::Confirmed(ConfirmedBy::Backend { attempt_token: 1 });
        assert_eq!(
            mint(&store, &detector, &copy.incident_ref()).unwrap_err(),
            NodeMutationError::FencingClearanceRefused(ClearanceRefusal::NotConfirmed)
        );

        // A copy of a genuinely CONFIRMED incident after it was retired and
        // replaced by a new incident.
        let durable = store.load_existing().unwrap().fencing_incident.unwrap();
        store
            .apply_fencing_transition(applied(
                durable
                    .confirm_by_attestation(AttestationId::new(ATTESTATION_UUID))
                    .unwrap(),
            ))
            .unwrap();
        let confirmed_copy = store.load_existing().unwrap().fencing_incident.unwrap();
        assert!(mint(&store, &detector, &confirmed_copy.incident_ref()).is_ok());
        store
            .retire_fencing_incident(&confirmed_copy.incident_ref())
            .unwrap();
        assert!(matches!(
            mint(&store, &detector, &confirmed_copy.incident_ref()),
            Err(NodeMutationError::FencingIncident(_))
        ));
        let replacement = store
            .open_fencing_incident(opening_gen1(FencingBackend::None))
            .unwrap();
        assert!(matches!(
            mint(&store, &detector, &confirmed_copy.incident_ref()),
            Err(NodeMutationError::FencingIncident(_))
        ));
        assert_eq!(
            mint(&store, &detector, &replacement.incident_ref()).unwrap_err(),
            NodeMutationError::FencingClearanceRefused(ClearanceRefusal::NotConfirmed)
        );
        let _ = fs::remove_file(file);
    }

    /// F-01 positive control: both authorized CONFIRMED sources (T5 backend
    /// verification, T8 operator attestation), persisted through the store,
    /// mint a clearance bound to the exact durable provenance.
    #[test]
    fn stage14_4r_legitimate_t5_and_t8_paths_mint_clearance() {
        let detector = live_detector();
        let file = path("f01-legitimate");
        let store = initialized(&file);

        let opened = store
            .open_fencing_incident(opening_gen1(FencingBackend::Command))
            .unwrap();
        let verifying = store
            .apply_fencing_transition(
                opened
                    .action_returned(1, ActionOutcome::ReportedSuccess)
                    .unwrap(),
            )
            .unwrap();
        let confirmed = store
            .apply_fencing_transition(applied(verifying.confirm_by_verification(1).unwrap()))
            .unwrap();
        let clearance = mint(&store, &detector, &confirmed.incident_ref()).unwrap();
        // v0.7 G-2 (G-A2, audit L-8): the T5 provenance survives the mint and maps to an
        // automated route handoff.
        assert_eq!(clearance.backend_attempt_token(), Some(1));
        assert_eq!(
            crate::daemon::route_origin(&crate::daemon::FencingPrerequisite::Cleared(
                mint(&store, &detector, &confirmed.incident_ref()).unwrap()
            )),
            crate::route_handoff::RhOrigin::Fencing {
                incident_seq: confirmed.incident_seq,
                incident_id: confirmed.incident_id.as_str().to_string(),
                attempt_token: 1,
                confirmed_by: crate::route_handoff::RhConfirmation::Backend,
            }
        );
        assert_eq!(clearance.incident(), &confirmed.incident_ref());
        assert_eq!(clearance.target_node_id(), &confirmed.target_node_id);
        assert_eq!(clearance.anchor_term(), confirmed.anchor_term);
        assert_eq!(
            clearance.observer_session_id(),
            &confirmed.observer_session_id
        );
        assert_eq!(clearance.observer_loss_generation(), 1);

        store
            .retire_fencing_incident(&confirmed.incident_ref())
            .unwrap();
        let opened = store
            .open_fencing_incident(opening_gen1(FencingBackend::None))
            .unwrap();
        let attested = store
            .apply_fencing_transition(applied(
                opened
                    .confirm_by_attestation(AttestationId::new(ATTESTATION_UUID))
                    .unwrap(),
            ))
            .unwrap();
        let clearance = mint(&store, &detector, &attested.incident_ref()).unwrap();
        // v0.7 G-2 (G-A2, audit L-8): a T8 clearance carries no backend token and maps to an
        // operator-attested origin, which never automates the route.
        assert_eq!(clearance.backend_attempt_token(), None);
        assert!(matches!(
            crate::daemon::route_origin(&crate::daemon::FencingPrerequisite::Cleared(
                mint(&store, &detector, &attested.incident_ref()).unwrap()
            )),
            crate::route_handoff::RhOrigin::Fencing {
                attempt_token: 0,
                confirmed_by: crate::route_handoff::RhConfirmation::Operator,
                ..
            }
        ));
        assert_eq!(clearance.incident(), &attested.incident_ref());
        let _ = fs::remove_file(file);
    }

    /// F-01 exact current-store rules: only the current durable `CONFIRMED`
    /// incident with the exact `(seq, id)` and passing R1-R4 mints; every
    /// other durable state, identity, and continuity fact refuses, and minting
    /// never writes.
    #[test]
    fn stage14_4r_clearance_requires_the_exact_current_confirmed_incident() {
        let detector = live_detector();
        let file = path("f01-exact");
        let store = initialized(&file);

        // Every non-CONFIRMED durable state, reached through real transitions.
        let not_confirmed = |store: &NodeMutationStore| {
            let current = store.load_existing().unwrap().fencing_incident.unwrap();
            assert_eq!(
                mint(store, &detector, &current.incident_ref()).unwrap_err(),
                NodeMutationError::FencingClearanceRefused(ClearanceRefusal::NotConfirmed),
                "{:?}",
                current.state
            );
            current
        };
        let unknown = store
            .open_fencing_incident(opening_gen1(FencingBackend::None))
            .unwrap();
        not_confirmed(&store);
        let requested = store
            .apply_fencing_transition(unknown.request_again(FencingBackend::Command).unwrap())
            .unwrap();
        not_confirmed(&store);
        let verifying = store
            .apply_fencing_transition(
                requested
                    .action_returned(1, ActionOutcome::TimedOut)
                    .unwrap(),
            )
            .unwrap();
        not_confirmed(&store);
        let failed = store
            .apply_fencing_transition(applied(verifying.verification_not_isolated(1).unwrap()))
            .unwrap();
        not_confirmed(&store);
        let requested = store
            .apply_fencing_transition(failed.request_again(FencingBackend::Command).unwrap())
            .unwrap();
        let verifying = store
            .apply_fencing_transition(requested.action_returned(2, ActionOutcome::Signal).unwrap())
            .unwrap();
        let inconclusive = store
            .apply_fencing_transition(applied(
                verifying
                    .verification_inconclusive(2, InconclusiveKind::Timeout, true)
                    .unwrap(),
            ))
            .unwrap();
        not_confirmed(&store);
        let confirmed = store
            .apply_fencing_transition(applied(
                inconclusive
                    .confirm_by_attestation(AttestationId::new(ATTESTATION_UUID))
                    .unwrap(),
            ))
            .unwrap();
        assert!(mint(&store, &detector, &confirmed.incident_ref()).is_ok());

        // Exact identity.
        let bytes = fs::read(&file).unwrap();
        for wrong in [
            IncidentRef {
                incident_seq: confirmed.incident_seq + 1,
                incident_id: confirmed.incident_id.clone(),
            },
            IncidentRef {
                incident_seq: confirmed.incident_seq,
                incident_id: IncidentId::new(INCIDENT_UUID),
            },
        ] {
            assert!(matches!(
                mint(&store, &detector, &wrong),
                Err(NodeMutationError::FencingIncident(_))
            ));
        }

        // R1-R4 through the store.
        let evidence = detector.loss_evidence();
        let peer = NodeId::new("node-b");
        let current = SessionId::new(OBSERVER);
        let other_peer = NodeId::new("node-c");
        let restarted = SessionId::new("fedcba9876543210");
        let mut new_episode = detector.clone();
        new_episode
            .observe_trusted_heartbeat(
                &SessionId::new("peer-session-1"),
                Sequence(2),
                std::time::Instant::now() + std::time::Duration::from_secs(6),
            )
            .unwrap();
        new_episode
            .observe_transport_failure(
                std::time::Instant::now() + std::time::Duration::from_secs(7),
            )
            .unwrap();
        new_episode
            .tick(std::time::Instant::now() + std::time::Duration::from_secs(12))
            .unwrap();
        let second = new_episode.loss_evidence();
        assert_eq!(second.as_ref().unwrap().generation(), 2);
        let cases: [(ContinuityContext<'_>, Term, ContinuityViolation); 5] = [
            (
                ContinuityContext {
                    configured_peer: &other_peer,
                    current_session: &current,
                    live_episode: evidence.as_ref(),
                },
                Term(41),
                ContinuityViolation::Target,
            ),
            (
                ContinuityContext {
                    configured_peer: &peer,
                    current_session: &restarted,
                    live_episode: evidence.as_ref(),
                },
                Term(41),
                ContinuityViolation::ObserverSession,
            ),
            (
                ContinuityContext {
                    configured_peer: &peer,
                    current_session: &current,
                    live_episode: None,
                },
                Term(41),
                ContinuityViolation::Episode,
            ),
            (
                ContinuityContext {
                    configured_peer: &peer,
                    current_session: &current,
                    live_episode: second.as_ref(),
                },
                Term(41),
                ContinuityViolation::Episode,
            ),
            (
                ContinuityContext {
                    configured_peer: &peer,
                    current_session: &current,
                    live_episode: evidence.as_ref(),
                },
                Term(42),
                ContinuityViolation::WitnessEpoch,
            ),
        ];
        for (context, view_term, violation) in cases {
            assert_eq!(
                store
                    .mint_fencing_clearance(&confirmed.incident_ref(), &context, view_term)
                    .unwrap_err(),
                NodeMutationError::FencingClearanceRefused(ClearanceRefusal::Continuity(violation))
            );
        }
        assert_eq!(fs::read(&file).unwrap(), bytes);
        let _ = fs::remove_file(file);
    }

    // ---------------------------------------------------------------------
    // Stage 14 Phase 14.10: the success ARM (§25) and the atomic
    // abort-cleanup transaction (§25.1) — old/new images, validation, and
    // the crash/fault matrix over the real recovery transaction.
    // ---------------------------------------------------------------------

    const LEASE_14_10: &str = "lease-14-10";

    /// A CONFIRMED(operator) incident (anchor 41, generation 1) and its
    /// clearance, minted by the only production path.
    fn confirmed_with_clearance(store: &NodeMutationStore) -> (FencingIncident, FencingClearance) {
        let detector = live_detector();
        let opened = store
            .open_fencing_incident(opening_gen1(FencingBackend::None))
            .unwrap();
        let confirmed = store
            .apply_fencing_transition(applied(
                opened
                    .confirm_by_attestation(crate::fencing::AttestationId::new(ATTESTATION_UUID))
                    .unwrap(),
            ))
            .unwrap();
        let clearance = mint(store, &detector, &confirmed.incident_ref()).unwrap();
        (confirmed, clearance)
    }

    fn binding_of(incident: &FencingIncident) -> IncidentBinding {
        IncidentBinding {
            incident: incident.incident_ref(),
            observer_session_id: incident.observer_session_id.clone(),
            observer_loss_generation: incident.observer_loss_generation,
        }
    }

    /// The expected post-transaction image: the old one with the incident
    /// removed and O = (term, lease) — M, generation, the high-water, and
    /// identity untouched.
    fn consumed(old: &NodeMutationPersistentState, term: Term) -> NodeMutationPersistentState {
        let mut new = old.clone();
        new.fencing_incident = None;
        new.release_obligation = Some(ReleaseObligation {
            term,
            lease_id: LeaseId::new(LEASE_14_10),
        });
        new
    }

    /// §25 old/new image: the exact clearance incident in CONFIRMED with the
    /// clearance episode, grant = anchor + 1, target = configured peer, O and
    /// M absent -> one write: incident absent, O = (term, lease), everything
    /// else unchanged.
    #[test]
    fn stage14_10_success_arm_consumes_the_incident_and_installs_o() {
        let file = path("14-10-arm");
        let store = initialized(&file);
        let (_, clearance) = confirmed_with_clearance(&store);
        let old = store.load_existing().unwrap();
        let obligation = store
            .arm_consuming_fencing(
                Term(42),
                LeaseId::new(LEASE_14_10),
                &clearance,
                &NodeId::new("node-b"),
            )
            .unwrap();
        assert_eq!(obligation.term, Term(42));
        assert_eq!(store.load_existing().unwrap(), consumed(&old, Term(42)));
        // Single consumption: the same clearance can never ARM again.
        assert!(matches!(
            store.arm_consuming_fencing(
                Term(42),
                LeaseId::new(LEASE_14_10),
                &clearance,
                &NodeId::new("node-b")
            ),
            Err(NodeMutationError::FencingIncident(_))
        ));
        let _ = fs::remove_file(file);
    }

    /// §25 validation: every old-image mismatch writes nothing.
    #[test]
    fn stage14_10_success_arm_rejects_every_old_image_mismatch() {
        type Edit = fn(&mut NodeMutationPersistentState);
        let cases: [(&str, Term, &str, Option<Edit>); 9] = [
            ("grant == anchor", Term(41), "node-b", None),
            ("grant > anchor + 1", Term(43), "node-b", None),
            ("wrong configured peer", Term(42), "node-c", None),
            (
                "state not CONFIRMED",
                Term(42),
                "node-b",
                Some(|state| {
                    let incident = state.fencing_incident.as_mut().unwrap();
                    incident.state = FencingState::Unknown(UnknownReason::NotAttempted {});
                }),
            ),
            (
                "observer session",
                Term(42),
                "node-b",
                Some(|state| {
                    state.fencing_incident.as_mut().unwrap().observer_session_id =
                        SessionId::new("fedcba9876543210");
                }),
            ),
            (
                "loss generation",
                Term(42),
                "node-b",
                Some(|state| {
                    state
                        .fencing_incident
                        .as_mut()
                        .unwrap()
                        .observer_loss_generation = 2;
                }),
            ),
            (
                "anchor term",
                Term(42),
                "node-b",
                Some(|state| {
                    state.fencing_incident.as_mut().unwrap().anchor_term = Term(40);
                }),
            ),
            (
                "incident identity",
                Term(42),
                "node-b",
                Some(|state| {
                    state.fencing_incident.as_mut().unwrap().incident_id =
                        IncidentId::new("99999999-2222-4333-8444-555555555555");
                }),
            ),
            (
                "incident absent",
                Term(42),
                "node-b",
                Some(|state| {
                    state.fencing_incident = None;
                }),
            ),
        ];
        for (name, term, peer, edit) in cases {
            let file = path("14-10-arm-reject");
            let store = initialized(&file);
            let (_, clearance) = confirmed_with_clearance(&store);
            if let Some(edit) = edit {
                let mut state = store.load_existing().unwrap();
                edit(&mut state);
                store.save_for_test(&state).unwrap();
            }
            let before = fs::read(&file).unwrap();
            assert!(
                matches!(
                    store.arm_consuming_fencing(
                        term,
                        LeaseId::new(LEASE_14_10),
                        &clearance,
                        &NodeId::new(peer)
                    ),
                    Err(NodeMutationError::FencingIncident(_))
                ),
                "{name}"
            );
            assert_eq!(fs::read(&file).unwrap(), before, "{name}: nothing written");
            let _ = fs::remove_file(file);
        }
        // M present (the C10 LeaseRequest): rejected, M kept.
        let file = path("14-10-arm-m");
        let store = initialized(&file);
        let (_, clearance) = confirmed_with_clearance(&store);
        store
            .begin_lease_request(Term(41), 100, DurationMs(10_000))
            .unwrap();
        let before = fs::read(&file).unwrap();
        assert!(matches!(
            store.arm_consuming_fencing(
                Term(42),
                LeaseId::new(LEASE_14_10),
                &clearance,
                &NodeId::new("node-b")
            ),
            Err(NodeMutationError::FencingIncident(_))
        ));
        assert_eq!(fs::read(&file).unwrap(), before);
        let _ = fs::remove_file(file);
    }

    /// §25.1 old/new image: the incident (in any state) with the exact
    /// durable binding, target = configured peer, O and M absent -> one
    /// write: incident absent, cleanup O = the exact granted epoch.
    #[test]
    fn stage14_10_abort_cleanup_retires_and_arms_in_one_write() {
        for confirmed in [false, true] {
            let file = path("14-10-cleanup");
            let store = initialized(&file);
            let incident = if confirmed {
                confirmed_with_clearance(&store).0
            } else {
                store
                    .open_fencing_incident(opening_gen1(FencingBackend::None))
                    .unwrap()
            };
            let old = store.load_existing().unwrap();
            store
                .retire_incident_and_arm_cleanup_obligation(
                    Term(42),
                    LeaseId::new(LEASE_14_10),
                    &binding_of(&incident),
                    &NodeId::new("node-b"),
                )
                .unwrap();
            assert_eq!(store.load_existing().unwrap(), consumed(&old, Term(42)));
            let _ = fs::remove_file(file);
        }
    }

    /// §25.1 validation: a wrong or stale incident, a wrong durable
    /// generation or session, a wrong peer, an incompatible M, or no incident
    /// -> no write; M is never overwritten.
    #[test]
    fn stage14_10_abort_cleanup_rejects_every_old_image_mismatch() {
        let file = path("14-10-cleanup-reject");
        let store = initialized(&file);
        let incident = store
            .open_fencing_incident(opening_gen1(FencingBackend::None))
            .unwrap();
        let exact = binding_of(&incident);
        let before = fs::read(&file).unwrap();
        let mut wrong_seq = exact.clone();
        wrong_seq.incident.incident_seq += 1;
        let mut wrong_id = exact.clone();
        wrong_id.incident.incident_id = IncidentId::new("99999999-2222-4333-8444-555555555555");
        let mut wrong_session = exact.clone();
        wrong_session.observer_session_id = SessionId::new("fedcba9876543210");
        let mut wrong_generation = exact.clone();
        wrong_generation.observer_loss_generation = 2;
        for (name, binding, peer) in [
            ("seq", &wrong_seq, "node-b"),
            ("id", &wrong_id, "node-b"),
            ("session", &wrong_session, "node-b"),
            ("generation", &wrong_generation, "node-b"),
            ("peer", &exact, "node-c"),
        ] {
            assert!(
                matches!(
                    store.retire_incident_and_arm_cleanup_obligation(
                        Term(42),
                        LeaseId::new(LEASE_14_10),
                        binding,
                        &NodeId::new(peer)
                    ),
                    Err(NodeMutationError::FencingIncident(_))
                ),
                "{name}"
            );
            assert_eq!(fs::read(&file).unwrap(), before, "{name}");
        }
        store
            .begin_lease_request(Term(41), 100, DurationMs(10_000))
            .unwrap();
        let with_m = fs::read(&file).unwrap();
        assert!(matches!(
            store.retire_incident_and_arm_cleanup_obligation(
                Term(42),
                LeaseId::new(LEASE_14_10),
                &exact,
                &NodeId::new("node-b")
            ),
            Err(NodeMutationError::FencingIncident(_))
        ));
        assert_eq!(fs::read(&file).unwrap(), with_m, "M never overwritten");
        let _ = fs::remove_file(&file);

        let file = path("14-10-cleanup-absent");
        let store = initialized(&file);
        let before = fs::read(&file).unwrap();
        assert!(matches!(
            store.retire_incident_and_arm_cleanup_obligation(
                Term(42),
                LeaseId::new(LEASE_14_10),
                &exact,
                &NodeId::new("node-b")
            ),
            Err(NodeMutationError::FencingIncident(_))
        ));
        assert_eq!(fs::read(&file).unwrap(), before);
        let _ = fs::remove_file(file);
    }

    /// §21 C12b / §34.5 / §34.14: the crash/fault matrix. At every recovery
    /// transaction fault point, each transaction ends in exactly the old
    /// image (incident, no O) — PreCommitFailure, nothing to recover — or the
    /// new image (no incident, O) — committed — or an uncertain outcome that
    /// is RecoveryBlocked and whose canonical bytes are exactly the old or
    /// the new image. Never "incident + O", never "no incident + no O".
    #[test]
    fn stage14_10_incident_o_transactions_fault_matrix() {
        use crate::recovery::{CanonicalFingerprint, DetailedInspection, FaultPoint};
        let points = [
            FaultPoint::RecoveryTempFsync,
            FaultPoint::RecoveryInstall,
            FaultPoint::RecoveryParentFsync,
            FaultPoint::CandidateTempFsync,
            FaultPoint::CanonicalInstallBeforeMutation,
            FaultPoint::CanonicalInstall,
            FaultPoint::CanonicalParentFsync,
            FaultPoint::RecoveryUnlink,
            FaultPoint::CleanupParentFsync,
        ];
        for transaction in ["success-arm", "abort-cleanup"] {
            let mut classes = Vec::new();
            for point in points {
                let file = path("14-10-fault");
                let store = initialized(&file);
                let (incident, clearance) = confirmed_with_clearance(&store);
                let old_state = store.load_existing().unwrap();
                let old = fs::read(&file).unwrap();
                let new_state = consumed(&old_state, Term(42));
                crate::recovery::inject_fault_once(point);
                let result = if transaction == "success-arm" {
                    store.arm_consuming_fencing(
                        Term(42),
                        LeaseId::new(LEASE_14_10),
                        &clearance,
                        &NodeId::new("node-b"),
                    )
                } else {
                    store.retire_incident_and_arm_cleanup_obligation(
                        Term(42),
                        LeaseId::new(LEASE_14_10),
                        &binding_of(&incident),
                        &NodeId::new("node-b"),
                    )
                };
                let canonical: NodeMutationPersistentState =
                    parse_state(&fs::read_to_string(&file).unwrap()).unwrap();
                assert_ne!(
                    (
                        canonical.fencing_incident.is_some(),
                        canonical.release_obligation.is_some()
                    ),
                    (true, true),
                    "{transaction} {point:?}: incident + O"
                );
                assert_ne!(
                    (
                        canonical.fencing_incident.is_some(),
                        canonical.release_obligation.is_some()
                    ),
                    (false, false),
                    "{transaction} {point:?}: no incident + no O"
                );
                let class = match result {
                    Ok(_) => {
                        assert_eq!(store.load_existing().unwrap(), new_state);
                        assert!(!crate::recovery::marker_path(&file).exists());
                        "committed"
                    }
                    Err(NodeMutationError::Io(_)) => {
                        assert_eq!(fs::read(&file).unwrap(), old, "{transaction} {point:?}");
                        assert_eq!(store.load_existing().unwrap(), old_state);
                        "precommit"
                    }
                    Err(NodeMutationError::RecoveryRequired(_)) => {
                        assert!(matches!(
                            store.load_existing(),
                            Err(NodeMutationError::RecoveryRequired(_))
                        ));
                        let fingerprint = match crate::recovery::inspect_detailed(
                            &file,
                            crate::recovery::StoreKind::Node,
                            "cluster",
                            "node-a",
                        ) {
                            DetailedInspection::Active { canonical, .. } => Some(canonical),
                            _ => None,
                        };
                        if canonical == old_state {
                            assert_ne!(fingerprint, Some(CanonicalFingerprint::New));
                            "uncertain-old"
                        } else {
                            assert_eq!(canonical, new_state, "{transaction} {point:?}");
                            assert_ne!(fingerprint, Some(CanonicalFingerprint::Old));
                            "uncertain-new"
                        }
                    }
                    Err(other) => panic!("{transaction} {point:?}: {other:?}"),
                };
                classes.push((point, class));
                let _ = fs::remove_file(&file);
                let _ = fs::remove_file(crate::recovery::marker_path(&file));
                let _ = fs::remove_dir_all(crate::recovery::marker_path(&file));
            }
            eprintln!("stage14.10 fault matrix {transaction}: {classes:?}");
            for expected in ["precommit", "uncertain-new"] {
                assert!(
                    classes.iter().any(|(_, class)| *class == expected),
                    "{transaction}: no {expected} class observed: {classes:?}"
                );
            }
        }
    }

    /// J35 (Amendment C, AC-2 / CL-10): both exceptional settles remove
    /// exactly the owned `M` and `O` in one save and keep the generation.
    #[test]
    fn j35_settles_remove_exactly_the_owned_release_and_obligation() {
        for retired in [false, true] {
            let file = path("j35-settle");
            let store = initialized(&file);
            store
                .arm_release_obligation(Term(9), LeaseId::new("lease-9"))
                .unwrap();
            let release = store
                .begin_lease_release_for_test(Term(9), LeaseId::new("lease-9"), "cleanup".into())
                .unwrap();
            let settle = |request_id: &RequestId, generation, term, lease_id: &LeaseId| {
                if retired {
                    store.settle_retired_owned_release(request_id, generation, term, lease_id)
                } else {
                    store.settle_rejected_owned_release(request_id, generation, term, lease_id)
                }
            };
            // Any identity mismatch is refused and nothing is written.
            let before = fs::read(&file).unwrap();
            for (request_id, generation, term, lease_id) in [
                (
                    RequestId::new("00000000-0000-4000-8000-000000000001"),
                    release.mutation_generation,
                    Term(9),
                    LeaseId::new("lease-9"),
                ),
                (
                    release.request_id.clone(),
                    release.mutation_generation + 1,
                    Term(9),
                    LeaseId::new("lease-9"),
                ),
                (
                    release.request_id.clone(),
                    release.mutation_generation,
                    Term(8),
                    LeaseId::new("lease-9"),
                ),
                (
                    release.request_id.clone(),
                    release.mutation_generation,
                    Term(9),
                    LeaseId::new("other"),
                ),
            ] {
                assert!(
                    matches!(
                        settle(&request_id, generation, term, &lease_id),
                        Err(NodeMutationError::CompletionMismatch(_))
                    ),
                    "retired={retired} {request_id:?} {generation} {term:?} {lease_id:?}"
                );
                assert_eq!(fs::read(&file).unwrap(), before);
            }
            settle(
                &release.request_id,
                release.mutation_generation,
                Term(9),
                &LeaseId::new("lease-9"),
            )
            .unwrap();
            let state = super::tests::store(&file).load_existing().unwrap();
            assert!(state.outstanding_mutation.is_none());
            assert!(state.release_obligation.is_none());
            assert_eq!(state.highest_started_mutation_generation, 1);
            // Nothing left to settle; an `O` without `M` is never settled.
            assert!(settle(&release.request_id, 1, Term(9), &LeaseId::new("lease-9")).is_err());
            store
                .arm_release_obligation(Term(10), LeaseId::new("lease-10"))
                .unwrap();
            assert!(matches!(
                settle(&release.request_id, 1, Term(10), &LeaseId::new("lease-10")),
                Err(NodeMutationError::CompletionMismatch(
                    "outstanding mutation"
                ))
            ));
            assert!(store.release_obligation().unwrap().is_some());
            let _ = fs::remove_file(file);
        }
    }

    /// J35 (AC-2, T-06 / T-07): at every persistence fault point the settle
    /// leaves `M` and `O` both present or both absent; a pre-commit failure
    /// keeps the old bytes and an uncertain commit is RecoveryRequired.
    #[test]
    fn j35_settle_fault_matrix_never_splits_m_and_o() {
        use crate::recovery::FaultPoint;
        let points = [
            FaultPoint::RecoveryTempFsync,
            FaultPoint::RecoveryInstall,
            FaultPoint::RecoveryParentFsync,
            FaultPoint::CandidateTempFsync,
            FaultPoint::CanonicalInstallBeforeMutation,
            FaultPoint::CanonicalInstall,
            FaultPoint::CanonicalParentFsync,
            FaultPoint::RecoveryUnlink,
            FaultPoint::CleanupParentFsync,
        ];
        let mut classes = Vec::new();
        for point in points {
            let file = path("j35-settle-fault");
            let store = initialized(&file);
            store
                .arm_release_obligation(Term(9), LeaseId::new("lease-9"))
                .unwrap();
            let release = store
                .begin_lease_release_for_test(Term(9), LeaseId::new("lease-9"), "cleanup".into())
                .unwrap();
            let old = fs::read(&file).unwrap();
            crate::recovery::inject_fault_once(point);
            let result = store.settle_retired_owned_release(
                &release.request_id,
                release.mutation_generation,
                Term(9),
                &LeaseId::new("lease-9"),
            );
            let canonical: NodeMutationPersistentState =
                parse_state(&fs::read_to_string(&file).unwrap()).unwrap();
            assert_eq!(
                canonical.outstanding_mutation.is_some(),
                canonical.release_obligation.is_some(),
                "{point:?}: M and O split"
            );
            let class = match result {
                Ok(()) => {
                    let state = store.load_existing().unwrap();
                    assert!(
                        state.outstanding_mutation.is_none() && state.release_obligation.is_none()
                    );
                    "committed"
                }
                Err(NodeMutationError::Io(_)) => {
                    assert_eq!(fs::read(&file).unwrap(), old, "{point:?}");
                    "precommit"
                }
                Err(NodeMutationError::RecoveryRequired(_)) => {
                    assert!(matches!(
                        store.load_existing(),
                        Err(NodeMutationError::RecoveryRequired(_))
                    ));
                    "uncertain"
                }
                Err(other) => panic!("{point:?}: {other:?}"),
            };
            classes.push((point, class));
            let _ = fs::remove_file(&file);
            let _ = fs::remove_file(crate::recovery::marker_path(&file));
            let _ = fs::remove_dir_all(crate::recovery::marker_path(&file));
        }
        eprintln!("j35 settle fault matrix: {classes:?}");
        for expected in ["precommit", "uncertain"] {
            assert!(
                classes.iter().any(|(_, class)| *class == expected),
                "no {expected} class observed: {classes:?}"
            );
        }
    }

    /// J35 (E-6 / CL-08 / AC-6): neither settle ever writes over an image
    /// with a fencing incident. A valid store cannot hold an incident with
    /// `O` (§19.2), so such an image is refused at load, before the in-guard
    /// incident check, and the bytes stay as they are.
    #[test]
    fn j35_settles_never_write_with_a_fencing_incident() {
        let file = path("j35-settle-incident");
        let store = initialized(&file);
        confirmed_with_clearance(&store);
        let mut mixed = store.load_existing().unwrap();
        mixed.release_obligation = Some(ReleaseObligation {
            term: Term(42),
            lease_id: LeaseId::new(LEASE_14_10),
        });
        fs::write(&file, toml::to_string(&mixed).unwrap()).unwrap();
        let before = fs::read(&file).unwrap();
        let id = RequestId::new("00000000-0000-4000-8000-000000000001");
        let lease = LeaseId::new(LEASE_14_10);
        assert!(
            store
                .settle_rejected_owned_release(&id, 1, Term(42), &lease)
                .is_err()
        );
        assert!(
            store
                .settle_retired_owned_release(&id, 1, Term(42), &lease)
                .is_err()
        );
        assert_eq!(fs::read(&file).unwrap(), before);
        let _ = fs::remove_file(file);
    }

    /// §19.2: a committed "incident + O" image is corruption and is
    /// RecoveryBlocked on load, never read as clean.
    #[test]
    fn stage14_10_mixed_incident_and_o_image_is_rejected() {
        let file = path("14-10-mixed");
        let store = initialized(&file);
        confirmed_with_clearance(&store);
        let mut mixed = store.load_existing().unwrap();
        mixed.release_obligation = Some(ReleaseObligation {
            term: Term(42),
            lease_id: LeaseId::new(LEASE_14_10),
        });
        fs::write(&file, toml::to_string(&mixed).unwrap()).unwrap();
        assert!(matches!(
            store.load_existing(),
            Err(NodeMutationError::Invariant(_))
        ));
        let _ = fs::remove_file(file);
    }

    impl NodeMutationStore {
        #[cfg(test)]
        fn save_for_test(
            &self,
            state: &NodeMutationPersistentState,
        ) -> Result<(), NodeMutationError> {
            let expected_old = self.load_existing_snapshot()?.expected_old;
            save_state(&self.path, state, &expected_old)
        }
    }

    // ---- ARM gate (F15-M4 / BG-12): only Ok commits ----------------------

    /// One value of every error variant. The exhaustive `match` below fails
    /// to compile when a variant is added, so a new error cannot silently
    /// fall outside this table.
    fn every_error() -> Vec<NodeMutationError> {
        fn covered(error: &NodeMutationError) {
            match error {
                NodeMutationError::StateMissing
                | NodeMutationError::AlreadyExists
                | NodeMutationError::Io(_)
                | NodeMutationError::Parse(_)
                | NodeMutationError::Path(_)
                | NodeMutationError::Invariant(_)
                | NodeMutationError::IdentityMismatch(_)
                | NodeMutationError::UnsupportedVersion(_)
                | NodeMutationError::OutstandingExists
                | NodeMutationError::GenerationExhausted
                | NodeMutationError::RequestIdGeneration
                | NodeMutationError::CompletionMismatch(_)
                | NodeMutationError::MutexPoisoned
                | NodeMutationError::RecoveryRequired(_)
                | NodeMutationError::FencingIncident(_)
                | NodeMutationError::FencingClearanceRefused(_) => {}
            }
        }
        let all = vec![
            NodeMutationError::StateMissing,
            NodeMutationError::AlreadyExists,
            NodeMutationError::Io("disk".into()),
            NodeMutationError::Parse("bad".into()),
            NodeMutationError::Path("bad".into()),
            NodeMutationError::Invariant("invariant"),
            NodeMutationError::IdentityMismatch("identity"),
            NodeMutationError::UnsupportedVersion(9),
            NodeMutationError::OutstandingExists,
            NodeMutationError::GenerationExhausted,
            NodeMutationError::RequestIdGeneration,
            NodeMutationError::CompletionMismatch("field"),
            NodeMutationError::MutexPoisoned,
            NodeMutationError::RecoveryRequired("uncertain".into()),
            NodeMutationError::FencingIncident("incident"),
            NodeMutationError::FencingClearanceRefused(
                crate::fencing::ClearanceRefusal::NotConfirmed,
            ),
        ];
        all.iter().for_each(covered);
        all
    }

    #[test]
    fn only_a_successful_arm_is_committed() {
        assert_eq!(plain_arm_gate(Ok(())), ArmGate::Committed);
        assert_eq!(plain_arm_gate(Ok(42u64)), ArmGate::Committed);
        for error in every_error() {
            let gate = plain_arm_gate::<()>(Err(error.clone()));
            assert_ne!(gate, ArmGate::Committed, "{error}");
        }
    }

    #[test]
    fn the_arm_gate_tells_not_committed_rejected_and_recovery_blocked_apart() {
        for error in every_error() {
            let gate = plain_arm_gate::<()>(Err(error.clone()));
            let expected = match &error {
                NodeMutationError::Io(reason) => ArmGate::NotCommitted(reason.clone()),
                NodeMutationError::OutstandingExists | NodeMutationError::Invariant(_) => {
                    ArmGate::Rejected(error.to_string())
                }
                // Uncertain persistence and everything unnamed: fail-closed.
                _ => ArmGate::RecoveryBlocked(error.to_string()),
            };
            assert_eq!(gate, expected, "{error}");
        }
        assert_eq!(
            plain_arm_gate::<()>(Err(NodeMutationError::Io("disk".into()))),
            ArmGate::NotCommitted("disk".into())
        );
        assert!(matches!(
            plain_arm_gate::<()>(Err(NodeMutationError::RecoveryRequired("x".into()))),
            ArmGate::RecoveryBlocked(_)
        ));
    }

    /// The real store's refusals pass through the gate as refusals: a second
    /// ARM over an armed O is `Rejected`, the first is `Committed`.
    #[test]
    fn the_real_plain_arm_is_gated() {
        let path = path("arm-gate");
        let store = initialized(&path);
        let lease = LeaseId::new("lease-1");
        assert_eq!(
            plain_arm_gate(store.arm_release_obligation(Term(7), lease.clone())),
            ArmGate::Committed
        );
        assert!(matches!(
            plain_arm_gate(store.arm_release_obligation(Term(8), LeaseId::new("lease-2"))),
            ArmGate::Rejected(_)
        ));
        let _ = fs::remove_file(&path);
    }
}
