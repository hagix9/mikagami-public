//! Durable idempotency and generation classification primitives for Witness.

use crate::protocol::{
    LeaseGrantPayload, MessageType, ProtocolMessage, RequestId, UnsignedEnvelope,
};
use crate::witness_state::{WitnessPersistentState, WitnessStateError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

pub const JOURNAL_CAPACITY: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommittedSemanticResult {
    LeaseGrant(LeaseGrantPayload),
    LeaseRenewed(LeaseGrantPayload),
    LeaseReleased(crate::protocol::LeaseReleasedPayload),
    LeaseReject(crate::protocol::LeaseRejectPayload),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalRecord {
    pub request_id: RequestId,
    pub requester_node_id: String,
    pub request_kind: MessageType,
    pub mutation_generation: u64,
    pub semantic_fingerprint: [u8; 32],
    #[serde(with = "persisted_result")]
    pub result: CommittedSemanticResult,
}

mod persisted_result {
    use super::CommittedSemanticResult;
    use crate::protocol::{LeaseRejectPayload, WitnessMutationOutcomeCode};
    use serde::{Deserialize, Serialize};

    #[allow(clippy::enum_variant_names)]
    #[derive(Serialize, Deserialize)]
    enum PersistedResult {
        LeaseGrant(crate::protocol::LeaseGrantPayload),
        LeaseRenewed(crate::protocol::LeaseGrantPayload),
        LeaseReleased(crate::protocol::LeaseReleasedPayload),
        LeaseReject(PersistedReject),
    }

    /// OD-J32-4 (ii): a persistence-only type, so it rejects unknown fields.
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PersistedReject {
        reason: String,
    }

    pub fn serialize<S>(result: &CommittedSemanticResult, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let persisted = match result {
            CommittedSemanticResult::LeaseGrant(payload) => {
                PersistedResult::LeaseGrant(payload.clone())
            }
            CommittedSemanticResult::LeaseRenewed(payload) => {
                PersistedResult::LeaseRenewed(payload.clone())
            }
            CommittedSemanticResult::LeaseReleased(payload) => {
                PersistedResult::LeaseReleased(payload.clone())
            }
            CommittedSemanticResult::LeaseReject(payload) => {
                PersistedResult::LeaseReject(PersistedReject {
                    reason: payload.reason.clone(),
                })
            }
        };
        persisted.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<CommittedSemanticResult, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match PersistedResult::deserialize(deserializer)? {
            PersistedResult::LeaseGrant(payload) => {
                Ok(CommittedSemanticResult::LeaseGrant(payload))
            }
            PersistedResult::LeaseRenewed(payload) => {
                Ok(CommittedSemanticResult::LeaseRenewed(payload))
            }
            PersistedResult::LeaseReleased(payload) => {
                Ok(CommittedSemanticResult::LeaseReleased(payload))
            }
            PersistedResult::LeaseReject(payload) => {
                Ok(CommittedSemanticResult::LeaseReject(LeaseRejectPayload {
                    code: WitnessMutationOutcomeCode::PolicyReject,
                    reason: payload.reason,
                }))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationRequestIdentity {
    pub request_id: RequestId,
    pub requester_node_id: String,
    pub request_kind: MessageType,
    pub mutation_generation: u64,
    pub semantic_fingerprint: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalClassification {
    Duplicate { result: CommittedSemanticResult },
    Conflict,
    RetiredStale,
    NewEligible,
    GenerationGap,
}

#[derive(Debug)]
pub enum JournalError {
    NotMutatingRequest,
    InvalidRequest(WitnessStateError),
    InvalidResult,
    Serialization(String),
    JournalFull,
    Invariant(&'static str),
}

impl fmt::Display for JournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotMutatingRequest => write!(f, "message is not a mutating Witness request"),
            Self::InvalidRequest(error) => write!(f, "invalid Witness request: {error}"),
            Self::InvalidResult => write!(f, "committed result does not match request kind"),
            Self::Serialization(error) => write!(f, "fingerprint serialization failed: {error}"),
            Self::JournalFull => write!(f, "Witness idempotency journal is full"),
            Self::Invariant(error) => write!(f, "Witness journal invariant failed: {error}"),
        }
    }
}

impl std::error::Error for JournalError {}

pub fn request_identity(
    request: &UnsignedEnvelope,
) -> Result<MutationRequestIdentity, JournalError> {
    request.validate().map_err(|error| {
        JournalError::InvalidRequest(WitnessStateError::Parse(error.to_string()))
    })?;
    let request_kind = request.message.message_type();
    let mutation_generation = match &request.message {
        ProtocolMessage::LeaseRequest(payload) => payload.mutation_generation,
        ProtocolMessage::LeaseRenew(payload) => payload.mutation_generation,
        ProtocolMessage::LeaseRelease(payload) => payload.mutation_generation,
        _ => return Err(JournalError::NotMutatingRequest),
    };
    let request_id = request
        .common
        .request_id
        .clone()
        .ok_or(JournalError::NotMutatingRequest)?;
    Ok(MutationRequestIdentity {
        request_id,
        requester_node_id: request.common.sender_node_id.as_str().to_owned(),
        request_kind,
        mutation_generation,
        semantic_fingerprint: semantic_fingerprint(request)?,
    })
}

#[derive(Serialize)]
struct FingerprintInput {
    request_kind: MessageType,
    requester_node_id: String,
    semantic_payload: ProtocolMessage,
}

pub fn semantic_fingerprint(request: &UnsignedEnvelope) -> Result<[u8; 32], JournalError> {
    let request_kind = request.message.message_type();
    if !matches!(
        request_kind,
        MessageType::LeaseRequest | MessageType::LeaseRenew | MessageType::LeaseRelease
    ) {
        return Err(JournalError::NotMutatingRequest);
    }
    let input = FingerprintInput {
        request_kind,
        requester_node_id: request.common.sender_node_id.as_str().to_owned(),
        semantic_payload: request.message.clone(),
    };
    let bytes = cbor2::to_canonical_vec(&input)
        .map_err(|error| JournalError::Serialization(error.to_string()))?;
    let digest = Sha256::digest(bytes);
    Ok(digest.into())
}

pub fn classify(
    state: &WitnessPersistentState,
    request: &UnsignedEnvelope,
) -> Result<JournalClassification, JournalError> {
    let identity = request_identity(request)?;
    if let Some(record) = state
        .journal
        .iter()
        .find(|record| record.request_id == identity.request_id)
    {
        if record.requester_node_id == identity.requester_node_id
            && record.request_kind == identity.request_kind
            && record.mutation_generation == identity.mutation_generation
            && record.semantic_fingerprint == identity.semantic_fingerprint
        {
            return Ok(JournalClassification::Duplicate {
                result: record.result.clone(),
            });
        }
        return Ok(JournalClassification::Conflict);
    }

    let watermark = state
        .generation_watermarks
        .get(&identity.requester_node_id)
        .copied()
        .unwrap_or(0);
    if identity.mutation_generation <= watermark {
        return Ok(JournalClassification::RetiredStale);
    }
    if watermark < u64::MAX && identity.mutation_generation == watermark + 1 {
        return Ok(JournalClassification::NewEligible);
    }
    Ok(JournalClassification::GenerationGap)
}

pub fn commit_candidate(
    state: &WitnessPersistentState,
    request: &UnsignedEnvelope,
    result: CommittedSemanticResult,
) -> Result<WitnessPersistentState, JournalError> {
    let identity = request_identity(request)?;
    if !matches!(
        classify(state, request)?,
        JournalClassification::NewEligible
    ) {
        return Err(JournalError::Invariant("request is not NewEligible"));
    }
    match (&request.message, &result) {
        (ProtocolMessage::LeaseRequest(_), CommittedSemanticResult::LeaseGrant(_))
        | (ProtocolMessage::LeaseRequest(_), CommittedSemanticResult::LeaseReject(_))
        | (ProtocolMessage::LeaseRenew(_), CommittedSemanticResult::LeaseRenewed(_))
        | (ProtocolMessage::LeaseRenew(_), CommittedSemanticResult::LeaseReject(_))
        | (ProtocolMessage::LeaseRelease(_), CommittedSemanticResult::LeaseReleased(_))
        | (ProtocolMessage::LeaseRelease(_), CommittedSemanticResult::LeaseReject(_)) => {}
        _ => return Err(JournalError::InvalidResult),
    }

    let mut candidate = state.clone();
    if candidate.journal.len() >= JOURNAL_CAPACITY {
        let requester_watermarks = &candidate.generation_watermarks;
        let removable = candidate.journal.iter().position(|record| {
            requester_watermarks
                .get(&record.requester_node_id)
                .is_some_and(|watermark| record.mutation_generation <= *watermark)
        });
        let Some(index) = removable else {
            return Err(JournalError::JournalFull);
        };
        candidate.journal.remove(index);
    }
    candidate.journal.push(JournalRecord {
        request_id: identity.request_id,
        requester_node_id: identity.requester_node_id.clone(),
        request_kind: identity.request_kind,
        mutation_generation: identity.mutation_generation,
        semantic_fingerprint: identity.semantic_fingerprint,
        result,
    });
    candidate
        .generation_watermarks
        .insert(identity.requester_node_id, identity.mutation_generation);
    Ok(candidate)
}

pub fn validate_state(state: &WitnessPersistentState) -> Result<(), WitnessStateError> {
    if state.journal.len() > JOURNAL_CAPACITY {
        return Err(WitnessStateError::Invariant("journal exceeds capacity"));
    }
    for (index, record) in state.journal.iter().enumerate() {
        if !crate::protocol::is_valid_mutating_request_id(record.request_id.as_str())
            || record.requester_node_id.trim().is_empty()
        {
            return Err(WitnessStateError::Invariant("journal identity is invalid"));
        }
        if record.mutation_generation == 0 {
            return Err(WitnessStateError::Invariant("journal generation is zero"));
        }
        if state
            .journal
            .iter()
            .skip(index + 1)
            .any(|other| other.request_id == record.request_id)
        {
            return Err(WitnessStateError::Invariant("duplicate journal request_id"));
        }
        if state
            .generation_watermarks
            .get(&record.requester_node_id)
            .is_none_or(|watermark| record.mutation_generation > *watermark)
        {
            return Err(WitnessStateError::Invariant(
                "journal generation exceeds requester watermark",
            ));
        }
        if state.journal.iter().skip(index + 1).any(|other| {
            other.requester_node_id == record.requester_node_id
                && other.mutation_generation == record.mutation_generation
        }) {
            return Err(WitnessStateError::Invariant(
                "duplicate requester generation",
            ));
        }
        let result_matches = matches!(
            (&record.request_kind, &record.result),
            (
                MessageType::LeaseRequest,
                CommittedSemanticResult::LeaseGrant(_)
            ) | (
                MessageType::LeaseRequest,
                CommittedSemanticResult::LeaseReject(_)
            ) | (
                MessageType::LeaseRenew,
                CommittedSemanticResult::LeaseRenewed(_)
            ) | (
                MessageType::LeaseRenew,
                CommittedSemanticResult::LeaseReject(_)
            ) | (
                MessageType::LeaseRelease,
                CommittedSemanticResult::LeaseReleased(_)
            ) | (
                MessageType::LeaseRelease,
                CommittedSemanticResult::LeaseReject(_)
            )
        );
        if !result_matches {
            return Err(WitnessStateError::Invariant("journal result kind mismatch"));
        }
    }
    if state
        .generation_watermarks
        .iter()
        .any(|(requester, value)| requester.trim().is_empty() || *value == 0)
    {
        return Err(WitnessStateError::Invariant("watermark is zero"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        ClusterId, CommonFields, DurationMs, LeaseId, LeaseReleasePayload, LeaseRenewPayload,
        LeaseRequestPayload, NodeId, Sequence, SessionId, Term,
    };

    const REQUEST_ID: &str = "00000000-0000-4000-8000-000000000001";

    fn request(message: ProtocolMessage) -> UnsignedEnvelope {
        UnsignedEnvelope {
            common: CommonFields {
                protocol_version: crate::protocol::PROTOCOL_VERSION,
                cluster_id: ClusterId::new("cluster"),
                sender_node_id: NodeId::new("node-a"),
                receiver_node_id: NodeId::new("witness"),
                session_id: SessionId::new("session-a"),
                sequence: Sequence(1),
                term: Term(7),
                lease_id: None,
                request_id: Some(RequestId::new(REQUEST_ID)),
                operation_id: None,
            },
            message,
        }
    }

    fn lease_request(generation: u64) -> UnsignedEnvelope {
        request(ProtocolMessage::LeaseRequest(LeaseRequestPayload {
            mutation_generation: generation,
            observed_term: Term(7),
            priority: 100,
            requested_ttl: DurationMs(10_000),
        }))
    }

    fn empty_state() -> WitnessPersistentState {
        WitnessPersistentState::new(
            ClusterId::new("cluster"),
            crate::witness_state::BootId::new("boot-a"),
        )
    }

    fn reject() -> CommittedSemanticResult {
        CommittedSemanticResult::LeaseReject(crate::protocol::LeaseRejectPayload {
            code: crate::protocol::WitnessMutationOutcomeCode::PolicyReject,
            reason: "not ready".to_string(),
        })
    }

    #[test]
    fn fingerprints_ignore_transport_identity_but_cover_semantics() {
        let original = lease_request(1);
        let mut retry = original.clone();
        retry.common.session_id = SessionId::new("session-b");
        retry.common.sequence = Sequence(99);
        assert_eq!(
            semantic_fingerprint(&original).unwrap(),
            semantic_fingerprint(&retry).unwrap()
        );

        let mut changed = original.clone();
        if let ProtocolMessage::LeaseRequest(payload) = &mut changed.message {
            payload.priority = 101;
        }
        assert_ne!(
            semantic_fingerprint(&original).unwrap(),
            semantic_fingerprint(&changed).unwrap()
        );

        let mut generation = original.clone();
        if let ProtocolMessage::LeaseRequest(payload) = &mut generation.message {
            payload.mutation_generation = 2;
        }
        assert_ne!(
            semantic_fingerprint(&original).unwrap(),
            semantic_fingerprint(&generation).unwrap()
        );
    }

    #[test]
    fn classification_obeys_contiguous_watermark_rules() {
        let state = empty_state();
        assert_eq!(
            classify(&state, &lease_request(1)).unwrap(),
            JournalClassification::NewEligible
        );
        assert_eq!(
            classify(&state, &lease_request(2)).unwrap(),
            JournalClassification::GenerationGap
        );

        let mut state = state;
        state.generation_watermarks.insert("node-a".to_string(), 3);
        assert_eq!(
            classify(&state, &lease_request(1)).unwrap(),
            JournalClassification::RetiredStale
        );
        assert_eq!(
            classify(&state, &lease_request(3)).unwrap(),
            JournalClassification::RetiredStale
        );
        let mut next = lease_request(4);
        next.common.request_id = Some(RequestId::new("00000000-0000-4000-8000-000000000004"));
        assert_eq!(
            classify(&state, &next).unwrap(),
            JournalClassification::NewEligible
        );
        let mut gap = next.clone();
        if let ProtocolMessage::LeaseRequest(payload) = &mut gap.message {
            payload.mutation_generation = 5;
        }
        assert_eq!(
            classify(&state, &gap).unwrap(),
            JournalClassification::GenerationGap
        );
    }

    #[test]
    fn journal_hit_exact_is_duplicate_and_any_identity_change_is_conflict() {
        let state = commit_candidate(&empty_state(), &lease_request(1), reject()).unwrap();
        assert!(matches!(
            classify(&state, &lease_request(1)).unwrap(),
            JournalClassification::Duplicate { .. }
        ));

        let mut changed = lease_request(1);
        if let ProtocolMessage::LeaseRequest(payload) = &mut changed.message {
            payload.priority = 99;
        }
        assert_eq!(
            classify(&state, &changed).unwrap(),
            JournalClassification::Conflict
        );

        let mut different_generation = lease_request(1);
        if let ProtocolMessage::LeaseRequest(payload) = &mut different_generation.message {
            payload.mutation_generation = 2;
        }
        assert_eq!(
            classify(&state, &different_generation).unwrap(),
            JournalClassification::Conflict
        );
    }

    #[test]
    fn commit_advances_only_requester_watermark_and_persists_result() {
        let mut state = empty_state();
        state.generation_watermarks.insert("node-b".to_string(), 4);
        let candidate = commit_candidate(&state, &lease_request(1), reject()).unwrap();
        assert_eq!(candidate.generation_watermarks.get("node-a"), Some(&1));
        assert_eq!(candidate.generation_watermarks.get("node-b"), Some(&4));
        assert_eq!(candidate.journal.len(), 1);
        assert!(matches!(
            classify(&candidate, &lease_request(1)).unwrap(),
            JournalClassification::Duplicate { .. }
        ));
    }

    #[test]
    fn journal_capacity_is_hard_and_unsafe_space_returns_journal_full() {
        let mut state = empty_state();
        state.journal = (0..JOURNAL_CAPACITY)
            .map(|index| JournalRecord {
                request_id: RequestId::new(format!("old-{index}")),
                requester_node_id: "unknown-node".to_string(),
                request_kind: MessageType::LeaseRequest,
                mutation_generation: 1,
                semantic_fingerprint: [0; 32],
                result: reject(),
            })
            .collect();
        assert!(matches!(
            commit_candidate(&state, &lease_request(1), reject()),
            Err(JournalError::JournalFull)
        ));
        assert_eq!(state.journal.len(), JOURNAL_CAPACITY);
        assert!(state.generation_watermarks.is_empty());
    }

    #[test]
    fn all_mutating_request_kinds_have_semantic_fingerprints() {
        for message in [
            ProtocolMessage::LeaseRequest(LeaseRequestPayload {
                mutation_generation: 1,
                observed_term: Term(7),
                priority: 100,
                requested_ttl: DurationMs(10_000),
            }),
            ProtocolMessage::LeaseRenew(LeaseRenewPayload {
                mutation_generation: 1,
                term: Term(7),
                lease_id: LeaseId::new("lease-1"),
            }),
            ProtocolMessage::LeaseRelease(LeaseReleasePayload {
                mutation_generation: 1,
                term: Term(7),
                lease_id: LeaseId::new("lease-1"),
                reason: "test".to_string(),
            }),
        ] {
            assert!(semantic_fingerprint(&request(message)).is_ok());
        }
    }

    /// J35 (S-9 T-03, J32 a01 NV-2): the capacity eviction order. The exact
    /// replay of a committed LEASE_RELEASE is a Duplicate while at most 63
    /// later records exist and RetiredStale once 64 later records were
    /// committed (the oldest record is evicted first); the journal never
    /// exceeds 64 records.
    #[test]
    fn j35_fifo_eviction_order_at_the_capacity_boundary() {
        fn with(mut envelope: UnsignedEnvelope, node: &str, id: u64) -> UnsignedEnvelope {
            envelope.common.sender_node_id = NodeId::new(node);
            envelope.common.request_id =
                Some(RequestId::new(format!("00000000-0000-4000-8000-{id:012x}")));
            envelope
        }
        let release = with(
            request(ProtocolMessage::LeaseRelease(LeaseReleasePayload {
                mutation_generation: 1,
                term: Term(7),
                lease_id: LeaseId::new("lease-a"),
                reason: "j35".to_string(),
            })),
            "node-a",
            0xa,
        );
        for later in [0u64, 1, 62, 63, 64, 65] {
            let mut state = commit_candidate(&empty_state(), &release, reject()).unwrap();
            for generation in 1..=later {
                let other = with(lease_request(generation), "node-b", 0x1000 + generation);
                state = commit_candidate(&state, &other, reject()).unwrap();
                assert!(state.journal.len() <= JOURNAL_CAPACITY);
            }
            let duplicate = matches!(
                classify(&state, &release).unwrap(),
                JournalClassification::Duplicate { .. }
            );
            let retired = matches!(
                classify(&state, &release).unwrap(),
                JournalClassification::RetiredStale
            );
            assert_eq!(duplicate, later <= 63, "later={later}");
            assert_eq!(retired, later >= 64, "later={later}");
            // The release stays the oldest record until it is evicted.
            assert_eq!(
                state
                    .journal
                    .first()
                    .is_some_and(|record| record.requester_node_id == "node-a"),
                later <= 63,
                "later={later}"
            );
        }
    }
}
