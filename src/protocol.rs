use crate::state_machine::{NodeState, OperationPhase};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt;

pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterId(String);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeId(String);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionId(String);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseId(String);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestId(String);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationId(String);

macro_rules! string_id {
    ($name:ident) => {
        impl $name {
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

string_id!(ClusterId);
string_id!(NodeId);
string_id!(SessionId);
string_id!(LeaseId);
string_id!(RequestId);
string_id!(OperationId);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Term(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sequence(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurationMs(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    Active,
    Standby,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    Hello,
    HelloAck,
    Heartbeat,
    HeartbeatAck,
    StateAnnounce,
    StateAnnounceAck,
    PromotionIntent,
    PromotionAck,
    PromotionBlock,
    PromotionUnknown,
    PromotionCommitted,
    DemotionIntent,
    DemotionAck,
    DemotionCommitted,
    GetTerm,
    TermStatus,
    LeaseRequest,
    LeaseGrant,
    LeaseRenew,
    LeaseRenewed,
    LeaseRelease,
    LeaseReleased,
    LeaseReject,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommonFields {
    pub protocol_version: u32,
    pub cluster_id: ClusterId,
    pub sender_node_id: NodeId,
    pub receiver_node_id: NodeId,
    pub session_id: SessionId,
    pub sequence: Sequence,
    pub term: Term,
    pub lease_id: Option<LeaseId>,
    pub request_id: Option<RequestId>,
    pub operation_id: Option<OperationId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolMessage {
    Hello(HelloPayload),
    HelloAck,
    Heartbeat(NodeStatusPayload),
    HeartbeatAck,
    StateAnnounce(StateAnnouncePayload),
    StateAnnounceAck,
    PromotionIntent(PromotionIntentPayload),
    PromotionAck,
    PromotionBlock,
    PromotionUnknown,
    PromotionCommitted(ResourceStatusPayload),
    DemotionAck,
    DemotionIntent(DemotionIntentPayload),
    DemotionCommitted(DemotionCommittedPayload),
    GetTerm,
    TermStatus(TermStatusPayload),
    LeaseRequest(LeaseRequestPayload),
    LeaseGrant(LeaseGrantPayload),
    LeaseRenew(LeaseRenewPayload),
    LeaseRenewed(LeaseGrantPayload),
    LeaseRelease(LeaseReleasePayload),
    LeaseReleased(LeaseReleasedPayload),
    LeaseReject(LeaseRejectPayload),
}

impl ProtocolMessage {
    pub const fn message_type(&self) -> MessageType {
        match self {
            Self::Hello(_) => MessageType::Hello,
            Self::HelloAck => MessageType::HelloAck,
            Self::Heartbeat(_) => MessageType::Heartbeat,
            Self::HeartbeatAck => MessageType::HeartbeatAck,
            Self::StateAnnounce(_) => MessageType::StateAnnounce,
            Self::StateAnnounceAck => MessageType::StateAnnounceAck,
            Self::PromotionIntent(_) => MessageType::PromotionIntent,
            Self::PromotionAck => MessageType::PromotionAck,
            Self::PromotionBlock => MessageType::PromotionBlock,
            Self::PromotionUnknown => MessageType::PromotionUnknown,
            Self::PromotionCommitted(_) => MessageType::PromotionCommitted,
            Self::DemotionAck => MessageType::DemotionAck,
            Self::DemotionIntent(_) => MessageType::DemotionIntent,
            Self::DemotionCommitted(_) => MessageType::DemotionCommitted,
            Self::GetTerm => MessageType::GetTerm,
            Self::TermStatus(_) => MessageType::TermStatus,
            Self::LeaseRequest(_) => MessageType::LeaseRequest,
            Self::LeaseGrant(_) => MessageType::LeaseGrant,
            Self::LeaseRenew(_) => MessageType::LeaseRenew,
            Self::LeaseRenewed(_) => MessageType::LeaseRenewed,
            Self::LeaseRelease(_) => MessageType::LeaseRelease,
            Self::LeaseReleased(_) => MessageType::LeaseReleased,
            Self::LeaseReject(_) => MessageType::LeaseReject,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsignedEnvelope {
    pub common: CommonFields,
    pub message: ProtocolMessage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authentication {
    pub mac: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireMessage {
    pub unsigned: UnsignedEnvelope,
    pub authentication: Authentication,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloPayload {
    pub priority: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeStatusPayload {
    pub node_state: NodeState,
    pub operation_phase: Option<OperationPhase>,
    pub role: Role,
    pub service_state: String,
    pub health_state: String,
    pub vip_state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateAnnouncePayload {
    pub status: NodeStatusPayload,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionIntentPayload {
    pub priority: i32,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceStatusPayload {
    pub service_state: String,
    pub vip_state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemotionIntentPayload {
    pub phase: OperationPhase,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemotionCommittedPayload {
    pub service_stopped: bool,
    pub vip_released: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TermStatusPayload {
    pub current_term: Term,
    pub current_holder: Option<NodeId>,
    pub current_lease_id: Option<LeaseId>,
    pub lease_remaining_ms: Option<DurationMs>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseRequestPayload {
    pub mutation_generation: u64,
    pub observed_term: Term,
    pub priority: i32,
    pub requested_ttl: DurationMs,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseGrantPayload {
    pub term: Term,
    pub lease_id: LeaseId,
    pub holder_node_id: NodeId,
    pub lease_ttl_ms: DurationMs,
    pub renew_after_ms: DurationMs,
    pub lease_remaining_ms: DurationMs,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseRenewPayload {
    pub mutation_generation: u64,
    pub term: Term,
    pub lease_id: LeaseId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseReleasePayload {
    pub mutation_generation: u64,
    pub term: Term,
    pub lease_id: LeaseId,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseReleasedPayload {
    pub term: Term,
    pub lease_id: LeaseId,
    pub result: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WitnessMutationOutcomeCode {
    PolicyReject,
    RetiredStale,
    Conflict,
    GenerationGap,
    TemporarilyUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseRejectPayload {
    pub code: WitnessMutationOutcomeCode,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    InvalidVersion { actual: u32 },
    EmptyField(&'static str),
    InvalidFieldValue(&'static str),
    InvalidOperationPhase(MessageType),
    RequestIdRequired(MessageType),
    UnexpectedRequestId(MessageType),
    InvalidRequestId(MessageType),
    InvalidMutationGeneration(MessageType),
    OperationIdRequired(MessageType),
    UnexpectedOperationId(MessageType),
    TermStatusTermMismatch,
    TermStatusLeaseMismatch,
}

fn requires_request_id(message_type: MessageType) -> bool {
    matches!(
        message_type,
        MessageType::GetTerm
            | MessageType::TermStatus
            | MessageType::LeaseRequest
            | MessageType::LeaseGrant
            | MessageType::LeaseRenew
            | MessageType::LeaseRenewed
            | MessageType::LeaseRelease
            | MessageType::LeaseReleased
            | MessageType::LeaseReject
    )
}

fn validate_optional_id(field: &'static str, value: Option<&str>) -> Result<(), ProtocolError> {
    if value.is_some_and(|value| value.trim().is_empty()) {
        Err(ProtocolError::EmptyField(field))
    } else {
        Ok(())
    }
}

fn is_canonical_mutating_request_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 36
        || [8, 13, 18, 23]
            .into_iter()
            .any(|index| bytes.get(index) != Some(&b'-'))
    {
        return false;
    }
    if bytes.iter().enumerate().any(|(index, byte)| {
        if [8, 13, 18, 23].contains(&index) {
            false
        } else {
            !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase()
        }
    }) {
        return false;
    }
    if bytes[14] != b'4' || !matches!(bytes[19], b'8'..=b'9' | b'a'..=b'b') {
        return false;
    }
    !bytes
        .iter()
        .enumerate()
        .filter(|(index, _)| ![8, 13, 18, 23].contains(index))
        .all(|(_, byte)| *byte == b'0')
}

pub(crate) fn is_valid_mutating_request_id(value: &str) -> bool {
    is_canonical_mutating_request_id(value)
}

fn validate_mutating_request_id(
    message_type: MessageType,
    request_id: Option<&RequestId>,
) -> Result<(), ProtocolError> {
    if request_id.is_some_and(|id| !is_canonical_mutating_request_id(id.as_str())) {
        Err(ProtocolError::InvalidRequestId(message_type))
    } else {
        Ok(())
    }
}

fn validate_choice(
    field: &'static str,
    value: &str,
    choices: &[&str],
) -> Result<(), ProtocolError> {
    if choices.contains(&value) {
        Ok(())
    } else {
        Err(ProtocolError::InvalidFieldValue(field))
    }
}

fn validate_node_status(status: &NodeStatusPayload) -> Result<(), ProtocolError> {
    validate_choice(
        "service_state",
        &status.service_state,
        &["running", "stopped", "unknown"],
    )?;
    validate_choice(
        "health_state",
        &status.health_state,
        &["healthy", "unhealthy", "unknown"],
    )?;
    validate_choice(
        "vip_state",
        &status.vip_state,
        &["present", "absent", "unknown"],
    )
}

fn validate_resource_status(status: &ResourceStatusPayload) -> Result<(), ProtocolError> {
    validate_choice(
        "service_state",
        &status.service_state,
        &["running", "stopped", "unknown"],
    )?;
    validate_choice(
        "vip_state",
        &status.vip_state,
        &["present", "absent", "unknown"],
    )
}

fn validate_lease_release_result(result: &str) -> Result<(), ProtocolError> {
    validate_choice(
        "lease_release.result",
        result,
        &["released", "already_released", "unknown"],
    )
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVersion { actual } => {
                write!(f, "unsupported protocol version: {actual}")
            }
            Self::EmptyField(field) => write!(f, "protocol field must not be empty: {field}"),
            Self::InvalidFieldValue(field) => {
                write!(f, "protocol field has an invalid value: {field}")
            }
            Self::InvalidOperationPhase(message_type) => {
                write!(f, "invalid operation phase for {message_type:?}")
            }
            Self::RequestIdRequired(message_type) => {
                write!(f, "request_id is required for {message_type:?}")
            }
            Self::UnexpectedRequestId(message_type) => {
                write!(f, "request_id is not valid for {message_type:?}")
            }
            Self::InvalidRequestId(message_type) => {
                write!(
                    f,
                    "request_id is not a canonical UUIDv4 for {message_type:?}"
                )
            }
            Self::InvalidMutationGeneration(message_type) => {
                write!(
                    f,
                    "mutation_generation must be greater than zero for {message_type:?}"
                )
            }
            Self::OperationIdRequired(message_type) => {
                write!(f, "operation_id is required for {message_type:?}")
            }
            Self::UnexpectedOperationId(message_type) => {
                write!(f, "operation_id is not valid for {message_type:?}")
            }
            Self::TermStatusTermMismatch => {
                write!(f, "TERM_STATUS term fields do not match")
            }
            Self::TermStatusLeaseMismatch => {
                write!(f, "TERM_STATUS lease_id fields do not match")
            }
        }
    }
}

impl std::error::Error for ProtocolError {}

impl UnsignedEnvelope {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        let common = &self.common;
        if common.protocol_version != PROTOCOL_VERSION {
            return Err(ProtocolError::InvalidVersion {
                actual: common.protocol_version,
            });
        }
        for (field, value) in [
            ("cluster_id", common.cluster_id.as_str()),
            ("sender_node_id", common.sender_node_id.as_str()),
            ("receiver_node_id", common.receiver_node_id.as_str()),
            ("session_id", common.session_id.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(ProtocolError::EmptyField(field));
            }
        }

        validate_optional_id("lease_id", common.lease_id.as_ref().map(LeaseId::as_str))?;
        validate_optional_id(
            "request_id",
            common.request_id.as_ref().map(RequestId::as_str),
        )?;
        validate_optional_id(
            "operation_id",
            common.operation_id.as_ref().map(OperationId::as_str),
        )?;

        let message_type = self.message.message_type();
        let request_required = requires_request_id(message_type);
        if request_required && common.request_id.is_none() {
            return Err(ProtocolError::RequestIdRequired(message_type));
        }
        if !request_required && common.request_id.is_some() {
            return Err(ProtocolError::UnexpectedRequestId(message_type));
        }

        if matches!(
            message_type,
            MessageType::LeaseRequest | MessageType::LeaseRenew | MessageType::LeaseRelease
        ) {
            validate_mutating_request_id(message_type, common.request_id.as_ref())?;
        }

        let operation_required = matches!(
            self.message.message_type(),
            MessageType::PromotionIntent
                | MessageType::PromotionAck
                | MessageType::PromotionBlock
                | MessageType::PromotionUnknown
                | MessageType::PromotionCommitted
                | MessageType::DemotionIntent
                | MessageType::DemotionAck
                | MessageType::DemotionCommitted
        );
        if operation_required && common.operation_id.is_none() {
            return Err(ProtocolError::OperationIdRequired(message_type));
        }
        if !operation_required && common.operation_id.is_some() {
            return Err(ProtocolError::UnexpectedOperationId(message_type));
        }

        match &self.message {
            ProtocolMessage::TermStatus(payload) => {
                if common.term != payload.current_term {
                    return Err(ProtocolError::TermStatusTermMismatch);
                }
                if common.lease_id != payload.current_lease_id {
                    return Err(ProtocolError::TermStatusLeaseMismatch);
                }
            }
            ProtocolMessage::Heartbeat(status) => validate_node_status(status)?,
            ProtocolMessage::StateAnnounce(payload) => validate_node_status(&payload.status)?,
            ProtocolMessage::PromotionCommitted(status) => validate_resource_status(status)?,
            ProtocolMessage::DemotionIntent(payload)
                if matches!(payload.phase, OperationPhase::Promotion(_)) =>
            {
                return Err(ProtocolError::InvalidOperationPhase(message_type));
            }
            ProtocolMessage::LeaseReleased(payload) => {
                validate_lease_release_result(&payload.result)?;
            }
            ProtocolMessage::LeaseReject(payload) if payload.reason.trim().is_empty() => {
                return Err(ProtocolError::EmptyField("lease_reject.reason"));
            }
            ProtocolMessage::LeaseRequest(payload) if payload.mutation_generation == 0 => {
                return Err(ProtocolError::InvalidMutationGeneration(message_type));
            }
            ProtocolMessage::LeaseRenew(payload) if payload.mutation_generation == 0 => {
                return Err(ProtocolError::InvalidMutationGeneration(message_type));
            }
            ProtocolMessage::LeaseRelease(payload) if payload.mutation_generation == 0 => {
                return Err(ProtocolError::InvalidMutationGeneration(message_type));
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SerializationError {
    Encode(String),
    Decode(String),
    NonCanonical,
}

impl fmt::Display for SerializationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encode(message) => write!(f, "CBOR encode error: {message}"),
            Self::Decode(message) => write!(f, "CBOR decode error: {message}"),
            Self::NonCanonical => write!(f, "CBOR input is not canonical"),
        }
    }
}

impl std::error::Error for SerializationError {}

pub trait CanonicalSerializer {
    fn serialize_unsigned(&self, message: &UnsignedEnvelope)
    -> Result<Vec<u8>, SerializationError>;

    fn serialize_wire(&self, message: &WireMessage) -> Result<Vec<u8>, SerializationError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CborSerializer;

impl CborSerializer {
    pub fn deserialize_unsigned(
        &self,
        bytes: &[u8],
    ) -> Result<UnsignedEnvelope, SerializationError> {
        decode_canonical(bytes)
    }

    pub fn deserialize_wire(&self, bytes: &[u8]) -> Result<WireMessage, SerializationError> {
        decode_canonical(bytes)
    }
}

impl CanonicalSerializer for CborSerializer {
    fn serialize_unsigned(
        &self,
        message: &UnsignedEnvelope,
    ) -> Result<Vec<u8>, SerializationError> {
        cbor2::to_canonical_vec(message)
            .map_err(|error| SerializationError::Encode(error.to_string()))
    }

    fn serialize_wire(&self, message: &WireMessage) -> Result<Vec<u8>, SerializationError> {
        cbor2::to_canonical_vec(message)
            .map_err(|error| SerializationError::Encode(error.to_string()))
    }
}

fn decode_canonical<T>(bytes: &[u8]) -> Result<T, SerializationError>
where
    T: DeserializeOwned + Serialize,
{
    cbor2::validate_slice(bytes).map_err(|error| SerializationError::Decode(error.to_string()))?;
    let value =
        cbor2::from_slice(bytes).map_err(|error| SerializationError::Decode(error.to_string()))?;
    let canonical = cbor2::to_canonical_vec(&value)
        .map_err(|error| SerializationError::Encode(error.to_string()))?;
    if canonical != bytes {
        return Err(SerializationError::NonCanonical);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn common() -> CommonFields {
        CommonFields {
            protocol_version: PROTOCOL_VERSION,
            cluster_id: ClusterId::new("cluster"),
            sender_node_id: NodeId::new("node-a"),
            receiver_node_id: NodeId::new("node-b"),
            session_id: SessionId::new("process-session"),
            sequence: Sequence(1),
            term: Term(7),
            lease_id: None,
            request_id: None,
            operation_id: None,
        }
    }

    fn envelope(message: ProtocolMessage) -> UnsignedEnvelope {
        UnsignedEnvelope {
            common: common(),
            message,
        }
    }

    #[test]
    fn protocol_version_is_one() {
        assert_eq!(PROTOCOL_VERSION, 1);
    }

    #[test]
    fn node_state_is_reused_in_heartbeat_payload() {
        let message = ProtocolMessage::Heartbeat(NodeStatusPayload {
            node_state: NodeState::Standby,
            operation_phase: None,
            role: Role::Standby,
            service_state: "stopped".to_string(),
            health_state: "unknown".to_string(),
            vip_state: "absent".to_string(),
        });
        assert_eq!(message.message_type(), MessageType::Heartbeat);
    }

    #[test]
    fn all_message_variants_have_expected_types() {
        let messages = [
            (
                ProtocolMessage::Hello(HelloPayload { priority: 100 }),
                MessageType::Hello,
            ),
            (ProtocolMessage::HelloAck, MessageType::HelloAck),
            (
                ProtocolMessage::Heartbeat(heartbeat_payload()),
                MessageType::Heartbeat,
            ),
            (ProtocolMessage::HeartbeatAck, MessageType::HeartbeatAck),
            (
                ProtocolMessage::StateAnnounce(state_announce_payload()),
                MessageType::StateAnnounce,
            ),
            (
                ProtocolMessage::StateAnnounceAck,
                MessageType::StateAnnounceAck,
            ),
            (
                ProtocolMessage::PromotionIntent(promotion_intent_payload()),
                MessageType::PromotionIntent,
            ),
            (ProtocolMessage::PromotionAck, MessageType::PromotionAck),
            (ProtocolMessage::PromotionBlock, MessageType::PromotionBlock),
            (
                ProtocolMessage::PromotionUnknown,
                MessageType::PromotionUnknown,
            ),
            (
                ProtocolMessage::PromotionCommitted(resource_status_payload()),
                MessageType::PromotionCommitted,
            ),
            (
                ProtocolMessage::DemotionIntent(demotion_intent_payload()),
                MessageType::DemotionIntent,
            ),
            (ProtocolMessage::DemotionAck, MessageType::DemotionAck),
            (
                ProtocolMessage::DemotionCommitted(demotion_committed_payload()),
                MessageType::DemotionCommitted,
            ),
            (ProtocolMessage::GetTerm, MessageType::GetTerm),
            (
                ProtocolMessage::TermStatus(term_status_payload()),
                MessageType::TermStatus,
            ),
            (
                ProtocolMessage::LeaseRequest(lease_request_payload()),
                MessageType::LeaseRequest,
            ),
            (
                ProtocolMessage::LeaseGrant(lease_grant_payload()),
                MessageType::LeaseGrant,
            ),
            (
                ProtocolMessage::LeaseRenew(lease_renew_payload()),
                MessageType::LeaseRenew,
            ),
            (
                ProtocolMessage::LeaseRenewed(lease_grant_payload()),
                MessageType::LeaseRenewed,
            ),
            (
                ProtocolMessage::LeaseRelease(lease_release_payload()),
                MessageType::LeaseRelease,
            ),
            (
                ProtocolMessage::LeaseReleased(lease_released_payload()),
                MessageType::LeaseReleased,
            ),
            (
                ProtocolMessage::LeaseReject(lease_reject_payload()),
                MessageType::LeaseReject,
            ),
        ];

        for (message, expected_type) in messages {
            assert_eq!(message.message_type(), expected_type);
        }
    }

    #[test]
    fn valid_node_message_is_accepted() {
        let message = envelope(ProtocolMessage::Hello(HelloPayload { priority: 100 }));
        assert!(message.validate().is_ok());
    }

    #[test]
    fn valid_witness_message_requires_request_id() {
        let mut message = envelope(ProtocolMessage::GetTerm);
        message.common.request_id = Some(RequestId::new("00000000-0000-4000-8000-000000000001"));
        assert!(message.validate().is_ok());
    }

    #[test]
    fn term_status_requires_matching_common_authority_fields() {
        let payload = TermStatusPayload {
            current_term: Term(7),
            current_holder: Some(NodeId::new("node-a")),
            current_lease_id: Some(LeaseId::new("lease-1")),
            lease_remaining_ms: Some(DurationMs(3_000)),
        };
        let mut message = envelope(ProtocolMessage::TermStatus(payload.clone()));
        message.common.request_id = Some(RequestId::new("request-1"));
        message.common.term = Term(7);
        message.common.lease_id = Some(LeaseId::new("lease-1"));
        assert!(message.validate().is_ok());

        message.common.term = Term(8);
        assert!(matches!(
            message.validate(),
            Err(ProtocolError::TermStatusTermMismatch)
        ));
        message.common.term = Term(7);
        message.common.lease_id = Some(LeaseId::new("lease-2"));
        assert!(matches!(
            message.validate(),
            Err(ProtocolError::TermStatusLeaseMismatch)
        ));
    }

    #[test]
    fn witness_request_and_response_messages_require_request_id() {
        let messages = [
            ProtocolMessage::GetTerm,
            ProtocolMessage::TermStatus(term_status_payload()),
            ProtocolMessage::LeaseRequest(lease_request_payload()),
            ProtocolMessage::LeaseGrant(lease_grant_payload()),
            ProtocolMessage::LeaseRenew(lease_renew_payload()),
            ProtocolMessage::LeaseRenewed(lease_grant_payload()),
            ProtocolMessage::LeaseRelease(lease_release_payload()),
            ProtocolMessage::LeaseReleased(lease_released_payload()),
            ProtocolMessage::LeaseReject(lease_reject_payload()),
        ];

        for message in messages {
            let mut valid = envelope(message.clone());
            valid.common.request_id = Some(RequestId::new("00000000-0000-4000-8000-000000000001"));
            assert!(
                valid.validate().is_ok(),
                "valid {:?}",
                message.message_type()
            );

            let invalid = envelope(message);
            assert!(matches!(
                invalid.validate(),
                Err(ProtocolError::RequestIdRequired(_))
            ));
        }
    }

    #[test]
    fn lease_reject_outcome_codes_round_trip_and_validate() {
        let serializer = CborSerializer;
        let codes = [
            WitnessMutationOutcomeCode::PolicyReject,
            WitnessMutationOutcomeCode::RetiredStale,
            WitnessMutationOutcomeCode::Conflict,
            WitnessMutationOutcomeCode::GenerationGap,
            WitnessMutationOutcomeCode::TemporarilyUnavailable,
        ];

        for code in codes {
            let mut message = envelope(ProtocolMessage::LeaseReject(LeaseRejectPayload {
                code,
                reason: "diagnostic".to_string(),
            }));
            message.common.request_id =
                Some(RequestId::new("00000000-0000-4000-8000-000000000001"));
            assert!(message.validate().is_ok());
            let bytes = serializer.serialize_unsigned(&message).unwrap();
            if code == WitnessMutationOutcomeCode::PolicyReject {
                assert_eq!(
                    hex(&bytes),
                    "a266636f6d6d6f6eaa647465726d07686c656173655f6964f66873657175656e6365016a636c75737465725f696467636c75737465726a726571756573745f6964782430303030303030302d303030302d343030302d383030302d3030303030303030303030316a73657373696f6e5f69646f70726f636573732d73657373696f6e6c6f7065726174696f6e5f6964f66e73656e6465725f6e6f64655f6964666e6f64652d617070726f746f636f6c5f76657273696f6e017072656365697665725f6e6f64655f6964666e6f64652d62676d657373616765a16b4c6561736552656a656374a264636f64656c506f6c69637952656a65637466726561736f6e6a646961676e6f73746963"
                );
            }
            let decoded = serializer.deserialize_unsigned(&bytes).unwrap();
            assert_eq!(decoded, message);
        }
    }

    #[test]
    fn lease_reject_reason_must_not_be_empty() {
        let mut message = envelope(ProtocolMessage::LeaseReject(LeaseRejectPayload {
            code: WitnessMutationOutcomeCode::PolicyReject,
            reason: "   ".to_string(),
        }));
        message.common.request_id = Some(RequestId::new("00000000-0000-4000-8000-000000000001"));
        assert!(matches!(
            message.validate(),
            Err(ProtocolError::EmptyField("lease_reject.reason"))
        ));
    }

    #[test]
    fn rejects_version_mismatch() {
        let mut message = envelope(ProtocolMessage::Hello(HelloPayload { priority: 100 }));
        message.common.protocol_version = 2;
        assert!(matches!(
            message.validate(),
            Err(ProtocolError::InvalidVersion { actual: 2 })
        ));
    }

    #[test]
    fn rejects_empty_common_field() {
        let mut message = envelope(ProtocolMessage::Hello(HelloPayload { priority: 100 }));
        message.common.session_id = SessionId::new("   ");
        assert!(matches!(
            message.validate(),
            Err(ProtocolError::EmptyField("session_id"))
        ));
    }

    #[test]
    fn rejects_missing_request_id() {
        let message = envelope(ProtocolMessage::LeaseRenew(LeaseRenewPayload {
            mutation_generation: 1,
            term: Term(1),
            lease_id: LeaseId::new("lease-1"),
        }));
        assert!(matches!(
            message.validate(),
            Err(ProtocolError::RequestIdRequired(MessageType::LeaseRenew))
        ));
    }

    #[test]
    fn rejects_unexpected_request_id() {
        let mut message = envelope(ProtocolMessage::Hello(HelloPayload { priority: 100 }));
        message.common.request_id = Some(RequestId::new("00000000-0000-4000-8000-000000000001"));
        assert!(matches!(
            message.validate(),
            Err(ProtocolError::UnexpectedRequestId(MessageType::Hello))
        ));
    }

    #[test]
    fn requires_operation_id_for_promotion() {
        let message = envelope(ProtocolMessage::PromotionIntent(PromotionIntentPayload {
            priority: 100,
            reason: "planned".to_string(),
        }));
        assert!(matches!(
            message.validate(),
            Err(ProtocolError::OperationIdRequired(
                MessageType::PromotionIntent
            ))
        ));
    }

    #[test]
    fn rejects_unexpected_operation_id() {
        let mut message = envelope(ProtocolMessage::Hello(HelloPayload { priority: 100 }));
        message.common.operation_id = Some(OperationId::new("operation-1"));
        assert!(matches!(
            message.validate(),
            Err(ProtocolError::UnexpectedOperationId(MessageType::Hello))
        ));
    }

    #[test]
    fn operation_id_is_required_for_all_operation_messages() {
        let messages = [
            ProtocolMessage::PromotionIntent(promotion_intent_payload()),
            ProtocolMessage::PromotionAck,
            ProtocolMessage::PromotionBlock,
            ProtocolMessage::PromotionUnknown,
            ProtocolMessage::PromotionCommitted(resource_status_payload()),
            ProtocolMessage::DemotionIntent(demotion_intent_payload()),
            ProtocolMessage::DemotionAck,
            ProtocolMessage::DemotionCommitted(demotion_committed_payload()),
        ];

        for message in messages {
            let mut valid = envelope(message.clone());
            valid.common.operation_id = Some(OperationId::new("operation-1"));
            assert!(
                valid.validate().is_ok(),
                "valid {:?}",
                message.message_type()
            );

            let missing = envelope(message);
            assert!(matches!(
                missing.validate(),
                Err(ProtocolError::OperationIdRequired(_))
            ));
        }
    }

    #[test]
    fn rejects_empty_correlation_and_lease_ids() {
        for value in ["", "   "] {
            let mut request = envelope(ProtocolMessage::GetTerm);
            request.common.request_id = Some(RequestId::new(value));
            assert!(matches!(
                request.validate(),
                Err(ProtocolError::EmptyField("request_id"))
            ));

            let mut operation = envelope(ProtocolMessage::PromotionAck);
            operation.common.operation_id = Some(OperationId::new(value));
            assert!(matches!(
                operation.validate(),
                Err(ProtocolError::EmptyField("operation_id"))
            ));

            let mut lease = envelope(ProtocolMessage::HelloAck);
            lease.common.lease_id = Some(LeaseId::new(value));
            assert!(matches!(
                lease.validate(),
                Err(ProtocolError::EmptyField("lease_id"))
            ));
        }
    }

    #[test]
    fn mutating_witness_requests_require_canonical_uuidv4_request_ids() {
        let valid = "00000000-0000-4000-8000-000000000001";
        assert!(is_canonical_mutating_request_id(valid));

        for invalid in [
            "00000000-0000-1000-8000-000000000001",
            "00000000-0000-4000-0000-000000000001",
            "00000000-0000-0000-0000-000000000000",
            "00000000-0000-4000-8000-00000000001",
            "00000000000040008000000000000001",
            "{00000000-0000-4000-8000-000000000001}",
            "00000000-0000-4000-8000-000000000001 ",
            "00000000-0000-4000-8000-00000000000G",
            "00000000-0000-4000-c000-000000000001",
            "00000000-0000-4000-8000-00000000000A",
        ] {
            assert!(!is_canonical_mutating_request_id(invalid), "{invalid}");
        }
    }

    #[test]
    fn each_mutating_witness_request_rejects_invalid_request_id() {
        let messages = [
            ProtocolMessage::LeaseRequest(lease_request_payload()),
            ProtocolMessage::LeaseRenew(lease_renew_payload()),
            ProtocolMessage::LeaseRelease(lease_release_payload()),
        ];

        for message in messages {
            let mut envelope = envelope(message);
            envelope.common.request_id =
                Some(RequestId::new("00000000-0000-1000-8000-000000000001"));
            assert!(matches!(
                envelope.validate(),
                Err(ProtocolError::InvalidRequestId(_))
            ));
        }
    }

    #[test]
    fn mutating_witness_requests_reject_zero_generation_and_accept_maximum() {
        let messages = [
            ProtocolMessage::LeaseRequest(lease_request_payload()),
            ProtocolMessage::LeaseRenew(lease_renew_payload()),
            ProtocolMessage::LeaseRelease(lease_release_payload()),
        ];

        for message in messages {
            let mut valid = envelope(message.clone());
            valid.common.request_id = Some(RequestId::new("00000000-0000-4000-8000-000000000001"));
            assert!(valid.validate().is_ok());

            let mut zero = valid.clone();
            match &mut zero.message {
                ProtocolMessage::LeaseRequest(payload) => payload.mutation_generation = 0,
                ProtocolMessage::LeaseRenew(payload) => payload.mutation_generation = 0,
                ProtocolMessage::LeaseRelease(payload) => payload.mutation_generation = 0,
                _ => unreachable!(),
            }
            assert!(matches!(
                zero.validate(),
                Err(ProtocolError::InvalidMutationGeneration(_))
            ));

            let mut maximum = valid;
            match &mut maximum.message {
                ProtocolMessage::LeaseRequest(payload) => payload.mutation_generation = u64::MAX,
                ProtocolMessage::LeaseRenew(payload) => payload.mutation_generation = u64::MAX,
                ProtocolMessage::LeaseRelease(payload) => payload.mutation_generation = u64::MAX,
                _ => unreachable!(),
            }
            assert!(maximum.validate().is_ok());
        }
    }

    #[test]
    fn mutating_witness_requests_round_trip_generation_in_canonical_cbor() {
        let serializer = CborSerializer;
        let request_id = RequestId::new("00000000-0000-4000-8000-000000000001");
        let messages = [
            ProtocolMessage::LeaseRequest(lease_request_payload()),
            ProtocolMessage::LeaseRenew(lease_renew_payload()),
            ProtocolMessage::LeaseRelease(lease_release_payload()),
        ];

        for message in messages {
            let mut envelope = envelope(message);
            envelope.common.request_id = Some(request_id.clone());
            let bytes = serializer.serialize_unsigned(&envelope).unwrap();
            let decoded = serializer.deserialize_unsigned(&bytes).unwrap();
            assert_eq!(decoded, envelope);
            assert_eq!(serializer.serialize_unsigned(&decoded).unwrap(), bytes);
        }
    }

    #[test]
    fn validates_demotion_intent_phase() {
        let mut valid = envelope(ProtocolMessage::DemotionIntent(demotion_intent_payload()));
        valid.common.operation_id = Some(OperationId::new("operation-1"));
        assert!(valid.validate().is_ok());

        let mut invalid = valid.clone();
        invalid.message = ProtocolMessage::DemotionIntent(DemotionIntentPayload {
            phase: OperationPhase::Promotion(crate::state_machine::PromotionPhase::AcquireVip),
            reason: "test".to_string(),
        });
        assert!(matches!(
            invalid.validate(),
            Err(ProtocolError::InvalidOperationPhase(
                MessageType::DemotionIntent
            ))
        ));
    }

    #[test]
    fn validates_protocol_state_vocabularies() {
        for value in ["running", "stopped", "unknown"] {
            let mut message = envelope(ProtocolMessage::Heartbeat(heartbeat_payload()));
            if let ProtocolMessage::Heartbeat(status) = &mut message.message {
                status.service_state = value.to_string();
            }
            assert!(message.validate().is_ok());
        }

        for value in ["healthy", "unhealthy", "unknown"] {
            let mut message = envelope(ProtocolMessage::Heartbeat(heartbeat_payload()));
            if let ProtocolMessage::Heartbeat(status) = &mut message.message {
                status.health_state = value.to_string();
            }
            assert!(message.validate().is_ok());
        }

        for value in ["present", "absent", "unknown"] {
            let mut message = envelope(ProtocolMessage::Heartbeat(heartbeat_payload()));
            if let ProtocolMessage::Heartbeat(status) = &mut message.message {
                status.vip_state = value.to_string();
            }
            assert!(message.validate().is_ok());
        }

        for value in ["running", "stopped", "unknown"] {
            let mut message = envelope(ProtocolMessage::PromotionCommitted(
                resource_status_payload(),
            ));
            message.common.operation_id = Some(OperationId::new("operation-1"));
            if let ProtocolMessage::PromotionCommitted(status) = &mut message.message {
                status.service_state = value.to_string();
            }
            assert!(message.validate().is_ok());
        }

        for (field, value) in [
            ("service", "invalid"),
            ("health", "HEALTHY"),
            ("vip", ""),
            ("resource_service", "invalid"),
            ("resource_vip", "invalid"),
        ] {
            let mut message = if field.starts_with("resource") {
                let mut message = envelope(ProtocolMessage::PromotionCommitted(
                    resource_status_payload(),
                ));
                message.common.operation_id = Some(OperationId::new("operation-1"));
                message
            } else {
                envelope(ProtocolMessage::Heartbeat(heartbeat_payload()))
            };
            match &mut message.message {
                ProtocolMessage::Heartbeat(status) => match field {
                    "service" => status.service_state = value.to_string(),
                    "health" => status.health_state = value.to_string(),
                    _ => status.vip_state = value.to_string(),
                },
                ProtocolMessage::PromotionCommitted(status) => match field {
                    "resource_service" => status.service_state = value.to_string(),
                    _ => status.vip_state = value.to_string(),
                },
                _ => unreachable!(),
            }
            assert!(matches!(
                message.validate(),
                Err(ProtocolError::InvalidFieldValue(_))
            ));
        }
    }

    #[test]
    fn validates_lease_release_result_vocabulary() {
        for value in ["released", "already_released", "unknown"] {
            let mut message = envelope(ProtocolMessage::LeaseReleased(LeaseReleasedPayload {
                term: Term(1),
                lease_id: LeaseId::new("lease-1"),
                result: value.to_string(),
            }));
            message.common.request_id =
                Some(RequestId::new("00000000-0000-4000-8000-000000000001"));
            assert!(message.validate().is_ok());
        }

        for value in ["RELEASED", "success", "failed", ""] {
            let mut message = envelope(ProtocolMessage::LeaseReleased(LeaseReleasedPayload {
                term: Term(1),
                lease_id: LeaseId::new("lease-1"),
                result: value.to_string(),
            }));
            message.common.request_id = Some(RequestId::new("request-1"));
            assert!(matches!(
                message.validate(),
                Err(ProtocolError::InvalidFieldValue("lease_release.result"))
            ));
        }
    }

    #[test]
    fn authentication_is_outside_unsigned_envelope() {
        let unsigned = envelope(ProtocolMessage::Hello(HelloPayload { priority: 100 }));
        let wire = WireMessage {
            unsigned: unsigned.clone(),
            authentication: Authentication { mac: [0; 32] },
        };
        assert_eq!(wire.unsigned, unsigned);
    }

    #[test]
    fn identifiers_are_not_interchangeable() {
        let session = SessionId::new("id");
        let lease = LeaseId::new("id");
        assert_eq!(session.as_str(), lease.as_str());
        // The distinct types prevent assigning one identifier kind to the other.
    }

    #[test]
    fn fixed_canonical_serialization_vectors() {
        let serializer = CborSerializer;
        let hello = envelope(ProtocolMessage::Hello(HelloPayload { priority: 100 }));
        let mut lease_request = envelope(ProtocolMessage::LeaseRequest(LeaseRequestPayload {
            mutation_generation: 1,
            observed_term: Term(7),
            priority: 100,
            requested_ttl: DurationMs(10_000),
        }));
        lease_request.common.request_id =
            Some(RequestId::new("00000000-0000-4000-8000-000000000001"));
        let wire = WireMessage {
            unsigned: hello.clone(),
            authentication: Authentication { mac: [0xabu8; 32] },
        };
        assert_eq!(
            hex(&serializer.serialize_unsigned(&hello).unwrap()),
            "a266636f6d6d6f6eaa647465726d07686c656173655f6964f66873657175656e6365016a636c75737465725f696467636c75737465726a726571756573745f6964f66a73657373696f6e5f69646f70726f636573732d73657373696f6e6c6f7065726174696f6e5f6964f66e73656e6465725f6e6f64655f6964666e6f64652d617070726f746f636f6c5f76657273696f6e017072656365697665725f6e6f64655f6964666e6f64652d62676d657373616765a16548656c6c6fa1687072696f726974791864"
        );
        assert_eq!(
            hex(&serializer.serialize_unsigned(&lease_request).unwrap()),
            "a266636f6d6d6f6eaa647465726d07686c656173655f6964f66873657175656e6365016a636c75737465725f696467636c75737465726a726571756573745f6964782430303030303030302d303030302d343030302d383030302d3030303030303030303030316a73657373696f6e5f69646f70726f636573732d73657373696f6e6c6f7065726174696f6e5f6964f66e73656e6465725f6e6f64655f6964666e6f64652d617070726f746f636f6c5f76657273696f6e017072656365697665725f6e6f64655f6964666e6f64652d62676d657373616765a16c4c6561736552657175657374a4687072696f7269747918646d6f627365727665645f7465726d076d7265717565737465645f74746c192710736d75746174696f6e5f67656e65726174696f6e01"
        );
        let mut expected_wire = decode_hex(
            "a268756e7369676e6564a266636f6d6d6f6eaa647465726d07686c656173655f6964f66873657175656e6365016a636c75737465725f696467636c75737465726a726571756573745f6964f66a73657373696f6e5f69646f70726f636573732d73657373696f6e6c6f7065726174696f6e5f6964f66e73656e6465725f6e6f64655f6964666e6f64652d617070726f746f636f6c5f76657273696f6e017072656365697665725f6e6f64655f6964666e6f64652d62676d657373616765a16548656c6c6fa1687072696f7269747918646e61757468656e7469636174696f6ea1636d61639820",
        );
        for _ in 0..32 {
            expected_wire.extend([0x18, 0xab]);
        }
        assert_eq!(serializer.serialize_wire(&wire).unwrap(), expected_wire);
    }

    // ---- Phase 14.11 remediation L3: the complete wire-shape pin ----

    fn full_common() -> CommonFields {
        CommonFields {
            protocol_version: PROTOCOL_VERSION,
            cluster_id: ClusterId::new("cluster"),
            sender_node_id: NodeId::new("node-a"),
            receiver_node_id: NodeId::new("node-b"),
            session_id: SessionId::new("process-session"),
            sequence: Sequence(1),
            term: Term(7),
            lease_id: Some(LeaseId::new("lease-1")),
            request_id: Some(RequestId::new("request-1")),
            operation_id: Some(OperationId::new("operation-1")),
        }
    }

    fn node_status() -> NodeStatusPayload {
        NodeStatusPayload {
            node_state: NodeState::Active,
            operation_phase: Some(OperationPhase::Promotion(
                crate::state_machine::PromotionPhase::CommitActive,
            )),
            role: Role::Active,
            service_state: "running".to_string(),
            health_state: "healthy".to_string(),
            vip_state: "present".to_string(),
        }
    }

    fn lease_grant() -> LeaseGrantPayload {
        LeaseGrantPayload {
            term: Term(8),
            lease_id: LeaseId::new("lease-2"),
            holder_node_id: NodeId::new("node-a"),
            lease_ttl_ms: DurationMs(10_000),
            renew_after_ms: DurationMs(3_000),
            lease_remaining_ms: DurationMs(9_000),
        }
    }

    /// One fully populated value for every `ProtocolMessage` variant, in
    /// declaration order. Every payload field is set to a distinct value so
    /// that a renamed, dropped, added, or re-shaped field changes the bytes.
    fn every_protocol_message() -> Vec<(&'static str, ProtocolMessage)> {
        vec![
            (
                "Hello",
                ProtocolMessage::Hello(HelloPayload { priority: 100 }),
            ),
            ("HelloAck", ProtocolMessage::HelloAck),
            ("Heartbeat", ProtocolMessage::Heartbeat(node_status())),
            ("HeartbeatAck", ProtocolMessage::HeartbeatAck),
            (
                "StateAnnounce",
                ProtocolMessage::StateAnnounce(StateAnnouncePayload {
                    status: node_status(),
                    reason: "announce".to_string(),
                }),
            ),
            ("StateAnnounceAck", ProtocolMessage::StateAnnounceAck),
            (
                "PromotionIntent",
                ProtocolMessage::PromotionIntent(PromotionIntentPayload {
                    priority: 90,
                    reason: "intent".to_string(),
                }),
            ),
            ("PromotionAck", ProtocolMessage::PromotionAck),
            ("PromotionBlock", ProtocolMessage::PromotionBlock),
            ("PromotionUnknown", ProtocolMessage::PromotionUnknown),
            (
                "PromotionCommitted",
                ProtocolMessage::PromotionCommitted(ResourceStatusPayload {
                    service_state: "running".to_string(),
                    vip_state: "present".to_string(),
                }),
            ),
            ("DemotionAck", ProtocolMessage::DemotionAck),
            (
                "DemotionIntent",
                ProtocolMessage::DemotionIntent(DemotionIntentPayload {
                    phase: OperationPhase::Demotion(
                        crate::state_machine::DemotionPhase::ReleaseVip,
                    ),
                    reason: "demote".to_string(),
                }),
            ),
            (
                "DemotionCommitted",
                ProtocolMessage::DemotionCommitted(DemotionCommittedPayload {
                    service_stopped: true,
                    vip_released: false,
                }),
            ),
            ("GetTerm", ProtocolMessage::GetTerm),
            (
                "TermStatus",
                ProtocolMessage::TermStatus(TermStatusPayload {
                    current_term: Term(7),
                    current_holder: Some(NodeId::new("node-b")),
                    current_lease_id: Some(LeaseId::new("lease-1")),
                    lease_remaining_ms: Some(DurationMs(4_000)),
                }),
            ),
            (
                "LeaseRequest",
                ProtocolMessage::LeaseRequest(LeaseRequestPayload {
                    mutation_generation: 5,
                    observed_term: Term(7),
                    priority: 100,
                    requested_ttl: DurationMs(10_000),
                }),
            ),
            ("LeaseGrant", ProtocolMessage::LeaseGrant(lease_grant())),
            (
                "LeaseRenew",
                ProtocolMessage::LeaseRenew(LeaseRenewPayload {
                    mutation_generation: 6,
                    term: Term(8),
                    lease_id: LeaseId::new("lease-2"),
                }),
            ),
            ("LeaseRenewed", ProtocolMessage::LeaseRenewed(lease_grant())),
            (
                "LeaseRelease",
                ProtocolMessage::LeaseRelease(LeaseReleasePayload {
                    mutation_generation: 7,
                    term: Term(8),
                    lease_id: LeaseId::new("lease-2"),
                    reason: "release".to_string(),
                }),
            ),
            (
                "LeaseReleased",
                ProtocolMessage::LeaseReleased(LeaseReleasedPayload {
                    term: Term(8),
                    lease_id: LeaseId::new("lease-2"),
                    result: "released".to_string(),
                }),
            ),
            (
                "LeaseReject",
                ProtocolMessage::LeaseReject(LeaseRejectPayload {
                    code: WitnessMutationOutcomeCode::Conflict,
                    reason: "conflict".to_string(),
                }),
            ),
        ]
    }

    /// Every nested wire enum value (each variant of `NodeState`, `Role`,
    /// `PromotionPhase`, `DemotionPhase`, and `WitnessMutationOutcomeCode`,
    /// and both `OperationPhase` arms), serialized alone. The exhaustive
    /// matches make a new variant a compile error here.
    fn every_nested_wire_enum() -> Vec<(String, Vec<u8>)> {
        use crate::state_machine::{DemotionPhase as D, PromotionPhase as P};
        let mut out: Vec<(String, Vec<u8>)> = Vec::new();
        let mut put = |name: &str, bytes: Vec<u8>| {
            out.push((name.to_string(), bytes));
        };
        for v in [
            NodeState::Init,
            NodeState::Standby,
            NodeState::Candidate,
            NodeState::Active,
            NodeState::Degraded,
            NodeState::Isolated,
            NodeState::QuorumUnknown,
            NodeState::RecoveryPending,
            NodeState::Maintenance,
            NodeState::Failed,
        ] {
            match v {
                NodeState::Init
                | NodeState::Standby
                | NodeState::Candidate
                | NodeState::Active
                | NodeState::Degraded
                | NodeState::Isolated
                | NodeState::QuorumUnknown
                | NodeState::RecoveryPending
                | NodeState::Maintenance
                | NodeState::Failed => {}
            }
            put(
                &format!("NodeState::{v:?}"),
                cbor2::to_canonical_vec(&v).unwrap(),
            );
        }
        for v in [Role::Active, Role::Standby] {
            match v {
                Role::Active | Role::Standby => {}
            }
            put(
                &format!("Role::{v:?}"),
                cbor2::to_canonical_vec(&v).unwrap(),
            );
        }
        for v in [
            P::CheckPromotionGuard,
            P::AcquireLease,
            P::AcquireVip,
            P::StartService,
            P::WaitForHealth,
            P::AnnounceGratuitousArp,
            P::CommitActive,
            P::Rollback,
        ] {
            match v {
                P::CheckPromotionGuard
                | P::AcquireLease
                | P::AcquireVip
                | P::StartService
                | P::WaitForHealth
                | P::AnnounceGratuitousArp
                | P::CommitActive
                | P::Rollback => {}
            }
            put(
                &format!("OperationPhase::Promotion({v:?})"),
                cbor2::to_canonical_vec(&OperationPhase::Promotion(v)).unwrap(),
            );
        }
        for v in [
            D::StopService,
            D::ConfirmServiceStopped,
            D::ReleaseVip,
            D::ConfirmVipReleased,
            D::ReleaseLease,
            D::CommitStandby,
        ] {
            match v {
                D::StopService
                | D::ConfirmServiceStopped
                | D::ReleaseVip
                | D::ConfirmVipReleased
                | D::ReleaseLease
                | D::CommitStandby => {}
            }
            put(
                &format!("OperationPhase::Demotion({v:?})"),
                cbor2::to_canonical_vec(&OperationPhase::Demotion(v)).unwrap(),
            );
        }
        for v in [
            WitnessMutationOutcomeCode::PolicyReject,
            WitnessMutationOutcomeCode::RetiredStale,
            WitnessMutationOutcomeCode::Conflict,
            WitnessMutationOutcomeCode::GenerationGap,
            WitnessMutationOutcomeCode::TemporarilyUnavailable,
        ] {
            match v {
                WitnessMutationOutcomeCode::PolicyReject
                | WitnessMutationOutcomeCode::RetiredStale
                | WitnessMutationOutcomeCode::Conflict
                | WitnessMutationOutcomeCode::GenerationGap
                | WitnessMutationOutcomeCode::TemporarilyUnavailable => {}
            }
            put(
                &format!("WitnessMutationOutcomeCode::{v:?}"),
                cbor2::to_canonical_vec(&v).unwrap(),
            );
        }
        out
    }

    /// The canonical CBOR of `CommonFields` with every optional field absent
    /// and present. Golden bytes: the wire representation of the Stage 10
    /// baseline, which Stage 14 must not change.
    const GOLDEN_COMMON_NONE: &str = concat!(
        "aa647465726d07686c656173655f6964f66873657175656e6365016a636c75737465725f696467636c757374",
        "65726a726571756573745f6964f66a73657373696f6e5f69646f70726f636573732d73657373696f6e6c6f70",
        "65726174696f6e5f6964f66e73656e6465725f6e6f64655f6964666e6f64652d617070726f746f636f6c5f76",
        "657273696f6e017072656365697665725f6e6f64655f6964666e6f64652d62",
    );
    const GOLDEN_COMMON_FULL: &str = concat!(
        "aa647465726d07686c656173655f6964676c656173652d316873657175656e6365016a636c75737465725f69",
        "6467636c75737465726a726571756573745f696469726571756573742d316a73657373696f6e5f69646f7072",
        "6f636573732d73657373696f6e6c6f7065726174696f6e5f69646b6f7065726174696f6e2d316e73656e6465",
        "725f6e6f64655f6964666e6f64652d617070726f746f636f6c5f76657273696f6e017072656365697665725f",
        "6e6f64655f6964666e6f64652d62",
    );

    /// The canonical CBOR of each `ProtocolMessage` variant (externally tagged
    /// by variant name), from `every_protocol_message`.
    const GOLDEN_MESSAGES: [(&str, &str); 23] = [
        ("Hello", "a16548656c6c6fa1687072696f726974791864"),
        ("HelloAck", "6848656c6c6f41636b"),
        (
            "Heartbeat",
            concat!(
                "a169486561727462656174a664726f6c6566416374697665697669705f73746174656770726573656e746a6e",
                "6f64655f7374617465664163746976656c6865616c74685f7374617465676865616c7468796d736572766963",
                "655f73746174656772756e6e696e676f6f7065726174696f6e5f7068617365a16950726f6d6f74696f6e6c43",
                "6f6d6d6974416374697665",
            ),
        ),
        ("HeartbeatAck", "6c48656172746265617441636b"),
        (
            "StateAnnounce",
            concat!(
                "a16d5374617465416e6e6f756e6365a266726561736f6e68616e6e6f756e636566737461747573a664726f6c",
                "6566416374697665697669705f73746174656770726573656e746a6e6f64655f737461746566416374697665",
                "6c6865616c74685f7374617465676865616c7468796d736572766963655f73746174656772756e6e696e676f",
                "6f7065726174696f6e5f7068617365a16950726f6d6f74696f6e6c436f6d6d6974416374697665",
            ),
        ),
        ("StateAnnounceAck", "705374617465416e6e6f756e636541636b"),
        (
            "PromotionIntent",
            "a16f50726f6d6f74696f6e496e74656e74a266726561736f6e66696e74656e74687072696f72697479185a",
        ),
        ("PromotionAck", "6c50726f6d6f74696f6e41636b"),
        ("PromotionBlock", "6e50726f6d6f74696f6e426c6f636b"),
        ("PromotionUnknown", "7050726f6d6f74696f6e556e6b6e6f776e"),
        (
            "PromotionCommitted",
            concat!(
                "a17250726f6d6f74696f6e436f6d6d6974746564a2697669705f73746174656770726573656e746d73657276",
                "6963655f73746174656772756e6e696e67",
            ),
        ),
        ("DemotionAck", "6b44656d6f74696f6e41636b"),
        (
            "DemotionIntent",
            concat!(
                "a16e44656d6f74696f6e496e74656e74a2657068617365a16844656d6f74696f6e6a52656c65617365566970",
                "66726561736f6e6664656d6f7465",
            ),
        ),
        (
            "DemotionCommitted",
            concat!(
                "a17144656d6f74696f6e436f6d6d6974746564a26c7669705f72656c6561736564f46f736572766963655f73",
                "746f70706564f5",
            ),
        ),
        ("GetTerm", "674765745465726d"),
        (
            "TermStatus",
            concat!(
                "a16a5465726d537461747573a46c63757272656e745f7465726d076e63757272656e745f686f6c646572666e",
                "6f64652d627063757272656e745f6c656173655f6964676c656173652d31726c656173655f72656d61696e69",
                "6e675f6d73190fa0",
            ),
        ),
        (
            "LeaseRequest",
            concat!(
                "a16c4c6561736552657175657374a4687072696f7269747918646d6f627365727665645f7465726d076d7265",
                "717565737465645f74746c192710736d75746174696f6e5f67656e65726174696f6e05",
            ),
        ),
        (
            "LeaseGrant",
            concat!(
                "a16a4c656173654772616e74a6647465726d08686c656173655f6964676c656173652d326c6c656173655f74",
                "746c5f6d731927106e686f6c6465725f6e6f64655f6964666e6f64652d616e72656e65775f61667465725f6d",
                "73190bb8726c656173655f72656d61696e696e675f6d73192328",
            ),
        ),
        (
            "LeaseRenew",
            concat!(
                "a16a4c6561736552656e6577a3647465726d08686c656173655f6964676c656173652d32736d75746174696f",
                "6e5f67656e65726174696f6e06",
            ),
        ),
        (
            "LeaseRenewed",
            concat!(
                "a16c4c6561736552656e65776564a6647465726d08686c656173655f6964676c656173652d326c6c65617365",
                "5f74746c5f6d731927106e686f6c6465725f6e6f64655f6964666e6f64652d616e72656e65775f6166746572",
                "5f6d73190bb8726c656173655f72656d61696e696e675f6d73192328",
            ),
        ),
        (
            "LeaseRelease",
            concat!(
                "a16c4c6561736552656c65617365a4647465726d0866726561736f6e6772656c65617365686c656173655f69",
                "64676c656173652d32736d75746174696f6e5f67656e65726174696f6e07",
            ),
        ),
        (
            "LeaseReleased",
            concat!(
                "a16d4c6561736552656c6561736564a3647465726d0866726573756c746872656c6561736564686c65617365",
                "5f6964676c656173652d32",
            ),
        ),
        (
            "LeaseReject",
            "a16b4c6561736552656a656374a264636f646568436f6e666c69637466726561736f6e68636f6e666c696374",
        ),
    ];

    /// The canonical CBOR of every nested wire enum value.
    const GOLDEN_ENUMS: [(&str, &str); 31] = [
        ("NodeState::Init", "64496e6974"),
        ("NodeState::Standby", "675374616e646279"),
        ("NodeState::Candidate", "6943616e646964617465"),
        ("NodeState::Active", "66416374697665"),
        ("NodeState::Degraded", "684465677261646564"),
        ("NodeState::Isolated", "6849736f6c61746564"),
        ("NodeState::QuorumUnknown", "6d51756f72756d556e6b6e6f776e"),
        (
            "NodeState::RecoveryPending",
            "6f5265636f7665727950656e64696e67",
        ),
        ("NodeState::Maintenance", "6b4d61696e74656e616e6365"),
        ("NodeState::Failed", "664661696c6564"),
        ("Role::Active", "66416374697665"),
        ("Role::Standby", "675374616e646279"),
        (
            "OperationPhase::Promotion(CheckPromotionGuard)",
            "a16950726f6d6f74696f6e73436865636b50726f6d6f74696f6e4775617264",
        ),
        (
            "OperationPhase::Promotion(AcquireLease)",
            "a16950726f6d6f74696f6e6c416371756972654c65617365",
        ),
        (
            "OperationPhase::Promotion(AcquireVip)",
            "a16950726f6d6f74696f6e6a41637175697265566970",
        ),
        (
            "OperationPhase::Promotion(StartService)",
            "a16950726f6d6f74696f6e6c537461727453657276696365",
        ),
        (
            "OperationPhase::Promotion(WaitForHealth)",
            "a16950726f6d6f74696f6e6d57616974466f724865616c7468",
        ),
        (
            "OperationPhase::Promotion(AnnounceGratuitousArp)",
            "a16950726f6d6f74696f6e75416e6e6f756e6365477261747569746f7573417270",
        ),
        (
            "OperationPhase::Promotion(CommitActive)",
            "a16950726f6d6f74696f6e6c436f6d6d6974416374697665",
        ),
        (
            "OperationPhase::Promotion(Rollback)",
            "a16950726f6d6f74696f6e68526f6c6c6261636b",
        ),
        (
            "OperationPhase::Demotion(StopService)",
            "a16844656d6f74696f6e6b53746f7053657276696365",
        ),
        (
            "OperationPhase::Demotion(ConfirmServiceStopped)",
            "a16844656d6f74696f6e75436f6e6669726d5365727669636553746f70706564",
        ),
        (
            "OperationPhase::Demotion(ReleaseVip)",
            "a16844656d6f74696f6e6a52656c65617365566970",
        ),
        (
            "OperationPhase::Demotion(ConfirmVipReleased)",
            "a16844656d6f74696f6e72436f6e6669726d56697052656c6561736564",
        ),
        (
            "OperationPhase::Demotion(ReleaseLease)",
            "a16844656d6f74696f6e6c52656c656173654c65617365",
        ),
        (
            "OperationPhase::Demotion(CommitStandby)",
            "a16844656d6f74696f6e6d436f6d6d69745374616e646279",
        ),
        (
            "WitnessMutationOutcomeCode::PolicyReject",
            "6c506f6c69637952656a656374",
        ),
        (
            "WitnessMutationOutcomeCode::RetiredStale",
            "6c526574697265645374616c65",
        ),
        ("WitnessMutationOutcomeCode::Conflict", "68436f6e666c696374"),
        (
            "WitnessMutationOutcomeCode::GenerationGap",
            "6d47656e65726174696f6e476170",
        ),
        (
            "WitnessMutationOutcomeCode::TemporarilyUnavailable",
            "7654656d706f726172696c79556e617661696c61626c65",
        ),
    ];

    /// L3 (the semantic pin behind guard `017_no_wire_change`): the canonical
    /// serialization of `CommonFields`, of every `ProtocolMessage` variant with
    /// every payload field populated, and of every nested wire enum value is
    /// byte-identical to the Stage 10 baseline. A renamed, added, removed, or
    /// re-shaped field, a serde `rename`/`alias`/`skip`/`tag`/`flatten`/
    /// `default`/`with` change, or a changed enum tag or representation that
    /// reaches the wire changes these bytes and fails this test. A change that
    /// does not reach the wire (for example a `serde` attribute on
    /// `MessageType`, which no wire type carries) does not.
    #[test]
    fn wire_shape_is_byte_identical_to_the_frozen_baseline() {
        assert_eq!(
            hex(&cbor2::to_canonical_vec(&common()).unwrap()),
            GOLDEN_COMMON_NONE,
            "CommonFields (optional fields absent)"
        );
        assert_eq!(
            hex(&cbor2::to_canonical_vec(&full_common()).unwrap()),
            GOLDEN_COMMON_FULL,
            "CommonFields (optional fields present)"
        );
        let messages = every_protocol_message();
        assert_eq!(
            messages.len(),
            GOLDEN_MESSAGES.len(),
            "a ProtocolMessage variant was added or removed"
        );
        for ((name, message), (golden_name, golden)) in messages.iter().zip(GOLDEN_MESSAGES) {
            assert_eq!(*name, golden_name);
            assert_eq!(
                hex(&cbor2::to_canonical_vec(message).unwrap()),
                golden,
                "ProtocolMessage::{name} wire bytes changed"
            );
            // The bytes also decode back to the same value (the wire is
            // bidirectional, not just stable on the way out).
            let decoded: ProtocolMessage =
                cbor2::from_slice(&decode_hex(golden)).expect("golden decodes");
            assert_eq!(&decoded, message, "ProtocolMessage::{name} decode changed");
        }
        let enums = every_nested_wire_enum();
        assert_eq!(
            enums.len(),
            GOLDEN_ENUMS.len(),
            "a nested wire enum variant was added or removed"
        );
        for ((name, bytes), (golden_name, golden)) in enums.iter().zip(GOLDEN_ENUMS) {
            assert_eq!(name, golden_name);
            assert_eq!(hex(bytes), golden, "{name} wire bytes changed");
        }
    }

    /// L3 (decode side): the frozen decoder accepts exactly the baseline key
    /// names and requires every baseline field. A serde `alias` (which accepts
    /// a second name) or `default` (which accepts a missing field) changes what
    /// the wire accepts without changing one serialized byte, so the encode
    /// goldens alone cannot see it.
    #[test]
    fn wire_decode_accepts_exactly_the_baseline_names_and_requires_every_field() {
        // CommonFields decodes from the golden, and from nothing else renamed.
        let golden = decode_hex(GOLDEN_COMMON_NONE);
        let decoded: CommonFields = cbor2::from_slice(&golden).expect("golden decodes");
        assert_eq!(decoded, common());
        // "term" (64 7465726d) spelled "trm" (63 74726d) is not accepted.
        let renamed = GOLDEN_COMMON_NONE.replacen("647465726d07", "6374726d07", 1);
        assert_ne!(renamed, GOLDEN_COMMON_NONE);
        assert!(cbor2::from_slice::<CommonFields>(&decode_hex(&renamed)).is_err());
        // A payload with its required `reason` field missing is not accepted.
        let without_reason = "a16b4c6561736552656a656374a164636f646568436f6e666c696374";
        assert!(cbor2::from_slice::<ProtocolMessage>(&decode_hex(without_reason)).is_err());
        // Each message golden minus one map entry is rejected for every
        // variant that carries a struct payload.
        for (name, golden) in GOLDEN_MESSAGES {
            let bytes = decode_hex(golden);
            let value: cbor2::Value = cbor2::from_slice(&bytes).expect("value");
            let cbor2::Value::Map(outer) = value else {
                continue; // unit variants are a bare text string
            };
            let (tag, payload) = outer.into_iter().next().expect("one entry");
            let cbor2::Value::Map(fields) = payload else {
                continue;
            };
            for index in 0..fields.len() {
                // serde treats an absent `Option` field as `None` (baseline
                // behavior, not a wire change), so those are not required.
                if matches!(
                    &fields[index].0,
                    cbor2::Value::Text(key) if [
                        "operation_phase",
                        "current_holder",
                        "current_lease_id",
                        "lease_remaining_ms",
                    ]
                    .contains(&key.as_str())
                ) {
                    continue;
                }
                let mut reduced = fields.clone();
                reduced.remove(index);
                let mutated = cbor2::Value::Map(vec![(tag.clone(), cbor2::Value::Map(reduced))]);
                let mutated = cbor2::to_canonical_vec(&mutated).unwrap();
                assert!(
                    cbor2::from_slice::<ProtocolMessage>(&mutated).is_err(),
                    "{name}: a payload missing field #{index} must not decode"
                );
            }
        }
    }

    /// L3: the full envelope composes the pinned parts unchanged: a field of
    /// `UnsignedEnvelope`/`WireMessage`/`Authentication` cannot be renamed,
    /// reordered into a different shape, or dropped unnoticed.
    #[test]
    fn wire_envelope_composition_is_byte_identical_to_the_frozen_baseline() {
        let serializer = CborSerializer;
        for (name, message) in every_protocol_message() {
            let unsigned = UnsignedEnvelope {
                common: full_common(),
                message: message.clone(),
            };
            let bytes = serializer.serialize_unsigned(&unsigned).unwrap();
            let common_hex = GOLDEN_COMMON_FULL;
            let message_hex = GOLDEN_MESSAGES
                .iter()
                .find(|(golden_name, _)| *golden_name == name)
                .unwrap()
                .1;
            // map(2) { "common": <common>, "message": <message> } with the
            // canonical (length-first) key order.
            let expected = format!("a266636f6d6d6f6e{common_hex}676d657373616765{message_hex}");
            assert_eq!(hex(&bytes), expected, "UnsignedEnvelope for {name}");
            let wire = WireMessage {
                unsigned,
                authentication: Authentication { mac: [0x5a; 32] },
            };
            let wire_bytes = serializer.serialize_wire(&wire).unwrap();
            let mac = "185a".repeat(32);
            // map(2) { "unsigned": <envelope>, "authentication": map(1)
            // { "mac": array(32) of uint } }.
            let expected_wire = format!(
                "a268756e7369676e6564{expected}6e61757468656e7469636174696f6ea1636d61639820{mac}",
            );
            assert_eq!(hex(&wire_bytes), expected_wire, "WireMessage for {name}");
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
        assert!(remainder.is_empty());
        pairs
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn canonical_round_trip_is_stable() {
        let serializer = CborSerializer;
        let message = WireMessage {
            unsigned: envelope(ProtocolMessage::Hello(HelloPayload { priority: 100 })),
            authentication: Authentication { mac: [0xabu8; 32] },
        };
        let bytes = serializer.serialize_wire(&message).unwrap();
        let decoded = serializer.deserialize_wire(&bytes).unwrap();
        assert_eq!(decoded, message);
        assert_eq!(serializer.serialize_wire(&decoded).unwrap(), bytes);
    }

    #[test]
    fn rejects_noncanonical_and_trailing_input() {
        let serializer = CborSerializer;
        let message = envelope(ProtocolMessage::Hello(HelloPayload { priority: 100 }));
        let canonical = serializer.serialize_unsigned(&message).unwrap();

        let key = b"protocol_version";
        let key_start = canonical
            .windows(key.len())
            .position(|window| window == key)
            .expect("protocol_version key");
        let value_index = key_start + key.len();
        let mut noncanonical = canonical.clone();
        noncanonical[value_index] = 0x18;
        noncanonical.insert(value_index + 1, 0x01);
        assert!(matches!(
            serializer.deserialize_unsigned(&noncanonical),
            Err(SerializationError::NonCanonical)
        ));

        let mut trailing = canonical;
        trailing.push(0);
        assert!(matches!(
            serializer.deserialize_unsigned(&trailing),
            Err(SerializationError::Decode(_))
        ));
    }

    fn heartbeat_payload() -> NodeStatusPayload {
        NodeStatusPayload {
            node_state: NodeState::Standby,
            operation_phase: None,
            role: Role::Standby,
            service_state: "stopped".to_string(),
            health_state: "unknown".to_string(),
            vip_state: "absent".to_string(),
        }
    }

    fn state_announce_payload() -> StateAnnouncePayload {
        StateAnnouncePayload {
            status: heartbeat_payload(),
            reason: "test".to_string(),
        }
    }

    fn promotion_intent_payload() -> PromotionIntentPayload {
        PromotionIntentPayload {
            priority: 100,
            reason: "test".to_string(),
        }
    }

    fn resource_status_payload() -> ResourceStatusPayload {
        ResourceStatusPayload {
            service_state: "running".to_string(),
            vip_state: "present".to_string(),
        }
    }

    fn demotion_intent_payload() -> DemotionIntentPayload {
        DemotionIntentPayload {
            phase: OperationPhase::Demotion(crate::state_machine::DemotionPhase::StopService),
            reason: "test".to_string(),
        }
    }

    fn demotion_committed_payload() -> DemotionCommittedPayload {
        DemotionCommittedPayload {
            service_stopped: true,
            vip_released: true,
        }
    }

    fn term_status_payload() -> TermStatusPayload {
        TermStatusPayload {
            current_term: Term(7),
            current_holder: None,
            current_lease_id: None,
            lease_remaining_ms: None,
        }
    }

    fn lease_request_payload() -> LeaseRequestPayload {
        LeaseRequestPayload {
            mutation_generation: 1,
            observed_term: Term(7),
            priority: 100,
            requested_ttl: DurationMs(10_000),
        }
    }

    fn lease_grant_payload() -> LeaseGrantPayload {
        LeaseGrantPayload {
            term: Term(7),
            lease_id: LeaseId::new("lease-1"),
            holder_node_id: NodeId::new("node-a"),
            lease_ttl_ms: DurationMs(10_000),
            renew_after_ms: DurationMs(3_000),
            lease_remaining_ms: DurationMs(10_000),
        }
    }

    fn lease_renew_payload() -> LeaseRenewPayload {
        LeaseRenewPayload {
            mutation_generation: 1,
            term: Term(7),
            lease_id: LeaseId::new("lease-1"),
        }
    }

    fn lease_release_payload() -> LeaseReleasePayload {
        LeaseReleasePayload {
            mutation_generation: 1,
            term: Term(7),
            lease_id: LeaseId::new("lease-1"),
            reason: "test".to_string(),
        }
    }

    fn lease_released_payload() -> LeaseReleasedPayload {
        LeaseReleasedPayload {
            term: Term(7),
            lease_id: LeaseId::new("lease-1"),
            result: "released".to_string(),
        }
    }

    fn lease_reject_payload() -> LeaseRejectPayload {
        LeaseRejectPayload {
            code: WitnessMutationOutcomeCode::PolicyReject,
            reason: "rejected".to_string(),
        }
    }
}
