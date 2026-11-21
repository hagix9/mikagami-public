use crate::connection_manager::PeerConnectionManager;
use crate::peer_dispatch::{
    PeerDispatchError, PeerMessageKind, PendingPeerMessage, commit_pending_peer_message,
};
use crate::protocol::{
    CborSerializer, ClusterId, LeaseId, OperationId, PromotionIntentPayload, ProtocolError,
    ProtocolMessage, Role, Sequence, SessionId, Term, UnsignedEnvelope,
};
use crate::security::MessageAuthenticator;
use crate::session::{ProcessSession, SequenceError};
use crate::tcp::TcpError;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromotionOutstandingState {
    Idle,
    AwaitingResponse { operation_id: OperationId },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotionOutstanding {
    state: PromotionOutstandingState,
}

impl PromotionOutstanding {
    pub const fn new() -> Self {
        Self {
            state: PromotionOutstandingState::Idle,
        }
    }

    pub fn state(&self) -> &PromotionOutstandingState {
        &self.state
    }

    fn begin(&mut self, operation_id: OperationId) -> Result<(), PromotionRuntimeError> {
        if !matches!(self.state, PromotionOutstandingState::Idle) {
            return Err(PromotionRuntimeError::PromotionAlreadyOutstanding);
        }
        self.state = PromotionOutstandingState::AwaitingResponse { operation_id };
        Ok(())
    }

    fn complete(&mut self) {
        self.state = PromotionOutstandingState::Idle;
    }
}

impl Default for PromotionOutstanding {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotionIntentObservation {
    pub operation_id: OperationId,
    pub priority: i32,
    pub reason: String,
    pub term: Term,
    pub lease_id: Option<LeaseId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromotionPeerResponseKind {
    Ack,
    Block,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotionPeerResponse {
    pub operation_id: OperationId,
    pub kind: PromotionPeerResponseKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotionCommittedObservation {
    pub operation_id: OperationId,
    pub term: Term,
    pub lease_id: Option<LeaseId>,
    pub role: Role,
    pub service_state: String,
    pub vip_state: String,
}

#[derive(Debug)]
pub enum PromotionRuntimeError {
    Dispatcher(PeerDispatchError),
    Protocol(ProtocolError),
    Sequence(SequenceError),
    Tcp(TcpError),
    WrongMessageKind {
        expected: PeerMessageKind,
        actual: PeerMessageKind,
    },
    InvalidPayloadVariant,
    MissingOperationId,
    PromotionAlreadyOutstanding,
    NoOutstandingPromotion,
    OperationIdMismatch {
        expected: OperationId,
        actual: OperationId,
    },
}

impl fmt::Display for PromotionRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dispatcher(error) => write!(f, "peer dispatch failed: {error}"),
            Self::Protocol(error) => write!(f, "promotion protocol validation failed: {error}"),
            Self::Sequence(error) => write!(f, "promotion sequence allocation failed: {error}"),
            Self::Tcp(error) => write!(f, "promotion TCP send failed: {error}"),
            Self::WrongMessageKind { expected, actual } => {
                write!(
                    f,
                    "wrong promotion message kind: expected {expected:?}, got {actual:?}"
                )
            }
            Self::InvalidPayloadVariant => write!(f, "promotion message payload variant mismatch"),
            Self::MissingOperationId => write!(f, "promotion message is missing operation_id"),
            Self::PromotionAlreadyOutstanding => {
                write!(f, "a promotion response is already outstanding")
            }
            Self::NoOutstandingPromotion => write!(f, "no promotion response is outstanding"),
            Self::OperationIdMismatch { expected, actual } => write!(
                f,
                "promotion operation_id mismatch: expected {}, got {}",
                expected.as_str(),
                actual.as_str()
            ),
        }
    }
}

impl std::error::Error for PromotionRuntimeError {}

#[allow(clippy::too_many_arguments)]
pub fn send_promotion_intent(
    manager: &mut PeerConnectionManager,
    process_session: &mut ProcessSession,
    outstanding: &mut PromotionOutstanding,
    cluster_id: ClusterId,
    term: Term,
    lease_id: Option<LeaseId>,
    operation_id: OperationId,
    priority: i32,
    reason: String,
    serializer: &CborSerializer,
    authenticator: &MessageAuthenticator,
) -> Result<(), PromotionRuntimeError> {
    if !matches!(outstanding.state, PromotionOutstandingState::Idle) {
        return Err(PromotionRuntimeError::PromotionAlreadyOutstanding);
    }
    if operation_id.as_str().trim().is_empty() {
        return Err(PromotionRuntimeError::MissingOperationId);
    }
    if !manager.has_connection() {
        return Err(PromotionRuntimeError::Dispatcher(
            PeerDispatchError::NoConnection,
        ));
    }
    let message = UnsignedEnvelope {
        common: common_fields(
            manager,
            process_session.session_id().clone(),
            process_session
                .next_sequence()
                .map_err(PromotionRuntimeError::Sequence)?,
            cluster_id,
            term,
            lease_id,
            Some(operation_id.clone()),
        ),
        message: ProtocolMessage::PromotionIntent(PromotionIntentPayload { priority, reason }),
    };
    message
        .validate()
        .map_err(PromotionRuntimeError::Protocol)?;
    manager
        .connection_mut()
        .ok_or(PromotionRuntimeError::Dispatcher(
            PeerDispatchError::NoConnection,
        ))?
        .send_message(message, serializer, authenticator)
        .map_err(PromotionRuntimeError::Tcp)?;
    outstanding.begin(operation_id)
}

#[allow(clippy::too_many_arguments)]
pub fn send_promotion_response(
    manager: &mut PeerConnectionManager,
    process_session: &mut ProcessSession,
    cluster_id: ClusterId,
    term: Term,
    lease_id: Option<LeaseId>,
    operation_id: OperationId,
    kind: PromotionPeerResponseKind,
    serializer: &CborSerializer,
    authenticator: &MessageAuthenticator,
) -> Result<(), PromotionRuntimeError> {
    if operation_id.as_str().trim().is_empty() {
        return Err(PromotionRuntimeError::MissingOperationId);
    }
    if !manager.has_connection() {
        return Err(PromotionRuntimeError::Dispatcher(
            PeerDispatchError::NoConnection,
        ));
    }
    let message = UnsignedEnvelope {
        common: common_fields(
            manager,
            process_session.session_id().clone(),
            process_session
                .next_sequence()
                .map_err(PromotionRuntimeError::Sequence)?,
            cluster_id,
            term,
            lease_id,
            Some(operation_id),
        ),
        message: match kind {
            PromotionPeerResponseKind::Ack => ProtocolMessage::PromotionAck,
            PromotionPeerResponseKind::Block => ProtocolMessage::PromotionBlock,
            PromotionPeerResponseKind::Unknown => ProtocolMessage::PromotionUnknown,
        },
    };
    message
        .validate()
        .map_err(PromotionRuntimeError::Protocol)?;
    manager
        .connection_mut()
        .ok_or(PromotionRuntimeError::Dispatcher(
            PeerDispatchError::NoConnection,
        ))?
        .send_message(message, serializer, authenticator)
        .map_err(PromotionRuntimeError::Tcp)
}

pub fn handle_pending_promotion_intent(
    manager: &mut PeerConnectionManager,
    pending: &PendingPeerMessage,
) -> Result<PromotionIntentObservation, PromotionRuntimeError> {
    require_kind(pending, PeerMessageKind::PromotionIntent)?;
    let ProtocolMessage::PromotionIntent(payload) = &pending.message().unsigned().message else {
        return Err(PromotionRuntimeError::InvalidPayloadVariant);
    };
    let operation_id = pending
        .message()
        .unsigned()
        .common
        .operation_id
        .clone()
        .ok_or(PromotionRuntimeError::MissingOperationId)?;
    let observation = PromotionIntentObservation {
        operation_id,
        priority: payload.priority,
        reason: payload.reason.clone(),
        term: pending.message().unsigned().common.term,
        lease_id: pending.message().unsigned().common.lease_id.clone(),
    };
    commit_pending_peer_message(manager, pending).map_err(PromotionRuntimeError::Dispatcher)?;
    Ok(observation)
}

pub fn handle_pending_promotion_response(
    manager: &mut PeerConnectionManager,
    pending: &PendingPeerMessage,
    outstanding: &mut PromotionOutstanding,
) -> Result<PromotionPeerResponse, PromotionRuntimeError> {
    let kind = pending.kind();
    let response_kind = match kind {
        PeerMessageKind::PromotionAck => PromotionPeerResponseKind::Ack,
        PeerMessageKind::PromotionBlock => PromotionPeerResponseKind::Block,
        PeerMessageKind::PromotionUnknown => PromotionPeerResponseKind::Unknown,
        actual => {
            return Err(PromotionRuntimeError::WrongMessageKind {
                expected: PeerMessageKind::PromotionAck,
                actual,
            });
        }
    };
    if !matches!(
        pending.message().unsigned().message,
        ProtocolMessage::PromotionAck
            | ProtocolMessage::PromotionBlock
            | ProtocolMessage::PromotionUnknown
    ) {
        return Err(PromotionRuntimeError::InvalidPayloadVariant);
    }
    let operation_id = pending
        .message()
        .unsigned()
        .common
        .operation_id
        .clone()
        .ok_or(PromotionRuntimeError::MissingOperationId)?;
    let PromotionOutstandingState::AwaitingResponse {
        operation_id: expected,
    } = outstanding.state.clone()
    else {
        return Err(PromotionRuntimeError::NoOutstandingPromotion);
    };
    if operation_id != expected {
        return Err(PromotionRuntimeError::OperationIdMismatch {
            expected,
            actual: operation_id,
        });
    }
    commit_pending_peer_message(manager, pending).map_err(PromotionRuntimeError::Dispatcher)?;
    outstanding.complete();
    Ok(PromotionPeerResponse {
        operation_id,
        kind: response_kind,
    })
}

pub fn handle_pending_promotion_committed(
    manager: &mut PeerConnectionManager,
    pending: &PendingPeerMessage,
) -> Result<PromotionCommittedObservation, PromotionRuntimeError> {
    require_kind(pending, PeerMessageKind::PromotionCommitted)?;
    let ProtocolMessage::PromotionCommitted(payload) = &pending.message().unsigned().message else {
        return Err(PromotionRuntimeError::InvalidPayloadVariant);
    };
    let operation_id = pending
        .message()
        .unsigned()
        .common
        .operation_id
        .clone()
        .ok_or(PromotionRuntimeError::MissingOperationId)?;
    let observation = PromotionCommittedObservation {
        operation_id,
        term: pending.message().unsigned().common.term,
        lease_id: pending.message().unsigned().common.lease_id.clone(),
        role: Role::Active,
        service_state: payload.service_state.clone(),
        vip_state: payload.vip_state.clone(),
    };
    commit_pending_peer_message(manager, pending).map_err(PromotionRuntimeError::Dispatcher)?;
    Ok(observation)
}

fn common_fields(
    manager: &PeerConnectionManager,
    session_id: SessionId,
    sequence: Sequence,
    cluster_id: ClusterId,
    term: Term,
    lease_id: Option<LeaseId>,
    operation_id: Option<OperationId>,
) -> crate::protocol::CommonFields {
    crate::protocol::CommonFields {
        protocol_version: crate::protocol::PROTOCOL_VERSION,
        cluster_id,
        sender_node_id: manager.local_node_id().clone(),
        receiver_node_id: manager.peer_node_id().clone(),
        session_id,
        sequence,
        term,
        lease_id,
        request_id: None,
        operation_id,
    }
}

fn require_kind(
    pending: &PendingPeerMessage,
    expected: PeerMessageKind,
) -> Result<(), PromotionRuntimeError> {
    let actual = pending.kind();
    if actual == expected {
        Ok(())
    } else {
        Err(PromotionRuntimeError::WrongMessageKind { expected, actual })
    }
}
