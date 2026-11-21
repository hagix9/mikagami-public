use crate::connection_manager::PeerConnectionManager;
use crate::peer_dispatch::{
    PeerDispatchError, PeerMessageKind, PendingPeerMessage, commit_pending_peer_message,
};
use crate::protocol::{
    CborSerializer, ClusterId, DemotionCommittedPayload, DemotionIntentPayload, LeaseId,
    OperationId, ProtocolError, ProtocolMessage, Sequence, SessionId, Term, UnsignedEnvelope,
};
use crate::security::MessageAuthenticator;
use crate::session::{ProcessSession, SequenceError};
use crate::state_machine::OperationPhase;
use crate::tcp::TcpError;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DemotionOutstandingState {
    Idle,
    AwaitingAck { operation_id: OperationId },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemotionOutstanding {
    state: DemotionOutstandingState,
}

impl DemotionOutstanding {
    pub const fn new() -> Self {
        Self {
            state: DemotionOutstandingState::Idle,
        }
    }
    pub fn state(&self) -> &DemotionOutstandingState {
        &self.state
    }
    fn begin(&mut self, operation_id: OperationId) -> Result<(), DemotionRuntimeError> {
        if !matches!(self.state, DemotionOutstandingState::Idle) {
            return Err(DemotionRuntimeError::DemotionAlreadyOutstanding);
        }
        self.state = DemotionOutstandingState::AwaitingAck { operation_id };
        Ok(())
    }
    fn complete(&mut self) {
        self.state = DemotionOutstandingState::Idle;
    }
}

impl Default for DemotionOutstanding {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemotionIntentObservation {
    pub operation_id: OperationId,
    pub term: Term,
    pub lease_id: Option<LeaseId>,
    pub phase: OperationPhase,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemotionAckObservation {
    pub operation_id: OperationId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemotionCommittedObservation {
    pub operation_id: OperationId,
    pub term: Term,
    pub lease_id: Option<LeaseId>,
    pub service_stopped: bool,
    pub vip_released: bool,
}

#[derive(Debug)]
pub enum DemotionRuntimeError {
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
    DemotionAlreadyOutstanding,
    NoOutstandingDemotion,
    OperationIdMismatch {
        expected: OperationId,
        actual: OperationId,
    },
}

impl fmt::Display for DemotionRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dispatcher(e) => write!(f, "peer dispatch failed: {e}"),
            Self::Protocol(e) => write!(f, "demotion protocol validation failed: {e}"),
            Self::Sequence(e) => write!(f, "demotion sequence allocation failed: {e}"),
            Self::Tcp(e) => write!(f, "demotion TCP send failed: {e}"),
            Self::WrongMessageKind { expected, actual } => write!(
                f,
                "wrong demotion message kind: expected {expected:?}, got {actual:?}"
            ),
            Self::InvalidPayloadVariant => write!(f, "demotion message payload variant mismatch"),
            Self::MissingOperationId => write!(f, "demotion message is missing operation_id"),
            Self::DemotionAlreadyOutstanding => write!(f, "a demotion ACK is already outstanding"),
            Self::NoOutstandingDemotion => write!(f, "no demotion ACK is outstanding"),
            Self::OperationIdMismatch { expected, actual } => write!(
                f,
                "demotion operation_id mismatch: expected {}, got {}",
                expected.as_str(),
                actual.as_str()
            ),
        }
    }
}
impl std::error::Error for DemotionRuntimeError {}

#[allow(clippy::too_many_arguments)]
pub fn send_demotion_intent(
    manager: &mut PeerConnectionManager,
    process_session: &mut ProcessSession,
    outstanding: &mut DemotionOutstanding,
    cluster_id: ClusterId,
    term: Term,
    lease_id: Option<LeaseId>,
    operation_id: OperationId,
    phase: OperationPhase,
    reason: String,
    serializer: &CborSerializer,
    authenticator: &MessageAuthenticator,
) -> Result<(), DemotionRuntimeError> {
    if !matches!(outstanding.state, DemotionOutstandingState::Idle) {
        return Err(DemotionRuntimeError::DemotionAlreadyOutstanding);
    }
    if operation_id.as_str().trim().is_empty() {
        return Err(DemotionRuntimeError::MissingOperationId);
    }
    if !manager.has_connection() {
        return Err(DemotionRuntimeError::Dispatcher(
            PeerDispatchError::NoConnection,
        ));
    }
    let message = UnsignedEnvelope {
        common: common_fields(
            manager,
            process_session.session_id().clone(),
            process_session
                .next_sequence()
                .map_err(DemotionRuntimeError::Sequence)?,
            cluster_id,
            term,
            lease_id,
            Some(operation_id.clone()),
        ),
        message: ProtocolMessage::DemotionIntent(DemotionIntentPayload { phase, reason }),
    };
    message.validate().map_err(DemotionRuntimeError::Protocol)?;
    manager
        .connection_mut()
        .ok_or(DemotionRuntimeError::Dispatcher(
            PeerDispatchError::NoConnection,
        ))?
        .send_message(message, serializer, authenticator)
        .map_err(DemotionRuntimeError::Tcp)?;
    outstanding.begin(operation_id)
}

#[allow(clippy::too_many_arguments)]
pub fn send_demotion_ack(
    manager: &mut PeerConnectionManager,
    process_session: &mut ProcessSession,
    cluster_id: ClusterId,
    term: Term,
    lease_id: Option<LeaseId>,
    operation_id: OperationId,
    serializer: &CborSerializer,
    authenticator: &MessageAuthenticator,
) -> Result<(), DemotionRuntimeError> {
    send_demotion_message(
        manager,
        process_session,
        cluster_id,
        term,
        lease_id,
        operation_id,
        ProtocolMessage::DemotionAck,
        serializer,
        authenticator,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn send_demotion_committed(
    manager: &mut PeerConnectionManager,
    process_session: &mut ProcessSession,
    cluster_id: ClusterId,
    term: Term,
    lease_id: Option<LeaseId>,
    operation_id: OperationId,
    service_stopped: bool,
    vip_released: bool,
    serializer: &CborSerializer,
    authenticator: &MessageAuthenticator,
) -> Result<(), DemotionRuntimeError> {
    send_demotion_message(
        manager,
        process_session,
        cluster_id,
        term,
        lease_id,
        operation_id,
        ProtocolMessage::DemotionCommitted(DemotionCommittedPayload {
            service_stopped,
            vip_released,
        }),
        serializer,
        authenticator,
    )
}

#[allow(clippy::too_many_arguments)]
fn send_demotion_message(
    manager: &mut PeerConnectionManager,
    process_session: &mut ProcessSession,
    cluster_id: ClusterId,
    term: Term,
    lease_id: Option<LeaseId>,
    operation_id: OperationId,
    message: ProtocolMessage,
    serializer: &CborSerializer,
    authenticator: &MessageAuthenticator,
) -> Result<(), DemotionRuntimeError> {
    if operation_id.as_str().trim().is_empty() {
        return Err(DemotionRuntimeError::MissingOperationId);
    }
    if !manager.has_connection() {
        return Err(DemotionRuntimeError::Dispatcher(
            PeerDispatchError::NoConnection,
        ));
    }
    let envelope = UnsignedEnvelope {
        common: common_fields(
            manager,
            process_session.session_id().clone(),
            process_session
                .next_sequence()
                .map_err(DemotionRuntimeError::Sequence)?,
            cluster_id,
            term,
            lease_id,
            Some(operation_id),
        ),
        message,
    };
    envelope
        .validate()
        .map_err(DemotionRuntimeError::Protocol)?;
    manager
        .connection_mut()
        .ok_or(DemotionRuntimeError::Dispatcher(
            PeerDispatchError::NoConnection,
        ))?
        .send_message(envelope, serializer, authenticator)
        .map_err(DemotionRuntimeError::Tcp)
}

pub fn handle_pending_demotion_intent(
    manager: &mut PeerConnectionManager,
    pending: &PendingPeerMessage,
) -> Result<DemotionIntentObservation, DemotionRuntimeError> {
    require_kind(pending, PeerMessageKind::DemotionIntent)?;
    let ProtocolMessage::DemotionIntent(payload) = &pending.message().unsigned().message else {
        return Err(DemotionRuntimeError::InvalidPayloadVariant);
    };
    let operation_id = operation_id(pending)?;
    let observation = DemotionIntentObservation {
        operation_id,
        term: pending.message().unsigned().common.term,
        lease_id: pending.message().unsigned().common.lease_id.clone(),
        phase: payload.phase,
        reason: payload.reason.clone(),
    };
    commit_pending_peer_message(manager, pending).map_err(DemotionRuntimeError::Dispatcher)?;
    Ok(observation)
}

pub fn handle_pending_demotion_ack(
    manager: &mut PeerConnectionManager,
    pending: &PendingPeerMessage,
    outstanding: &mut DemotionOutstanding,
) -> Result<DemotionAckObservation, DemotionRuntimeError> {
    require_kind(pending, PeerMessageKind::DemotionAck)?;
    if !matches!(
        pending.message().unsigned().message,
        ProtocolMessage::DemotionAck
    ) {
        return Err(DemotionRuntimeError::InvalidPayloadVariant);
    }
    let incoming = operation_id(pending)?;
    let DemotionOutstandingState::AwaitingAck {
        operation_id: expected,
    } = outstanding.state.clone()
    else {
        return Err(DemotionRuntimeError::NoOutstandingDemotion);
    };
    if incoming != expected {
        return Err(DemotionRuntimeError::OperationIdMismatch {
            expected,
            actual: incoming,
        });
    }
    commit_pending_peer_message(manager, pending).map_err(DemotionRuntimeError::Dispatcher)?;
    outstanding.complete();
    Ok(DemotionAckObservation {
        operation_id: expected,
    })
}

pub fn handle_pending_demotion_committed(
    manager: &mut PeerConnectionManager,
    pending: &PendingPeerMessage,
) -> Result<DemotionCommittedObservation, DemotionRuntimeError> {
    require_kind(pending, PeerMessageKind::DemotionCommitted)?;
    let ProtocolMessage::DemotionCommitted(payload) = &pending.message().unsigned().message else {
        return Err(DemotionRuntimeError::InvalidPayloadVariant);
    };
    let observation = DemotionCommittedObservation {
        operation_id: operation_id(pending)?,
        term: pending.message().unsigned().common.term,
        lease_id: pending.message().unsigned().common.lease_id.clone(),
        service_stopped: payload.service_stopped,
        vip_released: payload.vip_released,
    };
    commit_pending_peer_message(manager, pending).map_err(DemotionRuntimeError::Dispatcher)?;
    Ok(observation)
}

fn operation_id(pending: &PendingPeerMessage) -> Result<OperationId, DemotionRuntimeError> {
    pending
        .message()
        .unsigned()
        .common
        .operation_id
        .clone()
        .ok_or(DemotionRuntimeError::MissingOperationId)
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
) -> Result<(), DemotionRuntimeError> {
    let actual = pending.kind();
    if actual == expected {
        Ok(())
    } else {
        Err(DemotionRuntimeError::WrongMessageKind { expected, actual })
    }
}
