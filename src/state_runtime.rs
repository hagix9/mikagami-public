use crate::connection_manager::PeerConnectionManager;
use crate::peer_dispatch::{
    PeerDispatchError, PeerMessageKind, PendingPeerMessage, commit_pending_peer_message,
};
use crate::protocol::{
    CborSerializer, ClusterId, LeaseId, NodeStatusPayload, ProtocolError, ProtocolMessage, Term,
    UnsignedEnvelope,
};
use crate::security::MessageAuthenticator;
use crate::session::{ProcessSession, SequenceError};
use crate::tcp::TcpError;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateAnnounceOutstandingState {
    Idle,
    AwaitingAck,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateAnnounceOutstanding {
    state: StateAnnounceOutstandingState,
}

impl StateAnnounceOutstanding {
    pub const fn new() -> Self {
        Self {
            state: StateAnnounceOutstandingState::Idle,
        }
    }

    pub const fn state(&self) -> StateAnnounceOutstandingState {
        self.state
    }

    pub fn begin(&mut self) -> Result<(), StateRuntimeError> {
        if self.state != StateAnnounceOutstandingState::Idle {
            return Err(StateRuntimeError::StateAnnounceAlreadyOutstanding);
        }
        self.state = StateAnnounceOutstandingState::AwaitingAck;
        Ok(())
    }

    fn complete(&mut self) {
        self.state = StateAnnounceOutstandingState::Idle;
    }
}

impl Default for StateAnnounceOutstanding {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerStateObservation {
    pub status: NodeStatusPayload,
    pub reason: String,
    pub term: Term,
    pub lease_id: Option<LeaseId>,
}

#[derive(Debug)]
pub enum StateRuntimeError {
    Dispatcher(PeerDispatchError),
    Protocol(ProtocolError),
    Sequence(SequenceError),
    Tcp(TcpError),
    WrongMessageKind {
        expected: PeerMessageKind,
        actual: PeerMessageKind,
    },
    InvalidPayloadVariant,
    NoOutstandingStateAnnounce,
    StateAnnounceAlreadyOutstanding,
}

impl fmt::Display for StateRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dispatcher(error) => write!(f, "peer dispatch failed: {error}"),
            Self::Protocol(error) => {
                write!(f, "state announce protocol validation failed: {error}")
            }
            Self::Sequence(error) => {
                write!(f, "state announce sequence allocation failed: {error}")
            }
            Self::Tcp(error) => write!(f, "state announce TCP send failed: {error}"),
            Self::WrongMessageKind { expected, actual } => {
                write!(
                    f,
                    "wrong state message kind: expected {expected:?}, got {actual:?}"
                )
            }
            Self::InvalidPayloadVariant => write!(f, "state message payload variant mismatch"),
            Self::NoOutstandingStateAnnounce => {
                write!(f, "no state announce is awaiting an ACK")
            }
            Self::StateAnnounceAlreadyOutstanding => {
                write!(f, "a state announce is already awaiting an ACK")
            }
        }
    }
}

impl std::error::Error for StateRuntimeError {}

#[allow(clippy::too_many_arguments)]
pub fn send_state_announce(
    manager: &mut PeerConnectionManager,
    process_session: &mut ProcessSession,
    outstanding: &mut StateAnnounceOutstanding,
    cluster_id: ClusterId,
    term: Term,
    lease_id: Option<LeaseId>,
    status: NodeStatusPayload,
    reason: String,
    serializer: &CborSerializer,
    authenticator: &MessageAuthenticator,
) -> Result<(), StateRuntimeError> {
    if outstanding.state != StateAnnounceOutstandingState::Idle {
        return Err(StateRuntimeError::StateAnnounceAlreadyOutstanding);
    }
    if !manager.has_connection() {
        return Err(StateRuntimeError::Dispatcher(
            PeerDispatchError::NoConnection,
        ));
    }
    let message = UnsignedEnvelope {
        common: crate::protocol::CommonFields {
            protocol_version: crate::protocol::PROTOCOL_VERSION,
            cluster_id,
            sender_node_id: manager.local_node_id().clone(),
            receiver_node_id: manager.peer_node_id().clone(),
            session_id: process_session.session_id().clone(),
            sequence: process_session
                .next_sequence()
                .map_err(StateRuntimeError::Sequence)?,
            term,
            lease_id,
            request_id: None,
            operation_id: None,
        },
        message: ProtocolMessage::StateAnnounce(crate::protocol::StateAnnouncePayload {
            status,
            reason,
        }),
    };
    message.validate().map_err(StateRuntimeError::Protocol)?;
    manager
        .connection_mut()
        .ok_or(StateRuntimeError::Dispatcher(
            PeerDispatchError::NoConnection,
        ))?
        .send_message(message, serializer, authenticator)
        .map_err(StateRuntimeError::Tcp)?;
    outstanding.state = StateAnnounceOutstandingState::AwaitingAck;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn handle_pending_state_announce(
    manager: &mut PeerConnectionManager,
    pending: &PendingPeerMessage,
    process_session: &mut ProcessSession,
    cluster_id: ClusterId,
    term: Term,
    lease_id: Option<LeaseId>,
    serializer: &CborSerializer,
    authenticator: &MessageAuthenticator,
) -> Result<PeerStateObservation, StateRuntimeError> {
    require_kind(pending, PeerMessageKind::StateAnnounce)?;
    let ProtocolMessage::StateAnnounce(payload) = &pending.message().unsigned().message else {
        return Err(StateRuntimeError::InvalidPayloadVariant);
    };
    let observation = PeerStateObservation {
        status: payload.status.clone(),
        reason: payload.reason.clone(),
        term: pending.message().unsigned().common.term,
        lease_id: pending.message().unsigned().common.lease_id.clone(),
    };
    commit_pending_peer_message(manager, pending).map_err(StateRuntimeError::Dispatcher)?;
    let ack = UnsignedEnvelope {
        common: crate::protocol::CommonFields {
            protocol_version: crate::protocol::PROTOCOL_VERSION,
            cluster_id,
            sender_node_id: manager.local_node_id().clone(),
            receiver_node_id: manager.peer_node_id().clone(),
            session_id: process_session.session_id().clone(),
            sequence: process_session
                .next_sequence()
                .map_err(StateRuntimeError::Sequence)?,
            term,
            lease_id,
            request_id: None,
            operation_id: None,
        },
        message: ProtocolMessage::StateAnnounceAck,
    };
    ack.validate().map_err(StateRuntimeError::Protocol)?;
    manager
        .connection_mut()
        .ok_or(StateRuntimeError::Dispatcher(
            PeerDispatchError::NoConnection,
        ))?
        .send_message(ack, serializer, authenticator)
        .map_err(StateRuntimeError::Tcp)?;
    Ok(observation)
}

pub fn handle_pending_state_announce_ack(
    manager: &mut PeerConnectionManager,
    pending: &PendingPeerMessage,
    outstanding: &mut StateAnnounceOutstanding,
) -> Result<(), StateRuntimeError> {
    require_kind(pending, PeerMessageKind::StateAnnounceAck)?;
    if !matches!(
        pending.message().unsigned().message,
        ProtocolMessage::StateAnnounceAck
    ) {
        return Err(StateRuntimeError::InvalidPayloadVariant);
    }
    if outstanding.state != StateAnnounceOutstandingState::AwaitingAck {
        return Err(StateRuntimeError::NoOutstandingStateAnnounce);
    }
    commit_pending_peer_message(manager, pending).map_err(StateRuntimeError::Dispatcher)?;
    outstanding.complete();
    Ok(())
}

fn require_kind(
    pending: &PendingPeerMessage,
    expected: PeerMessageKind,
) -> Result<(), StateRuntimeError> {
    let actual = pending.kind();
    if actual == expected {
        Ok(())
    } else {
        Err(StateRuntimeError::WrongMessageKind { expected, actual })
    }
}
