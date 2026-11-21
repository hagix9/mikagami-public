use crate::connection_manager::{PeerConnectionManager, PeerSequenceCommitError};
use crate::protocol::{ClusterId, MessageType, Sequence, SessionId};
use crate::receive::AuthenticatedMessage;
use crate::security::MessageAuthenticator;
use crate::tcp::{ReceiveMessageResult, TcpError};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerMessageKind {
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
}

impl TryFrom<MessageType> for PeerMessageKind {
    type Error = PeerDispatchError;

    fn try_from(message_type: MessageType) -> Result<Self, Self::Error> {
        let kind = match message_type {
            MessageType::Heartbeat => Self::Heartbeat,
            MessageType::HeartbeatAck => Self::HeartbeatAck,
            MessageType::StateAnnounce => Self::StateAnnounce,
            MessageType::StateAnnounceAck => Self::StateAnnounceAck,
            MessageType::PromotionIntent => Self::PromotionIntent,
            MessageType::PromotionAck => Self::PromotionAck,
            MessageType::PromotionBlock => Self::PromotionBlock,
            MessageType::PromotionUnknown => Self::PromotionUnknown,
            MessageType::PromotionCommitted => Self::PromotionCommitted,
            MessageType::DemotionIntent => Self::DemotionIntent,
            MessageType::DemotionAck => Self::DemotionAck,
            MessageType::DemotionCommitted => Self::DemotionCommitted,
            _ => return Err(PeerDispatchError::DisallowedMessage(message_type)),
        };
        Ok(kind)
    }
}

/// An authenticated, peer-validated, replay-fresh message awaiting handler acceptance.
/// The peer sequence is not committed until `commit_pending_peer_message` succeeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPeerMessage {
    message: AuthenticatedMessage,
    kind: PeerMessageKind,
}

impl PendingPeerMessage {
    pub fn kind(&self) -> PeerMessageKind {
        self.kind
    }

    pub fn message(&self) -> &AuthenticatedMessage {
        &self.message
    }

    pub fn session_id(&self) -> &SessionId {
        &self.message.unsigned().common.session_id
    }

    pub fn sequence(&self) -> Sequence {
        self.message.unsigned().common.sequence
    }
}

#[derive(Debug)]
pub enum PeerDispatchError {
    NoConnection,
    MissingReplayState,
    Tcp(TcpError),
    CleanEof,
    WrongCluster,
    WrongSender,
    WrongReceiver,
    WrongSession,
    StaleOrDuplicateSequence,
    DisallowedMessage(MessageType),
    Commit(PeerSequenceCommitError),
}

impl fmt::Display for PeerDispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::NoConnection => "no canonical connection is available",
            Self::MissingReplayState => "peer replay state is not available",
            Self::Tcp(error) => return write!(f, "peer message TCP receive failed: {error}"),
            Self::CleanEof => "peer closed connection",
            Self::WrongCluster => "peer message cluster identity mismatch",
            Self::WrongSender => "peer message sender identity mismatch",
            Self::WrongReceiver => "peer message receiver identity mismatch",
            Self::WrongSession => "peer message session_id mismatch",
            Self::StaleOrDuplicateSequence => "peer message sequence is stale or duplicate",
            Self::DisallowedMessage(message_type) => {
                return write!(
                    f,
                    "message is not allowed on an established node peer connection: {message_type:?}"
                );
            }
            Self::Commit(error) => return write!(f, "peer sequence commit failed: {error}"),
        };
        write!(f, "{message}")
    }
}

impl std::error::Error for PeerDispatchError {}

pub fn dispatch_next(
    manager: &mut PeerConnectionManager,
    cluster_id: &ClusterId,
    serializer: &crate::protocol::CborSerializer,
    authenticator: &MessageAuthenticator,
) -> Result<PendingPeerMessage, PeerDispatchError> {
    if !manager.has_connection() {
        return Err(PeerDispatchError::NoConnection);
    }
    let replay = manager
        .replay_state()
        .ok_or(PeerDispatchError::MissingReplayState)?;
    let peer_session_id = replay.session_id().clone();
    let highest_sequence = replay.highest_accepted_sequence();
    let received = manager
        .connection_mut()
        .ok_or(PeerDispatchError::NoConnection)?
        .receive_message(serializer, authenticator)
        .map_err(PeerDispatchError::Tcp)?;
    let message = match received {
        ReceiveMessageResult::Eof => return Err(PeerDispatchError::CleanEof),
        ReceiveMessageResult::Message(message) => *message,
    };
    let common = &message.unsigned().common;
    if common.cluster_id != *cluster_id {
        return Err(PeerDispatchError::WrongCluster);
    }
    if common.sender_node_id != *manager.peer_node_id() {
        return Err(PeerDispatchError::WrongSender);
    }
    if common.receiver_node_id != *manager.local_node_id() {
        return Err(PeerDispatchError::WrongReceiver);
    }
    if common.session_id != peer_session_id {
        return Err(PeerDispatchError::WrongSession);
    }
    if common.sequence.0 <= highest_sequence.0 {
        return Err(PeerDispatchError::StaleOrDuplicateSequence);
    }
    let kind = PeerMessageKind::try_from(message.unsigned().message.message_type())?;
    Ok(PendingPeerMessage { message, kind })
}

pub fn commit_pending_peer_message(
    manager: &mut PeerConnectionManager,
    pending: &PendingPeerMessage,
) -> Result<(), PeerDispatchError> {
    manager
        .commit_peer_sequence(pending.session_id(), pending.sequence())
        .map_err(PeerDispatchError::Commit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection_manager::{AdoptionResult, ConnectionDirection};
    use crate::handshake::{accept_peer_handshake, connect_and_handshake};
    use crate::heartbeat::{build_heartbeat, build_heartbeat_ack};
    use crate::listener::PeerListener;
    use crate::liveness::PeerLivenessTracker;
    use crate::protocol::{
        CborSerializer, CommonFields, DemotionCommittedPayload, DemotionIntentPayload, NodeId,
        NodeStatusPayload, PromotionIntentPayload, ProtocolMessage, Role, SessionId,
        StateAnnouncePayload, Term, UnsignedEnvelope,
    };
    use crate::security::{MessageAuthenticator, Psk};
    use crate::state_machine::{DemotionPhase, NodeState, OperationPhase};
    use std::net::SocketAddr;
    use std::thread;
    use std::time::Duration;

    const TIMEOUT: Duration = Duration::from_secs(2);

    fn auth() -> MessageAuthenticator {
        MessageAuthenticator::new(Psk::from_test_bytes([0x0b; 32]))
    }

    fn status() -> NodeStatusPayload {
        NodeStatusPayload {
            node_state: NodeState::Standby,
            operation_phase: None,
            role: Role::Standby,
            service_state: "running".to_string(),
            health_state: "healthy".to_string(),
            vip_state: "present".to_string(),
        }
    }

    fn process(id: &str) -> crate::session::ProcessSession {
        crate::session::ProcessSession::from_session_id(SessionId::new(id))
    }

    fn listener() -> (PeerListener, SocketAddr) {
        let listener =
            PeerListener::bind("127.0.0.1:0".parse().unwrap(), TIMEOUT, TIMEOUT).unwrap();
        let address = listener.local_addr().unwrap();
        (listener, address)
    }

    fn established_managers() -> (
        PeerConnectionManager,
        PeerConnectionManager,
        crate::session::ProcessSession,
        crate::session::ProcessSession,
    ) {
        let (listener, address) = listener();
        let server = thread::spawn(move || {
            let (connection, _) = listener.accept().unwrap();
            let mut process = process("session-b");
            accept_peer_handshake(
                connection,
                ClusterId::new("cluster"),
                NodeId::new("node-b"),
                NodeId::new("node-a"),
                120,
                &mut process,
                Term(1),
                &CborSerializer,
                &auth(),
            )
            .map(|result| (result, process))
        });
        let mut process_a = process("session-a");
        let client = connect_and_handshake(
            address,
            TIMEOUT,
            TIMEOUT,
            TIMEOUT,
            ClusterId::new("cluster"),
            NodeId::new("node-a"),
            NodeId::new("node-b"),
            120,
            &mut process_a,
            Term(1),
            &CborSerializer,
            &auth(),
        )
        .unwrap();
        let (server_result, process_b) = server.join().unwrap().unwrap();
        let mut manager_a =
            PeerConnectionManager::new(NodeId::new("node-a"), NodeId::new("node-b")).unwrap();
        assert_eq!(
            manager_a.adopt(ConnectionDirection::Outbound, client),
            AdoptionResult::Adopted
        );
        let mut manager_b =
            PeerConnectionManager::new(NodeId::new("node-b"), NodeId::new("node-a")).unwrap();
        assert_eq!(
            manager_b.adopt(ConnectionDirection::Inbound, server_result),
            AdoptionResult::Adopted
        );
        (manager_a, manager_b, process_a, process_b)
    }

    fn envelope(message: ProtocolMessage) -> UnsignedEnvelope {
        UnsignedEnvelope {
            common: CommonFields {
                protocol_version: 1,
                cluster_id: ClusterId::new("cluster"),
                sender_node_id: NodeId::new("node-a"),
                receiver_node_id: NodeId::new("node-b"),
                session_id: SessionId::new("session-a"),
                sequence: crate::protocol::Sequence(2),
                term: Term(1),
                lease_id: None,
                request_id: None,
                operation_id: None,
            },
            message,
        }
    }

    #[test]
    fn classifies_established_node_messages_without_witness_messages() {
        let cases = [
            (
                ProtocolMessage::Heartbeat(status()),
                PeerMessageKind::Heartbeat,
            ),
            (ProtocolMessage::HeartbeatAck, PeerMessageKind::HeartbeatAck),
            (
                ProtocolMessage::StateAnnounce(StateAnnouncePayload {
                    status: status(),
                    reason: "test".to_string(),
                }),
                PeerMessageKind::StateAnnounce,
            ),
            (
                ProtocolMessage::StateAnnounceAck,
                PeerMessageKind::StateAnnounceAck,
            ),
            (
                ProtocolMessage::PromotionIntent(PromotionIntentPayload {
                    priority: 100,
                    reason: "test".to_string(),
                }),
                PeerMessageKind::PromotionIntent,
            ),
            (ProtocolMessage::PromotionAck, PeerMessageKind::PromotionAck),
            (
                ProtocolMessage::PromotionBlock,
                PeerMessageKind::PromotionBlock,
            ),
            (
                ProtocolMessage::PromotionUnknown,
                PeerMessageKind::PromotionUnknown,
            ),
            (
                ProtocolMessage::PromotionCommitted(crate::protocol::ResourceStatusPayload {
                    service_state: "running".to_string(),
                    vip_state: "present".to_string(),
                }),
                PeerMessageKind::PromotionCommitted,
            ),
            (ProtocolMessage::DemotionAck, PeerMessageKind::DemotionAck),
            (
                ProtocolMessage::DemotionIntent(DemotionIntentPayload {
                    phase: OperationPhase::Demotion(DemotionPhase::StopService),
                    reason: "test".to_string(),
                }),
                PeerMessageKind::DemotionIntent,
            ),
            (
                ProtocolMessage::DemotionCommitted(DemotionCommittedPayload {
                    service_stopped: true,
                    vip_released: true,
                }),
                PeerMessageKind::DemotionCommitted,
            ),
        ];
        for (message, expected) in cases {
            let message_type = envelope(message).message.message_type();
            assert!(matches!(
                PeerMessageKind::try_from(message_type),
                Ok(actual) if actual == expected
            ));
        }
    }

    #[test]
    fn classifies_witness_and_handshake_messages_as_disallowed() {
        for message_type in [
            MessageType::Hello,
            MessageType::HelloAck,
            MessageType::GetTerm,
            MessageType::TermStatus,
            MessageType::LeaseRequest,
            MessageType::LeaseGrant,
            MessageType::LeaseRenew,
            MessageType::LeaseRenewed,
            MessageType::LeaseRelease,
            MessageType::LeaseReleased,
            MessageType::LeaseReject,
        ] {
            assert!(matches!(
                PeerMessageKind::try_from(message_type),
                Err(PeerDispatchError::DisallowedMessage(actual)) if actual == message_type
            ));
        }
    }

    #[test]
    fn dispatches_pending_heartbeat_without_committing_or_updating_liveness() {
        let (mut manager_a, mut manager_b, mut process_a, process_b) = established_managers();
        let heartbeat = build_heartbeat(
            &mut process_a,
            ClusterId::new("cluster"),
            NodeId::new("node-a"),
            NodeId::new("node-b"),
            Term(1),
            None,
            status(),
        )
        .unwrap();
        manager_a
            .connection_mut()
            .unwrap()
            .send_message(heartbeat, &CborSerializer, &auth())
            .unwrap();
        let pending = dispatch_next(
            &mut manager_b,
            &ClusterId::new("cluster"),
            &CborSerializer,
            &auth(),
        )
        .unwrap();
        assert_eq!(pending.kind(), PeerMessageKind::Heartbeat);
        assert_eq!(pending.session_id(), &SessionId::new("session-a"));
        assert_eq!(pending.sequence(), crate::protocol::Sequence(2));
        assert_eq!(
            manager_b
                .replay_state()
                .unwrap()
                .highest_accepted_sequence(),
            crate::protocol::Sequence(1)
        );
        let tracker = PeerLivenessTracker::new();
        assert!(tracker.last_success().is_none());
        commit_pending_peer_message(&mut manager_b, &pending).unwrap();
        assert_eq!(
            manager_b
                .replay_state()
                .unwrap()
                .highest_accepted_sequence(),
            crate::protocol::Sequence(2)
        );
        drop(manager_a);
        drop(process_b);
    }

    #[test]
    fn dispatches_heartbeat_ack() {
        let (mut manager_a, mut manager_b, process_a, mut process_b) = established_managers();
        let ack = build_heartbeat_ack(
            &mut process_b,
            ClusterId::new("cluster"),
            NodeId::new("node-b"),
            NodeId::new("node-a"),
            Term(1),
            None,
        )
        .unwrap();
        manager_b
            .connection_mut()
            .unwrap()
            .send_message(ack, &CborSerializer, &auth())
            .unwrap();
        let pending = dispatch_next(
            &mut manager_a,
            &ClusterId::new("cluster"),
            &CborSerializer,
            &auth(),
        )
        .unwrap();
        assert_eq!(pending.kind(), PeerMessageKind::HeartbeatAck);
        assert_eq!(
            manager_a
                .replay_state()
                .unwrap()
                .highest_accepted_sequence(),
            crate::protocol::Sequence(1)
        );
        commit_pending_peer_message(&mut manager_a, &pending).unwrap();
        drop(process_a);
    }

    #[test]
    fn double_commit_is_rejected_by_manager() {
        let (mut manager_a, mut manager_b, mut process_a, process_b) = established_managers();
        let heartbeat = build_heartbeat(
            &mut process_a,
            ClusterId::new("cluster"),
            NodeId::new("node-a"),
            NodeId::new("node-b"),
            Term(1),
            None,
            status(),
        )
        .unwrap();
        manager_a
            .connection_mut()
            .unwrap()
            .send_message(heartbeat, &CborSerializer, &auth())
            .unwrap();
        let pending = dispatch_next(
            &mut manager_b,
            &ClusterId::new("cluster"),
            &CborSerializer,
            &auth(),
        )
        .unwrap();
        commit_pending_peer_message(&mut manager_b, &pending).unwrap();
        assert!(matches!(
            commit_pending_peer_message(&mut manager_b, &pending),
            Err(PeerDispatchError::Commit(
                PeerSequenceCommitError::StaleOrDuplicate
            ))
        ));
        drop((process_b, manager_a));
    }
}
