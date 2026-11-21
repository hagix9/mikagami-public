use crate::connection_manager::{PeerConnectionManager, PeerSequenceCommitError};
use crate::liveness::{LivenessTrackerError, PeerLivenessTracker};
use crate::protocol::{
    ClusterId, CommonFields, LeaseId, NodeId, NodeStatusPayload, PROTOCOL_VERSION, ProtocolError,
    ProtocolMessage, Sequence, Term, UnsignedEnvelope,
};
use crate::security::MessageAuthenticator;
use crate::session::{ProcessSession, SequenceError};
use crate::tcp::{ReceiveMessageResult, TcpError};
use std::fmt;
use std::time::Instant;

pub fn build_heartbeat(
    process_session: &mut ProcessSession,
    cluster_id: ClusterId,
    local_node_id: NodeId,
    peer_node_id: NodeId,
    term: Term,
    lease_id: Option<LeaseId>,
    status: NodeStatusPayload,
) -> Result<UnsignedEnvelope, HeartbeatError> {
    let message = UnsignedEnvelope {
        common: CommonFields {
            protocol_version: PROTOCOL_VERSION,
            cluster_id,
            sender_node_id: local_node_id,
            receiver_node_id: peer_node_id,
            session_id: process_session.session_id().clone(),
            sequence: process_session.next_sequence()?,
            term,
            lease_id,
            request_id: None,
            operation_id: None,
        },
        message: ProtocolMessage::Heartbeat(status),
    };
    message.validate().map_err(HeartbeatError::Protocol)?;
    Ok(message)
}

pub fn build_heartbeat_ack(
    process_session: &mut ProcessSession,
    cluster_id: ClusterId,
    local_node_id: NodeId,
    peer_node_id: NodeId,
    term: Term,
    lease_id: Option<LeaseId>,
) -> Result<UnsignedEnvelope, HeartbeatError> {
    let message = UnsignedEnvelope {
        common: CommonFields {
            protocol_version: PROTOCOL_VERSION,
            cluster_id,
            sender_node_id: local_node_id,
            receiver_node_id: peer_node_id,
            session_id: process_session.session_id().clone(),
            sequence: process_session.next_sequence()?,
            term,
            lease_id,
            request_id: None,
            operation_id: None,
        },
        message: ProtocolMessage::HeartbeatAck,
    };
    message.validate().map_err(HeartbeatError::Protocol)?;
    Ok(message)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeartbeatObservation {
    pub status: NodeStatusPayload,
    pub term: Term,
    pub lease_id: Option<LeaseId>,
}

#[allow(clippy::too_many_arguments)]
pub fn send_heartbeat(
    manager: &mut PeerConnectionManager,
    process_session: &mut ProcessSession,
    cluster_id: ClusterId,
    term: Term,
    lease_id: Option<LeaseId>,
    status: NodeStatusPayload,
    serializer: &crate::protocol::CborSerializer,
    authenticator: &MessageAuthenticator,
) -> Result<(), HeartbeatError> {
    let (peer_node_id, local_node_id, peer_session_id, highest_sequence) =
        manager_metadata(manager)?;
    let heartbeat = build_heartbeat(
        process_session,
        cluster_id.clone(),
        local_node_id.clone(),
        peer_node_id.clone(),
        term,
        lease_id,
        status,
    )?;
    let received = {
        let connection = manager
            .connection_mut()
            .ok_or(HeartbeatError::NoConnection)?;
        connection
            .send_message(heartbeat, serializer, authenticator)
            .map_err(HeartbeatError::Tcp)?;
        connection
            .receive_message(serializer, authenticator)
            .map_err(HeartbeatError::Tcp)?
    };
    let message = match received {
        ReceiveMessageResult::Eof => return Err(HeartbeatError::CleanEof),
        ReceiveMessageResult::Message(message) => message,
    };
    validate_peer_message(
        &message,
        &cluster_id,
        &local_node_id,
        &peer_node_id,
        &peer_session_id,
        highest_sequence,
        ProtocolMessageKind::HeartbeatAck,
    )?;
    manager
        .commit_peer_sequence(
            &message.unsigned().common.session_id,
            message.unsigned().common.sequence,
        )
        .map_err(HeartbeatError::Commit)
}

#[allow(clippy::too_many_arguments)]
pub fn send_heartbeat_and_record_success(
    manager: &mut PeerConnectionManager,
    process_session: &mut ProcessSession,
    cluster_id: ClusterId,
    term: Term,
    lease_id: Option<LeaseId>,
    status: NodeStatusPayload,
    serializer: &crate::protocol::CborSerializer,
    authenticator: &MessageAuthenticator,
    tracker: &mut PeerLivenessTracker,
    now: Instant,
) -> Result<(), HeartbeatRuntimeError> {
    send_heartbeat(
        manager,
        process_session,
        cluster_id,
        term,
        lease_id,
        status,
        serializer,
        authenticator,
    )
    .map_err(HeartbeatRuntimeError::Heartbeat)?;
    tracker
        .record_success(now)
        .map_err(HeartbeatRuntimeError::Liveness)
}

pub fn receive_heartbeat(
    manager: &mut PeerConnectionManager,
    process_session: &mut ProcessSession,
    cluster_id: ClusterId,
    term: Term,
    lease_id: Option<LeaseId>,
    serializer: &crate::protocol::CborSerializer,
    authenticator: &MessageAuthenticator,
) -> Result<HeartbeatObservation, HeartbeatError> {
    let observation =
        receive_heartbeat_and_commit(manager, cluster_id.clone(), serializer, authenticator)?;
    send_heartbeat_ack(
        manager,
        process_session,
        cluster_id,
        term,
        lease_id,
        serializer,
        authenticator,
    )?;
    Ok(observation)
}

#[allow(clippy::too_many_arguments)]
pub fn receive_heartbeat_and_record_success(
    manager: &mut PeerConnectionManager,
    process_session: &mut ProcessSession,
    cluster_id: ClusterId,
    term: Term,
    lease_id: Option<LeaseId>,
    serializer: &crate::protocol::CborSerializer,
    authenticator: &MessageAuthenticator,
    tracker: &mut PeerLivenessTracker,
    now: Instant,
) -> Result<HeartbeatObservation, HeartbeatRuntimeError> {
    let observation =
        receive_heartbeat_and_commit(manager, cluster_id.clone(), serializer, authenticator)
            .map_err(HeartbeatRuntimeError::Heartbeat)?;
    tracker
        .record_success(now)
        .map_err(HeartbeatRuntimeError::Liveness)?;
    send_heartbeat_ack(
        manager,
        process_session,
        cluster_id,
        term,
        lease_id,
        serializer,
        authenticator,
    )
    .map_err(HeartbeatRuntimeError::Heartbeat)?;
    Ok(observation)
}

fn receive_heartbeat_and_commit(
    manager: &mut PeerConnectionManager,
    cluster_id: ClusterId,
    serializer: &crate::protocol::CborSerializer,
    authenticator: &MessageAuthenticator,
) -> Result<HeartbeatObservation, HeartbeatError> {
    let (peer_node_id, local_node_id, peer_session_id, highest_sequence) =
        manager_metadata(manager)?;
    let received = {
        let connection = manager
            .connection_mut()
            .ok_or(HeartbeatError::NoConnection)?;
        connection
            .receive_message(serializer, authenticator)
            .map_err(HeartbeatError::Tcp)?
    };
    let message = match received {
        ReceiveMessageResult::Eof => return Err(HeartbeatError::CleanEof),
        ReceiveMessageResult::Message(message) => message,
    };
    validate_peer_message(
        &message,
        &cluster_id,
        &local_node_id,
        &peer_node_id,
        &peer_session_id,
        highest_sequence,
        ProtocolMessageKind::Heartbeat,
    )?;
    let common = &message.unsigned().common;
    let status = match &message.unsigned().message {
        ProtocolMessage::Heartbeat(status) => status.clone(),
        ProtocolMessage::HeartbeatAck => return Err(HeartbeatError::UnexpectedMessage),
        _ => return Err(HeartbeatError::UnexpectedMessage),
    };
    manager
        .commit_peer_sequence(&common.session_id, common.sequence)
        .map_err(HeartbeatError::Commit)?;
    Ok(HeartbeatObservation {
        status,
        term: common.term,
        lease_id: common.lease_id.clone(),
    })
}

fn send_heartbeat_ack(
    manager: &mut PeerConnectionManager,
    process_session: &mut ProcessSession,
    cluster_id: ClusterId,
    term: Term,
    lease_id: Option<LeaseId>,
    serializer: &crate::protocol::CborSerializer,
    authenticator: &MessageAuthenticator,
) -> Result<(), HeartbeatError> {
    if !manager.has_connection() {
        return Err(HeartbeatError::NoConnection);
    }
    let ack = build_heartbeat_ack(
        process_session,
        cluster_id,
        manager.local_node_id().clone(),
        manager.peer_node_id().clone(),
        term,
        lease_id,
    )?;
    manager
        .connection_mut()
        .ok_or(HeartbeatError::NoConnection)?
        .send_message(ack, serializer, authenticator)
        .map_err(HeartbeatError::Tcp)
}

fn manager_metadata(
    manager: &PeerConnectionManager,
) -> Result<(NodeId, NodeId, crate::protocol::SessionId, Sequence), HeartbeatError> {
    if !manager.has_connection() {
        return Err(HeartbeatError::NoConnection);
    }
    let replay = manager
        .replay_state()
        .ok_or(HeartbeatError::MissingReplayState)?;
    Ok((
        manager.peer_node_id().clone(),
        manager.local_node_id().clone(),
        replay.session_id().clone(),
        replay.highest_accepted_sequence(),
    ))
}

#[derive(Clone, Copy)]
enum ProtocolMessageKind {
    Heartbeat,
    HeartbeatAck,
}

fn validate_peer_message(
    message: &crate::receive::AuthenticatedMessage,
    cluster_id: &ClusterId,
    local_node_id: &NodeId,
    peer_node_id: &NodeId,
    peer_session_id: &crate::protocol::SessionId,
    highest_sequence: Sequence,
    expected_kind: ProtocolMessageKind,
) -> Result<(), HeartbeatError> {
    let common = &message.unsigned().common;
    if common.cluster_id != *cluster_id {
        return Err(HeartbeatError::WrongCluster);
    }
    if common.sender_node_id != *peer_node_id {
        return Err(HeartbeatError::WrongSender);
    }
    if common.receiver_node_id != *local_node_id {
        return Err(HeartbeatError::WrongReceiver);
    }
    if common.session_id != *peer_session_id {
        return Err(HeartbeatError::WrongSession);
    }
    let actual_kind = match &message.unsigned().message {
        ProtocolMessage::Heartbeat(_) => ProtocolMessageKind::Heartbeat,
        ProtocolMessage::HeartbeatAck => ProtocolMessageKind::HeartbeatAck,
        _ => return Err(HeartbeatError::UnexpectedMessage),
    };
    if !matches!(
        (actual_kind, expected_kind),
        (
            ProtocolMessageKind::Heartbeat,
            ProtocolMessageKind::Heartbeat
        ) | (
            ProtocolMessageKind::HeartbeatAck,
            ProtocolMessageKind::HeartbeatAck
        )
    ) {
        return Err(HeartbeatError::UnexpectedMessage);
    }
    if common.sequence.0 <= highest_sequence.0 {
        return Err(HeartbeatError::StaleOrDuplicateSequence);
    }
    Ok(())
}

#[derive(Debug)]
pub enum HeartbeatError {
    NoConnection,
    MissingReplayState,
    Sequence(SequenceError),
    Protocol(ProtocolError),
    Tcp(TcpError),
    Commit(PeerSequenceCommitError),
    CleanEof,
    WrongCluster,
    WrongSender,
    WrongReceiver,
    WrongSession,
    UnexpectedMessage,
    StaleOrDuplicateSequence,
}

#[derive(Debug)]
pub enum HeartbeatRuntimeError {
    Heartbeat(HeartbeatError),
    Liveness(LivenessTrackerError),
}

impl fmt::Display for HeartbeatRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Heartbeat(error) => write!(f, "heartbeat failed: {error}"),
            Self::Liveness(error) => write!(f, "liveness update failed: {error}"),
        }
    }
}

impl std::error::Error for HeartbeatRuntimeError {}

impl fmt::Display for HeartbeatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::NoConnection => "no canonical connection is available",
            Self::MissingReplayState => "peer replay state is not available",
            Self::Sequence(error) => return write!(f, "sequence allocation failed: {error}"),
            Self::Protocol(error) => {
                return write!(f, "heartbeat protocol validation failed: {error}");
            }
            Self::Tcp(error) => return write!(f, "heartbeat TCP I/O failed: {error}"),
            Self::Commit(error) => return write!(f, "peer sequence commit failed: {error}"),
            Self::CleanEof => "peer closed connection during heartbeat",
            Self::WrongCluster => "heartbeat cluster identity mismatch",
            Self::WrongSender => "heartbeat sender identity mismatch",
            Self::WrongReceiver => "heartbeat receiver identity mismatch",
            Self::WrongSession => "heartbeat peer session_id mismatch",
            Self::UnexpectedMessage => "unexpected heartbeat message",
            Self::StaleOrDuplicateSequence => "heartbeat sequence is stale or duplicate",
        };
        write!(f, "{message}")
    }
}

impl std::error::Error for HeartbeatError {}

impl From<SequenceError> for HeartbeatError {
    fn from(error: SequenceError) -> Self {
        Self::Sequence(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection_manager::{AdoptionResult, ConnectionDirection};
    use crate::handshake::{accept_peer_handshake, connect_and_handshake};
    use crate::listener::PeerListener;
    use crate::protocol::{CborSerializer, Role, SessionId};
    use crate::security::Psk;
    use crate::state_machine::{NodeState, OperationPhase};
    use std::net::SocketAddr;
    use std::thread;
    use std::time::{Duration, Instant};

    const TIMEOUT: Duration = Duration::from_secs(2);

    fn authenticator(value: u8) -> MessageAuthenticator {
        MessageAuthenticator::new(Psk::from_test_bytes([value; 32]))
    }

    fn status() -> NodeStatusPayload {
        NodeStatusPayload {
            node_state: NodeState::Standby,
            operation_phase: None::<OperationPhase>,
            role: Role::Standby,
            service_state: "running".to_string(),
            health_state: "healthy".to_string(),
            vip_state: "present".to_string(),
        }
    }

    fn manager() -> PeerConnectionManager {
        PeerConnectionManager::new(NodeId::new("node-a"), NodeId::new("node-b")).unwrap()
    }

    fn no_connection_process() -> ProcessSession {
        ProcessSession::from_session_id(SessionId::new("local-session"))
    }

    fn listener() -> (PeerListener, SocketAddr) {
        let listener =
            PeerListener::bind("127.0.0.1:0".parse().unwrap(), TIMEOUT, TIMEOUT).unwrap();
        let address = listener.local_addr().unwrap();
        (listener, address)
    }

    fn process(id: &str, next_sequence: u64) -> ProcessSession {
        let mut process = ProcessSession::from_session_id(SessionId::new(id));
        for _ in 1..next_sequence {
            process.next_sequence().unwrap();
        }
        process
    }

    fn established_managers() -> (
        PeerConnectionManager,
        PeerConnectionManager,
        ProcessSession,
        ProcessSession,
    ) {
        let (listener, address) = listener();
        let server = thread::spawn(move || {
            let (connection, _) = listener.accept().unwrap();
            let mut process = process("session-b", 1);
            accept_peer_handshake(
                connection,
                ClusterId::new("cluster"),
                NodeId::new("node-b"),
                NodeId::new("node-a"),
                120,
                &mut process,
                Term(1),
                &CborSerializer,
                &authenticator(0x0b),
            )
            .map(|result| (result, process))
        });
        let mut process_a = process("session-a", 1);
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
            &authenticator(0x0b),
        )
        .unwrap();
        let (server_result, process_b) = server.join().unwrap().unwrap();
        let mut manager_a = manager();
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

    #[test]
    fn builds_heartbeat_with_existing_status_and_fields() {
        let mut process = no_connection_process();
        let message = build_heartbeat(
            &mut process,
            ClusterId::new("cluster"),
            NodeId::new("node-a"),
            NodeId::new("node-b"),
            Term(3),
            Some(LeaseId::new("lease-a")),
            status(),
        )
        .unwrap();
        assert_eq!(message.common.session_id, SessionId::new("local-session"));
        assert_eq!(message.common.sequence, Sequence(1));
        assert_eq!(message.common.term, Term(3));
        assert_eq!(message.common.lease_id, Some(LeaseId::new("lease-a")));
        assert_eq!(message.common.request_id, None);
        assert_eq!(message.common.operation_id, None);
        assert_eq!(message.message, ProtocolMessage::Heartbeat(status()));
    }

    #[test]
    fn builds_heartbeat_ack_from_responder_process_namespace() {
        let mut process = process("session-b", 80);
        let message = build_heartbeat_ack(
            &mut process,
            ClusterId::new("cluster"),
            NodeId::new("node-b"),
            NodeId::new("node-a"),
            Term(4),
            Some(LeaseId::new("lease-b")),
        )
        .unwrap();
        assert_eq!(message.common.session_id, SessionId::new("session-b"));
        assert_eq!(message.common.sequence, Sequence(80));
        assert_eq!(message.common.term, Term(4));
        assert_eq!(message.common.lease_id, Some(LeaseId::new("lease-b")));
        assert_eq!(message.common.request_id, None);
        assert_eq!(message.common.operation_id, None);
        assert_eq!(message.message, ProtocolMessage::HeartbeatAck);
    }

    #[test]
    fn heartbeat_and_ack_use_independent_process_sequence_namespaces() {
        let mut node_a = process("session-a", 20);
        let mut node_b = process("session-b", 80);
        let heartbeat = build_heartbeat(
            &mut node_a,
            ClusterId::new("cluster"),
            NodeId::new("node-a"),
            NodeId::new("node-b"),
            Term(1),
            None,
            status(),
        )
        .unwrap();
        let ack = build_heartbeat_ack(
            &mut node_b,
            ClusterId::new("cluster"),
            NodeId::new("node-b"),
            NodeId::new("node-a"),
            Term(1),
            None,
        )
        .unwrap();
        assert_eq!(heartbeat.common.session_id, SessionId::new("session-a"));
        assert_eq!(heartbeat.common.sequence, Sequence(20));
        assert_eq!(ack.common.session_id, SessionId::new("session-b"));
        assert_eq!(ack.common.sequence, Sequence(80));
        assert_ne!(ack.common.sequence, heartbeat.common.sequence);
    }

    #[test]
    fn reports_no_connection_without_connecting() {
        let mut manager = manager();
        let mut process = no_connection_process();
        assert!(matches!(
            send_heartbeat(
                &mut manager,
                &mut process,
                ClusterId::new("cluster"),
                Term(1),
                None,
                status(),
                &CborSerializer,
                &authenticator(0x0b),
            ),
            Err(HeartbeatError::NoConnection)
        ));
        assert!(matches!(
            receive_heartbeat(
                &mut manager,
                &mut process,
                ClusterId::new("cluster"),
                Term(1),
                None,
                &CborSerializer,
                &authenticator(0x0b),
            ),
            Err(HeartbeatError::NoConnection)
        ));
    }

    #[test]
    fn commits_peer_sequence_with_gap_and_rejects_stale_or_wrong_session() {
        let mut manager = manager();
        let result = crate::handshake::HandshakeResult {
            connection: {
                let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                let address = listener.local_addr().unwrap();
                let client =
                    crate::tcp::TcpConnection::connect(address, TIMEOUT, TIMEOUT, TIMEOUT).unwrap();
                let (stream, _) = listener.accept().unwrap();
                drop(stream);
                client
            },
            peer_session_id: SessionId::new("peer"),
            peer_last_accepted_sequence: Sequence(40),
        };
        assert_eq!(
            manager.adopt(ConnectionDirection::Outbound, result),
            AdoptionResult::Adopted
        );
        assert_eq!(
            manager.commit_peer_sequence(&SessionId::new("peer"), Sequence(41)),
            Ok(())
        );
        assert_eq!(
            manager.commit_peer_sequence(&SessionId::new("peer"), Sequence(100)),
            Ok(())
        );
        assert_eq!(
            manager.commit_peer_sequence(&SessionId::new("peer"), Sequence(100)),
            Err(PeerSequenceCommitError::StaleOrDuplicate)
        );
        assert_eq!(
            manager.commit_peer_sequence(&SessionId::new("other"), Sequence(101)),
            Err(PeerSequenceCommitError::SessionMismatch)
        );
        assert_eq!(
            manager.replay_state().unwrap().highest_accepted_sequence(),
            Sequence(100)
        );
    }

    #[test]
    fn completes_real_tcp_heartbeat_round_trip_and_keeps_connections() {
        let (mut manager_a, manager_b, mut process_a, mut process_b) = established_managers();
        let server = thread::spawn(move || {
            let mut manager_b = manager_b;
            let observation = receive_heartbeat(
                &mut manager_b,
                &mut process_b,
                ClusterId::new("cluster"),
                Term(2),
                Some(LeaseId::new("lease-b")),
                &CborSerializer,
                &authenticator(0x0b),
            );
            (manager_b, observation)
        });
        let observation_status = status();
        send_heartbeat(
            &mut manager_a,
            &mut process_a,
            ClusterId::new("cluster"),
            Term(2),
            Some(LeaseId::new("lease-a")),
            observation_status.clone(),
            &CborSerializer,
            &authenticator(0x0b),
        )
        .unwrap();
        assert!(manager_a.has_connection());
        assert_eq!(
            manager_a
                .replay_state()
                .unwrap()
                .highest_accepted_sequence(),
            Sequence(2)
        );
        let (manager_b, observation) = server.join().unwrap();
        let observation = observation.unwrap();
        assert!(manager_b.has_connection());
        assert_eq!(observation.status, observation_status);
        assert_eq!(observation.term, Term(2));
        assert_eq!(observation.lease_id, Some(LeaseId::new("lease-a")));
        assert_eq!(
            manager_b
                .replay_state()
                .unwrap()
                .highest_accepted_sequence(),
            Sequence(2)
        );
    }

    #[test]
    fn outbound_accepted_ack_records_liveness_success() {
        let (mut manager_a, manager_b, mut process_a, mut process_b) = established_managers();
        let server = thread::spawn(move || {
            let mut manager_b = manager_b;
            receive_heartbeat(
                &mut manager_b,
                &mut process_b,
                ClusterId::new("cluster"),
                Term(2),
                None,
                &CborSerializer,
                &authenticator(0x0b),
            )
            .unwrap();
        });
        let now = Instant::now();
        let mut tracker = PeerLivenessTracker::new();
        send_heartbeat_and_record_success(
            &mut manager_a,
            &mut process_a,
            ClusterId::new("cluster"),
            Term(2),
            None,
            status(),
            &CborSerializer,
            &authenticator(0x0b),
            &mut tracker,
            now,
        )
        .unwrap();
        server.join().unwrap();
        assert_eq!(tracker.last_success(), Some(now));
    }

    #[test]
    fn inbound_accepted_heartbeat_records_liveness_before_ack() {
        let (mut manager_a, mut manager_b, mut process_a, mut process_b) = established_managers();
        let now = Instant::now();
        let server = thread::spawn(move || {
            let mut tracker = PeerLivenessTracker::new();
            let result = receive_heartbeat_and_record_success(
                &mut manager_b,
                &mut process_b,
                ClusterId::new("cluster"),
                Term(2),
                None,
                &CborSerializer,
                &authenticator(0x0b),
                &mut tracker,
                now,
            );
            (manager_b, tracker, result)
        });
        send_heartbeat(
            &mut manager_a,
            &mut process_a,
            ClusterId::new("cluster"),
            Term(2),
            None,
            status(),
            &CborSerializer,
            &authenticator(0x0b),
        )
        .unwrap();
        let (manager_b, tracker, result) = server.join().unwrap();
        result.unwrap();
        assert_eq!(tracker.last_success(), Some(now));
        assert_eq!(
            manager_b
                .replay_state()
                .unwrap()
                .highest_accepted_sequence(),
            Sequence(2)
        );
    }

    #[test]
    fn outbound_tracker_time_reversal_does_not_rollback_peer_commit() {
        let (mut manager_a, manager_b, mut process_a, mut process_b) = established_managers();
        let server = thread::spawn(move || {
            let mut manager_b = manager_b;
            receive_heartbeat(
                &mut manager_b,
                &mut process_b,
                ClusterId::new("cluster"),
                Term(2),
                None,
                &CborSerializer,
                &authenticator(0x0b),
            )
            .unwrap();
        });
        let t1 = Instant::now();
        let t0 = t1 - Duration::from_secs(1);
        let mut tracker = PeerLivenessTracker::new();
        tracker.record_success(t1).unwrap();
        let result = send_heartbeat_and_record_success(
            &mut manager_a,
            &mut process_a,
            ClusterId::new("cluster"),
            Term(2),
            None,
            status(),
            &CborSerializer,
            &authenticator(0x0b),
            &mut tracker,
            t0,
        );
        server.join().unwrap();
        assert!(matches!(
            result,
            Err(HeartbeatRuntimeError::Liveness(
                LivenessTrackerError::TimeWentBackwards
            ))
        ));
        assert_eq!(tracker.last_success(), Some(t1));
        assert_eq!(
            manager_a
                .replay_state()
                .unwrap()
                .highest_accepted_sequence(),
            Sequence(2)
        );
    }

    #[test]
    fn inbound_tracker_time_reversal_commits_without_sending_ack() {
        let (mut manager_a, mut manager_b, mut process_a, mut process_b) = established_managers();
        let t1 = Instant::now();
        let t0 = t1 - Duration::from_secs(1);
        let mut tracker = PeerLivenessTracker::new();
        tracker.record_success(t1).unwrap();
        let server = thread::spawn(move || {
            let result = receive_heartbeat_and_record_success(
                &mut manager_b,
                &mut process_b,
                ClusterId::new("cluster"),
                Term(2),
                None,
                &CborSerializer,
                &authenticator(0x0b),
                &mut tracker,
                t0,
            );
            (manager_b, tracker, result)
        });
        let heartbeat = build_heartbeat(
            &mut process_a,
            ClusterId::new("cluster"),
            NodeId::new("node-a"),
            NodeId::new("node-b"),
            Term(2),
            None,
            status(),
        )
        .unwrap();
        manager_a
            .connection_mut()
            .unwrap()
            .send_message(heartbeat, &CborSerializer, &authenticator(0x0b))
            .unwrap();
        let (manager_b, tracker, result) = server.join().unwrap();
        assert!(matches!(
            result,
            Err(HeartbeatRuntimeError::Liveness(
                LivenessTrackerError::TimeWentBackwards
            ))
        ));
        assert_eq!(tracker.last_success(), Some(t1));
        assert_eq!(
            manager_b
                .replay_state()
                .unwrap()
                .highest_accepted_sequence(),
            Sequence(2)
        );
        drop(manager_b);
        assert!(matches!(
            manager_a
                .connection_mut()
                .unwrap()
                .receive_message(&CborSerializer, &authenticator(0x0b)),
            Ok(ReceiveMessageResult::Eof)
        ));
    }

    #[test]
    fn rejects_wrong_message_without_advancing_high_water() {
        let (mut manager_a, mut manager_b, mut process_a, mut process_b) = established_managers();
        let server = thread::spawn(move || {
            let wrong_message = build_heartbeat(
                &mut process_b,
                ClusterId::new("cluster"),
                NodeId::new("node-b"),
                NodeId::new("node-a"),
                Term(2),
                None,
                status(),
            )
            .unwrap();
            manager_b
                .connection_mut()
                .unwrap()
                .send_message(wrong_message, &CborSerializer, &authenticator(0x0b))
                .unwrap();
            manager_b
        });
        let result = send_heartbeat(
            &mut manager_a,
            &mut process_a,
            ClusterId::new("cluster"),
            Term(2),
            None,
            status(),
            &CborSerializer,
            &authenticator(0x0b),
        );
        assert!(matches!(result, Err(HeartbeatError::UnexpectedMessage)));
        assert_eq!(
            manager_a
                .replay_state()
                .unwrap()
                .highest_accepted_sequence(),
            Sequence(1)
        );
        assert!(server.join().unwrap().has_connection());
    }

    #[test]
    fn rejects_wrong_session_without_advancing_high_water() {
        let (mut manager_a, mut manager_b, mut process_a, mut process_b) = established_managers();
        let server = thread::spawn(move || {
            let mut wrong_session_ack = build_heartbeat_ack(
                &mut process_b,
                ClusterId::new("cluster"),
                NodeId::new("node-b"),
                NodeId::new("node-a"),
                Term(2),
                None,
            )
            .unwrap();
            wrong_session_ack.common.session_id = SessionId::new("other-session");
            manager_b
                .connection_mut()
                .unwrap()
                .send_message(wrong_session_ack, &CborSerializer, &authenticator(0x0b))
                .unwrap();
            manager_b
        });
        let result = send_heartbeat(
            &mut manager_a,
            &mut process_a,
            ClusterId::new("cluster"),
            Term(2),
            None,
            status(),
            &CborSerializer,
            &authenticator(0x0b),
        );
        assert!(matches!(result, Err(HeartbeatError::WrongSession)));
        assert_eq!(
            manager_a
                .replay_state()
                .unwrap()
                .highest_accepted_sequence(),
            Sequence(1)
        );
        assert!(server.join().unwrap().has_connection());
    }
}
