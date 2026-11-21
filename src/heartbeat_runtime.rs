use crate::connection_manager::PeerConnectionManager;
use crate::heartbeat::{
    HeartbeatError, HeartbeatObservation, build_heartbeat, build_heartbeat_ack,
};
use crate::liveness::{LivenessTrackerError, PeerLivenessTracker};
use crate::peer_dispatch::{
    PeerDispatchError, PeerMessageKind, PendingPeerMessage, commit_pending_peer_message,
    dispatch_next,
};
use crate::protocol::{ClusterId, ProtocolMessage, Term};
use crate::security::MessageAuthenticator;
use crate::session::ProcessSession;
use std::fmt;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeartbeatOutstandingState {
    Idle,
    AwaitingAck,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeartbeatOutstanding {
    state: HeartbeatOutstandingState,
}

impl HeartbeatOutstanding {
    pub const fn new() -> Self {
        Self {
            state: HeartbeatOutstandingState::Idle,
        }
    }

    pub const fn state(&self) -> HeartbeatOutstandingState {
        self.state
    }

    pub fn begin(&mut self) -> Result<(), HeartbeatRuntimeDispatchError> {
        if self.state != HeartbeatOutstandingState::Idle {
            return Err(HeartbeatRuntimeDispatchError::HeartbeatAlreadyOutstanding);
        }
        self.state = HeartbeatOutstandingState::AwaitingAck;
        Ok(())
    }

    fn complete(&mut self) {
        self.state = HeartbeatOutstandingState::Idle;
    }
}

impl Default for HeartbeatOutstanding {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub enum HeartbeatRuntimeDispatchError {
    Dispatcher(PeerDispatchError),
    Heartbeat(HeartbeatError),
    WrongMessageKind {
        expected: PeerMessageKind,
        actual: PeerMessageKind,
    },
    InvalidPayloadVariant,
    NoOutstandingHeartbeat,
    HeartbeatAlreadyOutstanding,
    Liveness(LivenessTrackerError),
}

impl fmt::Display for HeartbeatRuntimeDispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dispatcher(error) => write!(f, "peer dispatch failed: {error}"),
            Self::Heartbeat(error) => write!(f, "heartbeat operation failed: {error}"),
            Self::WrongMessageKind { expected, actual } => {
                write!(
                    f,
                    "wrong heartbeat message kind: expected {expected:?}, got {actual:?}"
                )
            }
            Self::InvalidPayloadVariant => write!(f, "heartbeat message payload variant mismatch"),
            Self::NoOutstandingHeartbeat => {
                write!(f, "no outstanding heartbeat is awaiting an ACK")
            }
            Self::HeartbeatAlreadyOutstanding => {
                write!(f, "a heartbeat is already awaiting an ACK")
            }
            Self::Liveness(error) => write!(f, "liveness update failed: {error}"),
        }
    }
}

impl std::error::Error for HeartbeatRuntimeDispatchError {}

#[allow(clippy::too_many_arguments)]
pub fn send_heartbeat_request(
    manager: &mut PeerConnectionManager,
    process_session: &mut ProcessSession,
    cluster_id: ClusterId,
    term: Term,
    lease_id: Option<crate::protocol::LeaseId>,
    status: crate::protocol::NodeStatusPayload,
    serializer: &crate::protocol::CborSerializer,
    authenticator: &MessageAuthenticator,
    outstanding: &mut HeartbeatOutstanding,
) -> Result<(), HeartbeatRuntimeDispatchError> {
    if outstanding.state != HeartbeatOutstandingState::Idle {
        return Err(HeartbeatRuntimeDispatchError::HeartbeatAlreadyOutstanding);
    }
    if !manager.has_connection() {
        return Err(HeartbeatRuntimeDispatchError::Heartbeat(
            HeartbeatError::NoConnection,
        ));
    }
    let heartbeat = build_heartbeat(
        process_session,
        cluster_id,
        manager.local_node_id().clone(),
        manager.peer_node_id().clone(),
        term,
        lease_id,
        status,
    )
    .map_err(HeartbeatRuntimeDispatchError::Heartbeat)?;
    manager
        .connection_mut()
        .ok_or(HeartbeatRuntimeDispatchError::Heartbeat(
            HeartbeatError::NoConnection,
        ))?
        .send_message(heartbeat, serializer, authenticator)
        .map_err(|error| HeartbeatRuntimeDispatchError::Heartbeat(HeartbeatError::Tcp(error)))?;
    outstanding.begin()
}

#[allow(clippy::too_many_arguments)]
pub fn handle_pending_heartbeat(
    manager: &mut PeerConnectionManager,
    pending: &PendingPeerMessage,
    tracker: &mut PeerLivenessTracker,
    now: Instant,
    process_session: &mut ProcessSession,
    cluster_id: ClusterId,
    term: Term,
    lease_id: Option<crate::protocol::LeaseId>,
    serializer: &crate::protocol::CborSerializer,
    authenticator: &MessageAuthenticator,
) -> Result<HeartbeatObservation, HeartbeatRuntimeDispatchError> {
    require_kind(pending, PeerMessageKind::Heartbeat)?;
    let ProtocolMessage::Heartbeat(status) = &pending.message().unsigned().message else {
        return Err(HeartbeatRuntimeDispatchError::InvalidPayloadVariant);
    };
    let observation = HeartbeatObservation {
        status: status.clone(),
        term: pending.message().unsigned().common.term,
        lease_id: pending.message().unsigned().common.lease_id.clone(),
    };
    commit_pending_peer_message(manager, pending)
        .map_err(HeartbeatRuntimeDispatchError::Dispatcher)?;
    tracker
        .record_success(now)
        .map_err(HeartbeatRuntimeDispatchError::Liveness)?;
    let ack = build_heartbeat_ack(
        process_session,
        cluster_id,
        manager.local_node_id().clone(),
        manager.peer_node_id().clone(),
        term,
        lease_id,
    )
    .map_err(HeartbeatRuntimeDispatchError::Heartbeat)?;
    manager
        .connection_mut()
        .ok_or(HeartbeatRuntimeDispatchError::Heartbeat(
            HeartbeatError::NoConnection,
        ))?
        .send_message(ack, serializer, authenticator)
        .map_err(|error| HeartbeatRuntimeDispatchError::Heartbeat(HeartbeatError::Tcp(error)))?;
    Ok(observation)
}

pub fn handle_pending_heartbeat_ack(
    manager: &mut PeerConnectionManager,
    pending: &PendingPeerMessage,
    tracker: &mut PeerLivenessTracker,
    now: Instant,
    outstanding: &mut HeartbeatOutstanding,
) -> Result<(), HeartbeatRuntimeDispatchError> {
    require_kind(pending, PeerMessageKind::HeartbeatAck)?;
    if !matches!(
        pending.message().unsigned().message,
        ProtocolMessage::HeartbeatAck
    ) {
        return Err(HeartbeatRuntimeDispatchError::InvalidPayloadVariant);
    }
    if outstanding.state != HeartbeatOutstandingState::AwaitingAck {
        return Err(HeartbeatRuntimeDispatchError::NoOutstandingHeartbeat);
    }
    commit_pending_peer_message(manager, pending)
        .map_err(HeartbeatRuntimeDispatchError::Dispatcher)?;
    let liveness_result = tracker.record_success(now);
    outstanding.complete();
    liveness_result.map_err(HeartbeatRuntimeDispatchError::Liveness)
}

pub fn dispatch_next_heartbeat_message(
    manager: &mut PeerConnectionManager,
    cluster_id: &ClusterId,
    serializer: &crate::protocol::CborSerializer,
    authenticator: &MessageAuthenticator,
) -> Result<PendingPeerMessage, HeartbeatRuntimeDispatchError> {
    dispatch_next(manager, cluster_id, serializer, authenticator)
        .map_err(HeartbeatRuntimeDispatchError::Dispatcher)
}

fn require_kind(
    pending: &PendingPeerMessage,
    expected: PeerMessageKind,
) -> Result<(), HeartbeatRuntimeDispatchError> {
    let actual = pending.kind();
    if actual == expected {
        Ok(())
    } else {
        Err(HeartbeatRuntimeDispatchError::WrongMessageKind { expected, actual })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection_manager::{AdoptionResult, ConnectionDirection};
    use crate::handshake::{accept_peer_handshake, connect_and_handshake};
    use crate::heartbeat::{build_heartbeat, build_heartbeat_ack};
    use crate::listener::PeerListener;
    use crate::peer_dispatch::dispatch_next;
    use crate::protocol::{
        CborSerializer, CommonFields, NodeId, NodeStatusPayload, ProtocolMessage, Role, Sequence,
        SessionId, StateAnnouncePayload, Term, UnsignedEnvelope,
    };
    use crate::security::{MessageAuthenticator, Psk};
    use crate::state_machine::NodeState;
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

    fn process(id: &str) -> ProcessSession {
        ProcessSession::from_session_id(SessionId::new(id))
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
        ProcessSession,
        ProcessSession,
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

    #[test]
    fn completes_one_shot_round_trip_through_dispatcher() {
        let (mut manager_a, mut manager_b, mut process_a, mut process_b) = established_managers();
        let mut outstanding = HeartbeatOutstanding::new();
        let mut tracker_a = PeerLivenessTracker::new();
        let mut tracker_b = PeerLivenessTracker::new();
        let now_a = Instant::now();
        let now_b = now_a + Duration::from_millis(1);

        send_heartbeat_request(
            &mut manager_a,
            &mut process_a,
            ClusterId::new("cluster"),
            Term(1),
            None,
            status(),
            &CborSerializer,
            &auth(),
            &mut outstanding,
        )
        .unwrap();
        assert_eq!(tracker_a.last_success(), None);
        assert_eq!(outstanding.state(), HeartbeatOutstandingState::AwaitingAck);

        let pending_b = dispatch_next(
            &mut manager_b,
            &ClusterId::new("cluster"),
            &CborSerializer,
            &auth(),
        )
        .unwrap();
        handle_pending_heartbeat(
            &mut manager_b,
            &pending_b,
            &mut tracker_b,
            now_b,
            &mut process_b,
            ClusterId::new("cluster"),
            Term(1),
            None,
            &CborSerializer,
            &auth(),
        )
        .unwrap();
        assert_eq!(tracker_b.last_success(), Some(now_b));

        let pending_a = dispatch_next(
            &mut manager_a,
            &ClusterId::new("cluster"),
            &CborSerializer,
            &auth(),
        )
        .unwrap();
        handle_pending_heartbeat_ack(
            &mut manager_a,
            &pending_a,
            &mut tracker_a,
            now_a,
            &mut outstanding,
        )
        .unwrap();
        assert_eq!(tracker_a.last_success(), Some(now_a));
        assert_eq!(outstanding.state(), HeartbeatOutstandingState::Idle);
        assert_eq!(
            manager_a
                .replay_state()
                .unwrap()
                .highest_accepted_sequence(),
            Sequence(2)
        );
        assert_eq!(
            manager_b
                .replay_state()
                .unwrap()
                .highest_accepted_sequence(),
            Sequence(2)
        );
    }

    #[test]
    fn send_request_does_not_update_liveness_and_allows_only_one_outstanding() {
        let (mut manager_a, _manager_b, mut process_a, _process_b) = established_managers();
        let mut outstanding = HeartbeatOutstanding::new();
        let tracker = PeerLivenessTracker::new();
        send_heartbeat_request(
            &mut manager_a,
            &mut process_a,
            ClusterId::new("cluster"),
            Term(1),
            None,
            status(),
            &CborSerializer,
            &auth(),
            &mut outstanding,
        )
        .unwrap();
        assert!(tracker.last_success().is_none());
        let result = send_heartbeat_request(
            &mut manager_a,
            &mut process_a,
            ClusterId::new("cluster"),
            Term(1),
            None,
            status(),
            &CborSerializer,
            &auth(),
            &mut outstanding,
        );
        assert!(matches!(
            result,
            Err(HeartbeatRuntimeDispatchError::HeartbeatAlreadyOutstanding)
        ));
        assert_eq!(outstanding.state(), HeartbeatOutstandingState::AwaitingAck);
        assert_eq!(process_a.next_sequence().unwrap(), Sequence(3));
    }

    #[test]
    fn non_heartbeat_message_does_not_cancel_outstanding_request() {
        let (mut manager_a, mut manager_b, mut process_a, process_b) = established_managers();
        let mut outstanding = HeartbeatOutstanding::new();
        send_heartbeat_request(
            &mut manager_a,
            &mut process_a,
            ClusterId::new("cluster"),
            Term(1),
            None,
            status(),
            &CborSerializer,
            &auth(),
            &mut outstanding,
        )
        .unwrap();
        let state = crate::protocol::UnsignedEnvelope {
            common: CommonFields {
                protocol_version: 1,
                cluster_id: ClusterId::new("cluster"),
                sender_node_id: NodeId::new("node-b"),
                receiver_node_id: NodeId::new("node-a"),
                session_id: SessionId::new("session-b"),
                sequence: Sequence(2),
                term: Term(1),
                lease_id: None,
                request_id: None,
                operation_id: None,
            },
            message: ProtocolMessage::StateAnnounce(StateAnnouncePayload {
                status: status(),
                reason: "interleaved".to_string(),
            }),
        };
        manager_b
            .connection_mut()
            .unwrap()
            .send_message(state, &CborSerializer, &auth())
            .unwrap();
        let pending = dispatch_next(
            &mut manager_a,
            &ClusterId::new("cluster"),
            &CborSerializer,
            &auth(),
        )
        .unwrap();
        assert_eq!(pending.kind(), PeerMessageKind::StateAnnounce);
        assert_eq!(outstanding.state(), HeartbeatOutstandingState::AwaitingAck);
        assert_eq!(
            manager_a
                .replay_state()
                .unwrap()
                .highest_accepted_sequence(),
            Sequence(1)
        );
        drop(process_b);
    }

    #[test]
    fn unsolicited_ack_is_rejected_without_commit() {
        let (mut manager_a, mut manager_b, _process_a, mut process_b) = established_managers();
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
        let mut tracker = PeerLivenessTracker::new();
        let mut outstanding = HeartbeatOutstanding::new();
        assert!(matches!(
            handle_pending_heartbeat_ack(
                &mut manager_a,
                &pending,
                &mut tracker,
                Instant::now(),
                &mut outstanding
            ),
            Err(HeartbeatRuntimeDispatchError::NoOutstandingHeartbeat)
        ));
        assert_eq!(
            manager_a
                .replay_state()
                .unwrap()
                .highest_accepted_sequence(),
            Sequence(1)
        );
        assert!(tracker.last_success().is_none());
    }

    #[test]
    fn inbound_tracker_error_commits_but_does_not_send_ack() {
        let (mut manager_a, mut manager_b, mut process_a, mut process_b) = established_managers();
        let t1 = Instant::now();
        let t0 = t1 - Duration::from_secs(1);
        let mut tracker_b = PeerLivenessTracker::new();
        tracker_b.record_success(t1).unwrap();
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
        let result = handle_pending_heartbeat(
            &mut manager_b,
            &pending,
            &mut tracker_b,
            t0,
            &mut process_b,
            ClusterId::new("cluster"),
            Term(1),
            None,
            &CborSerializer,
            &auth(),
        );
        assert!(matches!(
            result,
            Err(HeartbeatRuntimeDispatchError::Liveness(
                LivenessTrackerError::TimeWentBackwards
            ))
        ));
        assert_eq!(tracker_b.last_success(), Some(t1));
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
                .receive_message(&CborSerializer, &auth()),
            Ok(crate::tcp::ReceiveMessageResult::Eof)
        ));
    }

    #[test]
    fn ack_tracker_error_completes_outstanding_without_rollback() {
        let (mut manager_a, mut manager_b, mut process_a, mut process_b) = established_managers();
        let mut outstanding = HeartbeatOutstanding::new();
        send_heartbeat_request(
            &mut manager_a,
            &mut process_a,
            ClusterId::new("cluster"),
            Term(1),
            None,
            status(),
            &CborSerializer,
            &auth(),
            &mut outstanding,
        )
        .unwrap();
        let pending_b = dispatch_next(
            &mut manager_b,
            &ClusterId::new("cluster"),
            &CborSerializer,
            &auth(),
        )
        .unwrap();
        let mut tracker_b = PeerLivenessTracker::new();
        handle_pending_heartbeat(
            &mut manager_b,
            &pending_b,
            &mut tracker_b,
            Instant::now(),
            &mut process_b,
            ClusterId::new("cluster"),
            Term(1),
            None,
            &CborSerializer,
            &auth(),
        )
        .unwrap();
        let pending_a = dispatch_next(
            &mut manager_a,
            &ClusterId::new("cluster"),
            &CborSerializer,
            &auth(),
        )
        .unwrap();
        let t1 = Instant::now();
        let t0 = t1 - Duration::from_secs(1);
        let mut tracker_a = PeerLivenessTracker::new();
        tracker_a.record_success(t1).unwrap();
        let result = handle_pending_heartbeat_ack(
            &mut manager_a,
            &pending_a,
            &mut tracker_a,
            t0,
            &mut outstanding,
        );
        assert!(matches!(
            result,
            Err(HeartbeatRuntimeDispatchError::Liveness(
                LivenessTrackerError::TimeWentBackwards
            ))
        ));
        assert_eq!(outstanding.state(), HeartbeatOutstandingState::Idle);
        assert_eq!(tracker_a.last_success(), Some(t1));
        assert_eq!(
            manager_a
                .replay_state()
                .unwrap()
                .highest_accepted_sequence(),
            Sequence(2)
        );
    }

    #[test]
    fn wrong_pending_kind_is_rejected_without_side_effects() {
        let (mut manager_a, mut manager_b, process_a, mut process_b) = established_managers();
        let message = UnsignedEnvelope {
            common: CommonFields {
                protocol_version: 1,
                cluster_id: ClusterId::new("cluster"),
                sender_node_id: NodeId::new("node-a"),
                receiver_node_id: NodeId::new("node-b"),
                session_id: SessionId::new("session-a"),
                sequence: Sequence(2),
                term: Term(1),
                lease_id: None,
                request_id: None,
                operation_id: None,
            },
            message: ProtocolMessage::StateAnnounce(StateAnnouncePayload {
                status: status(),
                reason: "test".to_string(),
            }),
        };
        manager_a
            .connection_mut()
            .unwrap()
            .send_message(message, &CborSerializer, &auth())
            .unwrap();
        let pending = dispatch_next(
            &mut manager_b,
            &ClusterId::new("cluster"),
            &CborSerializer,
            &auth(),
        )
        .unwrap();
        let mut tracker = PeerLivenessTracker::new();
        let result = handle_pending_heartbeat(
            &mut manager_b,
            &pending,
            &mut tracker,
            Instant::now(),
            &mut process_b,
            ClusterId::new("cluster"),
            Term(1),
            None,
            &CborSerializer,
            &auth(),
        );
        assert!(matches!(
            result,
            Err(HeartbeatRuntimeDispatchError::WrongMessageKind { .. })
        ));
        assert_eq!(
            manager_b
                .replay_state()
                .unwrap()
                .highest_accepted_sequence(),
            Sequence(1)
        );
        assert!(tracker.last_success().is_none());
        drop(process_a);
    }
}
