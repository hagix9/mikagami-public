use crate::connection_manager::PeerConnectionManager;
use crate::demotion_runtime::{
    DemotionAckObservation, DemotionCommittedObservation, DemotionIntentObservation,
    DemotionOutstanding, DemotionRuntimeError, handle_pending_demotion_ack,
    handle_pending_demotion_committed, handle_pending_demotion_intent,
};
use crate::heartbeat::HeartbeatObservation;
use crate::heartbeat_runtime::{
    HeartbeatOutstanding, HeartbeatRuntimeDispatchError, handle_pending_heartbeat,
    handle_pending_heartbeat_ack,
};
use crate::liveness::PeerLivenessTracker;
use crate::peer_dispatch::{PeerDispatchError, PeerMessageKind, PendingPeerMessage, dispatch_next};
use crate::promotion_runtime::{
    PromotionCommittedObservation, PromotionIntentObservation, PromotionOutstanding,
    PromotionPeerResponse, PromotionRuntimeError, handle_pending_promotion_committed,
    handle_pending_promotion_intent, handle_pending_promotion_response,
};
use crate::protocol::{ClusterId, LeaseId, Term};
use crate::security::MessageAuthenticator;
use crate::session::ProcessSession;
use crate::state_runtime::{
    PeerStateObservation, StateAnnounceOutstanding, StateRuntimeError,
    handle_pending_state_announce, handle_pending_state_announce_ack,
};
use std::fmt;
use std::time::Instant;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerRuntimeStep {
    HeartbeatAccepted(HeartbeatObservation),
    HeartbeatAckAccepted,
    StateAnnounceAccepted(PeerStateObservation),
    StateAnnounceAckAccepted,
    PromotionIntentAccepted(PromotionIntentObservation),
    PromotionResponseAccepted(PromotionPeerResponse),
    PromotionCommittedAccepted(PromotionCommittedObservation),
    DemotionIntentAccepted(DemotionIntentObservation),
    DemotionAckAccepted(DemotionAckObservation),
    DemotionCommittedAccepted(DemotionCommittedObservation),
    Pending(Box<PendingPeerMessage>),
}

#[derive(Debug)]
pub enum PeerRuntimeError {
    Dispatcher(PeerDispatchError),
    Heartbeat(HeartbeatRuntimeDispatchError),
    State(StateRuntimeError),
    Promotion(PromotionRuntimeError),
    Demotion(DemotionRuntimeError),
}

impl fmt::Display for PeerRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dispatcher(error) => write!(f, "peer dispatch failed: {error}"),
            Self::Heartbeat(error) => write!(f, "heartbeat runtime failed: {error}"),
            Self::State(error) => write!(f, "state runtime failed: {error}"),
            Self::Promotion(error) => write!(f, "promotion runtime failed: {error}"),
            Self::Demotion(error) => write!(f, "demotion runtime failed: {error}"),
        }
    }
}

impl std::error::Error for PeerRuntimeError {}

#[allow(clippy::too_many_arguments)]
pub fn process_next_peer_message(
    manager: &mut PeerConnectionManager,
    process_session: &mut ProcessSession,
    tracker: &mut PeerLivenessTracker,
    outstanding: &mut HeartbeatOutstanding,
    state_outstanding: &mut StateAnnounceOutstanding,
    promotion_outstanding: &mut PromotionOutstanding,
    demotion_outstanding: &mut DemotionOutstanding,
    now: Instant,
    cluster_id: ClusterId,
    term: Term,
    lease_id: Option<LeaseId>,
    serializer: &crate::protocol::CborSerializer,
    authenticator: &MessageAuthenticator,
) -> Result<PeerRuntimeStep, PeerRuntimeError> {
    let pending = dispatch_next(manager, &cluster_id, serializer, authenticator)
        .map_err(PeerRuntimeError::Dispatcher)?;
    match pending.kind() {
        PeerMessageKind::Heartbeat => handle_pending_heartbeat(
            manager,
            &pending,
            tracker,
            now,
            process_session,
            cluster_id,
            term,
            lease_id,
            serializer,
            authenticator,
        )
        .map(PeerRuntimeStep::HeartbeatAccepted)
        .map_err(PeerRuntimeError::Heartbeat),
        PeerMessageKind::HeartbeatAck => {
            handle_pending_heartbeat_ack(manager, &pending, tracker, now, outstanding)
                .map(|()| PeerRuntimeStep::HeartbeatAckAccepted)
                .map_err(PeerRuntimeError::Heartbeat)
        }
        PeerMessageKind::StateAnnounce => handle_pending_state_announce(
            manager,
            &pending,
            process_session,
            cluster_id,
            term,
            lease_id,
            serializer,
            authenticator,
        )
        .map(PeerRuntimeStep::StateAnnounceAccepted)
        .map_err(PeerRuntimeError::State),
        PeerMessageKind::StateAnnounceAck => {
            handle_pending_state_announce_ack(manager, &pending, state_outstanding)
                .map(|()| PeerRuntimeStep::StateAnnounceAckAccepted)
                .map_err(PeerRuntimeError::State)
        }
        PeerMessageKind::PromotionIntent => handle_pending_promotion_intent(manager, &pending)
            .map(PeerRuntimeStep::PromotionIntentAccepted)
            .map_err(PeerRuntimeError::Promotion),
        PeerMessageKind::PromotionAck
        | PeerMessageKind::PromotionBlock
        | PeerMessageKind::PromotionUnknown => {
            handle_pending_promotion_response(manager, &pending, promotion_outstanding)
                .map(PeerRuntimeStep::PromotionResponseAccepted)
                .map_err(PeerRuntimeError::Promotion)
        }
        PeerMessageKind::PromotionCommitted => {
            handle_pending_promotion_committed(manager, &pending)
                .map(PeerRuntimeStep::PromotionCommittedAccepted)
                .map_err(PeerRuntimeError::Promotion)
        }
        PeerMessageKind::DemotionIntent => handle_pending_demotion_intent(manager, &pending)
            .map(PeerRuntimeStep::DemotionIntentAccepted)
            .map_err(PeerRuntimeError::Demotion),
        PeerMessageKind::DemotionAck => {
            handle_pending_demotion_ack(manager, &pending, demotion_outstanding)
                .map(PeerRuntimeStep::DemotionAckAccepted)
                .map_err(PeerRuntimeError::Demotion)
        }
        PeerMessageKind::DemotionCommitted => handle_pending_demotion_committed(manager, &pending)
            .map(PeerRuntimeStep::DemotionCommittedAccepted)
            .map_err(PeerRuntimeError::Demotion),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection_manager::{AdoptionResult, ConnectionDirection};
    use crate::demotion_runtime::{
        DemotionOutstanding, DemotionOutstandingState, send_demotion_ack, send_demotion_committed,
        send_demotion_intent,
    };
    use crate::handshake::HandshakeResult;
    use crate::heartbeat_runtime::{HeartbeatOutstandingState, send_heartbeat_request};
    use crate::peer_dispatch::dispatch_next;
    use crate::promotion_runtime::{
        PromotionOutstanding, PromotionOutstandingState, PromotionPeerResponseKind,
        PromotionRuntimeError, send_promotion_intent, send_promotion_response,
    };
    use crate::protocol::{
        CborSerializer, CommonFields, DemotionIntentPayload, NodeId, NodeStatusPayload,
        OperationId, ProtocolMessage, ResourceStatusPayload, Role, Sequence, SessionId,
        StateAnnouncePayload, UnsignedEnvelope,
    };
    use crate::security::{MessageAuthenticator, Psk};
    use crate::state_machine::{DemotionPhase, NodeState, OperationPhase};
    use crate::state_runtime::{
        StateAnnounceOutstanding, StateAnnounceOutstandingState, StateRuntimeError,
        handle_pending_state_announce, send_state_announce,
    };
    use crate::tcp::TcpConnection;
    use std::net::{Shutdown, TcpListener, TcpStream};
    #[cfg(unix)]
    use std::os::fd::AsRawFd;
    use std::time::Duration;

    fn auth() -> MessageAuthenticator {
        MessageAuthenticator::new(Psk::from_test_bytes([0x42; 32]))
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn reset_on_close(stream: &TcpStream) {
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
        let (socket_level, linger_option) = (0xffff, 0x0080);
        #[cfg(target_os = "linux")]
        let (socket_level, linger_option) = (1, 13);
        let result = unsafe {
            setsockopt(
                stream.as_raw_fd(),
                socket_level,
                linger_option,
                (&linger as *const Linger).cast(),
                std::mem::size_of::<Linger>() as u32,
            )
        };
        assert_eq!(result, 0);
    }

    fn status() -> NodeStatusPayload {
        NodeStatusPayload {
            node_state: NodeState::Standby,
            operation_phase: None,
            role: Role::Standby,
            service_state: "stopped".to_string(),
            health_state: "unknown".to_string(),
            vip_state: "absent".to_string(),
        }
    }

    fn managers() -> (
        PeerConnectionManager,
        PeerConnectionManager,
        ProcessSession,
        ProcessSession,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let client = std::net::TcpStream::connect(address).unwrap();
        let (server, _) = listener.accept().unwrap();
        let client =
            TcpConnection::from_stream(client, Duration::from_secs(2), Duration::from_secs(2))
                .unwrap();
        let server =
            TcpConnection::from_stream(server, Duration::from_secs(2), Duration::from_secs(2))
                .unwrap();

        let mut node_a =
            PeerConnectionManager::new(NodeId::new("node-a"), NodeId::new("node-b")).unwrap();
        let mut node_b =
            PeerConnectionManager::new(NodeId::new("node-b"), NodeId::new("node-a")).unwrap();
        assert_eq!(
            node_a.adopt(
                ConnectionDirection::Outbound,
                HandshakeResult {
                    connection: client,
                    peer_session_id: SessionId::new("session-b"),
                    peer_last_accepted_sequence: Sequence(0),
                },
            ),
            AdoptionResult::Adopted
        );
        assert_eq!(
            node_b.adopt(
                ConnectionDirection::Inbound,
                HandshakeResult {
                    connection: server,
                    peer_session_id: SessionId::new("session-a"),
                    peer_last_accepted_sequence: Sequence(0),
                },
            ),
            AdoptionResult::Adopted
        );
        (
            node_a,
            node_b,
            ProcessSession::from_session_id(SessionId::new("session-a")),
            ProcessSession::from_session_id(SessionId::new("session-b")),
        )
    }

    #[test]
    fn no_connection_is_returned_without_consuming_runtime_state() {
        let mut manager =
            PeerConnectionManager::new(NodeId::new("node-a"), NodeId::new("node-b")).unwrap();
        let mut process = ProcessSession::from_session_id(SessionId::new("session-a"));
        let mut tracker = PeerLivenessTracker::new();
        let mut outstanding = HeartbeatOutstanding::new();
        let mut state_outstanding = StateAnnounceOutstanding::new();
        let result = process_next_peer_message(
            &mut manager,
            &mut process,
            &mut tracker,
            &mut outstanding,
            &mut state_outstanding,
            &mut PromotionOutstanding::new(),
            &mut DemotionOutstanding::new(),
            Instant::now(),
            ClusterId::new("cluster"),
            Term(1),
            None,
            &CborSerializer,
            &auth(),
        );
        assert!(matches!(
            result,
            Err(PeerRuntimeError::Dispatcher(
                PeerDispatchError::NoConnection
            ))
        ));
        assert_eq!(tracker.last_success(), None);
        assert_eq!(outstanding.state(), HeartbeatOutstandingState::Idle);
    }

    #[test]
    fn process_next_routes_heartbeat_and_ack_through_the_runtime_handlers() {
        let (mut node_a, mut node_b, mut process_a, mut process_b) = managers();
        let serializer = CborSerializer;
        let authenticator = auth();
        let mut tracker_a = PeerLivenessTracker::new();
        let mut tracker_b = PeerLivenessTracker::new();
        let mut outstanding_a = HeartbeatOutstanding::new();
        let mut outstanding_b = HeartbeatOutstanding::new();
        let mut state_outstanding_b = StateAnnounceOutstanding::new();
        let now = Instant::now();

        send_heartbeat_request(
            &mut node_a,
            &mut process_a,
            ClusterId::new("cluster"),
            Term(1),
            None,
            status(),
            &serializer,
            &authenticator,
            &mut outstanding_a,
        )
        .unwrap();

        assert!(matches!(
            process_next_peer_message(
                &mut node_b,
                &mut process_b,
                &mut tracker_b,
                &mut outstanding_b,
                &mut state_outstanding_b,
                &mut PromotionOutstanding::new(),
                &mut DemotionOutstanding::new(),
                now,
                ClusterId::new("cluster"),
                Term(1),
                None,
                &serializer,
                &authenticator,
            )
            .unwrap(),
            PeerRuntimeStep::HeartbeatAccepted(_)
        ));
        assert_eq!(tracker_b.last_success(), Some(now));

        assert_eq!(
            process_next_peer_message(
                &mut node_a,
                &mut process_a,
                &mut tracker_a,
                &mut outstanding_a,
                &mut StateAnnounceOutstanding::new(),
                &mut PromotionOutstanding::new(),
                &mut DemotionOutstanding::new(),
                now,
                ClusterId::new("cluster"),
                Term(1),
                None,
                &serializer,
                &authenticator,
            )
            .unwrap(),
            PeerRuntimeStep::HeartbeatAckAccepted
        );
        assert_eq!(tracker_a.last_success(), Some(now));
        assert_eq!(outstanding_a.state(), HeartbeatOutstandingState::Idle);
        assert_eq!(
            node_a.replay_state().unwrap().highest_accepted_sequence(),
            Sequence(1)
        );
        assert_eq!(
            node_b.replay_state().unwrap().highest_accepted_sequence(),
            Sequence(1)
        );
    }

    #[test]
    fn promotion_intent_send_records_operation_after_success() {
        let (mut node_a, _node_b, mut process_a, _process_b) = managers();
        let mut outstanding = PromotionOutstanding::new();
        let operation_id = OperationId::new("operation-a");

        send_promotion_intent(
            &mut node_a,
            &mut process_a,
            &mut outstanding,
            ClusterId::new("cluster"),
            Term(1),
            None,
            operation_id.clone(),
            100,
            "operator request".to_string(),
            &CborSerializer,
            &auth(),
        )
        .unwrap();

        assert_eq!(
            outstanding.state(),
            &PromotionOutstandingState::AwaitingResponse { operation_id }
        );
        assert_eq!(process_a.next_sequence().unwrap(), Sequence(2));
    }

    #[test]
    fn second_promotion_intent_is_rejected_before_sequence_allocation() {
        let (mut node_a, _node_b, mut process_a, _process_b) = managers();
        let mut outstanding = PromotionOutstanding::new();
        let serializer = CborSerializer;
        let authenticator = auth();

        send_promotion_intent(
            &mut node_a,
            &mut process_a,
            &mut outstanding,
            ClusterId::new("cluster"),
            Term(1),
            None,
            OperationId::new("operation-a"),
            100,
            "first".to_string(),
            &serializer,
            &authenticator,
        )
        .unwrap();
        let result = send_promotion_intent(
            &mut node_a,
            &mut process_a,
            &mut outstanding,
            ClusterId::new("cluster"),
            Term(1),
            None,
            OperationId::new("operation-b"),
            90,
            "second".to_string(),
            &serializer,
            &authenticator,
        );

        assert!(matches!(
            result,
            Err(PromotionRuntimeError::PromotionAlreadyOutstanding)
        ));
        assert_eq!(process_a.next_sequence().unwrap(), Sequence(2));
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn failed_promotion_intent_send_keeps_idle_and_does_not_reuse_sequence() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let client = TcpStream::connect(address).unwrap();
        let (server, _) = listener.accept().unwrap();
        let server_control = server.try_clone().unwrap();
        reset_on_close(&server_control);
        drop(server_control);
        let client =
            TcpConnection::from_stream(client, Duration::from_secs(2), Duration::from_secs(2))
                .unwrap();
        let server =
            TcpConnection::from_stream(server, Duration::from_secs(2), Duration::from_secs(2))
                .unwrap();
        let mut node_a =
            PeerConnectionManager::new(NodeId::new("node-a"), NodeId::new("node-b")).unwrap();
        let mut node_b =
            PeerConnectionManager::new(NodeId::new("node-b"), NodeId::new("node-a")).unwrap();
        assert_eq!(
            node_a.adopt(
                ConnectionDirection::Outbound,
                HandshakeResult {
                    connection: client,
                    peer_session_id: SessionId::new("session-b"),
                    peer_last_accepted_sequence: Sequence(0)
                }
            ),
            AdoptionResult::Adopted
        );
        assert_eq!(
            node_b.adopt(
                ConnectionDirection::Inbound,
                HandshakeResult {
                    connection: server,
                    peer_session_id: SessionId::new("session-a"),
                    peer_last_accepted_sequence: Sequence(0)
                }
            ),
            AdoptionResult::Adopted
        );
        drop(node_b);

        let mut process_a = ProcessSession::from_session_id(SessionId::new("session-a"));
        let mut outstanding = PromotionOutstanding::new();
        let result = send_promotion_intent(
            &mut node_a,
            &mut process_a,
            &mut outstanding,
            ClusterId::new("cluster"),
            Term(1),
            None,
            OperationId::new("operation-a"),
            100,
            "failure".to_string(),
            &CborSerializer,
            &auth(),
        );
        assert!(matches!(result, Err(PromotionRuntimeError::Tcp(_))));
        assert_eq!(outstanding.state(), &PromotionOutstandingState::Idle);
        assert_eq!(process_a.next_sequence().unwrap(), Sequence(2));
    }

    #[test]
    fn inbound_promotion_intent_is_observed_and_committed_without_runtime_side_effects() {
        let (mut node_a, mut node_b, mut process_a, mut process_b) = managers();
        let serializer = CborSerializer;
        let authenticator = auth();
        let operation_id = OperationId::new("operation-a");
        let mut sender_outstanding = PromotionOutstanding::new();

        send_promotion_intent(
            &mut node_a,
            &mut process_a,
            &mut sender_outstanding,
            ClusterId::new("cluster"),
            Term(7),
            None,
            operation_id.clone(),
            100,
            "promote".to_string(),
            &serializer,
            &authenticator,
        )
        .unwrap();

        let mut tracker = PeerLivenessTracker::new();
        let mut heartbeat_outstanding = HeartbeatOutstanding::new();
        let mut state_outstanding = StateAnnounceOutstanding::new();
        let mut promotion_outstanding = PromotionOutstanding::new();
        let step = process_next_peer_message(
            &mut node_b,
            &mut process_b,
            &mut tracker,
            &mut heartbeat_outstanding,
            &mut state_outstanding,
            &mut promotion_outstanding,
            &mut DemotionOutstanding::new(),
            Instant::now(),
            ClusterId::new("cluster"),
            Term(7),
            None,
            &serializer,
            &authenticator,
        )
        .unwrap();

        let PeerRuntimeStep::PromotionIntentAccepted(observation) = step else {
            panic!("expected promotion intent observation");
        };
        assert_eq!(observation.operation_id, operation_id);
        assert_eq!(observation.priority, 100);
        assert_eq!(observation.reason, "promote");
        assert_eq!(observation.term, Term(7));
        assert_eq!(
            node_b.replay_state().unwrap().highest_accepted_sequence(),
            Sequence(1)
        );
        assert_eq!(tracker.last_success(), None);
        assert_eq!(
            heartbeat_outstanding.state(),
            HeartbeatOutstandingState::Idle
        );
        assert_eq!(
            promotion_outstanding.state(),
            &PromotionOutstandingState::Idle
        );
    }

    #[test]
    fn promotion_committed_is_an_observation_without_authority_side_effects() {
        let (mut node_a, mut node_b, mut process_a, _process_b) = managers();
        let serializer = CborSerializer;
        let authenticator = auth();
        let operation_id = OperationId::new("operation-a");
        let mut promotion = PromotionOutstanding::new();
        send_promotion_intent(
            &mut node_a,
            &mut process_a,
            &mut promotion,
            ClusterId::new("cluster"),
            Term(2),
            None,
            operation_id.clone(),
            100,
            "promote".to_string(),
            &serializer,
            &authenticator,
        )
        .unwrap();
        let mut heartbeat = HeartbeatOutstanding::new();
        send_heartbeat_request(
            &mut node_a,
            &mut process_a,
            ClusterId::new("cluster"),
            Term(2),
            None,
            status(),
            &serializer,
            &authenticator,
            &mut heartbeat,
        )
        .unwrap();
        let committed = UnsignedEnvelope {
            common: CommonFields {
                protocol_version: crate::protocol::PROTOCOL_VERSION,
                cluster_id: ClusterId::new("cluster"),
                sender_node_id: NodeId::new("node-b"),
                receiver_node_id: NodeId::new("node-a"),
                session_id: SessionId::new("session-b"),
                sequence: Sequence(1),
                term: Term(2),
                lease_id: Some(crate::protocol::LeaseId::new("lease-b")),
                request_id: None,
                operation_id: Some(operation_id.clone()),
            },
            message: ProtocolMessage::PromotionCommitted(ResourceStatusPayload {
                service_state: "running".to_string(),
                vip_state: "present".to_string(),
            }),
        };
        node_b
            .connection_mut()
            .unwrap()
            .send_message(committed, &serializer, &authenticator)
            .unwrap();

        let mut tracker = PeerLivenessTracker::new();
        let mut state = StateAnnounceOutstanding::new();
        let step = process_next_peer_message(
            &mut node_a,
            &mut process_a,
            &mut tracker,
            &mut heartbeat,
            &mut state,
            &mut promotion,
            &mut DemotionOutstanding::new(),
            Instant::now(),
            ClusterId::new("cluster"),
            Term(2),
            None,
            &serializer,
            &authenticator,
        )
        .unwrap();
        let PeerRuntimeStep::PromotionCommittedAccepted(observation) = step else {
            panic!("expected promotion committed observation");
        };
        assert_eq!(observation.operation_id, operation_id);
        assert_eq!(observation.term, Term(2));
        assert_eq!(
            observation.lease_id,
            Some(crate::protocol::LeaseId::new("lease-b"))
        );
        assert_eq!(observation.role, Role::Active);
        assert_eq!(observation.service_state, "running");
        assert_eq!(observation.vip_state, "present");
        assert_eq!(tracker.last_success(), None);
        assert_eq!(heartbeat.state(), HeartbeatOutstandingState::AwaitingAck);
        assert_eq!(
            promotion.state(),
            &PromotionOutstandingState::AwaitingResponse { operation_id }
        );
        assert_eq!(
            node_a.replay_state().unwrap().highest_accepted_sequence(),
            Sequence(1)
        );
    }

    #[test]
    fn matching_promotion_responses_complete_the_outstanding_operation() {
        for kind in [
            PromotionPeerResponseKind::Ack,
            PromotionPeerResponseKind::Block,
            PromotionPeerResponseKind::Unknown,
        ] {
            let (mut node_a, mut node_b, mut process_a, mut process_b) = managers();
            let serializer = CborSerializer;
            let authenticator = auth();
            let operation_id = OperationId::new("operation-a");
            let mut promotion_outstanding = PromotionOutstanding::new();
            send_promotion_intent(
                &mut node_a,
                &mut process_a,
                &mut promotion_outstanding,
                ClusterId::new("cluster"),
                Term(1),
                None,
                operation_id.clone(),
                100,
                "promote".to_string(),
                &serializer,
                &authenticator,
            )
            .unwrap();

            let mut tracker_b = PeerLivenessTracker::new();
            let mut heartbeat_b = HeartbeatOutstanding::new();
            let mut state_b = StateAnnounceOutstanding::new();
            process_next_peer_message(
                &mut node_b,
                &mut process_b,
                &mut tracker_b,
                &mut heartbeat_b,
                &mut state_b,
                &mut PromotionOutstanding::new(),
                &mut DemotionOutstanding::new(),
                Instant::now(),
                ClusterId::new("cluster"),
                Term(1),
                None,
                &serializer,
                &authenticator,
            )
            .unwrap();
            send_promotion_response(
                &mut node_b,
                &mut process_b,
                ClusterId::new("cluster"),
                Term(1),
                None,
                operation_id.clone(),
                kind,
                &serializer,
                &authenticator,
            )
            .unwrap();

            let mut tracker_a = PeerLivenessTracker::new();
            let mut heartbeat_a = HeartbeatOutstanding::new();
            let mut state_a = StateAnnounceOutstanding::new();
            let step = process_next_peer_message(
                &mut node_a,
                &mut process_a,
                &mut tracker_a,
                &mut heartbeat_a,
                &mut state_a,
                &mut promotion_outstanding,
                &mut DemotionOutstanding::new(),
                Instant::now(),
                ClusterId::new("cluster"),
                Term(1),
                None,
                &serializer,
                &authenticator,
            )
            .unwrap();
            assert_eq!(
                step,
                PeerRuntimeStep::PromotionResponseAccepted(
                    crate::promotion_runtime::PromotionPeerResponse { operation_id, kind }
                )
            );
            assert_eq!(
                promotion_outstanding.state(),
                &PromotionOutstandingState::Idle
            );
            assert_eq!(tracker_a.last_success(), None);
            assert_eq!(heartbeat_a.state(), HeartbeatOutstandingState::Idle);
            assert_eq!(
                node_a.replay_state().unwrap().highest_accepted_sequence(),
                Sequence(1)
            );
        }
    }

    #[test]
    fn cloned_promotion_committed_pending_cannot_be_accepted_twice() {
        let (mut node_a, mut node_b, _process_a, _process_b) = managers();
        let message = UnsignedEnvelope {
            common: CommonFields {
                protocol_version: crate::protocol::PROTOCOL_VERSION,
                cluster_id: ClusterId::new("cluster"),
                sender_node_id: NodeId::new("node-b"),
                receiver_node_id: NodeId::new("node-a"),
                session_id: SessionId::new("session-b"),
                sequence: Sequence(1),
                term: Term(3),
                lease_id: None,
                request_id: None,
                operation_id: Some(OperationId::new("operation-a")),
            },
            message: ProtocolMessage::PromotionCommitted(ResourceStatusPayload {
                service_state: "running".to_string(),
                vip_state: "present".to_string(),
            }),
        };
        node_b
            .connection_mut()
            .unwrap()
            .send_message(message, &CborSerializer, &auth())
            .unwrap();
        let pending = dispatch_next(
            &mut node_a,
            &ClusterId::new("cluster"),
            &CborSerializer,
            &auth(),
        )
        .unwrap();
        let clone = pending.clone();
        let first =
            crate::promotion_runtime::handle_pending_promotion_committed(&mut node_a, &pending)
                .unwrap();
        assert_eq!(first.operation_id, OperationId::new("operation-a"));
        assert!(matches!(
            crate::promotion_runtime::handle_pending_promotion_committed(&mut node_a, &clone),
            Err(PromotionRuntimeError::Dispatcher(_))
        ));
        assert_eq!(
            node_a.replay_state().unwrap().highest_accepted_sequence(),
            Sequence(1)
        );
    }

    #[test]
    fn unsolicited_or_wrong_operation_promotion_responses_do_not_commit() {
        for kind in [
            PromotionPeerResponseKind::Ack,
            PromotionPeerResponseKind::Block,
            PromotionPeerResponseKind::Unknown,
        ] {
            let (mut node_a, mut node_b, mut process_a, mut process_b) = managers();
            let serializer = CborSerializer;
            let authenticator = auth();
            send_promotion_response(
                &mut node_b,
                &mut process_b,
                ClusterId::new("cluster"),
                Term(1),
                None,
                OperationId::new("operation-a"),
                kind,
                &serializer,
                &authenticator,
            )
            .unwrap();
            let mut tracker = PeerLivenessTracker::new();
            let mut heartbeat = HeartbeatOutstanding::new();
            let mut state = StateAnnounceOutstanding::new();
            let mut promotion = PromotionOutstanding::new();
            let result = process_next_peer_message(
                &mut node_a,
                &mut process_a,
                &mut tracker,
                &mut heartbeat,
                &mut state,
                &mut promotion,
                &mut DemotionOutstanding::new(),
                Instant::now(),
                ClusterId::new("cluster"),
                Term(1),
                None,
                &serializer,
                &authenticator,
            );
            assert!(matches!(
                result,
                Err(PeerRuntimeError::Promotion(
                    PromotionRuntimeError::NoOutstandingPromotion
                ))
            ));
            assert_eq!(
                node_a.replay_state().unwrap().highest_accepted_sequence(),
                Sequence(0)
            );
        }

        for kind in [
            PromotionPeerResponseKind::Ack,
            PromotionPeerResponseKind::Block,
            PromotionPeerResponseKind::Unknown,
        ] {
            let (mut node_a, mut node_b, mut process_a, mut process_b) = managers();
            let serializer = CborSerializer;
            let authenticator = auth();
            let expected = OperationId::new("operation-a");
            let mut promotion = PromotionOutstanding::new();
            send_promotion_intent(
                &mut node_a,
                &mut process_a,
                &mut promotion,
                ClusterId::new("cluster"),
                Term(1),
                None,
                expected.clone(),
                100,
                "promote".to_string(),
                &serializer,
                &authenticator,
            )
            .unwrap();
            let mut tracker_b = PeerLivenessTracker::new();
            let mut heartbeat_b = HeartbeatOutstanding::new();
            let mut state_b = StateAnnounceOutstanding::new();
            process_next_peer_message(
                &mut node_b,
                &mut process_b,
                &mut tracker_b,
                &mut heartbeat_b,
                &mut state_b,
                &mut PromotionOutstanding::new(),
                &mut DemotionOutstanding::new(),
                Instant::now(),
                ClusterId::new("cluster"),
                Term(1),
                None,
                &serializer,
                &authenticator,
            )
            .unwrap();
            send_promotion_response(
                &mut node_b,
                &mut process_b,
                ClusterId::new("cluster"),
                Term(1),
                None,
                OperationId::new("operation-b"),
                kind,
                &serializer,
                &authenticator,
            )
            .unwrap();
            let mut tracker_a = PeerLivenessTracker::new();
            let mut heartbeat_a = HeartbeatOutstanding::new();
            let mut state_a = StateAnnounceOutstanding::new();
            let result = process_next_peer_message(
                &mut node_a,
                &mut process_a,
                &mut tracker_a,
                &mut heartbeat_a,
                &mut state_a,
                &mut promotion,
                &mut DemotionOutstanding::new(),
                Instant::now(),
                ClusterId::new("cluster"),
                Term(1),
                None,
                &serializer,
                &authenticator,
            );
            assert!(matches!(
                result,
                Err(PeerRuntimeError::Promotion(
                    PromotionRuntimeError::OperationIdMismatch { .. }
                ))
            ));
            assert_eq!(
                promotion.state(),
                &PromotionOutstandingState::AwaitingResponse {
                    operation_id: expected
                }
            );
            assert_eq!(
                node_a.replay_state().unwrap().highest_accepted_sequence(),
                Sequence(0)
            );
        }
    }

    #[test]
    fn process_next_returns_non_heartbeat_as_owned_uncommitted_pending() {
        let (mut node_a, mut node_b, _process_a, mut process_b) = managers();
        let serializer = CborSerializer;
        let authenticator = auth();
        let message = crate::protocol::UnsignedEnvelope {
            common: CommonFields {
                protocol_version: crate::protocol::PROTOCOL_VERSION,
                cluster_id: ClusterId::new("cluster"),
                sender_node_id: NodeId::new("node-a"),
                receiver_node_id: NodeId::new("node-b"),
                session_id: SessionId::new("session-a"),
                sequence: Sequence(1),
                term: Term(1),
                lease_id: None,
                request_id: None,
                operation_id: None,
            },
            message: ProtocolMessage::StateAnnounce(StateAnnouncePayload {
                status: status(),
                reason: "runtime test".to_string(),
            }),
        };
        node_a
            .connection_mut()
            .unwrap()
            .send_message(message, &serializer, &authenticator)
            .unwrap();

        let mut tracker = PeerLivenessTracker::new();
        let mut outstanding = HeartbeatOutstanding::new();
        let mut state_outstanding = StateAnnounceOutstanding::new();
        let observation = process_next_peer_message(
            &mut node_b,
            &mut process_b,
            &mut tracker,
            &mut outstanding,
            &mut state_outstanding,
            &mut PromotionOutstanding::new(),
            &mut DemotionOutstanding::new(),
            Instant::now(),
            ClusterId::new("cluster"),
            Term(1),
            None,
            &serializer,
            &authenticator,
        )
        .unwrap();
        let PeerRuntimeStep::StateAnnounceAccepted(observation) = observation else {
            panic!("expected accepted state announcement");
        };
        assert_eq!(observation.status, status());
        assert_eq!(observation.reason, "runtime test");
        assert_eq!(tracker.last_success(), None);
        assert_eq!(
            node_b.replay_state().unwrap().highest_accepted_sequence(),
            Sequence(1)
        );
        assert!(node_a.has_connection());
    }

    #[test]
    fn state_announce_preserves_heartbeat_awaiting_ack_and_liveness_state() {
        let (mut node_a, mut node_b, mut process_a, process_b) = managers();
        let serializer = CborSerializer;
        let authenticator = auth();
        let mut outstanding_a = HeartbeatOutstanding::new();
        send_heartbeat_request(
            &mut node_a,
            &mut process_a,
            ClusterId::new("cluster"),
            Term(1),
            None,
            status(),
            &serializer,
            &authenticator,
            &mut outstanding_a,
        )
        .unwrap();
        assert_eq!(
            outstanding_a.state(),
            HeartbeatOutstandingState::AwaitingAck
        );

        let message = UnsignedEnvelope {
            common: CommonFields {
                protocol_version: crate::protocol::PROTOCOL_VERSION,
                cluster_id: ClusterId::new("cluster"),
                sender_node_id: NodeId::new("node-b"),
                receiver_node_id: NodeId::new("node-a"),
                session_id: SessionId::new("session-b"),
                sequence: Sequence(1),
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
        message.validate().unwrap();
        node_b
            .connection_mut()
            .unwrap()
            .send_message(message, &serializer, &authenticator)
            .unwrap();

        let mut tracker_a = PeerLivenessTracker::new();
        let mut state_outstanding_a = StateAnnounceOutstanding::new();
        let observation = process_next_peer_message(
            &mut node_a,
            &mut process_a,
            &mut tracker_a,
            &mut outstanding_a,
            &mut state_outstanding_a,
            &mut PromotionOutstanding::new(),
            &mut DemotionOutstanding::new(),
            Instant::now(),
            ClusterId::new("cluster"),
            Term(1),
            None,
            &serializer,
            &authenticator,
        )
        .unwrap();
        let PeerRuntimeStep::StateAnnounceAccepted(observation) = observation else {
            panic!("expected accepted state announcement");
        };
        assert_eq!(observation.reason, "interleaved");
        assert_eq!(
            outstanding_a.state(),
            HeartbeatOutstandingState::AwaitingAck
        );
        assert_eq!(tracker_a.last_success(), None);
        assert_eq!(
            node_a.replay_state().unwrap().highest_accepted_sequence(),
            Sequence(1)
        );
        assert!(node_a.has_connection());
        drop(process_b);
    }

    #[test]
    fn clean_eof_is_propagated_without_changing_runtime_state() {
        let (node_a, mut node_b, _process_a, mut process_b) = managers();
        let mut tracker_b = PeerLivenessTracker::new();
        let last_success = Instant::now();
        tracker_b.record_success(last_success).unwrap();
        let mut outstanding_b = HeartbeatOutstanding::new();
        let mut state_outstanding_b = StateAnnounceOutstanding::new();
        outstanding_b.begin().unwrap();
        assert_eq!(
            outstanding_b.state(),
            HeartbeatOutstandingState::AwaitingAck
        );
        drop(node_a);

        let result = process_next_peer_message(
            &mut node_b,
            &mut process_b,
            &mut tracker_b,
            &mut outstanding_b,
            &mut state_outstanding_b,
            &mut PromotionOutstanding::new(),
            &mut DemotionOutstanding::new(),
            last_success,
            ClusterId::new("cluster"),
            Term(1),
            None,
            &CborSerializer,
            &auth(),
        );
        assert!(matches!(
            result,
            Err(PeerRuntimeError::Dispatcher(PeerDispatchError::CleanEof))
        ));
        assert_eq!(tracker_b.last_success(), Some(last_success));
        assert_eq!(
            outstanding_b.state(),
            HeartbeatOutstandingState::AwaitingAck
        );
        assert!(node_b.has_connection());
    }

    #[test]
    fn demotion_messages_are_routed_as_coordination_observations() {
        let cases = [
            (
                PeerMessageKind::DemotionIntent,
                ProtocolMessage::DemotionIntent(DemotionIntentPayload {
                    phase: OperationPhase::Demotion(DemotionPhase::StopService),
                    reason: "demote".to_string(),
                }),
                true,
            ),
            (
                PeerMessageKind::DemotionCommitted,
                ProtocolMessage::DemotionCommitted(crate::protocol::DemotionCommittedPayload {
                    service_stopped: true,
                    vip_released: true,
                }),
                true,
            ),
        ];

        for (expected_kind, message, needs_operation_id) in cases {
            let (mut node_a, mut node_b, _process_a, mut process_b) = managers();
            let envelope = UnsignedEnvelope {
                common: CommonFields {
                    protocol_version: crate::protocol::PROTOCOL_VERSION,
                    cluster_id: ClusterId::new("cluster"),
                    sender_node_id: NodeId::new("node-a"),
                    receiver_node_id: NodeId::new("node-b"),
                    session_id: SessionId::new("session-a"),
                    sequence: Sequence(1),
                    term: Term(1),
                    lease_id: None,
                    request_id: None,
                    operation_id: needs_operation_id.then(|| OperationId::new("operation-1")),
                },
                message,
            };
            envelope.validate().unwrap();
            node_a
                .connection_mut()
                .unwrap()
                .send_message(envelope, &CborSerializer, &auth())
                .unwrap();

            let mut tracker = PeerLivenessTracker::new();
            let mut outstanding = HeartbeatOutstanding::new();
            let mut state_outstanding = StateAnnounceOutstanding::new();
            let result = process_next_peer_message(
                &mut node_b,
                &mut process_b,
                &mut tracker,
                &mut outstanding,
                &mut state_outstanding,
                &mut PromotionOutstanding::new(),
                &mut DemotionOutstanding::new(),
                Instant::now(),
                ClusterId::new("cluster"),
                Term(1),
                None,
                &CborSerializer,
                &auth(),
            )
            .unwrap();
            match expected_kind {
                PeerMessageKind::DemotionIntent => {
                    assert!(matches!(result, PeerRuntimeStep::DemotionIntentAccepted(_)))
                }
                PeerMessageKind::DemotionAck => {
                    assert!(matches!(result, PeerRuntimeStep::DemotionAckAccepted(_)))
                }
                PeerMessageKind::DemotionCommitted => assert!(matches!(
                    result,
                    PeerRuntimeStep::DemotionCommittedAccepted(_)
                )),
                _ => unreachable!(),
            }
            assert_eq!(tracker.last_success(), None);
            assert_eq!(outstanding.state(), HeartbeatOutstandingState::Idle);
            assert_eq!(
                node_b.replay_state().unwrap().highest_accepted_sequence(),
                Sequence(1)
            );
        }
    }

    #[test]
    fn demotion_coordination_round_trip_preserves_authority_boundaries() {
        let (mut node_a, mut node_b, mut process_a, mut process_b) = managers();
        let serializer = CborSerializer;
        let authenticator = auth();
        let operation_id = OperationId::new("demotion-operation");
        let phase = OperationPhase::Demotion(DemotionPhase::StopService);
        let mut demotion_a = DemotionOutstanding::new();
        send_demotion_intent(
            &mut node_a,
            &mut process_a,
            &mut demotion_a,
            ClusterId::new("cluster"),
            Term(4),
            Some(crate::protocol::LeaseId::new("lease-a")),
            operation_id.clone(),
            phase,
            "operator request".to_string(),
            &serializer,
            &authenticator,
        )
        .unwrap();
        assert_eq!(
            demotion_a.state(),
            &DemotionOutstandingState::AwaitingAck {
                operation_id: operation_id.clone()
            }
        );

        let mut tracker_b = PeerLivenessTracker::new();
        let mut heartbeat_b = HeartbeatOutstanding::new();
        let mut state_b = StateAnnounceOutstanding::new();
        let mut demotion_b = DemotionOutstanding::new();
        let intent_step = process_next_peer_message(
            &mut node_b,
            &mut process_b,
            &mut tracker_b,
            &mut heartbeat_b,
            &mut state_b,
            &mut PromotionOutstanding::new(),
            &mut demotion_b,
            Instant::now(),
            ClusterId::new("cluster"),
            Term(4),
            None,
            &serializer,
            &authenticator,
        )
        .unwrap();
        let PeerRuntimeStep::DemotionIntentAccepted(observation) = intent_step else {
            panic!("expected demotion intent observation");
        };
        assert_eq!(observation.operation_id, operation_id);
        assert_eq!(observation.term, Term(4));
        assert_eq!(
            observation.lease_id,
            Some(crate::protocol::LeaseId::new("lease-a"))
        );
        assert_eq!(observation.phase, phase);
        assert_eq!(observation.reason, "operator request");
        assert_eq!(tracker_b.last_success(), None);
        assert_eq!(heartbeat_b.state(), HeartbeatOutstandingState::Idle);

        send_demotion_ack(
            &mut node_b,
            &mut process_b,
            ClusterId::new("cluster"),
            Term(4),
            None,
            operation_id.clone(),
            &serializer,
            &authenticator,
        )
        .unwrap();
        let mut tracker_a = PeerLivenessTracker::new();
        let mut heartbeat_a = HeartbeatOutstanding::new();
        let mut state_a = StateAnnounceOutstanding::new();
        let ack_step = process_next_peer_message(
            &mut node_a,
            &mut process_a,
            &mut tracker_a,
            &mut heartbeat_a,
            &mut state_a,
            &mut PromotionOutstanding::new(),
            &mut demotion_a,
            Instant::now(),
            ClusterId::new("cluster"),
            Term(4),
            None,
            &serializer,
            &authenticator,
        )
        .unwrap();
        assert!(matches!(ack_step, PeerRuntimeStep::DemotionAckAccepted(_)));
        assert_eq!(demotion_a.state(), &DemotionOutstandingState::Idle);
        assert_eq!(tracker_a.last_success(), None);
        assert_eq!(heartbeat_a.state(), HeartbeatOutstandingState::Idle);

        send_demotion_committed(
            &mut node_b,
            &mut process_b,
            ClusterId::new("cluster"),
            Term(4),
            None,
            operation_id.clone(),
            true,
            true,
            &serializer,
            &authenticator,
        )
        .unwrap();
        let committed_step = process_next_peer_message(
            &mut node_a,
            &mut process_a,
            &mut tracker_a,
            &mut heartbeat_a,
            &mut state_a,
            &mut PromotionOutstanding::new(),
            &mut demotion_a,
            Instant::now(),
            ClusterId::new("cluster"),
            Term(4),
            None,
            &serializer,
            &authenticator,
        )
        .unwrap();
        let PeerRuntimeStep::DemotionCommittedAccepted(observation) = committed_step else {
            panic!("expected demotion committed observation");
        };
        assert_eq!(observation.operation_id, operation_id);
        assert!(observation.service_stopped && observation.vip_released);
        assert_eq!(tracker_a.last_success(), None);
        assert_eq!(heartbeat_a.state(), HeartbeatOutstandingState::Idle);
        assert_eq!(demotion_a.state(), &DemotionOutstandingState::Idle);
    }

    #[test]
    fn second_demotion_intent_is_rejected_without_consuming_sequence() {
        let (mut node_a, _node_b, mut process_a, _process_b) = managers();
        let mut outstanding = DemotionOutstanding::new();
        let serializer = CborSerializer;
        let authenticator = auth();
        let phase = OperationPhase::Demotion(DemotionPhase::StopService);
        send_demotion_intent(
            &mut node_a,
            &mut process_a,
            &mut outstanding,
            ClusterId::new("cluster"),
            Term(1),
            None,
            OperationId::new("operation-a"),
            phase,
            "first".to_string(),
            &serializer,
            &authenticator,
        )
        .unwrap();
        let result = send_demotion_intent(
            &mut node_a,
            &mut process_a,
            &mut outstanding,
            ClusterId::new("cluster"),
            Term(1),
            None,
            OperationId::new("operation-b"),
            phase,
            "second".to_string(),
            &serializer,
            &authenticator,
        );
        assert!(matches!(
            result,
            Err(crate::demotion_runtime::DemotionRuntimeError::DemotionAlreadyOutstanding)
        ));
        assert_eq!(
            outstanding.state(),
            &DemotionOutstandingState::AwaitingAck {
                operation_id: OperationId::new("operation-a")
            }
        );
        assert_eq!(process_a.next_sequence().unwrap(), Sequence(2));
    }

    #[test]
    fn demotion_ack_correlation_rejects_unsolicited_and_wrong_operations_before_commit() {
        let (mut node_a, mut node_b, mut process_a, mut process_b) = managers();
        let serializer = CborSerializer;
        let authenticator = auth();
        send_demotion_ack(
            &mut node_b,
            &mut process_b,
            ClusterId::new("cluster"),
            Term(1),
            None,
            OperationId::new("operation-a"),
            &serializer,
            &authenticator,
        )
        .unwrap();
        let mut tracker = PeerLivenessTracker::new();
        let mut heartbeat = HeartbeatOutstanding::new();
        let mut state = StateAnnounceOutstanding::new();
        let mut demotion = DemotionOutstanding::new();
        let result = process_next_peer_message(
            &mut node_a,
            &mut process_a,
            &mut tracker,
            &mut heartbeat,
            &mut state,
            &mut PromotionOutstanding::new(),
            &mut demotion,
            Instant::now(),
            ClusterId::new("cluster"),
            Term(1),
            None,
            &serializer,
            &authenticator,
        );
        assert!(matches!(
            result,
            Err(PeerRuntimeError::Demotion(
                crate::demotion_runtime::DemotionRuntimeError::NoOutstandingDemotion
            ))
        ));
        assert_eq!(
            node_a.replay_state().unwrap().highest_accepted_sequence(),
            Sequence(0)
        );

        let mut demotion = DemotionOutstanding::new();
        send_demotion_intent(
            &mut node_a,
            &mut process_a,
            &mut demotion,
            ClusterId::new("cluster"),
            Term(1),
            None,
            OperationId::new("operation-a"),
            OperationPhase::Demotion(DemotionPhase::StopService),
            "request".to_string(),
            &serializer,
            &authenticator,
        )
        .unwrap();
        process_next_peer_message(
            &mut node_b,
            &mut process_b,
            &mut PeerLivenessTracker::new(),
            &mut HeartbeatOutstanding::new(),
            &mut StateAnnounceOutstanding::new(),
            &mut PromotionOutstanding::new(),
            &mut DemotionOutstanding::new(),
            Instant::now(),
            ClusterId::new("cluster"),
            Term(1),
            None,
            &serializer,
            &authenticator,
        )
        .unwrap();
        send_demotion_ack(
            &mut node_b,
            &mut process_b,
            ClusterId::new("cluster"),
            Term(1),
            None,
            OperationId::new("operation-b"),
            &serializer,
            &authenticator,
        )
        .unwrap();
        let result = process_next_peer_message(
            &mut node_a,
            &mut process_a,
            &mut tracker,
            &mut heartbeat,
            &mut state,
            &mut PromotionOutstanding::new(),
            &mut demotion,
            Instant::now(),
            ClusterId::new("cluster"),
            Term(1),
            None,
            &serializer,
            &authenticator,
        );
        assert!(matches!(
            result,
            Err(PeerRuntimeError::Demotion(
                crate::demotion_runtime::DemotionRuntimeError::OperationIdMismatch { .. }
            ))
        ));
        assert_eq!(
            demotion.state(),
            &DemotionOutstandingState::AwaitingAck {
                operation_id: OperationId::new("operation-a")
            }
        );
        assert_eq!(
            node_a.replay_state().unwrap().highest_accepted_sequence(),
            Sequence(0)
        );
        assert_eq!(tracker.last_success(), None);
        assert_eq!(heartbeat.state(), HeartbeatOutstandingState::Idle);
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn failed_demotion_intent_send_does_not_reuse_sequence() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let client = TcpStream::connect(address).unwrap();
        let (server, _) = listener.accept().unwrap();
        let control = server.try_clone().unwrap();
        reset_on_close(&control);
        drop(control);
        let client =
            TcpConnection::from_stream(client, Duration::from_secs(2), Duration::from_secs(2))
                .unwrap();
        let server =
            TcpConnection::from_stream(server, Duration::from_secs(2), Duration::from_secs(2))
                .unwrap();
        let mut node_a =
            PeerConnectionManager::new(NodeId::new("node-a"), NodeId::new("node-b")).unwrap();
        let mut node_b =
            PeerConnectionManager::new(NodeId::new("node-b"), NodeId::new("node-a")).unwrap();
        assert_eq!(
            node_a.adopt(
                ConnectionDirection::Outbound,
                HandshakeResult {
                    connection: client,
                    peer_session_id: SessionId::new("session-b"),
                    peer_last_accepted_sequence: Sequence(0)
                }
            ),
            AdoptionResult::Adopted
        );
        assert_eq!(
            node_b.adopt(
                ConnectionDirection::Inbound,
                HandshakeResult {
                    connection: server,
                    peer_session_id: SessionId::new("session-a"),
                    peer_last_accepted_sequence: Sequence(0)
                }
            ),
            AdoptionResult::Adopted
        );
        drop(node_b);
        let mut process = ProcessSession::from_session_id(SessionId::new("session-a"));
        let mut outstanding = DemotionOutstanding::new();
        let result = send_demotion_intent(
            &mut node_a,
            &mut process,
            &mut outstanding,
            ClusterId::new("cluster"),
            Term(1),
            None,
            OperationId::new("operation-a"),
            OperationPhase::Demotion(DemotionPhase::StopService),
            "failure".to_string(),
            &CborSerializer,
            &auth(),
        );
        assert!(matches!(
            result,
            Err(crate::demotion_runtime::DemotionRuntimeError::Tcp(_))
        ));
        assert_eq!(outstanding.state(), &DemotionOutstandingState::Idle);
        assert_eq!(process.next_sequence().unwrap(), Sequence(2));
    }

    #[test]
    fn cloned_demotion_ack_cannot_complete_twice() {
        let (mut node_a, mut node_b, mut process_a, mut process_b) = managers();
        let serializer = CborSerializer;
        let authenticator = auth();
        let operation_id = OperationId::new("operation-a");
        let mut outstanding = DemotionOutstanding::new();
        send_demotion_intent(
            &mut node_a,
            &mut process_a,
            &mut outstanding,
            ClusterId::new("cluster"),
            Term(1),
            None,
            operation_id.clone(),
            OperationPhase::Demotion(DemotionPhase::StopService),
            "request".to_string(),
            &serializer,
            &authenticator,
        )
        .unwrap();
        process_next_peer_message(
            &mut node_b,
            &mut process_b,
            &mut PeerLivenessTracker::new(),
            &mut HeartbeatOutstanding::new(),
            &mut StateAnnounceOutstanding::new(),
            &mut PromotionOutstanding::new(),
            &mut DemotionOutstanding::new(),
            Instant::now(),
            ClusterId::new("cluster"),
            Term(1),
            None,
            &serializer,
            &authenticator,
        )
        .unwrap();
        send_demotion_ack(
            &mut node_b,
            &mut process_b,
            ClusterId::new("cluster"),
            Term(1),
            None,
            operation_id,
            &serializer,
            &authenticator,
        )
        .unwrap();
        let ack = dispatch_next(
            &mut node_a,
            &ClusterId::new("cluster"),
            &serializer,
            &authenticator,
        )
        .unwrap();
        let clone = ack.clone();
        assert!(
            crate::demotion_runtime::handle_pending_demotion_ack(
                &mut node_a,
                &ack,
                &mut outstanding
            )
            .is_ok()
        );
        assert!(matches!(
            crate::demotion_runtime::handle_pending_demotion_ack(
                &mut node_a,
                &clone,
                &mut outstanding
            ),
            Err(crate::demotion_runtime::DemotionRuntimeError::NoOutstandingDemotion)
        ));
        assert_eq!(
            node_a.replay_state().unwrap().highest_accepted_sequence(),
            Sequence(1)
        );
    }

    #[test]
    fn cloned_demotion_intent_and_committed_are_not_accepted_twice() {
        let (mut node_a, mut node_b, _process_a, _process_b) = managers();
        let make = |message, sequence| UnsignedEnvelope {
            common: CommonFields {
                protocol_version: crate::protocol::PROTOCOL_VERSION,
                cluster_id: ClusterId::new("cluster"),
                sender_node_id: NodeId::new("node-b"),
                receiver_node_id: NodeId::new("node-a"),
                session_id: SessionId::new("session-b"),
                sequence: Sequence(sequence),
                term: Term(1),
                lease_id: None,
                request_id: None,
                operation_id: Some(OperationId::new("operation-a")),
            },
            message,
        };
        node_b
            .connection_mut()
            .unwrap()
            .send_message(
                make(
                    ProtocolMessage::DemotionIntent(DemotionIntentPayload {
                        phase: OperationPhase::Demotion(DemotionPhase::StopService),
                        reason: "clone".to_string(),
                    }),
                    1,
                ),
                &CborSerializer,
                &auth(),
            )
            .unwrap();
        let intent = dispatch_next(
            &mut node_a,
            &ClusterId::new("cluster"),
            &CborSerializer,
            &auth(),
        )
        .unwrap();
        let clone = intent.clone();
        assert!(
            crate::demotion_runtime::handle_pending_demotion_intent(&mut node_a, &intent).is_ok()
        );
        assert!(matches!(
            crate::demotion_runtime::handle_pending_demotion_intent(&mut node_a, &clone),
            Err(crate::demotion_runtime::DemotionRuntimeError::Dispatcher(_))
        ));
        node_b
            .connection_mut()
            .unwrap()
            .send_message(
                make(
                    ProtocolMessage::DemotionCommitted(crate::protocol::DemotionCommittedPayload {
                        service_stopped: true,
                        vip_released: true,
                    }),
                    2,
                ),
                &CborSerializer,
                &auth(),
            )
            .unwrap();
        let committed = dispatch_next(
            &mut node_a,
            &ClusterId::new("cluster"),
            &CborSerializer,
            &auth(),
        )
        .unwrap();
        let clone = committed.clone();
        assert!(
            crate::demotion_runtime::handle_pending_demotion_committed(&mut node_a, &committed)
                .is_ok()
        );
        assert!(matches!(
            crate::demotion_runtime::handle_pending_demotion_committed(&mut node_a, &clone),
            Err(crate::demotion_runtime::DemotionRuntimeError::Dispatcher(_))
        ));
        assert_eq!(
            node_a.replay_state().unwrap().highest_accepted_sequence(),
            Sequence(2)
        );
    }

    #[test]
    fn state_announce_round_trip_observes_and_completes_without_liveness() {
        let (mut node_a, mut node_b, mut process_a, mut process_b) = managers();
        let serializer = CborSerializer;
        let authenticator = auth();
        let mut state_outstanding_a = StateAnnounceOutstanding::new();
        let mut state_outstanding_b = StateAnnounceOutstanding::new();
        let mut heartbeat_outstanding_a = HeartbeatOutstanding::new();
        let mut heartbeat_outstanding_b = HeartbeatOutstanding::new();
        let mut tracker_a = PeerLivenessTracker::new();
        let mut tracker_b = PeerLivenessTracker::new();

        send_state_announce(
            &mut node_a,
            &mut process_a,
            &mut state_outstanding_a,
            ClusterId::new("cluster"),
            Term(3),
            None,
            status(),
            "state update".to_string(),
            &serializer,
            &authenticator,
        )
        .unwrap();
        assert_eq!(
            state_outstanding_a.state(),
            StateAnnounceOutstandingState::AwaitingAck
        );

        let step_b = process_next_peer_message(
            &mut node_b,
            &mut process_b,
            &mut tracker_b,
            &mut heartbeat_outstanding_b,
            &mut state_outstanding_b,
            &mut PromotionOutstanding::new(),
            &mut DemotionOutstanding::new(),
            Instant::now(),
            ClusterId::new("cluster"),
            Term(3),
            None,
            &serializer,
            &authenticator,
        )
        .unwrap();
        let PeerRuntimeStep::StateAnnounceAccepted(observation) = step_b else {
            panic!("expected accepted state announcement");
        };
        assert_eq!(observation.status, status());
        assert_eq!(observation.reason, "state update");
        assert_eq!(observation.term, Term(3));
        assert_eq!(tracker_b.last_success(), None);
        assert_eq!(
            node_b.replay_state().unwrap().highest_accepted_sequence(),
            Sequence(1)
        );

        assert_eq!(
            process_next_peer_message(
                &mut node_a,
                &mut process_a,
                &mut tracker_a,
                &mut heartbeat_outstanding_a,
                &mut state_outstanding_a,
                &mut PromotionOutstanding::new(),
                &mut DemotionOutstanding::new(),
                Instant::now(),
                ClusterId::new("cluster"),
                Term(3),
                None,
                &serializer,
                &authenticator,
            )
            .unwrap(),
            PeerRuntimeStep::StateAnnounceAckAccepted
        );
        assert_eq!(
            state_outstanding_a.state(),
            StateAnnounceOutstandingState::Idle
        );
        assert_eq!(tracker_a.last_success(), None);
        assert_eq!(
            node_a.replay_state().unwrap().highest_accepted_sequence(),
            Sequence(1)
        );
    }

    #[test]
    fn second_state_announce_is_rejected_before_sequence_allocation() {
        let (mut node_a, _node_b, mut process_a, _process_b) = managers();
        let mut outstanding = StateAnnounceOutstanding::new();
        let serializer = CborSerializer;
        let authenticator = auth();
        send_state_announce(
            &mut node_a,
            &mut process_a,
            &mut outstanding,
            ClusterId::new("cluster"),
            Term(1),
            None,
            status(),
            "first".to_string(),
            &serializer,
            &authenticator,
        )
        .unwrap();
        let result = send_state_announce(
            &mut node_a,
            &mut process_a,
            &mut outstanding,
            ClusterId::new("cluster"),
            Term(1),
            None,
            status(),
            "second".to_string(),
            &serializer,
            &authenticator,
        );
        assert!(matches!(
            result,
            Err(StateRuntimeError::StateAnnounceAlreadyOutstanding)
        ));
        assert_eq!(
            outstanding.state(),
            StateAnnounceOutstandingState::AwaitingAck
        );
        assert_eq!(process_a.next_sequence().unwrap(), Sequence(2));
    }

    #[test]
    fn promotion_intent_is_routed_as_observation_without_liveness_side_effects() {
        let (mut node_a, mut node_b, mut process_a, mut process_b) = managers();
        let serializer = CborSerializer;
        let authenticator = auth();
        let operation_id = OperationId::new("operation-a");
        send_promotion_intent(
            &mut node_a,
            &mut process_a,
            &mut PromotionOutstanding::new(),
            ClusterId::new("cluster"),
            Term(7),
            None,
            operation_id.clone(),
            100,
            "promote".to_string(),
            &serializer,
            &authenticator,
        )
        .unwrap();
        let mut tracker = PeerLivenessTracker::new();
        let mut heartbeat = HeartbeatOutstanding::new();
        let mut state = StateAnnounceOutstanding::new();
        let mut promotion = PromotionOutstanding::new();
        let step = process_next_peer_message(
            &mut node_b,
            &mut process_b,
            &mut tracker,
            &mut heartbeat,
            &mut state,
            &mut promotion,
            &mut DemotionOutstanding::new(),
            Instant::now(),
            ClusterId::new("cluster"),
            Term(7),
            None,
            &serializer,
            &authenticator,
        )
        .unwrap();
        let PeerRuntimeStep::PromotionIntentAccepted(observation) = step else {
            panic!("expected promotion intent observation");
        };
        assert_eq!(observation.operation_id, operation_id);
        assert_eq!(observation.priority, 100);
        assert_eq!(observation.reason, "promote");
        assert_eq!(observation.term, Term(7));
        assert_eq!(
            node_b.replay_state().unwrap().highest_accepted_sequence(),
            Sequence(1)
        );
        assert_eq!(tracker.last_success(), None);
        assert_eq!(heartbeat.state(), HeartbeatOutstandingState::Idle);
        assert_eq!(promotion.state(), &PromotionOutstandingState::Idle);
    }

    #[test]
    fn cloned_promotion_pending_messages_cannot_commit_or_complete_twice() {
        let (mut node_a, mut node_b, mut process_a, mut process_b) = managers();
        let serializer = CborSerializer;
        let authenticator = auth();
        let operation_id = OperationId::new("operation-a");
        let mut outbound = PromotionOutstanding::new();
        send_promotion_intent(
            &mut node_a,
            &mut process_a,
            &mut outbound,
            ClusterId::new("cluster"),
            Term(1),
            None,
            operation_id.clone(),
            100,
            "clone".to_string(),
            &serializer,
            &authenticator,
        )
        .unwrap();
        let intent = dispatch_next(
            &mut node_b,
            &ClusterId::new("cluster"),
            &serializer,
            &authenticator,
        )
        .unwrap();
        let intent_clone = intent.clone();
        let observation =
            crate::promotion_runtime::handle_pending_promotion_intent(&mut node_b, &intent)
                .unwrap();
        assert_eq!(observation.operation_id, operation_id);
        assert!(matches!(
            crate::promotion_runtime::handle_pending_promotion_intent(&mut node_b, &intent_clone),
            Err(PromotionRuntimeError::Dispatcher(_))
        ));
        assert_eq!(
            node_b.replay_state().unwrap().highest_accepted_sequence(),
            Sequence(1)
        );

        send_promotion_response(
            &mut node_b,
            &mut process_b,
            ClusterId::new("cluster"),
            Term(1),
            None,
            operation_id,
            PromotionPeerResponseKind::Ack,
            &serializer,
            &authenticator,
        )
        .unwrap();
        let response = dispatch_next(
            &mut node_a,
            &ClusterId::new("cluster"),
            &serializer,
            &authenticator,
        )
        .unwrap();
        let response_clone = response.clone();
        let accepted = crate::promotion_runtime::handle_pending_promotion_response(
            &mut node_a,
            &response,
            &mut outbound,
        )
        .unwrap();
        assert_eq!(accepted.kind, PromotionPeerResponseKind::Ack);
        assert_eq!(outbound.state(), &PromotionOutstandingState::Idle);
        assert!(matches!(
            crate::promotion_runtime::handle_pending_promotion_response(
                &mut node_a,
                &response_clone,
                &mut outbound
            ),
            Err(PromotionRuntimeError::NoOutstandingPromotion)
        ));
        assert_eq!(
            node_a.replay_state().unwrap().highest_accepted_sequence(),
            Sequence(1)
        );
    }

    #[test]
    fn unsolicited_state_announce_ack_is_rejected_without_commit() {
        let (mut node_a, mut node_b, mut process_a, process_b) = managers();
        let ack = UnsignedEnvelope {
            common: CommonFields {
                protocol_version: crate::protocol::PROTOCOL_VERSION,
                cluster_id: ClusterId::new("cluster"),
                sender_node_id: NodeId::new("node-b"),
                receiver_node_id: NodeId::new("node-a"),
                session_id: SessionId::new("session-b"),
                sequence: Sequence(1),
                term: Term(1),
                lease_id: None,
                request_id: None,
                operation_id: None,
            },
            message: ProtocolMessage::StateAnnounceAck,
        };
        node_b
            .connection_mut()
            .unwrap()
            .send_message(ack, &CborSerializer, &auth())
            .unwrap();
        let mut tracker = PeerLivenessTracker::new();
        let mut heartbeat_outstanding = HeartbeatOutstanding::new();
        let mut state_outstanding = StateAnnounceOutstanding::new();
        let result = process_next_peer_message(
            &mut node_a,
            &mut process_a,
            &mut tracker,
            &mut heartbeat_outstanding,
            &mut state_outstanding,
            &mut PromotionOutstanding::new(),
            &mut DemotionOutstanding::new(),
            Instant::now(),
            ClusterId::new("cluster"),
            Term(1),
            None,
            &CborSerializer,
            &auth(),
        );
        assert!(matches!(
            result,
            Err(PeerRuntimeError::State(
                StateRuntimeError::NoOutstandingStateAnnounce
            ))
        ));
        assert_eq!(
            state_outstanding.state(),
            StateAnnounceOutstandingState::Idle
        );
        assert_eq!(tracker.last_success(), None);
        assert_eq!(
            node_a.replay_state().unwrap().highest_accepted_sequence(),
            Sequence(0)
        );
        drop(process_b);
    }

    #[test]
    fn cloned_state_announce_pending_cannot_commit_twice() {
        let (mut node_a, mut node_b, _process_a, mut process_b) = managers();
        let message = UnsignedEnvelope {
            common: CommonFields {
                protocol_version: crate::protocol::PROTOCOL_VERSION,
                cluster_id: ClusterId::new("cluster"),
                sender_node_id: NodeId::new("node-a"),
                receiver_node_id: NodeId::new("node-b"),
                session_id: SessionId::new("session-a"),
                sequence: Sequence(1),
                term: Term(1),
                lease_id: None,
                request_id: None,
                operation_id: None,
            },
            message: ProtocolMessage::StateAnnounce(StateAnnouncePayload {
                status: status(),
                reason: "clone".to_string(),
            }),
        };
        node_a
            .connection_mut()
            .unwrap()
            .send_message(message, &CborSerializer, &auth())
            .unwrap();
        let pending = dispatch_next(
            &mut node_b,
            &ClusterId::new("cluster"),
            &CborSerializer,
            &auth(),
        )
        .unwrap();
        let clone = pending.clone();
        let state_outstanding = StateAnnounceOutstanding::new();
        handle_pending_state_announce(
            &mut node_b,
            &pending,
            &mut process_b,
            ClusterId::new("cluster"),
            Term(1),
            None,
            &CborSerializer,
            &auth(),
        )
        .unwrap();
        let mut state_process = ProcessSession::from_session_id(SessionId::new("unused"));
        let result = handle_pending_state_announce(
            &mut node_b,
            &clone,
            &mut state_process,
            ClusterId::new("cluster"),
            Term(1),
            None,
            &CborSerializer,
            &auth(),
        );
        assert!(matches!(
            result,
            Err(StateRuntimeError::Dispatcher(PeerDispatchError::Commit(_)))
        ));
        assert_eq!(
            state_outstanding.state(),
            StateAnnounceOutstandingState::Idle
        );
        assert_eq!(
            node_b.replay_state().unwrap().highest_accepted_sequence(),
            Sequence(1)
        );
    }

    #[test]
    fn state_announce_ack_send_failure_does_not_rollback_committed_peer_sequence() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let raw_client = TcpStream::connect(address).unwrap();
        let reset_client = raw_client.try_clone().unwrap();
        let (server, _) = listener.accept().unwrap();
        let client =
            TcpConnection::from_stream(raw_client, Duration::from_secs(2), Duration::from_secs(2))
                .unwrap();
        let server =
            TcpConnection::from_stream(server, Duration::from_secs(2), Duration::from_secs(2))
                .unwrap();
        let mut node_a =
            PeerConnectionManager::new(NodeId::new("node-a"), NodeId::new("node-b")).unwrap();
        let mut node_b =
            PeerConnectionManager::new(NodeId::new("node-b"), NodeId::new("node-a")).unwrap();
        assert_eq!(
            node_a.adopt(
                ConnectionDirection::Outbound,
                HandshakeResult {
                    connection: client,
                    peer_session_id: SessionId::new("session-b"),
                    peer_last_accepted_sequence: Sequence(0),
                },
            ),
            AdoptionResult::Adopted
        );
        assert_eq!(
            node_b.adopt(
                ConnectionDirection::Inbound,
                HandshakeResult {
                    connection: server,
                    peer_session_id: SessionId::new("session-a"),
                    peer_last_accepted_sequence: Sequence(0),
                },
            ),
            AdoptionResult::Adopted
        );
        let mut process_b = ProcessSession::from_session_id(SessionId::new("session-b"));
        let announce = UnsignedEnvelope {
            common: CommonFields {
                protocol_version: crate::protocol::PROTOCOL_VERSION,
                cluster_id: ClusterId::new("cluster"),
                sender_node_id: NodeId::new("node-a"),
                receiver_node_id: NodeId::new("node-b"),
                session_id: SessionId::new("session-a"),
                sequence: Sequence(1),
                term: Term(1),
                lease_id: None,
                request_id: None,
                operation_id: None,
            },
            message: ProtocolMessage::StateAnnounce(StateAnnouncePayload {
                status: status(),
                reason: "ack failure".to_string(),
            }),
        };
        announce.validate().unwrap();
        node_a
            .connection_mut()
            .unwrap()
            .send_message(announce, &CborSerializer, &auth())
            .unwrap();
        let pending = dispatch_next(
            &mut node_b,
            &ClusterId::new("cluster"),
            &CborSerializer,
            &auth(),
        )
        .unwrap();
        assert_eq!(
            node_b.replay_state().unwrap().highest_accepted_sequence(),
            Sequence(0)
        );
        reset_on_close(&reset_client);
        drop(node_a);
        reset_client.shutdown(Shutdown::Both).unwrap();
        drop(reset_client);

        let result = handle_pending_state_announce(
            &mut node_b,
            &pending,
            &mut process_b,
            ClusterId::new("cluster"),
            Term(1),
            None,
            &CborSerializer,
            &auth(),
        );
        match result {
            Err(StateRuntimeError::Tcp(_)) => {}
            Err(error) => panic!("unexpected state runtime error: {error:?}"),
            Ok(observation) => panic!("unexpected successful observation: {observation:?}"),
        }
        assert_eq!(
            node_b.replay_state().unwrap().highest_accepted_sequence(),
            Sequence(1)
        );
    }
}
