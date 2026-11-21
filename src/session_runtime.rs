//! Deterministic connection/session boundary for an established peer.
//!
//! This module consumes already authenticated protocol messages.  It owns
//! connection identity and HELLO completion, and emits only trusted session
//! events to the peer observer.  It does not make HA decisions.

#![allow(dead_code)]

use crate::peer_observer::{
    EstablishedHeartbeat, PeerObservation, PeerObserver, PeerTransport, PeerTransportEvent,
};
use crate::protocol::{ClusterId, MessageType, NodeId, SessionId};
use crate::receive::AuthenticatedMessage;
use crate::session::{PeerSession, SessionAction, SessionError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ConnectionGeneration(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnectionGenerationError {
    Exhausted,
}

pub(crate) struct ConnectionGenerationAllocator {
    next: u64,
}

impl ConnectionGenerationAllocator {
    pub(crate) const fn new() -> Self {
        Self { next: 0 }
    }

    pub(crate) fn next(&mut self) -> Result<ConnectionGeneration, ConnectionGenerationError> {
        self.next = self
            .next
            .checked_add(1)
            .ok_or(ConnectionGenerationError::Exhausted)?;
        Ok(ConnectionGeneration(self.next))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionRuntimeState {
    Disconnected,
    HelloPending,
    Established,
    Invalid,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SessionRuntimeInput {
    Connect {
        generation: ConnectionGeneration,
        connection_id: u64,
    },
    Authenticated {
        generation: ConnectionGeneration,
        connection_id: u64,
        message: AuthenticatedMessage,
    },
    Malformed {
        generation: ConnectionGeneration,
        connection_id: u64,
    },
    AuthenticationFailure {
        generation: ConnectionGeneration,
        connection_id: u64,
    },
    ProtocolMismatch {
        generation: ConnectionGeneration,
        connection_id: u64,
    },
    Disconnect {
        generation: ConnectionGeneration,
        connection_id: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SessionRuntimeError {
    NotConnected,
    StaleConnection,
    ConnectionIdentityConflict,
    Session(SessionError),
    InvalidInput,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SessionRuntimeEvent {
    SendHelloAck,
    SessionEstablished {
        session_id: SessionId,
    },
    EstablishedHeartbeat(EstablishedHeartbeat),
    /// An authenticated `PROMOTION_INTENT` on the established session (a
    /// Bootstrap Admission probe; the answer is decided by the daemon).
    ProbeRequest(crate::protocol::UnsignedEnvelope),
    /// An authenticated `PROMOTION_ACK` / `BLOCK` / `UNKNOWN`: a response to a
    /// probe this node sent.
    ProbeResponse(crate::protocol::UnsignedEnvelope),
    IgnoredAuthenticatedMessage,
    TransportUnavailable,
    Rejected(SessionRuntimeError),
}

impl SessionRuntimeEvent {
    fn into_peer_event(self) -> Option<PeerTransportEvent> {
        match self {
            Self::SessionEstablished { session_id } => {
                Some(PeerTransportEvent::SessionEstablished { session_id })
            }
            Self::EstablishedHeartbeat(message) => Some(PeerTransportEvent::EstablishedHeartbeat(
                message.into_unsigned(),
            )),
            Self::TransportUnavailable => Some(PeerTransportEvent::TransportFailure),
            Self::SendHelloAck
            | Self::ProbeRequest(_)
            | Self::ProbeResponse(_)
            | Self::IgnoredAuthenticatedMessage
            | Self::Rejected(_) => None,
        }
    }
}

pub(crate) struct SessionRuntime {
    cluster_id: ClusterId,
    local_node_id: NodeId,
    peer_node_id: NodeId,
    expected_peer_priority: i32,
    state: SessionRuntimeState,
    generation: Option<ConnectionGeneration>,
    connection_id: Option<u64>,
    peer_session: Option<PeerSession>,
}

impl SessionRuntime {
    pub(crate) fn new(
        cluster_id: ClusterId,
        local_node_id: NodeId,
        peer_node_id: NodeId,
        expected_peer_priority: i32,
    ) -> Self {
        Self {
            cluster_id,
            local_node_id,
            peer_node_id,
            expected_peer_priority,
            state: SessionRuntimeState::Disconnected,
            generation: None,
            connection_id: None,
            peer_session: None,
        }
    }

    pub(crate) const fn state(&self) -> SessionRuntimeState {
        self.state
    }

    pub(crate) fn current_session_id(&self) -> Option<&SessionId> {
        self.peer_session
            .as_ref()
            .and_then(PeerSession::peer_session_id)
    }

    pub(crate) fn handle(&mut self, input: SessionRuntimeInput) -> Vec<SessionRuntimeEvent> {
        match input {
            SessionRuntimeInput::Connect {
                generation,
                connection_id,
            } => {
                match self.generation {
                    Some(current) if generation < current => {
                        return vec![SessionRuntimeEvent::Rejected(
                            SessionRuntimeError::StaleConnection,
                        )];
                    }
                    Some(current) if generation == current => {
                        if self.connection_id == Some(connection_id) {
                            return Vec::new();
                        }
                        return vec![SessionRuntimeEvent::Rejected(
                            SessionRuntimeError::ConnectionIdentityConflict,
                        )];
                    }
                    None | Some(_) => {}
                }
                self.generation = Some(generation);
                self.connection_id = Some(connection_id);
                self.peer_session = Some(PeerSession::new(
                    self.cluster_id.clone(),
                    self.local_node_id.clone(),
                    self.peer_node_id.clone(),
                    self.expected_peer_priority,
                ));
                self.state = SessionRuntimeState::HelloPending;
                Vec::new()
            }
            SessionRuntimeInput::Authenticated {
                generation,
                connection_id,
                message,
            } => self.handle_authenticated(generation, connection_id, message),
            SessionRuntimeInput::Malformed {
                generation,
                connection_id,
            }
            | SessionRuntimeInput::AuthenticationFailure {
                generation,
                connection_id,
            }
            | SessionRuntimeInput::ProtocolMismatch {
                generation,
                connection_id,
            } => {
                if !self.matches_connection(generation, connection_id) {
                    return vec![SessionRuntimeEvent::Rejected(
                        SessionRuntimeError::StaleConnection,
                    )];
                }
                self.state = SessionRuntimeState::Invalid;
                self.peer_session = None;
                vec![SessionRuntimeEvent::Rejected(
                    SessionRuntimeError::InvalidInput,
                )]
            }
            SessionRuntimeInput::Disconnect {
                generation,
                connection_id,
            } => {
                if !self.matches_connection(generation, connection_id) {
                    return vec![SessionRuntimeEvent::Rejected(
                        SessionRuntimeError::StaleConnection,
                    )];
                }
                self.state = SessionRuntimeState::Disconnected;
                self.connection_id = None;
                self.peer_session = None;
                vec![SessionRuntimeEvent::TransportUnavailable]
            }
        }
    }

    fn handle_authenticated(
        &mut self,
        generation: ConnectionGeneration,
        connection_id: u64,
        message: AuthenticatedMessage,
    ) -> Vec<SessionRuntimeEvent> {
        if !self.matches_connection(generation, connection_id) {
            return vec![SessionRuntimeEvent::Rejected(
                SessionRuntimeError::StaleConnection,
            )];
        }
        let Some(peer_session) = self.peer_session.as_mut() else {
            return vec![SessionRuntimeEvent::Rejected(
                SessionRuntimeError::NotConnected,
            )];
        };

        let message_type = message.unsigned().message.message_type();
        match peer_session.accept(&message) {
            Ok(SessionAction::SendHelloAck) => {
                self.state = SessionRuntimeState::Established;
                let session_id = peer_session
                    .peer_session_id()
                    .expect("HELLO acceptance records peer session_id")
                    .clone();
                vec![
                    SessionRuntimeEvent::SendHelloAck,
                    SessionRuntimeEvent::SessionEstablished { session_id },
                ]
            }
            Ok(SessionAction::Accept) if message_type == MessageType::Heartbeat => {
                vec![SessionRuntimeEvent::EstablishedHeartbeat(
                    EstablishedHeartbeat::from_session_runtime(message.unsigned().clone()),
                )]
            }
            Ok(SessionAction::Accept) if message_type == MessageType::PromotionIntent => {
                vec![SessionRuntimeEvent::ProbeRequest(
                    message.unsigned().clone(),
                )]
            }
            Ok(SessionAction::Accept)
                if matches!(
                    message_type,
                    MessageType::PromotionAck
                        | MessageType::PromotionBlock
                        | MessageType::PromotionUnknown
                ) =>
            {
                vec![SessionRuntimeEvent::ProbeResponse(
                    message.unsigned().clone(),
                )]
            }
            Ok(SessionAction::Accept) => {
                vec![SessionRuntimeEvent::IgnoredAuthenticatedMessage]
            }
            Err(error) => {
                self.state = SessionRuntimeState::Invalid;
                vec![SessionRuntimeEvent::Rejected(SessionRuntimeError::Session(
                    error,
                ))]
            }
        }
    }

    fn matches_connection(&self, generation: ConnectionGeneration, connection_id: u64) -> bool {
        self.generation == Some(generation) && self.connection_id == Some(connection_id)
    }
}

struct NoopTransport;

impl PeerTransport for NoopTransport {
    fn poll_heartbeat(&mut self) -> PeerTransportEvent {
        PeerTransportEvent::NoMessage
    }
}

/// Combines the connection/session boundary with the existing observer while
/// keeping all HA decisions outside both components.
pub(crate) struct PeerSessionRuntime {
    session: SessionRuntime,
    observer: PeerObserver<NoopTransport>,
}

impl PeerSessionRuntime {
    pub(crate) fn new(
        cluster_id: ClusterId,
        local_node_id: NodeId,
        peer_node_id: NodeId,
        expected_peer_priority: i32,
        freshness_timeout_ms: u64,
    ) -> Self {
        let observer = PeerObserver::new(
            NoopTransport,
            cluster_id.clone(),
            local_node_id.clone(),
            peer_node_id.clone(),
            freshness_timeout_ms,
        );
        Self {
            session: SessionRuntime::new(
                cluster_id,
                local_node_id,
                peer_node_id,
                expected_peer_priority,
            ),
            observer,
        }
    }

    pub(crate) fn handle(
        &mut self,
        input: SessionRuntimeInput,
        now_ms: u64,
    ) -> Vec<SessionRuntimeEvent> {
        let events = self.session.handle(input);
        for event in &events {
            let peer_event = match event {
                SessionRuntimeEvent::SessionEstablished { session_id } => {
                    Some(PeerTransportEvent::SessionEstablished {
                        session_id: session_id.clone(),
                    })
                }
                SessionRuntimeEvent::EstablishedHeartbeat(message) => Some(
                    PeerTransportEvent::EstablishedHeartbeat(message.as_unsigned().clone()),
                ),
                SessionRuntimeEvent::TransportUnavailable => {
                    Some(PeerTransportEvent::TransportFailure)
                }
                SessionRuntimeEvent::SendHelloAck
                | SessionRuntimeEvent::ProbeRequest(_)
                | SessionRuntimeEvent::ProbeResponse(_)
                | SessionRuntimeEvent::IgnoredAuthenticatedMessage
                | SessionRuntimeEvent::Rejected(_) => None,
            };
            if let Some(peer_event) = peer_event {
                self.observer.observe_event(peer_event, now_ms);
            }
        }
        events
    }

    pub(crate) fn tick(&mut self, now_ms: u64) {
        self.observer.tick(now_ms);
    }

    pub(crate) const fn session_state(&self) -> SessionRuntimeState {
        self.session.state()
    }

    pub(crate) fn snapshot(&self, now_ms: u64) -> PeerObservation {
        self.observer.snapshot(now_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_observer::PeerObservationState;
    use crate::protocol::{
        CanonicalSerializer, CborSerializer, CommonFields, HelloPayload, NodeStatusPayload,
        PROTOCOL_VERSION, ProtocolMessage, Role, Sequence, Term, UnsignedEnvelope,
    };
    use crate::receive::receive;
    use crate::security::{MessageAuthenticator, Psk};
    use crate::state_machine::NodeState;

    fn authenticator() -> MessageAuthenticator {
        MessageAuthenticator::new(Psk::from_test_bytes([0x44; 32]))
    }

    fn authenticated_with_identity(
        message: ProtocolMessage,
        cluster: &str,
        sender: &str,
        receiver: &str,
        session: &str,
        sequence: u64,
    ) -> AuthenticatedMessage {
        let unsigned = UnsignedEnvelope {
            common: CommonFields {
                protocol_version: PROTOCOL_VERSION,
                cluster_id: ClusterId::new(cluster),
                sender_node_id: NodeId::new(sender),
                receiver_node_id: NodeId::new(receiver),
                session_id: SessionId::new(session),
                sequence: Sequence(sequence),
                term: Term(1),
                lease_id: None,
                request_id: None,
                operation_id: None,
            },
            message,
        };
        let serializer = CborSerializer;
        let wire = authenticator().sign(unsigned, &serializer).unwrap();
        let bytes = serializer.serialize_wire(&wire).unwrap();
        receive(&bytes, &serializer, &authenticator()).unwrap()
    }

    fn authenticated(
        message: ProtocolMessage,
        sender: &str,
        session: &str,
        sequence: u64,
    ) -> AuthenticatedMessage {
        authenticated_with_identity(message, "cluster", sender, "node-a", session, sequence)
    }

    fn hello(session: &str, sequence: u64) -> AuthenticatedMessage {
        authenticated(
            ProtocolMessage::Hello(HelloPayload { priority: 100 }),
            "node-b",
            session,
            sequence,
        )
    }

    fn heartbeat(session: &str, sequence: u64) -> AuthenticatedMessage {
        authenticated(
            ProtocolMessage::Heartbeat(NodeStatusPayload {
                node_state: NodeState::Standby,
                operation_phase: None,
                role: Role::Standby,
                service_state: "stopped".into(),
                health_state: "unknown".into(),
                vip_state: "absent".into(),
            }),
            "node-b",
            session,
            sequence,
        )
    }

    fn runtime() -> PeerSessionRuntime {
        PeerSessionRuntime::new(
            ClusterId::new("cluster"),
            NodeId::new("node-a"),
            NodeId::new("node-b"),
            100,
            100,
        )
    }

    fn generation(value: u64) -> ConnectionGeneration {
        ConnectionGeneration(value)
    }

    fn connect(generation_value: u64, connection_id: u64) -> SessionRuntimeInput {
        SessionRuntimeInput::Connect {
            generation: generation(generation_value),
            connection_id,
        }
    }

    #[test]
    fn heartbeat_before_hello_is_rejected_and_does_not_establish() {
        let mut runtime = runtime();
        runtime.handle(connect(1, 1), 10);
        let events = runtime.handle(
            SessionRuntimeInput::Authenticated {
                generation: generation(1),
                connection_id: 1,
                message: heartbeat("session-a", 1),
            },
            20,
        );
        assert!(matches!(
            events.as_slice(),
            [SessionRuntimeEvent::Rejected(SessionRuntimeError::Session(
                SessionError::ExpectedHello
            ))]
        ));
        assert_eq!(runtime.session_state(), SessionRuntimeState::Invalid);
        assert_eq!(runtime.snapshot(20).state, PeerObservationState::NeverSeen);
    }

    #[test]
    fn valid_hello_emits_establishment_once_and_heartbeat_becomes_fresh() {
        let mut runtime = runtime();
        runtime.handle(connect(1, 1), 0);
        let events = runtime.handle(
            SessionRuntimeInput::Authenticated {
                generation: generation(1),
                connection_id: 1,
                message: hello("session-a", 1),
            },
            10,
        );
        assert!(matches!(
            events.as_slice(),
            [
                SessionRuntimeEvent::SendHelloAck,
                SessionRuntimeEvent::SessionEstablished { .. }
            ]
        ));
        let events = runtime.handle(
            SessionRuntimeInput::Authenticated {
                generation: generation(1),
                connection_id: 1,
                message: heartbeat("session-a", 2),
            },
            20,
        );
        assert!(matches!(
            events.as_slice(),
            [SessionRuntimeEvent::EstablishedHeartbeat(_)]
        ));
        assert_eq!(runtime.snapshot(20).state, PeerObservationState::Fresh);

        let events = runtime.handle(
            SessionRuntimeInput::Authenticated {
                generation: generation(1),
                connection_id: 1,
                message: hello("session-a", 3),
            },
            30,
        );
        assert!(matches!(
            events.as_slice(),
            [SessionRuntimeEvent::IgnoredAuthenticatedMessage]
        ));
        assert_eq!(runtime.snapshot(30).sequence, Some(Sequence(2)));
        assert_eq!(runtime.snapshot(30).last_received_ms, Some(20));
    }

    #[test]
    fn replacement_requires_new_hello_and_invalidates_old_observation() {
        let mut runtime = runtime();
        runtime.handle(connect(1, 1), 0);
        runtime.handle(
            SessionRuntimeInput::Authenticated {
                generation: generation(1),
                connection_id: 1,
                message: hello("session-a", 1),
            },
            1,
        );
        runtime.handle(
            SessionRuntimeInput::Authenticated {
                generation: generation(1),
                connection_id: 1,
                message: heartbeat("session-a", 2),
            },
            2,
        );
        runtime.handle(connect(2, 2), 3);
        assert_eq!(runtime.snapshot(3).state, PeerObservationState::Fresh);
        let old = runtime.handle(
            SessionRuntimeInput::Authenticated {
                generation: generation(1),
                connection_id: 1,
                message: heartbeat("session-a", 3),
            },
            4,
        );
        assert!(matches!(
            old.as_slice(),
            [SessionRuntimeEvent::Rejected(
                SessionRuntimeError::StaleConnection
            )]
        ));
        runtime.handle(
            SessionRuntimeInput::Authenticated {
                generation: generation(2),
                connection_id: 2,
                message: hello("session-b", 1),
            },
            5,
        );
        assert_eq!(runtime.snapshot(5).state, PeerObservationState::NeverSeen);
        runtime.handle(
            SessionRuntimeInput::Authenticated {
                generation: generation(2),
                connection_id: 2,
                message: heartbeat("session-b", 2),
            },
            6,
        );
        assert_eq!(runtime.snapshot(6).state, PeerObservationState::Fresh);
    }

    #[test]
    fn dg_delayed_old_connect_cannot_replace_newer_current_connection() {
        let mut runtime = runtime();
        runtime.handle(connect(1, 1), 0);
        runtime.handle(
            SessionRuntimeInput::Authenticated {
                generation: generation(1),
                connection_id: 1,
                message: hello("session-a", 1),
            },
            1,
        );
        runtime.handle(connect(2, 2), 2);
        runtime.handle(
            SessionRuntimeInput::Authenticated {
                generation: generation(2),
                connection_id: 2,
                message: hello("session-b", 1),
            },
            3,
        );

        let events = runtime.handle(connect(1, 1), 4);
        assert!(matches!(
            events.as_slice(),
            [SessionRuntimeEvent::Rejected(
                SessionRuntimeError::StaleConnection
            )]
        ));
        assert_eq!(runtime.session_state(), SessionRuntimeState::Established);
        assert_eq!(
            runtime.session.current_session_id(),
            Some(&SessionId::new("session-b"))
        );
    }

    #[test]
    fn dh_old_hello_after_stale_connect_cannot_roll_session_back() {
        let mut runtime = runtime();
        runtime.handle(connect(1, 1), 0);
        runtime.handle(
            SessionRuntimeInput::Authenticated {
                generation: generation(1),
                connection_id: 1,
                message: hello("session-a", 1),
            },
            1,
        );
        runtime.handle(connect(2, 2), 2);
        let current = runtime.handle(
            SessionRuntimeInput::Authenticated {
                generation: generation(2),
                connection_id: 2,
                message: hello("session-b", 1),
            },
            3,
        );
        assert!(current
            .iter()
            .any(|event| matches!(event, SessionRuntimeEvent::SessionEstablished { session_id } if session_id.as_str() == "session-b")));

        assert!(matches!(
            runtime.handle(connect(1, 1), 4).as_slice(),
            [SessionRuntimeEvent::Rejected(
                SessionRuntimeError::StaleConnection
            )]
        ));
        let old_hello = runtime.handle(
            SessionRuntimeInput::Authenticated {
                generation: generation(1),
                connection_id: 1,
                message: hello("session-a", 3),
            },
            5,
        );
        assert!(matches!(
            old_hello.as_slice(),
            [SessionRuntimeEvent::Rejected(
                SessionRuntimeError::StaleConnection
            )]
        ));
        assert_eq!(
            runtime.session.current_session_id(),
            Some(&SessionId::new("session-b"))
        );
    }

    #[test]
    fn di_stale_connect_does_not_invalidate_current_fresh_observation() {
        let mut runtime = runtime();
        runtime.handle(connect(1, 1), 0);
        runtime.handle(
            SessionRuntimeInput::Authenticated {
                generation: generation(1),
                connection_id: 1,
                message: hello("session-a", 1),
            },
            1,
        );
        runtime.handle(
            SessionRuntimeInput::Authenticated {
                generation: generation(1),
                connection_id: 1,
                message: heartbeat("session-a", 2),
            },
            20,
        );
        let before = runtime.snapshot(20);
        assert!(matches!(
            runtime.handle(connect(0, 99), 21).as_slice(),
            [SessionRuntimeEvent::Rejected(
                SessionRuntimeError::StaleConnection
            )]
        ));
        let after = runtime.snapshot(21);
        assert_eq!(after.state, PeerObservationState::Fresh);
        assert_eq!(after.session_id, before.session_id);
        assert_eq!(after.sequence, before.sequence);
        assert_eq!(after.last_received_ms, before.last_received_ms);
    }

    #[test]
    fn dj_duplicate_current_connect_is_idempotent() {
        let mut runtime = runtime();
        runtime.handle(connect(1, 1), 0);
        runtime.handle(
            SessionRuntimeInput::Authenticated {
                generation: generation(1),
                connection_id: 1,
                message: hello("session-a", 1),
            },
            1,
        );
        runtime.handle(
            SessionRuntimeInput::Authenticated {
                generation: generation(1),
                connection_id: 1,
                message: heartbeat("session-a", 2),
            },
            20,
        );
        assert!(runtime.handle(connect(1, 1), 21).is_empty());
        assert_eq!(runtime.session_state(), SessionRuntimeState::Established);
        assert_eq!(runtime.snapshot(21).state, PeerObservationState::Fresh);
        assert_eq!(runtime.snapshot(21).sequence, Some(Sequence(2)));
    }

    #[test]
    fn dk_same_generation_with_different_connection_is_rejected() {
        let mut runtime = runtime();
        runtime.handle(connect(1, 1), 0);
        let events = runtime.handle(connect(1, 2), 1);
        assert!(matches!(
            events.as_slice(),
            [SessionRuntimeEvent::Rejected(
                SessionRuntimeError::ConnectionIdentityConflict
            )]
        ));
        assert_eq!(runtime.session_state(), SessionRuntimeState::HelloPending);
    }

    #[test]
    fn dl_stale_disconnect_cannot_tear_down_newer_current_connection() {
        let mut runtime = runtime();
        runtime.handle(connect(1, 1), 0);
        runtime.handle(
            SessionRuntimeInput::Authenticated {
                generation: generation(1),
                connection_id: 1,
                message: hello("session-a", 1),
            },
            1,
        );
        runtime.handle(connect(2, 2), 2);
        runtime.handle(
            SessionRuntimeInput::Authenticated {
                generation: generation(2),
                connection_id: 2,
                message: hello("session-b", 1),
            },
            3,
        );
        let events = runtime.handle(
            SessionRuntimeInput::Disconnect {
                generation: generation(1),
                connection_id: 1,
            },
            4,
        );
        assert!(matches!(
            events.as_slice(),
            [SessionRuntimeEvent::Rejected(
                SessionRuntimeError::StaleConnection
            )]
        ));
        assert_eq!(runtime.session_state(), SessionRuntimeState::Established);
    }

    #[test]
    fn dm_old_generation_heartbeat_cannot_refresh_current_observation() {
        let mut runtime = runtime();
        runtime.handle(connect(1, 1), 0);
        runtime.handle(
            SessionRuntimeInput::Authenticated {
                generation: generation(1),
                connection_id: 1,
                message: hello("session-a", 1),
            },
            1,
        );
        runtime.handle(
            SessionRuntimeInput::Authenticated {
                generation: generation(1),
                connection_id: 1,
                message: heartbeat("session-a", 2),
            },
            2,
        );
        runtime.handle(connect(2, 2), 3);
        runtime.handle(
            SessionRuntimeInput::Authenticated {
                generation: generation(2),
                connection_id: 2,
                message: hello("session-b", 1),
            },
            4,
        );
        let events = runtime.handle(
            SessionRuntimeInput::Authenticated {
                generation: generation(1),
                connection_id: 1,
                message: heartbeat("session-a", 3),
            },
            5,
        );
        assert!(matches!(
            events.as_slice(),
            [SessionRuntimeEvent::Rejected(
                SessionRuntimeError::StaleConnection
            )]
        ));
        assert_eq!(runtime.snapshot(5).state, PeerObservationState::NeverSeen);
    }

    #[test]
    fn generation_allocator_rejects_overflow_without_wrapping() {
        let mut allocator = ConnectionGenerationAllocator { next: u64::MAX };
        assert_eq!(allocator.next(), Err(ConnectionGenerationError::Exhausted));
        assert_eq!(allocator.next, u64::MAX);
    }

    #[test]
    fn teardown_and_reconnect_do_not_create_fresh_without_hello() {
        let mut runtime = runtime();
        runtime.handle(connect(1, 1), 0);
        runtime.handle(
            SessionRuntimeInput::Authenticated {
                generation: generation(1),
                connection_id: 1,
                message: hello("session-a", 1),
            },
            1,
        );
        runtime.handle(
            SessionRuntimeInput::Authenticated {
                generation: generation(1),
                connection_id: 1,
                message: heartbeat("session-a", 2),
            },
            2,
        );
        let events = runtime.handle(
            SessionRuntimeInput::Disconnect {
                generation: generation(1),
                connection_id: 1,
            },
            3,
        );
        assert!(matches!(
            events.as_slice(),
            [SessionRuntimeEvent::TransportUnavailable]
        ));
        assert_eq!(runtime.snapshot(3).state, PeerObservationState::Unavailable);
        runtime.handle(connect(2, 2), 4);
        assert_eq!(runtime.snapshot(4).state, PeerObservationState::Unavailable);
        let events = runtime.handle(
            SessionRuntimeInput::Authenticated {
                generation: generation(2),
                connection_id: 2,
                message: heartbeat("session-b", 1),
            },
            5,
        );
        assert!(matches!(
            events.as_slice(),
            [SessionRuntimeEvent::Rejected(_)]
        ));
        assert_ne!(runtime.snapshot(5).state, PeerObservationState::Fresh);
    }

    #[test]
    fn invalid_identity_and_protocol_inputs_cannot_establish() {
        let mut runtime = runtime();
        runtime.handle(connect(1, 1), 0);
        let events = runtime.handle(
            SessionRuntimeInput::ProtocolMismatch {
                generation: generation(1),
                connection_id: 1,
            },
            1,
        );
        assert!(matches!(
            events.as_slice(),
            [SessionRuntimeEvent::Rejected(
                SessionRuntimeError::InvalidInput
            )]
        ));
        assert_eq!(runtime.session_state(), SessionRuntimeState::Invalid);

        runtime.handle(connect(2, 2), 2);
        let wrong_cluster = authenticated_with_identity(
            ProtocolMessage::Hello(HelloPayload { priority: 100 }),
            "wrong-cluster",
            "node-b",
            "node-a",
            "session-b",
            1,
        );
        let events = runtime.handle(
            SessionRuntimeInput::Authenticated {
                generation: generation(2),
                connection_id: 2,
                message: wrong_cluster,
            },
            3,
        );
        assert!(matches!(
            events.as_slice(),
            [SessionRuntimeEvent::Rejected(SessionRuntimeError::Session(
                SessionError::ClusterMismatch
            ))]
        ));

        runtime.handle(connect(3, 3), 4);
        let wrong_peer = authenticated_with_identity(
            ProtocolMessage::Hello(HelloPayload { priority: 100 }),
            "cluster",
            "unexpected-node",
            "node-a",
            "session-c",
            1,
        );
        let events = runtime.handle(
            SessionRuntimeInput::Authenticated {
                generation: generation(3),
                connection_id: 3,
                message: wrong_peer,
            },
            5,
        );
        assert!(matches!(
            events.as_slice(),
            [SessionRuntimeEvent::Rejected(SessionRuntimeError::Session(
                SessionError::SenderMismatch
            ))]
        ));

        runtime.handle(connect(4, 4), 6);
        let events = runtime.handle(
            SessionRuntimeInput::AuthenticationFailure {
                generation: generation(4),
                connection_id: 4,
            },
            7,
        );
        assert!(matches!(
            events.as_slice(),
            [SessionRuntimeEvent::Rejected(
                SessionRuntimeError::InvalidInput
            )]
        ));
    }
}
