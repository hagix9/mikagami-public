use crate::protocol::{
    ClusterId, CommonFields, HelloPayload, MessageType, NodeId, PROTOCOL_VERSION, ProtocolMessage,
    Sequence, SessionId, Term, UnsignedEnvelope,
};
use crate::receive::AuthenticatedMessage;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};

const SESSION_ID_BYTES: usize = 16;

pub struct ProcessSession {
    session_id: SessionId,
    next_sequence: Option<u64>,
}

impl ProcessSession {
    pub fn generate() -> Result<Self, SessionGenerationError> {
        let mut bytes = [0u8; SESSION_ID_BYTES];
        File::open("/dev/urandom")?
            .read_exact(&mut bytes)
            .map_err(SessionGenerationError::Io)?;

        let mut encoded = String::with_capacity(SESSION_ID_BYTES * 2);
        for byte in bytes {
            use std::fmt::Write;
            write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
        }

        Ok(Self {
            session_id: SessionId::new(encoded),
            next_sequence: Some(1),
        })
    }

    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub fn next_sequence(&mut self) -> Result<Sequence, SequenceError> {
        let current = self.next_sequence.take().ok_or(SequenceError::Exhausted)?;
        if current < u64::MAX {
            self.next_sequence = Some(current + 1);
        }
        Ok(Sequence(current))
    }

    #[cfg(test)]
    pub(crate) fn from_session_id(session_id: SessionId) -> Self {
        Self {
            session_id,
            next_sequence: Some(1),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_next_sequence(session_id: SessionId, next_sequence: u64) -> Self {
        Self {
            session_id,
            next_sequence: Some(next_sequence),
        }
    }
}

#[derive(Debug)]
pub enum SessionGenerationError {
    Io(io::Error),
}

impl fmt::Display for SessionGenerationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "failed to read OS CSPRNG: {error}"),
        }
    }
}

impl std::error::Error for SessionGenerationError {}

impl From<io::Error> for SessionGenerationError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequenceError {
    Exhausted,
}

impl fmt::Display for SequenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exhausted => write!(f, "outbound sequence is exhausted"),
        }
    }
}

impl std::error::Error for SequenceError {}

pub struct OutboundHandshake {
    cluster_id: ClusterId,
    local_node_id: NodeId,
    peer_node_id: NodeId,
    local_priority: i32,
    state: OutboundHandshakeState,
    peer_session_id: Option<SessionId>,
    peer_last_accepted_sequence: Option<Sequence>,
}

impl OutboundHandshake {
    pub fn new(
        cluster_id: ClusterId,
        local_node_id: NodeId,
        peer_node_id: NodeId,
        local_priority: i32,
    ) -> Self {
        Self {
            cluster_id,
            local_node_id,
            peer_node_id,
            local_priority,
            state: OutboundHandshakeState::Ready,
            peer_session_id: None,
            peer_last_accepted_sequence: None,
        }
    }

    pub const fn state(&self) -> OutboundHandshakeState {
        self.state
    }

    pub fn peer_session_id(&self) -> Option<&SessionId> {
        self.peer_session_id.as_ref()
    }

    pub const fn peer_last_accepted_sequence(&self) -> Option<Sequence> {
        self.peer_last_accepted_sequence
    }

    pub fn build_hello(
        &mut self,
        process_session: &mut ProcessSession,
        term: Term,
    ) -> Result<UnsignedEnvelope, OutboundHandshakeError> {
        if self.state != OutboundHandshakeState::Ready {
            return Err(OutboundHandshakeError::HelloAlreadySent);
        }

        let sequence = process_session
            .next_sequence()
            .map_err(OutboundHandshakeError::Sequence)?;
        let hello = UnsignedEnvelope {
            common: CommonFields {
                protocol_version: PROTOCOL_VERSION,
                cluster_id: self.cluster_id.clone(),
                sender_node_id: self.local_node_id.clone(),
                receiver_node_id: self.peer_node_id.clone(),
                session_id: process_session.session_id().clone(),
                sequence,
                term,
                lease_id: None,
                request_id: None,
                operation_id: None,
            },
            message: ProtocolMessage::Hello(HelloPayload {
                priority: self.local_priority,
            }),
        };
        self.state = OutboundHandshakeState::HelloSent;
        Ok(hello)
    }

    pub fn accept_hello_ack(
        &mut self,
        message: &AuthenticatedMessage,
    ) -> Result<(), OutboundHandshakeError> {
        if self.state == OutboundHandshakeState::Rejected {
            return Err(OutboundHandshakeError::Rejected);
        }
        if self.state != OutboundHandshakeState::HelloSent {
            return Err(OutboundHandshakeError::HelloNotSent);
        }

        let common = &message.unsigned().common;
        if common.cluster_id != self.cluster_id {
            return self.reject(OutboundHandshakeError::ClusterMismatch);
        }
        if common.sender_node_id != self.peer_node_id {
            return self.reject(OutboundHandshakeError::SenderMismatch);
        }
        if common.receiver_node_id != self.local_node_id {
            return self.reject(OutboundHandshakeError::ReceiverMismatch);
        }
        if message.unsigned().message.message_type() != MessageType::HelloAck {
            return self.reject(OutboundHandshakeError::ExpectedHelloAck);
        }
        if common.sequence.0 == 0 {
            return self.reject(OutboundHandshakeError::InvalidSequence);
        }

        self.peer_session_id = Some(common.session_id.clone());
        self.peer_last_accepted_sequence = Some(common.sequence);
        self.state = OutboundHandshakeState::Established;
        Ok(())
    }

    fn reject(&mut self, error: OutboundHandshakeError) -> Result<(), OutboundHandshakeError> {
        self.state = OutboundHandshakeState::Rejected;
        Err(error)
    }
}

pub fn build_hello_ack(
    process_session: &mut ProcessSession,
    cluster_id: ClusterId,
    local_node_id: NodeId,
    peer_node_id: NodeId,
    term: Term,
) -> Result<UnsignedEnvelope, SequenceError> {
    Ok(UnsignedEnvelope {
        common: CommonFields {
            protocol_version: PROTOCOL_VERSION,
            cluster_id,
            sender_node_id: local_node_id,
            receiver_node_id: peer_node_id,
            session_id: process_session.session_id().clone(),
            sequence: process_session.next_sequence()?,
            term,
            lease_id: None,
            request_id: None,
            operation_id: None,
        },
        message: ProtocolMessage::HelloAck,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundHandshakeState {
    Ready,
    HelloSent,
    Established,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundHandshakeError {
    HelloAlreadySent,
    Sequence(SequenceError),
    HelloNotSent,
    ExpectedHelloAck,
    ClusterMismatch,
    SenderMismatch,
    ReceiverMismatch,
    InvalidSequence,
    Rejected,
}

impl fmt::Display for OutboundHandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::HelloAlreadySent => "HELLO has already been prepared",
            Self::Sequence(error) => return write!(f, "sequence allocation failed: {error}"),
            Self::HelloNotSent => "HELLO must be prepared before HELLO_ACK",
            Self::ExpectedHelloAck => "HELLO_ACK is required",
            Self::ClusterMismatch => "cluster identity mismatch",
            Self::SenderMismatch => "sender identity mismatch",
            Self::ReceiverMismatch => "receiver identity mismatch",
            Self::InvalidSequence => "HELLO_ACK sequence must be greater than zero",
            Self::Rejected => "outbound handshake is rejected",
        };
        write!(f, "{message}")
    }
}

impl std::error::Error for OutboundHandshakeError {}

pub struct PeerSession {
    cluster_id: ClusterId,
    local_node_id: NodeId,
    peer_node_id: NodeId,
    expected_peer_priority: i32,
    state: PeerSessionState,
    peer_session_id: Option<SessionId>,
    last_accepted_sequence: Option<Sequence>,
}

impl PeerSession {
    pub fn new(
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
            state: PeerSessionState::AwaitingHello,
            peer_session_id: None,
            last_accepted_sequence: None,
        }
    }

    pub const fn state(&self) -> PeerSessionState {
        self.state
    }

    pub fn peer_session_id(&self) -> Option<&SessionId> {
        self.peer_session_id.as_ref()
    }

    pub const fn last_accepted_sequence(&self) -> Option<Sequence> {
        self.last_accepted_sequence
    }

    pub fn accept(
        &mut self,
        message: &AuthenticatedMessage,
    ) -> Result<SessionAction, SessionError> {
        if self.state == PeerSessionState::Rejected {
            return Err(SessionError::Rejected);
        }

        if self.state == PeerSessionState::AwaitingHello
            && message.unsigned().message.message_type() != MessageType::Hello
        {
            return self.reject(SessionError::ExpectedHello);
        }

        let common = &message.unsigned().common;
        if common.cluster_id != self.cluster_id {
            return self.reject(SessionError::ClusterMismatch);
        }
        if common.sender_node_id != self.peer_node_id {
            return self.reject(SessionError::SenderMismatch);
        }
        if common.receiver_node_id != self.local_node_id {
            return self.reject(SessionError::ReceiverMismatch);
        }

        if self.state == PeerSessionState::AwaitingHello {
            let priority = match &message.unsigned().message {
                crate::protocol::ProtocolMessage::Hello(payload) => payload.priority,
                _ => unreachable!("HELLO was checked above"),
            };
            if priority != self.expected_peer_priority {
                return self.reject(SessionError::PriorityMismatch);
            }
            if common.sequence.0 == 0 {
                return self.reject(SessionError::InvalidHelloSequence);
            }
            self.peer_session_id = Some(common.session_id.clone());
            self.last_accepted_sequence = Some(common.sequence);
            self.state = PeerSessionState::Established;
            return Ok(SessionAction::SendHelloAck);
        }

        if self.peer_session_id.as_ref() != Some(&common.session_id) {
            return self.reject(SessionError::SessionIdMismatch);
        }
        if self
            .last_accepted_sequence
            .is_some_and(|last| common.sequence.0 <= last.0)
        {
            return self.reject(SessionError::StaleOrDuplicateSequence);
        }

        self.last_accepted_sequence = Some(common.sequence);
        Ok(SessionAction::Accept)
    }

    fn reject(&mut self, error: SessionError) -> Result<SessionAction, SessionError> {
        self.state = PeerSessionState::Rejected;
        Err(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerSessionState {
    AwaitingHello,
    Established,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAction {
    SendHelloAck,
    Accept,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    ClusterMismatch,
    SenderMismatch,
    ReceiverMismatch,
    PriorityMismatch,
    ExpectedHello,
    InvalidHelloSequence,
    SessionIdMismatch,
    StaleOrDuplicateSequence,
    Rejected,
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ClusterMismatch => "cluster identity mismatch",
            Self::SenderMismatch => "sender identity mismatch",
            Self::ReceiverMismatch => "receiver identity mismatch",
            Self::PriorityMismatch => "peer priority mismatch",
            Self::ExpectedHello => "HELLO is required before other messages",
            Self::InvalidHelloSequence => "HELLO sequence must be greater than zero",
            Self::SessionIdMismatch => "peer session_id changed",
            Self::StaleOrDuplicateSequence => "stale or duplicate sequence",
            Self::Rejected => "peer session is rejected",
        };
        write!(f, "{message}")
    }
}

impl std::error::Error for SessionError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        CanonicalSerializer, CborSerializer, CommonFields, HelloPayload, NodeStatusPayload,
        ProtocolMessage, Role, Sequence, Term, UnsignedEnvelope,
    };
    use crate::receive::receive;
    use crate::security::{MessageAuthenticator, Psk};

    fn authenticator() -> MessageAuthenticator {
        MessageAuthenticator::new(Psk::from_test_bytes([0x0b; 32]))
    }

    fn authenticated(
        message: ProtocolMessage,
        cluster: &str,
        sender: &str,
        receiver: &str,
        session: &str,
        sequence: u64,
    ) -> AuthenticatedMessage {
        let unsigned = UnsignedEnvelope {
            common: CommonFields {
                protocol_version: 1,
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
        let authenticator = authenticator();
        let wire = authenticator.sign(unsigned, &serializer).unwrap();
        let bytes = serializer.serialize_wire(&wire).unwrap();
        receive(&bytes, &serializer, &authenticator).unwrap()
    }

    fn hello(
        cluster: &str,
        sender: &str,
        receiver: &str,
        session: &str,
        sequence: u64,
    ) -> AuthenticatedMessage {
        authenticated(
            ProtocolMessage::Hello(HelloPayload { priority: 100 }),
            cluster,
            sender,
            receiver,
            session,
            sequence,
        )
    }

    fn heartbeat(session: &str, sequence: u64) -> AuthenticatedMessage {
        authenticated(
            ProtocolMessage::Heartbeat(NodeStatusPayload {
                node_state: crate::state_machine::NodeState::Standby,
                operation_phase: None,
                role: Role::Standby,
                service_state: "stopped".to_string(),
                health_state: "unknown".to_string(),
                vip_state: "absent".to_string(),
            }),
            "cluster",
            "node-b",
            "node-a",
            session,
            sequence,
        )
    }

    fn make_session() -> PeerSession {
        PeerSession::new(
            ClusterId::new("cluster"),
            NodeId::new("node-a"),
            NodeId::new("node-b"),
            100,
        )
    }

    #[test]
    fn accepts_hello_and_requests_ack() {
        let mut session = make_session();
        let message = hello("cluster", "node-b", "node-a", "session-a", 1);
        assert_eq!(session.accept(&message), Ok(SessionAction::SendHelloAck));
        assert_eq!(session.state(), PeerSessionState::Established);
        assert_eq!(session.peer_session_id().unwrap().as_str(), "session-a");
        assert_eq!(session.last_accepted_sequence(), Some(Sequence(1)));
    }

    #[test]
    fn rejects_wrong_peer_identity() {
        for (cluster, sender, receiver, expected) in [
            ("other", "node-b", "node-a", SessionError::ClusterMismatch),
            ("cluster", "other", "node-a", SessionError::SenderMismatch),
            ("cluster", "node-b", "other", SessionError::ReceiverMismatch),
        ] {
            let mut session = make_session();
            assert_eq!(
                session.accept(&hello(cluster, sender, receiver, "session-a", 1)),
                Err(expected)
            );
            assert_eq!(session.state(), PeerSessionState::Rejected);
        }

        let mut session = make_session();
        let message = authenticated(
            ProtocolMessage::Hello(HelloPayload { priority: 90 }),
            "cluster",
            "node-b",
            "node-a",
            "session-a",
            1,
        );
        assert_eq!(
            session.accept(&message),
            Err(SessionError::PriorityMismatch)
        );
        assert_eq!(session.state(), PeerSessionState::Rejected);
    }

    #[test]
    fn requires_hello_as_first_message() {
        let mut session = make_session();
        assert_eq!(
            session.accept(&heartbeat("session-a", 1)),
            Err(SessionError::ExpectedHello)
        );
        assert_eq!(session.state(), PeerSessionState::Rejected);
    }

    #[test]
    fn rejects_hello_sequence_zero() {
        let mut session = make_session();
        assert_eq!(
            session.accept(&hello("cluster", "node-b", "node-a", "session-a", 0)),
            Err(SessionError::InvalidHelloSequence)
        );
    }

    #[test]
    fn invalid_hello_sequence_error_describes_current_contract() {
        assert_eq!(
            SessionError::InvalidHelloSequence.to_string(),
            "HELLO sequence must be greater than zero"
        );
    }

    #[test]
    fn accepts_reconnect_style_hello_sequence() {
        let mut session = make_session();
        assert_eq!(
            session.accept(&hello("cluster", "node-b", "node-a", "session-a", 57)),
            Ok(SessionAction::SendHelloAck)
        );
        assert_eq!(session.state(), PeerSessionState::Established);
        assert_eq!(session.peer_session_id().unwrap().as_str(), "session-a");
        assert_eq!(session.last_accepted_sequence(), Some(Sequence(57)));
    }

    #[test]
    fn accepts_hello_sequence_two() {
        let mut session = make_session();
        assert_eq!(
            session.accept(&hello("cluster", "node-b", "node-a", "session-a", 2)),
            Ok(SessionAction::SendHelloAck)
        );
        assert_eq!(session.last_accepted_sequence(), Some(Sequence(2)));
    }

    #[test]
    fn enforces_established_session_and_strictly_increasing_sequence() {
        let mut session = make_session();
        assert_eq!(
            session.accept(&hello("cluster", "node-b", "node-a", "session-a", 1)),
            Ok(SessionAction::SendHelloAck)
        );
        assert_eq!(
            session.accept(&heartbeat("session-a", 2)),
            Ok(SessionAction::Accept)
        );
        assert_eq!(
            session.accept(&heartbeat("session-a", 3)),
            Ok(SessionAction::Accept)
        );
        assert_eq!(
            session.accept(&heartbeat("session-a", 3)),
            Err(SessionError::StaleOrDuplicateSequence)
        );
        assert_eq!(session.state(), PeerSessionState::Rejected);

        let mut gap_session = make_session();
        gap_session
            .accept(&hello("cluster", "node-b", "node-a", "session-b", 57))
            .unwrap();
        assert_eq!(
            gap_session.accept(&heartbeat("session-b", 58)),
            Ok(SessionAction::Accept)
        );
        assert_eq!(
            gap_session.accept(&heartbeat("session-b", 100)),
            Ok(SessionAction::Accept)
        );
        assert_eq!(gap_session.last_accepted_sequence(), Some(Sequence(100)));
    }

    #[test]
    fn rejects_sequences_not_greater_than_hello() {
        for sequence in [57, 56] {
            let mut session = make_session();
            session
                .accept(&hello("cluster", "node-b", "node-a", "session-a", 57))
                .unwrap();
            assert_eq!(
                session.accept(&heartbeat("session-a", sequence)),
                Err(SessionError::StaleOrDuplicateSequence)
            );
        }
    }

    #[test]
    fn rejects_session_change_after_established() {
        let mut session = make_session();
        session
            .accept(&hello("cluster", "node-b", "node-a", "session-a", 1))
            .unwrap();
        let changed = heartbeat("session-b", 2);
        assert_eq!(
            session.accept(&changed),
            Err(SessionError::SessionIdMismatch)
        );
        assert_eq!(session.state(), PeerSessionState::Rejected);
    }

    #[test]
    fn rejected_session_cannot_accept_later_messages() {
        let mut session = make_session();
        session
            .accept(&hello("other", "node-b", "node-a", "session-a", 1))
            .unwrap_err();
        assert_eq!(
            session.accept(&hello("cluster", "node-b", "node-a", "session-a", 1)),
            Err(SessionError::Rejected)
        );
    }

    #[test]
    fn rejected_message_does_not_advance_sequence() {
        let mut session = make_session();
        session
            .accept(&hello("cluster", "node-b", "node-a", "session-a", 1))
            .unwrap();
        session.accept(&heartbeat("session-a", 2)).unwrap();

        let invalid_identity = authenticated(
            ProtocolMessage::Heartbeat(NodeStatusPayload {
                node_state: crate::state_machine::NodeState::Standby,
                operation_phase: None,
                role: Role::Standby,
                service_state: "stopped".to_string(),
                health_state: "unknown".to_string(),
                vip_state: "absent".to_string(),
            }),
            "cluster",
            "other-node",
            "node-a",
            "session-a",
            100,
        );
        assert_eq!(
            session.accept(&invalid_identity),
            Err(SessionError::SenderMismatch)
        );
        assert_eq!(session.last_accepted_sequence(), Some(Sequence(2)));
    }

    #[test]
    fn process_session_uses_fixed_identity_and_process_wide_sequences() {
        let mut process = ProcessSession::from_session_id(SessionId::new("fixed-session"));
        assert_eq!(process.session_id().as_str(), "fixed-session");
        assert_eq!(process.next_sequence(), Ok(Sequence(1)));
        assert_eq!(process.next_sequence(), Ok(Sequence(2)));
        assert_eq!(process.next_sequence(), Ok(Sequence(3)));
    }

    #[test]
    fn production_session_id_uses_nonempty_hex_identity() {
        let first = ProcessSession::generate().unwrap();
        let second = ProcessSession::generate().unwrap();
        assert_eq!(first.session_id().as_str().len(), 32);
        assert!(
            first
                .session_id()
                .as_str()
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        );
        assert_ne!(first.session_id(), second.session_id());
    }

    #[test]
    fn sequence_exhaustion_does_not_wrap() {
        let mut process = ProcessSession::with_next_sequence(SessionId::new("fixed"), u64::MAX);
        assert_eq!(process.next_sequence(), Ok(Sequence(u64::MAX)));
        assert_eq!(process.next_sequence(), Err(SequenceError::Exhausted));
    }

    #[test]
    fn builds_first_hello_from_process_session() {
        let mut process = ProcessSession::from_session_id(SessionId::new("local-session"));
        let mut handshake = OutboundHandshake::new(
            ClusterId::new("cluster"),
            NodeId::new("node-a"),
            NodeId::new("node-b"),
            120,
        );
        let hello = handshake.build_hello(&mut process, Term(4)).unwrap();
        hello.validate().unwrap();
        assert_eq!(handshake.state(), OutboundHandshakeState::HelloSent);
        assert_eq!(hello.common.cluster_id, ClusterId::new("cluster"));
        assert_eq!(hello.common.sender_node_id, NodeId::new("node-a"));
        assert_eq!(hello.common.receiver_node_id, NodeId::new("node-b"));
        assert_eq!(hello.common.session_id, SessionId::new("local-session"));
        assert_eq!(hello.common.sequence, Sequence(1));
        assert_eq!(hello.common.term, Term(4));
        assert_eq!(hello.common.lease_id, None);
        assert_eq!(hello.common.request_id, None);
        assert_eq!(hello.common.operation_id, None);
        assert_eq!(
            hello.message,
            ProtocolMessage::Hello(HelloPayload { priority: 120 })
        );
    }

    #[test]
    fn reconnect_handshake_continues_process_sequence() {
        let mut process = ProcessSession::from_session_id(SessionId::new("local-session"));
        let mut first = OutboundHandshake::new(
            ClusterId::new("cluster"),
            NodeId::new("node-a"),
            NodeId::new("node-b"),
            100,
        );
        assert_eq!(
            first
                .build_hello(&mut process, Term(1))
                .unwrap()
                .common
                .sequence,
            Sequence(1)
        );
        assert_eq!(process.next_sequence(), Ok(Sequence(2)));
        assert_eq!(process.next_sequence(), Ok(Sequence(3)));

        let mut second = OutboundHandshake::new(
            ClusterId::new("cluster"),
            NodeId::new("node-a"),
            NodeId::new("node-b"),
            100,
        );
        assert_eq!(
            second
                .build_hello(&mut process, Term(1))
                .unwrap()
                .common
                .sequence,
            Sequence(4)
        );
    }

    #[test]
    fn outbound_hello_is_one_shot_without_extra_sequence_consumption() {
        let mut process = ProcessSession::from_session_id(SessionId::new("local-session"));
        let mut handshake = OutboundHandshake::new(
            ClusterId::new("cluster"),
            NodeId::new("node-a"),
            NodeId::new("node-b"),
            100,
        );
        handshake.build_hello(&mut process, Term(1)).unwrap();
        assert_eq!(
            handshake.build_hello(&mut process, Term(1)),
            Err(OutboundHandshakeError::HelloAlreadySent)
        );
        assert_eq!(process.next_sequence(), Ok(Sequence(2)));
    }

    #[test]
    fn accepts_authenticated_hello_ack_and_captures_peer_sequence() {
        let mut process = ProcessSession::from_session_id(SessionId::new("local-session"));
        let mut handshake = OutboundHandshake::new(
            ClusterId::new("cluster"),
            NodeId::new("node-a"),
            NodeId::new("node-b"),
            100,
        );
        handshake.build_hello(&mut process, Term(1)).unwrap();
        let ack = authenticated(
            ProtocolMessage::HelloAck,
            "cluster",
            "node-b",
            "node-a",
            "peer-session",
            7,
        );
        assert_eq!(handshake.accept_hello_ack(&ack), Ok(()));
        assert_eq!(handshake.state(), OutboundHandshakeState::Established);
        assert_eq!(
            handshake.peer_session_id().unwrap().as_str(),
            "peer-session"
        );
        assert_eq!(handshake.peer_last_accepted_sequence(), Some(Sequence(7)));
    }

    #[test]
    fn rejects_ack_before_hello_and_rejected_handshake_stays_rejected() {
        let ack = authenticated(
            ProtocolMessage::HelloAck,
            "cluster",
            "node-b",
            "node-a",
            "peer-session",
            7,
        );
        let mut ready = OutboundHandshake::new(
            ClusterId::new("cluster"),
            NodeId::new("node-a"),
            NodeId::new("node-b"),
            100,
        );
        assert_eq!(
            ready.accept_hello_ack(&ack),
            Err(OutboundHandshakeError::HelloNotSent)
        );
        assert_eq!(ready.state(), OutboundHandshakeState::Ready);

        let mut rejected = OutboundHandshake::new(
            ClusterId::new("cluster"),
            NodeId::new("node-a"),
            NodeId::new("node-b"),
            100,
        );
        let mut process = ProcessSession::from_session_id(SessionId::new("local-session"));
        rejected.build_hello(&mut process, Term(1)).unwrap();
        let wrong_sender = authenticated(
            ProtocolMessage::HelloAck,
            "cluster",
            "other-node",
            "node-a",
            "peer-session",
            7,
        );
        assert_eq!(
            rejected.accept_hello_ack(&wrong_sender),
            Err(OutboundHandshakeError::SenderMismatch)
        );
        assert_eq!(rejected.state(), OutboundHandshakeState::Rejected);
        assert_eq!(
            rejected.accept_hello_ack(&ack),
            Err(OutboundHandshakeError::Rejected)
        );
    }

    #[test]
    fn rejects_hello_ack_identity_type_and_zero_sequence_mismatch() {
        let cases = [
            (
                authenticated(
                    ProtocolMessage::HelloAck,
                    "other",
                    "node-b",
                    "node-a",
                    "peer-session",
                    7,
                ),
                OutboundHandshakeError::ClusterMismatch,
            ),
            (
                authenticated(
                    ProtocolMessage::HelloAck,
                    "cluster",
                    "node-b",
                    "other",
                    "peer-session",
                    7,
                ),
                OutboundHandshakeError::ReceiverMismatch,
            ),
            (
                heartbeat("peer-session", 7),
                OutboundHandshakeError::ExpectedHelloAck,
            ),
            (
                authenticated(
                    ProtocolMessage::HelloAck,
                    "cluster",
                    "node-b",
                    "node-a",
                    "peer-session",
                    0,
                ),
                OutboundHandshakeError::InvalidSequence,
            ),
        ];
        for (message, expected) in cases {
            let mut process = ProcessSession::from_session_id(SessionId::new("local-session"));
            let mut handshake = OutboundHandshake::new(
                ClusterId::new("cluster"),
                NodeId::new("node-a"),
                NodeId::new("node-b"),
                100,
            );
            handshake.build_hello(&mut process, Term(1)).unwrap();
            assert_eq!(handshake.accept_hello_ack(&message), Err(expected));
            assert_eq!(handshake.state(), OutboundHandshakeState::Rejected);
        }
    }

    #[test]
    fn rejects_ack_after_established_without_rewriting_peer_state() {
        let mut process = ProcessSession::from_session_id(SessionId::new("local-session"));
        let mut handshake = OutboundHandshake::new(
            ClusterId::new("cluster"),
            NodeId::new("node-a"),
            NodeId::new("node-b"),
            100,
        );
        handshake.build_hello(&mut process, Term(1)).unwrap();
        let first = authenticated(
            ProtocolMessage::HelloAck,
            "cluster",
            "node-b",
            "node-a",
            "peer-session",
            7,
        );
        handshake.accept_hello_ack(&first).unwrap();
        let second = authenticated(
            ProtocolMessage::HelloAck,
            "cluster",
            "node-b",
            "node-a",
            "other-peer-session",
            8,
        );
        assert_eq!(
            handshake.accept_hello_ack(&second),
            Err(OutboundHandshakeError::HelloNotSent)
        );
        assert_eq!(
            handshake.peer_session_id().unwrap().as_str(),
            "peer-session"
        );
        assert_eq!(handshake.peer_last_accepted_sequence(), Some(Sequence(7)));
    }
}
