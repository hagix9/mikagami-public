use crate::protocol::{CborSerializer, ClusterId, NodeId, Sequence, Term};
use crate::security::MessageAuthenticator;
use crate::session::{
    OutboundHandshake, OutboundHandshakeError, PeerSession, ProcessSession, SessionAction,
    SessionError, build_hello_ack,
};
use crate::tcp::{ReceiveMessageResult, TcpConnection, TcpError};
use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

pub struct HandshakeResult {
    pub connection: TcpConnection,
    pub peer_session_id: crate::protocol::SessionId,
    pub peer_last_accepted_sequence: Sequence,
}

#[allow(clippy::too_many_arguments)]
pub fn accept_peer_handshake(
    mut connection: TcpConnection,
    cluster_id: ClusterId,
    local_node_id: NodeId,
    peer_node_id: NodeId,
    expected_peer_priority: i32,
    process_session: &mut ProcessSession,
    term: Term,
    serializer: &CborSerializer,
    authenticator: &MessageAuthenticator,
) -> Result<HandshakeResult, HandshakeError> {
    let message = match connection
        .receive_message(serializer, authenticator)
        .map_err(HandshakeError::Tcp)?
    {
        ReceiveMessageResult::Eof => return Err(HandshakeError::CleanEof),
        ReceiveMessageResult::Message(message) => message,
    };

    let mut peer_session = PeerSession::new(
        cluster_id.clone(),
        local_node_id.clone(),
        peer_node_id.clone(),
        expected_peer_priority,
    );
    if peer_session
        .accept(&message)
        .map_err(HandshakeError::Session)?
        != SessionAction::SendHelloAck
    {
        return Err(HandshakeError::UnexpectedSessionAction);
    }

    let peer_session_id = peer_session
        .peer_session_id()
        .cloned()
        .ok_or(HandshakeError::MissingPeerSession)?;
    let peer_last_accepted_sequence = peer_session
        .last_accepted_sequence()
        .ok_or(HandshakeError::MissingPeerSequence)?;
    let ack = build_hello_ack(
        process_session,
        cluster_id,
        local_node_id,
        peer_node_id,
        term,
    )
    .map_err(HandshakeError::Sequence)?;
    connection
        .send_message(ack, serializer, authenticator)
        .map_err(HandshakeError::Tcp)?;

    Ok(HandshakeResult {
        connection,
        peer_session_id,
        peer_last_accepted_sequence,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn connect_and_handshake(
    address: SocketAddr,
    connect_timeout: Duration,
    read_timeout: Duration,
    write_timeout: Duration,
    cluster_id: ClusterId,
    local_node_id: NodeId,
    peer_node_id: NodeId,
    local_priority: i32,
    process_session: &mut ProcessSession,
    term: Term,
    serializer: &CborSerializer,
    authenticator: &MessageAuthenticator,
) -> Result<HandshakeResult, HandshakeError> {
    let mut connection =
        TcpConnection::connect(address, connect_timeout, read_timeout, write_timeout)
            .map_err(HandshakeError::Tcp)?;
    let mut handshake =
        OutboundHandshake::new(cluster_id, local_node_id, peer_node_id, local_priority);
    let hello = handshake
        .build_hello(process_session, term)
        .map_err(HandshakeError::Outbound)?;
    connection
        .send_message(hello, serializer, authenticator)
        .map_err(HandshakeError::Tcp)?;
    let message = match connection
        .receive_message(serializer, authenticator)
        .map_err(HandshakeError::Tcp)?
    {
        ReceiveMessageResult::Eof => return Err(HandshakeError::CleanEof),
        ReceiveMessageResult::Message(message) => message,
    };
    handshake
        .accept_hello_ack(&message)
        .map_err(HandshakeError::Outbound)?;

    Ok(HandshakeResult {
        connection,
        peer_session_id: handshake
            .peer_session_id()
            .cloned()
            .ok_or(HandshakeError::MissingPeerSession)?,
        peer_last_accepted_sequence: handshake
            .peer_last_accepted_sequence()
            .ok_or(HandshakeError::MissingPeerSequence)?,
    })
}

#[derive(Debug)]
pub enum HandshakeError {
    Tcp(TcpError),
    Session(SessionError),
    Outbound(OutboundHandshakeError),
    Sequence(crate::session::SequenceError),
    CleanEof,
    UnexpectedSessionAction,
    MissingPeerSession,
    MissingPeerSequence,
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp(error) => write!(f, "TCP handshake failed: {error}"),
            Self::Session(error) => write!(f, "inbound session handshake failed: {error}"),
            Self::Outbound(error) => write!(f, "outbound handshake failed: {error}"),
            Self::Sequence(error) => write!(f, "HELLO_ACK sequence allocation failed: {error}"),
            Self::CleanEof => write!(f, "peer closed connection during handshake"),
            Self::UnexpectedSessionAction => write!(f, "unexpected inbound session action"),
            Self::MissingPeerSession => write!(f, "peer session_id was not captured"),
            Self::MissingPeerSequence => write!(f, "peer sequence was not captured"),
        }
    }
}

impl std::error::Error for HandshakeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Tcp(error) => Some(error),
            Self::Session(error) => Some(error),
            Self::Outbound(error) => Some(error),
            Self::Sequence(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listener::PeerListener;
    use crate::protocol::{
        CommonFields, NodeStatusPayload, PROTOCOL_VERSION, ProtocolMessage, Role, UnsignedEnvelope,
    };
    use crate::security::{AuthenticationError, Psk};
    use crate::state_machine::NodeState;
    use crate::tcp::ReceiveMessageResult;
    use std::net::SocketAddr;
    use std::thread;

    const TIMEOUT: Duration = Duration::from_secs(2);

    fn authenticator(value: u8) -> MessageAuthenticator {
        MessageAuthenticator::new(Psk::from_test_bytes([value; 32]))
    }

    fn listener() -> (PeerListener, SocketAddr) {
        let listener =
            PeerListener::bind("127.0.0.1:0".parse().unwrap(), TIMEOUT, TIMEOUT).unwrap();
        let address = listener.local_addr().unwrap();
        (listener, address)
    }

    fn process(id: &str, next_sequence: u64) -> ProcessSession {
        let mut process = ProcessSession::from_session_id(crate::protocol::SessionId::new(id));
        for _ in 1..next_sequence {
            process.next_sequence().unwrap();
        }
        process
    }

    fn heartbeat() -> UnsignedEnvelope {
        UnsignedEnvelope {
            common: CommonFields {
                protocol_version: PROTOCOL_VERSION,
                cluster_id: ClusterId::new("cluster"),
                sender_node_id: NodeId::new("node-a"),
                receiver_node_id: NodeId::new("node-b"),
                session_id: crate::protocol::SessionId::new("session-a"),
                sequence: Sequence(1),
                term: Term(1),
                lease_id: None,
                request_id: None,
                operation_id: None,
            },
            message: ProtocolMessage::Heartbeat(NodeStatusPayload {
                node_state: NodeState::Standby,
                operation_phase: None,
                role: Role::Standby,
                service_state: "stopped".to_string(),
                health_state: "unknown".to_string(),
                vip_state: "absent".to_string(),
            }),
        }
    }

    fn server(
        listener: PeerListener,
        process_session: ProcessSession,
        expected_priority: i32,
        psk: u8,
    ) -> thread::JoinHandle<Result<HandshakeResult, HandshakeError>> {
        thread::spawn(move || {
            let (connection, _) = listener.accept().unwrap();
            let mut process_session = process_session;
            accept_peer_handshake(
                connection,
                ClusterId::new("cluster"),
                NodeId::new("node-b"),
                NodeId::new("node-a"),
                expected_priority,
                &mut process_session,
                Term(1),
                &CborSerializer,
                &authenticator(psk),
            )
        })
    }

    #[test]
    fn completes_successful_localhost_handshake_and_keeps_connection() {
        let (listener, address) = listener();
        let server = server(listener, process("session-b", 1), 120, 0x0b);
        let mut client_process = process("session-a", 1);
        let result = connect_and_handshake(
            address,
            TIMEOUT,
            TIMEOUT,
            TIMEOUT,
            ClusterId::new("cluster"),
            NodeId::new("node-a"),
            NodeId::new("node-b"),
            120,
            &mut client_process,
            Term(1),
            &CborSerializer,
            &authenticator(0x0b),
        )
        .unwrap();
        assert_eq!(result.peer_session_id.as_str(), "session-b");
        assert_eq!(result.peer_last_accepted_sequence, Sequence(1));
        assert!(server.join().unwrap().is_ok());
    }

    #[test]
    fn uses_independent_process_sequence_namespaces_for_hello_and_ack() {
        let (listener, address) = listener();
        let server = server(listener, process("session-b", 40), 120, 0x0b);
        let mut client_process = process("session-a", 10);
        let result = connect_and_handshake(
            address,
            TIMEOUT,
            TIMEOUT,
            TIMEOUT,
            ClusterId::new("cluster"),
            NodeId::new("node-a"),
            NodeId::new("node-b"),
            120,
            &mut client_process,
            Term(1),
            &CborSerializer,
            &authenticator(0x0b),
        )
        .unwrap();
        assert_eq!(result.peer_last_accepted_sequence, Sequence(40));
        assert_eq!(client_process.next_sequence(), Ok(Sequence(11)));
        let server_result = server.join().unwrap().unwrap();
        assert_eq!(server_result.peer_last_accepted_sequence, Sequence(10));
    }

    #[test]
    fn rejects_wrong_peer_identity_over_tcp() {
        let (listener, address) = listener();
        let server = server(listener, process("session-b", 1), 120, 0x0b);
        let mut client = TcpConnection::connect(address, TIMEOUT, TIMEOUT, TIMEOUT).unwrap();
        let mut hello =
            ProcessSession::from_session_id(crate::protocol::SessionId::new("session-a"));
        let mut handshake = OutboundHandshake::new(
            ClusterId::new("cluster"),
            NodeId::new("node-a"),
            NodeId::new("node-b"),
            120,
        );
        let mut message = handshake.build_hello(&mut hello, Term(1)).unwrap();
        message.common.sender_node_id = NodeId::new("wrong-node");
        client
            .send_message(message, &CborSerializer, &authenticator(0x0b))
            .unwrap();
        assert!(matches!(
            server.join().unwrap(),
            Err(HandshakeError::Session(SessionError::SenderMismatch))
        ));
    }

    #[test]
    fn rejects_wrong_psk_over_tcp() {
        let (listener, address) = listener();
        let server = server(listener, process("session-b", 1), 120, 0x0b);
        let mut client_process = process("session-a", 1);
        let client_result = connect_and_handshake(
            address,
            TIMEOUT,
            TIMEOUT,
            TIMEOUT,
            ClusterId::new("cluster"),
            NodeId::new("node-a"),
            NodeId::new("node-b"),
            120,
            &mut client_process,
            Term(1),
            &CborSerializer,
            &authenticator(0x0c),
        );
        assert!(matches!(
            client_result,
            Err(HandshakeError::Tcp(_)) | Err(HandshakeError::CleanEof)
        ));
        assert!(matches!(
            server.join().unwrap(),
            Err(HandshakeError::Tcp(crate::tcp::TcpError::Receive(
                crate::receive::ReceiveError::Authentication(AuthenticationError::InvalidMac)
            )))
        ));
    }

    #[test]
    fn rejects_non_hello_first_message_over_tcp() {
        let (listener, address) = listener();
        let server = server(listener, process("session-b", 1), 120, 0x0b);
        let mut client = TcpConnection::connect(address, TIMEOUT, TIMEOUT, TIMEOUT).unwrap();
        client
            .send_message(heartbeat(), &CborSerializer, &authenticator(0x0b))
            .unwrap();
        assert!(matches!(
            server.join().unwrap(),
            Err(HandshakeError::Session(SessionError::ExpectedHello))
        ));
        assert!(matches!(
            client.receive_message(&CborSerializer, &authenticator(0x0b)),
            Ok(ReceiveMessageResult::Eof)
        ));
    }
}
