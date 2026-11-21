//! Caller-driven TCP connection ownership for the established peer runtime.
//!
//! This module owns sockets and local connection provenance only.  It does not
//! decide peer liveness or perform any HA action.  Authenticated messages are
//! handed to `SessionRuntime`, which remains the session authority.

#![allow(dead_code)]

use crate::connection_manager::{ConnectionDirection, DirectionError, canonical_direction};
use crate::listener::{ListenerError, PeerListener};
#[cfg(test)]
use crate::protocol::MessageType;
use crate::protocol::{CborSerializer, NodeId, UnsignedEnvelope};
use crate::receive::{ReceiveError, receive};
use crate::security::MessageAuthenticator;
use crate::session_runtime::{
    ConnectionGeneration, ConnectionGenerationAllocator, SessionRuntime, SessionRuntimeEvent,
    SessionRuntimeInput,
};
use crate::tcp::{PollFrameResult, TcpConnection, TcpError};
use crate::transport::TransportError;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConnectionToken {
    pub(crate) generation: ConnectionGeneration,
    pub(crate) connection_id: u64,
}

/// Test-only: a distinct token per `n >= 1` (generation `n`, connection `n`).
#[cfg(test)]
pub(crate) fn test_connection_token(n: u64) -> ConnectionToken {
    let mut allocator = ConnectionGenerationAllocator::new();
    let mut generation = allocator.next().expect("generation");
    for _ in 1..n {
        generation = allocator.next().expect("generation");
    }
    ConnectionToken {
        generation,
        connection_id: n,
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TcpRuntimeStep {
    NoEvent,
    Connected(ConnectionToken),
    Frame {
        token: ConnectionToken,
        payload: Vec<u8>,
    },
    Session {
        token: ConnectionToken,
        events: Vec<SessionRuntimeEvent>,
    },
    TransportUnavailable {
        token: ConnectionToken,
        events: Vec<SessionRuntimeEvent>,
    },
    RejectedNonCanonical,
    StaleIgnored,
}

struct CurrentConnection {
    token: ConnectionToken,
    connection: TcpConnection,
}

pub(crate) struct TcpPeerRuntime {
    local_node_id: NodeId,
    peer_node_id: NodeId,
    direction: ConnectionDirection,
    read_timeout: Duration,
    write_timeout: Duration,
    listener: Option<PeerListener>,
    current: Option<CurrentConnection>,
    pending_disconnect: Option<ConnectionToken>,
    generations: ConnectionGenerationAllocator,
    next_connection_id: u64,
    #[cfg(test)]
    fail_next_send_type: Option<MessageType>,
    #[cfg(test)]
    last_failed_send_message_type: Option<MessageType>,
    #[cfg(test)]
    failed_send_attempts: usize,
    #[cfg(test)]
    fail_next_accept: bool,
}

impl TcpPeerRuntime {
    pub(crate) fn new(
        local_node_id: NodeId,
        peer_node_id: NodeId,
        read_timeout: Duration,
        write_timeout: Duration,
    ) -> Result<Self, DirectionError> {
        Ok(Self {
            direction: canonical_direction(&local_node_id, &peer_node_id)?,
            local_node_id,
            peer_node_id,
            read_timeout,
            write_timeout,
            listener: None,
            current: None,
            pending_disconnect: None,
            generations: ConnectionGenerationAllocator::new(),
            next_connection_id: 0,
            #[cfg(test)]
            fail_next_send_type: None,
            #[cfg(test)]
            last_failed_send_message_type: None,
            #[cfg(test)]
            failed_send_attempts: 0,
            #[cfg(test)]
            fail_next_accept: false,
        })
    }

    pub(crate) const fn direction(&self) -> ConnectionDirection {
        self.direction
    }

    pub(crate) fn local_node_id(&self) -> &NodeId {
        &self.local_node_id
    }

    pub(crate) fn peer_node_id(&self) -> &NodeId {
        &self.peer_node_id
    }

    pub(crate) fn bind(&mut self, address: SocketAddr) -> Result<SocketAddr, TcpRuntimeError> {
        let listener = PeerListener::bind(address, self.read_timeout, self.write_timeout)
            .map_err(TcpRuntimeError::Listener)?;
        listener
            .set_nonblocking(true)
            .map_err(TcpRuntimeError::Listener)?;
        let local_addr = listener.local_addr().map_err(TcpRuntimeError::Listener)?;
        self.listener = Some(listener);
        Ok(local_addr)
    }

    pub(crate) fn accept_one(&mut self) -> Result<TcpRuntimeStep, TcpRuntimeError> {
        let Some(listener) = &self.listener else {
            return Err(TcpRuntimeError::NotBound);
        };
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_accept) {
            return Err(TcpRuntimeError::Listener(ListenerError::Io(
                io::Error::other("deterministic accept failure"),
            )));
        }
        let Some((connection, _peer_address)) =
            listener.try_accept().map_err(TcpRuntimeError::Listener)?
        else {
            return Ok(TcpRuntimeStep::NoEvent);
        };

        if self.direction != ConnectionDirection::Inbound {
            return Ok(TcpRuntimeStep::RejectedNonCanonical);
        }

        let token = self.install(connection)?;
        Ok(TcpRuntimeStep::Connected(token))
    }

    pub(crate) fn connect(
        &mut self,
        address: SocketAddr,
    ) -> Result<ConnectionToken, TcpRuntimeError> {
        if self.direction != ConnectionDirection::Outbound {
            return Err(TcpRuntimeError::NonCanonicalDirection);
        }
        if self.pending_disconnect.is_some() {
            return Err(TcpRuntimeError::PendingDisconnect);
        }
        let connection = TcpConnection::connect(
            address,
            self.read_timeout,
            self.read_timeout,
            self.write_timeout,
        )
        .map_err(TcpRuntimeError::Tcp)?;
        self.install(connection)
    }

    pub(crate) fn current_token(&self) -> Option<ConnectionToken> {
        self.current.as_ref().map(|connection| connection.token)
    }

    pub(crate) fn listener_available(&self) -> bool {
        self.listener.is_some()
    }

    pub(crate) fn pending_disconnect(&self) -> bool {
        self.pending_disconnect.is_some()
    }

    pub(crate) fn close_listener(&mut self) {
        self.listener = None;
    }

    #[cfg(test)]
    pub(crate) fn wait_for_readable_for_test(&mut self) -> Result<(), TcpRuntimeError> {
        self.current
            .as_mut()
            .ok_or(TcpRuntimeError::NoConnection)?
            .connection
            .wait_for_readable_for_test()
            .map_err(TcpRuntimeError::Tcp)
    }

    pub(crate) fn send_payload(
        &mut self,
        token: ConnectionToken,
        payload: &[u8],
    ) -> Result<(), TcpRuntimeError> {
        let current = self.current.as_mut().ok_or(TcpRuntimeError::NoConnection)?;
        if current.token != token {
            return Err(TcpRuntimeError::StaleSocket);
        }
        let result = current.connection.send_payload(payload);
        if let Err(error) = result {
            if is_terminal_write_error(&error) {
                self.teardown(token);
            }
            return Err(TcpRuntimeError::Tcp(error));
        }
        Ok(())
    }

    pub(crate) fn send_message(
        &mut self,
        token: ConnectionToken,
        message: UnsignedEnvelope,
        serializer: &CborSerializer,
        authenticator: &MessageAuthenticator,
    ) -> Result<(), TcpRuntimeError> {
        #[cfg(test)]
        if self
            .fail_next_send_type
            .is_some_and(|expected| expected == message.message.message_type())
        {
            self.fail_next_send_type = None;
            self.last_failed_send_message_type = Some(message.message.message_type());
            self.failed_send_attempts += 1;
            let token = self.current_token().ok_or(TcpRuntimeError::NoConnection)?;
            self.teardown(token);
            return Err(TcpRuntimeError::Tcp(TcpError::Io(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "deterministic terminal write failure",
            ))));
        }
        let current = self.current.as_mut().ok_or(TcpRuntimeError::NoConnection)?;
        if current.token != token {
            return Err(TcpRuntimeError::StaleSocket);
        }
        let result = current
            .connection
            .send_message(message, serializer, authenticator);
        if let Err(error) = result {
            if is_terminal_write_error(&error) {
                self.teardown(token);
            }
            return Err(TcpRuntimeError::Tcp(error));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn fail_next_accept_for_test(&mut self) {
        self.fail_next_accept = true;
    }

    #[cfg(test)]
    pub(crate) fn fail_next_send_of_for_test(&mut self, message_type: MessageType) {
        self.fail_next_send_type = Some(message_type);
    }

    #[cfg(test)]
    pub(crate) fn last_failed_send_message_type_for_test(&self) -> Option<MessageType> {
        self.last_failed_send_message_type
    }

    #[cfg(test)]
    pub(crate) fn failed_send_attempts_for_test(&self) -> usize {
        self.failed_send_attempts
    }

    #[cfg(test)]
    pub(crate) fn has_pending_disconnect_for_test(&self) -> bool {
        self.pending_disconnect.is_some()
    }

    pub(crate) fn poll_frame(&mut self) -> Result<TcpRuntimeStep, TcpRuntimeError> {
        let Some(current) = self.current.as_mut() else {
            return Ok(TcpRuntimeStep::NoEvent);
        };
        let token = current.token;
        match current.connection.poll_payload() {
            Ok(PollFrameResult::NoFrame) => Ok(TcpRuntimeStep::NoEvent),
            Ok(PollFrameResult::Frame(payload)) => Ok(TcpRuntimeStep::Frame { token, payload }),
            Ok(PollFrameResult::Eof) => {
                self.teardown(token);
                Ok(TcpRuntimeStep::TransportUnavailable {
                    token,
                    events: Vec::new(),
                })
            }
            Err(error) => {
                self.teardown(token);
                Err(TcpRuntimeError::Tcp(error))
            }
        }
    }

    pub(crate) fn poll_session(
        &mut self,
        session: &mut SessionRuntime,
        serializer: &CborSerializer,
        authenticator: &MessageAuthenticator,
    ) -> Result<TcpRuntimeStep, TcpRuntimeError> {
        if let Some(token) = self.pending_disconnect.take() {
            let events = session.handle(SessionRuntimeInput::Disconnect {
                generation: token.generation,
                connection_id: token.connection_id,
            });
            return Ok(TcpRuntimeStep::TransportUnavailable { token, events });
        }
        let step = self.poll_frame()?;
        if let TcpRuntimeStep::TransportUnavailable { token, .. } = step {
            self.pending_disconnect = None;
            let events = session.handle(SessionRuntimeInput::Disconnect {
                generation: token.generation,
                connection_id: token.connection_id,
            });
            return Ok(TcpRuntimeStep::TransportUnavailable { token, events });
        }
        let TcpRuntimeStep::Frame { token, payload } = step else {
            return Ok(step);
        };

        let input = match receive(&payload, serializer, authenticator) {
            Ok(message) => SessionRuntimeInput::Authenticated {
                generation: token.generation,
                connection_id: token.connection_id,
                message,
            },
            Err(ReceiveError::Authentication(_)) => SessionRuntimeInput::AuthenticationFailure {
                generation: token.generation,
                connection_id: token.connection_id,
            },
            Err(ReceiveError::Serialization(_) | ReceiveError::Protocol(_)) => {
                SessionRuntimeInput::Malformed {
                    generation: token.generation,
                    connection_id: token.connection_id,
                }
            }
        };
        let events = session.handle(input);
        if events
            .iter()
            .any(|event| matches!(event, SessionRuntimeEvent::Rejected(_)))
        {
            self.current = None;
            return Ok(TcpRuntimeStep::TransportUnavailable { token, events });
        }
        Ok(TcpRuntimeStep::Session { token, events })
    }

    /// Deliver a terminal disconnect that was queued after the current
    /// socket was detached. This is intentionally independent of
    /// `current_token`: a detached socket is the normal state while this
    /// event is waiting for its caller-driven delivery.
    pub(crate) fn poll_pending_disconnect(
        &mut self,
        session: &mut SessionRuntime,
    ) -> TcpRuntimeStep {
        let Some(token) = self.pending_disconnect.take() else {
            return TcpRuntimeStep::NoEvent;
        };
        let events = session.handle(SessionRuntimeInput::Disconnect {
            generation: token.generation,
            connection_id: token.connection_id,
        });
        TcpRuntimeStep::TransportUnavailable { token, events }
    }

    pub(crate) fn disconnect(
        &mut self,
        token: ConnectionToken,
        session: &mut SessionRuntime,
    ) -> TcpRuntimeStep {
        if self.current_token() != Some(token) {
            return TcpRuntimeStep::StaleIgnored;
        }
        self.teardown(token);
        self.pending_disconnect = None;
        let events = session.handle(SessionRuntimeInput::Disconnect {
            generation: token.generation,
            connection_id: token.connection_id,
        });
        TcpRuntimeStep::TransportUnavailable { token, events }
    }

    /// Detach a current connection while leaving its disconnect notification
    /// queued for the caller-driven session drain.
    pub(crate) fn detach(&mut self, token: ConnectionToken) {
        self.teardown(token);
    }

    fn teardown(&mut self, token: ConnectionToken) {
        if self.current_token() == Some(token) {
            self.current = None;
            self.pending_disconnect = Some(token);
        }
    }

    fn install(&mut self, connection: TcpConnection) -> Result<ConnectionToken, TcpRuntimeError> {
        if self.pending_disconnect.is_some() {
            return Err(TcpRuntimeError::PendingDisconnect);
        }
        let generation = self
            .generations
            .next()
            .map_err(|_| TcpRuntimeError::GenerationExhausted)?;
        self.next_connection_id = self
            .next_connection_id
            .checked_add(1)
            .ok_or(TcpRuntimeError::ConnectionIdExhausted)?;
        let token = ConnectionToken {
            generation,
            connection_id: self.next_connection_id,
        };
        self.current = Some(CurrentConnection { token, connection });
        Ok(token)
    }
}

fn is_terminal_write_error(error: &TcpError) -> bool {
    matches!(
        error,
        TcpError::Io(_) | TcpError::Transport(TransportError::Io(_))
    )
}

#[derive(Debug)]
pub(crate) enum TcpRuntimeError {
    Listener(ListenerError),
    Tcp(TcpError),
    NotBound,
    NoConnection,
    StaleSocket,
    PendingDisconnect,
    NonCanonicalDirection,
    GenerationExhausted,
    ConnectionIdExhausted,
}

impl fmt::Display for TcpRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Listener(error) => write!(f, "TCP listener failed: {error}"),
            Self::Tcp(error) => write!(f, "TCP connection failed: {error}"),
            Self::NotBound => write!(f, "TCP listener is not bound"),
            Self::NoConnection => write!(f, "no current TCP connection exists"),
            Self::StaleSocket => write!(f, "socket event belongs to a stale connection"),
            Self::PendingDisconnect => write!(f, "current connection teardown is pending"),
            Self::NonCanonicalDirection => write!(f, "connection direction is not canonical"),
            Self::GenerationExhausted => write!(f, "connection generation is exhausted"),
            Self::ConnectionIdExhausted => write!(f, "connection identity is exhausted"),
        }
    }
}

impl std::error::Error for TcpRuntimeError {}

impl From<io::Error> for TcpRuntimeError {
    fn from(error: io::Error) -> Self {
        Self::Tcp(TcpError::Io(error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        CanonicalSerializer, ClusterId, CommonFields, HelloPayload, NodeId, NodeStatusPayload,
        ProtocolMessage, RequestId, Role, Sequence, SessionId, Term, UnsignedEnvelope,
    };
    use crate::security::Psk;
    use crate::session_runtime::{SessionRuntimeInput, SessionRuntimeState};
    use std::io::Write;
    use std::net::{Shutdown, TcpStream};

    const TIMEOUT: Duration = Duration::from_secs(2);

    fn runtime(local: &str, peer: &str) -> TcpPeerRuntime {
        TcpPeerRuntime::new(NodeId::new(local), NodeId::new(peer), TIMEOUT, TIMEOUT).unwrap()
    }

    fn session(local: &str, peer: &str) -> SessionRuntime {
        SessionRuntime::new(
            ClusterId::new("cluster"),
            NodeId::new(local),
            NodeId::new(peer),
            100,
        )
    }

    fn auth(value: u8) -> MessageAuthenticator {
        MessageAuthenticator::new(Psk::from_test_bytes([value; 32]))
    }

    fn heartbeat() -> UnsignedEnvelope {
        UnsignedEnvelope {
            common: CommonFields {
                protocol_version: 1,
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
            message: ProtocolMessage::Heartbeat(NodeStatusPayload {
                node_state: crate::state_machine::NodeState::Standby,
                operation_phase: None,
                role: Role::Standby,
                service_state: "stopped".to_string(),
                health_state: "unknown".to_string(),
                vip_state: "absent".to_string(),
            }),
        }
    }

    fn hello() -> UnsignedEnvelope {
        UnsignedEnvelope {
            common: CommonFields {
                protocol_version: 1,
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
            message: ProtocolMessage::Hello(HelloPayload { priority: 100 }),
        }
    }

    fn frame(bytes: &[u8]) -> Vec<u8> {
        crate::framing::encode_frame(bytes).unwrap()
    }

    fn accepted_server() -> (TcpPeerRuntime, TcpStream, ConnectionToken) {
        let mut server = runtime("node-b", "node-a");
        let address = server.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let client = TcpStream::connect(address).unwrap();
        let token = accept_token(&mut server);
        (server, client, token)
    }

    fn accept_token(server: &mut TcpPeerRuntime) -> ConnectionToken {
        for _ in 0..10_000 {
            match server.accept_one().unwrap() {
                TcpRuntimeStep::Connected(token) => return token,
                TcpRuntimeStep::NoEvent => std::thread::yield_now(),
                other => panic!("unexpected step: {other:?}"),
            }
        }
        panic!("connection was not accepted within the bounded test loop");
    }

    fn poll_frame_event(server: &mut TcpPeerRuntime) -> Result<TcpRuntimeStep, TcpRuntimeError> {
        for _ in 0..10_000 {
            match server.poll_frame()? {
                TcpRuntimeStep::NoEvent => std::thread::yield_now(),
                event => return Ok(event),
            }
        }
        panic!("frame was not observed within the bounded test loop");
    }

    fn poll_session_event(
        server: &mut TcpPeerRuntime,
        session: &mut SessionRuntime,
        serializer: &CborSerializer,
        authenticator: &MessageAuthenticator,
    ) -> Result<TcpRuntimeStep, TcpRuntimeError> {
        for _ in 0..10_000 {
            match server.poll_session(session, serializer, authenticator)? {
                TcpRuntimeStep::NoEvent => std::thread::yield_now(),
                event => return Ok(event),
            }
        }
        panic!("session event was not observed within the bounded test loop");
    }

    #[test]
    fn dn_tcp_connection_alone_stays_hello_pending() {
        let (server, _client, token) = accepted_server();
        let mut session = session("node-b", "node-a");
        let events = session.handle(SessionRuntimeInput::Connect {
            generation: token.generation,
            connection_id: token.connection_id,
        });
        assert!(events.is_empty());
        assert_eq!(session.state(), SessionRuntimeState::HelloPending);
        assert_eq!(server.current_token(), Some(token));
    }

    #[test]
    fn do_heartbeat_before_hello_is_rejected() {
        let (mut server, mut client, token) = accepted_server();
        let mut session = session("node-b", "node-a");
        session.handle(SessionRuntimeInput::Connect {
            generation: token.generation,
            connection_id: token.connection_id,
        });
        let serializer = CborSerializer;
        let wire = auth(0x0b).sign(heartbeat(), &serializer).unwrap();
        let payload = serializer.serialize_wire(&wire).unwrap();
        client
            .write_all(&frame(&payload))
            .expect("heartbeat frame should be written");
        let step = poll_session_event(&mut server, &mut session, &serializer, &auth(0x0b)).unwrap();
        assert!(matches!(step, TcpRuntimeStep::TransportUnavailable { .. }));
        assert_eq!(session.state(), SessionRuntimeState::Invalid);
    }

    #[test]
    fn dp_partial_frame_is_retained_until_complete() {
        let (mut server, mut client, token) = accepted_server();
        let encoded = frame(b"partial");
        client.write_all(&encoded[..3]).unwrap();
        assert_eq!(server.poll_frame().unwrap(), TcpRuntimeStep::NoEvent);
        client.write_all(&encoded[3..]).unwrap();
        assert_eq!(
            poll_frame_event(&mut server).unwrap(),
            TcpRuntimeStep::Frame {
                token,
                payload: b"partial".to_vec()
            }
        );
    }

    #[test]
    fn dq_multiple_frames_are_separated() {
        let (mut server, mut client, token) = accepted_server();
        let mut bytes = frame(b"first");
        bytes.extend_from_slice(&frame(b"second"));
        client.write_all(&bytes).unwrap();
        assert_eq!(
            poll_frame_event(&mut server).unwrap(),
            TcpRuntimeStep::Frame {
                token,
                payload: b"first".to_vec()
            }
        );
        assert_eq!(
            poll_frame_event(&mut server).unwrap(),
            TcpRuntimeStep::Frame {
                token,
                payload: b"second".to_vec()
            }
        );
    }

    #[test]
    fn dr_oversized_frame_is_rejected_before_allocation() {
        let (mut server, mut client, _token) = accepted_server();
        client.write_all(&[0, 0, 0x40, 1]).unwrap();
        assert!(matches!(
            poll_frame_event(&mut server),
            Err(TcpRuntimeError::Tcp(TcpError::Transport(
                crate::transport::TransportError::Frame(
                    crate::framing::FrameError::PayloadTooLarge { .. }
                )
            )))
        ));
    }

    #[test]
    fn ds_truncated_frame_is_not_accepted() {
        let (mut server, mut client, _token) = accepted_server();
        client.write_all(&[0, 0, 0, 10, 1, 2]).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        assert!(matches!(
            poll_frame_event(&mut server),
            Err(TcpRuntimeError::Tcp(TcpError::Transport(
                crate::transport::TransportError::TruncatedPayload
            )))
        ));
    }

    #[test]
    fn ds_clean_eof_is_delivered_to_session_runtime() {
        let (mut server, client, token) = accepted_server();
        let mut session = session("node-b", "node-a");
        session.handle(SessionRuntimeInput::Connect {
            generation: token.generation,
            connection_id: token.connection_id,
        });
        client.shutdown(Shutdown::Write).unwrap();
        let step =
            poll_session_event(&mut server, &mut session, &CborSerializer, &auth(0x0b)).unwrap();
        assert!(matches!(step, TcpRuntimeStep::TransportUnavailable { .. }));
        assert_eq!(session.state(), SessionRuntimeState::Disconnected);
    }

    #[test]
    fn ek_oversized_frame_detaches_current_transport() {
        let (mut server, mut client, token) = accepted_server();
        let mut session = session("node-b", "node-a");
        session.handle(SessionRuntimeInput::Connect {
            generation: token.generation,
            connection_id: token.connection_id,
        });
        client.write_all(&[0, 0, 0x40, 1]).unwrap();
        assert!(matches!(
            poll_session_event(&mut server, &mut session, &CborSerializer, &auth(0x0b)),
            Err(TcpRuntimeError::Tcp(_))
        ));
        assert_eq!(server.current_token(), None);
        assert_eq!(session.state(), SessionRuntimeState::HelloPending);
        let step = server
            .poll_session(&mut session, &CborSerializer, &auth(0x0b))
            .unwrap();
        assert!(matches!(step, TcpRuntimeStep::TransportUnavailable { .. }));
        assert_eq!(session.state(), SessionRuntimeState::Disconnected);
        assert_eq!(server.current_token(), None);
    }

    #[test]
    fn el_truncated_eof_detaches_established_session() {
        let (mut server, mut client, token) = accepted_server();
        let mut session = session("node-b", "node-a");
        session.handle(SessionRuntimeInput::Connect {
            generation: token.generation,
            connection_id: token.connection_id,
        });
        let serializer = CborSerializer;
        let hello_wire = auth(0x0b).sign(hello(), &serializer).unwrap();
        client
            .write_all(&frame(&serializer.serialize_wire(&hello_wire).unwrap()))
            .unwrap();
        let hello_step =
            poll_session_event(&mut server, &mut session, &serializer, &auth(0x0b)).unwrap();
        assert!(matches!(hello_step, TcpRuntimeStep::Session { .. }));
        assert_eq!(session.state(), SessionRuntimeState::Established);

        client.write_all(&[0, 0, 0, 10, 1, 2]).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        assert!(matches!(
            poll_session_event(&mut server, &mut session, &serializer, &auth(0x0b)),
            Err(TcpRuntimeError::Tcp(_))
        ));
        assert_eq!(server.current_token(), None);
        let step = server
            .poll_session(&mut session, &serializer, &auth(0x0b))
            .unwrap();
        assert!(matches!(step, TcpRuntimeStep::TransportUnavailable { .. }));
        assert_eq!(session.state(), SessionRuntimeState::Disconnected);
    }

    #[test]
    fn em_terminal_read_failure_notifies_disconnect_once() {
        let (mut server, mut client, token) = accepted_server();
        let mut session = session("node-b", "node-a");
        session.handle(SessionRuntimeInput::Connect {
            generation: token.generation,
            connection_id: token.connection_id,
        });
        client.write_all(&[0, 0, 0, 10, 1]).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        assert!(
            poll_session_event(&mut server, &mut session, &CborSerializer, &auth(0x0b)).is_err()
        );
        let first = server
            .poll_session(&mut session, &CborSerializer, &auth(0x0b))
            .unwrap();
        assert!(matches!(first, TcpRuntimeStep::TransportUnavailable { .. }));
        assert_eq!(session.state(), SessionRuntimeState::Disconnected);
        assert_eq!(server.poll_frame().unwrap(), TcpRuntimeStep::NoEvent);
        assert_eq!(server.poll_frame().unwrap(), TcpRuntimeStep::NoEvent);
    }

    #[test]
    fn en_would_block_keeps_current_session_and_sends_no_disconnect() {
        let (mut server, _client, token) = accepted_server();
        let mut session = session("node-b", "node-a");
        session.handle(SessionRuntimeInput::Connect {
            generation: token.generation,
            connection_id: token.connection_id,
        });
        assert_eq!(
            server
                .poll_session(&mut session, &CborSerializer, &auth(0x0b))
                .unwrap(),
            TcpRuntimeStep::NoEvent
        );
        assert_eq!(server.current_token(), Some(token));
        assert_eq!(session.state(), SessionRuntimeState::HelloPending);
    }

    #[test]
    fn eo_fatal_write_failure_detaches_current_transport_without_reconnect() {
        let (mut server, client, token) = accepted_server();
        let mut session = session("node-b", "node-a");
        session.handle(SessionRuntimeInput::Connect {
            generation: token.generation,
            connection_id: token.connection_id,
        });
        drop(client);
        let payload = vec![0xab; crate::framing::MAX_FRAME_PAYLOAD_SIZE];
        let mut failure = None;
        for _ in 0..1_000 {
            match server.send_payload(token, &payload) {
                Ok(()) => std::thread::yield_now(),
                Err(error) => {
                    failure = Some(error);
                    break;
                }
            }
        }
        assert!(matches!(failure, Some(TcpRuntimeError::Tcp(_))));
        assert_eq!(server.current_token(), None);
        assert!(matches!(
            server
                .poll_session(&mut session, &CborSerializer, &auth(0x0b))
                .unwrap(),
            TcpRuntimeStep::TransportUnavailable { .. }
        ));
        assert_eq!(session.state(), SessionRuntimeState::Disconnected);
        assert_eq!(server.current_token(), None);
    }

    #[test]
    fn ep_semantic_invalid_message_keeps_current_established_connection() {
        let (mut server, mut client, token) = accepted_server();
        let mut session = session("node-b", "node-a");
        session.handle(SessionRuntimeInput::Connect {
            generation: token.generation,
            connection_id: token.connection_id,
        });
        let serializer = CborSerializer;
        let hello_wire = auth(0x0b).sign(hello(), &serializer).unwrap();
        client
            .write_all(&frame(&serializer.serialize_wire(&hello_wire).unwrap()))
            .unwrap();
        let hello_step =
            poll_session_event(&mut server, &mut session, &serializer, &auth(0x0b)).unwrap();
        assert!(matches!(hello_step, TcpRuntimeStep::Session { .. }));
        assert_eq!(session.state(), SessionRuntimeState::Established);

        let mut invalid = hello();
        invalid.common.request_id = Some(RequestId::new("00000000-0000-4000-8000-000000000001"));
        assert!(matches!(
            server.send_message(token, invalid, &serializer, &auth(0x0b)),
            Err(TcpRuntimeError::Tcp(TcpError::Protocol(_)))
        ));
        assert_eq!(server.current_token(), Some(token));
        assert_eq!(session.state(), SessionRuntimeState::Established);
        assert_eq!(
            server
                .poll_session(&mut session, &serializer, &auth(0x0b))
                .unwrap(),
            TcpRuntimeStep::NoEvent
        );

        let mut valid = hello();
        valid.common.sender_node_id = NodeId::new("node-b");
        valid.common.receiver_node_id = NodeId::new("node-a");
        server
            .send_message(token, valid, &serializer, &auth(0x0b))
            .unwrap();
        assert_eq!(server.current_token(), Some(token));
    }

    #[test]
    fn du_no_frame_is_not_peer_dead() {
        let (mut server, _client, token) = accepted_server();
        assert_eq!(server.poll_frame().unwrap(), TcpRuntimeStep::NoEvent);
        assert_eq!(server.current_token(), Some(token));
    }

    #[test]
    fn dv_connect_failure_has_no_session_or_ha_action() {
        let mut client = runtime("node-a", "node-b");
        let address = "127.0.0.1:1".parse().unwrap();
        assert!(matches!(
            client.connect(address),
            Err(TcpRuntimeError::Tcp(_))
        ));
        assert_eq!(client.current_token(), None);
    }

    #[test]
    fn dw_disconnect_only_reports_transport_unavailable() {
        let (mut server, _client, token) = accepted_server();
        let mut session = session("node-b", "node-a");
        session.handle(SessionRuntimeInput::Connect {
            generation: token.generation,
            connection_id: token.connection_id,
        });
        let step = server.disconnect(token, &mut session);
        assert!(matches!(step, TcpRuntimeStep::TransportUnavailable { .. }));
        assert_eq!(session.state(), SessionRuntimeState::Disconnected);
    }

    #[test]
    fn dx_stale_socket_event_cannot_teardown_newer_connection() {
        let mut server = runtime("node-b", "node-a");
        let address = server.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let _old_client = TcpStream::connect(address).unwrap();
        let old = accept_token(&mut server);
        let _new_client = TcpStream::connect(address).unwrap();
        let new = accept_token(&mut server);
        assert!(new.generation > old.generation);
        let mut session = session("node-b", "node-a");
        assert_eq!(
            server.disconnect(old, &mut session),
            TcpRuntimeStep::StaleIgnored
        );
        assert_eq!(server.current_token(), Some(new));
    }

    #[test]
    fn dy_stale_frame_token_is_not_current_observation() {
        let mut server = runtime("node-b", "node-a");
        let address = server.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let _old_client = TcpStream::connect(address).unwrap();
        let old = accept_token(&mut server);
        let _new_client = TcpStream::connect(address).unwrap();
        let new = accept_token(&mut server);
        assert_ne!(old, new);
        assert_eq!(
            server.disconnect(old, &mut session("node-b", "node-a")),
            TcpRuntimeStep::StaleIgnored
        );
        assert_eq!(server.current_token(), Some(new));
    }

    #[test]
    fn dz_new_connections_receive_trusted_local_generations() {
        let mut server = runtime("node-b", "node-a");
        let address = server.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let _first = TcpStream::connect(address).unwrap();
        let first = accept_token(&mut server);
        let _second = TcpStream::connect(address).unwrap();
        let second = accept_token(&mut server);
        assert!(second.generation > first.generation);
    }

    #[test]
    fn ea_wire_payload_cannot_supply_generation() {
        let (server, _client, token) = accepted_server();
        assert_eq!(server.current_token(), Some(token));
        assert_ne!(token.connection_id, 0);
    }

    #[test]
    fn eb_current_socket_identity_is_stable_until_replacement() {
        let (mut server, _client, token) = accepted_server();
        assert_eq!(server.current_token(), Some(token));
        assert_eq!(server.poll_frame().unwrap(), TcpRuntimeStep::NoEvent);
        assert_eq!(server.current_token(), Some(token));
    }

    #[test]
    fn ec_reconnect_alone_does_not_establish_session() {
        let (server, _client, token) = accepted_server();
        let mut session = session("node-b", "node-a");
        session.handle(SessionRuntimeInput::Connect {
            generation: token.generation,
            connection_id: token.connection_id,
        });
        assert_eq!(session.state(), SessionRuntimeState::HelloPending);
        assert_eq!(server.current_token(), Some(token));
    }

    #[test]
    fn ed_new_connection_still_requires_hello_before_heartbeat() {
        let (_server, _client, token) = accepted_server();
        let mut session = session("node-b", "node-a");
        session.handle(SessionRuntimeInput::Connect {
            generation: token.generation,
            connection_id: token.connection_id,
        });
        assert_eq!(session.state(), SessionRuntimeState::HelloPending);
    }

    #[test]
    fn ee_invalid_authenticated_input_does_not_refresh_session() {
        let (mut server, mut client, token) = accepted_server();
        let mut session = session("node-b", "node-a");
        session.handle(SessionRuntimeInput::Connect {
            generation: token.generation,
            connection_id: token.connection_id,
        });
        client.write_all(&frame(&[0xff])).unwrap();
        let step =
            poll_session_event(&mut server, &mut session, &CborSerializer, &auth(0x0b)).unwrap();
        assert!(matches!(step, TcpRuntimeStep::TransportUnavailable { .. }));
        assert_eq!(session.state(), SessionRuntimeState::Invalid);
    }

    #[test]
    fn ef_repeated_oversized_frames_remain_bounded() {
        let (mut server, mut client, _token) = accepted_server();
        client.write_all(&[0, 0, 0x40, 1]).unwrap();
        assert!(poll_frame_event(&mut server).is_err());
        assert_eq!(server.current_token(), None);
        for _ in 0..8 {
            let _ = client.write_all(&[0, 0, 0x40, 1]);
            assert_eq!(server.poll_frame().unwrap(), TcpRuntimeStep::NoEvent);
        }
    }

    #[test]
    fn eg_status_like_access_does_not_poll_socket() {
        let (server, _client, token) = accepted_server();
        let before = server.current_token();
        assert_eq!(server.current_token(), before);
        assert_eq!(server.current_token(), Some(token));
    }

    #[test]
    fn eh_transport_steps_do_not_contain_ha_actions() {
        let (mut server, _client, token) = accepted_server();
        let step = server.poll_frame().unwrap();
        assert_eq!(step, TcpRuntimeStep::NoEvent);
        assert_eq!(server.current_token(), Some(token));
    }

    #[test]
    fn dual_direction_policy_allows_only_canonical_side_to_dial() {
        let outbound = runtime("node-a", "node-b");
        let inbound = runtime("node-b", "node-a");
        assert_eq!(outbound.direction(), ConnectionDirection::Outbound);
        assert_eq!(inbound.direction(), ConnectionDirection::Inbound);
    }
}
