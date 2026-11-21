use crate::framing::{DecodeResult, decode_frame};
use crate::protocol::{
    CanonicalSerializer, CborSerializer, ProtocolError, SerializationError, UnsignedEnvelope,
};
use crate::receive::{AuthenticatedMessage, ReceiveError, receive};
use crate::security::AuthenticationError;
use crate::transport::{ReadFrameResult, TransportError, read_frame, write_frame};
use std::fmt;
use std::io::{self, Read};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

#[cfg(all(test, unix))]
use std::os::fd::AsRawFd;

#[cfg(all(test, unix))]
const F_GETFL: i32 = 3;
#[cfg(all(test, target_os = "linux"))]
const O_NONBLOCK: i32 = 0x800;
#[cfg(all(test, target_os = "macos"))]
const O_NONBLOCK: i32 = 0x4;

#[cfg(all(test, unix))]
unsafe extern "C" {
    fn fcntl(fd: i32, command: i32, ...) -> i32;
}

#[cfg(all(test, unix))]
fn actual_nonblocking_for_test(stream: &TcpStream) -> io::Result<bool> {
    let flags = unsafe { fcntl(stream.as_raw_fd(), F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(flags & O_NONBLOCK != 0)
}

pub struct TcpConnection {
    /// `None` once the connection was closed on purpose. Closing must release
    /// the descriptor (a bare `shutdown` is not enough: after a peer FIN,
    /// macOS rejects `shutdown` with `ENOTCONN` and the socket stays in
    /// `CLOSE_WAIT`), so the stream is dropped rather than shut down.
    stream: Option<TcpStream>,
    frame_buffer: Vec<u8>,
}

impl TcpConnection {
    pub fn connect(
        address: SocketAddr,
        connect_timeout: Duration,
        read_timeout: Duration,
        write_timeout: Duration,
    ) -> Result<Self, TcpError> {
        let stream = TcpStream::connect_timeout(&address, connect_timeout).map_err(TcpError::Io)?;
        Self::from_stream(stream, read_timeout, write_timeout)
    }

    pub fn from_stream(
        stream: TcpStream,
        read_timeout: Duration,
        write_timeout: Duration,
    ) -> Result<Self, TcpError> {
        stream
            .set_read_timeout(Some(read_timeout))
            .map_err(TcpError::Io)?;
        stream
            .set_write_timeout(Some(write_timeout))
            .map_err(TcpError::Io)?;
        Ok(Self {
            stream: Some(stream),
            frame_buffer: Vec::new(),
        })
    }

    /// Pure liveness probe: did the peer close its side?
    ///
    /// Reads nothing and changes no protocol state (`MSG_PEEK`). `Ok(true)`
    /// means the peer's FIN was observed and the connection is dead;
    /// `Ok(false)` covers both "no data" and "data pending" (alive either
    /// way). Used by an idle Standby so a stopped Witness is detected without
    /// sending a request and without consuming a frame that belongs to the
    /// single outstanding request slot.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn peek_closed(&mut self) -> Result<bool, TcpError> {
        let stream = self.stream_mut()?;
        // The configured socket mode is blocking + read timeout (the same
        // invariant `poll_payload` relies on); restore it on every path so a
        // probe cannot make later blocking reads fail instantly.
        stream.set_nonblocking(true).map_err(TcpError::Io)?;
        let observation = (|| {
            let mut byte = [0u8; 1];
            match stream.peek(&mut byte) {
                Ok(0) => Ok(true),
                Ok(_) => Ok(false),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(false),
                Err(error) => Err(TcpError::Io(error)),
            }
        })();
        let restore = stream.set_nonblocking(false).map_err(TcpError::Io);
        restore?;
        observation
    }

    /// Release the socket now instead of waiting for the owning value to be
    /// dropped. A peer that has already sent FIN leaves this end in
    /// `CLOSE_WAIT` until the local descriptor is closed; a session owner that
    /// recognises the closed connection must call this so the descriptor
    /// (and the half-closed connection) is not retained for the rest of the
    /// process lifetime.
    ///
    /// Idempotent. The stream is dropped (which closes the descriptor and
    /// sends our FIN); every future use of the same value is then refused
    /// deterministically as `NotConnected`. A bare `shutdown(2)` is not
    /// enough: after a peer FIN, macOS rejects it with `ENOTCONN` and does
    /// not send our FIN, so the socket would stay in `CLOSE_WAIT`.
    pub(crate) fn close(&mut self) {
        // Dropping the stream closes the descriptor, which sends our FIN even
        // when the peer already closed its side.
        drop(self.stream.take());
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn is_closed(&self) -> bool {
        self.stream.is_none()
    }

    fn stream_mut(&mut self) -> Result<&mut TcpStream, TcpError> {
        self.stream
            .as_mut()
            .ok_or_else(|| TcpError::Io(io::Error::from(io::ErrorKind::NotConnected)))
    }

    pub fn send_payload(&mut self, payload: &[u8]) -> Result<(), TcpError> {
        write_frame(self.stream_mut()?, payload).map_err(TcpError::Transport)
    }

    pub fn receive_payload(&mut self) -> Result<ReadFrameResult, TcpError> {
        read_frame(self.stream_mut()?).map_err(TcpError::Transport)
    }

    #[cfg(all(test, unix))]
    pub(crate) fn wait_for_readable_for_test(&mut self) -> Result<(), TcpError> {
        const TEST_READABILITY_TIMEOUT: Duration = Duration::from_millis(250);

        let stream = self.stream_mut()?;
        let original_nonblocking = actual_nonblocking_for_test(stream).map_err(TcpError::Io)?;
        let original_read_timeout = stream.read_timeout().map_err(TcpError::Io)?;

        let observation = (|| {
            stream
                .set_read_timeout(Some(TEST_READABILITY_TIMEOUT))
                .map_err(TcpError::Io)?;
            stream.set_nonblocking(false).map_err(TcpError::Io)?;
            let mut byte = [0u8; 1];
            let length = stream.peek(&mut byte).map_err(|error| {
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) {
                    TcpError::Io(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "test readability wait timed out",
                    ))
                } else {
                    TcpError::Io(error)
                }
            })?;
            if length == 0 {
                return Err(TcpError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer closed before test readability event",
                )));
            }
            Ok(())
        })();

        let mode_restore = stream
            .set_nonblocking(original_nonblocking)
            .map_err(TcpError::Io);
        let timeout_restore = stream
            .set_read_timeout(original_read_timeout)
            .map_err(TcpError::Io);

        let restore_errors: Vec<String> = [mode_restore, timeout_restore]
            .into_iter()
            .filter_map(|result| result.err())
            .map(|error| format!("{error:?}"))
            .collect();
        if !restore_errors.is_empty() {
            let operation = match observation {
                Ok(()) => "none".to_string(),
                Err(error) => format!("{error:?}"),
            };
            return Err(TcpError::Io(io::Error::other(format!(
                "socket state restore failed: restore={restore_errors:?}, operation={operation}"
            ))));
        }

        observation
    }

    #[cfg(all(test, unix))]
    pub(crate) fn stream_for_test(&self) -> &TcpStream {
        self.stream.as_ref().expect("test access to an open stream")
    }

    #[cfg(all(test, unix))]
    pub(crate) fn stream_mut_for_test(&mut self) -> &mut TcpStream {
        self.stream.as_mut().expect("test access to an open stream")
    }

    #[cfg(all(test, unix))]
    pub(crate) fn socket_state_for_test(&self) -> Result<(bool, Option<Duration>), TcpError> {
        let stream = self
            .stream
            .as_ref()
            .ok_or_else(|| TcpError::Io(io::Error::from(io::ErrorKind::NotConnected)))?;
        stream
            .read_timeout()
            .and_then(|timeout| actual_nonblocking_for_test(stream).map(|mode| (mode, timeout)))
            .map_err(TcpError::Io)
    }

    pub(crate) fn poll_payload(&mut self) -> Result<PollFrameResult, TcpError> {
        let stream = self.stream_mut()?;
        stream.set_nonblocking(true).map_err(TcpError::Io)?;
        let result = self.poll_payload_nonblocking();
        // The configured socket mode is blocking + read timeout; a
        // nonblocking poll must not leak nonblocking mode into later
        // blocking reads (`receive_payload`/`read_frame`), or every
        // subsequent receive would fail instantly with `WouldBlock`.
        // Restore on every exit path, preserving the poll's own error.
        let restore = self
            .stream
            .as_ref()
            .ok_or_else(|| TcpError::Io(io::Error::from(io::ErrorKind::NotConnected)))
            .and_then(|stream| stream.set_nonblocking(false).map_err(TcpError::Io));
        match (result, restore) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    fn poll_payload_nonblocking(&mut self) -> Result<PollFrameResult, TcpError> {
        let mut chunk = [0u8; 4096];
        loop {
            if !self.frame_buffer.is_empty() {
                match decode_frame(&self.frame_buffer)
                    .map_err(|error| TcpError::Transport(TransportError::Frame(error)))?
                {
                    DecodeResult::Incomplete => {}
                    DecodeResult::Complete { payload, consumed } => {
                        let payload = payload.to_vec();
                        self.frame_buffer.drain(..consumed);
                        return Ok(PollFrameResult::Frame(payload));
                    }
                }
            }
            let read_result = match self.stream.as_mut() {
                Some(stream) => stream.read(&mut chunk),
                None => {
                    return Err(TcpError::Io(io::Error::from(io::ErrorKind::NotConnected)));
                }
            };
            match read_result {
                Ok(0) if self.frame_buffer.is_empty() => return Ok(PollFrameResult::Eof),
                Ok(0) => return Err(TcpError::Transport(TransportError::TruncatedPayload)),
                Ok(read) => {
                    self.frame_buffer.extend_from_slice(&chunk[..read]);
                    match decode_frame(&self.frame_buffer)
                        .map_err(|error| TcpError::Transport(TransportError::Frame(error)))?
                    {
                        DecodeResult::Incomplete => continue,
                        DecodeResult::Complete { payload, consumed } => {
                            let payload = payload.to_vec();
                            self.frame_buffer.drain(..consumed);
                            return Ok(PollFrameResult::Frame(payload));
                        }
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(PollFrameResult::NoFrame);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(TcpError::Io(error)),
            }
        }
    }

    pub fn send_message(
        &mut self,
        unsigned: UnsignedEnvelope,
        serializer: &CborSerializer,
        authenticator: &crate::security::MessageAuthenticator,
    ) -> Result<(), TcpError> {
        unsigned.validate().map_err(TcpError::Protocol)?;
        let wire = authenticator
            .sign(unsigned, serializer)
            .map_err(TcpError::Authentication)?;
        let payload = serializer
            .serialize_wire(&wire)
            .map_err(TcpError::Serialization)?;
        self.send_payload(&payload)
    }

    pub fn receive_message(
        &mut self,
        serializer: &CborSerializer,
        authenticator: &crate::security::MessageAuthenticator,
    ) -> Result<ReceiveMessageResult, TcpError> {
        match self.receive_payload()? {
            ReadFrameResult::Eof => Ok(ReceiveMessageResult::Eof),
            ReadFrameResult::Frame(payload) => receive(&payload, serializer, authenticator)
                .map(|message| ReceiveMessageResult::Message(Box::new(message)))
                .map_err(TcpError::Receive),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PollFrameResult {
    NoFrame,
    Eof,
    Frame(Vec<u8>),
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReceiveMessageResult {
    Eof,
    Message(Box<AuthenticatedMessage>),
}

#[derive(Debug)]
pub enum TcpError {
    Io(io::Error),
    Transport(TransportError),
    Authentication(AuthenticationError),
    Serialization(SerializationError),
    Protocol(ProtocolError),
    Receive(ReceiveError),
}

impl fmt::Display for TcpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "TCP I/O failed: {error}"),
            Self::Transport(error) => write!(f, "transport failed: {error}"),
            Self::Authentication(error) => write!(f, "authentication failed: {error}"),
            Self::Serialization(error) => write!(f, "serialization failed: {error}"),
            Self::Protocol(error) => write!(f, "protocol validation failed: {error}"),
            Self::Receive(error) => write!(f, "message receive failed: {error}"),
        }
    }
}

impl std::error::Error for TcpError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        ClusterId, CommonFields, HelloPayload, ProtocolMessage, Sequence, SessionId, Term,
    };
    use crate::security::Psk;
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener};
    use std::thread;

    const TIMEOUT: Duration = Duration::from_secs(2);

    fn authenticator(value: u8) -> crate::security::MessageAuthenticator {
        crate::security::MessageAuthenticator::new(Psk::from_test_bytes([value; 32]))
    }

    fn hello() -> UnsignedEnvelope {
        UnsignedEnvelope {
            common: CommonFields {
                protocol_version: 1,
                cluster_id: ClusterId::new("cluster"),
                sender_node_id: crate::protocol::NodeId::new("node-a"),
                receiver_node_id: crate::protocol::NodeId::new("node-b"),
                session_id: SessionId::new("session"),
                sequence: Sequence(1),
                term: Term(1),
                lease_id: None,
                request_id: None,
                operation_id: None,
            },
            message: ProtocolMessage::Hello(HelloPayload { priority: 100 }),
        }
    }

    fn connect_pair() -> (TcpConnection, TcpConnection) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let client = TcpConnection::connect(address, TIMEOUT, TIMEOUT, TIMEOUT).unwrap();
        let (stream, _) = listener.accept().unwrap();
        let server = TcpConnection::from_stream(stream, TIMEOUT, TIMEOUT).unwrap();
        (client, server)
    }

    fn connect_pair_with_server_mode(nonblocking: bool) -> (TcpConnection, TcpConnection) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let client = TcpConnection::connect(address, TIMEOUT, TIMEOUT, TIMEOUT).unwrap();
        let (stream, _) = listener.accept().unwrap();
        let actual = actual_nonblocking_for_test(&stream).unwrap();
        assert!(!actual);
        stream.set_nonblocking(nonblocking).unwrap();
        let server = TcpConnection::from_stream(stream, TIMEOUT, TIMEOUT).unwrap();
        (client, server)
    }

    #[test]
    fn sends_and_receives_signed_message_over_localhost_tcp() {
        let (mut client, mut server) = connect_pair();
        let serializer = CborSerializer;
        let sender = authenticator(0x0b);
        let expected = hello();
        client
            .send_message(expected.clone(), &serializer, &sender)
            .unwrap();
        let received = server
            .receive_message(&serializer, &authenticator(0x0b))
            .unwrap();
        let ReceiveMessageResult::Message(received) = received else {
            panic!("message should be received");
        };
        assert_eq!(received.unsigned(), &expected);
    }

    #[test]
    fn supports_bidirectional_messages_on_one_connection() {
        let (mut client, mut server) = connect_pair();
        let serializer = CborSerializer;
        let auth = authenticator(0x0b);
        client.send_message(hello(), &serializer, &auth).unwrap();
        assert!(matches!(
            server.receive_message(&serializer, &auth).unwrap(),
            ReceiveMessageResult::Message(_)
        ));

        let mut reply = hello();
        reply.common.sender_node_id = crate::protocol::NodeId::new("node-b");
        reply.common.receiver_node_id = crate::protocol::NodeId::new("node-a");
        reply.message = ProtocolMessage::HelloAck;
        server
            .send_message(reply.clone(), &serializer, &auth)
            .unwrap();
        let ReceiveMessageResult::Message(received) =
            client.receive_message(&serializer, &auth).unwrap()
        else {
            panic!("reply should be received");
        };
        assert_eq!(received.unsigned(), &reply);
    }

    #[test]
    fn supports_multiple_messages_on_one_connection() {
        let (mut client, mut server) = connect_pair();
        let serializer = CborSerializer;
        let auth = authenticator(0x0b);
        let first = hello();
        let mut second = hello();
        second.common.sequence = Sequence(2);
        client
            .send_message(first.clone(), &serializer, &auth)
            .unwrap();
        client
            .send_message(second.clone(), &serializer, &auth)
            .unwrap();
        for expected in [&first, &second] {
            let ReceiveMessageResult::Message(received) =
                server.receive_message(&serializer, &auth).unwrap()
            else {
                panic!("message should be received");
            };
            assert_eq!(received.unsigned(), expected);
        }
    }

    #[test]
    fn real_tcp_clean_eof_is_distinguished() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            drop(stream);
        });
        let mut client = TcpConnection::connect(address, TIMEOUT, TIMEOUT, TIMEOUT).unwrap();
        server.join().unwrap();
        assert_eq!(
            client
                .receive_message(&CborSerializer, &authenticator(0x0b))
                .unwrap(),
            ReceiveMessageResult::Eof
        );
    }

    /// v0.6 A-1: a peer FIN leaves the local socket in `CLOSE_WAIT` until this
    /// end closes it. `close` must release the descriptor immediately; the
    /// peer then observes our FIN instead of a half-closed connection that is
    /// retained for the rest of the process lifetime.
    #[test]
    fn close_after_peer_fin_releases_the_descriptor() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = TcpConnection::connect(address, TIMEOUT, TIMEOUT, TIMEOUT).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        server.set_read_timeout(Some(TIMEOUT)).unwrap();

        // The Witness goes away: its sending direction is closed.
        server.shutdown(Shutdown::Write).unwrap();
        assert_eq!(
            client.receive_payload().unwrap(),
            ReadFrameResult::Eof,
            "peer FIN is observed as EOF"
        );
        assert!(!client.is_closed(), "EOF alone does not close the socket");

        client.close();
        assert!(client.is_closed());

        // The peer can read again and sees our FIN (0 bytes). If the local
        // socket were still in CLOSE_WAIT this read would block until the
        // read timeout.
        let mut byte = [0u8; 1];
        assert_eq!(server.read(&mut byte).unwrap(), 0);
    }

    #[test]
    fn peek_reports_a_peer_fin_without_consuming_pending_data() {
        let (mut client, mut server) = connect_pair();

        // A live session with no data is not closed.
        assert!(!client.peek_closed().unwrap());

        // Pending data is alive, and the probe must not consume it.
        server.send_payload(b"frame").unwrap();
        assert!(!client.peek_closed().unwrap());
        assert_eq!(
            client.receive_payload().unwrap(),
            ReadFrameResult::Frame(b"frame".to_vec())
        );

        // The peer goes away: the probe sees the FIN without a request.
        server.close();
        let mut closed = false;
        for _ in 0..200 {
            if client.peek_closed().unwrap() {
                closed = true;
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(
            closed,
            "a peer FIN must be visible to a pure liveness probe"
        );
        assert!(
            !client.is_closed(),
            "the probe only reports; it does not close"
        );
    }

    #[test]
    fn closed_connection_refuses_further_io_instead_of_blocking() {
        let (mut client, _server) = connect_pair();
        client.send_payload(b"before-close").unwrap();
        client.close();
        assert!(matches!(
            client.send_payload(b"after-close"),
            Err(TcpError::Io(error)) if error.kind() == io::ErrorKind::NotConnected
        ));
        assert!(matches!(
            client.receive_payload(),
            Err(TcpError::Io(error)) if error.kind() == io::ErrorKind::NotConnected
        ));
        assert!(matches!(
            client.poll_payload(),
            Err(TcpError::Io(error)) if error.kind() == io::ErrorKind::NotConnected
        ));
        // Idempotent: a second close neither panics nor reports failure.
        client.close();
    }

    #[test]
    fn wait_for_readable_for_test_times_out_when_no_data_arrives() {
        let (_client, mut server) = connect_pair();
        let before = server.socket_state_for_test().unwrap();
        let started = std::time::Instant::now();

        assert!(matches!(
            server.wait_for_readable_for_test(),
            Err(TcpError::Io(error)) if error.kind() == io::ErrorKind::TimedOut
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(server.socket_state_for_test().unwrap(), before);
    }

    #[test]
    fn wait_for_readable_for_test_returns_when_data_is_available_without_consuming_it() {
        let (mut client, mut server) = connect_pair();
        let before = server.socket_state_for_test().unwrap();
        client.send_payload(b"readiness-test").unwrap();

        server.wait_for_readable_for_test().unwrap();
        assert_eq!(server.socket_state_for_test().unwrap(), before);
        assert_eq!(
            server.receive_payload().unwrap(),
            ReadFrameResult::Frame(b"readiness-test".to_vec())
        );
    }

    #[test]
    fn wait_for_readable_for_test_reports_eof() {
        let (client, mut server) = connect_pair();
        let before = server.socket_state_for_test().unwrap();
        drop(client);

        assert!(matches!(
            server.wait_for_readable_for_test(),
            Err(TcpError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof
        ));
        assert_eq!(server.socket_state_for_test().unwrap(), before);
    }

    #[test]
    fn already_nonblocking_stream_remains_nonblocking_after_readability_wait() {
        let (_client, mut server) = connect_pair_with_server_mode(true);
        server.stream_mut_for_test().set_read_timeout(None).unwrap();
        assert!(actual_nonblocking_for_test(server.stream_for_test()).unwrap());
        assert!(matches!(
            server.wait_for_readable_for_test(),
            Err(TcpError::Io(error)) if error.kind() == io::ErrorKind::TimedOut
        ));
        assert!(actual_nonblocking_for_test(server.stream_for_test()).unwrap());
    }

    #[test]
    fn blocking_stream_remains_blocking_after_readability_wait() {
        let (_client, mut server) = connect_pair_with_server_mode(false);
        assert!(!actual_nonblocking_for_test(server.stream_for_test()).unwrap());
        assert!(matches!(
            server.wait_for_readable_for_test(),
            Err(TcpError::Io(error)) if error.kind() == io::ErrorKind::TimedOut
        ));
        assert!(!actual_nonblocking_for_test(server.stream_for_test()).unwrap());
    }

    #[test]
    fn readability_wait_restores_custom_read_timeout() {
        let (_client, mut server) = connect_pair();
        let custom_timeout = Duration::from_millis(37);
        server
            .stream_mut_for_test()
            .set_read_timeout(Some(custom_timeout))
            .unwrap();
        let before = server.socket_state_for_test().unwrap();
        assert!(!actual_nonblocking_for_test(server.stream_for_test()).unwrap());
        assert!(matches!(
            server.wait_for_readable_for_test(),
            Err(TcpError::Io(error)) if error.kind() == io::ErrorKind::TimedOut
        ));
        assert_eq!(server.socket_state_for_test().unwrap(), before);
    }

    #[test]
    fn real_tcp_truncated_payload_is_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .write_all(&[0, 0, 0, 10, 0, 1, 2, 3, 4, 5, 6, 7, 8])
                .unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });
        let mut client = TcpConnection::connect(address, TIMEOUT, TIMEOUT, TIMEOUT).unwrap();
        assert!(matches!(
            client.receive_payload(),
            Err(TcpError::Transport(TransportError::TruncatedPayload))
        ));
        server.join().unwrap();
    }

    #[test]
    fn real_tcp_oversized_prefix_is_rejected_before_payload_read() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(&[0, 0, 0x40, 1]).unwrap();
        });
        let mut client = TcpConnection::connect(address, TIMEOUT, TIMEOUT, TIMEOUT).unwrap();
        assert!(matches!(
            client.receive_payload(),
            Err(TcpError::Transport(TransportError::Frame(
                crate::framing::FrameError::PayloadTooLarge { .. }
            )))
        ));
        server.join().unwrap();
    }

    #[test]
    fn real_tcp_wrong_psk_is_authentication_error() {
        let (mut client, mut server) = connect_pair();
        let serializer = CborSerializer;
        client
            .send_message(hello(), &serializer, &authenticator(0x0b))
            .unwrap();
        assert!(matches!(
            server.receive_message(&serializer, &authenticator(0x0c)),
            Err(TcpError::Receive(ReceiveError::Authentication(
                AuthenticationError::InvalidMac
            )))
        ));
    }

    #[test]
    fn semantic_invalid_message_is_rejected_before_network_write() {
        let (mut client, mut server) = connect_pair();
        let mut invalid = hello();
        invalid.common.request_id = Some(crate::protocol::RequestId::new(
            "00000000-0000-4000-8000-000000000001",
        ));
        assert!(matches!(
            client.send_message(invalid, &CborSerializer, &authenticator(0x0b)),
            Err(TcpError::Protocol(_))
        ));
        server
            .stream_mut_for_test()
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut byte = [0u8; 1];
        assert!(matches!(
            server.stream_mut_for_test().read(&mut byte),
            Err(error) if matches!(error.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock)
        ));
    }

    #[test]
    fn read_timeout_is_applied_to_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            TcpConnection::from_stream(stream, Duration::from_millis(200), TIMEOUT)
                .unwrap()
                .receive_payload()
        });
        let _client = TcpConnection::connect(address, TIMEOUT, TIMEOUT, TIMEOUT).unwrap();
        assert!(matches!(
            server.join().unwrap(),
            Err(TcpError::Transport(TransportError::Io(error)))
                if matches!(error.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock)
        ));
    }
}
