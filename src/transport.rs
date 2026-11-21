use crate::framing::{FrameError, decode_length_prefix, encode_frame};
use std::fmt;
use std::io::{self, Read, Write};

pub fn read_frame<R: Read>(reader: &mut R) -> Result<ReadFrameResult, TransportError> {
    let mut prefix = [0u8; 4];
    let mut read = 0;
    while read < prefix.len() {
        match reader.read(&mut prefix[read..]) {
            Ok(0) if read == 0 => return Ok(ReadFrameResult::Eof),
            Ok(0) => return Err(TransportError::TruncatedPrefix),
            Ok(count) => read += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(TransportError::Io(error)),
        }
    }

    let length = decode_length_prefix(prefix).map_err(TransportError::Frame)?;
    let mut payload = vec![0u8; length];
    reader
        .read_exact(&mut payload)
        .map_err(|error| match error.kind() {
            io::ErrorKind::UnexpectedEof => TransportError::TruncatedPayload,
            _ => TransportError::Io(error),
        })?;
    Ok(ReadFrameResult::Frame(payload))
}

pub fn write_frame<W: Write>(writer: &mut W, payload: &[u8]) -> Result<(), TransportError> {
    let frame = encode_frame(payload).map_err(TransportError::Frame)?;
    writer.write_all(&frame).map_err(TransportError::Io)
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReadFrameResult {
    Eof,
    Frame(Vec<u8>),
}

#[derive(Debug)]
pub enum TransportError {
    Io(io::Error),
    Frame(FrameError),
    TruncatedPrefix,
    TruncatedPayload,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "transport I/O failed: {error}"),
            Self::Frame(error) => write!(f, "invalid frame: {error}"),
            Self::TruncatedPrefix => write!(f, "frame length prefix was truncated"),
            Self::TruncatedPayload => write!(f, "frame payload was truncated"),
        }
    }
}

impl std::error::Error for TransportError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::MAX_FRAME_PAYLOAD_SIZE;
    use crate::protocol::{
        CanonicalSerializer, CborSerializer, ClusterId, CommonFields, HelloPayload, NodeId,
        ProtocolMessage, Sequence, SessionId, Term, UnsignedEnvelope,
    };
    use crate::receive::receive;
    use crate::security::{MessageAuthenticator, Psk};
    use std::io::{self, Cursor};

    struct ShortReader {
        inner: Cursor<Vec<u8>>,
        max: usize,
    }

    impl Read for ShortReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let limit = buffer.len().min(self.max);
            self.inner.read(&mut buffer[..limit])
        }
    }

    struct ShortWriter {
        bytes: Vec<u8>,
        max: usize,
    }

    impl Write for ShortWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            let count = buffer.len().min(self.max);
            self.bytes.extend_from_slice(&buffer[..count]);
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            panic!("write_frame must not flush");
        }
    }

    fn assert_frame_error(input: &[u8], expected: FrameError) {
        let mut reader = Cursor::new(input.to_vec());
        assert!(matches!(
            read_frame(&mut reader),
            Err(TransportError::Frame(error)) if error == expected
        ));
    }

    #[test]
    fn reads_prefix_and_payload_with_partial_reads() {
        let frame = crate::framing::encode_frame(b"payload").unwrap();
        let mut reader = ShortReader {
            inner: Cursor::new(frame),
            max: 1,
        };
        assert_eq!(
            read_frame(&mut reader).unwrap(),
            ReadFrameResult::Frame(b"payload".to_vec())
        );
    }

    #[test]
    fn writes_complete_frame_with_partial_writes_without_flushing() {
        let mut writer = ShortWriter {
            bytes: Vec::new(),
            max: 2,
        };
        write_frame(&mut writer, b"payload").unwrap();
        assert_eq!(
            writer.bytes,
            crate::framing::encode_frame(b"payload").unwrap()
        );
    }

    #[test]
    fn distinguishes_clean_eof_and_truncated_prefix() {
        let mut reader = Cursor::new(Vec::<u8>::new());
        assert_eq!(read_frame(&mut reader).unwrap(), ReadFrameResult::Eof);
        for length in 1..4 {
            let mut reader = Cursor::new(vec![0; length]);
            assert!(matches!(
                read_frame(&mut reader),
                Err(TransportError::TruncatedPrefix)
            ));
        }
    }

    #[test]
    fn truncated_payload_is_rejected() {
        let mut reader = Cursor::new(vec![0, 0, 0, 10, 0, 1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(matches!(
            read_frame(&mut reader),
            Err(TransportError::TruncatedPayload)
        ));
    }

    #[test]
    fn rejects_zero_and_oversized_prefix_before_payload_read() {
        assert_frame_error(&[0, 0, 0, 0], FrameError::EmptyPayload);
        assert_frame_error(
            &[0, 0, 0x40, 1],
            FrameError::PayloadTooLarge {
                size: MAX_FRAME_PAYLOAD_SIZE + 1,
                max: MAX_FRAME_PAYLOAD_SIZE,
            },
        );
    }

    #[test]
    fn reads_and_writes_maximum_payload() {
        let payload = vec![0xab; MAX_FRAME_PAYLOAD_SIZE];
        let mut writer = Vec::new();
        write_frame(&mut writer, &payload).unwrap();
        let mut reader = Cursor::new(writer);
        assert_eq!(
            read_frame(&mut reader).unwrap(),
            ReadFrameResult::Frame(payload)
        );

        let too_large = vec![0; MAX_FRAME_PAYLOAD_SIZE + 1];
        let mut writer = Vec::new();
        assert!(matches!(
            write_frame(&mut writer, &too_large),
            Err(TransportError::Frame(FrameError::PayloadTooLarge { .. }))
        ));
    }

    #[test]
    fn reads_multiple_frames_then_clean_eof() {
        let mut stream = crate::framing::encode_frame(b"one").unwrap();
        stream.extend_from_slice(&crate::framing::encode_frame(b"two").unwrap());
        let mut reader = Cursor::new(stream);
        assert_eq!(
            read_frame(&mut reader).unwrap(),
            ReadFrameResult::Frame(b"one".to_vec())
        );
        assert_eq!(
            read_frame(&mut reader).unwrap(),
            ReadFrameResult::Frame(b"two".to_vec())
        );
        assert_eq!(read_frame(&mut reader).unwrap(), ReadFrameResult::Eof);
    }

    #[test]
    fn transport_to_receive_integration() {
        let serializer = CborSerializer;
        let authenticator = MessageAuthenticator::new(Psk::from_test_bytes([0x0b; 32]));
        let unsigned = UnsignedEnvelope {
            common: CommonFields {
                protocol_version: 1,
                cluster_id: ClusterId::new("cluster"),
                sender_node_id: NodeId::new("node-a"),
                receiver_node_id: NodeId::new("node-b"),
                session_id: SessionId::new("session"),
                sequence: Sequence(1),
                term: Term(1),
                lease_id: None,
                request_id: None,
                operation_id: None,
            },
            message: ProtocolMessage::Hello(HelloPayload { priority: 100 }),
        };
        let wire = authenticator.sign(unsigned, &serializer).unwrap();
        let payload = serializer.serialize_wire(&wire).unwrap();
        let mut stream = Vec::new();
        write_frame(&mut stream, &payload).unwrap();
        let mut reader = Cursor::new(stream);
        let ReadFrameResult::Frame(payload) = read_frame(&mut reader).unwrap() else {
            panic!("signed message frame should be present");
        };
        let received = receive(&payload, &serializer, &authenticator);
        assert!(received.is_ok());
        assert_eq!(received.unwrap().unsigned(), &wire.unsigned);
    }
}
