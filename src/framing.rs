use std::fmt;

pub const MAX_FRAME_PAYLOAD_SIZE: usize = 16 * 1024;
const FRAME_LENGTH_PREFIX_SIZE: usize = 4;

pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    validate_payload_length(payload.len())?;

    let length = u32::try_from(payload.len()).expect("maximum frame size fits in u32");
    let mut frame = Vec::with_capacity(FRAME_LENGTH_PREFIX_SIZE + payload.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

pub fn decode_frame(bytes: &[u8]) -> Result<DecodeResult<'_>, FrameError> {
    if bytes.len() < FRAME_LENGTH_PREFIX_SIZE {
        return Ok(DecodeResult::Incomplete);
    }

    let length = decode_length_prefix([bytes[0], bytes[1], bytes[2], bytes[3]])?;

    let frame_length = FRAME_LENGTH_PREFIX_SIZE + length;
    if bytes.len() < frame_length {
        return Ok(DecodeResult::Incomplete);
    }

    Ok(DecodeResult::Complete {
        payload: &bytes[FRAME_LENGTH_PREFIX_SIZE..frame_length],
        consumed: frame_length,
    })
}

pub fn decode_length_prefix(prefix: [u8; 4]) -> Result<usize, FrameError> {
    let length = u32::from_be_bytes(prefix);
    let length = usize::try_from(length).expect("u32 fits in usize on supported targets");
    validate_payload_length(length)?;
    Ok(length)
}

fn validate_payload_length(length: usize) -> Result<(), FrameError> {
    if length == 0 {
        return Err(FrameError::EmptyPayload);
    }
    if length > MAX_FRAME_PAYLOAD_SIZE {
        return Err(FrameError::PayloadTooLarge {
            size: length,
            max: MAX_FRAME_PAYLOAD_SIZE,
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeResult<'a> {
    Incomplete,
    Complete { payload: &'a [u8], consumed: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    EmptyPayload,
    PayloadTooLarge { size: usize, max: usize },
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPayload => write!(f, "frame payload must not be empty"),
            Self::PayloadTooLarge { size, max } => {
                write!(
                    f,
                    "frame payload is too large: {size} bytes (maximum {max})"
                )
            }
        }
    }
}

impl std::error::Error for FrameError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        CanonicalSerializer, CborSerializer, ClusterId, CommonFields, HelloPayload,
        ProtocolMessage, Sequence, SessionId, Term, UnsignedEnvelope,
    };
    use crate::receive::{ReceiveError, receive};
    use crate::security::{MessageAuthenticator, Psk};

    fn valid_envelope() -> UnsignedEnvelope {
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

    fn authenticator() -> MessageAuthenticator {
        MessageAuthenticator::new(Psk::from_test_bytes([0x0b; 32]))
    }

    fn assert_incomplete(bytes: &[u8]) {
        assert_eq!(decode_frame(bytes).unwrap(), DecodeResult::Incomplete);
    }

    #[test]
    fn encodes_boundaries_and_big_endian_length() {
        let one = encode_frame(&[0xaa]).unwrap();
        assert_eq!(one, vec![0, 0, 0, 1, 0xaa]);

        let maximum = encode_frame(&vec![0; MAX_FRAME_PAYLOAD_SIZE]).unwrap();
        assert_eq!(
            maximum.len(),
            FRAME_LENGTH_PREFIX_SIZE + MAX_FRAME_PAYLOAD_SIZE
        );
        assert_eq!(&maximum[..4], &[0, 0, 0x40, 0]);

        let length_258 = encode_frame(&vec![0; 258]).unwrap();
        assert_eq!(&length_258[..4], &[0, 0, 1, 2]);
    }

    #[test]
    fn rejects_invalid_encode_lengths() {
        assert_eq!(encode_frame(&[]), Err(FrameError::EmptyPayload));
        assert_eq!(
            encode_frame(&vec![0; MAX_FRAME_PAYLOAD_SIZE + 1]),
            Err(FrameError::PayloadTooLarge {
                size: MAX_FRAME_PAYLOAD_SIZE + 1,
                max: MAX_FRAME_PAYLOAD_SIZE,
            })
        );
    }

    #[test]
    fn partial_prefix_is_incomplete() {
        for length in 0..4 {
            assert_incomplete(&[0; 4][..length]);
        }
    }

    #[test]
    fn partial_payload_is_incomplete_until_complete() {
        let prefix = [0, 0, 0, 10];
        for payload_length in [0, 1, 9] {
            let mut bytes = prefix.to_vec();
            bytes.extend_from_slice(&vec![0; payload_length]);
            assert_incomplete(&bytes);
        }

        let mut bytes = prefix.to_vec();
        bytes.extend_from_slice(&[0; 10]);
        assert_eq!(
            decode_frame(&bytes).unwrap(),
            DecodeResult::Complete {
                payload: &[0; 10],
                consumed: 14,
            }
        );
    }

    #[test]
    fn decodes_exactly_one_frame() {
        let frame = encode_frame(b"payload").unwrap();
        assert_eq!(
            decode_frame(&frame).unwrap(),
            DecodeResult::Complete {
                payload: b"payload",
                consumed: frame.len(),
            }
        );
    }

    #[test]
    fn decodes_multiple_consecutive_frames() {
        let first = encode_frame(b"first").unwrap();
        let second = encode_frame(b"second").unwrap();
        let mut buffer = first.clone();
        buffer.extend_from_slice(&second);

        let DecodeResult::Complete { payload, consumed } = decode_frame(&buffer).unwrap() else {
            panic!("first frame should be complete");
        };
        assert_eq!(payload, b"first");
        assert_eq!(consumed, first.len());

        assert_eq!(
            decode_frame(&buffer[consumed..]).unwrap(),
            DecodeResult::Complete {
                payload: b"second",
                consumed: second.len(),
            }
        );
    }

    #[test]
    fn rejects_zero_and_oversized_prefix_immediately() {
        assert_eq!(decode_frame(&[0, 0, 0, 0]), Err(FrameError::EmptyPayload));
        assert_eq!(
            decode_frame(&[0, 0, 0x40, 1]),
            Err(FrameError::PayloadTooLarge {
                size: MAX_FRAME_PAYLOAD_SIZE + 1,
                max: MAX_FRAME_PAYLOAD_SIZE,
            })
        );
    }

    #[test]
    fn framing_does_not_interpret_garbage_payload() {
        let frame = encode_frame(&[0xff, 0xff, 0xff]).unwrap();
        let DecodeResult::Complete { payload, .. } = decode_frame(&frame).unwrap() else {
            panic!("garbage payload is still a complete frame");
        };
        assert_eq!(payload, &[0xff, 0xff, 0xff]);

        let serializer = CborSerializer;
        assert!(matches!(
            receive(payload, &serializer, &authenticator()),
            Err(ReceiveError::Serialization(_))
        ));
    }

    #[test]
    fn protocol_to_receive_integration() {
        let serializer = CborSerializer;
        let authenticator = authenticator();
        let wire = authenticator.sign(valid_envelope(), &serializer).unwrap();
        let payload = serializer.serialize_wire(&wire).unwrap();
        let frame = encode_frame(&payload).unwrap();
        let DecodeResult::Complete {
            payload: framed_payload,
            consumed,
        } = decode_frame(&frame).unwrap()
        else {
            panic!("signed WireMessage frame should be complete");
        };
        assert_eq!(consumed, frame.len());
        let received = receive(framed_payload, &serializer, &authenticator).unwrap();
        assert_eq!(received.unsigned(), &wire.unsigned);
    }

    #[test]
    fn malformed_frame_payload_reaches_receive_as_decode_error() {
        let serializer = CborSerializer;
        let frame = encode_frame(&[0xff]).unwrap();
        let DecodeResult::Complete { payload, .. } = decode_frame(&frame).unwrap() else {
            panic!("frame should be complete");
        };
        assert!(matches!(
            receive(payload, &serializer, &authenticator()),
            Err(ReceiveError::Serialization(_))
        ));
    }
}
