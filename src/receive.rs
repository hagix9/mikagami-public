use crate::protocol::{
    CborSerializer, ProtocolError, SerializationError, UnsignedEnvelope, WireMessage,
};
use crate::security::{AuthenticationError, MessageAuthenticator};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedMessage {
    wire: WireMessage,
}

impl AuthenticatedMessage {
    pub fn unsigned(&self) -> &UnsignedEnvelope {
        &self.wire.unsigned
    }

    pub fn wire(&self) -> &WireMessage {
        &self.wire
    }
}

pub fn receive(
    bytes: &[u8],
    serializer: &CborSerializer,
    authenticator: &MessageAuthenticator,
) -> Result<AuthenticatedMessage, ReceiveError> {
    let wire = deserialize_wire(bytes, serializer)?;
    authenticator
        .verify(&wire, serializer)
        .map_err(ReceiveError::Authentication)?;
    wire.unsigned.validate().map_err(ReceiveError::Protocol)?;
    Ok(AuthenticatedMessage { wire })
}

fn deserialize_wire(
    bytes: &[u8],
    serializer: &CborSerializer,
) -> Result<WireMessage, ReceiveError> {
    serializer
        .deserialize_wire(bytes)
        .map_err(ReceiveError::Serialization)
}

#[derive(Debug)]
pub enum ReceiveError {
    Serialization(SerializationError),
    Authentication(AuthenticationError),
    Protocol(ProtocolError),
}

impl fmt::Display for ReceiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Serialization(error) => write!(f, "message decode failed: {error}"),
            Self::Authentication(error) => write!(f, "message authentication failed: {error}"),
            Self::Protocol(error) => write!(f, "message validation failed: {error}"),
        }
    }
}

impl std::error::Error for ReceiveError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        CanonicalSerializer, ClusterId, CommonFields, DurationMs, HelloPayload,
        LeaseRequestPayload, NodeId, ProtocolMessage, RequestId, Sequence, SessionId, Term,
    };
    use crate::security::Psk;

    fn authenticator(value: u8) -> MessageAuthenticator {
        MessageAuthenticator::new(Psk::from_test_bytes([value; 32]))
    }

    fn envelope() -> UnsignedEnvelope {
        UnsignedEnvelope {
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
        }
    }

    fn witness_request() -> UnsignedEnvelope {
        let mut message = envelope();
        message.common.request_id = Some(RequestId::new("00000000-0000-4000-8000-000000000001"));
        message.message = ProtocolMessage::LeaseRequest(LeaseRequestPayload {
            mutation_generation: 1,
            observed_term: Term(1),
            priority: 100,
            requested_ttl: DurationMs(10_000),
        });
        message
    }

    fn receive_wire(
        unsigned: UnsignedEnvelope,
        signer: &MessageAuthenticator,
    ) -> Result<AuthenticatedMessage, ReceiveError> {
        let serializer = CborSerializer;
        let wire = signer.sign(unsigned, &serializer).unwrap();
        let bytes = serializer.serialize_wire(&wire).unwrap();
        receive(&bytes, &serializer, signer)
    }

    #[test]
    fn successful_receive_returns_authenticated_message() {
        let message = receive_wire(witness_request(), &authenticator(0x0b)).unwrap();
        assert_eq!(
            message
                .unsigned()
                .common
                .request_id
                .as_ref()
                .unwrap()
                .as_str(),
            "00000000-0000-4000-8000-000000000001"
        );
        assert_eq!(
            message.unsigned().message.message_type(),
            crate::protocol::MessageType::LeaseRequest
        );
    }

    #[test]
    fn wrong_psk_is_rejected() {
        let serializer = CborSerializer;
        let signer = authenticator(0x0b);
        let receiver = authenticator(0x0c);
        let wire = signer.sign(witness_request(), &serializer).unwrap();
        let bytes = serializer.serialize_wire(&wire).unwrap();
        assert!(matches!(
            receive(&bytes, &serializer, &receiver),
            Err(ReceiveError::Authentication(
                AuthenticationError::InvalidMac
            ))
        ));
    }

    #[test]
    fn tampering_is_rejected() {
        let serializer = CborSerializer;
        let signer = authenticator(0x0b);
        let mut wire = signer.sign(witness_request(), &serializer).unwrap();
        wire.unsigned.common.sequence = Sequence(2);
        let bytes = serializer.serialize_wire(&wire).unwrap();
        assert!(matches!(
            receive(&bytes, &serializer, &signer),
            Err(ReceiveError::Authentication(
                AuthenticationError::InvalidMac
            ))
        ));
    }

    #[test]
    fn authentication_precedes_semantic_validation() {
        let serializer = CborSerializer;
        let signer = authenticator(0x0b);
        let mut wire = signer.sign(envelope(), &serializer).unwrap();
        wire.unsigned.common.request_id =
            Some(RequestId::new("00000000-0000-4000-8000-000000000001"));
        assert!(wire.unsigned.validate().is_err());
        let bytes = serializer.serialize_wire(&wire).unwrap();
        assert!(matches!(
            receive(&bytes, &serializer, &signer),
            Err(ReceiveError::Authentication(
                AuthenticationError::InvalidMac
            ))
        ));
    }

    #[test]
    fn correctly_signed_semantic_invalid_message_returns_protocol_error() {
        let serializer = CborSerializer;
        let signer = authenticator(0x0b);
        let mut invalid = envelope();
        invalid.common.request_id = Some(RequestId::new("00000000-0000-4000-8000-000000000001"));
        assert!(invalid.validate().is_err());
        let wire = signer.sign(invalid, &serializer).unwrap();
        let bytes = serializer.serialize_wire(&wire).unwrap();
        assert!(matches!(
            receive(&bytes, &serializer, &signer),
            Err(ReceiveError::Protocol(_))
        ));
    }

    #[test]
    fn malformed_cbor_is_rejected_before_authentication() {
        let serializer = CborSerializer;
        assert!(matches!(
            receive(&[0xde, 0xad], &serializer, &authenticator(0x0b)),
            Err(ReceiveError::Serialization(_))
        ));
    }

    #[test]
    fn noncanonical_cbor_is_rejected_before_authentication() {
        let serializer = CborSerializer;
        let signer = authenticator(0x0b);
        let wire = signer.sign(envelope(), &serializer).unwrap();
        let mut bytes = serializer.serialize_wire(&wire).unwrap();
        let key = b"protocol_version";
        let key_start = bytes
            .windows(key.len())
            .position(|window| window == key)
            .unwrap();
        let value_index = key_start + key.len();
        bytes[value_index] = 0x18;
        bytes.insert(value_index + 1, 0x01);
        assert!(matches!(
            receive(&bytes, &serializer, &signer),
            Err(ReceiveError::Serialization(
                SerializationError::NonCanonical
            ))
        ));
    }

    #[test]
    fn trailing_bytes_are_rejected_before_authentication() {
        let serializer = CborSerializer;
        let signer = authenticator(0x0b);
        let wire = signer.sign(envelope(), &serializer).unwrap();
        let mut bytes = serializer.serialize_wire(&wire).unwrap();
        bytes.push(0);
        assert!(matches!(
            receive(&bytes, &serializer, &signer),
            Err(ReceiveError::Serialization(SerializationError::Decode(_)))
        ));
    }
}
