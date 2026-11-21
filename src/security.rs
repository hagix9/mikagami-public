use crate::protocol::{
    Authentication, CanonicalSerializer, SerializationError, UnsignedEnvelope, WireMessage,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::Path;

type HmacSha256 = Hmac<Sha256>;

const PSK_BYTES: usize = 32;
const PSK_HEX_BYTES: usize = PSK_BYTES * 2;

pub struct Psk([u8; PSK_BYTES]);

impl Psk {
    pub fn load(path: &Path) -> Result<Self, PskError> {
        let file = open_psk_file(path)?;
        let metadata = file.metadata().map_err(PskError::Io)?;
        validate_metadata(&metadata)?;

        let mut contents = Vec::new();
        file.take((PSK_HEX_BYTES + 2) as u64)
            .read_to_end(&mut contents)
            .map_err(PskError::Io)?;
        Self::from_file_contents(&contents)
    }

    fn from_file_contents(contents: &[u8]) -> Result<Self, PskError> {
        let hex = match contents.strip_suffix(b"\n") {
            Some(value) if !value.ends_with(b"\n") => value,
            _ => contents,
        };
        if hex.len() != PSK_HEX_BYTES
            || !hex
                .iter()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(PskError::InvalidFormat);
        }

        let mut bytes = [0u8; PSK_BYTES];
        let (chunks, _) = hex.as_chunks::<2>();
        for (index, chunk) in chunks.iter().enumerate() {
            bytes[index] = (hex_digit(chunk[0])? << 4) | hex_digit(chunk[1])?;
        }
        Ok(Self(bytes))
    }

    #[cfg(test)]
    pub(crate) fn from_test_bytes(bytes: [u8; PSK_BYTES]) -> Self {
        Self(bytes)
    }

    /// HMAC-SHA256 over the concatenation of `parts` (the two-node wire). The key never
    /// leaves this type.
    pub(crate) fn hmac_parts(&self, parts: &[&[u8]]) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.0).expect("HMAC accepts any key length");
        for part in parts {
            mac.update(part);
        }
        let mut output = [0u8; 32];
        output.copy_from_slice(&mac.finalize().into_bytes());
        output
    }

    /// Constant-time verification of [`Psk::hmac_parts`].
    pub(crate) fn verify_parts(&self, parts: &[&[u8]], tag: &[u8]) -> bool {
        let mut mac = HmacSha256::new_from_slice(&self.0).expect("HMAC accepts any key length");
        for part in parts {
            mac.update(part);
        }
        mac.verify_slice(tag).is_ok()
    }
}

impl Clone for Psk {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

pub struct MessageAuthenticator {
    psk: Psk,
}

impl MessageAuthenticator {
    pub fn new(psk: Psk) -> Self {
        Self { psk }
    }

    pub fn authenticate<S: CanonicalSerializer>(
        &self,
        message: &UnsignedEnvelope,
        serializer: &S,
    ) -> Result<Authentication, AuthenticationError> {
        let bytes = serializer
            .serialize_unsigned(message)
            .map_err(AuthenticationError::Serialization)?;
        let mac = compute_mac(&self.psk, &bytes)?;
        Ok(Authentication { mac })
    }

    pub fn sign<S: CanonicalSerializer>(
        &self,
        unsigned: UnsignedEnvelope,
        serializer: &S,
    ) -> Result<WireMessage, AuthenticationError> {
        let authentication = self.authenticate(&unsigned, serializer)?;
        Ok(WireMessage {
            unsigned,
            authentication,
        })
    }

    pub fn verify<S: CanonicalSerializer>(
        &self,
        message: &WireMessage,
        serializer: &S,
    ) -> Result<(), AuthenticationError> {
        let bytes = serializer
            .serialize_unsigned(&message.unsigned)
            .map_err(AuthenticationError::Serialization)?;
        let mut mac =
            HmacSha256::new_from_slice(&self.psk.0).map_err(|_| AuthenticationError::InvalidKey)?;
        mac.update(&bytes);
        mac.verify_slice(&message.authentication.mac)
            .map_err(|_| AuthenticationError::InvalidMac)
    }
}

fn compute_mac(psk: &Psk, bytes: &[u8]) -> Result<[u8; 32], AuthenticationError> {
    let mut mac =
        HmacSha256::new_from_slice(&psk.0).map_err(|_| AuthenticationError::InvalidKey)?;
    mac.update(bytes);
    let result = mac.finalize().into_bytes();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    Ok(output)
}

fn hex_digit(byte: u8) -> Result<u8, PskError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(PskError::InvalidFormat),
    }
}

fn open_psk_file(path: &Path) -> Result<File, PskError> {
    let link_metadata = fs::symlink_metadata(path).map_err(PskError::Io)?;
    if link_metadata.file_type().is_symlink() {
        return Err(PskError::InsecureFile("symlink is not allowed"));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .read(true)
            .custom_flags(o_nofollow())
            .open(path)
            .map_err(PskError::Io)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        File::open(path).map_err(PskError::Io)
    }
}

#[cfg(target_os = "linux")]
const fn o_nofollow() -> i32 {
    0x20000
}

#[cfg(target_os = "macos")]
const fn o_nofollow() -> i32 {
    0x100
}

fn validate_metadata(metadata: &fs::Metadata) -> Result<(), PskError> {
    if !metadata.is_file() {
        return Err(PskError::InsecureFile("not a regular file"));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o777 != 0o600 {
            return Err(PskError::InsecureFile("permission must be 0600"));
        }
        #[cfg(target_os = "linux")]
        if metadata.uid() != 0 || metadata.gid() != 0 {
            return Err(PskError::InsecureFile("owner and group must be root"));
        }
    }

    Ok(())
}

#[derive(Debug)]
pub enum PskError {
    Io(std::io::Error),
    InvalidFormat,
    InsecureFile(&'static str),
}

impl fmt::Display for PskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "could not read PSK file: {error}"),
            Self::InvalidFormat => write!(
                f,
                "PSK must be 64 lowercase hexadecimal characters with at most one trailing LF"
            ),
            Self::InsecureFile(reason) => write!(f, "PSK file rejected: {reason}"),
        }
    }
}

impl std::error::Error for PskError {}

#[derive(Debug)]
pub enum AuthenticationError {
    Serialization(SerializationError),
    InvalidKey,
    InvalidMac,
}

impl fmt::Display for AuthenticationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Serialization(error) => write!(f, "authentication serialization failed: {error}"),
            Self::InvalidKey => write!(f, "invalid HMAC key"),
            Self::InvalidMac => write!(f, "authentication failed: invalid MAC"),
        }
    }
}

impl std::error::Error for AuthenticationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn psk() -> Psk {
        Psk([0x0b; PSK_BYTES])
    }

    fn envelope() -> UnsignedEnvelope {
        UnsignedEnvelope {
            common: CommonFields {
                protocol_version: PROTOCOL_VERSION,
                cluster_id: ClusterId::new("cluster"),
                sender_node_id: NodeId::new("node-a"),
                receiver_node_id: NodeId::new("node-b"),
                session_id: SessionId::new("process-session"),
                sequence: Sequence(1),
                term: Term(7),
                lease_id: None,
                request_id: None,
                operation_id: None,
            },
            message: ProtocolMessage::Hello(HelloPayload { priority: 100 }),
        }
    }

    fn witness_request_envelope() -> UnsignedEnvelope {
        let mut message = envelope();
        message.common.request_id = Some(RequestId::new("00000000-0000-4000-8000-000000000001"));
        message.message = ProtocolMessage::LeaseRequest(LeaseRequestPayload {
            mutation_generation: 1,
            observed_term: Term(7),
            priority: 100,
            requested_ttl: DurationMs(10_000),
        });
        message
    }

    fn promotion_envelope() -> UnsignedEnvelope {
        let mut message = envelope();
        message.common.operation_id = Some(OperationId::new("operation-1"));
        message.message = ProtocolMessage::PromotionIntent(PromotionIntentPayload {
            priority: 100,
            reason: "failover".to_string(),
        });
        message
    }

    fn lease_reject_envelope(code: WitnessMutationOutcomeCode) -> UnsignedEnvelope {
        let mut message = envelope();
        message.common.request_id = Some(RequestId::new("00000000-0000-4000-8000-000000000001"));
        message.message = ProtocolMessage::LeaseReject(LeaseRejectPayload {
            code,
            reason: "diagnostic".to_string(),
        });
        message
    }

    fn temp_path(name: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("mikagami-{name}-{nonce}"))
    }

    #[test]
    fn parses_valid_psk_forms() {
        let input = vec![b'0'; PSK_HEX_BYTES];
        assert!(Psk::from_file_contents(&input).is_ok());
        assert!(Psk::from_file_contents(&[input, vec![b'\n']].concat()).is_ok());
    }

    #[test]
    fn rejects_invalid_psk_forms() {
        for input in [
            vec![b'0'; 63],
            vec![b'0'; 65],
            vec![b'A'; PSK_HEX_BYTES],
            [vec![b'0'; 63], vec![b'g']].concat(),
            [vec![b' '; 1], vec![b'0'; PSK_HEX_BYTES - 1]].concat(),
            [vec![b'0'; PSK_HEX_BYTES - 1], vec![b' ']].concat(),
            [vec![b'0'; PSK_HEX_BYTES], vec![b'\r', b'\n']].concat(),
            [vec![b'0'; PSK_HEX_BYTES], vec![b'\n', b'\n']].concat(),
            vec![],
        ] {
            assert!(matches!(
                Psk::from_file_contents(&input),
                Err(PskError::InvalidFormat)
            ));
        }
    }

    #[test]
    fn fixed_hmac_vector_matches() {
        let serializer = CborSerializer;
        let authenticator = MessageAuthenticator::new(psk());
        let authentication = authenticator
            .authenticate(&envelope(), &serializer)
            .unwrap();
        assert_eq!(
            authentication.mac,
            [
                0x88, 0xb9, 0x9d, 0x74, 0xbe, 0x3c, 0x12, 0xa0, 0xb3, 0xba, 0xc7, 0xb6, 0x67, 0xaa,
                0x18, 0x86, 0x1f, 0xc4, 0x18, 0x20, 0xe2, 0xb5, 0xb4, 0xed, 0x63, 0x3c, 0x41, 0xbe,
                0x67, 0x55, 0xa6, 0x43,
            ]
        );
    }

    #[test]
    fn authentication_detects_tampering_and_wrong_key() {
        let serializer = CborSerializer;
        let authenticator = MessageAuthenticator::new(psk());
        let signed = authenticator.sign(envelope(), &serializer).unwrap();
        assert!(authenticator.verify(&signed, &serializer).is_ok());

        let wrong = MessageAuthenticator::new(Psk([0x0c; PSK_BYTES]));
        assert!(matches!(
            wrong.verify(&signed, &serializer),
            Err(AuthenticationError::InvalidMac)
        ));

        let mut changed = signed.clone();
        changed.unsigned.common.sequence = Sequence(2);
        assert!(matches!(
            authenticator.verify(&changed, &serializer),
            Err(AuthenticationError::InvalidMac)
        ));

        let mut changed = signed.clone();
        changed.unsigned.message = ProtocolMessage::Hello(HelloPayload { priority: 101 });
        assert!(matches!(
            authenticator.verify(&changed, &serializer),
            Err(AuthenticationError::InvalidMac)
        ));

        let mut changed = signed;
        changed.authentication.mac[0] ^= 1;
        assert!(matches!(
            authenticator.verify(&changed, &serializer),
            Err(AuthenticationError::InvalidMac)
        ));
    }

    #[test]
    fn request_id_tampering_is_detected_for_valid_witness_message() {
        let serializer = CborSerializer;
        let authenticator = MessageAuthenticator::new(psk());
        let unsigned = witness_request_envelope();
        assert!(unsigned.validate().is_ok());

        let mut signed = authenticator.sign(unsigned, &serializer).unwrap();
        signed.unsigned.common.request_id =
            Some(RequestId::new("00000000-0000-4000-8000-000000000002"));
        assert!(signed.unsigned.validate().is_ok());
        assert!(matches!(
            authenticator.verify(&signed, &serializer),
            Err(AuthenticationError::InvalidMac)
        ));
    }

    #[test]
    fn mutation_generation_tampering_is_detected_for_valid_witness_message() {
        let serializer = CborSerializer;
        let authenticator = MessageAuthenticator::new(psk());
        let unsigned = witness_request_envelope();
        assert!(unsigned.validate().is_ok());

        let mut signed = authenticator.sign(unsigned, &serializer).unwrap();
        if let ProtocolMessage::LeaseRequest(payload) = &mut signed.unsigned.message {
            payload.mutation_generation = 2;
        } else {
            unreachable!();
        }
        assert!(signed.unsigned.validate().is_ok());
        assert!(matches!(
            authenticator.verify(&signed, &serializer),
            Err(AuthenticationError::InvalidMac)
        ));
    }

    #[test]
    fn operation_id_tampering_is_detected_for_valid_promotion_message() {
        let serializer = CborSerializer;
        let authenticator = MessageAuthenticator::new(psk());
        let unsigned = promotion_envelope();
        assert!(unsigned.validate().is_ok());

        let mut signed = authenticator.sign(unsigned, &serializer).unwrap();
        signed.unsigned.common.operation_id = Some(OperationId::new("operation-2"));
        assert!(signed.unsigned.validate().is_ok());
        assert!(matches!(
            authenticator.verify(&signed, &serializer),
            Err(AuthenticationError::InvalidMac)
        ));
    }

    #[test]
    fn operation_id_tampering_is_detected_for_response_message() {
        let serializer = CborSerializer;
        let authenticator = MessageAuthenticator::new(psk());
        let mut unsigned = envelope();
        unsigned.common.operation_id = Some(OperationId::new("operation-1"));
        unsigned.message = ProtocolMessage::PromotionAck;
        assert!(unsigned.validate().is_ok());

        let mut signed = authenticator.sign(unsigned, &serializer).unwrap();
        signed.unsigned.common.operation_id = Some(OperationId::new("operation-2"));
        assert!(signed.unsigned.validate().is_ok());
        assert!(matches!(
            authenticator.verify(&signed, &serializer),
            Err(AuthenticationError::InvalidMac)
        ));
    }

    #[test]
    fn all_witness_mutation_outcomes_are_authenticated() {
        let serializer = CborSerializer;
        let authenticator = MessageAuthenticator::new(psk());
        let codes = [
            WitnessMutationOutcomeCode::PolicyReject,
            WitnessMutationOutcomeCode::RetiredStale,
            WitnessMutationOutcomeCode::Conflict,
            WitnessMutationOutcomeCode::GenerationGap,
            WitnessMutationOutcomeCode::TemporarilyUnavailable,
        ];

        for code in codes {
            let unsigned = lease_reject_envelope(code);
            assert!(unsigned.validate().is_ok());
            let signed = authenticator.sign(unsigned, &serializer).unwrap();
            assert!(authenticator.verify(&signed, &serializer).is_ok());
        }
    }

    #[test]
    fn tampering_lease_reject_outcome_code_is_detected() {
        let serializer = CborSerializer;
        let authenticator = MessageAuthenticator::new(psk());
        let unsigned = lease_reject_envelope(WitnessMutationOutcomeCode::Conflict);
        let mut signed = authenticator.sign(unsigned, &serializer).unwrap();
        if let ProtocolMessage::LeaseReject(payload) = &mut signed.unsigned.message {
            payload.code = WitnessMutationOutcomeCode::RetiredStale;
        } else {
            unreachable!();
        }
        assert!(signed.unsigned.validate().is_ok());
        assert!(matches!(
            authenticator.verify(&signed, &serializer),
            Err(AuthenticationError::InvalidMac)
        ));
    }

    #[test]
    fn tampering_lease_reject_reason_is_detected() {
        let serializer = CborSerializer;
        let authenticator = MessageAuthenticator::new(psk());
        let unsigned = lease_reject_envelope(WitnessMutationOutcomeCode::PolicyReject);
        let mut signed = authenticator.sign(unsigned, &serializer).unwrap();
        if let ProtocolMessage::LeaseReject(payload) = &mut signed.unsigned.message {
            payload.reason = "changed".to_string();
        } else {
            unreachable!();
        }
        assert!(signed.unsigned.validate().is_ok());
        assert!(matches!(
            authenticator.verify(&signed, &serializer),
            Err(AuthenticationError::InvalidMac)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_and_non_regular_file() {
        let target = temp_path("target");
        let link = temp_path("link");
        fs::write(&target, vec![b'0'; PSK_HEX_BYTES]).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(matches!(Psk::load(&link), Err(PskError::InsecureFile(_))));
        fs::remove_file(&link).unwrap();
        fs::remove_file(&target).unwrap();

        let directory = temp_path("directory");
        fs::create_dir(&directory).unwrap();
        assert!(matches!(
            Psk::load(&directory),
            Err(PskError::InsecureFile(_))
        ));
        fs::remove_dir(&directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_insecure_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let path = temp_path("permissions");
        fs::write(&path, vec![b'0'; PSK_HEX_BYTES]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(Psk::load(&path), Err(PskError::InsecureFile(_))));
        fs::remove_file(&path).unwrap();
    }
}
