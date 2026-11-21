//! The two-node peer messages and their authenticated link encoding.
//!
//! This is a separate wire from the frozen Protocol v1 (which the Witness topology keeps
//! using unchanged). A distinct 8-byte magic and an HMAC domain string make a frame of one
//! wire unacceptable to the other.
//!
//! Link session rules (per TCP connection, `LinkSession`):
//! * Each side opens with `Hello` carrying a fresh random nonce (no receiver nonce yet).
//! * Every later message carries the sender's nonce and the receiver's nonce, and a sequence
//!   number that is exactly the previous one plus one. A message replayed from another
//!   connection or reordered fails; any violation closes the connection.
//! * `ack` is the highest sequence number of ours the peer has received on this
//!   connection. A link is *up* only while acknowledged traffic is fresh (both directions),
//!   so an asymmetric loss takes the link down on both sides.
//!
//! A received message is an authenticated observation only. No message carries authority
//! by itself: the controller applies every gate.

use crate::security::Psk;
use serde::{Deserialize, Serialize};

pub const MAGIC: &[u8; 8] = b"MKG2N\x00\x01\x00";
const MAC_DOMAIN: &[u8] = b"mikagami-two-node-wire-v1\x00";
const MAC_LEN: usize = 32;

/// The role a node announces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    /// Not owning; resources confirmed absent only when `zero_resource` is true.
    Standby,
    /// Durably owns an epoch and is acquiring resources.
    Promoting,
    /// Owns an epoch and holds the resources.
    Active,
    /// Releasing resources (startup cleanup, demotion, shutdown).
    Demoting,
    /// Resources uncertain or a safety contradiction: never promotes, never grants.
    Blocked,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standby => "standby",
            Self::Promoting => "promoting",
            Self::Active => "active",
            Self::Demoting => "demoting",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantView {
    pub claim_id: String,
    pub epoch: u64,
    pub grantee: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimView {
    pub claim_id: String,
    pub epoch: u64,
}

/// The periodically announced state of one node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerState {
    pub incarnation: String,
    /// Increases whenever the announcing controller publishes a new state; an older
    /// announcement (for example from the slower link) is ignored.
    pub state_seq: u64,
    pub role: Role,
    pub epoch: u64,
    pub owner: Option<String>,
    /// A trusted local observation: service stopped and VIP absent.
    pub zero_resource: bool,
    /// Willing to own (not over its start-failure limit, not cleanup-only, no contradiction).
    pub eligible: bool,
    pub grant: Option<GrantView>,
    pub claim: Option<ClaimView>,
    /// Shutting down after releasing: the peer may claim at once (planned handover).
    pub leaving: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Control {
    /// Ask the peer to durably grant `epoch` to the claimant incarnation.
    Claim {
        claim_id: String,
        epoch: u64,
        claimant_incarnation: String,
    },
    /// The peer durably recorded the grant before sending this.
    Grant {
        claim_id: String,
        epoch: u64,
        grantee_incarnation: String,
    },
    Refuse {
        claim_id: String,
        reason: String,
    },
    /// The claimant will never act on this claim (late grants are ignored).
    Abandon {
        claim_id: String,
    },
}

/// What the runtime hands the controller after authentication and session checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerMessage {
    Announce(PeerState),
    Control {
        msg_id: String,
        from_incarnation: String,
        body: Control,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum WireBody {
    Hello {
        incarnation: String,
        /// The configuration summary of a shared configuration file (`two_node::shared`).
        /// Absent for a per-node file, so a per-node file stays wire-compatible with the
        /// previous release; a binary of the previous release refuses a `Hello` that has it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        config: Option<String>,
    },
    Announce {
        state: PeerState,
    },
    Control {
        msg_id: String,
        incarnation: String,
        body: Control,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub cluster: String,
    pub from: String,
    pub to: String,
    pub link: u8,
    pub sender_nonce: String,
    pub receiver_nonce: Option<String>,
    pub seq: u64,
    pub ack: u64,
    pub body: WireBody,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    BadMagic,
    Short,
    BadMac,
    Malformed,
    WrongIdentity,
    NotHelloFirst,
    UnexpectedHello,
    WrongNonce,
    Sequence,
    /// An authenticated `Hello` of the configured peer whose configuration summary differs
    /// from ours (`peer` is its summary). The peer is alive but incompatible.
    ConfigMismatch {
        peer: Option<String>,
    },
}

pub fn encode(psk: &Psk, envelope: &Envelope) -> Vec<u8> {
    let body = serde_json::to_vec(envelope).expect("envelope serializes");
    let mac = psk.hmac_parts(&[MAC_DOMAIN, &body]);
    let mut payload = Vec::with_capacity(MAGIC.len() + MAC_LEN + body.len());
    payload.extend_from_slice(MAGIC);
    payload.extend_from_slice(&mac);
    payload.extend_from_slice(&body);
    payload
}

/// Verifies the magic and the MAC over the exact received bytes, then parses.
pub fn decode(psk: &Psk, payload: &[u8]) -> Result<Envelope, WireError> {
    if payload.len() < MAGIC.len() + MAC_LEN + 2 {
        return Err(WireError::Short);
    }
    if &payload[..MAGIC.len()] != MAGIC {
        return Err(WireError::BadMagic);
    }
    let mac = &payload[MAGIC.len()..MAGIC.len() + MAC_LEN];
    let body = &payload[MAGIC.len() + MAC_LEN..];
    if !psk.verify_parts(&[MAC_DOMAIN, body], mac) {
        return Err(WireError::BadMac);
    }
    serde_json::from_slice(body).map_err(|_| WireError::Malformed)
}

pub fn fresh_nonce() -> Option<String> {
    crate::node_mutation::generate_uuid()
}

/// Per-connection session state (pure; the runtime owns the socket).
#[derive(Debug, Clone)]
pub struct LinkSession {
    pub cluster: String,
    pub local: String,
    pub peer: String,
    pub link: u8,
    pub local_nonce: String,
    pub local_incarnation: String,
    peer_nonce: Option<String>,
    peer_incarnation: Option<String>,
    next_send_seq: u64,
    last_recv_seq: u64,
    /// The highest of our sequence numbers the peer acknowledged.
    pub peer_ack: u64,
    /// Our configuration summary; the peer's `Hello` must carry the same.
    local_config: Option<String>,
}

impl LinkSession {
    pub fn new(
        cluster: &str,
        local: &str,
        peer: &str,
        link: u8,
        local_nonce: String,
        local_incarnation: String,
    ) -> Self {
        Self {
            cluster: cluster.to_string(),
            local: local.to_string(),
            peer: peer.to_string(),
            link,
            local_nonce,
            local_incarnation,
            peer_nonce: None,
            peer_incarnation: None,
            next_send_seq: 1,
            last_recv_seq: 0,
            peer_ack: 0,
            local_config: None,
        }
    }

    /// Sets the configuration summary the peer's `Hello` must match.
    pub fn with_config(mut self, summary: Option<String>) -> Self {
        self.local_config = summary;
        self
    }

    pub fn local_config(&self) -> Option<&str> {
        self.local_config.as_deref()
    }

    pub fn peer_incarnation(&self) -> Option<&str> {
        self.peer_incarnation.as_deref()
    }

    pub fn established(&self) -> bool {
        self.peer_nonce.is_some()
    }

    /// Builds the next outgoing envelope and returns its sequence number. `Hello` must be
    /// the first message; later bodies need an established session.
    pub fn outgoing(&mut self, body: WireBody) -> Option<(u64, Envelope)> {
        let hello = matches!(body, WireBody::Hello { .. });
        if hello != (self.next_send_seq == 1) {
            return None;
        }
        if !hello && self.peer_nonce.is_none() {
            return None;
        }
        let seq = self.next_send_seq;
        self.next_send_seq = self.next_send_seq.checked_add(1)?;
        Some((
            seq,
            Envelope {
                cluster: self.cluster.clone(),
                from: self.local.clone(),
                to: self.peer.clone(),
                link: self.link,
                sender_nonce: self.local_nonce.clone(),
                receiver_nonce: self.peer_nonce.clone(),
                seq,
                ack: self.last_recv_seq,
                body,
            },
        ))
    }

    /// Checks one authenticated envelope against this session. `Ok(None)` for the peer's
    /// `Hello`; `Ok(Some(message))` for a message to hand to the controller.
    pub fn accept(&mut self, envelope: Envelope) -> Result<Option<PeerMessage>, WireError> {
        if envelope.cluster != self.cluster
            || envelope.from != self.peer
            || envelope.to != self.local
            || envelope.link != self.link
        {
            return Err(WireError::WrongIdentity);
        }
        if envelope.seq
            != self
                .last_recv_seq
                .checked_add(1)
                .ok_or(WireError::Sequence)?
        {
            return Err(WireError::Sequence);
        }
        match (&self.peer_nonce, &envelope.body) {
            (
                None,
                WireBody::Hello {
                    incarnation,
                    config,
                },
            ) => {
                if envelope.receiver_nonce.is_some() || envelope.ack != 0 {
                    return Err(WireError::NotHelloFirst);
                }
                if envelope.sender_nonce.is_empty() || incarnation.is_empty() {
                    return Err(WireError::Malformed);
                }
                // Checked only after the MAC (decode) and the identity: an authenticated
                // peer with a different configuration. The session is never established.
                if config.as_deref() != self.local_config.as_deref() {
                    return Err(WireError::ConfigMismatch {
                        peer: config.clone(),
                    });
                }
                self.peer_nonce = Some(envelope.sender_nonce.clone());
                self.peer_incarnation = Some(incarnation.clone());
                self.last_recv_seq = envelope.seq;
                Ok(None)
            }
            (None, _) => Err(WireError::NotHelloFirst),
            (Some(_), WireBody::Hello { .. }) => Err(WireError::UnexpectedHello),
            (Some(peer_nonce), _) => {
                if &envelope.sender_nonce != peer_nonce
                    || envelope.receiver_nonce.as_deref() != Some(self.local_nonce.as_str())
                {
                    return Err(WireError::WrongNonce);
                }
                if envelope.ack >= self.next_send_seq {
                    return Err(WireError::Sequence);
                }
                self.last_recv_seq = envelope.seq;
                self.peer_ack = self.peer_ack.max(envelope.ack);
                let incarnation = self.peer_incarnation.clone().unwrap_or_default();
                match envelope.body {
                    WireBody::Announce { state } => {
                        if state.incarnation != incarnation {
                            return Err(WireError::WrongIdentity);
                        }
                        Ok(Some(PeerMessage::Announce(state)))
                    }
                    WireBody::Control {
                        msg_id,
                        incarnation: from,
                        body,
                    } => {
                        if from != incarnation {
                            return Err(WireError::WrongIdentity);
                        }
                        Ok(Some(PeerMessage::Control {
                            msg_id,
                            from_incarnation: from,
                            body,
                        }))
                    }
                    WireBody::Hello { .. } => Err(WireError::UnexpectedHello),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn psk(byte: u8) -> Psk {
        Psk::from_test_bytes([byte; 32])
    }

    fn state(incarnation: &str) -> PeerState {
        PeerState {
            incarnation: incarnation.into(),
            state_seq: 1,
            role: Role::Standby,
            epoch: 0,
            owner: None,
            zero_resource: true,
            eligible: true,
            grant: None,
            claim: None,
            leaving: false,
        }
    }

    fn pair() -> (LinkSession, LinkSession) {
        (
            LinkSession::new("c", "a", "b", 0, "na".into(), "ia".into()),
            LinkSession::new("c", "b", "a", 0, "nb".into(), "ib".into()),
        )
    }

    fn handshake(a: &mut LinkSession, b: &mut LinkSession, key: &Psk) {
        let (_, hello_a) = a
            .outgoing(WireBody::Hello {
                incarnation: "ia".into(),
                config: None,
            })
            .unwrap();
        let (_, hello_b) = b
            .outgoing(WireBody::Hello {
                incarnation: "ib".into(),
                config: None,
            })
            .unwrap();
        assert_eq!(
            b.accept(decode(key, &encode(key, &hello_a)).unwrap()),
            Ok(None)
        );
        assert_eq!(
            a.accept(decode(key, &encode(key, &hello_b)).unwrap()),
            Ok(None)
        );
    }

    #[test]
    fn authenticated_round_trip_and_ack() {
        let key = psk(1);
        let (mut a, mut b) = pair();
        handshake(&mut a, &mut b, &key);
        let (seq, envelope) = a
            .outgoing(WireBody::Announce { state: state("ia") })
            .unwrap();
        assert_eq!(seq, 2);
        let message = b
            .accept(decode(&key, &encode(&key, &envelope)).unwrap())
            .unwrap();
        assert_eq!(message, Some(PeerMessage::Announce(state("ia"))));
        let (_, reply) = b
            .outgoing(WireBody::Announce { state: state("ib") })
            .unwrap();
        assert_eq!(reply.ack, 2);
        a.accept(reply).unwrap();
        assert_eq!(a.peer_ack, 2);
    }

    #[test]
    fn wrong_key_magic_or_tamper_is_rejected() {
        let (mut a, _) = pair();
        let (_, hello) = a
            .outgoing(WireBody::Hello {
                incarnation: "ia".into(),
                config: None,
            })
            .unwrap();
        let bytes = encode(&psk(1), &hello);
        assert_eq!(decode(&psk(2), &bytes), Err(WireError::BadMac));
        let mut tampered = bytes.clone();
        let last = tampered.len() - 2;
        tampered[last] ^= 1;
        assert_eq!(decode(&psk(1), &tampered), Err(WireError::BadMac));
        let mut wrong_magic = bytes.clone();
        wrong_magic[0] = b'X';
        assert_eq!(decode(&psk(1), &wrong_magic), Err(WireError::BadMagic));
        assert_eq!(decode(&psk(1), &bytes[..10]), Err(WireError::Short));
    }

    #[test]
    fn replay_across_connections_and_reorder_fail() {
        let key = psk(1);
        let (mut a, mut b) = pair();
        handshake(&mut a, &mut b, &key);
        let (_, first) = a
            .outgoing(WireBody::Announce { state: state("ia") })
            .unwrap();
        let (_, second) = a
            .outgoing(WireBody::Announce { state: state("ia") })
            .unwrap();
        // Reordering (second before first) fails.
        let mut reorder = b.clone();
        assert_eq!(reorder.accept(second.clone()), Err(WireError::Sequence));
        // Replay of the same message fails.
        b.accept(first.clone()).unwrap();
        assert_eq!(b.accept(first.clone()), Err(WireError::Sequence));
        // A new connection (fresh nonces) rejects the old connection's messages.
        let mut b2 = LinkSession::new("c", "b", "a", 0, "nb2".into(), "ib".into());
        let mut a2 = LinkSession::new("c", "a", "b", 0, "na2".into(), "ia".into());
        handshake(&mut a2, &mut b2, &key);
        let mut replayed = second;
        replayed.seq = 2;
        assert_eq!(b2.accept(replayed), Err(WireError::WrongNonce));
    }

    #[test]
    fn hello_rules_and_identity() {
        let (mut a, mut b) = pair();
        assert!(
            a.outgoing(WireBody::Announce { state: state("ia") })
                .is_none()
        );
        let (_, hello) = a
            .outgoing(WireBody::Hello {
                incarnation: "ia".into(),
                config: None,
            })
            .unwrap();
        assert!(
            a.outgoing(WireBody::Hello {
                incarnation: "ia".into(),
                config: None,
            })
            .is_none()
        );
        let mut wrong = hello.clone();
        wrong.cluster = "other".into();
        assert_eq!(b.clone().accept(wrong), Err(WireError::WrongIdentity));
        let mut wrong_link = hello.clone();
        wrong_link.link = 1;
        assert_eq!(b.clone().accept(wrong_link), Err(WireError::WrongIdentity));
        b.accept(hello.clone()).unwrap();
        let mut again = hello;
        again.seq = 2;
        assert_eq!(b.accept(again), Err(WireError::UnexpectedHello));
    }

    #[test]
    fn announce_incarnation_must_match_hello_and_ack_cannot_exceed_sent() {
        let key = psk(1);
        let (mut a, mut b) = pair();
        handshake(&mut a, &mut b, &key);
        let (_, envelope) = a
            .outgoing(WireBody::Announce {
                state: state("other"),
            })
            .unwrap();
        assert_eq!(
            b.clone().accept(envelope.clone()),
            Err(WireError::WrongIdentity)
        );
        let mut bad_ack = envelope;
        bad_ack.body = WireBody::Announce { state: state("ia") };
        bad_ack.ack = 99;
        assert_eq!(b.accept(bad_ack), Err(WireError::Sequence));
    }

    #[test]
    fn a_hello_with_another_configuration_summary_is_refused_after_authentication() {
        let key = psk(1);
        for (mine, theirs) in [
            (Some("vip=1"), Some("vip=2")),
            (Some("vip=1"), None),
            (None, Some("vip=1")),
        ] {
            let mut a = LinkSession::new("c", "a", "b", 0, "na".into(), "ia".into())
                .with_config(theirs.map(String::from));
            let mut b = LinkSession::new("c", "b", "a", 0, "nb".into(), "ib".into())
                .with_config(mine.map(String::from));
            let (_, hello_a) = a
                .outgoing(WireBody::Hello {
                    incarnation: "ia".into(),
                    config: theirs.map(String::from),
                })
                .unwrap();
            assert_eq!(
                b.accept(decode(&key, &encode(&key, &hello_a)).unwrap()),
                Err(WireError::ConfigMismatch {
                    peer: theirs.map(String::from)
                })
            );
            assert!(
                !b.established(),
                "a mismatched hello never establishes the session"
            );
        }
        // The same summary on both sides establishes the session.
        let mut a = LinkSession::new("c", "a", "b", 0, "na".into(), "ia".into())
            .with_config(Some("s".into()));
        let mut b = LinkSession::new("c", "b", "a", 0, "nb".into(), "ib".into())
            .with_config(Some("s".into()));
        let (_, hello_a) = a
            .outgoing(WireBody::Hello {
                incarnation: "ia".into(),
                config: Some("s".into()),
            })
            .unwrap();
        assert_eq!(
            b.accept(decode(&key, &encode(&key, &hello_a)).unwrap()),
            Ok(None)
        );
        assert!(b.established());
    }

    #[test]
    fn a_mismatched_hello_from_a_wrong_identity_is_an_identity_error_not_a_mismatch() {
        let key = psk(1);
        let mut a = LinkSession::new("c", "x", "b", 0, "na".into(), "ia".into());
        let mut b = LinkSession::new("c", "b", "a", 0, "nb".into(), "ib".into())
            .with_config(Some("s".into()));
        let (_, hello) = a
            .outgoing(WireBody::Hello {
                incarnation: "ia".into(),
                config: Some("other".into()),
            })
            .unwrap();
        assert_eq!(
            b.accept(decode(&key, &encode(&key, &hello)).unwrap()),
            Err(WireError::WrongIdentity)
        );
        // A forged MAC never reaches the comparison.
        let mut bytes = encode(&key, &hello);
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert!(decode(&key, &bytes).is_err());
    }

    #[test]
    fn a_hello_without_a_summary_has_no_config_field_on_the_wire() {
        let mut a = LinkSession::new("c", "a", "b", 0, "na".into(), "ia".into());
        let (_, hello) = a
            .outgoing(WireBody::Hello {
                incarnation: "ia".into(),
                config: None,
            })
            .unwrap();
        let text = serde_json::to_string(&hello).unwrap();
        assert!(!text.contains("config"), "{text}");
    }
}
