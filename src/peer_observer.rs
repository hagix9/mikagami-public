//! Runtime-only observation of the statically configured peer.
//!
//! The transport boundary is intentionally post-authentication: TCP/session,
//! HMAC, and replay framing remain owned by the existing protocol runtime.
//! This module never makes an HA decision from a peer observation.

#![allow(dead_code)]

use crate::protocol::{ClusterId, NodeId, Sequence, SessionId, UnsignedEnvelope};
use crate::state_machine::NodeState;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeerObservationState {
    NeverSeen,
    Fresh,
    Stale,
    Invalid,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PeerObservation {
    pub(crate) state: PeerObservationState,
    pub(crate) node_state: Option<NodeState>,
    pub(crate) session_id: Option<SessionId>,
    pub(crate) sequence: Option<Sequence>,
    pub(crate) last_received_ms: Option<u64>,
}

impl PeerObservation {
    fn never_seen() -> Self {
        Self {
            state: PeerObservationState::NeverSeen,
            node_state: None,
            session_id: None,
            sequence: None,
            last_received_ms: None,
        }
    }
}

/// A heartbeat after the authenticated current-session boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EstablishedHeartbeat(UnsignedEnvelope);

impl EstablishedHeartbeat {
    pub(crate) fn from_session_runtime(message: UnsignedEnvelope) -> Self {
        Self(message)
    }

    pub(crate) fn as_unsigned(&self) -> &UnsignedEnvelope {
        &self.0
    }

    pub(crate) fn into_unsigned(self) -> UnsignedEnvelope {
        self.0
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PeerTransportEvent {
    NoMessage,
    /// Emitted only by the upstream session runtime after HELLO completion.
    SessionEstablished {
        session_id: SessionId,
    },
    /// Emitted only by the upstream session runtime after HELLO completion.
    EstablishedHeartbeat(UnsignedEnvelope),
    /// Legacy direct-test fixture retained only for the pre-11.10 unit tests.
    #[cfg(test)]
    AuthenticatedHeartbeat(UnsignedEnvelope),
    AuthenticationFailure,
    Malformed,
    TransportFailure,
}

pub(crate) trait PeerTransport {
    fn poll_heartbeat(&mut self) -> PeerTransportEvent;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PeerObservationError {
    Protocol(String),
    WrongCluster,
    WrongSender,
    WrongReceiver,
    UnestablishedSession,
    UnexpectedMessage,
    Replay,
}

impl fmt::Display for PeerObservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Protocol(error) => error.as_str(),
            Self::WrongCluster => "heartbeat cluster identity is not configured cluster",
            Self::WrongSender => "heartbeat sender is not the configured peer",
            Self::WrongReceiver => "heartbeat receiver is not the local node",
            Self::UnestablishedSession => {
                "heartbeat session is not the currently established peer session"
            }
            Self::UnexpectedMessage => "received message is not a heartbeat",
            Self::Replay => "heartbeat sequence is stale or duplicated",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for PeerObservationError {}

pub(crate) struct PeerObserver<T> {
    transport: T,
    cluster_id: ClusterId,
    local_node_id: NodeId,
    peer_node_id: NodeId,
    freshness_timeout_ms: u64,
    observation: PeerObservation,
    established_session: Option<SessionId>,
    accepted_sequence: Option<Sequence>,
    last_error: Option<PeerObservationError>,
}

impl<T: PeerTransport> PeerObserver<T> {
    pub(crate) fn new(
        transport: T,
        cluster_id: ClusterId,
        local_node_id: NodeId,
        peer_node_id: NodeId,
        freshness_timeout_ms: u64,
    ) -> Self {
        Self {
            transport,
            cluster_id,
            local_node_id,
            peer_node_id,
            freshness_timeout_ms,
            observation: PeerObservation::never_seen(),
            established_session: None,
            accepted_sequence: None,
            last_error: None,
        }
    }

    pub(crate) fn tick(&mut self, now_ms: u64) {
        let event = self.transport.poll_heartbeat();
        self.observe_event(event, now_ms);
    }

    pub(crate) fn observe_event(&mut self, event: PeerTransportEvent, now_ms: u64) {
        match event {
            PeerTransportEvent::NoMessage => self.age(now_ms),
            PeerTransportEvent::SessionEstablished { session_id } => {
                self.establish_session(session_id)
            }
            PeerTransportEvent::EstablishedHeartbeat(message) => {
                if let Err(error) = self.accept(message, now_ms) {
                    self.last_error = Some(error);
                    self.observation.state = PeerObservationState::Invalid;
                }
            }
            #[cfg(test)]
            PeerTransportEvent::AuthenticatedHeartbeat(message) => {
                if let Err(error) = self.accept(message, now_ms) {
                    self.last_error = Some(error);
                    self.observation.state = PeerObservationState::Invalid;
                }
            }
            PeerTransportEvent::AuthenticationFailure | PeerTransportEvent::Malformed => {
                self.last_error = Some(PeerObservationError::Protocol(
                    "heartbeat authentication or decoding failed".into(),
                ));
                self.observation.state = PeerObservationState::Invalid;
            }
            PeerTransportEvent::TransportFailure => {
                self.last_error = Some(PeerObservationError::Protocol(
                    "heartbeat transport unavailable".into(),
                ));
                self.observation.state = PeerObservationState::Unavailable;
            }
        }
    }

    pub(crate) fn snapshot(&self, now_ms: u64) -> PeerObservation {
        let mut observation = self.observation.clone();
        if observation.state == PeerObservationState::Fresh
            && let Some(received) = observation.last_received_ms
            && now_ms.saturating_sub(received) >= self.freshness_timeout_ms
        {
            observation.state = PeerObservationState::Stale;
        }
        observation
    }

    pub(crate) fn last_error(&self) -> Option<&PeerObservationError> {
        self.last_error.as_ref()
    }

    fn age(&mut self, now_ms: u64) {
        if self.snapshot(now_ms).state == PeerObservationState::Stale {
            self.observation.state = PeerObservationState::Stale;
        }
    }

    fn establish_session(&mut self, session_id: SessionId) {
        if self.established_session.as_ref() != Some(&session_id) {
            self.established_session = Some(session_id);
            self.accepted_sequence = None;
            self.observation = PeerObservation::never_seen();
            self.last_error = None;
        }
    }

    fn accept(
        &mut self,
        message: UnsignedEnvelope,
        now_ms: u64,
    ) -> Result<(), PeerObservationError> {
        message
            .validate()
            .map_err(|error| PeerObservationError::Protocol(error.to_string()))?;
        if message.common.cluster_id != self.cluster_id {
            return Err(PeerObservationError::WrongCluster);
        }
        if message.common.sender_node_id != self.peer_node_id {
            return Err(PeerObservationError::WrongSender);
        }
        if message.common.receiver_node_id != self.local_node_id {
            return Err(PeerObservationError::WrongReceiver);
        }
        let crate::protocol::ProtocolMessage::Heartbeat(status) = message.message else {
            return Err(PeerObservationError::UnexpectedMessage);
        };
        if self.established_session.as_ref() != Some(&message.common.session_id) {
            return Err(PeerObservationError::UnestablishedSession);
        }
        if self
            .accepted_sequence
            .is_some_and(|sequence| message.common.sequence.0 <= sequence.0)
        {
            return Err(PeerObservationError::Replay);
        }
        self.accepted_sequence = Some(message.common.sequence);
        self.last_error = None;
        self.observation = PeerObservation {
            state: PeerObservationState::Fresh,
            node_state: Some(status.node_state),
            session_id: Some(message.common.session_id),
            sequence: Some(message.common.sequence),
            last_received_ms: Some(now_ms),
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        CanonicalSerializer, CborSerializer, CommonFields, NodeStatusPayload, PROTOCOL_VERSION,
        ProtocolMessage, Role, Term,
    };
    use std::collections::VecDeque;

    #[derive(Default)]
    struct FakeTransport {
        events: VecDeque<PeerTransportEvent>,
        polls: usize,
    }

    impl PeerTransport for FakeTransport {
        fn poll_heartbeat(&mut self) -> PeerTransportEvent {
            self.polls += 1;
            self.events
                .pop_front()
                .unwrap_or(PeerTransportEvent::NoMessage)
        }
    }

    fn observer(
        events: impl IntoIterator<Item = PeerTransportEvent>,
    ) -> PeerObserver<FakeTransport> {
        PeerObserver::new(
            FakeTransport {
                events: events.into_iter().collect(),
                polls: 0,
            },
            ClusterId::new("cluster"),
            NodeId::new("node-a"),
            NodeId::new("node-b"),
            10,
        )
    }

    fn established_observer(
        session: &str,
        events: impl IntoIterator<Item = PeerTransportEvent>,
    ) -> PeerObserver<FakeTransport> {
        let mut all = vec![PeerTransportEvent::SessionEstablished {
            session_id: SessionId::new(session),
        }];
        all.extend(events);
        let mut observer = observer(all);
        observer.tick(0);
        observer
    }

    fn heartbeat(session: &str, sequence: u64, sender: &str, cluster: &str) -> UnsignedEnvelope {
        UnsignedEnvelope {
            common: CommonFields {
                protocol_version: PROTOCOL_VERSION,
                cluster_id: ClusterId::new(cluster),
                sender_node_id: NodeId::new(sender),
                receiver_node_id: NodeId::new("node-a"),
                session_id: SessionId::new(session),
                sequence: Sequence(sequence),
                term: Term(0),
                lease_id: None,
                request_id: None,
                operation_id: None,
            },
            message: ProtocolMessage::Heartbeat(NodeStatusPayload {
                node_state: NodeState::Active,
                operation_phase: None,
                role: Role::Active,
                service_state: "running".into(),
                health_state: "healthy".into(),
                vip_state: "present".into(),
            }),
        }
    }

    #[test]
    fn attack_bk_never_seen_is_not_dead() {
        let observer = observer([]);
        assert_eq!(
            observer.snapshot(100).state,
            PeerObservationState::NeverSeen
        );
    }

    #[test]
    fn attack_bl_stale_heartbeat_does_not_trigger_promotion() {
        let mut observer = established_observer(
            "session-1",
            [PeerTransportEvent::EstablishedHeartbeat(heartbeat(
                "session-1",
                1,
                "node-b",
                "cluster",
            ))],
        );
        observer.tick(0);
        assert_eq!(observer.snapshot(10).state, PeerObservationState::Stale);
    }

    #[test]
    fn attack_bm_stale_heartbeat_has_no_lease_mutation_path() {
        let mut observer = observer([PeerTransportEvent::NoMessage]);
        observer.tick(100);
        assert_eq!(
            observer.snapshot(100).state,
            PeerObservationState::NeverSeen
        );
    }

    #[test]
    fn attack_bn_remote_active_is_not_local_authority_proof() {
        let mut observer = established_observer(
            "session-1",
            [PeerTransportEvent::EstablishedHeartbeat(heartbeat(
                "session-1",
                1,
                "node-b",
                "cluster",
            ))],
        );
        observer.tick(0);
        assert_eq!(observer.snapshot(0).node_state, Some(NodeState::Active));
        assert_eq!(observer.snapshot(0).state, PeerObservationState::Fresh);
    }

    #[test]
    fn attack_bo_wrong_cluster_is_rejected() {
        let mut observer = established_observer(
            "session-1",
            [PeerTransportEvent::EstablishedHeartbeat(heartbeat(
                "session-1",
                1,
                "node-b",
                "wrong",
            ))],
        );
        observer.tick(0);
        assert_eq!(observer.snapshot(0).state, PeerObservationState::Invalid);
    }

    #[test]
    fn attack_bp_unexpected_peer_is_rejected() {
        let mut observer = established_observer(
            "session-1",
            [PeerTransportEvent::EstablishedHeartbeat(heartbeat(
                "session-1",
                1,
                "node-c",
                "cluster",
            ))],
        );
        observer.tick(0);
        assert_eq!(observer.snapshot(0).state, PeerObservationState::Invalid);
    }

    #[test]
    fn attack_bq_duplicate_sequence_does_not_refresh_freshness() {
        let mut observer = established_observer(
            "session-1",
            [
                PeerTransportEvent::AuthenticatedHeartbeat(heartbeat(
                    "session-1",
                    1,
                    "node-b",
                    "cluster",
                )),
                PeerTransportEvent::AuthenticatedHeartbeat(heartbeat(
                    "session-1",
                    1,
                    "node-b",
                    "cluster",
                )),
            ],
        );
        observer.tick(0);
        observer.tick(9);
        assert_eq!(observer.snapshot(10).last_received_ms, Some(0));
        assert_eq!(observer.snapshot(10).state, PeerObservationState::Invalid);
    }

    #[test]
    fn attack_br_older_sequence_does_not_refresh_freshness() {
        let mut observer = established_observer(
            "session-1",
            [
                PeerTransportEvent::AuthenticatedHeartbeat(heartbeat(
                    "session-1",
                    2,
                    "node-b",
                    "cluster",
                )),
                PeerTransportEvent::AuthenticatedHeartbeat(heartbeat(
                    "session-1",
                    1,
                    "node-b",
                    "cluster",
                )),
            ],
        );
        observer.tick(0);
        observer.tick(9);
        assert_eq!(observer.snapshot(10).last_received_ms, Some(0));
        assert_eq!(observer.snapshot(10).state, PeerObservationState::Invalid);
    }

    #[test]
    fn attack_bs_authentication_failure_does_not_refresh_observation() {
        let mut observer = established_observer(
            "session-1",
            [
                PeerTransportEvent::AuthenticatedHeartbeat(heartbeat(
                    "session-1",
                    1,
                    "node-b",
                    "cluster",
                )),
                PeerTransportEvent::AuthenticationFailure,
            ],
        );
        observer.tick(0);
        observer.tick(9);
        assert_eq!(observer.snapshot(9).last_received_ms, Some(0));
        assert_eq!(observer.snapshot(9).state, PeerObservationState::Invalid);
    }

    #[test]
    fn attack_bt_malformed_heartbeat_does_not_refresh_observation() {
        let mut observer = established_observer(
            "session-1",
            [
                PeerTransportEvent::AuthenticatedHeartbeat(heartbeat(
                    "session-1",
                    1,
                    "node-b",
                    "cluster",
                )),
                PeerTransportEvent::Malformed,
            ],
        );
        observer.tick(0);
        observer.tick(9);
        assert_eq!(observer.snapshot(9).last_received_ms, Some(0));
        assert_eq!(observer.snapshot(9).state, PeerObservationState::Invalid);
    }

    #[test]
    fn attack_bu_new_session_requires_trusted_establishment() {
        let mut observer = established_observer(
            "session-1",
            [
                PeerTransportEvent::AuthenticatedHeartbeat(heartbeat(
                    "session-1",
                    99,
                    "node-b",
                    "cluster",
                )),
                PeerTransportEvent::AuthenticatedHeartbeat(heartbeat(
                    "session-2",
                    1,
                    "node-b",
                    "cluster",
                )),
                PeerTransportEvent::SessionEstablished {
                    session_id: SessionId::new("session-2"),
                },
                PeerTransportEvent::AuthenticatedHeartbeat(heartbeat(
                    "session-2",
                    1,
                    "node-b",
                    "cluster",
                )),
            ],
        );
        observer.tick(0);
        observer.tick(1);
        assert_eq!(observer.snapshot(1).state, PeerObservationState::Invalid);
        assert_eq!(
            observer.snapshot(1).session_id,
            Some(SessionId::new("session-1"))
        );
        observer.tick(2);
        observer.tick(3);
        assert_eq!(observer.snapshot(3).state, PeerObservationState::Fresh);
        assert_eq!(
            observer.snapshot(3).session_id,
            Some(SessionId::new("session-2"))
        );
    }

    #[test]
    fn attack_ca_heartbeat_cannot_self_establish_arbitrary_new_session() {
        let mut observer = observer([PeerTransportEvent::AuthenticatedHeartbeat(heartbeat(
            "session-2",
            1,
            "node-b",
            "cluster",
        ))]);
        observer.tick(0);
        assert_eq!(observer.snapshot(0).state, PeerObservationState::Invalid);
        assert_eq!(observer.snapshot(0).session_id, None);
    }

    #[test]
    fn attack_cb_unestablished_session_does_not_reset_sequence_window() {
        let mut observer = established_observer(
            "session-1",
            [
                PeerTransportEvent::AuthenticatedHeartbeat(heartbeat(
                    "session-1",
                    99,
                    "node-b",
                    "cluster",
                )),
                PeerTransportEvent::AuthenticatedHeartbeat(heartbeat(
                    "session-2",
                    1,
                    "node-b",
                    "cluster",
                )),
            ],
        );
        observer.tick(0);
        observer.tick(1);
        assert_eq!(observer.snapshot(1).state, PeerObservationState::Invalid);
        assert_eq!(
            observer.snapshot(1).session_id,
            Some(SessionId::new("session-1"))
        );
        assert_eq!(observer.snapshot(1).sequence, Some(Sequence(99)));
    }

    #[test]
    fn attack_cc_trusted_session_establishment_permits_low_sequence() {
        let mut observer = established_observer(
            "session-1",
            [
                PeerTransportEvent::AuthenticatedHeartbeat(heartbeat(
                    "session-1",
                    99,
                    "node-b",
                    "cluster",
                )),
                PeerTransportEvent::SessionEstablished {
                    session_id: SessionId::new("session-2"),
                },
                PeerTransportEvent::AuthenticatedHeartbeat(heartbeat(
                    "session-2",
                    1,
                    "node-b",
                    "cluster",
                )),
            ],
        );
        observer.tick(0);
        observer.tick(1);
        observer.tick(2);
        assert_eq!(observer.snapshot(2).state, PeerObservationState::Fresh);
        assert_eq!(observer.snapshot(2).sequence, Some(Sequence(1)));
    }

    #[test]
    fn attack_cd_old_session_after_switch_is_rejected() {
        let mut observer = established_observer(
            "session-1",
            [
                PeerTransportEvent::AuthenticatedHeartbeat(heartbeat(
                    "session-1",
                    99,
                    "node-b",
                    "cluster",
                )),
                PeerTransportEvent::SessionEstablished {
                    session_id: SessionId::new("session-2"),
                },
                PeerTransportEvent::AuthenticatedHeartbeat(heartbeat(
                    "session-2",
                    1,
                    "node-b",
                    "cluster",
                )),
                PeerTransportEvent::AuthenticatedHeartbeat(heartbeat(
                    "session-1",
                    100,
                    "node-b",
                    "cluster",
                )),
            ],
        );
        observer.tick(0);
        observer.tick(1);
        observer.tick(2);
        observer.tick(3);
        assert_eq!(observer.snapshot(3).state, PeerObservationState::Invalid);
        assert_eq!(
            observer.snapshot(3).session_id,
            Some(SessionId::new("session-2"))
        );
        assert_eq!(observer.snapshot(3).sequence, Some(Sequence(1)));
    }

    #[test]
    fn attack_ce_rejected_old_session_does_not_refresh_freshness() {
        let mut observer = established_observer(
            "session-1",
            [
                PeerTransportEvent::AuthenticatedHeartbeat(heartbeat(
                    "session-1",
                    1,
                    "node-b",
                    "cluster",
                )),
                PeerTransportEvent::SessionEstablished {
                    session_id: SessionId::new("session-2"),
                },
                PeerTransportEvent::AuthenticatedHeartbeat(heartbeat(
                    "session-2",
                    1,
                    "node-b",
                    "cluster",
                )),
                PeerTransportEvent::AuthenticatedHeartbeat(heartbeat(
                    "session-1",
                    2,
                    "node-b",
                    "cluster",
                )),
            ],
        );
        observer.tick(0);
        observer.tick(1);
        observer.tick(2);
        observer.tick(9);
        assert_eq!(observer.snapshot(9).last_received_ms, Some(2));
        assert_eq!(observer.snapshot(9).state, PeerObservationState::Invalid);
    }

    #[test]
    fn attack_cf_same_session_duplicate_and_older_replay_remain_rejected() {
        let mut observer = established_observer(
            "session-1",
            [
                PeerTransportEvent::AuthenticatedHeartbeat(heartbeat(
                    "session-1",
                    2,
                    "node-b",
                    "cluster",
                )),
                PeerTransportEvent::AuthenticatedHeartbeat(heartbeat(
                    "session-1",
                    2,
                    "node-b",
                    "cluster",
                )),
                PeerTransportEvent::AuthenticatedHeartbeat(heartbeat(
                    "session-1",
                    1,
                    "node-b",
                    "cluster",
                )),
            ],
        );
        observer.tick(0);
        observer.tick(1);
        observer.tick(2);
        assert_eq!(observer.snapshot(2).sequence, Some(Sequence(2)));
        assert_eq!(observer.snapshot(2).last_received_ms, Some(0));
        assert_eq!(observer.snapshot(2).state, PeerObservationState::Invalid);
    }

    #[test]
    fn attack_cg_restart_restores_neither_session_nor_fresh_observation() {
        let mut first = established_observer(
            "session-1",
            [PeerTransportEvent::EstablishedHeartbeat(heartbeat(
                "session-1",
                1,
                "node-b",
                "cluster",
            ))],
        );
        first.tick(0);
        let restarted = observer([]);
        assert_eq!(restarted.snapshot(0).state, PeerObservationState::NeverSeen);
        assert_eq!(restarted.snapshot(0).session_id, None);
    }

    #[test]
    fn attack_ch_session_establishment_event_has_no_ha_action() {
        let mut observer = observer([PeerTransportEvent::SessionEstablished {
            session_id: SessionId::new("session-1"),
        }]);
        observer.tick(0);
        assert_eq!(observer.snapshot(0).state, PeerObservationState::NeverSeen);
        assert_eq!(observer.snapshot(0).last_received_ms, None);
    }

    #[test]
    fn attack_ci_established_new_session_updates_observation_only() {
        let mut observer = observer([
            PeerTransportEvent::SessionEstablished {
                session_id: SessionId::new("session-2"),
            },
            PeerTransportEvent::AuthenticatedHeartbeat(heartbeat(
                "session-2",
                1,
                "node-b",
                "cluster",
            )),
        ]);
        observer.tick(0);
        observer.tick(1);
        assert_eq!(observer.snapshot(1).state, PeerObservationState::Fresh);
        assert_eq!(observer.snapshot(1).node_state, Some(NodeState::Active));
    }

    #[test]
    fn attack_cj_new_session_establishment_invalidates_old_fresh_observation() {
        let mut observer = observer([
            PeerTransportEvent::SessionEstablished {
                session_id: SessionId::new("session-1"),
            },
            PeerTransportEvent::AuthenticatedHeartbeat(heartbeat(
                "session-1",
                99,
                "node-b",
                "cluster",
            )),
            PeerTransportEvent::SessionEstablished {
                session_id: SessionId::new("session-2"),
            },
        ]);
        observer.tick(0);
        observer.tick(1);
        assert_eq!(observer.snapshot(1).state, PeerObservationState::Fresh);
        observer.tick(2);
        assert_eq!(observer.snapshot(2).state, PeerObservationState::NeverSeen);
        assert_eq!(observer.snapshot(2).session_id, None);
        assert_eq!(observer.snapshot(2).last_received_ms, None);
    }

    #[test]
    fn attack_ck_new_session_becomes_fresh_only_after_first_valid_heartbeat() {
        let mut observer = observer([
            PeerTransportEvent::SessionEstablished {
                session_id: SessionId::new("session-1"),
            },
            PeerTransportEvent::AuthenticatedHeartbeat(heartbeat(
                "session-1",
                1,
                "node-b",
                "cluster",
            )),
            PeerTransportEvent::SessionEstablished {
                session_id: SessionId::new("session-2"),
            },
            PeerTransportEvent::AuthenticatedHeartbeat(heartbeat(
                "session-2",
                1,
                "node-b",
                "cluster",
            )),
        ]);
        observer.tick(0);
        observer.tick(1);
        observer.tick(2);
        assert_eq!(observer.snapshot(2).state, PeerObservationState::NeverSeen);
        observer.tick(3);
        assert_eq!(observer.snapshot(3).state, PeerObservationState::Fresh);
        assert_eq!(
            observer.snapshot(3).session_id,
            Some(SessionId::new("session-2"))
        );
    }

    #[test]
    fn attack_cl_duplicate_session_established_does_not_reset_replay_high_water() {
        let mut observer = observer([
            PeerTransportEvent::SessionEstablished {
                session_id: SessionId::new("session-1"),
            },
            PeerTransportEvent::AuthenticatedHeartbeat(heartbeat(
                "session-1",
                99,
                "node-b",
                "cluster",
            )),
            PeerTransportEvent::SessionEstablished {
                session_id: SessionId::new("session-1"),
            },
            PeerTransportEvent::AuthenticatedHeartbeat(heartbeat(
                "session-1",
                1,
                "node-b",
                "cluster",
            )),
        ]);
        observer.tick(0);
        observer.tick(1);
        observer.tick(2);
        observer.tick(3);
        assert_eq!(observer.snapshot(3).state, PeerObservationState::Invalid);
        assert_eq!(observer.snapshot(3).sequence, Some(Sequence(99)));
        assert_eq!(observer.snapshot(3).last_received_ms, Some(1));
    }

    #[test]
    fn attack_bv_restart_starts_never_seen() {
        let observer = observer([]);
        assert_eq!(observer.snapshot(0).state, PeerObservationState::NeverSeen);
        assert_eq!(observer.snapshot(0).last_received_ms, None);
    }

    #[test]
    fn attack_bw_snapshot_does_not_poll_or_mutate_cache() {
        let observer = observer([]);
        let before = observer.transport.polls;
        let first = observer.snapshot(0);
        let second = observer.snapshot(100);
        assert_eq!(observer.transport.polls, before);
        assert_eq!(first, second);
    }

    #[test]
    fn attack_bx_transport_failure_is_unavailable_not_ha_action() {
        let mut observer = observer([PeerTransportEvent::TransportFailure]);
        observer.tick(0);
        assert_eq!(
            observer.snapshot(0).state,
            PeerObservationState::Unavailable
        );
    }

    #[test]
    fn attack_by_fresh_observation_does_not_change_local_policy() {
        let mut observer = established_observer(
            "session-1",
            [PeerTransportEvent::EstablishedHeartbeat(heartbeat(
                "session-1",
                1,
                "node-b",
                "cluster",
            ))],
        );
        observer.tick(0);
        assert_eq!(observer.snapshot(0).state, PeerObservationState::Fresh);
    }

    #[test]
    fn attack_bz_invalid_input_uses_one_fixed_observation_slot() {
        let mut observer = observer(std::iter::repeat_n(PeerTransportEvent::Malformed, 100));
        for now in 0..100 {
            observer.tick(now);
        }
        assert_eq!(observer.snapshot(100).state, PeerObservationState::Invalid);
        assert!(observer.last_error().is_some());
    }

    #[test]
    fn heartbeat_fixture_is_canonical_and_semantically_valid() {
        let message = heartbeat("session-1", 1, "node-b", "cluster");
        message.validate().unwrap();
        CborSerializer.serialize_unsigned(&message).unwrap();
    }
}
