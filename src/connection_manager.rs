use crate::handshake::HandshakeResult;
use crate::protocol::{NodeId, Sequence, SessionId};
use std::collections::VecDeque;
use std::fmt;

const RETIRED_SESSION_HISTORY_LIMIT: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionDirection {
    Inbound,
    Outbound,
}

pub fn canonical_direction(
    local_node_id: &NodeId,
    peer_node_id: &NodeId,
) -> Result<ConnectionDirection, DirectionError> {
    match local_node_id.as_str().cmp(peer_node_id.as_str()) {
        std::cmp::Ordering::Less => Ok(ConnectionDirection::Outbound),
        std::cmp::Ordering::Greater => Ok(ConnectionDirection::Inbound),
        std::cmp::Ordering::Equal => Err(DirectionError::SameNodeId),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectionError {
    SameNodeId,
}

impl fmt::Display for DirectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SameNodeId => write!(f, "local and peer node IDs must differ"),
        }
    }
}

impl std::error::Error for DirectionError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerReplayState {
    session_id: SessionId,
    highest_accepted_sequence: Sequence,
}

impl PeerReplayState {
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub const fn highest_accepted_sequence(&self) -> Sequence {
        self.highest_accepted_sequence
    }
}

pub struct PeerConnectionManager {
    local_node_id: NodeId,
    peer_node_id: NodeId,
    canonical_direction: ConnectionDirection,
    replay_state: Option<PeerReplayState>,
    retired_session_ids: VecDeque<SessionId>,
    connection: Option<crate::tcp::TcpConnection>,
}

impl PeerConnectionManager {
    pub fn new(local_node_id: NodeId, peer_node_id: NodeId) -> Result<Self, DirectionError> {
        let canonical_direction = canonical_direction(&local_node_id, &peer_node_id)?;
        Ok(Self {
            local_node_id,
            peer_node_id,
            canonical_direction,
            replay_state: None,
            retired_session_ids: VecDeque::new(),
            connection: None,
        })
    }

    pub const fn canonical_direction(&self) -> ConnectionDirection {
        self.canonical_direction
    }

    pub fn local_node_id(&self) -> &NodeId {
        &self.local_node_id
    }

    pub fn peer_node_id(&self) -> &NodeId {
        &self.peer_node_id
    }

    pub fn replay_state(&self) -> Option<&PeerReplayState> {
        self.replay_state.as_ref()
    }

    pub fn has_connection(&self) -> bool {
        self.connection.is_some()
    }

    pub fn connection_mut(&mut self) -> Option<&mut crate::tcp::TcpConnection> {
        self.connection.as_mut()
    }

    pub fn take_connection(&mut self) -> Option<crate::tcp::TcpConnection> {
        self.connection.take()
    }

    /// Commits an already authenticated and peer-validated observation for
    /// the current peer session. This function performs no authentication or
    /// message validation of its own.
    pub(crate) fn commit_peer_sequence(
        &mut self,
        session_id: &SessionId,
        sequence: Sequence,
    ) -> Result<(), PeerSequenceCommitError> {
        let replay_state = self
            .replay_state
            .as_mut()
            .ok_or(PeerSequenceCommitError::MissingReplayState)?;
        if replay_state.session_id != *session_id {
            return Err(PeerSequenceCommitError::SessionMismatch);
        }
        if sequence.0 <= replay_state.highest_accepted_sequence.0 {
            return Err(PeerSequenceCommitError::StaleOrDuplicate);
        }
        replay_state.highest_accepted_sequence = sequence;
        Ok(())
    }

    pub fn adopt(
        &mut self,
        direction: ConnectionDirection,
        result: HandshakeResult,
    ) -> AdoptionResult {
        if direction != self.canonical_direction {
            return AdoptionResult::RejectedNonCanonical;
        }

        let session_id = result.peer_session_id.clone();
        let sequence = result.peer_last_accepted_sequence;
        if self
            .retired_session_ids
            .iter()
            .any(|retired| retired == &session_id)
        {
            return AdoptionResult::RejectedRetired;
        }

        if let Some(current) = &self.replay_state {
            if current.session_id == session_id {
                if sequence.0 <= current.highest_accepted_sequence.0 {
                    return AdoptionResult::RejectedStale;
                }
            } else {
                self.retire_current_session();
            }
        }

        self.replay_state = Some(PeerReplayState {
            session_id,
            highest_accepted_sequence: sequence,
        });
        self.connection = Some(result.connection);
        AdoptionResult::Adopted
    }

    fn retire_current_session(&mut self) {
        if let Some(current) = self.replay_state.take() {
            self.retired_session_ids.push_back(current.session_id);
            while self.retired_session_ids.len() > RETIRED_SESSION_HISTORY_LIMIT {
                self.retired_session_ids.pop_front();
            }
        }
        self.connection = None;
    }

    #[cfg(test)]
    fn retired_session_count(&self) -> usize {
        self.retired_session_ids.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdoptionResult {
    Adopted,
    RejectedNonCanonical,
    RejectedStale,
    RejectedRetired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerSequenceCommitError {
    MissingReplayState,
    SessionMismatch,
    StaleOrDuplicate,
}

impl fmt::Display for PeerSequenceCommitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::MissingReplayState => "peer replay state is not available",
            Self::SessionMismatch => "peer session_id does not match replay state",
            Self::StaleOrDuplicate => "peer sequence is stale or duplicate",
        };
        write!(f, "{message}")
    }
}

impl std::error::Error for PeerSequenceCommitError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::HandshakeResult;
    use crate::protocol::SessionId;
    use crate::tcp::TcpConnection;
    use std::net::TcpListener;
    use std::time::Duration;

    const TIMEOUT: Duration = Duration::from_secs(2);

    fn connection() -> TcpConnection {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let client = TcpConnection::connect(address, TIMEOUT, TIMEOUT, TIMEOUT).unwrap();
        let (stream, _) = listener.accept().unwrap();
        drop(stream);
        client
    }

    fn result(session_id: &str, sequence: u64) -> HandshakeResult {
        HandshakeResult {
            connection: connection(),
            peer_session_id: SessionId::new(session_id),
            peer_last_accepted_sequence: Sequence(sequence),
        }
    }

    fn manager() -> PeerConnectionManager {
        PeerConnectionManager::new(NodeId::new("node-a"), NodeId::new("node-b")).unwrap()
    }

    #[test]
    fn chooses_canonical_direction_from_node_ids() {
        assert_eq!(
            canonical_direction(&NodeId::new("node-a"), &NodeId::new("node-b")),
            Ok(ConnectionDirection::Outbound)
        );
        assert_eq!(
            canonical_direction(&NodeId::new("node-b"), &NodeId::new("node-a")),
            Ok(ConnectionDirection::Inbound)
        );
        assert_eq!(
            canonical_direction(&NodeId::new("same"), &NodeId::new("same")),
            Err(DirectionError::SameNodeId)
        );
        assert!(PeerConnectionManager::new(NodeId::new("same"), NodeId::new("same")).is_err());
    }

    #[test]
    fn adopts_first_canonical_connection_and_stores_observation() {
        let mut manager = manager();
        assert_eq!(
            manager.adopt(ConnectionDirection::Outbound, result("peer-a", 7)),
            AdoptionResult::Adopted
        );
        assert!(manager.has_connection());
        let before = manager.replay_state().cloned();
        assert!(manager.connection_mut().is_some());
        assert!(manager.has_connection());
        assert_eq!(manager.replay_state().cloned(), before);
        let state = manager.replay_state().unwrap();
        assert_eq!(state.session_id().as_str(), "peer-a");
        assert_eq!(state.highest_accepted_sequence(), Sequence(7));
    }

    #[test]
    fn rejects_noncanonical_connection_without_changing_state() {
        let mut manager = manager();
        assert_eq!(
            manager.adopt(ConnectionDirection::Inbound, result("peer-a", 7)),
            AdoptionResult::RejectedNonCanonical
        );
        assert!(!manager.has_connection());
        assert!(manager.connection_mut().is_none());
        assert!(manager.replay_state().is_none());
    }

    #[test]
    fn accepts_same_session_only_with_higher_sequence() {
        let mut manager = manager();
        assert_eq!(
            manager.adopt(ConnectionDirection::Outbound, result("peer-a", 40)),
            AdoptionResult::Adopted
        );
        assert_eq!(
            manager.adopt(ConnectionDirection::Outbound, result("peer-a", 40)),
            AdoptionResult::RejectedStale
        );
        assert_eq!(
            manager.adopt(ConnectionDirection::Outbound, result("peer-a", 39)),
            AdoptionResult::RejectedStale
        );
        assert_eq!(
            manager.adopt(ConnectionDirection::Outbound, result("peer-a", 41)),
            AdoptionResult::Adopted
        );
        assert_eq!(
            manager.replay_state().unwrap().highest_accepted_sequence(),
            Sequence(41)
        );
    }

    #[test]
    fn accepts_new_session_and_retires_previous_session() {
        let mut manager = manager();
        manager.adopt(ConnectionDirection::Outbound, result("peer-a", 100));
        assert_eq!(
            manager.adopt(ConnectionDirection::Outbound, result("peer-b", 1)),
            AdoptionResult::Adopted
        );
        assert_eq!(
            manager.replay_state().unwrap().session_id().as_str(),
            "peer-b"
        );
        assert_eq!(manager.retired_session_count(), 1);
        assert!(manager.has_connection());
    }

    #[test]
    fn rejects_return_of_retired_session() {
        let mut manager = manager();
        manager.adopt(ConnectionDirection::Outbound, result("peer-a", 100));
        manager.adopt(ConnectionDirection::Outbound, result("peer-b", 1));
        assert_eq!(
            manager.adopt(ConnectionDirection::Outbound, result("peer-a", 101)),
            AdoptionResult::RejectedRetired
        );
        assert_eq!(
            manager.replay_state().unwrap().session_id().as_str(),
            "peer-b"
        );
    }

    #[test]
    fn bounds_retired_session_history() {
        let mut manager = manager();
        for index in 0..(RETIRED_SESSION_HISTORY_LIMIT + 3) {
            manager.adopt(
                ConnectionDirection::Outbound,
                result(&format!("peer-{index}"), 1),
            );
        }
        assert_eq!(
            manager.retired_session_count(),
            RETIRED_SESSION_HISTORY_LIMIT
        );
    }

    #[test]
    fn replaces_existing_canonical_connection() {
        let mut manager = manager();
        assert_eq!(
            manager.adopt(ConnectionDirection::Outbound, result("peer-a", 1)),
            AdoptionResult::Adopted
        );
        assert_eq!(
            manager.adopt(ConnectionDirection::Outbound, result("peer-a", 2)),
            AdoptionResult::Adopted
        );
        assert!(manager.has_connection());
    }

    #[test]
    fn taking_connection_removes_only_connection_ownership() {
        let mut manager = manager();
        manager.adopt(ConnectionDirection::Outbound, result("peer-a", 7));
        let connection = manager.take_connection();
        assert!(connection.is_some());
        assert!(!manager.has_connection());
        assert_eq!(
            manager.replay_state().unwrap().session_id().as_str(),
            "peer-a"
        );
        assert_eq!(
            manager.replay_state().unwrap().highest_accepted_sequence(),
            Sequence(7)
        );
    }

    #[test]
    fn rejected_candidate_does_not_poison_state() {
        let mut manager = manager();
        manager.adopt(ConnectionDirection::Outbound, result("peer-a", 40));
        assert_eq!(
            manager.adopt(ConnectionDirection::Outbound, result("peer-a", 39)),
            AdoptionResult::RejectedStale
        );
        assert_eq!(
            manager.replay_state().unwrap().highest_accepted_sequence(),
            Sequence(40)
        );
        assert_eq!(
            manager.adopt(ConnectionDirection::Outbound, result("peer-b", 1)),
            AdoptionResult::Adopted
        );
    }
}
