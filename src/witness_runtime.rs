use crate::protocol::{
    CborSerializer, ClusterId, LeaseGrantPayload, LeaseId, LeaseRejectPayload, LeaseReleasePayload,
    LeaseReleasedPayload, LeaseRenewPayload, LeaseRequestPayload, MessageType, NodeId,
    ProtocolError, ProtocolMessage, RequestId, Sequence, SessionId, Term, TermStatusPayload,
    UnsignedEnvelope,
};
use crate::receive::{AuthenticatedMessage, ReceiveError};
use crate::security::MessageAuthenticator;
use crate::session::{ProcessSession, SequenceError};
use crate::tcp::{ReceiveMessageResult, TcpConnection, TcpError};
use crate::transport::TransportError;
use std::fmt;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessRequestKind {
    GetTerm,
    LeaseRequest,
    LeaseRenew,
    LeaseRelease,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessResponseKind {
    TermStatus,
    LeaseGrant,
    LeaseRenewed,
    LeaseReleased,
    LeaseReject,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WitnessOutstandingMutationIdentity {
    pub generation: u64,
    pub term: Term,
    pub lease_id: LeaseId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessRequestOutstandingState {
    pub request_id: RequestId,
    pub request_kind: WitnessRequestKind,
    mutation_identity: Option<WitnessOutstandingMutationIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessRequestOutstanding {
    Idle,
    AwaitingResponse(WitnessRequestOutstandingState),
}

impl WitnessRequestOutstanding {
    pub const fn new() -> Self {
        Self::Idle
    }
    pub fn state(&self) -> &Self {
        self
    }
    fn begin(
        &mut self,
        request_id: RequestId,
        request_kind: WitnessRequestKind,
        mutation_identity: Option<WitnessOutstandingMutationIdentity>,
    ) -> Result<(), WitnessRuntimeError> {
        if !matches!(self, Self::Idle) {
            return Err(WitnessRuntimeError::RequestAlreadyOutstanding);
        }
        *self = Self::AwaitingResponse(WitnessRequestOutstandingState {
            request_id,
            request_kind,
            mutation_identity,
        });
        Ok(())
    }
    fn complete(&mut self) {
        *self = Self::Idle;
    }
}
impl Default for WitnessRequestOutstanding {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessMessageKind {
    GetTerm,
    TermStatus,
    LeaseRequest,
    LeaseGrant,
    LeaseRenew,
    LeaseRenewed,
    LeaseRelease,
    LeaseReleased,
    LeaseReject,
}
impl WitnessMessageKind {
    fn from_message(message: &ProtocolMessage) -> Result<Self, WitnessRuntimeError> {
        Ok(match message.message_type() {
            MessageType::GetTerm => Self::GetTerm,
            MessageType::TermStatus => Self::TermStatus,
            MessageType::LeaseRequest => Self::LeaseRequest,
            MessageType::LeaseGrant => Self::LeaseGrant,
            MessageType::LeaseRenew => Self::LeaseRenew,
            MessageType::LeaseRenewed => Self::LeaseRenewed,
            MessageType::LeaseRelease => Self::LeaseRelease,
            MessageType::LeaseReleased => Self::LeaseReleased,
            MessageType::LeaseReject => Self::LeaseReject,
            _ => return Err(WitnessRuntimeError::DisallowedMessage),
        })
    }
    fn is_request(self) -> bool {
        matches!(
            self,
            Self::GetTerm | Self::LeaseRequest | Self::LeaseRenew | Self::LeaseRelease
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingWitnessMessage {
    message: AuthenticatedMessage,
    pub kind: WitnessMessageKind,
}
impl PendingWitnessMessage {
    pub fn message(&self) -> &AuthenticatedMessage {
        &self.message
    }
    pub fn sequence(&self) -> Sequence {
        self.message.unsigned().common.sequence
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessRequestObservation {
    GetTerm {
        request_id: RequestId,
        sender_node_id: NodeId,
        term: Term,
    },
    LeaseRequest {
        request_id: RequestId,
        sender_node_id: NodeId,
        term: Term,
        lease_id: Option<LeaseId>,
        payload: LeaseRequestPayload,
    },
    LeaseRenew {
        request_id: RequestId,
        sender_node_id: NodeId,
        term: Term,
        lease_id: Option<LeaseId>,
        payload: LeaseRenewPayload,
    },
    LeaseRelease {
        request_id: RequestId,
        sender_node_id: NodeId,
        term: Term,
        lease_id: Option<LeaseId>,
        payload: LeaseReleasePayload,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessResponseObservation {
    TermStatus(TermStatusPayload),
    LeaseGrant(LeaseGrantPayload),
    LeaseRenewed(LeaseGrantPayload),
    LeaseReleased(LeaseReleasedPayload),
    LeaseReject(LeaseRejectPayload),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessResponseContext {
    pub term: Term,
    pub lease_id: Option<LeaseId>,
}

#[derive(Debug)]
pub enum WitnessRuntimeError {
    Tcp(TcpError),
    Receive(ReceiveError),
    Protocol(ProtocolError),
    Sequence(SequenceError),
    DisallowedMessage,
    WrongIdentity,
    WrongCluster,
    WrongSession,
    StaleOrDuplicate,
    WrongMessageKind,
    MissingRequestId,
    RequestAlreadyOutstanding,
    NoOutstandingRequest,
    /// Every bounded attempt to find the response of the outstanding request
    /// only produced late responses of earlier requests.
    UncorrelatedResponsesExhausted,
    /// The Witness closed the connection (clean EOF) or the socket was
    /// already closed by this end. This is a permanent session failure, never
    /// a lease outcome and never a reason to retry on the same session.
    SessionClosed,
    RequestIdMismatch {
        expected: RequestId,
        actual: RequestId,
    },
    ResponseKindMismatch {
        request: WitnessRequestKind,
        response: WitnessResponseKind,
    },
}
impl fmt::Display for WitnessRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "witness runtime error: {:?}", self)
    }
}
impl std::error::Error for WitnessRuntimeError {}

/// Whether a Witness exchange error proves the connection is gone for good.
///
/// Only closure/reset/truncation qualify. A timeout, `WouldBlock` or any
/// protocol/authentication rejection leaves the transport status unknown: it
/// is not a lost session, the connection may still be usable, and the safety
/// layers continue to treat its authority as unproven.
pub(crate) fn session_terminated(error: &WitnessRuntimeError) -> bool {
    match error {
        WitnessRuntimeError::SessionClosed => true,
        // Frame reads/writes wrap the io error in `TransportError::Io`; a
        // direct `TcpError::Io` comes from the socket-mode/connect paths.
        // Both must classify identically (the adapter's `terminal()` does).
        WitnessRuntimeError::Tcp(TcpError::Io(error))
        | WitnessRuntimeError::Tcp(TcpError::Transport(TransportError::Io(error))) => matches!(
            error.kind(),
            std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::NotConnected
        ),
        WitnessRuntimeError::Tcp(TcpError::Transport(
            TransportError::TruncatedPrefix | TransportError::TruncatedPayload,
        )) => true,
        _ => false,
    }
}

pub struct WitnessConnection {
    local_node_id: NodeId,
    witness_id: NodeId,
    cluster_id: ClusterId,
    peer_session_id: SessionId,
    provenance: Arc<()>,
    highest_sequence: Sequence,
    connection: TcpConnection,
}

#[derive(Debug)]
pub(crate) enum WitnessPoll {
    Pending(Box<PendingWitnessMessage>, Arc<()>),
    NoFrame,
    Eof,
}
impl WitnessConnection {
    pub fn new(
        local_node_id: NodeId,
        witness_id: NodeId,
        cluster_id: ClusterId,
        peer_session_id: SessionId,
        connection: TcpConnection,
    ) -> Self {
        Self {
            local_node_id,
            witness_id,
            cluster_id,
            peer_session_id,
            provenance: Arc::new(()),
            highest_sequence: Sequence(0),
            connection,
        }
    }
    fn send(
        &mut self,
        message: UnsignedEnvelope,
        serializer: &CborSerializer,
        auth: &MessageAuthenticator,
    ) -> Result<(), WitnessRuntimeError> {
        self.connection
            .send_message(message, serializer, auth)
            .map_err(WitnessRuntimeError::Tcp)
    }
    pub fn receive_pending(
        &mut self,
        serializer: &CborSerializer,
        auth: &MessageAuthenticator,
    ) -> Result<PendingWitnessMessage, WitnessRuntimeError> {
        let ReceiveMessageResult::Message(message) = self
            .connection
            .receive_message(serializer, auth)
            .map_err(WitnessRuntimeError::Tcp)?
        else {
            // A clean EOF is a closed session, not a malformed frame. The
            // distinction matters: requests cannot make progress on a closed
            // session, while a malformed frame is a protocol fault.
            return Err(WitnessRuntimeError::SessionClosed);
        };
        self.validate_received(*message)
    }

    pub(crate) fn poll_pending(
        &mut self,
        serializer: &CborSerializer,
        auth: &MessageAuthenticator,
    ) -> Result<WitnessPoll, WitnessRuntimeError> {
        use crate::tcp::PollFrameResult;
        match self
            .connection
            .poll_payload()
            .map_err(WitnessRuntimeError::Tcp)?
        {
            PollFrameResult::NoFrame => Ok(WitnessPoll::NoFrame),
            PollFrameResult::Eof => Ok(WitnessPoll::Eof),
            PollFrameResult::Frame(bytes) => {
                let message = crate::receive::receive(&bytes, serializer, auth)
                    .map_err(WitnessRuntimeError::Receive)?;
                self.validate_received(message)
                    .map(Box::new)
                    .map(|pending| WitnessPoll::Pending(pending, Arc::clone(&self.provenance)))
            }
        }
    }

    fn validate_received(
        &self,
        message: AuthenticatedMessage,
    ) -> Result<PendingWitnessMessage, WitnessRuntimeError> {
        let common = &message.unsigned().common;
        if common.cluster_id != self.cluster_id {
            return Err(WitnessRuntimeError::WrongCluster);
        }
        if common.sender_node_id != self.witness_id || common.receiver_node_id != self.local_node_id
        {
            return Err(WitnessRuntimeError::WrongIdentity);
        }
        if common.session_id != self.peer_session_id {
            return Err(WitnessRuntimeError::WrongSession);
        }
        if common.sequence.0 <= self.highest_sequence.0 {
            return Err(WitnessRuntimeError::StaleOrDuplicate);
        }
        let kind = WitnessMessageKind::from_message(&message.unsigned().message)?;
        Ok(PendingWitnessMessage { message, kind })
    }
    fn commit(&mut self, pending: &PendingWitnessMessage) -> Result<(), WitnessRuntimeError> {
        if pending.message.unsigned().common.sequence.0 <= self.highest_sequence.0 {
            return Err(WitnessRuntimeError::StaleOrDuplicate);
        }
        self.highest_sequence = pending.sequence();
        Ok(())
    }
    pub fn highest_sequence(&self) -> Sequence {
        self.highest_sequence
    }

    pub(crate) fn provenance(&self) -> Arc<()> {
        Arc::clone(&self.provenance)
    }

    fn close(&mut self) {
        self.connection.close();
    }

    fn probe_closed(&mut self) -> Result<bool, TcpError> {
        self.connection.peek_closed()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn is_closed(&self) -> bool {
        self.connection.is_closed()
    }

    #[cfg(all(test, unix))]
    pub(crate) fn wait_for_readable_for_test(&mut self) -> Result<(), TcpError> {
        self.connection.wait_for_readable_for_test()
    }
}

/// Neutral Witness transport/session owner.
///
/// This is communication/session infrastructure only. It groups the one
/// physical `WitnessConnection`, the one `ProcessSession`, the one
/// `MessageAuthenticator`, and the one shared `WitnessRequestOutstanding` that
/// together form a single authenticated Witness session. It performs no
/// failover policy, promotion authorization, evidence classification, or
/// resource mutation, and it does not hold authority tokens.
///
/// Both Witness observation (GET_TERM) and future lease operations are intended
/// to borrow this one session so there is exactly one physical connection and
/// one outstanding request slot for the logical session.
///
/// Session-loss contract (v0.6 A-1):
/// - A closed/reset connection is detected by any exchange (send, receive,
///   poll) and latches `lost`; the socket is closed at the same moment so a
///   peer FIN never leaves a descriptor in `CLOSE_WAIT` for the process
///   lifetime.
/// - A lost session is never reused: every further request/response attempt
///   fails with `SessionClosed`, and the caller must stop and reconnect
///   through a new handshake (a new `ProcessSession`, sequence space and
///   epoch). Nothing from the old session is carried over.
/// - A timeout is not a lost session.
pub(crate) struct WitnessSession {
    connection: WitnessConnection,
    process: ProcessSession,
    authenticator: MessageAuthenticator,
    outstanding: WitnessRequestOutstanding,
    lost: bool,
}

#[allow(dead_code)]
impl WitnessSession {
    pub(crate) fn new(
        connection: WitnessConnection,
        process: ProcessSession,
        authenticator: MessageAuthenticator,
    ) -> Self {
        Self {
            connection,
            process,
            authenticator,
            outstanding: WitnessRequestOutstanding::new(),
            lost: false,
        }
    }

    /// Whether this session is permanently unusable. Once true it never
    /// returns to false: the only safe recovery is a new session.
    pub(crate) fn lost(&self) -> bool {
        self.lost
    }

    /// Mark the session lost and release the socket at once.
    /// Idempotent. Does not touch the outstanding slot or any authority; the
    /// callers keep their own fail-closed handling.
    pub(crate) fn mark_lost(&mut self) {
        self.lost = true;
        self.connection.close();
    }

    /// Voluntary close (shutdown). Releases the socket without declaring the
    /// session lost; the process is ending.
    pub(crate) fn close(&mut self) {
        self.connection.close();
    }

    /// Detect a closed connection without sending anything and without
    /// consuming an inbound frame. An idle Standby has no request to fail, so
    /// this is how a stopped Witness is noticed before the next promotion
    /// attempt: `true` means the session was (or already is) lost, and the
    /// socket has been released.
    ///
    /// A transport error other than a clean FIN is reported as `false`: the
    /// session is not known to be dead, and this probe never decides safety.
    pub(crate) fn probe_transport_closure(&mut self) -> bool {
        if self.lost {
            return true;
        }
        match self.connection.probe_closed() {
            Ok(true) => {
                self.mark_lost();
                true
            }
            Ok(false) | Err(_) => false,
        }
    }

    /// Latch a permanent transport failure. Any closed/reset/truncated
    /// connection is a lost session; timeouts and protocol faults are not.
    fn observe_error(&mut self, error: &WitnessRuntimeError) {
        if session_terminated(error) {
            self.mark_lost();
        }
    }

    fn require_live(&self) -> Result<(), WitnessRuntimeError> {
        if self.lost {
            return Err(WitnessRuntimeError::SessionClosed);
        }
        Ok(())
    }

    /// Send one GET_TERM using the shared session/outstanding slot.
    pub(crate) fn send_get_term(
        &mut self,
        request_id: RequestId,
    ) -> Result<(), WitnessRuntimeError> {
        self.require_live()?;
        let result = send_get_term(
            &mut self.connection,
            &mut self.process,
            &mut self.outstanding,
            request_id,
            &CborSerializer,
            &self.authenticator,
        );
        if let Err(error) = &result {
            self.observe_error(error);
        }
        result
    }

    /// Send one LeaseRequest through the same single outstanding slot used by
    /// observation. No second slot or session exists for lease traffic.
    pub(crate) fn send_lease_request(
        &mut self,
        request_id: RequestId,
        payload: LeaseRequestPayload,
    ) -> Result<(), WitnessRuntimeError> {
        self.require_live()?;
        let result = send_lease_request(
            &mut self.connection,
            &mut self.process,
            &mut self.outstanding,
            request_id,
            payload,
            &CborSerializer,
            &self.authenticator,
        );
        if let Err(error) = &result {
            self.observe_error(error);
        }
        result
    }

    /// Send one LeaseRenew through the shared outstanding slot.
    pub(crate) fn send_lease_renew(
        &mut self,
        request_id: RequestId,
        payload: LeaseRenewPayload,
    ) -> Result<(), WitnessRuntimeError> {
        self.require_live()?;
        let result = send_lease_renew(
            &mut self.connection,
            &mut self.process,
            &mut self.outstanding,
            request_id,
            payload,
            &CborSerializer,
            &self.authenticator,
        );
        if let Err(error) = &result {
            self.observe_error(error);
        }
        result
    }

    /// Send one LeaseRelease through the shared outstanding slot. Cleanup uses
    /// the same single slot as observation and acquisition.
    pub(crate) fn send_lease_release(
        &mut self,
        request_id: RequestId,
        payload: LeaseReleasePayload,
    ) -> Result<(), WitnessRuntimeError> {
        self.require_live()?;
        let result = send_lease_release(
            &mut self.connection,
            &mut self.process,
            &mut self.outstanding,
            request_id,
            payload,
            &CborSerializer,
            &self.authenticator,
        );
        if let Err(error) = &result {
            self.observe_error(error);
        }
        result
    }

    /// Blocking receive of the next framed Witness message for the caller
    /// that currently borrows this session. Completion consumption is owned
    /// by that borrower only.
    pub(crate) fn receive_pending(&mut self) -> Result<PendingWitnessMessage, WitnessRuntimeError> {
        self.require_live()?;
        let result = self
            .connection
            .receive_pending(&CborSerializer, &self.authenticator);
        if let Err(error) = &result {
            self.observe_error(error);
        }
        result
    }

    /// Whether the shared outstanding slot is occupied.
    pub(crate) fn request_in_flight(&self) -> bool {
        !matches!(self.outstanding, WitnessRequestOutstanding::Idle)
    }

    /// Identity of the request currently owning the sole session slot.
    /// Callers use this to join an exact durable retry owner without sending
    /// a duplicate request; no response or authority state is exposed here.
    pub(crate) fn outstanding_identity(&self) -> Option<(RequestId, WitnessRequestKind)> {
        match &self.outstanding {
            WitnessRequestOutstanding::Idle => None,
            WitnessRequestOutstanding::AwaitingResponse(state) => {
                Some((state.request_id.clone(), state.request_kind))
            }
        }
    }

    pub(crate) fn outstanding_renew_identity(&self) -> Option<(RequestId, u64, Term, LeaseId)> {
        let WitnessRequestOutstanding::AwaitingResponse(state) = &self.outstanding else {
            return None;
        };
        if state.request_kind != WitnessRequestKind::LeaseRenew {
            return None;
        }
        let identity = state.mutation_identity.as_ref()?;
        Some((
            state.request_id.clone(),
            identity.generation,
            identity.term,
            identity.lease_id.clone(),
        ))
    }

    /// Nonblocking poll of the next framed Witness message.
    ///
    /// A clean EOF latches the session as lost and releases the socket at the
    /// same call: the poll's caller (observation) must not keep a dead
    /// connection open while it decides what the loss means for safety.
    pub(crate) fn poll_pending(&mut self) -> Result<WitnessPoll, WitnessRuntimeError> {
        self.require_live()?;
        let result = self
            .connection
            .poll_pending(&CborSerializer, &self.authenticator);
        match &result {
            Ok(WitnessPoll::Eof) => self.mark_lost(),
            Err(error) => self.observe_error(error),
            Ok(WitnessPoll::NoFrame | WitnessPoll::Pending(_, _)) => {}
        }
        result
    }

    /// Correlate and commit a pending Witness response against the shared
    /// outstanding slot.
    pub(crate) fn handle_pending_response(
        &mut self,
        pending: &PendingWitnessMessage,
    ) -> Result<WitnessResponseObservation, WitnessRuntimeError> {
        handle_pending_witness_response(&mut self.connection, pending, &mut self.outstanding)
    }

    /// Phase 14.12 F1 (A2): acknowledge a late response of a generation the
    /// caller has already completed as timed out. The frame has already passed
    /// authentication, cluster / identity / session validation and the
    /// strictly-increasing sequence check (`validate_received`); this only
    /// advances the committed sequence so the frame cannot be replayed. It
    /// never touches the outstanding slot and exposes no observation.
    pub(crate) fn discard_stale_response(
        &mut self,
        pending: &PendingWitnessMessage,
    ) -> Result<(), WitnessRuntimeError> {
        if pending.kind.is_request() {
            return Err(WitnessRuntimeError::WrongMessageKind);
        }
        self.connection.commit(pending)
    }

    /// Clear the single outstanding request slot (e.g. after a local timeout or
    /// terminal completion). Preserves the one-slot invariant.
    pub(crate) fn reset_outstanding(&mut self) {
        self.outstanding = WitnessRequestOutstanding::new();
    }

    #[cfg(test)]
    pub(crate) fn outstanding(&self) -> &WitnessRequestOutstanding {
        &self.outstanding
    }

    pub(crate) fn provenance(&self) -> Arc<()> {
        self.connection.provenance()
    }

    #[cfg(all(test, unix))]
    pub(crate) fn wait_for_readable_for_test(&mut self) -> Result<(), TcpError> {
        self.connection.wait_for_readable_for_test()
    }

    #[cfg(test)]
    pub(crate) fn highest_sequence_for_test(&self) -> Sequence {
        self.connection.highest_sequence()
    }

    #[cfg(test)]
    pub(crate) fn receive_pending_for_test(
        &mut self,
    ) -> Result<PendingWitnessMessage, WitnessRuntimeError> {
        self.receive_pending()
    }

    #[cfg(test)]
    pub(crate) fn session_connection_closed_for_test(&self) -> bool {
        self.connection.is_closed()
    }
}

fn common(
    connection: &WitnessConnection,
    process: &ProcessSession,
    sequence: Sequence,
    request_id: RequestId,
) -> crate::protocol::CommonFields {
    crate::protocol::CommonFields {
        protocol_version: crate::protocol::PROTOCOL_VERSION,
        cluster_id: connection.cluster_id.clone(),
        sender_node_id: connection.local_node_id.clone(),
        receiver_node_id: connection.witness_id.clone(),
        session_id: process.session_id().clone(),
        sequence,
        term: Term(0),
        lease_id: None,
        request_id: Some(request_id),
        operation_id: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn send_request(
    connection: &mut WitnessConnection,
    process: &mut ProcessSession,
    outstanding: &mut WitnessRequestOutstanding,
    request_id: RequestId,
    kind: WitnessRequestKind,
    message: ProtocolMessage,
    serializer: &CborSerializer,
    auth: &MessageAuthenticator,
) -> Result<(), WitnessRuntimeError> {
    if !matches!(outstanding, WitnessRequestOutstanding::Idle) {
        return Err(WitnessRuntimeError::RequestAlreadyOutstanding);
    }
    if request_id.as_str().trim().is_empty() {
        return Err(WitnessRuntimeError::MissingRequestId);
    }
    let sequence = process
        .next_sequence()
        .map_err(WitnessRuntimeError::Sequence)?;
    let mutation_identity = match &message {
        ProtocolMessage::LeaseRenew(payload) => Some(WitnessOutstandingMutationIdentity {
            generation: payload.mutation_generation,
            term: payload.term,
            lease_id: payload.lease_id.clone(),
        }),
        _ => None,
    };
    let envelope = UnsignedEnvelope {
        common: common(connection, process, sequence, request_id.clone()),
        message,
    };
    envelope.validate().map_err(WitnessRuntimeError::Protocol)?;
    connection.send(envelope, serializer, auth)?;
    outstanding.begin(request_id, kind, mutation_identity)
}

pub fn send_get_term(
    c: &mut WitnessConnection,
    p: &mut ProcessSession,
    o: &mut WitnessRequestOutstanding,
    id: RequestId,
    s: &CborSerializer,
    a: &MessageAuthenticator,
) -> Result<(), WitnessRuntimeError> {
    send_request(
        c,
        p,
        o,
        id,
        WitnessRequestKind::GetTerm,
        ProtocolMessage::GetTerm,
        s,
        a,
    )
}
pub fn send_lease_request(
    c: &mut WitnessConnection,
    p: &mut ProcessSession,
    o: &mut WitnessRequestOutstanding,
    id: RequestId,
    payload: LeaseRequestPayload,
    s: &CborSerializer,
    a: &MessageAuthenticator,
) -> Result<(), WitnessRuntimeError> {
    send_request(
        c,
        p,
        o,
        id,
        WitnessRequestKind::LeaseRequest,
        ProtocolMessage::LeaseRequest(payload),
        s,
        a,
    )
}
pub fn send_lease_renew(
    c: &mut WitnessConnection,
    p: &mut ProcessSession,
    o: &mut WitnessRequestOutstanding,
    id: RequestId,
    payload: LeaseRenewPayload,
    s: &CborSerializer,
    a: &MessageAuthenticator,
) -> Result<(), WitnessRuntimeError> {
    send_request(
        c,
        p,
        o,
        id,
        WitnessRequestKind::LeaseRenew,
        ProtocolMessage::LeaseRenew(payload),
        s,
        a,
    )
}
pub fn send_lease_release(
    c: &mut WitnessConnection,
    p: &mut ProcessSession,
    o: &mut WitnessRequestOutstanding,
    id: RequestId,
    payload: LeaseReleasePayload,
    s: &CborSerializer,
    a: &MessageAuthenticator,
) -> Result<(), WitnessRuntimeError> {
    send_request(
        c,
        p,
        o,
        id,
        WitnessRequestKind::LeaseRelease,
        ProtocolMessage::LeaseRelease(payload),
        s,
        a,
    )
}

pub fn send_witness_response(
    c: &mut WitnessConnection,
    p: &mut ProcessSession,
    id: RequestId,
    message: ProtocolMessage,
    s: &CborSerializer,
    a: &MessageAuthenticator,
) -> Result<(), WitnessRuntimeError> {
    let context = match &message {
        ProtocolMessage::TermStatus(payload) => WitnessResponseContext {
            term: payload.current_term,
            lease_id: payload.current_lease_id.clone(),
        },
        _ => WitnessResponseContext {
            term: Term(0),
            lease_id: None,
        },
    };
    send_witness_response_with_context(c, p, id, message, context, s, a)
}

pub fn send_witness_response_with_context(
    c: &mut WitnessConnection,
    p: &mut ProcessSession,
    id: RequestId,
    message: ProtocolMessage,
    context: WitnessResponseContext,
    s: &CborSerializer,
    a: &MessageAuthenticator,
) -> Result<(), WitnessRuntimeError> {
    if id.as_str().trim().is_empty() {
        return Err(WitnessRuntimeError::MissingRequestId);
    }
    response_kind(&message)?;
    let sequence = p.next_sequence().map_err(WitnessRuntimeError::Sequence)?;
    let mut fields = common(c, p, sequence, id);
    fields.term = context.term;
    fields.lease_id = context.lease_id;
    fields.sender_node_id = c.local_node_id.clone();
    fields.receiver_node_id = c.witness_id.clone();
    c.send(
        UnsignedEnvelope {
            common: fields,
            message,
        },
        s,
        a,
    )
}

pub fn handle_pending_witness_request(
    c: &mut WitnessConnection,
    pending: &PendingWitnessMessage,
) -> Result<WitnessRequestObservation, WitnessRuntimeError> {
    if !pending.kind.is_request() {
        return Err(WitnessRuntimeError::WrongMessageKind);
    }
    let common = &pending.message.unsigned().common;
    let id = common
        .request_id
        .clone()
        .ok_or(WitnessRuntimeError::MissingRequestId)?;
    let sender = common.sender_node_id.clone();
    let term = common.term;
    let lease_id = common.lease_id.clone();
    let observation = match &pending.message.unsigned().message {
        ProtocolMessage::GetTerm => WitnessRequestObservation::GetTerm {
            request_id: id,
            sender_node_id: sender,
            term,
        },
        ProtocolMessage::LeaseRequest(payload) => WitnessRequestObservation::LeaseRequest {
            request_id: id,
            sender_node_id: sender,
            term,
            lease_id,
            payload: payload.clone(),
        },
        ProtocolMessage::LeaseRenew(payload) => WitnessRequestObservation::LeaseRenew {
            request_id: id,
            sender_node_id: sender,
            term,
            lease_id,
            payload: payload.clone(),
        },
        ProtocolMessage::LeaseRelease(payload) => WitnessRequestObservation::LeaseRelease {
            request_id: id,
            sender_node_id: sender,
            term,
            lease_id,
            payload: payload.clone(),
        },
        _ => return Err(WitnessRuntimeError::WrongMessageKind),
    };
    c.commit(pending)?;
    Ok(observation)
}

fn response_kind(message: &ProtocolMessage) -> Result<WitnessResponseKind, WitnessRuntimeError> {
    Ok(match message {
        ProtocolMessage::TermStatus(_) => WitnessResponseKind::TermStatus,
        ProtocolMessage::LeaseGrant(_) => WitnessResponseKind::LeaseGrant,
        ProtocolMessage::LeaseRenewed(_) => WitnessResponseKind::LeaseRenewed,
        ProtocolMessage::LeaseReleased(_) => WitnessResponseKind::LeaseReleased,
        ProtocolMessage::LeaseReject(_) => WitnessResponseKind::LeaseReject,
        _ => return Err(WitnessRuntimeError::WrongMessageKind),
    })
}
fn allowed(request: WitnessRequestKind, response: WitnessResponseKind) -> bool {
    matches!(
        (request, response),
        (WitnessRequestKind::GetTerm, WitnessResponseKind::TermStatus)
            | (
                WitnessRequestKind::LeaseRequest,
                WitnessResponseKind::LeaseGrant
            )
            | (
                WitnessRequestKind::LeaseRequest,
                WitnessResponseKind::LeaseReject
            )
            | (
                WitnessRequestKind::LeaseRenew,
                WitnessResponseKind::LeaseRenewed
            )
            | (
                WitnessRequestKind::LeaseRenew,
                WitnessResponseKind::LeaseReject
            )
            | (
                WitnessRequestKind::LeaseRelease,
                WitnessResponseKind::LeaseReleased
            )
            | (
                WitnessRequestKind::LeaseRelease,
                WitnessResponseKind::LeaseReject
            )
    )
}

pub fn handle_pending_witness_response(
    c: &mut WitnessConnection,
    pending: &PendingWitnessMessage,
    outstanding: &mut WitnessRequestOutstanding,
) -> Result<WitnessResponseObservation, WitnessRuntimeError> {
    if pending.kind.is_request() {
        return Err(WitnessRuntimeError::WrongMessageKind);
    }
    let kind = response_kind(&pending.message.unsigned().message)?;
    let id = pending
        .message
        .unsigned()
        .common
        .request_id
        .clone()
        .ok_or(WitnessRuntimeError::MissingRequestId)?;
    let WitnessRequestOutstanding::AwaitingResponse(state) = outstanding else {
        return Err(WitnessRuntimeError::NoOutstandingRequest);
    };
    if id != state.request_id {
        return Err(WitnessRuntimeError::RequestIdMismatch {
            expected: state.request_id.clone(),
            actual: id,
        });
    }
    if !allowed(state.request_kind, kind) {
        return Err(WitnessRuntimeError::ResponseKindMismatch {
            request: state.request_kind,
            response: kind,
        });
    }
    let observation = match &pending.message.unsigned().message {
        ProtocolMessage::TermStatus(v) => WitnessResponseObservation::TermStatus(v.clone()),
        ProtocolMessage::LeaseGrant(v) => WitnessResponseObservation::LeaseGrant(v.clone()),
        ProtocolMessage::LeaseRenewed(v) => WitnessResponseObservation::LeaseRenewed(v.clone()),
        ProtocolMessage::LeaseReleased(v) => WitnessResponseObservation::LeaseReleased(v.clone()),
        ProtocolMessage::LeaseReject(v) => WitnessResponseObservation::LeaseReject(v.clone()),
        _ => return Err(WitnessRuntimeError::WrongMessageKind),
    };
    c.commit(pending)?;
    outstanding.complete();
    Ok(observation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{CommonFields, DurationMs, LeaseRenewPayload, NodeStatusPayload, Role};
    use crate::security::Psk;
    use std::net::{TcpListener, TcpStream};
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    use std::os::fd::AsRawFd;
    use std::time::Duration;

    fn auth() -> MessageAuthenticator {
        MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32]))
    }

    fn pair() -> (WitnessConnection, WitnessConnection) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let client =
            TcpConnection::from_stream(client, Duration::from_secs(2), Duration::from_secs(2))
                .unwrap();
        let server =
            TcpConnection::from_stream(server, Duration::from_secs(2), Duration::from_secs(2))
                .unwrap();
        (
            WitnessConnection::new(
                NodeId::new("node-a"),
                NodeId::new("witness"),
                ClusterId::new("cluster"),
                SessionId::new("session-w"),
                client,
            ),
            WitnessConnection::new(
                NodeId::new("witness"),
                NodeId::new("node-a"),
                ClusterId::new("cluster"),
                SessionId::new("session-a"),
                server,
            ),
        )
    }

    fn request_payload(kind: WitnessRequestKind) -> ProtocolMessage {
        match kind {
            WitnessRequestKind::GetTerm => ProtocolMessage::GetTerm,
            WitnessRequestKind::LeaseRequest => {
                ProtocolMessage::LeaseRequest(LeaseRequestPayload {
                    mutation_generation: 1,
                    observed_term: Term(7),
                    priority: 100,
                    requested_ttl: DurationMs(10_000),
                })
            }
            WitnessRequestKind::LeaseRenew => ProtocolMessage::LeaseRenew(LeaseRenewPayload {
                mutation_generation: 1,
                term: Term(7),
                lease_id: LeaseId::new("lease-1"),
            }),
            WitnessRequestKind::LeaseRelease => {
                ProtocolMessage::LeaseRelease(LeaseReleasePayload {
                    mutation_generation: 1,
                    term: Term(7),
                    lease_id: LeaseId::new("lease-1"),
                    reason: "test".to_string(),
                })
            }
        }
    }

    fn response_payload(kind: WitnessResponseKind) -> ProtocolMessage {
        match kind {
            WitnessResponseKind::TermStatus => ProtocolMessage::TermStatus(TermStatusPayload {
                current_term: Term(7),
                current_holder: None,
                current_lease_id: None,
                lease_remaining_ms: None,
            }),
            WitnessResponseKind::LeaseGrant => ProtocolMessage::LeaseGrant(LeaseGrantPayload {
                term: Term(7),
                lease_id: LeaseId::new("lease-1"),
                holder_node_id: NodeId::new("node-a"),
                lease_ttl_ms: DurationMs(10_000),
                renew_after_ms: DurationMs(3_000),
                lease_remaining_ms: DurationMs(10_000),
            }),
            WitnessResponseKind::LeaseRenewed => ProtocolMessage::LeaseRenewed(LeaseGrantPayload {
                term: Term(7),
                lease_id: LeaseId::new("lease-1"),
                holder_node_id: NodeId::new("node-a"),
                lease_ttl_ms: DurationMs(10_000),
                renew_after_ms: DurationMs(3_000),
                lease_remaining_ms: DurationMs(10_000),
            }),
            WitnessResponseKind::LeaseReleased => {
                ProtocolMessage::LeaseReleased(LeaseReleasedPayload {
                    term: Term(7),
                    lease_id: LeaseId::new("lease-1"),
                    result: "released".to_string(),
                })
            }
            WitnessResponseKind::LeaseReject => ProtocolMessage::LeaseReject(LeaseRejectPayload {
                code: crate::protocol::WitnessMutationOutcomeCode::PolicyReject,
                reason: "rejected".to_string(),
            }),
        }
    }

    fn send_raw(
        connection: &mut WitnessConnection,
        process: &mut ProcessSession,
        message: ProtocolMessage,
        request_id: Option<RequestId>,
        sequence: Option<Sequence>,
    ) {
        let sequence = sequence.unwrap_or_else(|| process.next_sequence().unwrap());
        let (term, lease_id) = match &message {
            ProtocolMessage::TermStatus(payload) => {
                (payload.current_term, payload.current_lease_id.clone())
            }
            _ => (Term(7), Some(LeaseId::new("lease-1"))),
        };
        let envelope = UnsignedEnvelope {
            common: CommonFields {
                protocol_version: crate::protocol::PROTOCOL_VERSION,
                cluster_id: connection.cluster_id.clone(),
                sender_node_id: connection.local_node_id.clone(),
                receiver_node_id: connection.witness_id.clone(),
                session_id: process.session_id().clone(),
                sequence,
                term,
                lease_id,
                request_id,
                operation_id: None,
            },
            message,
        };
        connection.send(envelope, &CborSerializer, &auth()).unwrap();
    }

    fn status_payload() -> NodeStatusPayload {
        NodeStatusPayload {
            node_state: crate::state_machine::NodeState::Standby,
            operation_phase: None,
            role: Role::Standby,
            service_state: "stopped".to_string(),
            health_state: "unknown".to_string(),
            vip_state: "absent".to_string(),
        }
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn reset_on_close(stream: &TcpStream) {
        #[repr(C)]
        struct Linger {
            onoff: i32,
            linger: i32,
        }
        unsafe extern "C" {
            fn setsockopt(
                socket: i32,
                level: i32,
                option: i32,
                value: *const std::ffi::c_void,
                value_len: u32,
            ) -> i32;
        }
        let linger = Linger {
            onoff: 1,
            linger: 0,
        };
        #[cfg(target_os = "macos")]
        let (socket_level, linger_option) = (0xffff, 0x0080);
        #[cfg(target_os = "linux")]
        let (socket_level, linger_option) = (1, 13);
        let result = unsafe {
            setsockopt(
                stream.as_raw_fd(),
                socket_level,
                linger_option,
                (&linger as *const Linger).cast(),
                std::mem::size_of::<Linger>() as u32,
            )
        };
        assert_eq!(result, 0);
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn disconnected_node() -> WitnessConnection {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let connection =
            TcpConnection::from_stream(client, Duration::from_secs(2), Duration::from_secs(2))
                .unwrap();
        reset_on_close(&server);
        drop(server);
        WitnessConnection::new(
            NodeId::new("node-a"),
            NodeId::new("witness"),
            ClusterId::new("cluster"),
            SessionId::new("session-w"),
            connection,
        )
    }

    #[test]
    fn request_and_response_use_request_id_correlation() {
        let (mut node, mut witness) = pair();
        let serializer = CborSerializer;
        let authenticator = auth();
        let mut process = ProcessSession::from_session_id(SessionId::new("session-a"));
        let mut outstanding = WitnessRequestOutstanding::new();
        send_get_term(
            &mut node,
            &mut process,
            &mut outstanding,
            RequestId::new("00000000-0000-4000-8000-000000000001"),
            &serializer,
            &authenticator,
        )
        .unwrap();
        let pending = witness
            .receive_pending(&serializer, &authenticator)
            .unwrap();
        assert!(matches!(
            handle_pending_witness_request(&mut witness, &pending).unwrap(),
            WitnessRequestObservation::GetTerm { .. }
        ));
        let mut witness_process = ProcessSession::from_session_id(SessionId::new("session-w"));
        send_witness_response(
            &mut witness,
            &mut witness_process,
            RequestId::new("00000000-0000-4000-8000-000000000001"),
            ProtocolMessage::TermStatus(TermStatusPayload {
                current_term: Term(9),
                current_holder: None,
                current_lease_id: None,
                lease_remaining_ms: None,
            }),
            &serializer,
            &authenticator,
        )
        .unwrap();
        let response = node.receive_pending(&serializer, &authenticator).unwrap();
        assert!(matches!(
            handle_pending_witness_response(&mut node, &response, &mut outstanding).unwrap(),
            WitnessResponseObservation::TermStatus(_)
        ));
        assert!(matches!(outstanding, WitnessRequestOutstanding::Idle));
        assert_eq!(node.highest_sequence(), Sequence(1));
    }

    #[test]
    fn classifies_all_witness_messages_and_rejects_node_messages() {
        let requests = [
            (WitnessRequestKind::GetTerm, WitnessMessageKind::GetTerm),
            (
                WitnessRequestKind::LeaseRequest,
                WitnessMessageKind::LeaseRequest,
            ),
            (
                WitnessRequestKind::LeaseRenew,
                WitnessMessageKind::LeaseRenew,
            ),
            (
                WitnessRequestKind::LeaseRelease,
                WitnessMessageKind::LeaseRelease,
            ),
        ];
        for (kind, expected) in requests {
            let (mut node, mut witness) = pair();
            let mut process = ProcessSession::from_session_id(SessionId::new("session-a"));
            send_raw(
                &mut node,
                &mut process,
                request_payload(kind),
                Some(RequestId::new("00000000-0000-4000-8000-000000000001")),
                None,
            );
            assert_eq!(
                witness
                    .receive_pending(&CborSerializer, &auth())
                    .unwrap()
                    .kind,
                expected
            );
        }

        for kind in [
            WitnessResponseKind::TermStatus,
            WitnessResponseKind::LeaseGrant,
            WitnessResponseKind::LeaseRenewed,
            WitnessResponseKind::LeaseReleased,
            WitnessResponseKind::LeaseReject,
        ] {
            let (mut node, mut witness) = pair();
            let mut process = ProcessSession::from_session_id(SessionId::new("session-w"));
            send_raw(
                &mut witness,
                &mut process,
                response_payload(kind),
                Some(RequestId::new("00000000-0000-4000-8000-000000000001")),
                None,
            );
            assert_eq!(
                node.receive_pending(&CborSerializer, &auth()).unwrap().kind,
                match kind {
                    WitnessResponseKind::TermStatus => WitnessMessageKind::TermStatus,
                    WitnessResponseKind::LeaseGrant => WitnessMessageKind::LeaseGrant,
                    WitnessResponseKind::LeaseRenewed => WitnessMessageKind::LeaseRenewed,
                    WitnessResponseKind::LeaseReleased => WitnessMessageKind::LeaseReleased,
                    WitnessResponseKind::LeaseReject => WitnessMessageKind::LeaseReject,
                }
            );
        }

        let (mut node, mut witness) = pair();
        let mut process = ProcessSession::from_session_id(SessionId::new("session-w"));
        send_raw(
            &mut witness,
            &mut process,
            ProtocolMessage::Heartbeat(status_payload()),
            None,
            None,
        );
        assert!(matches!(
            node.receive_pending(&CborSerializer, &auth()),
            Err(WitnessRuntimeError::DisallowedMessage)
        ));
        assert_eq!(witness.highest_sequence(), Sequence(0));
    }

    #[test]
    fn all_request_senders_record_kind_and_advance_sequence() {
        let cases = [
            WitnessRequestKind::GetTerm,
            WitnessRequestKind::LeaseRequest,
            WitnessRequestKind::LeaseRenew,
            WitnessRequestKind::LeaseRelease,
        ];
        for (index, kind) in cases.into_iter().enumerate() {
            let (mut node, _witness) = pair();
            let mut process = ProcessSession::from_session_id(SessionId::new("session-a"));
            let mut outstanding = WitnessRequestOutstanding::new();
            let id = RequestId::new(format!("00000000-0000-4000-8000-{index:012x}"));
            send_request(
                &mut node,
                &mut process,
                &mut outstanding,
                id.clone(),
                kind,
                request_payload(kind),
                &CborSerializer,
                &auth(),
            )
            .unwrap();
            assert!(matches!(
                outstanding,
                WitnessRequestOutstanding::AwaitingResponse(WitnessRequestOutstandingState {
                    request_id,
                    request_kind,
                    ..
                }) if request_id == id && request_kind == kind
            ));
            assert_eq!(process.next_sequence().unwrap(), Sequence(2));
        }
    }

    #[test]
    fn second_request_is_rejected_without_allocating_sequence() {
        let (mut node, _witness) = pair();
        let mut process = ProcessSession::from_session_id(SessionId::new("session-a"));
        let mut outstanding = WitnessRequestOutstanding::new();
        send_get_term(
            &mut node,
            &mut process,
            &mut outstanding,
            RequestId::new("00000000-0000-4000-8000-00000000000a"),
            &CborSerializer,
            &auth(),
        )
        .unwrap();
        let error = send_get_term(
            &mut node,
            &mut process,
            &mut outstanding,
            RequestId::new("00000000-0000-4000-8000-00000000000b"),
            &CborSerializer,
            &auth(),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            WitnessRuntimeError::RequestAlreadyOutstanding
        ));
        assert!(matches!(
            outstanding,
            WitnessRequestOutstanding::AwaitingResponse(_)
        ));
        assert_eq!(process.next_sequence().unwrap(), Sequence(2));
    }

    #[test]
    fn request_receive_commits_only_after_handler_and_preserves_observation() {
        for kind in [
            WitnessRequestKind::GetTerm,
            WitnessRequestKind::LeaseRequest,
            WitnessRequestKind::LeaseRenew,
            WitnessRequestKind::LeaseRelease,
        ] {
            let (mut node, mut witness) = pair();
            let mut process = ProcessSession::from_session_id(SessionId::new("session-a"));
            send_request(
                &mut node,
                &mut process,
                &mut WitnessRequestOutstanding::new(),
                RequestId::new("00000000-0000-4000-8000-000000000001"),
                kind,
                request_payload(kind),
                &CborSerializer,
                &auth(),
            )
            .unwrap();
            let pending = witness.receive_pending(&CborSerializer, &auth()).unwrap();
            assert_eq!(witness.highest_sequence(), Sequence(0));
            let observation = handle_pending_witness_request(&mut witness, &pending).unwrap();
            assert_eq!(witness.highest_sequence(), Sequence(1));
            assert!(matches!(
                observation,
                WitnessRequestObservation::GetTerm { .. }
                    | WitnessRequestObservation::LeaseRequest { .. }
                    | WitnessRequestObservation::LeaseRenew { .. }
                    | WitnessRequestObservation::LeaseRelease { .. }
            ));
        }
    }

    #[test]
    fn response_matrix_correlates_and_rejects_invalid_pairs() {
        let valid = [
            (WitnessRequestKind::GetTerm, WitnessResponseKind::TermStatus),
            (
                WitnessRequestKind::LeaseRequest,
                WitnessResponseKind::LeaseGrant,
            ),
            (
                WitnessRequestKind::LeaseRequest,
                WitnessResponseKind::LeaseReject,
            ),
            (
                WitnessRequestKind::LeaseRenew,
                WitnessResponseKind::LeaseRenewed,
            ),
            (
                WitnessRequestKind::LeaseRenew,
                WitnessResponseKind::LeaseReject,
            ),
            (
                WitnessRequestKind::LeaseRelease,
                WitnessResponseKind::LeaseReleased,
            ),
            (
                WitnessRequestKind::LeaseRelease,
                WitnessResponseKind::LeaseReject,
            ),
        ];
        for (request, response) in valid {
            let (mut node, mut witness) = pair();
            let mut process = ProcessSession::from_session_id(SessionId::new("session-a"));
            let mut outstanding = WitnessRequestOutstanding::new();
            send_request(
                &mut node,
                &mut process,
                &mut outstanding,
                RequestId::new("00000000-0000-4000-8000-000000000001"),
                request,
                request_payload(request),
                &CborSerializer,
                &auth(),
            )
            .unwrap();
            let pending_request = witness.receive_pending(&CborSerializer, &auth()).unwrap();
            handle_pending_witness_request(&mut witness, &pending_request).unwrap();
            let mut witness_process = ProcessSession::from_session_id(SessionId::new("session-w"));
            send_witness_response(
                &mut witness,
                &mut witness_process,
                RequestId::new("00000000-0000-4000-8000-000000000001"),
                response_payload(response),
                &CborSerializer,
                &auth(),
            )
            .unwrap();
            let pending = node.receive_pending(&CborSerializer, &auth()).unwrap();
            assert!(handle_pending_witness_response(&mut node, &pending, &mut outstanding).is_ok());
            assert!(matches!(outstanding, WitnessRequestOutstanding::Idle));
        }

        for invalid_response in [
            WitnessResponseKind::LeaseGrant,
            WitnessResponseKind::LeaseReject,
        ] {
            let (mut node, mut witness) = pair();
            let mut process = ProcessSession::from_session_id(SessionId::new("session-a"));
            let mut outstanding = WitnessRequestOutstanding::new();
            send_get_term(
                &mut node,
                &mut process,
                &mut outstanding,
                RequestId::new("00000000-0000-4000-8000-000000000001"),
                &CborSerializer,
                &auth(),
            )
            .unwrap();
            let request = witness.receive_pending(&CborSerializer, &auth()).unwrap();
            handle_pending_witness_request(&mut witness, &request).unwrap();
            let mut witness_process = ProcessSession::from_session_id(SessionId::new("session-w"));
            send_raw(
                &mut witness,
                &mut witness_process,
                response_payload(invalid_response),
                Some(RequestId::new("00000000-0000-4000-8000-000000000001")),
                None,
            );
            let pending = node.receive_pending(&CborSerializer, &auth()).unwrap();
            assert!(matches!(
                handle_pending_witness_response(&mut node, &pending, &mut outstanding),
                Err(WitnessRuntimeError::ResponseKindMismatch { .. })
            ));
            assert_eq!(node.highest_sequence(), Sequence(0));
            assert!(matches!(
                outstanding,
                WitnessRequestOutstanding::AwaitingResponse(_)
            ));
        }
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn failed_request_send_keeps_idle_and_does_not_reuse_sequence() {
        let mut node = disconnected_node();
        let mut process = ProcessSession::from_session_id(SessionId::new("session-a"));
        let mut outstanding = WitnessRequestOutstanding::new();
        let error = send_get_term(
            &mut node,
            &mut process,
            &mut outstanding,
            RequestId::new("00000000-0000-4000-8000-000000000001"),
            &CborSerializer,
            &auth(),
        )
        .unwrap_err();
        assert!(matches!(error, WitnessRuntimeError::Tcp(_)));
        assert!(matches!(outstanding, WitnessRequestOutstanding::Idle));
        assert_eq!(process.next_sequence().unwrap(), Sequence(2));
    }

    #[test]
    fn unsolicited_and_mismatched_responses_do_not_commit_or_complete() {
        for id in ["request-a", "request-b"] {
            let (mut node, mut witness) = pair();
            let mut witness_process = ProcessSession::from_session_id(SessionId::new("session-w"));
            send_raw(
                &mut witness,
                &mut witness_process,
                response_payload(WitnessResponseKind::TermStatus),
                Some(RequestId::new(id)),
                None,
            );
            let pending = node.receive_pending(&CborSerializer, &auth()).unwrap();
            let mut outstanding = WitnessRequestOutstanding::new();
            assert!(matches!(
                handle_pending_witness_response(&mut node, &pending, &mut outstanding),
                Err(WitnessRuntimeError::NoOutstandingRequest)
            ));
            assert_eq!(node.highest_sequence(), Sequence(0));
        }
        let (mut node, mut witness) = pair();
        let mut process = ProcessSession::from_session_id(SessionId::new("session-a"));
        let mut outstanding = WitnessRequestOutstanding::new();
        send_get_term(
            &mut node,
            &mut process,
            &mut outstanding,
            RequestId::new("00000000-0000-4000-8000-00000000000a"),
            &CborSerializer,
            &auth(),
        )
        .unwrap();
        let request = witness.receive_pending(&CborSerializer, &auth()).unwrap();
        handle_pending_witness_request(&mut witness, &request).unwrap();
        let mut witness_process = ProcessSession::from_session_id(SessionId::new("session-w"));
        send_raw(
            &mut witness,
            &mut witness_process,
            response_payload(WitnessResponseKind::TermStatus),
            Some(RequestId::new("00000000-0000-4000-8000-00000000000b")),
            None,
        );
        let pending = node.receive_pending(&CborSerializer, &auth()).unwrap();
        assert!(matches!(
            handle_pending_witness_response(&mut node, &pending, &mut outstanding),
            Err(WitnessRuntimeError::RequestIdMismatch { .. })
        ));
        assert_eq!(node.highest_sequence(), Sequence(0));
        assert!(matches!(
            outstanding,
            WitnessRequestOutstanding::AwaitingResponse(_)
        ));
    }

    #[test]
    fn cloned_pending_messages_cannot_be_committed_twice() {
        let (mut node, mut witness) = pair();
        let mut process = ProcessSession::from_session_id(SessionId::new("session-a"));
        send_get_term(
            &mut node,
            &mut process,
            &mut WitnessRequestOutstanding::new(),
            RequestId::new("00000000-0000-4000-8000-000000000001"),
            &CborSerializer,
            &auth(),
        )
        .unwrap();
        let pending = witness.receive_pending(&CborSerializer, &auth()).unwrap();
        let clone = pending.clone();
        handle_pending_witness_request(&mut witness, &pending).unwrap();
        assert!(matches!(
            handle_pending_witness_request(&mut witness, &clone),
            Err(WitnessRuntimeError::StaleOrDuplicate)
        ));
        assert_eq!(witness.highest_sequence(), Sequence(1));

        let (mut node, mut witness) = pair();
        let mut process = ProcessSession::from_session_id(SessionId::new("session-a"));
        let mut outstanding = WitnessRequestOutstanding::new();
        send_get_term(
            &mut node,
            &mut process,
            &mut outstanding,
            RequestId::new("00000000-0000-4000-8000-000000000001"),
            &CborSerializer,
            &auth(),
        )
        .unwrap();
        let request = witness.receive_pending(&CborSerializer, &auth()).unwrap();
        handle_pending_witness_request(&mut witness, &request).unwrap();
        let mut witness_process = ProcessSession::from_session_id(SessionId::new("session-w"));
        send_witness_response(
            &mut witness,
            &mut witness_process,
            RequestId::new("00000000-0000-4000-8000-000000000001"),
            response_payload(WitnessResponseKind::TermStatus),
            &CborSerializer,
            &auth(),
        )
        .unwrap();
        let pending = node.receive_pending(&CborSerializer, &auth()).unwrap();
        let clone = pending.clone();
        handle_pending_witness_response(&mut node, &pending, &mut outstanding).unwrap();
        assert!(matches!(
            handle_pending_witness_response(&mut node, &clone, &mut outstanding),
            Err(WitnessRuntimeError::NoOutstandingRequest)
        ));
        assert_eq!(node.highest_sequence(), Sequence(1));
    }

    #[test]
    fn identity_session_and_stale_sequence_are_rejected_before_commit() {
        for (cluster, sender, receiver, session, sequence) in [
            ("other", "witness", "node-a", "session-w", 1),
            ("cluster", "other", "node-a", "session-w", 1),
            ("cluster", "witness", "other", "session-w", 1),
            ("cluster", "witness", "node-a", "other", 1),
            ("cluster", "witness", "node-a", "session-w", 0),
        ] {
            let (mut node, mut witness) = pair();
            let mut message = UnsignedEnvelope {
                common: CommonFields {
                    protocol_version: crate::protocol::PROTOCOL_VERSION,
                    cluster_id: ClusterId::new(cluster),
                    sender_node_id: NodeId::new(sender),
                    receiver_node_id: NodeId::new(receiver),
                    session_id: SessionId::new(session),
                    sequence: Sequence(sequence),
                    term: Term(7),
                    lease_id: None,
                    request_id: Some(RequestId::new("00000000-0000-4000-8000-000000000001")),
                    operation_id: None,
                },
                message: ProtocolMessage::GetTerm,
            };
            if sequence == 0 {
                message.common.sequence = Sequence(0);
            }
            witness.send(message, &CborSerializer, &auth()).unwrap();
            assert!(node.receive_pending(&CborSerializer, &auth()).is_err());
            assert_eq!(node.highest_sequence(), Sequence(0));
        }
    }

    #[test]
    fn response_sender_rejects_non_response_message() {
        let (mut node, _witness) = pair();
        let mut process = ProcessSession::from_session_id(SessionId::new("session-a"));
        let error = send_witness_response(
            &mut node,
            &mut process,
            RequestId::new("00000000-0000-4000-8000-000000000001"),
            ProtocolMessage::GetTerm,
            &CborSerializer,
            &auth(),
        )
        .unwrap_err();
        assert!(matches!(error, WitnessRuntimeError::WrongMessageKind));
        assert_eq!(process.next_sequence().unwrap(), Sequence(1));
    }
    // ---- v0.6 A-1: Witness session loss / socket release ------------------

    /// One `WitnessSession` on a real loopback socket plus the raw peer end,
    /// so a test can close the peer exactly like a stopped Witness.
    fn session_pair(read_timeout: Duration) -> (WitnessSession, std::net::TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        // Set while the connection is live: on macOS, setsockopt fails with
        // EINVAL once this end has shut down writing and received the peer's
        // FIN, which is exactly the state `assert_peer_sees_fin` inspects.
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let connection = TcpConnection::from_stream(client, read_timeout, read_timeout).unwrap();
        let node = WitnessConnection::new(
            NodeId::new("node-a"),
            NodeId::new("witness"),
            ClusterId::new("cluster"),
            SessionId::new("session-w"),
            connection,
        );
        (
            WitnessSession::new(
                node,
                ProcessSession::from_session_id(SessionId::new("session-a")),
                auth(),
            ),
            server,
        )
    }

    /// The peer end already has a 2 s read timeout (`session_pair`): a socket
    /// retained in CLOSE_WAIT makes this read time out and fail.
    fn assert_peer_sees_fin(server: &mut std::net::TcpStream) {
        use std::io::Read;
        let mut byte = [0u8; 1];
        assert_eq!(
            server.read(&mut byte).unwrap(),
            0,
            "the session socket must be closed (peer sees FIN), not retained in CLOSE_WAIT"
        );
    }

    #[test]
    fn eof_latches_a_lost_session_and_releases_the_socket() {
        use std::net::Shutdown;
        let (mut session, mut server) = session_pair(Duration::from_secs(2));
        assert!(!session.lost());
        // The Witness stops: its half of the connection is closed.
        server.shutdown(Shutdown::Write).unwrap();
        let error = session.receive_pending().unwrap_err();
        assert!(
            matches!(error, WitnessRuntimeError::SessionClosed),
            "{error:?}"
        );
        assert!(session.lost(), "EOF is a permanently lost session");
        assert_peer_sees_fin(&mut server);
    }

    #[test]
    fn poll_eof_latches_a_lost_session_and_releases_the_socket() {
        use std::net::Shutdown;
        let (mut session, mut server) = session_pair(Duration::from_secs(2));
        server.shutdown(Shutdown::Write).unwrap();
        let mut observed = WitnessPoll::NoFrame;
        for _ in 0..200 {
            match session.poll_pending().unwrap() {
                WitnessPoll::NoFrame => std::thread::sleep(Duration::from_millis(5)),
                other => {
                    observed = other;
                    break;
                }
            }
        }
        assert!(matches!(observed, WitnessPoll::Eof), "{observed:?}");
        assert!(session.lost());
        assert_peer_sees_fin(&mut server);
    }

    #[test]
    fn a_lost_session_is_never_reused_for_a_new_request() {
        use std::net::Shutdown;
        let (mut session, mut server) = session_pair(Duration::from_secs(2));
        server.shutdown(Shutdown::Write).unwrap();
        assert!(session.receive_pending().is_err());
        assert!(session.lost());
        // No new GET_TERM, lease request, renew or release may be sent on the
        // dead session; nothing reaches the peer.
        assert!(matches!(
            session.send_get_term(RequestId::new("00000000-0000-4000-8000-000000000001")),
            Err(WitnessRuntimeError::SessionClosed)
        ));
        assert!(matches!(
            session.send_lease_request(
                RequestId::new("00000000-0000-4000-8000-000000000002"),
                LeaseRequestPayload {
                    mutation_generation: 1,
                    observed_term: Term(1),
                    priority: 100,
                    requested_ttl: DurationMs(10_000),
                }
            ),
            Err(WitnessRuntimeError::SessionClosed)
        ));
        assert!(matches!(
            session.receive_pending(),
            Err(WitnessRuntimeError::SessionClosed)
        ));
        assert!(session.session_connection_closed_for_test());
        assert_peer_sees_fin(&mut server);
    }

    #[test]
    fn a_transport_probe_detects_a_stopped_witness_without_a_request() {
        use std::net::Shutdown;
        let (mut session, mut server) = session_pair(Duration::from_secs(2));
        // Alive: the probe says nothing and changes nothing.
        assert!(!session.probe_transport_closure());
        assert!(!session.lost());
        assert!(session.outstanding_identity().is_none());

        server.shutdown(Shutdown::Write).unwrap();
        let mut detected = false;
        for _ in 0..200 {
            if session.probe_transport_closure() {
                detected = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(detected, "an idle Standby must notice a closed Witness");
        assert!(session.lost());
        // The socket is released at detection time, not at process exit.
        assert_peer_sees_fin(&mut server);
        // The probe is a report, never a lease or authority outcome: the
        // outstanding slot is untouched and no frame was consumed.
        assert!(session.outstanding_identity().is_none());
    }

    #[test]
    fn a_transport_probe_does_not_consume_a_pending_frame() {
        let (mut session, mut server) = session_pair(Duration::from_secs(2));
        let _ = server.set_nodelay(true);
        // A frame from the Witness is pending but no request is outstanding
        // (observation state); the probe must leave it in the stream.
        let mut witness = WitnessConnection::new(
            NodeId::new("witness"),
            NodeId::new("node-a"),
            ClusterId::new("cluster"),
            SessionId::new("session-a"),
            TcpConnection::from_stream(server, Duration::from_secs(2), Duration::from_secs(2))
                .unwrap(),
        );
        let mut process = ProcessSession::from_session_id(SessionId::new("session-w"));
        send_raw(
            &mut witness,
            &mut process,
            ProtocolMessage::TermStatus(TermStatusPayload {
                current_term: Term(1),
                current_holder: None,
                current_lease_id: None,
                lease_remaining_ms: None,
            }),
            Some(RequestId::new("00000000-0000-4000-8000-000000000009")),
            None,
        );
        std::thread::sleep(Duration::from_millis(50));
        assert!(!session.probe_transport_closure());
        assert!(!session.lost());
        // The frame is still there and still validated normally.
        let pending = session.receive_pending().unwrap();
        assert_eq!(pending.kind, WitnessMessageKind::TermStatus);
    }

    #[test]
    fn a_read_timeout_does_not_latch_the_session_lost() {
        let (mut session, server) = session_pair(Duration::from_millis(150));
        let error = session.receive_pending().unwrap_err();
        assert!(
            matches!(
                &error,
                WitnessRuntimeError::Tcp(TcpError::Transport(
                    crate::transport::TransportError::Io(io_error)
                )) | WitnessRuntimeError::Tcp(TcpError::Io(io_error))
                    if matches!(io_error.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock)
            ),
            "{error:?}"
        );
        assert!(!session.lost(), "a timeout is not a lost session");
        assert!(!session.session_connection_closed_for_test());
        drop(server);
    }

    #[test]
    fn a_voluntary_close_releases_the_socket_without_marking_the_session_lost() {
        let (mut session, mut server) = session_pair(Duration::from_secs(2));
        session.close();
        assert!(!session.lost());
        assert!(session.session_connection_closed_for_test());
        assert_peer_sees_fin(&mut server);
    }
}
