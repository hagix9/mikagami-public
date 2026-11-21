//! Caller-driven composition of the TCP, session, and peer-observation layers.
//!
//! This module is deliberately an observation/transport boundary.  It does
//! not acquire a lease, mutate resources, reconnect, or make an HA decision.

#![allow(dead_code)]

use crate::bootstrap_admission::{
    BootstrapStamp, PROBE_REASON, ProbeOutcome, ProbeVerdict, is_valid_operation_id,
};
use crate::daemon::{DaemonHealth, DaemonService, DaemonVip, PeerStatusSnapshot};
use crate::failure_assessment::{PeerFailureDetector, PeerFailureSnapshot, VerifiedListenWindow};
use crate::heartbeat::{HeartbeatError, build_heartbeat, build_heartbeat_ack};
use crate::peer_observer::PeerObservationState;
use crate::peer_observer::{PeerObservation, PeerObserver, PeerTransport, PeerTransportEvent};
use crate::protocol::{
    CborSerializer, ClusterId, CommonFields, MessageType, NodeId, NodeStatusPayload, OperationId,
    PROTOCOL_VERSION, PromotionIntentPayload, ProtocolMessage, Sequence, SessionId, Term,
    UnsignedEnvelope,
};
use crate::receive::{AuthenticatedMessage, ReceiveError, receive};
use crate::security::MessageAuthenticator;
use crate::session::{OutboundHandshake, OutboundHandshakeError, ProcessSession, build_hello_ack};
use crate::session_runtime::{
    SessionRuntime, SessionRuntimeEvent, SessionRuntimeInput, SessionRuntimeState,
};
use crate::tcp_runtime::{ConnectionToken, TcpPeerRuntime, TcpRuntimeError, TcpRuntimeStep};
use std::collections::VecDeque;
use std::fmt;
use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, Instant};

pub(crate) const MAX_FRAMES_PER_TICK: usize = 8;

struct NoopTransport;

impl PeerTransport for NoopTransport {
    fn poll_heartbeat(&mut self) -> PeerTransportEvent {
        PeerTransportEvent::NoMessage
    }
}

#[derive(Debug)]
pub(crate) enum DaemonPeerRuntimeError {
    Direction(crate::connection_manager::DirectionError),
    SessionGeneration(crate::session::SessionGenerationError),
    Tcp(TcpRuntimeError),
    Receive(ReceiveError),
    Heartbeat(HeartbeatError),
    OutboundHandshake(OutboundHandshakeError),
    Sequence(crate::session::SequenceError),
    FailureAssessment(crate::failure_assessment::FailureAssessmentError),
    Protocol(crate::protocol::ProtocolError),
    NotEstablished,
}

#[derive(Debug)]
pub(crate) enum DaemonPeerRuntimeBuildError {
    Configuration(String),
    Transport(String),
}

impl fmt::Display for DaemonPeerRuntimeBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(error) => write!(formatter, "peer configuration failed: {error}"),
            Self::Transport(error) => write!(formatter, "peer transport unavailable: {error}"),
        }
    }
}

impl fmt::Display for DaemonPeerRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direction(error) => write!(formatter, "peer direction failed: {error}"),
            Self::SessionGeneration(error) => {
                write!(formatter, "process session generation failed: {error}")
            }
            Self::Tcp(error) => write!(formatter, "peer TCP runtime failed: {error}"),
            Self::Receive(error) => write!(formatter, "peer message receive failed: {error}"),
            Self::Heartbeat(error) => write!(formatter, "peer heartbeat failed: {error}"),
            Self::OutboundHandshake(error) => write!(formatter, "outbound HELLO failed: {error}"),
            Self::Sequence(error) => write!(formatter, "peer sequence allocation failed: {error}"),
            Self::FailureAssessment(error) => {
                write!(formatter, "peer failure assessment failed: {error}")
            }
            Self::Protocol(error) => write!(formatter, "peer message invalid: {error}"),
            Self::NotEstablished => write!(formatter, "peer session is not established"),
        }
    }
}

impl std::error::Error for DaemonPeerRuntimeError {}

impl From<TcpRuntimeError> for DaemonPeerRuntimeError {
    fn from(error: TcpRuntimeError) -> Self {
        Self::Tcp(error)
    }
}

impl From<crate::connection_manager::DirectionError> for DaemonPeerRuntimeError {
    fn from(error: crate::connection_manager::DirectionError) -> Self {
        Self::Direction(error)
    }
}

impl From<crate::failure_assessment::FailureAssessmentError> for DaemonPeerRuntimeError {
    fn from(error: crate::failure_assessment::FailureAssessmentError) -> Self {
        Self::FailureAssessment(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeerRuntimeRole {
    Inbound,
    Outbound,
}

const INITIAL_RETRY_DELAY: Duration = Duration::from_millis(250);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(5);
const MAX_RETRY_FAILURES: u32 = 32;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);

/// Stage 14 Appendix R.3(13): a verified-listen window lasts at least the
/// canonical Outbound peer's own reconnect + handshake bound.
const VERIFIED_LISTEN_MIN_DURATION: Duration = MAX_RETRY_DELAY.saturating_add(HANDSHAKE_TIMEOUT);

/// Why the current verified-listen window was voided (Appendix R.4, R.7).
/// Diagnostic only; never an input to any decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ListenWindowVoid {
    AcceptedConnection,
    AcceptError,
    ListenerGenerationChanged,
    IterationNotAdvanced,
    PollGapExceeded,
    ClockRegression,
    LossGenerationChanged,
    IdentityUncertainty,
    Shutdown,
    /// §27.5 / Appendix R.8: a blocking fencing step (the gate G fence
    /// action or a `drive_fencing_step` verify poll) is about to run.
    FencingStep,
}

/// Stage 14 §28.1 (FA-06): the ephemeral, runtime-only `ListenerInterference`
/// diagnostic counters. An accepted TCP connection that ends without
/// authenticating as the configured peer is an *unauthenticated arrival*.
///
/// **Diagnostics are not evidence** (guard `017_diagnostics_not_evidence`).
/// These counters are written by the peer runtime's accept/teardown path and
/// read only by the operator log and the blocked-attempt log line. No
/// detector, fencing, Witness, authority, promotion, or status code reads
/// them, none of them is persisted or on the wire, and resetting or
/// disabling them changes no observation, freshness, or authority decision
/// (proved by `stage14_11_diagnostics_have_no_state_effect`).
#[derive(Debug, Default)]
struct ListenerInterferenceDiagnostics {
    /// Recent unauthenticated arrivals as `(observation instant, arrivals at
    /// that instant)`, oldest first, for "in the last 30 s".
    ///
    /// **Exactness (L1).** `recent_arrivals` sums every arrival whose own
    /// observation instant is inside the inclusive
    /// `LOCAL_LOSS_EVIDENCE_MAX_AGE` window. No entry is ever merged into
    /// another entry's instant and no arrival is ever dropped before its own
    /// instant leaves the window, so the reported count is the mathematical
    /// count of arrivals in the window for *any* arrival sequence: never
    /// over-reported, never under-reported.
    ///
    /// **Memory bound (L1-MEM).** One entry per *distinct observation
    /// instant* in the window, never one entry per arrival; entries already
    /// outside the window are pruned on every record. The entry count is
    /// therefore at most the number of foreground ticks in a closed 30 s
    /// window:
    ///
    /// - `note_unauthenticated_arrival` runs only inside `tick_at`, and every
    ///   arrival of one `tick_at` call carries that call's single `now`, so one
    ///   tick adds at most one entry whatever the arrival rate (a million
    ///   arrivals at one instant keep one entry);
    /// - `tick_at` has one production caller, the observation loop, which
    ///   samples `Instant::now()` once per iteration and ends every iteration
    ///   with `sleep(delay)`; `delay >= min(ordinary, 100 ms floor)` except for
    ///   at most one expiry-limited wait per Active tenure, and `ordinary` is at
    ///   least 1 s (`active_wait_delay`, `ACTIVE_RENEW_MIN_WAIT`);
    /// - hence at most `floor(30 s / 100 ms) + 1 + 2 = 303` ticks (a
    ///   conservative bound: two expiry-limited edge spacings are allowed for),
    ///   i.e. at most 303 entries, at most 512 allocated entries
    ///   (`VecDeque` grows by powers of two and never shrinks, so 512 is also
    ///   the lifetime high-water mark): 12,288 bytes of entry payload.
    ///
    /// There is deliberately no fixed bucket cap: an exact count over an
    /// unbounded number of distinct instants cannot be held in a fixed number
    /// of timestamps without merging (over-report) or dropping (under-report)
    /// an arrival. The bound rests on the scheduling invariant above, which is
    /// pinned by `active_wait_delay` tests and the architecture guard
    /// `mkm_arch_017_active_wait_floor_bounds_the_diagnostic_window`.
    /// Derivation and premises:
    /// `MIKAGAMI_STAGE_14_PHASE_14_11_L1_MEM_SCHEDULER_ADDENDUM.md`.
    recent: VecDeque<(Instant, u64)>,
    arrivals_since_warn: u64,
    voided_since_warn: u64,
    last_warn: Option<Instant>,
    guidance_printed: bool,
}

/// What one `ListenerInterference` WARN reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InterferenceWarn {
    arrivals: u64,
    voided_windows: u64,
    first: bool,
}

impl ListenerInterferenceDiagnostics {
    /// §28.1: at most one WARN per `LOCAL_LOSS_EVIDENCE_MAX_AGE`; the first
    /// occurrence after a quiet window logs immediately.
    fn warn_due(&self, now: Instant) -> bool {
        self.last_warn.is_none_or(|last| {
            now.checked_duration_since(last).is_some_and(|elapsed| {
                elapsed >= crate::failure_assessment::LOCAL_LOSS_EVIDENCE_MAX_AGE
            })
        })
    }

    fn take_warn(&mut self, now: Instant) -> InterferenceWarn {
        let warn = InterferenceWarn {
            arrivals: std::mem::take(&mut self.arrivals_since_warn),
            voided_windows: std::mem::take(&mut self.voided_since_warn),
            first: !self.guidance_printed,
        };
        self.guidance_printed = true;
        self.last_warn = Some(now);
        warn
    }

    /// One unauthenticated arrival at `now`; `voided_window` is whether its
    /// accept voided an open verified-listen window.
    fn record(&mut self, now: Instant, voided_window: bool) -> Option<InterferenceWarn> {
        self.note_recent(now);
        self.arrivals_since_warn = self.arrivals_since_warn.saturating_add(1);
        if voided_window {
            self.voided_since_warn = self.voided_since_warn.saturating_add(1);
        }
        self.warn_due(now).then(|| self.take_warn(now))
    }

    /// Counts accumulated inside a rate-limited interval are reported once the
    /// interval has passed, so they are never silently lost.
    fn flush(&mut self, now: Instant) -> Option<InterferenceWarn> {
        (self.arrivals_since_warn > 0 && self.warn_due(now)).then(|| self.take_warn(now))
    }

    /// Add one arrival to the exact recent-window representation.
    ///
    /// Arrivals observed at the same instant aggregate into one entry;
    /// arrivals observed at a *different* instant always get their own entry,
    /// so no arrival is ever attributed to an instant that is not its own and
    /// no arrival is ever dropped (L1). Entries already outside the window are
    /// pruned first, which is what keeps the structure window-sized.
    fn note_recent(&mut self, now: Instant) {
        self.prune_recent(now);
        match self.recent.back_mut() {
            Some((at, count)) if *at == now => *count = count.saturating_add(1),
            _ => self.recent.push_back((now, 1)),
        }
    }

    /// Drop the entries whose own instant has left the window. Pruning is
    /// monotone in the recorded instants and never touches an entry that is
    /// still inside the window, so it cannot change the reported count.
    fn prune_recent(&mut self, now: Instant) {
        while self.recent.front().is_some_and(|(at, _)| {
            now.checked_duration_since(*at)
                .is_some_and(|age| age > crate::failure_assessment::LOCAL_LOSS_EVIDENCE_MAX_AGE)
        }) {
            self.recent.pop_front();
        }
    }

    /// Unauthenticated arrivals within the last `LOCAL_LOSS_EVIDENCE_MAX_AGE`
    /// (inclusive). Exact for any arrival count *and* for any number of
    /// distinct observation instants in the window: every arrival is counted
    /// against its own recorded instant and nothing else (L1).
    fn recent_arrivals(&self, now: Instant) -> u64 {
        self.recent
            .iter()
            .filter(|(at, _)| {
                now.checked_duration_since(*at).is_some_and(|age| {
                    age <= crate::failure_assessment::LOCAL_LOSS_EVIDENCE_MAX_AGE
                })
            })
            .fold(0u64, |total, (_, count)| total.saturating_add(*count))
    }
}

/// One open verified-listen window (Appendix R.2). Ephemeral instrumentation
/// of the single foreground owner; never persisted, never on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ListenWindow {
    w_start: Instant,
    listener_generation: u64,
    loss_generation: u64,
    sample_count: u64,
    last_sample: Instant,
    last_iteration: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RetrySchedule {
    next_attempt_at: Option<Instant>,
    consecutive_failures: u32,
    last_error: Option<String>,
}

impl RetrySchedule {
    const fn new() -> Self {
        Self {
            next_attempt_at: None,
            consecutive_failures: 0,
            last_error: None,
        }
    }

    fn schedule(&mut self, now: Instant, error: impl Into<String>) {
        self.consecutive_failures = self
            .consecutive_failures
            .saturating_add(1)
            .min(MAX_RETRY_FAILURES);
        let exponent = self.consecutive_failures.saturating_sub(1).min(5);
        let delay = INITIAL_RETRY_DELAY
            .checked_mul(1u32 << exponent)
            .unwrap_or(MAX_RETRY_DELAY)
            .min(MAX_RETRY_DELAY);
        self.next_attempt_at = now.checked_add(delay).or(Some(now));
        self.last_error = Some(error.into());
    }

    fn due(&self, now: Instant) -> bool {
        self.next_attempt_at.is_some_and(|deadline| now >= deadline)
    }

    fn begin_attempt(&mut self) {
        self.next_attempt_at = None;
    }

    fn reset(&mut self) {
        *self = Self::new();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TransportRecoverySnapshot {
    pub(crate) connected: bool,
    pub(crate) listener_available: bool,
    pub(crate) reconnect_scheduled: bool,
    pub(crate) rebind_scheduled: bool,
    pub(crate) consecutive_reconnect_failures: u32,
    pub(crate) consecutive_rebind_failures: u32,
    pub(crate) last_error: Option<String>,
}

/// The BA probe this runtime, as the evaluating side, has outstanding.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ProbeState {
    Idle,
    /// Asked for by the daemon after the anchor; sent from the next tick.
    Requested,
    Sent {
        operation_id: String,
        stamp: BootstrapStamp,
    },
}

/// A probe this runtime, as the answering side, still has to answer in the
/// tick that read it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProbeRequest {
    token: ConnectionToken,
    operation_id: OperationId,
    /// The reason is the exact BA reason and the operation id has the BA shape;
    /// anything else is answered `Unknown`.
    well_formed: bool,
}

/// At most this many probes are answered per tick (the rest are dropped
/// unanswered, which the asker treats as a failed probe).
const MAX_PROBE_REQUESTS_PER_TICK: usize = 4;

pub(crate) struct DaemonPeerRuntime {
    /// F-3 (final review R6): consecutive accepted heartbeats of the current
    /// peer session that reported `Active`. Reset by any other report and by
    /// a new peer session. In memory only; it feeds the automatic trigger's
    /// restriction and nothing else (never a safety decision).
    peer_active_streak: u32,
    peer_active_session: Option<SessionId>,
    transport: TcpPeerRuntime,
    session: SessionRuntime,
    observer: PeerObserver<NoopTransport>,
    process_session: ProcessSession,
    serializer: CborSerializer,
    authenticator: MessageAuthenticator,
    cluster_id: ClusterId,
    local_node_id: NodeId,
    peer_node_id: NodeId,
    peer_address: Option<SocketAddr>,
    bind_address: Option<SocketAddr>,
    role: PeerRuntimeRole,
    local_priority: i32,
    heartbeat_interval: Duration,
    last_heartbeat: Option<Instant>,
    outbound_handshake: Option<OutboundHandshake>,
    outbound_established: bool,
    peer_session_id: Option<SessionId>,
    peer_sequence: Option<Sequence>,
    current_token: Option<ConnectionToken>,
    handshake_deadline: Option<(ConnectionToken, Instant)>,
    clock_origin: Instant,
    local_status: PeerStatusSnapshot,
    reconnect: RetrySchedule,
    rebind: RetrySchedule,
    failure_assessment: PeerFailureDetector,
    shutting_down: bool,
    /// Stage 14 Appendix R.3(10): `loop_interval + HANDSHAKE_TIMEOUT`, with
    /// `loop_interval = max(heartbeat.interval_sec, 1) s`, computed once.
    listen_max_gap: Duration,
    /// Appendix R.2: identity of one continuous listener instance; checked
    /// `+1` on every successful bind.
    listener_generation: u64,
    /// Appendix R.2 (Revision 5): the instant at which the current generation
    /// was bound; `None` while unbound. Lifecycle instrumentation only: never
    /// a sample, window boundary, or freshness source.
    bound_since: Option<Instant>,
    /// Appendix R.2: advanced once per `tick_at` call.
    iteration_generation: u64,
    /// Appendix R.2: the last `accept_one` → `Ok(NoEvent)` sample
    /// `(instant, iteration_generation, listener_generation)`.
    last_accept_sample: Option<(Instant, u64, u64)>,
    /// Appendix R.2: the current open verified-listen window.
    listen_window: Option<ListenWindow>,
    /// Appendix R.4 "next window": the iteration that completed a window
    /// cannot also open the next one.
    last_window_completion_iteration: Option<u64>,
    /// Appendix R.2 `last_invalidation`: diagnostic only.
    last_window_void: Option<ListenWindowVoid>,
    /// §10.3.1: `(token, t_start)` of the connection attempt this runtime
    /// initiated and whose authenticated HELLO_ACK is still pending.
    outbound_attempt: Option<(ConnectionToken, Instant)>,
    /// §10.5 / R.6: the current accepted Inbound connection authenticated as
    /// the configured peer.
    inbound_authenticated: bool,
    /// §10.5: the connection being torn down ended in identity or
    /// authentication uncertainty.
    pending_identity_uncertainty: bool,
    /// Stage 14 §28.1 diagnostics (never evidence; see the type).
    interference: ListenerInterferenceDiagnostics,
    /// Whether the current accepted connection's accept voided an open
    /// verified-listen window. Diagnostic bookkeeping for `interference`.
    accept_voided_window: bool,
    /// The peer's process session of the established connection (both roles).
    established_peer_session: Option<SessionId>,
    /// BA (evaluating side): the one outstanding probe.
    probe: ProbeState,
    /// BA (evaluating side): the result the daemon takes once.
    probe_outcome: Option<ProbeOutcome>,
    /// BA (answering side): probes read in this tick, answered before it ends.
    pending_probe_requests: Vec<ProbeRequest>,
    #[cfg(test)]
    received_messages: Vec<UnsignedEnvelope>,
    #[cfg(test)]
    heartbeat_ack_messages: Vec<(Sequence, UnsignedEnvelope)>,
    #[cfg(test)]
    heartbeat_ack_send_attempts: Vec<(Sequence, SessionId)>,
    #[cfg(test)]
    heartbeat_ack_send_context: Option<(Sequence, SessionId)>,
    #[cfg(test)]
    fail_next_ack_send: bool,
    #[cfg(test)]
    last_accepted_heartbeat_sequence: Option<Sequence>,
    #[cfg(test)]
    last_sent_heartbeat_sequence: Option<Sequence>,
    #[cfg(test)]
    last_transport_failure_ms: Option<u64>,
    #[cfg(test)]
    tick_invocations: u64,
}

impl DaemonPeerRuntime {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        cluster_id: ClusterId,
        local_node_id: NodeId,
        peer_node_id: NodeId,
        local_priority: i32,
        peer_priority: i32,
        freshness_timeout: Duration,
        heartbeat_interval: Duration,
        transport_timeout: Duration,
        authenticator: MessageAuthenticator,
    ) -> Result<Self, DaemonPeerRuntimeError> {
        let transport = TcpPeerRuntime::new(
            local_node_id.clone(),
            peer_node_id.clone(),
            transport_timeout,
            transport_timeout,
        )?;
        let role = match transport.direction() {
            crate::connection_manager::ConnectionDirection::Inbound => PeerRuntimeRole::Inbound,
            crate::connection_manager::ConnectionDirection::Outbound => PeerRuntimeRole::Outbound,
        };
        Ok(Self {
            peer_active_streak: 0,
            peer_active_session: None,
            transport,
            session: SessionRuntime::new(
                cluster_id.clone(),
                local_node_id.clone(),
                peer_node_id.clone(),
                peer_priority,
            ),
            observer: PeerObserver::new(
                NoopTransport,
                cluster_id.clone(),
                local_node_id.clone(),
                peer_node_id.clone(),
                freshness_timeout.as_millis() as u64,
            ),
            process_session: ProcessSession::generate()
                .map_err(DaemonPeerRuntimeError::SessionGeneration)?,
            serializer: CborSerializer,
            authenticator,
            cluster_id,
            local_node_id,
            peer_node_id,
            peer_address: None,
            bind_address: None,
            role,
            local_priority,
            heartbeat_interval,
            last_heartbeat: None,
            outbound_handshake: None,
            outbound_established: false,
            peer_session_id: None,
            peer_sequence: None,
            current_token: None,
            handshake_deadline: None,
            clock_origin: Instant::now(),
            local_status: PeerStatusSnapshot::unobserved(),
            reconnect: RetrySchedule::new(),
            rebind: RetrySchedule::new(),
            failure_assessment: PeerFailureDetector::with_default_window(),
            shutting_down: false,
            listen_max_gap: heartbeat_interval
                .max(Duration::from_secs(1))
                .saturating_add(HANDSHAKE_TIMEOUT),
            listener_generation: 0,
            bound_since: None,
            iteration_generation: 0,
            last_accept_sample: None,
            listen_window: None,
            last_window_completion_iteration: None,
            last_window_void: None,
            outbound_attempt: None,
            inbound_authenticated: false,
            pending_identity_uncertainty: false,
            interference: ListenerInterferenceDiagnostics::default(),
            accept_voided_window: false,
            established_peer_session: None,
            probe: ProbeState::Idle,
            probe_outcome: None,
            pending_probe_requests: Vec::new(),
            #[cfg(test)]
            received_messages: Vec::new(),
            #[cfg(test)]
            heartbeat_ack_messages: Vec::new(),
            #[cfg(test)]
            heartbeat_ack_send_attempts: Vec::new(),
            #[cfg(test)]
            heartbeat_ack_send_context: None,
            #[cfg(test)]
            fail_next_ack_send: false,
            #[cfg(test)]
            last_accepted_heartbeat_sequence: None,
            #[cfg(test)]
            last_sent_heartbeat_sequence: None,
            #[cfg(test)]
            last_transport_failure_ms: None,
            #[cfg(test)]
            tick_invocations: 0,
        })
    }

    pub(crate) fn from_config(
        config: &crate::config::Config,
    ) -> Result<Self, DaemonPeerRuntimeBuildError> {
        let bind_ip = config
            .node
            .bind_address
            .as_deref()
            .map(|bind_address| {
                bind_address.parse::<std::net::Ipv4Addr>().map_err(|error| {
                    DaemonPeerRuntimeBuildError::Configuration(format!(
                        "node.bind_address is invalid: {error}"
                    ))
                })
            })
            .transpose()?;
        // The outbound (lower id) node dials `peer.address`; the inbound node
        // has none (the configuration parser enforces the role split).
        let peer_address = config
            .peer
            .address
            .as_deref()
            .map(|address| {
                address.parse::<SocketAddr>().map_err(|error| {
                    DaemonPeerRuntimeBuildError::Configuration(format!(
                        "peer.address is invalid: {error}"
                    ))
                })
            })
            .transpose()?;
        let psk =
            crate::security::Psk::load(Path::new(&config.security.psk_file)).map_err(|error| {
                DaemonPeerRuntimeBuildError::Configuration(format!(
                    "security.psk_file could not be loaded: {error}"
                ))
            })?;
        let mut runtime = Self::new(
            crate::protocol::ClusterId::new(config.cluster.id.clone()),
            crate::protocol::NodeId::new(config.node.id.clone()),
            crate::protocol::NodeId::new(config.peer.id.clone()),
            config.node.priority,
            config.peer.priority,
            Duration::from_secs(config.heartbeat.unreachable_after_sec),
            Duration::from_secs(config.heartbeat.interval_sec),
            Duration::from_secs(config.heartbeat.connect_timeout_sec),
            MessageAuthenticator::new(psk),
        )
        .map_err(|error| DaemonPeerRuntimeBuildError::Configuration(error.to_string()))?;
        runtime.peer_address = peer_address;
        // Stage 14 §11.1 condition 1: restart/uncertainty formation exists
        // only in conservative mode (configuration is immutable).
        runtime.failure_assessment = PeerFailureDetector::with_default_window()
            .with_restart_formation(config.cluster.mode == crate::config::Mode::Conservative);
        if runtime.role == PeerRuntimeRole::Inbound {
            let bind_ip = bind_ip.ok_or_else(|| {
                DaemonPeerRuntimeBuildError::Configuration(
                    "node.bind_address is required for the canonical inbound peer role".into(),
                )
            })?;
            runtime.bind_address = Some(SocketAddr::new(
                bind_ip.into(),
                config.cluster.heartbeat_port,
            ));
        }
        Ok(runtime)
    }

    pub(crate) fn initialize_transport(&mut self) -> Result<(), DaemonPeerRuntimeBuildError> {
        if let Some(address) = self.bind_address {
            // Revision 5 R.2: the startup bind precedes the first foreground
            // iteration, so its single startup instant is the bind instant
            // (and, on error, the rebind schedule base as before).
            let now = Instant::now();
            if let Err(error) = self.bind(address, now) {
                self.schedule_rebind(now, error.to_string());
            }
        }
        Ok(())
    }

    pub(crate) fn start_initial(&mut self) {
        if self.role == PeerRuntimeRole::Outbound {
            self.attempt_reconnect(Instant::now());
        }
    }

    pub(crate) fn bind(
        &mut self,
        address: SocketAddr,
        now: Instant,
    ) -> Result<SocketAddr, DaemonPeerRuntimeError> {
        let local = self.transport.bind(address)?;
        // Appendix R.2 / R.5: every successful bind starts a new listener
        // generation; the previous generation's window never survives it.
        let Some(generation) = self.listener_generation.checked_add(1) else {
            self.close_listener();
            return Err(DaemonPeerRuntimeError::Tcp(
                TcpRuntimeError::GenerationExhausted,
            ));
        };
        self.listener_generation = generation;
        self.bound_since = Some(now);
        self.void_listen_window(ListenWindowVoid::ListenerGenerationChanged);
        self.failure_assessment.observe_listener_generation_change();
        Ok(local)
    }

    pub(crate) fn role(&self) -> PeerRuntimeRole {
        self.role
    }

    pub(crate) fn set_local_status(&mut self, status: PeerStatusSnapshot) {
        self.local_status = status;
    }

    pub(crate) fn failure_assessment(&self) -> PeerFailureSnapshot {
        self.failure_assessment.snapshot()
    }

    /// F-3: this process has seen the peer report `Active` on at least two
    /// consecutive accepted heartbeats (and nothing else since). Used only to
    /// restrict the automatic trigger.
    pub(crate) fn peer_active_confirmed(&self) -> bool {
        self.peer_active_streak >= 2
    }

    /// The peer's last reported node state while its heartbeat is fresh.
    pub(crate) fn peer_reported_state(
        &self,
        now: Instant,
    ) -> Option<crate::state_machine::NodeState> {
        let observation = self.observer.snapshot(self.now_ms(now));
        (observation.state == PeerObservationState::Fresh)
            .then_some(observation.node_state)
            .flatten()
    }

    /// Current local communication-loss evidence epoch from the single
    /// detector owner, without advancing it. `None` means the current
    /// assessment (if `CommunicationLost`) carries no usable evidence —
    /// invalidated by recovery, session re-establishment, or never
    /// confirmed under the current context.
    pub(crate) fn loss_evidence(&self) -> Option<crate::failure_assessment::LocalLossEvidence> {
        self.failure_assessment.loss_evidence()
    }

    /// Stage 14 §26 R2: this runtime's own boot-scoped observer session —
    /// the `observer_session_id` every incident is bound to.
    pub(crate) fn observer_session_id(&self) -> &crate::protocol::SessionId {
        self.process_session.session_id()
    }

    /// Stage 14 §27.5 / Appendix R.8: before any blocking fencing step the
    /// single foreground owner voids the active verified-listen window. A
    /// new window starts only at the first successful sample after normal
    /// polling resumes; the step never refreshes local-loss freshness.
    pub(crate) fn void_listen_window_for_fencing_step(&mut self) {
        self.void_listen_window(ListenWindowVoid::FencingStep);
    }

    /// Test-only: number of times `tick_at` was invoked on this runtime. Used by
    /// the Linux composition test to prove at-most-once peer advancement.
    #[cfg(test)]
    pub(crate) fn tick_invocations_for_test(&self) -> u64 {
        self.tick_invocations
    }

    pub(crate) fn connect_once(
        &mut self,
        address: SocketAddr,
    ) -> Result<(), DaemonPeerRuntimeError> {
        self.connect_once_at(address, Instant::now())
    }

    fn connect_once_at(
        &mut self,
        address: SocketAddr,
        now: Instant,
    ) -> Result<(), DaemonPeerRuntimeError> {
        let token = self.transport.connect(address)?;
        self.current_token = Some(token);
        self.outbound_attempt = Some((token, now));
        self.handshake_deadline = Some((token, now.checked_add(HANDSHAKE_TIMEOUT).unwrap_or(now)));
        self.session.handle(SessionRuntimeInput::Connect {
            generation: token.generation,
            connection_id: token.connection_id,
        });
        let mut handshake = OutboundHandshake::new(
            self.cluster_id.clone(),
            self.local_node_id.clone(),
            self.peer_node_id.clone(),
            self.local_priority,
        );
        let hello = handshake
            .build_hello(&mut self.process_session, Term(1))
            .map_err(DaemonPeerRuntimeError::OutboundHandshake)?;
        self.send_message(token, hello, now)?;
        self.outbound_handshake = Some(handshake);
        Ok(())
    }

    fn attempt_reconnect(&mut self, now: Instant) {
        if self.shutting_down || self.current_token.is_some() || self.transport.pending_disconnect()
        {
            return;
        }
        let Some(address) = self.peer_address else {
            return;
        };
        self.reconnect.begin_attempt();
        if let Err(error) = self.connect_once_at(address, now) {
            // §10.3.1: a TCP connect or outbound HELLO send that really ran
            // (a syscall was issued) and failed is a real failed contact,
            // started at this iteration's `now`.
            if matches!(error, DaemonPeerRuntimeError::Tcp(TcpRuntimeError::Tcp(_))) {
                let _ = self.observe_initiated_contact_failure(now, now);
            }
            if !self.transport.pending_disconnect() {
                self.schedule_reconnect(now, error.to_string());
            }
        }
    }

    /// Stage 14 §10.3.1 (Outbound only): record a real failed contact of a
    /// connection attempt this runtime initiated.
    fn observe_initiated_contact_failure(
        &mut self,
        t_start: Instant,
        now: Instant,
    ) -> Result<(), DaemonPeerRuntimeError> {
        if self.shutting_down || self.role != PeerRuntimeRole::Outbound {
            return Ok(());
        }
        self.failure_assessment
            .observe_initiated_contact_failure(t_start, now)
            .map_err(DaemonPeerRuntimeError::from)
    }

    /// Appendix R.2: closing the listener ends the bound generation.
    fn close_listener(&mut self) {
        self.transport.close_listener();
        self.bound_since = None;
    }

    fn void_listen_window(&mut self, reason: ListenWindowVoid) {
        if self.listen_window.take().is_some() {
            self.last_window_void = Some(reason);
        }
    }

    /// Appendix R.4: one successful `accept_one` → `Ok(NoEvent)` sample at
    /// this iteration's single `now`. Extends, voids, opens, or completes the
    /// verified-listen window; a completed window is handed to the detector
    /// exactly once (§10.3.2).
    fn record_accept_sample(&mut self, now: Instant) -> Result<(), DaemonPeerRuntimeError> {
        let iteration = self.iteration_generation;
        let listener_generation = self.listener_generation;
        let loss_generation = self.failure_assessment.snapshot().loss_generation;
        // Appendix R.3(19) / R.4: a sample older than the previous sample is a
        // monotonic regression. It voids the window and never opens one, and
        // the sample high-water does not move backwards.
        if self
            .last_accept_sample
            .is_some_and(|(previous, _, _)| now < previous)
        {
            self.void_listen_window(ListenWindowVoid::ClockRegression);
            return Ok(());
        }
        self.last_accept_sample = Some((now, iteration, listener_generation));

        if let Some(window) = self.listen_window.as_mut() {
            let void = if window.listener_generation != listener_generation {
                Some(ListenWindowVoid::ListenerGenerationChanged)
            } else if iteration <= window.last_iteration {
                Some(ListenWindowVoid::IterationNotAdvanced)
            } else if window.loss_generation != loss_generation {
                Some(ListenWindowVoid::LossGenerationChanged)
            } else {
                match now.checked_duration_since(window.last_sample) {
                    None => Some(ListenWindowVoid::ClockRegression),
                    Some(gap) if gap > self.listen_max_gap => {
                        Some(ListenWindowVoid::PollGapExceeded)
                    }
                    Some(_) => None,
                }
            };
            match void {
                Some(reason) => self.void_listen_window(reason),
                None => {
                    // Phase 1-J27 TEST-ONLY (feature `j25-fault-injection`): a crash while a new
                    // observation of a live episode is in progress (J27 §10 point 3).
                    #[cfg(feature = "j25-fault-injection")]
                    if self.failure_assessment.loss_evidence().is_some() {
                        crate::j25_fault_injection::crash_if("j27-during-window");
                    }
                    window.last_sample = now;
                    window.last_iteration = iteration;
                    window.sample_count = window.sample_count.saturating_add(1);
                    let completed = now
                        .checked_duration_since(window.w_start)
                        .is_some_and(|duration| duration >= VERIFIED_LISTEN_MIN_DURATION);
                    if completed {
                        let window = self.listen_window.take().expect("window is open");
                        self.last_window_completion_iteration = Some(iteration);
                        self.failure_assessment
                            .observe_verified_listen_window(VerifiedListenWindow::new(
                                window.w_start,
                                now,
                                window.listener_generation,
                            ))
                            .map_err(DaemonPeerRuntimeError::from)?;
                        // Phase 1-J27 TEST-ONLY: a crash right after a completed window refreshed
                        // a live episode (J27 §10 point 4; the refresh exists only in memory).
                        #[cfg(feature = "j25-fault-injection")]
                        if self.failure_assessment.loss_evidence().is_some() {
                            crate::j25_fault_injection::crash_if("j27-after-refresh");
                        }
                    }
                    return Ok(());
                }
            }
        }

        // A voiding sample does not count toward the voided window, but it may
        // open the next one; the completing sample never opens a window.
        if self.listen_window.is_none() && self.last_window_completion_iteration != Some(iteration)
        {
            // Phase 1-J27 TEST-ONLY: a crash before a new observation of a live episode opens
            // (J27 §10 point 2).
            #[cfg(feature = "j25-fault-injection")]
            if self.failure_assessment.loss_evidence().is_some() {
                crate::j25_fault_injection::crash_if("j27-before-window");
            }
            self.listen_window = Some(ListenWindow {
                w_start: now,
                listener_generation,
                loss_generation,
                sample_count: 1,
                last_sample: now,
                last_iteration: iteration,
            });
        }
        Ok(())
    }

    fn attempt_rebind(&mut self, now: Instant) {
        if self.shutting_down || self.transport.listener_available() {
            return;
        }
        let Some(address) = self.bind_address else {
            return;
        };
        self.rebind.begin_attempt();
        if let Err(error) = self.bind(address, now) {
            self.schedule_rebind(now, error.to_string());
        } else {
            self.rebind.reset();
        }
    }

    fn schedule_reconnect(&mut self, now: Instant, error: impl Into<String>) {
        if !self.shutting_down {
            self.reconnect.schedule(now, error);
        }
    }

    fn schedule_rebind(&mut self, now: Instant, error: impl Into<String>) {
        if !self.shutting_down {
            self.rebind.schedule(now, error);
        }
    }

    pub(crate) fn tick(&mut self) -> Result<usize, DaemonPeerRuntimeError> {
        self.tick_at(Instant::now())
    }

    pub(crate) fn tick_at(&mut self, now: Instant) -> Result<usize, DaemonPeerRuntimeError> {
        // Without a verdict provider every probe is answered `Unknown`.
        self.tick_at_with(now, &mut || ProbeVerdict::Unknown)
    }

    /// One peer tick. `verdict` is called at most once, only when a Bootstrap
    /// Admission probe was read in this very tick, and the answer is sent
    /// before the tick ends (contract K-3): no state change of the node can
    /// happen between the observation behind `verdict` and the response.
    pub(crate) fn tick_at_with(
        &mut self,
        now: Instant,
        verdict: &mut dyn FnMut() -> ProbeVerdict,
    ) -> Result<usize, DaemonPeerRuntimeError> {
        #[cfg(test)]
        {
            self.tick_invocations += 1;
        }
        if self.shutting_down {
            return Ok(0);
        }
        // Appendix R.2: one iteration generation per `tick_at` call. A
        // saturated counter no longer advances, which voids any window.
        self.iteration_generation = self.iteration_generation.saturating_add(1);
        self.flush_interference_warn(now);

        self.drain_disconnect(now)?;

        if self.role == PeerRuntimeRole::Outbound && self.reconnect.due(now) {
            self.attempt_reconnect(now);
        }

        if self.role == PeerRuntimeRole::Inbound
            && !self.transport.listener_available()
            && self.rebind.due(now)
        {
            self.attempt_rebind(now);
        }

        if self.current_token.is_none()
            && self.role == PeerRuntimeRole::Inbound
            && self.transport.listener_available()
        {
            match self.transport.accept_one() {
                Ok(TcpRuntimeStep::Connected(token)) => {
                    // Appendix R.6: any accepted connection voids the window
                    // at accept time, before any authentication outcome.
                    self.accept_voided_window = self.listen_window.is_some();
                    self.void_listen_window(ListenWindowVoid::AcceptedConnection);
                    self.inbound_authenticated = false;
                    self.current_token = Some(token);
                    self.handshake_deadline = Some((token, now + HANDSHAKE_TIMEOUT));
                    self.session.handle(SessionRuntimeInput::Connect {
                        generation: token.generation,
                        connection_id: token.connection_id,
                    });
                }
                Ok(TcpRuntimeStep::NoEvent) => self.record_accept_sample(now)?,
                Ok(_) => {}
                Err(error) => {
                    self.void_listen_window(ListenWindowVoid::AcceptError);
                    self.close_listener();
                    self.schedule_rebind(now, error.to_string());
                }
            }
        }

        self.expire_handshake_if_due(now);

        let mut processed = 0;
        while processed < MAX_FRAMES_PER_TICK {
            let step = match self.transport.poll_frame() {
                Ok(step) => step,
                Err(error) => {
                    self.drain_disconnect(now)?;
                    return Err(error.into());
                }
            };
            match step {
                TcpRuntimeStep::NoEvent => break,
                TcpRuntimeStep::Frame { token, payload } => {
                    processed += 1;
                    self.process_frame(token, &payload, now)?;
                }
                TcpRuntimeStep::TransportUnavailable { .. } => {
                    self.clear_connection_state();
                    self.observe_transport_failure(now)?;
                    self.drain_disconnect(now)?;
                    break;
                }
                _ => break,
            }
        }

        self.answer_probes(now, verdict);
        self.send_requested_probe(now);
        if self.is_established() && self.heartbeat_due(now) {
            self.send_heartbeat_at(now)?;
            self.last_heartbeat = Some(now);
        }
        self.advance_failure_assessment(now)?;
        self.release_connection_of_live_loss_episode(now);
        Ok(processed)
    }

    /// Phase 1-J27 candidate (OD-J26-6): an authenticated connection that is still held while
    /// the detector has a live loss episode delivered no trusted heartbeat for the whole
    /// confirmation (a black-holed peer path leaves a half-open TCP connection: no FIN, no
    /// RST). While it is held, the Inbound role never samples its accept path (Appendix R.4)
    /// and the Outbound role never dials (§10.3.1), so neither permitted refresh source can
    /// run and the episode can only age out. Releasing it records no observation and touches
    /// no detector field: freshness still moves only by a later §10.3 observation, an
    /// authenticated return still ends the episode (R.6, §10.8.1), and a connection that is
    /// not authenticated is left to the handshake deadline (an unauthenticated release would
    /// be identity uncertainty, §10.5).
    fn release_connection_of_live_loss_episode(&mut self, now: Instant) {
        let Some(token) = self.current_token else {
            return;
        };
        if !self.is_established() || self.failure_assessment.loss_evidence().is_none() {
            return;
        }
        self.disconnect_current(token, now);
    }

    fn process_frame(
        &mut self,
        token: ConnectionToken,
        payload: &[u8],
        now: Instant,
    ) -> Result<(), DaemonPeerRuntimeError> {
        let message = match receive(payload, &self.serializer, &self.authenticator) {
            Ok(message) => message,
            Err(ReceiveError::Authentication(_)) => {
                // §10.4 / §10.5: an authentication failure on a connection
                // attributed to the configured peer is identity uncertainty.
                self.mark_identity_uncertainty(token);
                self.disconnect_current(token, now);
                return Ok(());
            }
            Err(error) => {
                // §10.4 / §10.5: decoding/validation failures invalidate.
                self.mark_identity_uncertainty(token);
                self.disconnect_current(token, now);
                return Err(DaemonPeerRuntimeError::Receive(error));
            }
        };

        if self.role == PeerRuntimeRole::Outbound && !self.outbound_established {
            let (established_session_id, peer_sequence) = {
                let Some(handshake) = self.outbound_handshake.as_mut() else {
                    self.disconnect_current(token, now);
                    return Err(DaemonPeerRuntimeError::NotEstablished);
                };
                if let Err(error) = handshake.accept_hello_ack(&message) {
                    // §10.5: a handshake identity mismatch on a connection
                    // this runtime initiated to the configured peer.
                    if matches!(
                        error,
                        OutboundHandshakeError::ClusterMismatch
                            | OutboundHandshakeError::SenderMismatch
                            | OutboundHandshakeError::ReceiverMismatch
                    ) {
                        self.mark_identity_uncertainty(token);
                    }
                    self.disconnect_current(token, now);
                    return Err(DaemonPeerRuntimeError::OutboundHandshake(error));
                }
                (
                    handshake
                        .peer_session_id()
                        .cloned()
                        .expect("HELLO_ACK session"),
                    handshake.peer_last_accepted_sequence(),
                )
            };
            self.outbound_established = true;
            self.handshake_deadline = None;
            self.outbound_attempt = None;
            self.peer_session_id = Some(established_session_id.clone());
            self.established_peer_session = Some(established_session_id.clone());
            self.peer_sequence = peer_sequence;
            self.observe_session_established_at(established_session_id, now)?;
            self.reconnect.reset();
            return Ok(());
        }

        let input = SessionRuntimeInput::Authenticated {
            generation: token.generation,
            connection_id: token.connection_id,
            message: message.clone(),
        };
        if self.role == PeerRuntimeRole::Inbound {
            let events = self.session.handle(input);
            self.apply_session_events(token, events, now)?;
            return Ok(());
        }

        let expected_kind = match message.unsigned().message {
            ProtocolMessage::Heartbeat(_) => MessageType::Heartbeat,
            ProtocolMessage::HeartbeatAck => MessageType::HeartbeatAck,
            // Bootstrap Admission: exactly the four frozen Protocol v1 probe
            // types are added; every other kind still disconnects.
            ProtocolMessage::PromotionIntent(_) => MessageType::PromotionIntent,
            ProtocolMessage::PromotionAck => MessageType::PromotionAck,
            ProtocolMessage::PromotionBlock => MessageType::PromotionBlock,
            ProtocolMessage::PromotionUnknown => MessageType::PromotionUnknown,
            _ => {
                self.disconnect_current(token, now);
                return Ok(());
            }
        };
        if !self.accept_outbound_message(&message, expected_kind) {
            // §10.5: an authenticated-envelope identity mismatch (cluster,
            // node, or session) is identity uncertainty; a stale sequence or
            // unexpected kind is an ordinary disconnect.
            if self.outbound_identity_mismatch(&message) {
                self.mark_identity_uncertainty(token);
            }
            self.disconnect_current(token, now);
            return Ok(());
        }

        #[cfg(test)]
        self.received_messages.push(message.unsigned().clone());

        match message.unsigned().message {
            ProtocolMessage::Heartbeat(_) => {
                self.observe_established_heartbeat(message.unsigned().clone(), now)?;
                let ack = build_heartbeat_ack(
                    &mut self.process_session,
                    self.cluster_id.clone(),
                    self.local_node_id.clone(),
                    self.peer_node_id.clone(),
                    Term(1),
                    None,
                )
                .map_err(DaemonPeerRuntimeError::Heartbeat)?;
                self.send_message(token, ack, now)?;
            }
            ProtocolMessage::HeartbeatAck => {}
            ProtocolMessage::PromotionIntent(_) => {
                self.on_probe_request(token, message.unsigned());
            }
            ProtocolMessage::PromotionAck
            | ProtocolMessage::PromotionBlock
            | ProtocolMessage::PromotionUnknown => {
                self.on_probe_response(token, message.unsigned());
            }
            _ => {
                self.disconnect_current(token, now);
            }
        }
        Ok(())
    }

    fn apply_session_events(
        &mut self,
        token: ConnectionToken,
        events: Vec<SessionRuntimeEvent>,
        now: Instant,
    ) -> Result<(), DaemonPeerRuntimeError> {
        for event in events {
            match event {
                SessionRuntimeEvent::SendHelloAck => {
                    let ack = build_hello_ack(
                        &mut self.process_session,
                        self.cluster_id.clone(),
                        self.local_node_id.clone(),
                        self.peer_node_id.clone(),
                        Term(1),
                    )
                    .map_err(DaemonPeerRuntimeError::Sequence)?;
                    self.send_message(token, ack, now)?;
                }
                SessionRuntimeEvent::SessionEstablished { session_id } => {
                    self.handshake_deadline = None;
                    self.inbound_authenticated = true;
                    self.established_peer_session = Some(session_id.clone());
                    self.observe_session_established_at(session_id, now)?;
                    self.reconnect.reset();
                }
                SessionRuntimeEvent::EstablishedHeartbeat(message) => {
                    #[cfg(test)]
                    let heartbeat_sequence = message.as_unsigned().common.sequence;
                    #[cfg(test)]
                    {
                        self.last_accepted_heartbeat_sequence = Some(heartbeat_sequence);
                        if self.fail_next_ack_send {
                            self.fail_next_ack_send = false;
                            self.transport
                                .fail_next_send_of_for_test(MessageType::HeartbeatAck);
                        }
                    }
                    self.observe_established_heartbeat(message.into_unsigned(), now)?;
                    let ack = build_heartbeat_ack(
                        &mut self.process_session,
                        self.cluster_id.clone(),
                        self.local_node_id.clone(),
                        self.peer_node_id.clone(),
                        Term(1),
                        None,
                    )
                    .map_err(DaemonPeerRuntimeError::Heartbeat)?;
                    #[cfg(test)]
                    self.heartbeat_ack_messages
                        .push((heartbeat_sequence, ack.clone()));
                    #[cfg(test)]
                    {
                        self.heartbeat_ack_send_context =
                            Some((heartbeat_sequence, ack.common.session_id.clone()));
                    }
                    let result = self.send_message(token, ack, now);
                    #[cfg(test)]
                    {
                        self.heartbeat_ack_send_context = None;
                    }
                    result?;
                }
                SessionRuntimeEvent::ProbeRequest(message) => {
                    self.on_probe_request(token, &message);
                }
                SessionRuntimeEvent::ProbeResponse(message) => {
                    self.on_probe_response(token, &message);
                }
                SessionRuntimeEvent::TransportUnavailable => {
                    self.observe_transport_failure(now)?;
                }
                SessionRuntimeEvent::IgnoredAuthenticatedMessage => {}
                SessionRuntimeEvent::Rejected(_) => {
                    // §10.5: a rejected handshake/message on an accepted
                    // connection (identity, protocol, or malformed handshake).
                    self.mark_identity_uncertainty(token);
                    self.disconnect_current(token, now);
                }
            }
        }
        Ok(())
    }

    // ---- Bootstrap Admission probe (contract K-2 / K-3) ----------------------

    /// What a BA session and probe are bound to right now: the established
    /// connection, the peer's process session and this process's own observer
    /// session. `None` unless a session is established.
    pub(crate) fn bootstrap_stamp(&self) -> Option<BootstrapStamp> {
        if !self.is_established() {
            return None;
        }
        Some(BootstrapStamp {
            connection: self.current_token?,
            peer_session: self.established_peer_session.clone()?,
            observer_session: self.process_session.session_id().clone(),
        })
    }

    /// Ask for one probe to be sent from the next tick. Only on an established
    /// connection and only when no probe is outstanding. The nonce is drawn
    /// when the probe is actually sent, i.e. after the caller's anchor.
    pub(crate) fn request_probe(&mut self) -> bool {
        if self.bootstrap_stamp().is_none() || self.probe != ProbeState::Idle {
            return false;
        }
        self.probe_outcome = None;
        self.probe = ProbeState::Requested;
        true
    }

    /// Take the probe outcome, once.
    pub(crate) fn take_probe_outcome(&mut self) -> Option<ProbeOutcome> {
        self.probe_outcome.take()
    }

    /// Drop an outstanding probe and any outcome (the session was dropped).
    pub(crate) fn discard_probe(&mut self) {
        self.probe = ProbeState::Idle;
        self.probe_outcome = None;
    }

    /// Answering side: remember a probe read in this tick. Nothing is decided
    /// here; the verdict is computed once, after the frame loop, from the
    /// node's state at that point of the same tick.
    fn on_probe_request(&mut self, token: ConnectionToken, message: &UnsignedEnvelope) {
        if self.current_token != Some(token)
            || self.pending_probe_requests.len() >= MAX_PROBE_REQUESTS_PER_TICK
        {
            return;
        }
        let Some(operation_id) = message.common.operation_id.clone() else {
            return;
        };
        let well_formed = matches!(
            &message.message,
            ProtocolMessage::PromotionIntent(payload) if payload.reason == PROBE_REASON
        ) && is_valid_operation_id(operation_id.as_str());
        self.pending_probe_requests.push(ProbeRequest {
            token,
            operation_id,
            well_formed,
        });
    }

    fn answer_probes(&mut self, now: Instant, verdict: &mut dyn FnMut() -> ProbeVerdict) {
        if self.pending_probe_requests.is_empty() {
            return;
        }
        let requests = std::mem::take(&mut self.pending_probe_requests);
        let computed = verdict();
        for request in requests {
            if self.current_token != Some(request.token) {
                continue;
            }
            let answer = if request.well_formed {
                computed
            } else {
                ProbeVerdict::Unknown
            };
            let message = match answer {
                ProbeVerdict::Ack => ProtocolMessage::PromotionAck,
                ProbeVerdict::Block => ProtocolMessage::PromotionBlock,
                ProbeVerdict::Unknown => ProtocolMessage::PromotionUnknown,
            };
            if let Ok(envelope) = self.probe_envelope(message, &request.operation_id) {
                // Fire and forget: a response that cannot be sent is a probe
                // the asker will treat as failed.
                let _ = self.send_message(request.token, envelope, now);
            }
        }
    }

    /// Evaluating side: send the requested probe.
    fn send_requested_probe(&mut self, now: Instant) {
        if self.probe != ProbeState::Requested {
            return;
        }
        let (Some(stamp), Some(token)) = (self.bootstrap_stamp(), self.current_token) else {
            self.probe = ProbeState::Idle;
            self.probe_outcome = Some(ProbeOutcome::Invalid);
            return;
        };
        let mut random = [0u8; 16];
        if getrandom::fill(&mut random).is_err() {
            self.probe = ProbeState::Idle;
            self.probe_outcome = Some(ProbeOutcome::Invalid);
            return;
        }
        let operation_id = format!(
            "{}{}",
            crate::bootstrap_admission::OPERATION_ID_PREFIX,
            random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        let message = ProtocolMessage::PromotionIntent(PromotionIntentPayload {
            priority: self.local_priority,
            reason: PROBE_REASON.to_string(),
        });
        let sent = self
            .probe_envelope(message, &OperationId::new(operation_id.clone()))
            .and_then(|envelope| self.send_message(token, envelope, now));
        match sent {
            Ok(()) => {
                self.probe = ProbeState::Sent {
                    operation_id,
                    stamp,
                };
            }
            Err(_) => {
                self.probe = ProbeState::Idle;
                self.probe_outcome = Some(ProbeOutcome::Invalid);
            }
        }
    }

    /// Evaluating side: an authenticated response on the established session.
    /// It only counts if it echoes the outstanding nonce exactly, on the very
    /// connection and peer session the probe was sent on.
    fn on_probe_response(&mut self, token: ConnectionToken, message: &UnsignedEnvelope) {
        let ProbeState::Sent {
            operation_id,
            stamp,
        } = &self.probe
        else {
            // Unsolicited: ignored (there is nothing to invalidate).
            return;
        };
        let verdict = match &message.message {
            ProtocolMessage::PromotionAck => ProbeVerdict::Ack,
            ProtocolMessage::PromotionBlock => ProbeVerdict::Block,
            ProtocolMessage::PromotionUnknown => ProbeVerdict::Unknown,
            _ => return,
        };
        let matches = message
            .common
            .operation_id
            .as_ref()
            .is_some_and(|echoed| echoed.as_str() == operation_id)
            && stamp.connection == token
            && self.current_token == Some(token)
            && message.common.session_id == stamp.peer_session
            && self.established_peer_session.as_ref() == Some(&stamp.peer_session)
            && stamp.observer_session == *self.process_session.session_id();
        let outcome = if matches {
            ProbeOutcome::Response {
                stamp: stamp.clone(),
                verdict,
            }
        } else {
            ProbeOutcome::Invalid
        };
        self.probe = ProbeState::Idle;
        self.probe_outcome = Some(outcome);
    }

    fn probe_envelope(
        &mut self,
        message: ProtocolMessage,
        operation_id: &OperationId,
    ) -> Result<UnsignedEnvelope, DaemonPeerRuntimeError> {
        let envelope = UnsignedEnvelope {
            common: CommonFields {
                protocol_version: PROTOCOL_VERSION,
                cluster_id: self.cluster_id.clone(),
                sender_node_id: self.local_node_id.clone(),
                receiver_node_id: self.peer_node_id.clone(),
                session_id: self.process_session.session_id().clone(),
                sequence: self
                    .process_session
                    .next_sequence()
                    .map_err(DaemonPeerRuntimeError::Sequence)?,
                term: Term(1),
                lease_id: None,
                request_id: None,
                operation_id: Some(operation_id.clone()),
            },
            message,
        };
        envelope
            .validate()
            .map_err(DaemonPeerRuntimeError::Protocol)?;
        Ok(envelope)
    }

    fn send_heartbeat(&mut self) -> Result<(), DaemonPeerRuntimeError> {
        self.send_heartbeat_at(Instant::now())
    }

    fn send_heartbeat_at(&mut self, now: Instant) -> Result<(), DaemonPeerRuntimeError> {
        let token = self
            .current_token
            .ok_or(DaemonPeerRuntimeError::NotEstablished)?;
        let local_status = self.local_status_payload();
        let heartbeat = build_heartbeat(
            &mut self.process_session,
            self.cluster_id.clone(),
            self.local_node_id.clone(),
            self.peer_node_id.clone(),
            Term(1),
            None,
            local_status,
        )
        .map_err(DaemonPeerRuntimeError::Heartbeat)?;
        #[cfg(test)]
        {
            self.last_sent_heartbeat_sequence = Some(heartbeat.common.sequence);
        }
        self.send_message(token, heartbeat, now)?;
        Ok(())
    }

    fn local_status_payload(&self) -> NodeStatusPayload {
        NodeStatusPayload {
            node_state: self.local_status.node_state,
            operation_phase: self.local_status.operation_phase,
            role: self.local_status.role,
            service_state: service_state(self.local_status.service),
            health_state: health_state(self.local_status.health),
            vip_state: vip_state(self.local_status.vip),
        }
    }

    fn send_message(
        &mut self,
        token: ConnectionToken,
        message: UnsignedEnvelope,
        now: Instant,
    ) -> Result<(), DaemonPeerRuntimeError> {
        #[cfg(test)]
        if message.message.message_type() == MessageType::HeartbeatAck
            && let Some(context) = &self.heartbeat_ack_send_context
        {
            self.heartbeat_ack_send_attempts.push(context.clone());
        }
        let result =
            self.transport
                .send_message(token, message, &self.serializer, &self.authenticator);
        if result.is_err() && self.transport.current_token().is_none() {
            self.clear_connection_state();
            let _ = self.observe_transport_failure(now);
        }
        result.map_err(DaemonPeerRuntimeError::Tcp)
    }

    fn drain_disconnect(&mut self, now: Instant) -> Result<(), DaemonPeerRuntimeError> {
        let step = self.transport.poll_pending_disconnect(&mut self.session);
        if matches!(step, TcpRuntimeStep::TransportUnavailable { .. }) {
            self.clear_connection_state();
            let _ = self.observe_transport_failure(now);
            if self.role == PeerRuntimeRole::Outbound {
                self.schedule_reconnect(now, "connection disconnect completed");
            }
        }
        Ok(())
    }

    fn expire_handshake_if_due(&mut self, now: Instant) {
        let Some((token, deadline)) = self.handshake_deadline else {
            return;
        };
        if self.current_token != Some(token) || self.is_established() || now < deadline {
            return;
        }

        self.handshake_deadline = None;
        // §10.3.1: the handshake deadline expired on a connection this
        // runtime initiated, with no authenticated HELLO_ACK.
        let initiated_at = self
            .outbound_attempt
            .filter(|(attempt, _)| *attempt == token)
            .map(|(_, started)| started);
        self.transport.detach(token);
        self.clear_connection_state();
        let _ = self.observe_transport_failure(now);
        if let Some(t_start) = initiated_at {
            let _ = self.observe_initiated_contact_failure(t_start, now);
        }
    }

    fn disconnect_current(&mut self, token: ConnectionToken, now: Instant) {
        if self.current_token == Some(token) {
            let _ = self.transport.disconnect(token, &mut self.session);
            self.clear_connection_state();
            let _ = self.observe_transport_failure(now);
            if self.role == PeerRuntimeRole::Outbound {
                self.schedule_reconnect(now, "connection disconnect completed");
            }
        }
    }

    fn clear_connection_state(&mut self) {
        // §10.5 / R.6: an accepted Inbound connection that ends without
        // authenticating as the configured peer is identity uncertainty.
        if self.role == PeerRuntimeRole::Inbound
            && self.current_token.is_some()
            && !self.inbound_authenticated
        {
            self.pending_identity_uncertainty = true;
        }
        self.inbound_authenticated = false;
        self.outbound_attempt = None;
        self.current_token = None;
        self.handshake_deadline = None;
        self.outbound_established = false;
        self.outbound_handshake = None;
        self.peer_session_id = None;
        self.peer_sequence = None;
        self.established_peer_session = None;
        // A probe is bound to the connection it was sent on: it dies with it.
        self.pending_probe_requests.clear();
        if self.probe != ProbeState::Idle {
            self.probe = ProbeState::Idle;
            self.probe_outcome = Some(ProbeOutcome::Invalid);
        }
    }

    fn mark_identity_uncertainty(&mut self, token: ConnectionToken) {
        if self.current_token == Some(token) {
            self.pending_identity_uncertainty = true;
        }
    }

    /// §10.5: the authenticated envelope names a different cluster, sender,
    /// receiver, or session than the established outbound session.
    fn outbound_identity_mismatch(&self, message: &AuthenticatedMessage) -> bool {
        let common = &message.unsigned().common;
        common.cluster_id != self.cluster_id
            || common.sender_node_id != self.peer_node_id
            || common.receiver_node_id != self.local_node_id
            || self
                .peer_session_id
                .as_ref()
                .is_some_and(|session| &common.session_id != session)
    }

    fn accept_outbound_message(
        &mut self,
        message: &AuthenticatedMessage,
        expected_kind: MessageType,
    ) -> bool {
        let common = &message.unsigned().common;
        let Some(peer_session_id) = self.peer_session_id.as_ref() else {
            return false;
        };
        if common.cluster_id != self.cluster_id
            || common.sender_node_id != self.peer_node_id
            || common.receiver_node_id != self.local_node_id
            || &common.session_id != peer_session_id
            || message.unsigned().message.message_type() != expected_kind
            || self
                .peer_sequence
                .is_some_and(|sequence| common.sequence.0 <= sequence.0)
        {
            return false;
        }
        self.peer_sequence = Some(common.sequence);
        true
    }

    fn observe_session_established_at(
        &mut self,
        session_id: SessionId,
        now: Instant,
    ) -> Result<(), DaemonPeerRuntimeError> {
        self.observer.observe_event(
            PeerTransportEvent::SessionEstablished {
                session_id: session_id.clone(),
            },
            self.now_ms(now),
        );
        self.failure_assessment
            .observe_session_established(session_id, now)
            .map_err(DaemonPeerRuntimeError::from)
    }

    fn observe_established_heartbeat(
        &mut self,
        message: UnsignedEnvelope,
        now: Instant,
    ) -> Result<(), DaemonPeerRuntimeError> {
        let session_id = message.common.session_id.clone();
        let sequence = message.common.sequence;
        self.observer.observe_event(
            PeerTransportEvent::EstablishedHeartbeat(message),
            self.now_ms(now),
        );
        let observation = self.observer.snapshot(self.now_ms(now));
        if observation.state == PeerObservationState::Fresh {
            self.failure_assessment
                .observe_trusted_heartbeat(&session_id, sequence, now)
                .map_err(DaemonPeerRuntimeError::from)?;
            // Count only a heartbeat the observer itself accepted.
            if observation.sequence == Some(sequence)
                && observation.session_id.as_ref() == Some(&session_id)
            {
                if self.peer_active_session.as_ref() != Some(&session_id) {
                    self.peer_active_session = Some(session_id.clone());
                    self.peer_active_streak = 0;
                }
                if observation.node_state == Some(crate::state_machine::NodeState::Active) {
                    self.peer_active_streak = self.peer_active_streak.saturating_add(1);
                } else {
                    self.peer_active_streak = 0;
                }
            }
        }
        Ok(())
    }

    fn advance_failure_assessment(&mut self, now: Instant) -> Result<(), DaemonPeerRuntimeError> {
        match self.observer.snapshot(self.now_ms(now)).state {
            PeerObservationState::Stale => self
                .failure_assessment
                .observe_heartbeat_stale(now)
                .map_err(DaemonPeerRuntimeError::from)?,
            PeerObservationState::Unavailable => self
                .failure_assessment
                .observe_transport_failure(now)
                .map_err(DaemonPeerRuntimeError::from)?,
            _ => {}
        }
        self.failure_assessment
            .tick(now)
            .map_err(DaemonPeerRuntimeError::from)
    }

    /// Stage 14 §28.1: an accepted connection ended without authenticating as
    /// the configured peer (Inbound only). Diagnostic only: it touches the
    /// counters and writes at most one rate-bounded WARN, and it returns
    /// nothing to the detector or to any decision.
    fn note_unauthenticated_arrival(&mut self, now: Instant) {
        if self.role != PeerRuntimeRole::Inbound {
            return;
        }
        let voided_window = std::mem::take(&mut self.accept_voided_window);
        if let Some(warn) = self.interference.record(now, voided_window) {
            crate::operator_log::warn_listener_interference(
                warn.arrivals,
                warn.voided_windows,
                warn.first,
            );
        }
    }

    /// Stage 14 §28.1: report counts held back by the WARN rate bound.
    fn flush_interference_warn(&mut self, now: Instant) {
        if let Some(warn) = self.interference.flush(now) {
            crate::operator_log::warn_listener_interference(
                warn.arrivals,
                warn.voided_windows,
                warn.first,
            );
        }
    }

    /// Stage 14 §28.1: unauthenticated arrivals in the last 30 s, for the
    /// blocked-attempt log line only. The value is diagnostic; no decision may
    /// depend on it (guard `017_diagnostics_not_evidence`).
    pub(crate) fn listener_interference_recent(&self, now: Instant) -> u64 {
        self.interference.recent_arrivals(now)
    }

    #[cfg(test)]
    fn reset_interference_for_test(&mut self) {
        self.interference = ListenerInterferenceDiagnostics::default();
        self.accept_voided_window = false;
    }

    fn observe_transport_failure(&mut self, now: Instant) -> Result<(), DaemonPeerRuntimeError> {
        #[cfg(test)]
        {
            self.last_transport_failure_ms = Some(self.now_ms(now));
        }
        // §10.5: a connection that ended in identity/authentication
        // uncertainty is a non-authenticated invalidation. It is applied
        // before the ordinary transport failure, so a Healthy detector never
        // takes the elapsed-time path after uncertainty.
        if std::mem::take(&mut self.pending_identity_uncertainty) && !self.shutting_down {
            self.note_unauthenticated_arrival(now);
            self.void_listen_window(ListenWindowVoid::IdentityUncertainty);
            self.failure_assessment
                .observe_identity_uncertainty(now)
                .map_err(DaemonPeerRuntimeError::from)?;
        }
        self.observer
            .observe_event(PeerTransportEvent::TransportFailure, self.now_ms(now));
        self.failure_assessment
            .observe_transport_failure(now)
            .map_err(DaemonPeerRuntimeError::from)
    }

    #[cfg(test)]
    fn last_transport_failure_ms_for_test(&self) -> Option<u64> {
        self.last_transport_failure_ms
    }

    fn is_established(&self) -> bool {
        match self.role {
            PeerRuntimeRole::Inbound => self.session.state() == SessionRuntimeState::Established,
            PeerRuntimeRole::Outbound => self.outbound_established,
        }
    }

    fn heartbeat_due(&self, now: Instant) -> bool {
        self.last_heartbeat
            .is_none_or(|last| now.saturating_duration_since(last) >= self.heartbeat_interval)
    }

    fn now_ms(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.clock_origin).as_millis() as u64
    }

    pub(crate) fn snapshot(&self, now: Instant) -> PeerObservation {
        self.observer.snapshot(self.now_ms(now))
    }

    pub(crate) fn transport_recovery_snapshot(&self) -> TransportRecoverySnapshot {
        TransportRecoverySnapshot {
            connected: self.current_token.is_some(),
            listener_available: self.transport.listener_available(),
            reconnect_scheduled: self.reconnect.next_attempt_at.is_some(),
            rebind_scheduled: self.rebind.next_attempt_at.is_some(),
            consecutive_reconnect_failures: self.reconnect.consecutive_failures,
            consecutive_rebind_failures: self.rebind.consecutive_failures,
            last_error: self
                .reconnect
                .last_error
                .clone()
                .or_else(|| self.rebind.last_error.clone()),
        }
    }

    pub(crate) fn shutdown(&mut self) {
        self.shutdown_at(Instant::now());
    }

    fn shutdown_at(&mut self, now: Instant) {
        self.shutting_down = true;
        self.void_listen_window(ListenWindowVoid::Shutdown);
        self.reconnect.reset();
        self.rebind.reset();
        self.close_listener();
        if let Some(token) = self.current_token {
            let _ = self.transport.disconnect(token, &mut self.session);
            self.clear_connection_state();
            let _ = self.observe_transport_failure(now);
        }
    }
}

fn service_state(state: DaemonService) -> String {
    match state {
        DaemonService::Running => "running",
        DaemonService::Stopped => "stopped",
        DaemonService::Unknown => "unknown",
    }
    .into()
}

fn health_state(state: DaemonHealth) -> String {
    match state {
        DaemonHealth::Healthy => "healthy",
        DaemonHealth::Unhealthy => "unhealthy",
        DaemonHealth::Unknown => "unknown",
    }
    .into()
}

fn vip_state(state: DaemonVip) -> String {
    match state {
        DaemonVip::Present => "present",
        DaemonVip::Absent => "absent",
        DaemonVip::Unknown => "unknown",
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_observer::PeerObservationState;
    use crate::protocol::Role;
    use crate::security::Psk;
    use crate::state_machine::{DemotionPhase, NodeState, OperationPhase};
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    fn auth() -> MessageAuthenticator {
        MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32]))
    }

    fn pair() -> (DaemonPeerRuntime, DaemonPeerRuntime, SocketAddr) {
        let mut inbound = DaemonPeerRuntime::new(
            ClusterId::new("cluster"),
            NodeId::new("node-b"),
            NodeId::new("node-a"),
            90,
            100,
            Duration::from_secs(10),
            Duration::from_secs(1),
            Duration::from_secs(2),
            auth(),
        )
        .unwrap();
        let address = inbound
            .bind("127.0.0.1:0".parse().unwrap(), Instant::now())
            .unwrap();
        let outbound = DaemonPeerRuntime::new(
            ClusterId::new("cluster"),
            NodeId::new("node-a"),
            NodeId::new("node-b"),
            100,
            90,
            Duration::from_secs(10),
            Duration::from_secs(1),
            Duration::from_secs(2),
            auth(),
        )
        .unwrap();
        (outbound, inbound, address)
    }

    fn establish_pair() -> (DaemonPeerRuntime, DaemonPeerRuntime, Instant) {
        let (mut outbound, mut inbound, address) = pair();
        outbound.connect_once(address).unwrap();
        let start = Instant::now();
        for offset in 0..4096u64 {
            let now = start + Duration::from_millis(offset);
            outbound.tick_at(now).unwrap();
            inbound.tick_at(now).unwrap();
            let next = now + Duration::from_millis(1);
            outbound.tick_at(next).unwrap();
            inbound.tick_at(next).unwrap();
            if outbound.snapshot(start + Duration::from_secs(1)).state
                == PeerObservationState::Fresh
                && inbound.snapshot(start + Duration::from_secs(1)).state
                    == PeerObservationState::Fresh
            {
                return (outbound, inbound, start);
            }
            thread::yield_now();
        }
        panic!("two runtime loopback did not reach Fresh");
    }

    /// Stage 14 Phase 14.2 (Design Revision 4 §8, §12.2, §22, §26 R2): the
    /// observer session is this runtime's own `ProcessSession` id. It is
    /// boot-scoped — generated once per runtime, unchanged by ticks,
    /// disconnects, and reconnects — and only a new runtime (an observer
    /// restart) has a different one, together with a detector that carries
    /// no loss provenance and no generation.
    #[test]
    fn stage14_observer_session_is_boot_scoped_and_survives_reconnect() {
        use crate::failure_assessment::PeerFailureAssessment;

        let (mut outbound, mut inbound, address) = pair();
        // As `from_config` does: the Outbound role reconnects to this address.
        outbound.peer_address = Some(address);
        outbound.connect_once(address).unwrap();
        let start = Instant::now();
        let mut now = start;
        for _ in 0..4_000u64 {
            now += Duration::from_millis(5);
            let _ = outbound.tick_at(now);
            let _ = inbound.tick_at(now);
            if outbound.is_established() && inbound.is_established() {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        assert!(outbound.is_established() && inbound.is_established());
        let outbound_observer = outbound.process_session.session_id().clone();
        let inbound_observer = inbound.process_session.session_id().clone();
        assert_ne!(outbound_observer, inbound_observer);
        for observer in [&outbound_observer, &inbound_observer] {
            let value = observer.as_str();
            assert!(
                !value.is_empty()
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "observer session id must be non-empty lowercase hex: {value}"
            );
        }

        // A real disconnect followed by the Outbound runtime's own reconnect.
        let old_token = inbound.current_token.unwrap();
        now += Duration::from_secs(2);
        inbound.disconnect_current(old_token, now);
        let mut reconnected = false;
        for _ in 0..4_000u64 {
            now += Duration::from_millis(5);
            let _ = outbound.tick_at(now);
            let _ = inbound.tick_at(now);
            if outbound.is_established()
                && inbound.is_established()
                && inbound
                    .current_token
                    .is_some_and(|token| token != old_token)
            {
                reconnected = true;
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        assert!(reconnected, "outbound runtime did not reconnect");
        assert_eq!(outbound.process_session.session_id(), &outbound_observer);
        assert_eq!(inbound.process_session.session_id(), &inbound_observer);

        // An observer restart is a new runtime: a new observer session and a
        // detector with no provenance and no loss generation.
        let (restarted, _, _) = pair();
        assert_ne!(restarted.process_session.session_id(), &outbound_observer);
        let snapshot = restarted.failure_assessment();
        assert_eq!(snapshot.assessment, PeerFailureAssessment::Unobserved);
        assert_eq!(snapshot.suspect_origin, None);
        assert_eq!(snapshot.loss_generation, 0);
        assert!(restarted.loss_evidence().is_none());
    }

    // -----------------------------------------------------------------
    // Stage 14 Phase 14.3: permitted observations and Appendix R
    // verified-listen / poll-gap tracking (Design Revision 4 §10.3, §10.5,
    // §11, Appendix R, §34.12, §34.13 GAP-01..12).
    // -----------------------------------------------------------------

    use crate::failure_assessment::{
        FAILURE_CONFIRMATION_WINDOW, PeerFailureAssessment, SuspectOrigin,
    };

    /// A canonical Inbound runtime (node-b listening for node-a) with a bound
    /// loopback listener and conservative-mode formation enabled.
    fn inbound_listener(interval: Duration) -> (DaemonPeerRuntime, SocketAddr) {
        let mut runtime = DaemonPeerRuntime::new(
            ClusterId::new("cluster"),
            NodeId::new("node-b"),
            NodeId::new("node-a"),
            90,
            100,
            Duration::from_secs(10),
            interval,
            Duration::from_secs(2),
            auth(),
        )
        .unwrap();
        runtime.failure_assessment =
            PeerFailureDetector::with_default_window().with_restart_formation(true);
        let address = runtime
            .bind("127.0.0.1:0".parse().unwrap(), Instant::now())
            .unwrap();
        (runtime, address)
    }

    /// A canonical Outbound runtime (node-a dialing node-b), conservative.
    fn outbound_dialer(peer: SocketAddr) -> DaemonPeerRuntime {
        let mut runtime = DaemonPeerRuntime::new(
            ClusterId::new("cluster"),
            NodeId::new("node-a"),
            NodeId::new("node-b"),
            100,
            90,
            Duration::from_secs(10),
            Duration::from_secs(1),
            Duration::from_secs(2),
            auth(),
        )
        .unwrap();
        runtime.failure_assessment =
            PeerFailureDetector::with_default_window().with_restart_formation(true);
        runtime.peer_address = Some(peer);
        runtime
    }

    fn closed_port() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        address
    }

    /// GAP-01 / GAP-11: production cadence `clock → tick_at(now) →
    /// next_wait_delay → wait → next clock`, with the loop interval as the
    /// wait and 20 ms of processing. Two consecutive windows form a new
    /// restart episode; each window mints exactly one observation.
    #[test]
    fn stage14_3_gap01_gap11_production_cadence_forms_restart_episode() {
        for interval_sec in [1u64, 2, 4, 5, 8] {
            let interval = Duration::from_secs(interval_sec);
            let (mut runtime, _) = inbound_listener(interval);
            let processing = Duration::from_millis(20);
            let mut now = Instant::now();
            let mut first_window: Option<Instant> = None;
            let mut formed = false;
            for _ in 0..200 {
                runtime.tick_at(now).unwrap();
                let snapshot = runtime.failure_assessment();
                if first_window.is_none() && snapshot.formation_count == 1 {
                    assert_eq!(
                        snapshot.suspect_origin,
                        Some(SuspectOrigin::RestartFormation)
                    );
                    assert!(runtime.listen_window.is_none(), "one window, one mint");
                    first_window = snapshot.suspect_since;
                }
                if snapshot.assessment == PeerFailureAssessment::CommunicationLost {
                    let w_start1 = first_window.expect("first window completed first");
                    let w_start2 = snapshot.last_failed_contact_at.unwrap();
                    assert!(w_start2 > w_start1);
                    assert_eq!(snapshot.suspect_since, Some(w_start1));
                    assert_eq!(snapshot.lost_at, Some(now), "lost_at = transition now");
                    assert_eq!(snapshot.loss_generation, 1);
                    assert_eq!(
                        runtime.loss_evidence().unwrap().freshness_reference(),
                        w_start2
                    );
                    formed = true;
                    break;
                }
                let delay = interval; // next_wait_delay in Standby
                now += delay + processing;
            }
            assert!(formed, "interval {interval_sec}s never formed");
        }
    }

    /// Opens a window at `start` and returns the runtime (I = 1 s,
    /// max_gap = 4 s).
    fn window_open_at(start: Instant) -> DaemonPeerRuntime {
        let (mut runtime, _) = inbound_listener(Duration::from_secs(1));
        runtime.tick_at(start).unwrap();
        assert_eq!(runtime.listen_window.as_ref().unwrap().w_start, start);
        runtime
    }

    /// GAP-02 / GAP-03 / GAP-04 / GAP-05 / GAP-06: the inclusive poll-gap
    /// boundary, processing/overshoot, and stalls.
    #[test]
    fn stage14_3_gap02_to_gap06_poll_gap_boundaries() {
        let max_gap = Duration::from_secs(1) + HANDSHAKE_TIMEOUT;
        let valid = [
            ("gap == max_gap", max_gap),
            ("GAP-04 1 s + 2 s processing", Duration::from_secs(3)),
            (
                "GAP-05 I + 3 s overshoot",
                Duration::from_secs(1) + HANDSHAKE_TIMEOUT,
            ),
        ];
        for (name, gap) in valid {
            let start = Instant::now();
            let mut runtime = window_open_at(start);
            runtime.tick_at(start + gap).unwrap();
            let window = runtime.listen_window.as_ref().expect(name);
            assert_eq!(window.w_start, start, "{name}");
            assert_eq!(window.sample_count, 2, "{name}");
        }
        let voiding = [
            ("GAP-03 max_gap + 1 ns", max_gap + Duration::from_nanos(1)),
            ("GAP-04 3.5 s processing", Duration::from_millis(4_500)),
            (
                "GAP-05 I + 3 s + 1 ms",
                Duration::from_secs(1) + HANDSHAKE_TIMEOUT + Duration::from_millis(1),
            ),
            ("GAP-06 30 s stall", Duration::from_secs(30)),
        ];
        for (name, gap) in voiding {
            let start = Instant::now();
            let mut runtime = window_open_at(start);
            runtime.tick_at(start + gap).unwrap();
            assert_eq!(
                runtime.last_window_void,
                Some(ListenWindowVoid::PollGapExceeded),
                "{name}"
            );
            // The violating sample does not count toward the old window but
            // may open the next one.
            let window = runtime.listen_window.as_ref().expect(name);
            assert_eq!(window.w_start, start + gap, "{name}");
            assert_eq!(window.sample_count, 1, "{name}");
            assert_eq!(runtime.failure_assessment().formation_count, 0, "{name}");
        }
        // GAP-06 for I = 8 s and I = 29 s as well.
        for interval_sec in [8u64, 29] {
            let (mut runtime, _) = inbound_listener(Duration::from_secs(interval_sec));
            let start = Instant::now();
            runtime.tick_at(start).unwrap();
            runtime
                .tick_at(
                    start
                        + Duration::from_secs(interval_sec)
                        + HANDSHAKE_TIMEOUT
                        + Duration::from_secs(30),
                )
                .unwrap();
            assert_eq!(
                runtime.last_window_void,
                Some(ListenWindowVoid::PollGapExceeded)
            );
        }
    }

    /// GAP-08 and attack B: an accepted connection voids the window at
    /// accept time, before any authentication result, even when the duration
    /// was already satisfied. Its unauthenticated end is identity
    /// uncertainty: no Healthy, no formation progress, no evidence.
    #[test]
    fn stage14_3_gap08_accepted_unauthenticated_connection_voids_and_invalidates() {
        let (mut runtime, address) = inbound_listener(Duration::from_secs(1));
        let start = Instant::now();
        let mut now = start;
        // Complete one window so a formation sequence is in progress.
        while runtime.failure_assessment().formation_count == 0 {
            runtime.tick_at(now).unwrap();
            now += Duration::from_secs(1);
        }
        assert_eq!(
            runtime.failure_assessment().suspect_origin,
            Some(SuspectOrigin::RestartFormation)
        );
        // Open a second window and run it up to (but not past) completion.
        runtime.tick_at(now).unwrap();
        let w_start = runtime.listen_window.as_ref().unwrap().w_start;
        while now < w_start + VERIFIED_LISTEN_MIN_DURATION - Duration::from_secs(1) {
            now += Duration::from_secs(1);
            runtime.tick_at(now).unwrap();
        }
        // A client connects but never authenticates.
        let client = TcpStream::connect(address).unwrap();
        let mut accepted = false;
        for _ in 0..200 {
            now += Duration::from_millis(10);
            runtime.tick_at(now).unwrap();
            if runtime.current_token.is_some() {
                accepted = true;
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        assert!(accepted);
        assert_eq!(
            runtime.last_window_void,
            Some(ListenWindowVoid::AcceptedConnection)
        );
        assert!(runtime.listen_window.is_none());
        assert_eq!(runtime.failure_assessment().formation_count, 1);
        // The connection ends without authentication (handshake deadline).
        drop(client);
        now += HANDSHAKE_TIMEOUT + Duration::from_secs(1);
        runtime.tick_at(now).unwrap();
        let snapshot = runtime.failure_assessment();
        assert_eq!(snapshot.assessment, PeerFailureAssessment::Unobserved);
        assert_eq!(snapshot.formation_count, 0);
        assert_ne!(snapshot.assessment, PeerFailureAssessment::Healthy);
        assert!(runtime.loss_evidence().is_none());
    }

    /// GAP-09 and attack D: a rebind starts a new listener generation; the
    /// open window is voided and a stale-generation window never completes.
    #[test]
    fn stage14_3_gap09_listener_rebind_voids_window_and_resets_formation() {
        let (mut runtime, _) = inbound_listener(Duration::from_secs(1));
        let start = Instant::now();
        let generation_a = runtime.listener_generation;
        runtime.tick_at(start).unwrap();
        assert_eq!(
            runtime.listen_window.as_ref().unwrap().listener_generation,
            generation_a
        );
        // Ordinary polling never changes the generation.
        for offset in 1..=3 {
            runtime
                .tick_at(start + Duration::from_secs(offset))
                .unwrap();
        }
        assert_eq!(runtime.listener_generation, generation_a);
        runtime.transport.close_listener();
        runtime
            .bind("127.0.0.1:0".parse().unwrap(), Instant::now())
            .unwrap();
        let generation_b = runtime.listener_generation;
        assert_eq!(generation_b, generation_a + 1);
        assert!(runtime.listen_window.is_none());
        assert_eq!(
            runtime.last_window_void,
            Some(ListenWindowVoid::ListenerGenerationChanged)
        );
        // The next sample opens a window on generation B only.
        runtime.tick_at(start + Duration::from_secs(9)).unwrap();
        let window = runtime.listen_window.as_ref().unwrap();
        assert_eq!(window.listener_generation, generation_b);
        assert_eq!(window.w_start, start + Duration::from_secs(9));
        assert_eq!(runtime.failure_assessment().formation_count, 0);
    }

    /// Stage 14 Phase 14.9, §27.5 / Appendix R.8: before a blocking fencing
    /// step the foreground owner voids the open verified-listen window with
    /// reason `FencingStep`. The window never completes across the step and a
    /// new window starts only at the first sample after polling resumes; the
    /// void mints no evidence and moves no formation.
    #[test]
    fn stage14_9_fencing_step_voids_listen_window() {
        let (mut runtime, _) = inbound_listener(Duration::from_secs(1));
        let start = Instant::now();
        for offset in 0..=3 {
            runtime
                .tick_at(start + Duration::from_secs(offset))
                .unwrap();
        }
        assert_eq!(runtime.listen_window.as_ref().unwrap().w_start, start);
        let before = runtime.failure_assessment();
        runtime.void_listen_window_for_fencing_step();
        assert!(runtime.listen_window.is_none());
        assert_eq!(
            runtime.last_window_void,
            Some(ListenWindowVoid::FencingStep)
        );
        assert_eq!(runtime.failure_assessment(), before);
        // A void with no open window records nothing new.
        runtime.last_window_void = None;
        runtime.void_listen_window_for_fencing_step();
        assert_eq!(runtime.last_window_void, None);
        // The next sample after the step opens a fresh window at that sample.
        let resumed = start + Duration::from_secs(4);
        runtime.tick_at(resumed).unwrap();
        assert_eq!(runtime.listen_window.as_ref().unwrap().w_start, resumed);
        assert_eq!(runtime.failure_assessment().formation_count, 0);
    }

    /// GAP-10: an `accept_one` error voids the window, closes the listener,
    /// and schedules a rebind; no observation is minted.
    #[test]
    fn stage14_3_gap10_accept_error_voids_and_closes_listener() {
        let (mut runtime, _) = inbound_listener(Duration::from_secs(1));
        let start = Instant::now();
        for offset in 0..=7 {
            runtime
                .tick_at(start + Duration::from_secs(offset))
                .unwrap();
        }
        runtime.transport.fail_next_accept_for_test();
        runtime.tick_at(start + Duration::from_secs(8)).unwrap();
        assert_eq!(
            runtime.last_window_void,
            Some(ListenWindowVoid::AcceptError)
        );
        assert!(!runtime.transport.listener_available());
        assert!(runtime.rebind.next_attempt_at.is_some());
        assert_eq!(runtime.failure_assessment().formation_count, 0);
        assert_eq!(
            runtime.failure_assessment().assessment,
            PeerFailureAssessment::Unobserved
        );
    }

    /// GAP-12: 60 s with no qualifying samples (listener never bound) forms
    /// and refreshes nothing.
    #[test]
    fn stage14_3_gap12_no_samples_no_formation() {
        let mut runtime = DaemonPeerRuntime::new(
            ClusterId::new("cluster"),
            NodeId::new("node-b"),
            NodeId::new("node-a"),
            90,
            100,
            Duration::from_secs(10),
            Duration::from_secs(1),
            Duration::from_secs(2),
            auth(),
        )
        .unwrap();
        runtime.failure_assessment =
            PeerFailureDetector::with_default_window().with_restart_formation(true);
        let start = Instant::now();
        for offset in 0..=60 {
            runtime
                .tick_at(start + Duration::from_secs(offset))
                .unwrap();
        }
        assert!(runtime.listen_window.is_none());
        assert!(runtime.last_accept_sample.is_none());
        assert_eq!(
            runtime.failure_assessment().assessment,
            PeerFailureAssessment::Unobserved
        );
        assert!(runtime.loss_evidence().is_none());
    }

    /// Appendix R.4: the completing sample never opens the next window, and a
    /// sample from a regressed clock voids the window.
    #[test]
    fn stage14_3_window_completion_and_clock_regression_rules() {
        let (mut runtime, _) = inbound_listener(Duration::from_secs(1));
        let start = Instant::now();
        let mut now = start;
        runtime.tick_at(now).unwrap();
        while runtime.failure_assessment().formation_count == 0 {
            now += Duration::from_secs(1);
            runtime.tick_at(now).unwrap();
        }
        assert!(
            runtime.listen_window.is_none(),
            "completing sample opens nothing"
        );
        now += Duration::from_secs(1);
        runtime.tick_at(now).unwrap();
        assert_eq!(runtime.listen_window.as_ref().unwrap().w_start, now);

        let (mut regressed, _) = inbound_listener(Duration::from_secs(1));
        let later = Instant::now() + Duration::from_secs(10);
        regressed.tick_at(later).unwrap();
        assert!(regressed.tick_at(later - Duration::from_secs(1)).is_err());
        assert!(regressed.listen_window.is_none());
        assert_eq!(
            regressed.last_window_void,
            Some(ListenWindowVoid::ClockRegression)
        );
    }

    /// §10.3.1: a refused TCP connect is a real failed contact at the
    /// attempt start; two of them ≥ 5 s apart form a restart episode.
    #[test]
    fn stage14_3_outbound_connect_refusal_is_a_failed_contact() {
        let mut runtime = outbound_dialer(closed_port());
        let t1 = Instant::now();
        runtime.attempt_reconnect(t1);
        let first = runtime.failure_assessment();
        assert_eq!(first.suspect_origin, Some(SuspectOrigin::RestartFormation));
        assert_eq!(first.suspect_since, Some(t1));
        let t2 = t1 + Duration::from_secs(5);
        runtime.attempt_reconnect(t2);
        let formed = runtime.failure_assessment();
        assert_eq!(formed.assessment, PeerFailureAssessment::CommunicationLost);
        assert_eq!(formed.last_failed_contact_at, Some(t2));

        // Failures observed while shutting down never count (§10.4).
        let mut stopping = outbound_dialer(closed_port());
        stopping.shutting_down = true;
        let at = Instant::now();
        stopping.attempt_reconnect(at);
        // The wrapper itself also refuses while shutting down, and on the
        // Inbound role (which never initiates contact).
        stopping.observe_initiated_contact_failure(at, at).unwrap();
        assert_eq!(stopping.failure_assessment().formation_count, 0);
        let (mut inbound, _) = inbound_listener(Duration::from_secs(1));
        inbound.observe_initiated_contact_failure(at, at).unwrap();
        assert_eq!(inbound.failure_assessment().formation_count, 0);
    }

    /// §10.3.1: an outbound HELLO send failure on an initiated connection.
    #[test]
    fn stage14_3_outbound_hello_send_failure_is_a_failed_contact() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut runtime = outbound_dialer(listener.local_addr().unwrap());
        runtime
            .transport
            .fail_next_send_of_for_test(MessageType::Hello);
        let t1 = Instant::now();
        runtime.attempt_reconnect(t1);
        let snapshot = runtime.failure_assessment();
        assert_eq!(
            snapshot.suspect_origin,
            Some(SuspectOrigin::RestartFormation)
        );
        assert_eq!(snapshot.suspect_since, Some(t1));
    }

    /// §10.3.1: the handshake deadline expiring on an initiated connection
    /// with no authenticated HELLO_ACK; the reference is the attempt start.
    #[test]
    fn stage14_3_outbound_handshake_deadline_is_a_failed_contact() {
        let silent = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut runtime = outbound_dialer(silent.local_addr().unwrap());
        let t1 = Instant::now();
        runtime.attempt_reconnect(t1);
        assert!(runtime.current_token.is_some());
        assert_eq!(runtime.failure_assessment().formation_count, 0);
        runtime.tick_at(t1 + HANDSHAKE_TIMEOUT).unwrap();
        let snapshot = runtime.failure_assessment();
        assert_eq!(
            snapshot.suspect_origin,
            Some(SuspectOrigin::RestartFormation)
        );
        assert_eq!(snapshot.suspect_since, Some(t1));
        assert_eq!(snapshot.formation_count, 1);
    }

    /// §10.5 / R.6: a wrong-PSK peer. The Inbound side sees an accepted
    /// connection that never authenticates (uncertainty); the Outbound side
    /// never receives an authenticated HELLO_ACK (a failed contact).
    #[test]
    fn stage14_3_wrong_psk_is_uncertainty_inbound_and_failed_contact_outbound() {
        let (mut inbound, address) = inbound_listener(Duration::from_secs(1));
        let mut outbound = outbound_dialer(address);
        outbound.authenticator = MessageAuthenticator::new(Psk::from_test_bytes([0x66; 32]));
        // The Inbound observer was in a live episode before the stray peer.
        let base = Instant::now();
        inbound.failure_assessment =
            PeerFailureDetector::with_default_window().with_restart_formation(true);
        inbound
            .failure_assessment
            .observe_initiated_contact_failure(base, base)
            .unwrap();
        inbound
            .failure_assessment
            .observe_initiated_contact_failure(
                base + Duration::from_secs(5),
                base + Duration::from_secs(5),
            )
            .unwrap();
        assert!(inbound.loss_evidence().is_some());

        let t1 = base + Duration::from_secs(6);
        outbound.attempt_reconnect(t1);
        let mut now = t1;
        for _ in 0..400 {
            now += Duration::from_millis(10);
            let _ = inbound.tick_at(now);
            let _ = outbound.tick_at(now);
            if inbound.failure_assessment().suspect_origin
                == Some(SuspectOrigin::UncertaintyFormation)
            {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        let inbound_snapshot = inbound.failure_assessment();
        assert_eq!(
            inbound_snapshot.suspect_origin,
            Some(SuspectOrigin::UncertaintyFormation)
        );
        assert!(inbound.loss_evidence().is_none());
        assert_ne!(inbound_snapshot.assessment, PeerFailureAssessment::Healthy);

        // The Outbound side: the peer closed the initiated connection before
        // any authenticated HELLO_ACK. That is not one of the §10.3.1 failed
        // contacts (connect error, HELLO send failure, handshake deadline), so
        // it neither refreshes nor forms loss, and it is never Healthy.
        let _ = outbound.tick_at(t1 + HANDSHAKE_TIMEOUT + Duration::from_secs(1));
        let outbound_snapshot = outbound.failure_assessment();
        assert_ne!(outbound_snapshot.assessment, PeerFailureAssessment::Healthy);
        assert!(outbound.loss_evidence().is_none());
    }

    /// §10.5 / attack A: an authenticated inbound peer under the current
    /// session is peer contact; an authenticated envelope that names a
    /// different session than the established one is identity uncertainty.
    #[test]
    fn stage14_3_established_session_identity_mismatch_is_uncertainty() {
        let (mut outbound, mut inbound, start) = establish_pair();
        let mut now = start + Duration::from_secs(2);
        for _ in 0..50 {
            now += Duration::from_millis(100);
            let _ = outbound.tick_at(now);
            let _ = inbound.tick_at(now);
            if outbound.failure_assessment().assessment == PeerFailureAssessment::Healthy
                && inbound.failure_assessment().assessment == PeerFailureAssessment::Healthy
            {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(
            outbound.failure_assessment().assessment,
            PeerFailureAssessment::Healthy
        );
        // Connected Inbound runtimes do not sample the listener.
        assert!(inbound.listen_window.is_none());

        // The outbound session now expects a different peer session.
        outbound.peer_session_id = Some(SessionId::new("other-session"));
        for _ in 0..400 {
            now += Duration::from_millis(100);
            let _ = inbound.tick_at(now);
            let _ = outbound.tick_at(now);
            if outbound.failure_assessment().suspect_origin
                == Some(SuspectOrigin::UncertaintyFormation)
            {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        let snapshot = outbound.failure_assessment();
        assert_eq!(
            snapshot.suspect_origin,
            Some(SuspectOrigin::UncertaintyFormation)
        );
        assert!(outbound.loss_evidence().is_none());
    }

    /// Observer restart: a new runtime has a new listener generation space,
    /// no window, no samples, and no formation state.
    #[test]
    fn stage14_3_observer_restart_discards_listen_instrumentation() {
        let (mut runtime, _) = inbound_listener(Duration::from_secs(1));
        let start = Instant::now();
        for offset in 0..=9 {
            runtime
                .tick_at(start + Duration::from_secs(offset))
                .unwrap();
        }
        assert_eq!(runtime.failure_assessment().formation_count, 1);
        let (restarted, _) = inbound_listener(Duration::from_secs(1));
        assert_eq!(restarted.listener_generation, 1);
        assert_eq!(restarted.iteration_generation, 0);
        assert!(restarted.listen_window.is_none());
        assert!(restarted.last_accept_sample.is_none());
        assert_eq!(restarted.failure_assessment().formation_count, 0);
        assert_ne!(
            restarted.process_session.session_id(),
            runtime.process_session.session_id()
        );
    }

    // -----------------------------------------------------------------
    // Stage 14 Phase 14.3 remediation (Design Revision 5): F14.3-01
    // `bound_since` (B1-B7) and F14.3-DQ-01 authenticated-session table
    // (A1-A6).
    // -----------------------------------------------------------------

    /// An unbound canonical Inbound runtime with conservative formation.
    fn unbound_inbound() -> DaemonPeerRuntime {
        let mut runtime = DaemonPeerRuntime::new(
            ClusterId::new("cluster"),
            NodeId::new("node-b"),
            NodeId::new("node-a"),
            90,
            100,
            Duration::from_secs(10),
            Duration::from_secs(1),
            Duration::from_secs(2),
            auth(),
        )
        .unwrap();
        runtime.failure_assessment =
            PeerFailureDetector::with_default_window().with_restart_formation(true);
        runtime
    }

    /// B1: `None` while unbound, including after a failed bind (no
    /// generation is started).
    #[test]
    fn stage14_3r_b1_bound_since_is_none_while_unbound() {
        let mut runtime = unbound_inbound();
        assert_eq!(runtime.bound_since, None);
        let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
        let taken = occupied.local_addr().unwrap();
        assert!(runtime.bind(taken, Instant::now()).is_err());
        assert_eq!(runtime.bound_since, None);
        assert_eq!(runtime.listener_generation, 0);
        assert!(!runtime.transport.listener_available());
    }

    /// B2: a successful bind records the supplied bind instant with the new
    /// generation; no other clock reading is used.
    #[test]
    fn stage14_3r_b2_successful_bind_records_the_bind_instant() {
        let mut runtime = unbound_inbound();
        let bound_at = Instant::now() + Duration::from_secs(3);
        runtime
            .bind("127.0.0.1:0".parse().unwrap(), bound_at)
            .unwrap();
        assert_eq!(runtime.bound_since, Some(bound_at));
        assert_eq!(runtime.listener_generation, 1);
    }

    /// B3: ordinary polling (samples, window open/extend/complete) never
    /// refreshes the bound instant.
    #[test]
    fn stage14_3r_b3_ordinary_polling_leaves_bound_since_unchanged() {
        let mut runtime = unbound_inbound();
        let bound_at = Instant::now();
        runtime
            .bind("127.0.0.1:0".parse().unwrap(), bound_at)
            .unwrap();
        let mut now = bound_at;
        for _ in 0..=9 {
            runtime.tick_at(now).unwrap();
            assert_eq!(runtime.bound_since, Some(bound_at));
            now += Duration::from_secs(1);
        }
        assert_eq!(runtime.failure_assessment().formation_count, 1);
        assert_eq!(runtime.listener_generation, 1);
    }

    /// B4: an accepted connection (the listener stays bound) leaves the bound
    /// instant unchanged; the window is voided as before.
    #[test]
    fn stage14_3r_b4_accepted_connection_leaves_bound_since_unchanged() {
        let mut runtime = unbound_inbound();
        let bound_at = Instant::now();
        let address = runtime
            .bind("127.0.0.1:0".parse().unwrap(), bound_at)
            .unwrap();
        let mut now = bound_at;
        runtime.tick_at(now).unwrap();
        assert!(runtime.listen_window.is_some());
        let _client = TcpStream::connect(address).unwrap();
        let mut accepted = false;
        for _ in 0..200 {
            now += Duration::from_millis(10);
            runtime.tick_at(now).unwrap();
            if runtime.current_token.is_some() {
                accepted = true;
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        assert!(accepted);
        assert_eq!(
            runtime.last_window_void,
            Some(ListenWindowVoid::AcceptedConnection)
        );
        assert!(runtime.transport.listener_available());
        assert_eq!(runtime.bound_since, Some(bound_at));
        assert_eq!(runtime.listener_generation, 1);
    }

    /// B5: an accept error closes the listener and clears the bound instant;
    /// so does a bind that exhausts the generation space.
    #[test]
    fn stage14_3r_b5_accept_error_and_listener_close_clear_bound_since() {
        let (mut runtime, _) = inbound_listener(Duration::from_secs(1));
        assert!(runtime.bound_since.is_some());
        let start = Instant::now();
        runtime.tick_at(start).unwrap();
        runtime.transport.fail_next_accept_for_test();
        runtime.tick_at(start + Duration::from_secs(1)).unwrap();
        assert!(!runtime.transport.listener_available());
        assert_eq!(runtime.bound_since, None);

        let mut exhausted = unbound_inbound();
        exhausted.listener_generation = u64::MAX;
        assert!(
            exhausted
                .bind("127.0.0.1:0".parse().unwrap(), Instant::now())
                .is_err()
        );
        assert!(!exhausted.transport.listener_available());
        assert_eq!(exhausted.bound_since, None);
        assert_eq!(exhausted.listener_generation, u64::MAX);
    }

    /// B6: a rebind inside `tick_at` records that iteration's `now` with the
    /// next generation.
    #[test]
    fn stage14_3r_b6_rebind_records_the_iteration_instant() {
        let mut runtime = unbound_inbound();
        runtime.bind_address = Some("127.0.0.1:0".parse().unwrap());
        let first_bound = Instant::now();
        runtime
            .bind(runtime.bind_address.unwrap(), first_bound)
            .unwrap();
        runtime.tick_at(first_bound).unwrap();
        runtime.transport.fail_next_accept_for_test();
        runtime
            .tick_at(first_bound + Duration::from_secs(1))
            .unwrap();
        assert_eq!(runtime.bound_since, None);
        let rebind_at = runtime.rebind.next_attempt_at.unwrap();
        runtime.tick_at(rebind_at).unwrap();
        assert!(runtime.transport.listener_available());
        assert_eq!(runtime.listener_generation, 2);
        assert_eq!(runtime.bound_since, Some(rebind_at));
        assert_ne!(runtime.bound_since, Some(first_bound));
    }

    /// B7: shutdown closes the listener and clears the bound instant; an
    /// observer restart starts unbound, and the startup bind (before the first
    /// foreground iteration) records the single startup instant.
    #[test]
    fn stage14_3r_b7_shutdown_and_restart_reset_bound_since() {
        let (mut old, _) = inbound_listener(Duration::from_secs(1));
        let start = Instant::now();
        old.tick_at(start).unwrap();
        assert!(old.bound_since.is_some());
        old.shutdown_at(start + Duration::from_secs(1));
        assert!(!old.transport.listener_available());
        assert_eq!(old.bound_since, None);

        let mut restarted = unbound_inbound();
        assert_eq!(restarted.bound_since, None);
        assert_eq!(restarted.listener_generation, 0);
        restarted.bind_address = Some("127.0.0.1:0".parse().unwrap());
        let before = Instant::now();
        restarted.initialize_transport().unwrap();
        let after = Instant::now();
        let bound_at = restarted.bound_since.unwrap();
        assert!(before <= bound_at && bound_at <= after);
        assert_eq!(restarted.listener_generation, 1);
        assert!(restarted.rebind.next_attempt_at.is_none());
    }

    /// One expected Revision 5 §10.8 authenticated-session table row.
    struct SessionRow {
        assessment: PeerFailureAssessment,
        origin: Option<SuspectOrigin>,
        suspect_since: Option<Instant>,
        formation_count: u8,
        formation_floor: Option<Instant>,
        last_failed_contact_at: Option<Instant>,
        lost_at: Option<Instant>,
        loss_generation: u64,
    }

    /// Applies an authenticated session at `at` to `detector` through the
    /// runtime's real establishment entry and checks the complete row, the
    /// peer session, the observer session, and that Healthy is never made.
    fn apply_session_row(
        detector: PeerFailureDetector,
        session: &SessionId,
        at: Instant,
        row: SessionRow,
    ) -> DaemonPeerRuntime {
        let (mut runtime, _) = inbound_listener(Duration::from_secs(1));
        runtime.failure_assessment = detector;
        let observer = runtime.process_session.session_id().clone();
        runtime
            .observe_session_established_at(session.clone(), at)
            .unwrap();
        let snapshot = runtime.failure_assessment();
        assert_eq!(snapshot.assessment, row.assessment);
        assert_ne!(snapshot.assessment, PeerFailureAssessment::Healthy);
        assert_eq!(snapshot.suspect_origin, row.origin);
        assert_eq!(snapshot.suspect_since, row.suspect_since);
        assert_eq!(snapshot.formation_count, row.formation_count);
        assert_eq!(
            runtime.failure_assessment.formation_floor_for_test(),
            row.formation_floor
        );
        assert_eq!(snapshot.last_failed_contact_at, row.last_failed_contact_at);
        assert_eq!(snapshot.lost_at, row.lost_at);
        assert_eq!(snapshot.loss_generation, row.loss_generation);
        assert_eq!(
            runtime.failure_assessment.current_session_for_test(),
            Some(session)
        );
        assert_eq!(runtime.process_session.session_id(), &observer);
        if row.lost_at.is_none() {
            assert!(runtime.loss_evidence().is_none());
        }
        runtime
    }

    fn healthy_detector(session: &SessionId, at: Instant) -> PeerFailureDetector {
        let mut detector = PeerFailureDetector::with_default_window().with_restart_formation(true);
        detector
            .observe_session_established(session.clone(), at)
            .unwrap();
        assert!(
            detector
                .observe_trusted_heartbeat(session, Sequence(1), at)
                .unwrap()
        );
        detector
    }

    /// A1: Unobserved + authenticated session stays Unobserved and ends the
    /// restart-formation path for this process session.
    #[test]
    fn stage14_3r_a1_unobserved_plus_authenticated_session() {
        let base = Instant::now();
        let peer = SessionId::new("session-1");
        let detector = PeerFailureDetector::with_default_window().with_restart_formation(true);
        let mut runtime = apply_session_row(
            detector,
            &peer,
            base,
            SessionRow {
                assessment: PeerFailureAssessment::Unobserved,
                origin: None,
                suspect_since: None,
                formation_count: 0,
                formation_floor: None,
                last_failed_contact_at: None,
                lost_at: None,
                loss_generation: 0,
            },
        );
        for offset in [1, 6, 11] {
            let start = base + Duration::from_secs(offset);
            runtime
                .failure_assessment
                .observe_initiated_contact_failure(start, start)
                .unwrap();
        }
        assert_eq!(
            runtime.failure_assessment().assessment,
            PeerFailureAssessment::Unobserved
        );
        // A trusted heartbeat for the session still follows the normal path.
        let heartbeat_at = base + Duration::from_secs(12);
        assert!(
            runtime
                .failure_assessment
                .observe_trusted_heartbeat(&peer, Sequence(1), heartbeat_at)
                .unwrap()
        );
        assert_eq!(
            runtime.failure_assessment().assessment,
            PeerFailureAssessment::Healthy
        );
    }

    /// A2: Healthy + a different authenticated session is a Healthy-origin
    /// Suspect (Stage 12.2/13.3 replacement path); a duplicate of the current
    /// session is a no-op. Neither manufactures a new Healthy.
    #[test]
    fn stage14_3r_a2_healthy_plus_authenticated_session() {
        let base = Instant::now();
        let s1 = SessionId::new("session-1");
        let s2 = SessionId::new("session-2");
        let at = base + Duration::from_secs(1);
        let mut runtime = apply_session_row(
            healthy_detector(&s1, base),
            &s2,
            at,
            SessionRow {
                assessment: PeerFailureAssessment::Suspect,
                origin: Some(SuspectOrigin::Healthy),
                suspect_since: Some(at),
                formation_count: 0,
                formation_floor: None,
                last_failed_contact_at: None,
                lost_at: None,
                loss_generation: 0,
            },
        );
        assert_eq!(
            runtime.failure_assessment().reason,
            Some(crate::failure_assessment::FailureReason::SessionLost)
        );
        // The pre-existing Healthy-origin timer still applies.
        runtime
            .failure_assessment
            .tick(at + FAILURE_CONFIRMATION_WINDOW)
            .unwrap();
        assert_eq!(runtime.failure_assessment().loss_generation, 1);

        let mut duplicate = healthy_detector(&s1, base);
        duplicate
            .observe_session_established(s1.clone(), at)
            .unwrap();
        assert_eq!(duplicate.assessment(), PeerFailureAssessment::Healthy);
        assert_eq!(duplicate.snapshot().suspect_origin, None);
        assert_eq!(duplicate.formation_floor_for_test(), None);
    }

    /// A3: Suspect(Healthy) + authenticated session stays Suspect(Healthy);
    /// its timer keeps the original `suspect_since`.
    #[test]
    fn stage14_3r_a3_healthy_origin_suspect_plus_authenticated_session() {
        let base = Instant::now();
        let s1 = SessionId::new("session-1");
        let mut detector = healthy_detector(&s1, base);
        let since = base + Duration::from_secs(1);
        detector.observe_transport_failure(since).unwrap();
        let mut runtime = apply_session_row(
            detector,
            &SessionId::new("session-2"),
            base + Duration::from_secs(2),
            SessionRow {
                assessment: PeerFailureAssessment::Suspect,
                origin: Some(SuspectOrigin::Healthy),
                suspect_since: Some(since),
                formation_count: 0,
                formation_floor: None,
                last_failed_contact_at: None,
                lost_at: None,
                loss_generation: 0,
            },
        );
        runtime
            .failure_assessment
            .tick(since + FAILURE_CONFIRMATION_WINDOW)
            .unwrap();
        assert_eq!(
            runtime.failure_assessment().assessment,
            PeerFailureAssessment::CommunicationLost
        );
    }

    /// A4: Suspect(RestartFormation) + authenticated session → Unobserved,
    /// formation cancelled, floor at the session instant, no re-formation.
    #[test]
    fn stage14_3r_a4_restart_formation_plus_authenticated_session() {
        let base = Instant::now();
        let mut detector = PeerFailureDetector::with_default_window().with_restart_formation(true);
        detector
            .observe_initiated_contact_failure(base, base)
            .unwrap();
        assert_eq!(
            detector.snapshot().suspect_origin,
            Some(SuspectOrigin::RestartFormation)
        );
        let at = base + Duration::from_secs(2);
        let mut runtime = apply_session_row(
            detector,
            &SessionId::new("session-1"),
            at,
            SessionRow {
                assessment: PeerFailureAssessment::Unobserved,
                origin: None,
                suspect_since: None,
                formation_count: 0,
                formation_floor: Some(at),
                last_failed_contact_at: None,
                lost_at: None,
                loss_generation: 0,
            },
        );
        for offset in [1, 6, 11] {
            let start = at + Duration::from_secs(offset);
            runtime
                .failure_assessment
                .observe_initiated_contact_failure(start, start)
                .unwrap();
        }
        assert_eq!(
            runtime.failure_assessment().assessment,
            PeerFailureAssessment::Unobserved
        );
        assert!(runtime.loss_evidence().is_none());
        // Healthy follows only from a trusted heartbeat, which clears the floor.
        let heartbeat_at = at + Duration::from_secs(12);
        assert!(
            runtime
                .failure_assessment
                .observe_trusted_heartbeat(&SessionId::new("session-1"), Sequence(1), heartbeat_at)
                .unwrap()
        );
        let snapshot = runtime.failure_assessment();
        assert_eq!(snapshot.assessment, PeerFailureAssessment::Healthy);
        assert_eq!(snapshot.formation_count, 0);
        assert_eq!(runtime.failure_assessment.formation_floor_for_test(), None);
    }

    /// A5: Suspect(UncertaintyFormation) + authenticated session keeps the
    /// uncertainty origin with formation cancelled and the floor at the
    /// session instant; only a complete post-session sequence forms.
    #[test]
    fn stage14_3r_a5_uncertainty_formation_plus_authenticated_session() {
        let base = Instant::now();
        let s1 = SessionId::new("session-1");
        let mut detector = healthy_detector(&s1, base);
        detector
            .observe_identity_uncertainty(base + Duration::from_secs(1))
            .unwrap();
        let o1 = base + Duration::from_secs(2);
        detector.observe_initiated_contact_failure(o1, o1).unwrap();
        assert_eq!(detector.snapshot().formation_count, 1);
        let at = base + Duration::from_secs(3);
        let mut runtime = apply_session_row(
            detector,
            &SessionId::new("session-2"),
            at,
            SessionRow {
                assessment: PeerFailureAssessment::Suspect,
                origin: Some(SuspectOrigin::UncertaintyFormation),
                suspect_since: None,
                formation_count: 0,
                formation_floor: Some(at),
                last_failed_contact_at: None,
                lost_at: None,
                loss_generation: 0,
            },
        );
        let detector = &mut runtime.failure_assessment;
        detector.observe_initiated_contact_failure(at, at).unwrap();
        assert_eq!(detector.snapshot().formation_count, 0);
        let n1 = at + Duration::from_secs(1);
        detector.observe_initiated_contact_failure(n1, n1).unwrap();
        let n2 = n1 + FAILURE_CONFIRMATION_WINDOW;
        detector.observe_initiated_contact_failure(n2, n2).unwrap();
        assert_eq!(
            detector.assessment(),
            PeerFailureAssessment::CommunicationLost
        );
        assert_eq!(detector.snapshot().last_failed_contact_at, Some(n2));
        assert_eq!(detector.snapshot().loss_generation, 1);
    }

    /// A6: CommunicationLost + any authenticated session establishment (a
    /// replacement, a re-establishment of the current session, or the first
    /// session after a restart-formed episode) invalidates the episode and
    /// stays CommunicationLost awaiting the pre-existing re-confirmation.
    #[test]
    fn stage14_3r_a6_communication_lost_plus_authenticated_session() {
        let base = Instant::now();
        let s1 = SessionId::new("session-1");
        let mut legacy = healthy_detector(&s1, base);
        legacy.observe_transport_failure(base).unwrap();
        let lost_at = base + FAILURE_CONFIRMATION_WINDOW;
        legacy.tick(lost_at).unwrap();
        assert_eq!(legacy.loss_evidence().unwrap().lost_at(), lost_at);

        let at = lost_at + Duration::from_secs(1);
        let mut reestablished = apply_session_row(
            legacy.clone(),
            &s1,
            at,
            SessionRow {
                assessment: PeerFailureAssessment::CommunicationLost,
                origin: None,
                suspect_since: Some(at),
                formation_count: 0,
                formation_floor: None,
                last_failed_contact_at: None,
                lost_at: None,
                loss_generation: 1,
            },
        );
        // The current session's sequence window is kept: an already accepted
        // heartbeat sequence cannot recover the assessment.
        assert!(
            !reestablished
                .failure_assessment
                .observe_trusted_heartbeat(&s1, Sequence(1), at)
                .unwrap()
        );
        assert_eq!(
            reestablished.failure_assessment().assessment,
            PeerFailureAssessment::CommunicationLost
        );

        let mut runtime = apply_session_row(
            legacy,
            &SessionId::new("session-2"),
            at,
            SessionRow {
                assessment: PeerFailureAssessment::CommunicationLost,
                origin: None,
                suspect_since: Some(at),
                formation_count: 0,
                formation_floor: None,
                last_failed_contact_at: None,
                lost_at: None,
                loss_generation: 1,
            },
        );
        runtime
            .failure_assessment
            .tick(at + FAILURE_CONFIRMATION_WINDOW)
            .unwrap();
        assert_eq!(runtime.failure_assessment().loss_generation, 2);

        let mut formed = PeerFailureDetector::with_default_window().with_restart_formation(true);
        formed
            .observe_initiated_contact_failure(base, base)
            .unwrap();
        let second = base + FAILURE_CONFIRMATION_WINDOW;
        formed
            .observe_initiated_contact_failure(second, second)
            .unwrap();
        assert!(formed.loss_evidence().is_some());
        let at = second + Duration::from_secs(1);
        apply_session_row(
            formed,
            &SessionId::new("session-1"),
            at,
            SessionRow {
                assessment: PeerFailureAssessment::CommunicationLost,
                origin: None,
                suspect_since: Some(at),
                formation_count: 0,
                formation_floor: None,
                last_failed_contact_at: None,
                lost_at: None,
                loss_generation: 1,
            },
        );
    }

    #[test]
    fn connected_socket_alone_is_not_fresh() {
        let (mut outbound, mut inbound, address) = pair();
        outbound.connect_once(address).unwrap();
        let now = Instant::now();
        inbound.tick_at(now).unwrap();
        assert_eq!(
            outbound.snapshot(now).state,
            PeerObservationState::NeverSeen
        );
        assert_eq!(inbound.snapshot(now).state, PeerObservationState::NeverSeen);
    }

    #[test]
    fn silent_outbound_peer_expires_handshake_and_schedules_reconnect_after_drain() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (mut outbound, _inbound, _unused) = pair();
        outbound.peer_address = Some(address);
        outbound.connect_once(address).unwrap();
        let deadline = outbound.handshake_deadline.unwrap().1;

        outbound
            .tick_at(deadline - Duration::from_nanos(1))
            .unwrap();
        assert!(outbound.current_token.is_some());
        assert!(!outbound.transport.pending_disconnect());

        outbound.tick_at(deadline).unwrap();
        assert!(outbound.current_token.is_none());
        assert!(outbound.transport.pending_disconnect());
        assert_eq!(outbound.session.state(), SessionRuntimeState::HelloPending);
        assert_eq!(
            outbound.snapshot(deadline).state,
            PeerObservationState::Unavailable
        );

        outbound.tick_at(deadline).unwrap();
        assert_eq!(outbound.session.state(), SessionRuntimeState::Disconnected);
        assert!(outbound.transport_recovery_snapshot().reconnect_scheduled);
    }

    #[test]
    fn handshake_timeout_is_transport_only_and_cannot_start_ha_action() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (mut outbound, _inbound, _unused) = pair();
        outbound.connect_once(address).unwrap();
        let deadline = outbound.handshake_deadline.unwrap().1;

        outbound.tick_at(deadline).unwrap();
        outbound.tick_at(deadline).unwrap();

        assert_eq!(outbound.session.state(), SessionRuntimeState::Disconnected);
        assert!(!outbound.is_established());
        assert_eq!(
            outbound.snapshot(deadline).state,
            PeerObservationState::Unavailable
        );
        assert!(outbound.transport_recovery_snapshot().reconnect_scheduled);
        assert!(outbound.peer_session_id.is_none());
        assert!(outbound.peer_sequence.is_none());
    }

    #[test]
    fn transport_failure_observation_uses_caller_tick_time() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (mut outbound, _inbound, _unused) = pair();
        outbound.connect_once(address).unwrap();
        let now = Instant::now() + Duration::from_secs(3_600);
        outbound.handshake_deadline = Some((outbound.current_token.unwrap(), now));

        outbound.tick_at(now).unwrap();

        assert_eq!(
            outbound.last_transport_failure_ms_for_test(),
            Some(outbound.now_ms(now))
        );
        assert_eq!(
            outbound.snapshot(now).state,
            PeerObservationState::Unavailable
        );
    }

    #[test]
    fn synthetic_future_disconnect_does_not_use_real_clock_for_observation() {
        let (mut outbound, mut inbound, start) = establish_pair();
        let token = outbound.current_token.unwrap();
        let now = start + Duration::from_secs(3_600);

        outbound.disconnect_current(token, now);

        assert_eq!(
            outbound.last_transport_failure_ms_for_test(),
            Some(outbound.now_ms(now))
        );
        assert_eq!(
            outbound.snapshot(now).state,
            PeerObservationState::Unavailable
        );
        inbound.shutdown();
    }

    #[test]
    fn silent_inbound_peer_expires_without_rebinding_and_allows_later_peer() {
        let (mut outbound, mut inbound, address) = pair();
        let silent = TcpStream::connect(address).unwrap();
        let accepted_at = Instant::now();
        for _ in 0..128 {
            inbound.tick_at(accepted_at).unwrap();
            if inbound.current_token.is_some() {
                break;
            }
            thread::yield_now();
        }
        let deadline = inbound.handshake_deadline.unwrap().1;
        assert!(inbound.current_token.is_some());

        inbound.tick_at(deadline - Duration::from_nanos(1)).unwrap();
        assert!(inbound.current_token.is_some());
        inbound.tick_at(deadline).unwrap();
        assert!(inbound.current_token.is_none());
        assert!(inbound.transport.pending_disconnect());
        assert!(inbound.transport.listener_available());
        inbound.tick_at(deadline).unwrap();
        assert_eq!(inbound.session.state(), SessionRuntimeState::Disconnected);
        assert!(!inbound.transport_recovery_snapshot().rebind_scheduled);

        outbound.connect_once(address).unwrap();
        let now = deadline;
        for _ in 0..4096 {
            outbound.tick_at(now).unwrap();
            inbound.tick_at(now).unwrap();
            if outbound.is_established() && inbound.is_established() {
                break;
            }
            thread::yield_now();
        }
        assert!(outbound.is_established());
        assert!(inbound.is_established());
        let _ = silent.shutdown(std::net::Shutdown::Both);
    }

    #[test]
    fn established_session_clears_handshake_deadline() {
        let (mut outbound, mut inbound, address) = pair();
        outbound.connect_once(address).unwrap();
        let start = Instant::now();
        for offset in 0..4096u64 {
            let now = start + Duration::from_millis(offset);
            outbound.tick_at(now).unwrap();
            inbound.tick_at(now).unwrap();
            if outbound.is_established() && inbound.is_established() {
                break;
            }
            thread::yield_now();
        }
        assert!(outbound.is_established());
        assert!(inbound.is_established());
        assert_eq!(outbound.handshake_deadline, None);
        assert_eq!(inbound.handshake_deadline, None);
        outbound
            .tick_at(start + HANDSHAKE_TIMEOUT + Duration::from_secs(1))
            .unwrap();
        inbound
            .tick_at(start + HANDSHAKE_TIMEOUT + Duration::from_secs(1))
            .unwrap();
        assert!(outbound.is_established());
        assert!(inbound.is_established());
    }

    #[test]
    fn stale_handshake_deadline_cannot_disconnect_replacement_connection() {
        let (mut outbound, mut inbound, address) = pair();
        outbound.connect_once(address).unwrap();
        let start = Instant::now();
        for offset in 0..4096u64 {
            let now = start + Duration::from_millis(offset);
            outbound.tick_at(now).unwrap();
            inbound.tick_at(now).unwrap();
            if inbound.current_token.is_some() {
                break;
            }
            thread::yield_now();
        }
        let old_token = inbound.current_token.unwrap();
        let old_deadline = start + HANDSHAKE_TIMEOUT;
        inbound.disconnect_current(old_token, start);
        assert_eq!(inbound.current_token, None);
        let mut replacement = DaemonPeerRuntime::new(
            ClusterId::new("cluster"),
            NodeId::new("node-a"),
            NodeId::new("node-b"),
            100,
            90,
            Duration::from_secs(10),
            Duration::from_secs(1),
            Duration::from_secs(2),
            auth(),
        )
        .unwrap();
        replacement.connect_once(address).unwrap();
        let replacement_start = Instant::now();
        for _ in 0..4096 {
            replacement.tick_at(replacement_start).unwrap();
            inbound.tick_at(replacement_start).unwrap();
            if replacement.is_established() && inbound.is_established() {
                break;
            }
            thread::yield_now();
        }
        let replacement_token = inbound.current_token.unwrap();
        assert_ne!(replacement_token, old_token);

        // A stale deadline cannot tear down the replacement connection.
        inbound.handshake_deadline = Some((old_token, old_deadline));
        inbound.expire_handshake_if_due(old_deadline + Duration::from_secs(1));
        assert_eq!(inbound.current_token, Some(replacement_token));
        assert!(!inbound.transport.pending_disconnect());
    }

    #[test]
    fn handshake_connect_does_not_reset_existing_backoff() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (mut outbound, _inbound, _unused) = pair();
        let now = Instant::now();
        outbound.reconnect.schedule(now, "previous failure");
        let failures = outbound.reconnect.consecutive_failures;
        outbound.connect_once(address).unwrap();
        assert_eq!(outbound.reconnect.consecutive_failures, failures);
        assert!(outbound.reconnect.next_attempt_at.is_some());
    }

    #[test]
    fn automatic_reconnect_handshake_deadline_uses_caller_tick_time() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (mut outbound, _inbound, _unused) = pair();
        outbound.peer_address = Some(address);
        let now = Instant::now() + Duration::from_secs(3_600);
        outbound.schedule_reconnect(now - INITIAL_RETRY_DELAY, "test");

        outbound.tick_at(now).unwrap();

        let (token, deadline) = outbound.handshake_deadline.unwrap();
        assert_eq!(outbound.current_token, Some(token));
        assert_eq!(deadline, now + HANDSHAKE_TIMEOUT);
        assert!(!outbound.transport.pending_disconnect());
        assert_eq!(outbound.session.state(), SessionRuntimeState::HelloPending);

        outbound
            .tick_at(now + HANDSHAKE_TIMEOUT - Duration::from_nanos(1))
            .unwrap();
        assert_eq!(outbound.current_token, Some(token));
        assert!(!outbound.transport.pending_disconnect());

        outbound.tick_at(now + HANDSHAKE_TIMEOUT).unwrap();
        assert!(outbound.current_token.is_none());
        assert!(outbound.transport.pending_disconnect());
    }

    #[test]
    fn partial_pre_auth_traffic_does_not_extend_handshake_deadline() {
        let (_outbound, mut inbound, address) = pair();
        let mut silent = TcpStream::connect(address).unwrap();
        let accepted_at = Instant::now();
        for _ in 0..128 {
            inbound.tick_at(accepted_at).unwrap();
            if inbound.current_token.is_some() {
                break;
            }
            thread::yield_now();
        }
        let (token, deadline) = inbound.handshake_deadline.unwrap();
        silent.write_all(&[0x01]).unwrap();
        inbound.tick_at(deadline - Duration::from_nanos(1)).unwrap();
        assert_eq!(inbound.handshake_deadline, Some((token, deadline)));
        assert_eq!(inbound.current_token, Some(token));
        silent.shutdown(std::net::Shutdown::Both).unwrap();
    }

    #[test]
    fn shutdown_during_handshake_suppresses_recovery() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (mut outbound, _inbound, _unused) = pair();
        outbound.connect_once(address).unwrap();
        outbound.shutdown();
        outbound
            .tick_at(Instant::now() + HANDSHAKE_TIMEOUT + Duration::from_secs(1))
            .unwrap();
        let recovery = outbound.transport_recovery_snapshot();
        assert!(!recovery.reconnect_scheduled);
        assert!(!recovery.rebind_scheduled);
        assert_eq!(outbound.handshake_deadline, None);
    }

    #[test]
    fn real_two_runtime_hello_heartbeat_reaches_fresh() {
        let (outbound, inbound, start) = establish_pair();
        assert_eq!(
            outbound.snapshot(start + Duration::from_secs(1)).state,
            PeerObservationState::Fresh
        );
        assert_eq!(
            inbound.snapshot(start + Duration::from_secs(1)).state,
            PeerObservationState::Fresh
        );
    }

    #[test]
    fn gg_inbound_established_heartbeat_emits_ack() {
        let (mut outbound, mut inbound, start) = establish_pair();
        let runtime_now = start + Duration::from_secs(2);
        outbound.received_messages.clear();
        inbound.heartbeat_ack_messages.clear();
        let sequence_before = outbound.peer_sequence;
        inbound.last_accepted_heartbeat_sequence = None;

        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(0);
        let (start_tx, start_rx) = std::sync::mpsc::sync_channel(0);
        let inbound_thread = thread::spawn(move || {
            ready_tx.send(()).unwrap();
            let _target_heartbeat_sequence = start_rx.recv().unwrap();
            for _ in 0..4096 {
                match inbound.transport.wait_for_readable_for_test() {
                    Ok(()) => {
                        inbound.tick_at(runtime_now).unwrap();
                    }
                    Err(TcpRuntimeError::Tcp(crate::tcp::TcpError::Io(error)))
                        if error.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        break;
                    }
                    Err(error) => panic!("inbound readability wait failed: {error:?}"),
                }
                thread::yield_now();
            }
            inbound
        });
        ready_rx.recv().unwrap();
        outbound.send_heartbeat().unwrap();
        let target_heartbeat_sequence = outbound.last_sent_heartbeat_sequence.unwrap();
        start_tx.send(target_heartbeat_sequence).unwrap();
        let inbound = inbound_thread.join().unwrap();
        let target_ack = inbound
            .heartbeat_ack_messages
            .iter()
            .filter(|(sequence, _)| *sequence == target_heartbeat_sequence)
            .map(|(_, ack)| ack)
            .next()
            .cloned();
        assert!(target_ack.is_some());
        let ack = target_ack.unwrap();
        assert_eq!(
            inbound
                .heartbeat_ack_send_attempts
                .iter()
                .filter(
                    |(sequence, session_id)| *sequence == target_heartbeat_sequence
                        && *session_id == ack.common.session_id
                )
                .count(),
            1,
            "target heartbeat ACK send attempt count"
        );

        for _ in 0..4096 {
            outbound.tick_at(runtime_now).unwrap();
            if outbound.received_messages.iter().any(|message| {
                message.message.message_type() == MessageType::HeartbeatAck
                    && message.common.session_id == ack.common.session_id
                    && message.common.sequence == ack.common.sequence
            }) {
                assert_eq!(
                    inbound
                        .heartbeat_ack_messages
                        .iter()
                        .filter(|(sequence, _)| *sequence == target_heartbeat_sequence)
                        .count(),
                    1
                );
                assert_eq!(ack.message.message_type(), MessageType::HeartbeatAck);
                assert_eq!(
                    &ack.common.session_id,
                    outbound.peer_session_id.as_ref().unwrap()
                );
                assert_eq!(
                    inbound.last_accepted_heartbeat_sequence,
                    Some(target_heartbeat_sequence)
                );
                assert!(outbound.peer_sequence.unwrap().0 > sequence_before.unwrap().0);
                break;
            }
            thread::yield_now();
        }
        assert!(outbound.received_messages.iter().any(|message| {
            message.message.message_type() == MessageType::HeartbeatAck
                && message.common.session_id == ack.common.session_id
                && message.common.sequence == ack.common.sequence
        }));
        for _ in 0..8 {
            match outbound.transport.wait_for_readable_for_test() {
                Ok(()) => {
                    outbound.tick_at(runtime_now).unwrap();
                }
                Err(TcpRuntimeError::Tcp(crate::tcp::TcpError::Io(error)))
                    if error.kind() == std::io::ErrorKind::TimedOut =>
                {
                    break;
                }
                Err(error) => panic!("outbound readability wait failed: {error:?}"),
            }
        }
        assert_eq!(
            outbound
                .received_messages
                .iter()
                .filter(|message| {
                    message.message.message_type() == MessageType::HeartbeatAck
                        && message.common.session_id == ack.common.session_id
                        && message.common.sequence == ack.common.sequence
                })
                .count(),
            1,
            "target heartbeat wire ACK count"
        );
    }

    #[test]
    fn gi_ack_terminal_send_failure_preserves_accepted_heartbeat_high_water() {
        let (mut outbound, mut inbound, start) = establish_pair();
        outbound.received_messages.clear();
        let previous_accepted_sequence = inbound.last_accepted_heartbeat_sequence;
        inbound.last_accepted_heartbeat_sequence = None;
        let drain_time = start + Duration::from_secs(10);
        let mut idle_ticks = 0;
        for _ in 0..128 {
            let inbound_processed = inbound.tick_at(drain_time).unwrap();
            let outbound_processed = outbound.tick_at(drain_time).unwrap();
            if inbound_processed == 0 && outbound_processed == 0 {
                idle_ticks += 1;
                if idle_ticks == 3 {
                    break;
                }
            } else {
                idle_ticks = 0;
            }
            thread::yield_now();
        }
        outbound.send_heartbeat().unwrap();
        inbound.fail_next_ack_send = true;

        let now = start + Duration::from_secs(11);
        let mut result = Ok(0);
        for _ in 0..128 {
            result = inbound.tick_at(now);
            if result.is_err() {
                break;
            }
            thread::yield_now();
        }
        assert!(matches!(
            result,
            Err(DaemonPeerRuntimeError::Tcp(TcpRuntimeError::Tcp(_)))
        ));

        let after = inbound.snapshot(now);
        let accepted_sequence = inbound.last_accepted_heartbeat_sequence.unwrap();
        assert!(
            previous_accepted_sequence.is_none_or(|previous| { accepted_sequence.0 > previous.0 })
        );
        assert_eq!(
            inbound.transport.last_failed_send_message_type_for_test(),
            Some(MessageType::HeartbeatAck)
        );
        assert_eq!(inbound.transport.failed_send_attempts_for_test(), 1);
        assert_eq!(after.sequence, Some(accepted_sequence));
        assert_eq!(after.state, PeerObservationState::Unavailable);
        assert_eq!(inbound.current_token, None);
        assert!(inbound.transport.has_pending_disconnect_for_test());

        inbound.tick_at(now).unwrap();
        assert_eq!(inbound.session.state(), SessionRuntimeState::Disconnected);
        assert_eq!(
            inbound.snapshot(now).sequence,
            after.sequence,
            "accepted heartbeat high-water must survive ACK failure"
        );
    }

    /// Real-time budget for the kernel to deliver a loopback event (a written
    /// frame or a peer reset) between two in-process runtimes. A wall-clock
    /// bound does not depend on CPU speed, and every wait exits the instant
    /// its condition holds, so the budget costs nothing on a healthy host.
    const LOOPBACK_WAIT: Duration = Duration::from_secs(10);

    #[test]
    fn connection_loss_is_unavailable_without_ha_action() {
        // Stage 14 Phase 14.11 F1 (root cause, test-only). Two independent
        // test races, neither in the runtime:
        //
        // 1. The old body stepped a synthetic clock 1-2 s per tick straight
        //    from `connect_once`. On a starved host the HELLO was processed
        //    only after synthetic time had passed the outbound's 3 s handshake
        //    deadline; the outbound then closed with the inbound's ACK unread,
        //    which the kernel answers with a reset (the historical
        //    ECONNRESET / EPIPE panic on the inbound tick). Fix: establish on
        //    the millisecond schedule first, as `establish_pair` does.
        // 2. After `inbound.shutdown()` the old body waited for the kernel to
        //    deliver the close to the outbound. On a saturated macOS loopback
        //    that notification can be lost outright (observed: the outbound
        //    socket stays ESTABLISHED in `netstat` although the peer socket is
        //    gone), so no bound makes that wait reliable. Fix: make the loss
        //    observable the way the sibling tests do, with an injected send
        //    failure. The read-error path is covered separately, with a real
        //    reset, by `stage14_11_f1_reset_during_handshake_is_observed_as_transport_failure`.
        let (mut outbound, mut inbound, established) = establish_pair();
        let start = established + Duration::from_secs(5);
        for offset in 0..32u64 {
            let now = start + Duration::from_secs(offset * 2);
            outbound.tick_at(now).unwrap();
            inbound.tick_at(now).unwrap();
            let next = now + Duration::from_secs(1);
            outbound.tick_at(next).unwrap();
            inbound.tick_at(next).unwrap();
            thread::yield_now();
        }
        let last = start + Duration::from_secs(63);
        assert_eq!(outbound.snapshot(last).state, PeerObservationState::Fresh);
        inbound.shutdown();
        outbound
            .transport
            .fail_next_send_of_for_test(MessageType::Heartbeat);
        assert!(outbound.send_heartbeat_at(last).is_err());
        assert_eq!(
            outbound.snapshot(last).state,
            PeerObservationState::Unavailable
        );
        assert!(!outbound.outbound_established);
    }

    /// Stage 14 Phase 14.11 F1 regression (production contract). When the
    /// outbound side times out its handshake and closes with the inbound's
    /// ACK still unread, the kernel resets the connection. Whether the inbound
    /// then sees the reset as an `Err` or as an EOF, the runtime tears the
    /// connection down, reports the peer `Unavailable`, and feeds the failure
    /// detector (`observe_transport_failure` via `drain_disconnect`). No
    /// authority, promotion, or fencing state is involved.
    #[test]
    fn stage14_11_f1_reset_during_handshake_is_observed_as_transport_failure() {
        let (mut outbound, mut inbound, address) = pair();
        outbound.connect_once(address).unwrap();
        let t0 = Instant::now();
        // The inbound accepts and answers the HELLO; the ACK stays unread by
        // the outbound. All inbound ticks stay well inside its own 3 s
        // handshake deadline, so only the outbound side times out.
        let mut step = 0u64;
        let deadline = Instant::now() + LOOPBACK_WAIT;
        loop {
            let processed = inbound.tick_at(t0 + Duration::from_millis(step)).unwrap();
            if processed > 0 {
                break;
            }
            step += 1;
            assert!(Instant::now() < deadline, "HELLO was never received");
            thread::yield_now();
        }
        let at = t0 + Duration::from_millis(step + 1);
        // The outbound handshake deadline (3 s after `connect_once`) passes
        // before the outbound reads the ACK: it closes with unread data.
        outbound
            .tick_at(t0 + HANDSHAKE_TIMEOUT + Duration::from_secs(1))
            .unwrap();
        assert!(!outbound.transport_recovery_snapshot().connected);
        let deadline = Instant::now() + LOOPBACK_WAIT;
        // The tick that observes the loss (a read error, or an EOF) must
        // complete the teardown itself: on that very tick the runtime is
        // disconnected, the peer is Unavailable, and the detector path was
        // informed. (A later tick's disconnect drain would otherwise mask a
        // read-error path that skipped it.)
        let mut observed = false;
        while Instant::now() < deadline {
            let result = inbound.tick_at(at);
            if result.is_err() || inbound.current_token.is_none() {
                assert!(!inbound.transport_recovery_snapshot().connected);
                assert_eq!(
                    inbound.snapshot(at).state,
                    PeerObservationState::Unavailable
                );
                assert!(
                    inbound.last_transport_failure_ms_for_test().is_some(),
                    "the detector path was informed on the tick that saw the loss"
                );
                observed = true;
                break;
            }
            thread::yield_now();
        }
        assert!(observed, "the reset was never observed");
    }

    /// F1 (detector half): a read error ends the connection on the tick that
    /// sees it. That tick returns the error without reaching the end-of-tick
    /// assessment, so the teardown itself must have informed the observer and
    /// the detector. A 16 KiB-plus length prefix is a framing error (not an
    /// EOF/reset), so this isolates the error path.
    #[test]
    fn stage14_11_f1_read_error_informs_observer_and_detector_on_that_tick() {
        let (_outbound, mut inbound, address) = pair();
        let t0 = Instant::now();
        let mut client = TcpStream::connect(address).unwrap();
        let deadline = Instant::now() + LOOPBACK_WAIT;
        while inbound.current_token.is_none() {
            inbound.tick_at(t0).unwrap();
            assert!(Instant::now() < deadline, "never accepted");
            thread::yield_now();
        }
        // The connection is treated as an authenticated session from here on
        // (so its loss is a plain transport failure, not identity
        // uncertainty), and the accept's own invalidation is replaced by a
        // Healthy detector with an authenticated peer session: the only thing
        // that can turn it Suspect on this connection's loss is the
        // transport-failure notification itself.
        inbound.inbound_authenticated = true;
        inbound.pending_identity_uncertainty = false;
        let peer_session = crate::protocol::SessionId::new("peer-session");
        inbound
            .failure_assessment
            .observe_session_established(peer_session.clone(), t0)
            .unwrap();
        inbound
            .failure_assessment
            .observe_trusted_heartbeat(&peer_session, crate::protocol::Sequence(1), t0)
            .unwrap();
        assert_eq!(
            inbound.failure_assessment().assessment,
            crate::failure_assessment::PeerFailureAssessment::Healthy
        );
        // An oversized length prefix: a framing error on the inbound read.
        client.write_all(&[0xff, 0xff, 0xff, 0xff]).unwrap();
        let at = t0 + Duration::from_millis(1);
        let deadline = Instant::now() + LOOPBACK_WAIT;
        loop {
            match inbound.tick_at(at) {
                Err(_) => break,
                Ok(_) => {
                    assert!(
                        Instant::now() < deadline,
                        "the framing error never surfaced"
                    );
                    thread::yield_now();
                }
            }
        }
        // On that very tick: disconnected, observer Unavailable, detector told.
        assert!(!inbound.transport_recovery_snapshot().connected);
        assert!(inbound.current_token.is_none());
        assert_eq!(
            inbound.snapshot(at).state,
            PeerObservationState::Unavailable,
            "observer informed"
        );
        assert!(inbound.last_transport_failure_ms_for_test().is_some());
        let detector = inbound.failure_assessment();
        assert_eq!(
            detector.assessment,
            crate::failure_assessment::PeerFailureAssessment::Suspect,
            "the detector was informed on the error tick"
        );
        assert!(
            format!("{:?}", inbound.failure_assessment)
                .contains("reason: Some(TransportUnavailable)"),
            "the notification was a transport failure"
        );
    }

    /// Stage 14 Phase 14.11 G04-TEST (behavioural pin for the first
    /// `observe_transport_failure(now)?` of the EOF / `TransportUnavailable`
    /// branch of `tick_at`).
    ///
    /// The independent re-audit disproved the earlier "equivalent mutant"
    /// verdict for deleting that call: with a sane clock the call is masked
    /// (`drain_disconnect` observes the same failure), but with a regressed
    /// clock the two programs diverge. This test is that distinguishing probe.
    ///
    /// Setup: an accepted, unauthenticated inbound connection with
    /// `pending_identity_uncertainty`, a detector already advanced to
    /// `base + 10 s`, then a real TCP half-close processed at `base + 1 s`
    /// (a regressed clock). The EOF branch must propagate the detector's
    /// `TimeWentBackwards` through its own `observe_transport_failure(now)?`
    /// *before* `drain_disconnect`, so the pending disconnect is not consumed
    /// on that tick: it stays pending, the session stays `HelloPending`, and
    /// the next (sane-clock) tick drains it and reports the peer
    /// `Unavailable`. Without the call, the same tick would drain (and
    /// swallow the error) at once, leaving `Disconnected` and an observer that
    /// never saw the failure (`NeverSeen`).
    #[test]
    fn stage14_11_g04_eof_with_regressed_clock_propagates_before_draining_disconnect() {
        let (mut inbound, address) = inbound_listener(Duration::from_secs(1));
        crate::operator_log::capture_start();
        let base = Instant::now();
        let client = TcpStream::connect(address).unwrap();
        let deadline = Instant::now() + LOOPBACK_WAIT;
        while inbound.current_token.is_none() {
            inbound.tick_at(base).unwrap();
            assert!(Instant::now() < deadline, "never accepted");
            thread::yield_now();
        }
        assert_eq!(inbound.session.state(), SessionRuntimeState::HelloPending);
        assert!(!inbound.inbound_authenticated);
        inbound.pending_identity_uncertainty = true;
        // The detector has already seen `base + 10 s`; `base + 1 s` regresses.
        inbound
            .failure_assessment
            .tick(base + Duration::from_secs(10))
            .unwrap();
        assert_eq!(
            inbound.snapshot(base + Duration::from_secs(1)).state,
            PeerObservationState::NeverSeen,
            "precondition: the observer has not seen any failure"
        );

        // A real TCP half-close, observed as readable (EOF) before the tick,
        // so the one tick below deterministically takes the EOF branch. The
        // detector rejects `base + 1 s` on every tick, so ticks cannot be
        // used to wait for the EOF.
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let deadline = Instant::now() + LOOPBACK_WAIT;
        loop {
            let readiness = inbound.transport.wait_for_readable_for_test();
            if !matches!(&readiness, Err(error) if format!("{error:?}").contains("TimedOut")) {
                break;
            }
            assert!(Instant::now() < deadline, "the EOF never became readable");
        }

        let regressed = base + Duration::from_secs(1);
        let first = inbound.tick_at(regressed);
        assert!(
            matches!(
                first,
                Err(DaemonPeerRuntimeError::FailureAssessment(
                    crate::failure_assessment::FailureAssessmentError::TimeWentBackwards
                ))
            ),
            "the EOF tick propagates the detector's clock regression: {first:?}"
        );
        assert!(
            !inbound.pending_identity_uncertainty,
            "the identity uncertainty was consumed by the observation"
        );
        // The error propagated before `drain_disconnect` could consume the
        // pending disconnect: nothing was drained on that tick.
        assert!(
            inbound.transport.pending_disconnect(),
            "the disconnect must still be pending after the propagated error"
        );
        assert_eq!(
            inbound.session.state(),
            SessionRuntimeState::HelloPending,
            "the session has not been told about the disconnect yet"
        );

        // The next tick (sane clock) drains the pending disconnect and the
        // observer learns of the failure.
        let next = base + Duration::from_secs(11);
        assert_eq!(inbound.tick_at(next).unwrap(), 0);
        assert!(!inbound.transport.pending_disconnect());
        assert_eq!(inbound.session.state(), SessionRuntimeState::Disconnected);
        assert_eq!(
            inbound.snapshot(next).state,
            PeerObservationState::Unavailable,
            "the drained disconnect on the next tick informs the observer"
        );
        let _ = crate::operator_log::capture_take();
        drop(client);
    }

    #[test]
    fn peer_tick_budget_is_bounded() {
        let (mut outbound, mut inbound, start) = establish_pair();
        for _ in 0..(MAX_FRAMES_PER_TICK * 2) {
            outbound.send_heartbeat().unwrap();
        }
        let mut processed = 0;
        for _ in 0..10_000 {
            processed = inbound.tick_at(start + Duration::from_secs(2)).unwrap();
            if processed != 0 {
                break;
            }
            thread::yield_now();
        }
        assert_eq!(processed, MAX_FRAMES_PER_TICK);
    }

    #[test]
    fn peer_transport_bind_failure_is_classified_as_unavailable() {
        let mut occupied = DaemonPeerRuntime::new(
            ClusterId::new("cluster"),
            NodeId::new("node-b"),
            NodeId::new("node-a"),
            90,
            100,
            Duration::from_secs(10),
            Duration::from_secs(1),
            Duration::from_secs(1),
            auth(),
        )
        .unwrap();
        let address = occupied
            .bind("127.0.0.1:0".parse().unwrap(), Instant::now())
            .unwrap();
        let mut runtime = DaemonPeerRuntime::new(
            ClusterId::new("cluster"),
            NodeId::new("node-b"),
            NodeId::new("node-a"),
            90,
            100,
            Duration::from_secs(10),
            Duration::from_secs(1),
            Duration::from_secs(1),
            auth(),
        )
        .unwrap();
        runtime.bind_address = Some(address);

        runtime.initialize_transport().unwrap();
        let recovery = runtime.transport_recovery_snapshot();
        assert!(!recovery.listener_available);
        assert!(recovery.rebind_scheduled);
        assert_eq!(recovery.consecutive_rebind_failures, 1);
        let retry_base = Instant::now();
        occupied.transport.close_listener();
        drop(occupied);
        runtime.bind_address = Some("127.0.0.1:0".parse().unwrap());
        for attempt in 1..=8 {
            runtime
                .tick_at(retry_base + Duration::from_millis(250 * attempt))
                .unwrap();
            if runtime.transport_recovery_snapshot().listener_available {
                break;
            }
        }
        let recovery = runtime.transport_recovery_snapshot();
        assert!(recovery.listener_available, "{recovery:?}");
        assert!(!recovery.rebind_scheduled);
        assert_eq!(recovery.consecutive_rebind_failures, 0);
    }

    #[test]
    fn initial_connect_failure_schedules_bounded_reconnect() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);

        let (mut outbound, _inbound, _unused) = pair();
        outbound.peer_address = Some(address);
        outbound.start_initial();
        let recovery = outbound.transport_recovery_snapshot();
        assert!(!recovery.connected);
        assert!(recovery.reconnect_scheduled);
        assert_eq!(recovery.consecutive_reconnect_failures, 1);
        assert!(recovery.last_error.is_some());
    }

    #[test]
    fn automatic_reconnect_establishes_new_session_before_fresh_observation() {
        let (mut outbound, mut inbound, address) = pair();
        outbound.peer_address = Some(address);
        outbound.connect_once(address).unwrap();
        let start = Instant::now();
        for offset in 0..4096u64 {
            let now = start + Duration::from_millis(offset * 2);
            outbound.tick_at(now).unwrap();
            inbound.tick_at(now).unwrap();
            let next = now + Duration::from_millis(1);
            outbound.tick_at(next).unwrap();
            inbound.tick_at(next).unwrap();
            if outbound.is_established() && inbound.is_established() {
                break;
            }
            thread::yield_now();
        }
        let old_session = outbound.peer_session_id.clone().unwrap();
        inbound.shutdown();

        outbound
            .transport
            .fail_next_send_of_for_test(MessageType::Heartbeat);
        assert!(outbound.send_heartbeat().is_err());
        let disconnect_time = start + Duration::from_secs(10);
        outbound.tick_at(disconnect_time).unwrap();
        assert!(outbound.transport_recovery_snapshot().reconnect_scheduled);

        let mut replacement = DaemonPeerRuntime::new(
            ClusterId::new("cluster"),
            NodeId::new("node-b"),
            NodeId::new("node-a"),
            90,
            100,
            Duration::from_secs(10),
            Duration::from_secs(1),
            Duration::from_secs(2),
            auth(),
        )
        .unwrap();
        replacement.bind(address, Instant::now()).unwrap();

        let mut reconnected_at = None;
        for offset in 1..256u64 {
            let now = disconnect_time + Duration::from_millis(250 + offset);
            outbound.tick_at(now).unwrap();
            if outbound.is_established() && reconnected_at.is_none() {
                let observation = outbound.snapshot(now);
                assert_eq!(observation.session_id, outbound.peer_session_id);
                if observation.state == PeerObservationState::Fresh {
                    assert!(observation.sequence.is_some());
                }
                reconnected_at = Some(now);
            }
            replacement.tick_at(now).unwrap();
            if reconnected_at.is_some() && replacement.is_established() {
                break;
            }
            thread::yield_now();
        }
        let reconnected_at = reconnected_at.unwrap_or_else(|| {
            panic!(
                "automatic reconnect: outbound={:?} replacement={:?}",
                outbound.transport_recovery_snapshot(),
                replacement.transport_recovery_snapshot()
            )
        });
        assert_ne!(outbound.peer_session_id.as_ref().unwrap(), &old_session);
        let observation = outbound.snapshot(reconnected_at);
        assert_eq!(observation.session_id, outbound.peer_session_id);
        if observation.state == PeerObservationState::Fresh {
            assert!(observation.sequence.is_some());
        }

        let mut fresh_at = None;
        for offset in 0..3_000u64 {
            let now = disconnect_time + Duration::from_millis(3_000 + offset);
            outbound.tick_at(now).unwrap();
            replacement.tick_at(now).unwrap();
            if outbound.snapshot(now).state == PeerObservationState::Fresh
                && replacement.snapshot(now).state == PeerObservationState::Fresh
            {
                fresh_at = Some(now);
                break;
            }
            thread::yield_now();
        }
        assert!(fresh_at.is_some());
        replacement.shutdown();
    }

    #[test]
    fn fq_active_local_cached_snapshot_is_reported_as_active() {
        let (mut outbound, _inbound, _address) = pair();
        outbound.set_local_status(PeerStatusSnapshot {
            node_state: NodeState::Active,
            operation_phase: None,
            role: Role::Active,
            service: DaemonService::Running,
            health: DaemonHealth::Healthy,
            vip: DaemonVip::Present,
        });
        let payload = outbound.local_status_payload();
        assert_eq!(payload.node_state, NodeState::Active);
        assert_eq!(payload.role, Role::Active);
    }

    #[test]
    fn fr_cached_resource_observation_is_preserved() {
        let (mut outbound, _inbound, _address) = pair();
        outbound.set_local_status(PeerStatusSnapshot {
            node_state: NodeState::Active,
            operation_phase: None,
            role: Role::Active,
            service: DaemonService::Running,
            health: DaemonHealth::Healthy,
            vip: DaemonVip::Present,
        });
        let payload = outbound.local_status_payload();
        assert_eq!(payload.service_state, "running");
        assert_eq!(payload.vip_state, "present");
    }

    #[test]
    fn fs_heartbeat_payload_uses_only_supplied_cached_status() {
        let (mut outbound, _inbound, _address) = pair();
        outbound.set_local_status(PeerStatusSnapshot {
            node_state: NodeState::RecoveryPending,
            operation_phase: Some(OperationPhase::Demotion(DemotionPhase::StopService)),
            role: Role::Standby,
            service: DaemonService::Unknown,
            health: DaemonHealth::Unknown,
            vip: DaemonVip::Unknown,
        });
        let payload = outbound.local_status_payload();
        assert_eq!(payload.node_state, NodeState::RecoveryPending);
        assert_eq!(
            payload.operation_phase,
            Some(OperationPhase::Demotion(DemotionPhase::StopService))
        );
        assert_eq!(payload.service_state, "unknown");
        assert_eq!(payload.health_state, "unknown");
        assert_eq!(payload.vip_state, "unknown");
    }

    #[test]
    fn ft_unknown_local_resource_truth_remains_unknown() {
        let (outbound, _inbound, _address) = pair();
        let payload = outbound.local_status_payload();
        assert_eq!(payload.service_state, "unknown");
        assert_eq!(payload.health_state, "unknown");
        assert_eq!(payload.vip_state, "unknown");
        assert_eq!(payload.node_state, NodeState::Init);
    }

    #[test]
    fn terminal_write_failure_is_drained_once_on_next_tick() {
        let (mut outbound, mut inbound, address) = pair();
        outbound.connect_once(address).unwrap();
        let start = Instant::now();
        for offset in 0..4096u64 {
            let now = start + Duration::from_millis(offset * 2);
            outbound.tick_at(now).unwrap();
            inbound.tick_at(now).unwrap();
            let next = now + Duration::from_millis(1);
            outbound.tick_at(next).unwrap();
            inbound.tick_at(next).unwrap();
            if outbound.is_established() && inbound.is_established() {
                break;
            }
            thread::yield_now();
        }
        assert!(outbound.is_established());
        inbound.shutdown();

        outbound
            .transport
            .fail_next_send_of_for_test(MessageType::Heartbeat);
        let failure = outbound.send_heartbeat();
        assert!(failure.is_err());
        assert_eq!(outbound.current_token, None);
        let reconnect = outbound.connect_once(address);
        assert!(
            matches!(
                &reconnect,
                Err(DaemonPeerRuntimeError::Tcp(
                    TcpRuntimeError::PendingDisconnect
                ))
            ),
            "unexpected reconnect result: {reconnect:?}"
        );

        outbound.tick_at(start + Duration::from_secs(2)).unwrap();
        assert_eq!(outbound.session.state(), SessionRuntimeState::Disconnected);
        assert_eq!(
            outbound
                .transport
                .poll_pending_disconnect(&mut outbound.session),
            TcpRuntimeStep::NoEvent
        );

        outbound.tick_at(start + Duration::from_secs(2)).unwrap();
        assert_eq!(outbound.session.state(), SessionRuntimeState::Disconnected);
        assert_eq!(
            outbound
                .transport
                .poll_pending_disconnect(&mut outbound.session),
            TcpRuntimeStep::NoEvent
        );
    }

    #[test]
    fn explicit_reconnect_is_possible_after_disconnect_drain() {
        let (mut outbound, mut inbound, address) = pair();
        outbound.connect_once(address).unwrap();
        let start = Instant::now();
        for offset in 0..4096u64 {
            let now = start + Duration::from_millis(offset * 2);
            outbound.tick_at(now).unwrap();
            inbound.tick_at(now).unwrap();
            let next = now + Duration::from_millis(1);
            outbound.tick_at(next).unwrap();
            inbound.tick_at(next).unwrap();
            if outbound.is_established() && inbound.is_established() {
                break;
            }
            thread::yield_now();
        }
        assert!(outbound.is_established());
        inbound.shutdown();
        outbound
            .transport
            .fail_next_send_of_for_test(MessageType::Heartbeat);
        assert!(outbound.send_heartbeat().is_err());
        let reconnect = outbound.connect_once(address);
        assert!(
            matches!(
                &reconnect,
                Err(DaemonPeerRuntimeError::Tcp(
                    TcpRuntimeError::PendingDisconnect
                ))
            ),
            "unexpected reconnect result: {reconnect:?}"
        );

        outbound.tick_at(start + Duration::from_secs(2)).unwrap();
        assert!(!matches!(
            outbound.connect_once(address),
            Err(DaemonPeerRuntimeError::Tcp(
                TcpRuntimeError::PendingDisconnect
            ))
        ));
    }

    #[test]
    fn retry_schedule_is_caller_driven_and_bounded() {
        let now = Instant::now();
        let mut retry = RetrySchedule::new();
        assert!(!retry.due(now));

        retry.schedule(now, "first");
        assert_eq!(
            retry.next_attempt_at.unwrap().duration_since(now),
            Duration::from_millis(250)
        );
        assert!(!retry.due(now + Duration::from_millis(249)));
        assert!(retry.due(now + Duration::from_millis(250)));

        for _ in 0..64 {
            retry.schedule(now, "repeated");
        }
        assert_eq!(retry.consecutive_failures, MAX_RETRY_FAILURES);
        assert_eq!(
            retry.next_attempt_at.unwrap().duration_since(now),
            MAX_RETRY_DELAY
        );
        retry.reset();
        assert_eq!(retry, RetrySchedule::new());
    }

    #[test]
    fn reconnect_attempt_before_deadline_does_nothing() {
        let (mut outbound, _inbound, address) = pair();
        outbound.peer_address = Some(address);
        let now = Instant::now();
        outbound.schedule_reconnect(now, "test");
        let before = outbound.transport_recovery_snapshot();
        outbound.tick_at(now + Duration::from_millis(249)).unwrap();
        assert_eq!(outbound.transport_recovery_snapshot(), before);
    }

    #[test]
    fn reconnect_attempt_at_deadline_is_limited_to_one_attempt_per_tick() {
        let (mut outbound, _inbound, address) = pair();
        outbound.peer_address = Some(address);
        let now = Instant::now();
        outbound.schedule_reconnect(now, "test");
        outbound.tick_at(now + Duration::from_millis(250)).unwrap();
        assert!(outbound.current_token.is_some());
        assert!(
            !outbound
                .reconnect
                .next_attempt_at
                .is_some_and(|deadline| { deadline <= now + Duration::from_millis(250) })
        );
    }

    #[test]
    fn shutdown_suppresses_reconnect_and_rebind() {
        let (mut outbound, mut inbound, address) = pair();
        outbound.peer_address = Some(address);
        outbound.schedule_reconnect(Instant::now(), "test");
        inbound.schedule_rebind(Instant::now(), "test");
        outbound.shutdown();
        inbound.shutdown();

        let now = Instant::now() + Duration::from_secs(10);
        outbound.tick_at(now).unwrap();
        inbound.tick_at(now).unwrap();
        assert!(!outbound.transport_recovery_snapshot().reconnect_scheduled);
        assert!(!inbound.transport_recovery_snapshot().rebind_scheduled);
    }

    // ------------------------------------------------------------------
    // Stage 14 Phase 14.11: §28.1 ListenerInterference diagnostics and the
    // §34.18 tests.
    // ------------------------------------------------------------------

    /// One unauthenticated arrival: a raw connection that never speaks. The
    /// inbound accepts it and its own 3 s handshake deadline ends it, a local
    /// close that does not depend on the kernel delivering a peer close (the
    /// F1 evidence). Returns the instant of the expiry tick.
    fn silent_arrival(
        inbound: &mut DaemonPeerRuntime,
        address: SocketAddr,
        at: Instant,
    ) -> Instant {
        let client = TcpStream::connect(address).unwrap();
        let deadline = Instant::now() + LOOPBACK_WAIT;
        while inbound.current_token.is_none() {
            inbound.tick_at(at).unwrap();
            assert!(
                Instant::now() < deadline,
                "the connection was never accepted"
            );
            thread::yield_now();
        }
        let expires = inbound.handshake_deadline.unwrap().1;
        inbound.tick_at(expires).unwrap();
        assert!(
            inbound.current_token.is_none(),
            "handshake deadline closed it"
        );
        inbound.tick_at(expires).unwrap();
        drop(client);
        expires
    }

    /// `(arrivals, voided windows)` of every `ListenerInterference` WARN.
    fn interference_warns(lines: &[String]) -> Vec<(u64, u64)> {
        lines
            .iter()
            .filter(|line| line.contains("WARN ListenerInterference:"))
            .map(|line| {
                let numbers: Vec<u64> = line
                    .split(|c: char| !c.is_ascii_digit())
                    .filter(|part| !part.is_empty())
                    .take(2)
                    .map(|part| part.parse().unwrap())
                    .collect();
                (numbers[0], numbers[1])
            })
            .collect()
    }

    /// §28.1 accounting (pure): one WARN per `LOCAL_LOSS_EVIDENCE_MAX_AGE`, the
    /// first occurrence immediately, exact counts, held counts flushed once the
    /// interval passes, guidance on the first WARN only, and a bounded
    /// "recent" ring.
    #[test]
    fn stage14_11_interference_accounting_is_rate_bounded_and_exact() {
        let t0 = Instant::now();
        let at = |seconds: u64| t0 + Duration::from_secs(seconds);
        let mut diagnostics = ListenerInterferenceDiagnostics::default();
        assert_eq!(
            diagnostics.record(at(0), false),
            Some(InterferenceWarn {
                arrivals: 1,
                voided_windows: 0,
                first: true
            })
        );
        // Five more arrivals inside the 30 s bound: counted, not reported.
        for seconds in [5, 10, 15, 20, 25] {
            assert_eq!(diagnostics.record(at(seconds), true), None);
        }
        assert_eq!(diagnostics.flush(at(29)), None, "still inside the bound");
        // The 30 s boundary is inclusive: the next arrival reports all six.
        assert_eq!(
            diagnostics.record(at(30), true),
            Some(InterferenceWarn {
                arrivals: 6,
                voided_windows: 6,
                first: false
            })
        );
        // Held counts are never silently lost.
        assert_eq!(diagnostics.record(at(35), false), None);
        assert_eq!(diagnostics.flush(at(59)), None);
        assert_eq!(
            diagnostics.flush(at(60)),
            Some(InterferenceWarn {
                arrivals: 1,
                voided_windows: 0,
                first: false
            })
        );
        assert_eq!(
            diagnostics.flush(at(120)),
            None,
            "nothing held, nothing to report"
        );
        // A quiet window: the next arrival logs immediately again.
        assert_eq!(
            diagnostics.record(at(200), false),
            Some(InterferenceWarn {
                arrivals: 1,
                voided_windows: 0,
                first: false
            })
        );
    }

    #[test]
    fn stage14_11_interference_recent_window_is_30s_inclusive() {
        let t0 = Instant::now();
        let mut diagnostics = ListenerInterferenceDiagnostics::default();
        for seconds in [0u64, 10, 20, 30] {
            diagnostics.record(t0 + Duration::from_secs(seconds), false);
        }
        assert_eq!(diagnostics.recent_arrivals(t0 + Duration::from_secs(30)), 4);
        assert_eq!(diagnostics.recent_arrivals(t0 + Duration::from_secs(31)), 3);
        assert_eq!(diagnostics.recent_arrivals(t0 + Duration::from_secs(61)), 0);
        // A clock that moved backwards counts nothing rather than guessing.
        assert_eq!(diagnostics.recent_arrivals(t0), 1);
    }

    /// L1: the displayed N is the exact number of arrivals in the window for
    /// every burst size, including the former 1024-entry saturation point,
    /// while the representation stays one bucket per observation instant.
    #[test]
    fn stage14_11_interference_recent_count_is_exact_for_any_burst() {
        for burst in [0u64, 1, 2, 1023, 1024, 1025, 2048, 5000, 1_000_000] {
            let t0 = Instant::now();
            let mut diagnostics = ListenerInterferenceDiagnostics::default();
            for _ in 0..burst {
                diagnostics.record(t0, true);
            }
            assert_eq!(diagnostics.recent_arrivals(t0), burst, "burst {burst}");
            assert_eq!(
                diagnostics.recent_arrivals(t0 + Duration::from_secs(30)),
                burst,
                "burst {burst}, at the inclusive 30 s boundary"
            );
            assert_eq!(
                diagnostics.recent_arrivals(t0 + Duration::from_secs(31)),
                0,
                "burst {burst}, one second past the window"
            );
            assert!(diagnostics.recent.len() <= 1, "burst {burst}: bounded");
            // The WARN counter is independent of the recent window and exact.
            assert_eq!(
                diagnostics.arrivals_since_warn,
                burst.saturating_sub(1),
                "burst {burst}: the first arrival logged immediately, the rest are held"
            );
        }
    }

    /// L1: entries expire across the 30 s boundary bucket by bucket, each
    /// carrying its own exact count.
    #[test]
    fn stage14_11_interference_buckets_expire_across_the_boundary() {
        let t0 = Instant::now();
        let at = |seconds: u64| t0 + Duration::from_secs(seconds);
        let mut diagnostics = ListenerInterferenceDiagnostics::default();
        for _ in 0..1025 {
            diagnostics.record(at(0), false);
        }
        for _ in 0..7 {
            diagnostics.record(at(15), false);
        }
        for _ in 0..3 {
            diagnostics.record(at(30), false);
        }
        assert_eq!(diagnostics.recent_arrivals(at(30)), 1025 + 7 + 3);
        assert_eq!(
            diagnostics.recent_arrivals(at(31)),
            7 + 3,
            "the 1025 at t0 fell out"
        );
        assert_eq!(diagnostics.recent_arrivals(at(45)), 7 + 3);
        assert_eq!(diagnostics.recent_arrivals(at(46)), 3);
        assert_eq!(diagnostics.recent_arrivals(at(60)), 3);
        assert_eq!(diagnostics.recent_arrivals(at(61)), 0);
        // Recording prunes what is past the window, so a long-lived runtime
        // holds only the current window.
        diagnostics.record(at(100), false);
        assert_eq!(diagnostics.recent.len(), 1);
        assert_eq!(diagnostics.recent_arrivals(at(100)), 1);
    }

    /// L1 memory bound: the representation is one entry per **distinct
    /// observation instant** in the window, never one entry per arrival, and
    /// it is pruned to the window on every record. The count is exact at every
    /// step, so the bound never costs an arrival.
    #[test]
    fn stage14_11_interference_recent_window_memory_is_bounded() {
        let t0 = Instant::now();
        let mut diagnostics = ListenerInterferenceDiagnostics::default();
        // 50 000 arrivals, every one at a distinct instant, all inside 30 s.
        // One entry per distinct instant; the count is exact.
        for i in 0..50_000u64 {
            diagnostics.record(t0 + Duration::from_micros(i * 500), false);
            assert_eq!(
                diagnostics.recent_arrivals(t0 + Duration::from_micros(i * 500)),
                i + 1,
                "exact at every distinct instant {i}"
            );
        }
        let now = t0 + Duration::from_micros(50_000 * 500);
        assert_eq!(
            diagnostics.recent.len(),
            50_000,
            "one entry per distinct instant"
        );
        assert_eq!(
            diagnostics.recent_arrivals(now),
            50_000,
            "a distinct-instant stream never drops an arrival"
        );
        // A long stream spanning many windows keeps only the current window.
        let mut diagnostics = ListenerInterferenceDiagnostics::default();
        for i in 0..3000u64 {
            diagnostics.record(t0 + Duration::from_millis(i * 100), false);
        }
        let now = t0 + Duration::from_millis(2999 * 100);
        assert_eq!(
            diagnostics.recent_arrivals(now),
            301,
            "exactly the arrivals in the last 30 s, inclusive"
        );
        assert!(
            diagnostics.recent.len() <= 302,
            "pruned to the window: {}",
            diagnostics.recent.len()
        );
    }

    /// L1 memory bound, the arrival-rate half: arrivals observed at ONE
    /// observation instant — the shape the real observation model produces,
    /// since `tick_at` gives every arrival of an iteration the same `now` —
    /// keep exactly ONE entry no matter how many arrive. Memory is bounded by
    /// the observation cadence, never by the arrival rate.
    #[test]
    fn stage14_11_interference_recent_memory_ignores_the_arrival_rate() {
        let t0 = Instant::now();
        let mut diagnostics = ListenerInterferenceDiagnostics::default();
        for _ in 0..1_000_000u64 {
            diagnostics.record(t0, false);
            assert_eq!(
                diagnostics.recent.len(),
                1,
                "a million arrivals at one instant are one entry"
            );
        }
        assert_eq!(diagnostics.recent_arrivals(t0), 1_000_000);
        assert_eq!(
            diagnostics.recent_arrivals(t0 + Duration::from_secs(30)),
            1_000_000
        );
        assert_eq!(
            diagnostics.recent_arrivals(t0 + Duration::from_nanos(30_000_000_001)),
            0
        );
    }

    // ---- Stage 14 Phase 14.11 L1-MEM: the quantified memory bound ---------
    //
    // The Active renew floor (`ACTIVE_RENEW_MIN_WAIT` = 100 ms, Linux-only
    // `linux_node_runtime`) and the ordinary cadence (>= 1 s) bound the
    // foreground tick spacing; `note_unauthenticated_arrival` adds at most one
    // distinct instant per tick. Closed 30 s window, in ticks:
    //   T <= floor(30 s / floor) + 1 + 2 = 303
    // (floor spacings + the first tick + at most two expiry-limited short
    // spacings at the window edges, a conservative allowance; derivation in
    // the addendum). The two
    // constants below are the test-side copy of the production constant; the
    // `mkm_arch_017_active_wait_floor_bounds_the_diagnostic_window` guard pins
    // them equal.
    const L1_RENEW_FLOOR_MS: u64 = 100;
    const L1_MAX_TICKS_30S: usize = (30_000 / L1_RENEW_FLOOR_MS) as usize + 1 + 2;
    const L1_MAX_CAPACITY: usize = 512;

    /// One recorded arrival per tick at the MINIMUM legal tick spacing, for
    /// 100 000 ticks (about 2.8 hours of controller time): the window never
    /// holds more entries than the closed-window tick bound, the count stays
    /// exact, and the long-run capacity high-water mark stays at or below the
    /// quantified maximum.
    #[test]
    fn stage14_11_l1_memory_is_bounded_at_the_minimum_tick_spacing() {
        assert_eq!(L1_MAX_TICKS_30S, 303);
        assert_eq!(
            std::mem::size_of::<(Instant, u64)>(),
            24,
            "the payload arithmetic below assumes the 24-byte entry"
        );
        let t0 = Instant::now();
        let spacing = Duration::from_millis(L1_RENEW_FLOOR_MS);
        let mut diagnostics = ListenerInterferenceDiagnostics::default();
        let mut max_len = 0usize;
        let mut max_capacity = 0usize;
        for i in 0..100_000u32 {
            let now = t0 + spacing * i;
            diagnostics.record(now, false);
            max_len = max_len.max(diagnostics.recent.len());
            max_capacity = max_capacity.max(diagnostics.recent.capacity());
            if i % 997 == 0 || i < 400 {
                let in_window = (i as u64).min(30_000 / L1_RENEW_FLOOR_MS) + 1;
                assert_eq!(
                    diagnostics.recent_arrivals(now),
                    in_window,
                    "exact count at tick {i}"
                );
            }
        }
        assert_eq!(max_len, 301, "30 s / 100 ms + 1 (inclusive window)");
        assert!(max_len <= L1_MAX_TICKS_30S);
        assert!(
            max_capacity <= L1_MAX_CAPACITY,
            "capacity high-water mark {max_capacity}"
        );
        assert!(
            diagnostics.recent.capacity() * std::mem::size_of::<(Instant, u64)>() <= 12_288,
            "payload bytes of the retained allocation"
        );
        // Quiet time does not grow it, and a later burst at the same instant
        // keeps one entry.
        let later = t0 + spacing * 100_000 + Duration::from_secs(3_600);
        for _ in 0..10_000 {
            diagnostics.record(later, false);
        }
        assert_eq!(diagnostics.recent.len(), 1);
        assert!(diagnostics.recent.capacity() <= L1_MAX_CAPACITY);
    }

    /// A conservative worst shape: the number of distinct tick instants a
    /// closed 30 s window holds when every spacing is at least the 100 ms floor
    /// except two 1 ms expiry-limited spacings (one at each edge): 2 + 299 + 1 =
    /// 302 ticks, one below the published bound of 303. (The addendum's
    /// sharper reading, in which an expiry-limited spacing is followed by an
    /// ordinary wait, gives 301; the shape here is deliberately more
    /// adversarial than any reachable one.) All are held, exactly counted, and
    /// the allocation is the quantified 512-entry maximum.
    #[test]
    fn stage14_11_l1_memory_at_the_derived_window_maximum_is_exact() {
        let t0 = Instant::now();
        let short = Duration::from_millis(1);
        let mut instants = vec![t0, t0 + short];
        let mut next = t0 + short;
        for _ in 0..299 {
            next += Duration::from_millis(L1_RENEW_FLOOR_MS);
            instants.push(next);
        }
        instants.push(next + short);
        assert_eq!(instants.len(), 302);
        assert!(instants.len() <= L1_MAX_TICKS_30S);
        assert!(
            instants.windows(2).all(|pair| pair[1] > pair[0]),
            "302 DISTINCT instants"
        );
        assert!(*instants.last().unwrap() <= t0 + Duration::from_secs(30));
        // One more floor spacing would leave the closed window: the shape is tight.
        assert!(
            *instants.last().unwrap() + Duration::from_millis(L1_RENEW_FLOOR_MS)
                > t0 + Duration::from_secs(30)
        );
        let mut diagnostics = ListenerInterferenceDiagnostics::default();
        for instant in &instants {
            diagnostics.record(*instant, false);
        }
        assert_eq!(diagnostics.recent.len(), 302);
        assert_eq!(
            diagnostics.recent_arrivals(t0 + Duration::from_secs(30)),
            302
        );
        assert_eq!(
            diagnostics.recent.capacity(),
            L1_MAX_CAPACITY,
            "302 entries are held by the 512-entry power-of-two allocation"
        );
        assert_eq!(
            diagnostics.recent.capacity() * std::mem::size_of::<(Instant, u64)>(),
            12_288
        );
        // One nanosecond past the window the oldest tick has left: exact.
        assert_eq!(
            diagnostics.recent_arrivals(t0 + Duration::from_nanos(30_000_000_001)),
            301
        );
    }

    /// L1 exactness, the case the independent re-audit reproduced: 1025
    /// arrivals at 1025 distinct observation instants inside the 30 s window,
    /// then only the oldest one leaves it. The reported count must be the
    /// mathematically correct one at every step.
    #[test]
    fn stage14_11_interference_1025_distinct_instants_expire_one_at_a_time() {
        let t0 = Instant::now();
        let mut diagnostics = ListenerInterferenceDiagnostics::default();
        for i in 0..1025u64 {
            diagnostics.record(t0 + Duration::from_millis(i), false);
            assert_eq!(
                diagnostics.recent_arrivals(t0 + Duration::from_millis(i)),
                i + 1,
                "all {i} distinct instants are inside the window"
            );
        }
        assert_eq!(
            diagnostics.recent.len(),
            1025,
            "one entry per distinct instant"
        );
        assert_eq!(
            diagnostics.recent_arrivals(t0 + Duration::from_millis(1024)),
            1025
        );
        // The oldest instant (t0) is the only one outside the window at
        // t0 + 30 s + 1 ns: 1024 remain, exactly.
        assert_eq!(
            diagnostics.recent_arrivals(t0 + Duration::from_nanos(30_000_000_001)),
            1024,
            "the oldest arrival expired; 1024 remain"
        );
        // And one nanosecond earlier the inclusive boundary still holds all.
        assert_eq!(
            diagnostics.recent_arrivals(t0 + Duration::from_nanos(30_000_000_000)),
            1025,
            "the 30 s boundary is inclusive"
        );
    }

    /// L1 exactness against an independent reference count. The observation
    /// clock only moves forward (one `Instant::now()` per `tick_at`) and the
    /// window is pruned at record time, so arrivals and queries are
    /// interleaved in non-decreasing instant order exactly as the runtime does
    /// them. At every step the reported count equals a direct recount of the
    /// recorded instants under the inclusive 30 s rule.
    #[test]
    fn stage14_11_interference_recent_count_matches_a_reference_recount() {
        let window = crate::failure_assessment::LOCAL_LOSS_EVIDENCE_MAX_AGE;
        let t0 = Instant::now();
        let mut diagnostics = ListenerInterferenceDiagnostics::default();
        // Irregular spacing with repeated instants, over 40 s, so many buckets
        // leave the window one after another.
        let arrival_at = |i: u64| Duration::from_millis((i * 137) % 40_000);
        let mut recorded: Vec<Duration> = Vec::new();
        let mut next_arrival = 0u64;
        for step in 0..=40_000u64 {
            let now = Duration::from_millis(step);
            while next_arrival < 400 && arrival_at(next_arrival) <= now {
                diagnostics.record(t0 + arrival_at(next_arrival), false);
                recorded.push(arrival_at(next_arrival));
                next_arrival += 1;
            }
            let expected = recorded
                .iter()
                .filter(|at| now.checked_sub(**at).is_some_and(|age| age <= window))
                .count() as u64;
            assert_eq!(
                diagnostics.recent_arrivals(t0 + now),
                expected,
                "exact recount at +{step} ms"
            );
        }
    }

    /// L1 exactness over a long arrival sequence interleaved with queries in
    /// forward clock order: the reported count is always the mathematical
    /// count, and the structure never grows past the current window.
    #[test]
    fn stage14_11_interference_long_sequence_stays_exact() {
        let window = crate::failure_assessment::LOCAL_LOSS_EVIDENCE_MAX_AGE;
        let t0 = Instant::now();
        let mut diagnostics = ListenerInterferenceDiagnostics::default();
        // 100 000 arrivals over 400 s (one every 4 ms, ~133 windows), queried
        // every 37 ms.
        let mut recorded: Vec<Duration> = Vec::new();
        let mut next_arrival = 0u64;
        for step in (0..=400_000u64).step_by(37) {
            let now = Duration::from_millis(step);
            while next_arrival < 100_000 && Duration::from_millis(next_arrival * 4) <= now {
                let at = Duration::from_millis(next_arrival * 4);
                diagnostics.record(t0 + at, false);
                recorded.push(at);
                next_arrival += 1;
            }
            let expected = recorded
                .iter()
                .filter(|at| now.checked_sub(**at).is_some_and(|age| age <= window))
                .count() as u64;
            assert_eq!(
                diagnostics.recent_arrivals(t0 + now),
                expected,
                "exact over a long sequence at +{step} ms"
            );
        }
        // Pruned to the window: one entry per distinct instant of the trailing
        // 30 s (4 ms apart => at most 7501) and nothing older.
        diagnostics.record(t0 + Duration::from_millis(400_000), false);
        assert!(
            diagnostics.recent.len() <= 7_501,
            "{}",
            diagnostics.recent.len()
        );
    }

    /// L1 through the runtime: 1025 accepted-but-unauthenticated arrivals at
    /// one observation instant are all reported by the operator-facing count
    /// and by the first WARN, which alone carries the guidance; a later WARN
    /// window repeats no guidance.
    #[test]
    fn stage14_11_runtime_reports_1025_arrivals_exactly() {
        let (_outbound, mut inbound, _address) = pair();
        let t0 = Instant::now();
        crate::operator_log::capture_start();
        for _ in 0..1025 {
            inbound.note_unauthenticated_arrival(t0);
        }
        let first = crate::operator_log::capture_take();
        assert_eq!(inbound.listener_interference_recent(t0), 1025);
        assert_eq!(interference_warns(&first), [(1, 0)], "{first:?}");
        assert!(first[0].contains(crate::operator_log::LISTENER_INTERFERENCE_GUIDANCE));
        // The next WARN window reports the other 1024 held arrivals exactly,
        // once, without guidance.
        crate::operator_log::capture_start();
        inbound.flush_interference_warn(t0 + Duration::from_secs(30));
        let second = crate::operator_log::capture_take();
        assert_eq!(interference_warns(&second), [(1024, 0)], "{second:?}");
        assert!(!second[0].contains(crate::operator_log::LISTENER_INTERFERENCE_GUIDANCE));
        // A third window after quiet: nothing held, nothing printed.
        crate::operator_log::capture_start();
        inbound.flush_interference_warn(t0 + Duration::from_secs(90));
        assert!(crate::operator_log::capture_take().is_empty());
        assert_eq!(
            inbound.listener_interference_recent(t0 + Duration::from_secs(31)),
            0
        );
    }

    /// §34.18 (1): an accepted unauthenticated connection voids the window at
    /// accept, before any authentication outcome is known; the arrival is
    /// counted only when it ends unauthenticated.
    #[test]
    fn stage14_11_accepted_connection_voids_the_window_before_authentication() {
        let (_outbound, mut inbound, address) = pair();
        let t0 = Instant::now();
        for seconds in 0..3 {
            inbound.tick_at(t0 + Duration::from_secs(seconds)).unwrap();
        }
        assert!(inbound.listen_window.is_some(), "a window is open");
        crate::operator_log::capture_start();
        let client = TcpStream::connect(address).unwrap();
        let deadline = Instant::now() + LOOPBACK_WAIT;
        let accept_at = t0 + Duration::from_secs(3);
        while inbound.current_token.is_none() {
            inbound.tick_at(accept_at).unwrap();
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
        // At accept: the window is already void, the arrival is not yet counted.
        assert_eq!(
            inbound.last_window_void,
            Some(ListenWindowVoid::AcceptedConnection)
        );
        assert!(inbound.listen_window.is_none());
        assert_eq!(inbound.interference.arrivals_since_warn, 0);
        assert!(crate::operator_log::capture_take().is_empty());
        // The handshake deadline ends it unauthenticated: now it is counted.
        crate::operator_log::capture_start();
        let expires = inbound.handshake_deadline.unwrap().1;
        inbound.tick_at(expires).unwrap();
        let lines = crate::operator_log::capture_take();
        drop(client);
        assert_eq!(interference_warns(&lines), [(1, 1)], "{lines:?}");
        assert!(lines[0].contains(crate::operator_log::LISTENER_INTERFERENCE_GUIDANCE));
    }

    /// §34.18 (2)-(4): arrivals every 5 s for 5 min complete no window and form
    /// no `CommunicationLost`; exactly one WARN per 30 s with accurate counts;
    /// after the arrivals stop, two consecutive windows form loss.
    #[test]
    fn stage14_11_arrivals_every_5s_for_5min_form_no_loss_and_then_recover() {
        let (_outbound, mut inbound, address) = pair();
        inbound.failure_assessment =
            PeerFailureDetector::with_default_window().with_restart_formation(true);
        crate::operator_log::capture_start();
        let base = Instant::now();
        // A window is open before the first arrival, so every accept voids one
        // (whether the kernel made the first connection acceptable on the
        // first tick is a loopback timing detail this test must not depend on).
        for seconds in 0..3 {
            inbound
                .tick_at(base + Duration::from_secs(seconds))
                .unwrap();
        }
        assert!(inbound.listen_window.is_some());
        let start = base + Duration::from_secs(3);
        for i in 0..60u64 {
            let expires = silent_arrival(&mut inbound, address, start + Duration::from_secs(5 * i));
            inbound.tick_at(expires + Duration::from_secs(1)).unwrap();
        }
        assert!(
            inbound.last_window_completion_iteration.is_none(),
            "no window completed"
        );
        assert!(inbound.loss_evidence().is_none(), "no loss episode formed");
        assert_ne!(
            inbound.failure_assessment().assessment,
            crate::failure_assessment::PeerFailureAssessment::CommunicationLost
        );
        // The held counts are reported once the 30 s bound has passed.
        let quiet = start + Duration::from_secs(5 * 59 + 4 + 31);
        inbound.tick_at(quiet).unwrap();
        let lines = crate::operator_log::capture_take();
        let warns = interference_warns(&lines);
        // The first arrival logs immediately. After that a WARN is due at the
        // first tick that sees the 30 s bound elapsed; it reports the arrivals
        // held so far (five, then six per 30 s), and the final flush reports
        // the rest.
        let arrivals: Vec<u64> = warns.iter().map(|(arrivals, _)| *arrivals).collect();
        assert_eq!(arrivals, [1, 5, 6, 6, 6, 6, 6, 6, 6, 6, 6], "{lines:?}");
        assert_eq!(
            arrivals.iter().sum::<u64>(),
            60,
            "every arrival is reported once"
        );
        let voided: u64 = warns.iter().map(|(_, voided)| *voided).sum();
        assert_eq!(voided, 60, "every accept voided an open window");
        assert_eq!(warns[0], (1, 1));
        assert!(lines[0].contains(crate::operator_log::LISTENER_INTERFERENCE_GUIDANCE));
        assert!(
            lines[1..]
                .iter()
                .all(|line| !line.contains(crate::operator_log::LISTENER_INTERFERENCE_GUIDANCE)),
            "guidance rides on the first WARN only"
        );
        // After the arrivals stop, verified-listen windows form loss again.
        let mut now = quiet;
        for _ in 0..60 {
            now += Duration::from_secs(1);
            inbound.tick_at(now).unwrap();
            if inbound.loss_evidence().is_some() {
                break;
            }
        }
        assert!(inbound.loss_evidence().is_some(), "two windows formed loss");
    }

    /// §34.18 (5) / MF-45: diagnostics have no state effect. The same
    /// scenario, with the diagnostic counters wiped after every tick, leaves
    /// the detector, the observation, the window, and the connection state
    /// identical at every step. The counters are demonstrably different
    /// between the two runs, so the comparison is not vacuous.
    #[test]
    fn stage14_11_diagnostics_have_no_state_effect() {
        type Observed = (
            crate::failure_assessment::PeerFailureAssessment,
            Option<crate::failure_assessment::FailureReason>,
            Option<crate::failure_assessment::SuspectOrigin>,
            u64,
            bool,
            PeerObservationState,
            bool,
            Option<ListenWindowVoid>,
            bool,
            // The whole detector, field for field (timestamps included).
            String,
        );
        fn observe(runtime: &DaemonPeerRuntime, now: Instant) -> Observed {
            let snapshot = runtime.failure_assessment();
            (
                snapshot.assessment,
                snapshot.reason,
                snapshot.suspect_origin,
                snapshot.loss_generation,
                runtime.loss_evidence().is_some(),
                runtime.snapshot(now).state,
                runtime.listen_window.is_some(),
                runtime.last_window_void,
                runtime.current_token.is_some(),
                format!("{:?}", runtime.failure_assessment),
            )
        }
        fn scenario(wipe: bool, base: Instant) -> (Vec<Observed>, u64) {
            let (_outbound, mut inbound, address) = pair();
            inbound.failure_assessment =
                PeerFailureDetector::with_default_window().with_restart_formation(true);
            crate::operator_log::capture_start();
            for seconds in 0..3 {
                inbound
                    .tick_at(base + Duration::from_secs(seconds))
                    .unwrap();
            }
            let start = base + Duration::from_secs(3);
            let mut seen = Vec::new();
            for i in 0..12u64 {
                let expires =
                    silent_arrival(&mut inbound, address, start + Duration::from_secs(5 * i));
                let after = expires + Duration::from_secs(1);
                inbound.tick_at(after).unwrap();
                if wipe {
                    inbound.reset_interference_for_test();
                }
                seen.push(observe(&inbound, after));
            }
            let mut now = start + Duration::from_secs(5 * 11 + 4);
            for _ in 0..40 {
                now += Duration::from_secs(1);
                inbound.tick_at(now).unwrap();
                if wipe {
                    inbound.reset_interference_for_test();
                }
                seen.push(observe(&inbound, now));
            }
            let _ = crate::operator_log::capture_take();
            (seen, inbound.interference.arrivals_since_warn)
        }
        // One shared time base: the detector's timestamps are then identical
        // in both runs, so the whole-detector comparison is exact.
        let base = Instant::now();
        let (with_diagnostics, held_a) = scenario(false, base);
        let (wiped, held_b) = scenario(true, base);
        assert_eq!(
            with_diagnostics, wiped,
            "diagnostics never change a decision"
        );
        assert!(
            with_diagnostics.iter().any(|seen| seen.4),
            "the scenario formed loss, so it exercised the detector"
        );
        assert_eq!(held_b, 0);
        let _ = held_a;
    }

    /// §28.1 / MF-45, steering variant: with the detector in a state where any
    /// stray stimulus or skipped tick is visible (a Healthy-origin Suspect that
    /// time alone turns into `CommunicationLost`) and an open verified-listen
    /// window, a burst of diagnostic arrivals must change nothing: the same
    /// run with the counters wiped after every arrival is identical at every
    /// step, field for field. The counters differ between the two runs, and
    /// the run does reach `CommunicationLost`, so the comparison is not vacuous.
    #[test]
    fn stage14_11_diagnostics_never_steer_the_detector_or_the_window() {
        fn observed(
            runtime: &DaemonPeerRuntime,
            now: Instant,
        ) -> (String, bool, Option<ListenWindowVoid>, bool) {
            (
                format!("{:?}", runtime.failure_assessment),
                runtime.listen_window.is_some(),
                runtime.last_window_void,
                runtime.loss_evidence().is_some(),
            )
        }
        fn scenario(
            wipe: bool,
            base: Instant,
        ) -> (
            Vec<(String, bool, Option<ListenWindowVoid>, bool)>,
            u64,
            bool,
        ) {
            let (_outbound, mut inbound, _address) = pair();
            inbound.failure_assessment = PeerFailureDetector::with_default_window();
            crate::operator_log::capture_start();
            // Open a verified-listen window (the listener samples each tick).
            for seconds in 0..3 {
                inbound
                    .tick_at(base + Duration::from_secs(seconds))
                    .unwrap();
            }
            assert!(inbound.listen_window.is_some(), "a window is open");
            // A Healthy-origin Suspect: only elapsed time can confirm it.
            let peer_session = crate::protocol::SessionId::new("peer-session");
            inbound
                .failure_assessment
                .observe_session_established(peer_session.clone(), base + Duration::from_secs(2))
                .unwrap();
            inbound
                .failure_assessment
                .observe_trusted_heartbeat(
                    &peer_session,
                    crate::protocol::Sequence(1),
                    base + Duration::from_secs(2),
                )
                .unwrap();
            let mut seen = Vec::new();
            // Diagnostic arrivals while the detector is Healthy ...
            for _ in 0..6 {
                inbound.note_unauthenticated_arrival(base + Duration::from_secs(2));
                if wipe {
                    inbound.reset_interference_for_test();
                }
                seen.push(observed(&inbound, base + Duration::from_secs(2)));
            }
            let t = base + Duration::from_secs(3);
            inbound
                .failure_assessment
                .observe_transport_failure(t)
                .unwrap();
            // A burst of diagnostic arrivals, at one instant, well past every
            // threshold a diagnostics-dependent branch could use.
            for _ in 0..12 {
                inbound.note_unauthenticated_arrival(t);
                if wipe {
                    inbound.reset_interference_for_test();
                }
                seen.push(observed(&inbound, t));
            }
            let recent = inbound.listener_interference_recent(t);
            // Then time passes; the detector alone decides.
            let mut lost = false;
            for step in 1..=8u64 {
                let now = t + Duration::from_secs(step);
                inbound.tick_at(now).unwrap();
                if wipe {
                    inbound.reset_interference_for_test();
                }
                lost |= inbound.failure_assessment().assessment
                    == crate::failure_assessment::PeerFailureAssessment::CommunicationLost;
                seen.push(observed(&inbound, now));
            }
            let _ = crate::operator_log::capture_take();
            (seen, recent, lost)
        }
        let base = Instant::now();
        let (with_diagnostics, recent_a, lost_a) = scenario(false, base);
        let (wiped, recent_b, lost_b) = scenario(true, base);
        assert_eq!(recent_a, 18, "the diagnostic bursts were counted");
        assert_eq!(recent_b, 0, "and wiped in the control run");
        assert!(
            lost_a && lost_b,
            "the detector reached CommunicationLost by time alone"
        );
        assert_eq!(
            with_diagnostics, wiped,
            "diagnostics never steer the detector or the window"
        );
    }

    /// §28.1: only an Inbound accepted connection that ends unauthenticated is
    /// a listener arrival. A wrong-PSK peer is counted (and reported) on the
    /// Inbound side and never on the Outbound side, whose identity failure is
    /// not an arrival.
    #[test]
    fn stage14_11_wrong_psk_arrival_is_counted_inbound_and_not_outbound() {
        let (mut inbound, address) = inbound_listener(Duration::from_secs(1));
        let mut outbound = outbound_dialer(address);
        outbound.authenticator = MessageAuthenticator::new(Psk::from_test_bytes([0x66; 32]));
        crate::operator_log::capture_start();
        let t1 = Instant::now();
        outbound.attempt_reconnect(t1);
        let mut now = t1;
        for _ in 0..400 {
            now += Duration::from_millis(10);
            let _ = inbound.tick_at(now);
            let _ = outbound.tick_at(now);
            if inbound.interference.recent_arrivals(now) > 0 {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        // The outbound side's own handshake deadline ends its attempt.
        let _ = outbound.tick_at(t1 + HANDSHAKE_TIMEOUT + Duration::from_secs(1));
        let lines = crate::operator_log::capture_take();
        assert!(
            inbound.interference.recent_arrivals(now) >= 1,
            "the arrival was counted"
        );
        assert_eq!(interference_warns(&lines)[0].0, 1, "{lines:?}");
        assert!(
            outbound.interference.recent.is_empty(),
            "no arrival on the dialing side"
        );
        assert_eq!(outbound.interference.arrivals_since_warn, 0);
        assert_eq!(outbound.listener_interference_recent(now), 0);
    }

    /// §28.1: authenticated peer traffic is never an unauthenticated
    /// arrival. Two runtimes authenticate, exchange heartbeats for a while, and
    /// then the peer closes cleanly: neither side counts an arrival, voids a
    /// reported window, or writes a `ListenerInterference` line, and the
    /// authenticated session stays Fresh throughout.
    #[test]
    fn stage14_11_authenticated_traffic_and_clean_close_are_never_arrivals() {
        crate::operator_log::capture_start();
        let (mut outbound, mut inbound, start) = establish_pair();
        let mut now = start + Duration::from_secs(1);
        for _ in 0..60 {
            now += Duration::from_secs(1);
            outbound.tick_at(now).unwrap();
            inbound.tick_at(now).unwrap();
            thread::yield_now();
        }
        assert!(inbound.is_established() && outbound.is_established());
        assert_eq!(
            inbound.snapshot(now).state,
            PeerObservationState::Fresh,
            "heartbeats really were exchanged"
        );
        // A clean close of the authenticated connection.
        outbound.shutdown_at(now);
        let deadline = Instant::now() + LOOPBACK_WAIT;
        while inbound.current_token.is_some() {
            now += Duration::from_millis(10);
            // A reset/EOF of the closed connection may surface as a tick
            // error (F1: drained first); it is a transport event, not an
            // arrival.
            let _ = inbound.tick_at(now);
            assert!(Instant::now() < deadline, "the close was never observed");
            thread::yield_now();
        }
        let lines = crate::operator_log::capture_take();
        assert!(interference_warns(&lines).is_empty(), "{lines:?}");
        for runtime in [&inbound, &outbound] {
            assert_eq!(runtime.listener_interference_recent(now), 0);
            assert_eq!(runtime.interference.arrivals_since_warn, 0);
            assert_eq!(runtime.interference.voided_since_warn, 0);
            assert!(runtime.interference.recent.is_empty());
        }
    }

    /// §28.1: the role condition. Only an Inbound accepted connection can be a
    /// listener arrival; an Outbound identity failure (a mismatching
    /// HELLO_ACK) is uncertainty but never an arrival, even with a stale
    /// accept flag. The same event on the Inbound side is counted.
    #[test]
    fn stage14_11_outbound_identity_uncertainty_is_not_an_arrival() {
        let (mut outbound, mut inbound, _address) = pair();
        let now = Instant::now();
        crate::operator_log::capture_start();
        outbound.pending_identity_uncertainty = true;
        outbound.accept_voided_window = true;
        outbound.observe_transport_failure(now).unwrap();
        assert!(crate::operator_log::capture_take().is_empty());
        assert_eq!(outbound.listener_interference_recent(now), 0);
        assert_eq!(outbound.interference.arrivals_since_warn, 0);
        assert_eq!(outbound.interference.voided_since_warn, 0);
        crate::operator_log::capture_start();
        inbound.pending_identity_uncertainty = true;
        inbound.accept_voided_window = true;
        inbound.observe_transport_failure(now).unwrap();
        let lines = crate::operator_log::capture_take();
        assert_eq!(interference_warns(&lines), [(1, 1)], "{lines:?}");
        assert_eq!(inbound.listener_interference_recent(now), 1);
    }

    // ===================================================================
    // Bootstrap Admission probe transport (contract K-2 / K-3)
    // ===================================================================

    use crate::bootstrap_admission::{BootstrapStamp, ProbeOutcome, ProbeVerdict};
    use std::cell::Cell;

    /// Real time one BA test may spend waiting for an effect of a real TCP
    /// exchange (the virtual ticks below run in microseconds; the kernel needs
    /// real time to deliver a small frame, on Linux up to ~41 ms with Nagle and
    /// delayed ACKs). A test never waits longer than this.
    const BA_REAL_BUDGET: Duration = Duration::from_secs(10);

    /// A short pause of REAL time between two virtual ticks, so that a frame
    /// written by one runtime can arrive before the other one polls.
    fn ba_pause() {
        thread::sleep(Duration::from_millis(1));
    }

    /// Paces a tick loop: yields `Some(n)` for n = 0, 1, 2, ... with a real
    /// pause between steps, and stops (`None`) after `max_steps` steps (this
    /// bounds the VIRTUAL time that passes) or when the real `budget` is used
    /// up (this bounds the REAL time). The waiting is therefore driven by the
    /// condition the loop checks, not by a fixed number of ticks.
    struct BaClock {
        started: Instant,
        deadline: Instant,
        steps: u64,
        max_steps: u64,
    }

    impl BaClock {
        fn new(budget: Duration, max_steps: u64) -> Self {
            let started = Instant::now();
            Self {
                started,
                deadline: started + budget,
                steps: 0,
                max_steps,
            }
        }

        fn tick(&mut self) -> Option<u64> {
            if self.steps >= self.max_steps || Instant::now() >= self.deadline {
                return None;
            }
            if self.steps > 0 {
                ba_pause();
            }
            let step = self.steps;
            self.steps += 1;
            Some(step)
        }

        fn steps(&self) -> u64 {
            self.steps
        }

        /// What a timed-out wait reports, so that a failure can be diagnosed.
        fn report(&self) -> String {
            format!(
                "after {} ticks and {:?} of real time (limits: {} ticks, {:?})",
                self.steps,
                self.started.elapsed(),
                self.max_steps,
                self.deadline.saturating_duration_since(self.started)
            )
        }
    }

    #[test]
    fn ba_clock_is_bounded_in_steps_and_in_real_time_and_lets_real_time_pass() {
        // bounded by steps
        let mut clock = BaClock::new(Duration::from_secs(30), 3);
        let t0 = Instant::now();
        let mut seen = Vec::new();
        while let Some(n) = clock.tick() {
            seen.push(n);
        }
        assert_eq!(seen, [0, 1, 2]);
        assert!(
            t0.elapsed() >= Duration::from_millis(2),
            "real time passes between steps"
        );
        // bounded by REAL time even with an enormous step budget
        let mut clock = BaClock::new(Duration::from_millis(60), u64::MAX);
        let t0 = Instant::now();
        while clock.tick().is_some() {}
        let spent = t0.elapsed();
        assert!(spent >= Duration::from_millis(60), "{spent:?}");
        assert!(spent < Duration::from_secs(5), "{spent:?}");
        assert!(clock.steps() < 10_000, "paced, not a busy loop");
        assert!(clock.report().contains("ticks"));
    }

    /// Tick both runtimes alternately; `outbound_verdict` / `inbound_verdict`
    /// are what each side would answer to a probe it reads. Each step is paced
    /// by a short real pause (`ba_pause`).
    fn ba_ticks(
        outbound: &mut DaemonPeerRuntime,
        inbound: &mut DaemonPeerRuntime,
        start: Instant,
        from_ms: u64,
        count: u64,
        outbound_verdict: ProbeVerdict,
        inbound_verdict: ProbeVerdict,
    ) {
        for offset in 0..count {
            let now = start + Duration::from_millis(from_ms + offset);
            outbound
                .tick_at_with(now, &mut || outbound_verdict)
                .unwrap();
            inbound.tick_at_with(now, &mut || inbound_verdict).unwrap();
            ba_pause();
        }
    }

    fn ba_outcome_within(
        asker: &mut DaemonPeerRuntime,
        answerer: &mut DaemonPeerRuntime,
        asker_is_outbound: bool,
        start: Instant,
        verdict: ProbeVerdict,
    ) -> Option<ProbeOutcome> {
        let mut clock = BaClock::new(BA_REAL_BUDGET, 2000);
        while let Some(step) = clock.tick() {
            let now = start + Duration::from_millis(5_000 + step);
            if asker_is_outbound {
                asker
                    .tick_at_with(now, &mut || ProbeVerdict::Unknown)
                    .unwrap();
                answerer.tick_at_with(now, &mut || verdict).unwrap();
            } else {
                answerer.tick_at_with(now, &mut || verdict).unwrap();
                asker
                    .tick_at_with(now, &mut || ProbeVerdict::Unknown)
                    .unwrap();
            }
            if let Some(outcome) = asker.take_probe_outcome() {
                return Some(outcome);
            }
        }
        eprintln!(
            "BA test: no probe outcome {}; asker probe state {:?}, answerer pending requests {}",
            clock.report(),
            asker.probe,
            answerer.pending_probe_requests.len()
        );
        None
    }

    #[test]
    fn ba_probe_round_trip_in_both_directions_returns_the_peers_verdict() {
        for verdict in [
            ProbeVerdict::Ack,
            ProbeVerdict::Block,
            ProbeVerdict::Unknown,
        ] {
            for asker_is_outbound in [true, false] {
                let (mut outbound, mut inbound, start) = establish_pair();
                let (asker, answerer) = if asker_is_outbound {
                    (&mut outbound, &mut inbound)
                } else {
                    (&mut inbound, &mut outbound)
                };
                let stamp = asker.bootstrap_stamp().expect("established");
                assert!(asker.request_probe());
                let outcome = ba_outcome_within(asker, answerer, asker_is_outbound, start, verdict)
                    .expect("a probe outcome");
                assert_eq!(
                    outcome,
                    ProbeOutcome::Response { stamp, verdict },
                    "{verdict:?} asker_outbound={asker_is_outbound}"
                );
                assert!(
                    asker.take_probe_outcome().is_none(),
                    "the outcome is taken once"
                );
            }
        }
    }

    /// K-3: the verdict is evaluated only when a probe was read, once per tick,
    /// and only after the frames of that tick were read.
    #[test]
    fn ba_verdict_is_computed_lazily_in_the_tick_that_read_the_probe() {
        let (mut outbound, mut inbound, start) = establish_pair();
        let calls = Cell::new(0u32);
        // idle ticks never evaluate the verdict
        for offset in 0..20u64 {
            let now = start + Duration::from_millis(3_000 + offset);
            inbound
                .tick_at_with(now, &mut || {
                    calls.set(calls.get() + 1);
                    ProbeVerdict::Ack
                })
                .unwrap();
            outbound.tick_at(now).unwrap();
        }
        assert_eq!(
            calls.get(),
            0,
            "no probe was read: no observation is requested"
        );
        assert!(outbound.request_probe());
        let mut answered_in_tick = None;
        for offset in 0..2000u64 {
            let now = start + Duration::from_millis(4_000 + offset);
            outbound.tick_at(now).unwrap();
            let before = calls.get();
            inbound
                .tick_at_with(now, &mut || {
                    calls.set(calls.get() + 1);
                    ProbeVerdict::Ack
                })
                .unwrap();
            if calls.get() != before && answered_in_tick.is_none() {
                answered_in_tick = Some(offset);
            }
            if outbound.take_probe_outcome().is_some() {
                break;
            }
            ba_pause();
        }
        assert!(answered_in_tick.is_some());
        assert_eq!(calls.get(), 1, "one probe, one evaluation");
    }

    #[test]
    fn ba_nothing_is_sent_before_the_probe_is_requested_and_only_one_probe_is_outstanding() {
        // The inbound node asks; the outbound node records what it receives.
        let (mut outbound, mut inbound, start) = establish_pair();
        ba_ticks(
            &mut outbound,
            &mut inbound,
            start,
            3_000,
            50,
            ProbeVerdict::Ack,
            ProbeVerdict::Ack,
        );
        assert!(
            !outbound
                .received_messages
                .iter()
                .any(|m| m.message.message_type() == MessageType::PromotionIntent),
            "no probe may exist before the daemon asks for one"
        );
        assert!(inbound.request_probe());
        assert!(!inbound.request_probe(), "a probe is already requested");
        // The probe is a small frame on a real TCP connection: wait (bounded
        // in virtual AND real time) until it has really reached the outbound
        // side, instead of assuming it arrives within a fixed number of ticks.
        let probes_received = |outbound: &DaemonPeerRuntime| {
            outbound
                .received_messages
                .iter()
                .filter(|m| m.message.message_type() == MessageType::PromotionIntent)
                .count()
        };
        let mut clock = BaClock::new(BA_REAL_BUDGET, 2_000);
        let mut arrived = false;
        while let Some(step) = clock.tick() {
            let now = start + Duration::from_millis(4_000 + step);
            outbound
                .tick_at_with(now, &mut || ProbeVerdict::Ack)
                .unwrap();
            inbound
                .tick_at_with(now, &mut || ProbeVerdict::Ack)
                .unwrap();
            if probes_received(&outbound) >= 1 {
                arrived = true;
                break;
            }
        }
        assert!(
            arrived,
            "the probe never reached the peer {}",
            clock.report()
        );
        // "only one probe is outstanding": keep ticking for a further real
        // window (100 paced ticks, more than twice the largest delivery delay
        // seen on Linux) and require that no second probe appears.
        ba_ticks(
            &mut outbound,
            &mut inbound,
            start,
            4_000 + clock.steps(),
            100,
            ProbeVerdict::Ack,
            ProbeVerdict::Ack,
        );
        let probes: Vec<_> = outbound
            .received_messages
            .iter()
            .filter(|m| m.message.message_type() == MessageType::PromotionIntent)
            .collect();
        assert_eq!(probes.len(), 1);
        // The wire shape of the probe.
        let probe = probes[0];
        let ProtocolMessage::PromotionIntent(payload) = &probe.message else {
            unreachable!()
        };
        assert_eq!(payload.reason, PROBE_REASON);
        assert_eq!(payload.priority, 90);
        let operation_id = probe.common.operation_id.as_ref().unwrap().as_str();
        assert!(is_valid_operation_id(operation_id), "{operation_id}");
        assert!(probe.common.request_id.is_none() && probe.common.lease_id.is_none());
    }

    #[test]
    fn ba_a_probe_cannot_be_requested_without_an_established_connection() {
        let (mut outbound, _inbound, _address) = pair();
        assert!(outbound.bootstrap_stamp().is_none());
        assert!(!outbound.request_probe());
    }

    #[test]
    fn ba_each_probe_carries_a_fresh_nonce() {
        let (mut outbound, mut inbound, start) = establish_pair();
        for round in 0..3u64 {
            assert!(inbound.request_probe());
            let outcome = ba_outcome_within(
                &mut inbound,
                &mut outbound,
                false,
                start + Duration::from_secs(round * 10),
                ProbeVerdict::Ack,
            );
            assert!(outcome.is_some());
        }
        let mut seen = std::collections::HashSet::new();
        for message in &outbound.received_messages {
            if message.message.message_type() == MessageType::PromotionIntent {
                assert!(
                    seen.insert(
                        message
                            .common
                            .operation_id
                            .clone()
                            .unwrap()
                            .as_str()
                            .to_string()
                    )
                );
            }
        }
        assert_eq!(seen.len(), 3);
    }

    /// Wrong nonce, wrong peer session, a response without a probe: only the
    /// first two invalidate an outstanding probe; the last is ignored.
    #[test]
    fn ba_responses_that_do_not_match_the_outstanding_probe_invalidate_it() {
        let (mut outbound, mut inbound, start) = establish_pair();
        let token = outbound.current_token.unwrap();
        // unsolicited
        let unsolicited = outbound
            .probe_envelope(ProtocolMessage::PromotionAck, &OperationId::new("ba-00"))
            .unwrap();
        outbound.on_probe_response(token, &unsolicited);
        assert!(
            outbound.take_probe_outcome().is_none(),
            "ignored without a probe"
        );

        for case in ["wrong-nonce", "wrong-session", "wrong-token"] {
            assert!(outbound.request_probe());
            // send the probe, but do not let the inbound answer it
            outbound
                .tick_at(start + Duration::from_millis(7_000))
                .unwrap();
            let ProbeState::Sent { operation_id, .. } = outbound.probe.clone() else {
                panic!("probe was not sent");
            };
            let mut forged = inbound
                .probe_envelope(
                    ProtocolMessage::PromotionAck,
                    &OperationId::new(if case == "wrong-nonce" {
                        format!("ba-{}", "0".repeat(32))
                    } else {
                        operation_id.clone()
                    }),
                )
                .unwrap();
            if case == "wrong-session" {
                forged.common.session_id = SessionId::new("another-peer-session");
            }
            let used = if case == "wrong-token" {
                crate::tcp_runtime::test_connection_token(4242)
            } else {
                token
            };
            outbound.on_probe_response(used, &forged);
            assert_eq!(
                outbound.take_probe_outcome(),
                Some(ProbeOutcome::Invalid),
                "{case}"
            );
            assert_eq!(outbound.probe, ProbeState::Idle, "{case}");
        }
    }

    #[test]
    fn ba_a_lost_connection_invalidates_the_probe_and_changes_the_stamp() {
        let (mut outbound, inbound, start) = establish_pair();
        let old: BootstrapStamp = outbound.bootstrap_stamp().unwrap();
        assert!(outbound.request_probe());
        outbound
            .tick_at(start + Duration::from_millis(7_000))
            .unwrap();
        let token = outbound.current_token.unwrap();
        outbound.disconnect_current(token, start + Duration::from_millis(7_001));
        assert_eq!(outbound.take_probe_outcome(), Some(ProbeOutcome::Invalid));
        assert!(
            outbound.bootstrap_stamp().is_none(),
            "no established connection"
        );
        // a new connection has a different stamp
        let address = inbound
            .bind_address
            .unwrap_or_else(|| "127.0.0.1:0".parse().unwrap());
        let _ = address;
        assert_ne!(Some(&old), outbound.bootstrap_stamp().as_ref());
    }

    #[test]
    fn ba_a_malformed_probe_is_answered_unknown() {
        for reason in ["something-else", ""] {
            let (mut outbound, mut inbound, start) = establish_pair();
            let token = outbound.current_token.unwrap();
            let envelope = outbound
                .probe_envelope(
                    ProtocolMessage::PromotionIntent(PromotionIntentPayload {
                        priority: 100,
                        reason: reason.to_string(),
                    }),
                    &OperationId::new(format!("ba-{}", "a".repeat(32))),
                )
                .unwrap();
            outbound.send_message(token, envelope, start).unwrap();
            let mut answer = None;
            for step in 0..2000u64 {
                let now = start + Duration::from_millis(6_000 + step);
                outbound.tick_at(now).unwrap();
                inbound
                    .tick_at_with(now, &mut || ProbeVerdict::Ack)
                    .unwrap();
                outbound.tick_at(now).unwrap();
                if let Some(message) = outbound
                    .received_messages
                    .iter()
                    .find(|m| m.message.message_type() == MessageType::PromotionUnknown)
                {
                    answer = Some(message.clone());
                    break;
                }
                ba_pause();
            }
            let answer = answer.expect("an answer");
            assert!(
                matches!(answer.message, ProtocolMessage::PromotionUnknown),
                "reason {reason:?}"
            );
        }
        // a bad operation id shape is Unknown too
        let (mut outbound, mut inbound, start) = establish_pair();
        let token = outbound.current_token.unwrap();
        let envelope = outbound
            .probe_envelope(
                ProtocolMessage::PromotionIntent(PromotionIntentPayload {
                    priority: 100,
                    reason: PROBE_REASON.to_string(),
                }),
                &OperationId::new("not-a-ba-id"),
            )
            .unwrap();
        outbound.send_message(token, envelope, start).unwrap();
        let mut unknown = false;
        for step in 0..2000u64 {
            let now = start + Duration::from_millis(6_000 + step);
            outbound.tick_at(now).unwrap();
            inbound
                .tick_at_with(now, &mut || ProbeVerdict::Ack)
                .unwrap();
            outbound.tick_at(now).unwrap();
            if outbound
                .received_messages
                .iter()
                .any(|m| m.message.message_type() == MessageType::PromotionUnknown)
            {
                unknown = true;
                break;
            }
            ba_pause();
        }
        assert!(unknown);
    }

    /// Heartbeats keep flowing while probes are exchanged; the probe traffic
    /// never disturbs the peer assessment.
    #[test]
    fn ba_probes_do_not_disturb_heartbeats() {
        let (mut outbound, mut inbound, start) = establish_pair();
        assert!(outbound.request_probe());
        let outcome =
            ba_outcome_within(&mut outbound, &mut inbound, true, start, ProbeVerdict::Ack);
        assert!(outcome.is_some());
        let now = start + Duration::from_secs(8);
        assert_eq!(outbound.snapshot(now).state, PeerObservationState::Fresh);
        assert_eq!(inbound.snapshot(now).state, PeerObservationState::Fresh);
    }
    #[test]
    fn independent_audit_multiple_probes_use_one_live_verdict_and_disconnect_drops() {
        let (mut outbound, mut inbound, start) = establish_pair();
        let token = outbound.current_token.unwrap();
        for n in 0..4 {
            let id = OperationId::new(format!("ba-{n:032x}"));
            let env = outbound
                .probe_envelope(
                    ProtocolMessage::PromotionIntent(PromotionIntentPayload {
                        priority: outbound.local_priority,
                        reason: PROBE_REASON.to_string(),
                    }),
                    &id,
                )
                .unwrap();
            outbound
                .send_message(token, env, start + Duration::from_secs(3))
                .unwrap();
        }
        let calls = Cell::new(0u32);
        for n in 0..2000u64 {
            let now = start + Duration::from_millis(3001 + n);
            inbound
                .tick_at_with(now, &mut || {
                    calls.set(calls.get() + 1);
                    ProbeVerdict::Block
                })
                .unwrap();
            outbound.tick_at(now).unwrap();
            let responses = outbound
                .received_messages
                .iter()
                .filter(|m| m.message == ProtocolMessage::PromotionBlock)
                .count();
            if responses == 4 {
                break;
            }
            ba_pause();
        }
        let answers: Vec<_> = outbound
            .received_messages
            .iter()
            .filter(|m| {
                matches!(
                    m.message,
                    ProtocolMessage::PromotionAck
                        | ProtocolMessage::PromotionBlock
                        | ProtocolMessage::PromotionUnknown
                )
            })
            .collect();
        assert_eq!(answers.len(), 4);
        assert!(
            answers
                .iter()
                .all(|m| m.message == ProtocolMessage::PromotionBlock)
        );
        assert!(calls.get() >= 1 && calls.get() <= 4);
        // Deterministic same-batch check, after authenticated transport was tested above.
        let token = inbound.current_token.unwrap();
        for n in 4..8 {
            let env = outbound
                .probe_envelope(
                    ProtocolMessage::PromotionIntent(PromotionIntentPayload {
                        priority: outbound.local_priority,
                        reason: PROBE_REASON.to_string(),
                    }),
                    &OperationId::new(format!("ba-{n:032x}")),
                )
                .unwrap();
            inbound.on_probe_request(token, &env);
        }
        calls.set(0);
        inbound.answer_probes(start + Duration::from_secs(7), &mut || {
            calls.set(calls.get() + 1);
            ProbeVerdict::Unknown
        });
        assert_eq!(calls.get(), 1);
        assert!(inbound.pending_probe_requests.is_empty());
        assert!(inbound.request_probe());
        inbound.clear_connection_state();
        assert_eq!(inbound.take_probe_outcome(), Some(ProbeOutcome::Invalid));
        assert!(inbound.pending_probe_requests.is_empty());
    }
}

// Phase 1-J27 TEST-ONLY: freshness after a long fencing (OD-J26-6).
#[cfg(test)]
#[path = "j27_freshness_tests.rs"]
mod j27_freshness_tests;

// Phase 1-J27 test-only (audit a02 NB2-1): the start of the open verified-listen window, for the
// Linux composition test. At the end of the file, so no production line moves.
#[cfg(test)]
impl DaemonPeerRuntime {
    pub(crate) fn listen_window_start_for_test(&self) -> Option<Instant> {
        self.listen_window.as_ref().map(|window| window.w_start)
    }
}
