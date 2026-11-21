//! The two-node decision core (TWO_NODE_SAFETY_MODEL.md §4–§8).
//!
//! A pure state machine: it reads no clock (`now_ms` is injected), performs no I/O except
//! through the [`DurableStore`] it is handed, and asks the runtime for every effect
//! (`Effect`). At most one long operation (fence, verify, acquire, release) is outstanding
//! at a time; its completion comes back as an `Event`.
//!
//! Ownership of an epoch is taken by exactly one of three bases, each written durably
//! (`intent`) **before** any resource action:
//!
//! * **Grant** — the peer is connected and authenticated, Standby with a trusted
//!   ZeroResource observation, and durably recorded a grant of `epoch` to this process
//!   incarnation before answering. One grant per epoch per granter; contention resolves
//!   by node id.
//! * **Fence** — the peer was lost (every link down for `dwell`), this process had seen the
//!   peer possibly owning (two consecutive announcements) or holds an outstanding grant to
//!   it, an independent fence device is declared, and *this process* ran the fence action
//!   and then a verify that observed the peer stopped, for the same fresh operation id,
//!   against the unchanged durable epoch, while the peer stayed lost. The proof is
//!   consumed in the same atomic save as the intent and is never reused.
//! * **Operator** — an operator attested the peer stopped (manual failover), once per
//!   attestation id, only while the peer is lost.
//!
//! Every process start is Standby after a local cleanup (service stopped, VIP absent): a
//! node never resumes an old ownership. Communication loss alone never promotes.

use super::config::{TwoNodePolicy, VERIFY_INTERVAL_MS};
use super::store::{
    Basis, DurableStore, FenceRecord, Grant, Incident, IncidentState, LoadError, OwnershipState,
    PromotionIntent,
};
use super::wire::{ClaimView, Control, GrantView, PeerMessage, PeerState, Role};
use std::collections::VecDeque;

/// A process younger than this never fences automatically (no guess after a restart).
pub const MIN_UPTIME_MS: u64 = 30_000;
/// A claim not granted within this time is abandoned.
pub const CLAIM_TIMEOUT_MS: u64 = 5_000;
/// Pause after a refused or abandoned claim.
pub const CLAIM_BACKOFF_MS: u64 = 3_000;
/// A failed local cleanup is retried after this pause.
pub const CLEANUP_RETRY_MS: u64 = 10_000;
/// Spacing before the n-th further fence attempt of one cycle (the last value repeats).
pub const FENCE_SPACING_MS: [u64; 3] = [5_000, 15_000, 30_000];
/// Automatic fence cycles per process window.
pub const CYCLE_WINDOW_MS: u64 = 600_000;
pub const CYCLE_LIMIT: usize = 3;
/// After a planned shutdown released the resources, the node stays this long as a granter
/// so the connected peer can take over (planned handover), then exits.
pub const HANDOVER_GRACE_MS: u64 = 15_000;
/// After a health failover this node is not eligible to own for this long, so a failing
/// service is not handed back and forth (the peer refuses to hand it back meanwhile).
pub const HEALTH_FAILOVER_COOLDOWN_MS: u64 = 600_000;
/// Operator-requested fence attempts per process (each request is one attempt).
pub const OPERATOR_FENCE_LIMIT: u32 = 10;
const SEEN_MESSAGES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerConfig {
    pub cluster_id: String,
    pub node_id: String,
    pub peer_id: String,
    pub preferred: bool,
    pub policy: TwoNodePolicy,
    pub dwell_ms: u64,
    pub bootstrap_dwell_ms: u64,
    pub bootstrap_defer_ms: u64,
    pub max_fence_actions: u32,
    pub verify_polls: u32,
    pub cycle_timeout_ms: u64,
    pub max_start_failures: u32,
    /// A process younger than this never fences automatically ([`MIN_UPTIME_MS`]; lowered
    /// only by tests).
    pub min_uptime_ms: u64,
}

impl ControllerConfig {
    /// The production values from a validated two-node configuration.
    pub fn from_config(config: &crate::config::Config) -> Option<Self> {
        let two_node = config.two_node.as_ref()?;
        Some(Self {
            cluster_id: config.cluster.id.clone(),
            node_id: config.node.id.clone(),
            peer_id: config.peer.id.clone(),
            preferred: config.node.preferred,
            policy: two_node.policy(config.failover.auto),
            dwell_ms: config.failover.dwell_sec.saturating_mul(1_000),
            bootstrap_dwell_ms: config.failover.bootstrap_dwell_sec.saturating_mul(1_000),
            bootstrap_defer_ms: config.failover.bootstrap_defer_sec.saturating_mul(1_000),
            max_fence_actions: u32::try_from(config.failover.max_fence_actions).unwrap_or(1),
            verify_polls: config
                .fencing
                .as_ref()
                .and_then(|f| f.verify_polls)
                .and_then(|p| u32::try_from(p).ok())
                .unwrap_or(crate::config::DEFAULT_VERIFY_POLLS as u32),
            cycle_timeout_ms: config.failover.cycle_timeout_sec.saturating_mul(1_000),
            max_start_failures: two_node.max_start_failures,
            min_uptime_ms: MIN_UPTIME_MS,
        })
    }
}

/// The fence action's report. Only an acceptance report: it never proves a stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceAction {
    ReportedSuccess,
    ReportedFailure,
    TimedOut,
    Signal,
    SpawnFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The verify observed the peer's OS stopped at the fence device.
    Isolated,
    /// The verify observed the peer running.
    NotIsolated,
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquireResult {
    /// VIP present, service running, health passed.
    Acquired,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Tick,
    /// Which links currently carry fresh, acknowledged, authenticated traffic.
    Links(Vec<bool>),
    /// Whether the peer was recently seen alive (an authenticated `Hello`) with a different
    /// configuration summary. Such a peer is never admitted, and is never taken for lost.
    PeerIncompatible(bool),
    /// `[health] on_failure = "failover"`: the Active's health became unhealthy. Hand over to
    /// the connected peer only through a confirmed release and the peer's claim (never by
    /// fencing). Refused (logged) when the peer cannot take over cooperatively.
    HealthFailover,
    /// The Active's own resources failed locally (a health restart whose stop or start was not
    /// confirmed): release them (a confirmed release gives up the ownership; an unconfirmed
    /// one blocks, keeping it).
    LocalResourceFailure,
    Peer(PeerMessage),
    FenceActionDone {
        op_id: String,
        outcome: FenceAction,
    },
    VerifyDone {
        op_id: String,
        verdict: Verdict,
    },
    AcquireDone(AcquireResult),
    /// `true` only for a trusted observation of service stopped and VIP absent.
    ReleaseDone {
        zero_resource: bool,
    },
    /// SIGUSR1: re-evaluate now, ignoring dwell timers (never a gate bypass).
    PromotionRequest,
    OperatorAttest {
        attestation_id: String,
        target: String,
    },
    OperatorFence {
        target: String,
    },
    Shutdown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    Publish(PeerState),
    Send(Control),
    RunFence {
        incident_seq: u64,
        attempt: u32,
        op_id: String,
    },
    RunVerify {
        incident_seq: u64,
        attempt: u32,
        op_id: String,
        poll: u32,
    },
    Acquire {
        epoch: u64,
    },
    Release {
        reason: &'static str,
    },
    Log(String),
    Exit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Pending {
    None,
    Fence { op_id: String },
    Verify { op_id: String },
    Acquire,
    Release { reason: &'static str },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OutClaim {
    claim_id: String,
    epoch: u64,
    sent_ms: u64,
}

#[derive(Debug, Clone, Default)]
struct PeerTracker {
    state: Option<PeerState>,
    /// Consecutive announcements of the current incarnation (reset by a new incarnation).
    consecutive: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Loss {
    since_ms: u64,
    generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IncidentRuntime {
    seq: u64,
    loss_generation: u64,
    cycle_started_ms: u64,
    actions: u32,
    polls: u32,
    next_ms: u64,
}

pub struct Controller {
    cfg: ControllerConfig,
    incarnation: String,
    started_ms: u64,
    durable: OwnershipState,
    store_ok: bool,
    role: Role,
    zero_resource: Option<bool>,
    pending: Pending,
    links: Vec<bool>,
    peer: PeerTracker,
    loss: Option<Loss>,
    loss_generation: u64,
    claim: Option<OutClaim>,
    next_claim_ms: u64,
    incident_rt: Option<IncidentRuntime>,
    fence_stopped: bool,
    cycles: VecDeque<u64>,
    operator_fences: u32,
    contradiction: bool,
    abort_promotion: bool,
    start_failures: u32,
    count_failure_after_release: bool,
    state_seq: u64,
    last_published: Option<PeerState>,
    bootstrap_since: Option<u64>,
    requested: bool,
    shutdown: bool,
    next_cleanup_ms: u64,
    seen: VecDeque<String>,
    degraded_logged: bool,
    leaving_until: Option<u64>,
    leaving_epoch: u64,
    held_claim: Option<(String, u64, String, u64)>,
    exit_sent: bool,
    retired_incarnations: VecDeque<String>,
    /// The peer is alive with a different configuration (see [`Event::PeerIncompatible`]).
    incompatible: bool,
    /// Not eligible to own until then (after a health failover of this node).
    cooldown_until: Option<u64>,
    /// The time of the last handled event (for eligibility, which has no clock argument).
    now_ms: u64,
}

impl Controller {
    /// A new process. Always starts by releasing local resources (Demoting) and never
    /// resumes an ownership the record names. A missing, corrupt or foreign record puts the
    /// node in cleanup-only mode (it never promotes, claims or fences; it may grant, since
    /// it never owns). A save that fails later has the same effect on new actions; an
    /// ownership already held continues until it is released.
    pub fn start(
        cfg: ControllerConfig,
        incarnation: String,
        loaded: Result<OwnershipState, LoadError>,
        now_ms: u64,
        store: &mut dyn DurableStore,
    ) -> (Self, Vec<Effect>) {
        let mut effects = Vec::new();
        let links = vec![false; cfg.policy.paths.links.max(1)];
        let (durable, store_ok) = match loaded {
            Ok(state) => (state, true),
            Err(error) => {
                effects.push(Effect::Log(format!(
                    "ERROR {error}; cleanup-only mode: this node releases its resources and \
                     never promotes, claims or fences (it may still grant) until an operator \
                     initialises the record"
                )));
                (OwnershipState::fresh(&cfg.cluster_id, &cfg.node_id), false)
            }
        };
        let mut controller = Self {
            cfg,
            incarnation,
            started_ms: now_ms,
            durable,
            store_ok,
            role: Role::Demoting,
            zero_resource: None,
            pending: Pending::None,
            links,
            peer: PeerTracker::default(),
            loss: None,
            loss_generation: 0,
            claim: None,
            next_claim_ms: 0,
            incident_rt: None,
            fence_stopped: false,
            cycles: VecDeque::new(),
            operator_fences: 0,
            contradiction: false,
            abort_promotion: false,
            start_failures: 0,
            count_failure_after_release: false,
            state_seq: 0,
            last_published: None,
            bootstrap_since: None,
            requested: false,
            shutdown: false,
            next_cleanup_ms: 0,
            seen: VecDeque::new(),
            degraded_logged: false,
            leaving_until: None,
            leaving_epoch: 0,
            held_claim: None,
            exit_sent: false,
            retired_incarnations: VecDeque::new(),
            incompatible: false,
            cooldown_until: None,
            now_ms: 0,
        };
        if controller.store_ok {
            let mut next = controller.durable.clone();
            next.starts = next.starts.saturating_add(1);
            if let Some(incident) = next.incident.take() {
                // A fence result never outlives the process that produced it.
                next.push_history(FenceRecord {
                    seq: incident.seq,
                    attempt: incident.attempt,
                    op_id: incident.op_id,
                    target: incident.target,
                    base_epoch: incident.base_epoch,
                    outcome: "retired-restart".into(),
                });
            }
            if next.holding || next.intent.is_some() {
                effects.push(Effect::Log(format!(
                    "WARN the record says this node may hold resources (epoch {}); a restart \
                     never resumes ownership: releasing them first",
                    next.epoch
                )));
            }
            controller.save(next, store, &mut effects);
        }
        effects.push(Effect::Log(format!(
            "INFO two-node controller started (incarnation {}, epoch {}, {})",
            controller.incarnation,
            controller.durable.epoch,
            if controller.store_ok {
                "record ok"
            } else {
                "cleanup-only"
            }
        )));
        controller.pending = Pending::Release { reason: "startup" };
        controller.publish(&mut effects);
        effects.push(Effect::Release { reason: "startup" });
        (controller, effects)
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn durable(&self) -> &OwnershipState {
        &self.durable
    }

    pub fn store_ok(&self) -> bool {
        self.store_ok
    }

    pub fn contradiction(&self) -> bool {
        self.contradiction
    }

    pub fn incarnation(&self) -> &str {
        &self.incarnation
    }

    pub fn peer_connected(&self) -> bool {
        self.links.iter().any(|up| *up)
    }

    pub fn links(&self) -> &[bool] {
        &self.links
    }

    pub fn peer_incompatible(&self) -> bool {
        self.incompatible
    }

    /// An authenticated peer with a different configuration is alive: it is not a loss. An
    /// open loss episode ends and an open fence incident is retired (its result is never
    /// used), exactly as when the peer answers. While it lasts no automatic fence, takeover
    /// or bootstrap starts and operator takeovers are refused. When it ends without a
    /// compatible connection there is no loss episode: the peer was never admitted, so
    /// nothing this process observed can found an automatic takeover.
    fn on_incompatible(
        &mut self,
        now: bool,
        store: &mut dyn DurableStore,
        effects: &mut Vec<Effect>,
    ) {
        if now == self.incompatible {
            return;
        }
        self.incompatible = now;
        if !now {
            return;
        }
        self.loss = None;
        self.bootstrap_since = None;
        if let Some(incident) = self.durable.incident.clone() {
            self.retire_incident("retired-peer-alive-config-mismatch", store, effects);
            effects.push(Effect::Log(format!(
                "INFO the peer is alive with another configuration: fence incident {} retired; \
                 its result is never used",
                incident.seq
            )));
        }
    }

    pub fn handle(
        &mut self,
        now_ms: u64,
        event: Event,
        store: &mut dyn DurableStore,
    ) -> Vec<Effect> {
        let mut effects = Vec::new();
        self.now_ms = now_ms;
        match event {
            Event::Tick => {}
            Event::HealthFailover => self.on_health_failover(now_ms, &mut effects),
            Event::LocalResourceFailure => self.on_local_failure(&mut effects),
            Event::Links(up) => self.on_links(now_ms, up, store, &mut effects),
            Event::PeerIncompatible(now) => self.on_incompatible(now, store, &mut effects),
            Event::Peer(message) => self.on_peer(now_ms, message, store, &mut effects),
            Event::FenceActionDone { op_id, outcome } => {
                self.on_fence_action(now_ms, &op_id, outcome, store, &mut effects)
            }
            Event::VerifyDone { op_id, verdict } => {
                self.on_verify(now_ms, &op_id, verdict, store, &mut effects)
            }
            Event::AcquireDone(result) => self.on_acquire(result, &mut effects),
            Event::ReleaseDone { zero_resource } => {
                self.on_release(now_ms, zero_resource, store, &mut effects)
            }
            Event::PromotionRequest => {
                self.requested = true;
                effects.push(Effect::Log(
                    "INFO promotion request: re-evaluating every gate now".into(),
                ));
            }
            Event::OperatorAttest {
                attestation_id,
                target,
            } => self.on_operator_attest(now_ms, &attestation_id, &target, store, &mut effects),
            Event::OperatorFence { target } => {
                self.on_operator_fence(now_ms, &target, store, &mut effects)
            }
            Event::Shutdown => self.on_shutdown(&mut effects),
        }
        self.evaluate(now_ms, store, &mut effects);
        // A promotion request means "evaluate now": it never lingers to trigger a later
        // automatic action (with the gates as they are then).
        self.requested = false;
        self.publish(&mut effects);
        if effects.contains(&Effect::Exit) {
            self.exit_sent = true;
        }
        effects
    }

    // ---- durable writes ---------------------------------------------------------------

    /// One atomic durable write. On failure the in-memory record is unchanged and the node
    /// drops to cleanup-only mode (a write it cannot make is never assumed made).
    fn save(
        &mut self,
        next: OwnershipState,
        store: &mut dyn DurableStore,
        effects: &mut Vec<Effect>,
    ) -> bool {
        if !self.store_ok {
            return false;
        }
        match store.save(&next) {
            Ok(()) => {
                self.durable = next;
                true
            }
            Err(error) => {
                self.store_ok = false;
                effects.push(Effect::Log(format!(
                    "ERROR durable save failed ({error}); cleanup-only mode from now on"
                )));
                false
            }
        }
    }

    /// A knowledge-only update (epoch learning, grant resolution): applied in memory in
    /// every mode, persisted when the record is usable. It never enables a promotion.
    fn remember(
        &mut self,
        next: OwnershipState,
        store: &mut dyn DurableStore,
        effects: &mut Vec<Effect>,
    ) {
        if self.store_ok {
            if !self.save(next.clone(), store, effects) {
                self.durable = next;
            }
        } else {
            self.durable = next;
        }
    }

    // ---- announcements ----------------------------------------------------------------

    fn eligible(&self) -> bool {
        self.store_ok
            && !self.contradiction
            && self.start_failures < self.cfg.max_start_failures
            && self.cooldown_until.is_none_or(|until| self.now_ms >= until)
    }

    /// See [`Event::HealthFailover`]. The gates: this node is Active with nothing pending, the
    /// peer is connected (compatible), a clean Standby, eligible and without an outstanding
    /// grant. Then this node releases (Demoting); only a confirmed release makes it a clean
    /// Standby that grants the peer's claim, and it stays ineligible for
    /// [`HEALTH_FAILOVER_COOLDOWN_MS`].
    fn on_health_failover(&mut self, now_ms: u64, effects: &mut Vec<Effect>) {
        let refusal = if self.role != Role::Active || self.pending != Pending::None {
            Some("this node is not an Active with nothing pending")
        } else if self.shutdown {
            Some("this node is shutting down")
        } else if self.incompatible {
            Some("the peer is alive with another configuration")
        } else if !self.peer_connected() {
            Some("the peer is not connected (a health failure never founds a fence)")
        } else if !self.cfg.policy.auto_bootstrap {
            Some(
                "automatic cooperative start is off (failover.auto = false): the peer would not claim",
            )
        } else {
            match self.peer_clean_standby() {
                None => Some("the peer is not a clean Standby"),
                Some(peer) if !peer.eligible => Some(
                    "the peer is not eligible to own (for example after its own health failover)",
                ),
                Some(peer) if peer.grant.is_some() || peer.claim.is_some() => {
                    Some("the peer has a grant or a claim outstanding")
                }
                Some(peer) if peer.leaving => Some("the peer is shutting down"),
                Some(_) => None,
            }
        };
        if let Some(why) = refusal {
            effects.push(Effect::Log(format!(
                "WARN health failover not started: {why}; staying as is (warn only)"
            )));
            return;
        }
        self.cooldown_until = Some(now_ms.saturating_add(HEALTH_FAILOVER_COOLDOWN_MS));
        self.role = Role::Demoting;
        self.pending = Pending::Release {
            reason: "health-failover",
        };
        effects.push(Effect::Log(format!(
            "WARN health failover: releasing the resources of epoch {} so the connected peer \
             can take over (it claims only after the release is confirmed); this node is not \
             eligible to own for {} s",
            self.durable.epoch,
            HEALTH_FAILOVER_COOLDOWN_MS / 1000
        )));
        effects.push(Effect::Release {
            reason: "health-failover",
        });
    }

    fn on_local_failure(&mut self, effects: &mut Vec<Effect>) {
        if self.role != Role::Active || self.pending != Pending::None {
            return;
        }
        self.count_failure_after_release = true;
        // The service failed here: do not take it straight back (the peer may own it).
        self.cooldown_until = Some(self.now_ms.saturating_add(HEALTH_FAILOVER_COOLDOWN_MS));
        self.role = Role::Demoting;
        self.pending = Pending::Release {
            reason: "local-failure",
        };
        effects.push(Effect::Log(format!(
            "WARN local resource failure while Active; releasing (a confirmed release gives up \
             the ownership, an unconfirmed one blocks); this node is not eligible to own for \
             {} s",
            HEALTH_FAILOVER_COOLDOWN_MS / 1000
        )));
        effects.push(Effect::Release {
            reason: "local-failure",
        });
    }

    fn current_state(&self) -> PeerState {
        PeerState {
            incarnation: self.incarnation.clone(),
            state_seq: self.state_seq,
            role: self.role,
            epoch: self.durable.epoch,
            owner: self.durable.owner.clone(),
            zero_resource: self.zero_resource == Some(true),
            eligible: self.eligible(),
            grant: self.durable.grant.as_ref().map(|grant| GrantView {
                claim_id: grant.claim_id.clone(),
                epoch: grant.epoch,
                grantee: grant.grantee.clone(),
            }),
            claim: self.claim.as_ref().map(|claim| ClaimView {
                claim_id: claim.claim_id.clone(),
                epoch: claim.epoch,
            }),
            leaving: self.leaving_until.is_some(),
        }
    }

    fn publish(&mut self, effects: &mut Vec<Effect>) {
        let mut state = self.current_state();
        if let Some(last) = &self.last_published {
            let mut comparable = state.clone();
            comparable.state_seq = last.state_seq;
            if &comparable == last {
                return;
            }
        }
        self.state_seq = self.state_seq.saturating_add(1);
        state.state_seq = self.state_seq;
        self.last_published = Some(state.clone());
        effects.push(Effect::Publish(state));
    }

    // ---- links and peer observations --------------------------------------------------

    fn on_links(
        &mut self,
        now_ms: u64,
        up: Vec<bool>,
        store: &mut dyn DurableStore,
        effects: &mut Vec<Effect>,
    ) {
        let was_connected = self.peer_connected();
        if up.len() == self.links.len() {
            self.links = up;
        } else {
            effects.push(Effect::Log(
                "ERROR link status of the wrong size ignored".into(),
            ));
            return;
        }
        let connected = self.peer_connected();
        let all = self.links.iter().all(|link| *link);
        if connected && !all && self.links.len() > 1 {
            if !self.degraded_logged {
                self.degraded_logged = true;
                effects.push(Effect::Log(format!(
                    "WARN peer path degraded: links up {:?}; no action (a single path loss \
                     never triggers fencing)",
                    self.links
                )));
            }
        } else if all {
            self.degraded_logged = false;
        }
        if was_connected && !connected && self.incompatible {
            // The peer is alive with another configuration: not a loss episode.
            effects.push(Effect::Log(
                "WARN peer links down while the peer is alive with another configuration; \
                 not a peer loss"
                    .into(),
            ));
        } else if was_connected && !connected {
            self.loss_generation = self.loss_generation.saturating_add(1);
            self.loss = Some(Loss {
                since_ms: now_ms,
                generation: self.loss_generation,
            });
            effects.push(Effect::Log(format!(
                "WARN peer lost on every link (episode {}); a loss is not a stop: no \
                 promotion without a grant or a confirmed fence",
                self.loss_generation
            )));
        } else if connected && (self.loss.is_some() || !was_connected) {
            // A return after a loss, or the first authenticated contact of this process.
            self.loss = None;
            self.peer_returned(store, effects);
        } else if !connected && self.loss.is_none() && was_connected == connected {
            // Never connected since start: there is no loss episode (wait for the peer).
        }
    }

    /// The peer is reachable again: an open incident is retired (its proof, if any, is not
    /// used), and the `not isolated` stop is lifted (authenticated return).
    fn peer_returned(&mut self, store: &mut dyn DurableStore, effects: &mut Vec<Effect>) {
        self.fence_stopped = false;
        if self.durable.fence_stopped {
            let mut next = self.durable.clone();
            next.fence_stopped = false;
            self.remember(next, store, effects);
        }
        if let Some(incident) = self.durable.incident.clone() {
            let outcome = if incident.state == IncidentState::Confirmed {
                "retired-peer-returned-after-confirm"
            } else {
                "retired-peer-returned"
            };
            self.retire_incident(outcome, store, effects);
            effects.push(Effect::Log(format!(
                "INFO peer reachable again: fence incident {} retired ({outcome}); its result \
                 is never used",
                incident.seq
            )));
        }
    }

    fn retire_incident(
        &mut self,
        outcome: &str,
        store: &mut dyn DurableStore,
        effects: &mut Vec<Effect>,
    ) {
        self.incident_rt = None;
        if matches!(self.pending, Pending::Fence { .. } | Pending::Verify { .. }) {
            // The running step's result is ignored when it returns (no matching incident).
        }
        let Some(incident) = self.durable.incident.clone() else {
            return;
        };
        let mut next = self.durable.clone();
        next.incident = None;
        next.push_history(FenceRecord {
            seq: incident.seq,
            attempt: incident.attempt,
            op_id: incident.op_id,
            target: incident.target,
            base_epoch: incident.base_epoch,
            outcome: outcome.to_string(),
        });
        if !self.save(next, store, effects) {
            // The incident stays open in memory only; cleanup-only mode refuses all use.
            self.durable.incident = None;
        }
    }

    fn on_peer(
        &mut self,
        now_ms: u64,
        message: PeerMessage,
        store: &mut dyn DurableStore,
        effects: &mut Vec<Effect>,
    ) {
        match message {
            PeerMessage::Announce(state) => self.on_announce(now_ms, state, store, effects),
            PeerMessage::Control {
                msg_id,
                from_incarnation,
                body,
            } => {
                if self.seen.contains(&msg_id) {
                    return;
                }
                self.seen.push_back(msg_id);
                if self.seen.len() > SEEN_MESSAGES {
                    self.seen.pop_front();
                }
                let current = self
                    .peer
                    .state
                    .as_ref()
                    .is_some_and(|state| state.incarnation == from_incarnation);
                if !current {
                    effects.push(Effect::Log(
                        "WARN control message from a peer incarnation not yet announced; ignored"
                            .into(),
                    ));
                    if let Control::Claim { claim_id, .. } = body {
                        effects.push(Effect::Send(Control::Refuse {
                            claim_id,
                            reason: "unknown-incarnation".into(),
                        }));
                    }
                    return;
                }
                self.on_control(now_ms, body, store, effects);
            }
        }
    }

    fn on_announce(
        &mut self,
        now_ms: u64,
        state: PeerState,
        store: &mut dyn DurableStore,
        effects: &mut Vec<Effect>,
    ) {
        match &self.peer.state {
            Some(last) if last.incarnation == state.incarnation => {
                if state.state_seq < last.state_seq {
                    return;
                }
                // Every announcement counts (periodic repeats included); an older one is
                // ignored and a repeat changes nothing else.
                self.peer.consecutive = self.peer.consecutive.saturating_add(1);
                if state.state_seq == last.state_seq {
                    return;
                }
            }
            Some(last) => {
                if self.retired_incarnations.contains(&state.incarnation) {
                    return; // A late announcement of an older process.
                }
                self.retired_incarnations
                    .push_back(last.incarnation.clone());
                if self.retired_incarnations.len() > 8 {
                    self.retired_incarnations.pop_front();
                }
                self.peer.consecutive = 1;
                effects.push(Effect::Log(format!(
                    "INFO peer process restarted (incarnation {})",
                    state.incarnation
                )));
            }
            None => self.peer.consecutive = 1,
        }
        self.peer.state = Some(state.clone());
        if self.durable.incident.is_some() {
            // The peer answers: whatever the link view says, it is not stopped (or it
            // restarted). The incident and any result of it are retired, never used.
            self.peer_returned(store, effects);
        }
        if let Some((claim_id, epoch, incarnation, at)) = self.held_claim.take()
            && now_ms.saturating_sub(at) <= CLAIM_TIMEOUT_MS
            && state.incarnation == incarnation
            && state.claim.as_ref().is_some_and(|c| c.claim_id == claim_id)
        {
            self.on_claim(now_ms, claim_id, epoch, incarnation, store, effects);
        }

        // Ownership contradiction checks (a holding node relinquishes; safety first).
        let mine = self.durable.epoch;
        let peer_holding = matches!(state.role, Role::Active | Role::Promoting);
        if matches!(self.role, Role::Active | Role::Promoting) {
            let peer_owns_same_or_higher =
                state.owner.as_deref() == Some(&self.cfg.peer_id) && state.epoch >= mine;
            if peer_holding && (state.epoch > mine || peer_owns_same_or_higher) {
                self.contradict(
                    format!(
                        "peer is {} at epoch {} while this node holds epoch {mine}",
                        state.role.as_str(),
                        state.epoch
                    ),
                    effects,
                );
            } else if peer_holding {
                effects.push(Effect::Log(format!(
                    "WARN peer is {} at the older epoch {}; it must relinquish (this node \
                     holds epoch {mine})",
                    state.role.as_str(),
                    state.epoch
                )));
            } else if state.epoch > mine && !(state.role == Role::Standby && state.zero_resource) {
                self.contradict(
                    format!(
                        "peer reports the newer epoch {} with resources possibly held",
                        state.epoch
                    ),
                    effects,
                );
            }
        } else if peer_holding
            && self.role == Role::Standby
            && self.durable.owner.as_deref() == Some(&self.cfg.node_id)
            && state.epoch < mine
            && self.zero_resource == Some(true)
        {
            effects.push(Effect::Log(format!(
                "WARN peer is {} at epoch {} below this node's released epoch {mine}",
                state.role.as_str(),
                state.epoch
            )));
        }

        // Epoch learning (knowledge only, never authority).
        if state.epoch > self.durable.epoch && !matches!(self.role, Role::Active | Role::Promoting)
        {
            let mut next = self.durable.clone();
            next.epoch = state.epoch;
            next.owner = state.owner.clone();
            self.remember(next, store, effects);
        }

        // Grant resolution (this node granted the peer).
        if let Some(grant) = self.durable.grant.clone()
            && Self::grant_resolved(&grant, &state)
        {
            let mut next = self.durable.clone();
            next.grant = None;
            self.remember(next, store, effects);
            {
                effects.push(Effect::Log(format!(
                    "INFO grant of epoch {} to the peer resolved (peer {} at epoch {})",
                    grant.epoch,
                    state.role.as_str(),
                    state.epoch
                )));
            }
        }
        let _ = now_ms;
    }

    /// Whether an announcement shows that the grantee can no longer act on `grant` without
    /// it being visible: it owns (or acquires) at or above the granted epoch, it restarted
    /// and finished its startup cleanup, or a later announcement of the same incarnation
    /// shows it Standby with zero resources and without the claim.
    fn grant_resolved(grant: &Grant, state: &PeerState) -> bool {
        if matches!(state.role, Role::Active | Role::Promoting) && state.epoch >= grant.epoch {
            return true;
        }
        let standby_clean = state.role == Role::Standby && state.zero_resource;
        if state.incarnation != grant.grantee_incarnation {
            return standby_clean;
        }
        standby_clean
            && state.state_seq > grant.claim_state_seq
            && state.claim.as_ref().map(|c| c.claim_id.as_str()) != Some(grant.claim_id.as_str())
    }

    fn contradict(&mut self, why: String, effects: &mut Vec<Effect>) {
        if !self.contradiction {
            effects.push(Effect::Log(format!(
                "ERROR ownership contradiction: {why}; relinquishing local resources, no \
                 automatic promotion, grant, claim or fence in this process (operator \
                 intervention)"
            )));
        }
        self.contradiction = true;
        match (&self.pending, self.role) {
            (Pending::Acquire, _) => self.abort_promotion = true,
            (Pending::None, Role::Active | Role::Promoting) => {
                self.role = Role::Demoting;
                self.pending = Pending::Release {
                    reason: "contradiction",
                };
                effects.push(Effect::Release {
                    reason: "contradiction",
                });
            }
            _ => {}
        }
    }

    // ---- claim / grant ----------------------------------------------------------------

    fn clean_standby(&self) -> bool {
        self.role == Role::Standby
            && self.zero_resource == Some(true)
            && self.store_ok
            && !self.contradiction
            && !self.shutdown
            && self.pending == Pending::None
            && self.durable.incident.is_none()
            && !self.durable.holding
    }

    fn peer_clean_standby(&self) -> Option<&PeerState> {
        if !self.peer_connected() {
            return None;
        }
        self.peer
            .state
            .as_ref()
            .filter(|s| s.role == Role::Standby && s.zero_resource)
    }

    fn on_control(
        &mut self,
        now_ms: u64,
        body: Control,
        store: &mut dyn DurableStore,
        effects: &mut Vec<Effect>,
    ) {
        match body {
            Control::Claim {
                claim_id,
                epoch,
                claimant_incarnation,
            } => self.on_claim(
                now_ms,
                claim_id,
                epoch,
                claimant_incarnation,
                store,
                effects,
            ),
            Control::Grant {
                claim_id,
                epoch,
                grantee_incarnation,
            } => self.on_grant(now_ms, claim_id, epoch, grantee_incarnation, store, effects),
            Control::Refuse { claim_id, reason } => {
                if self.claim.as_ref().is_some_and(|c| c.claim_id == claim_id) {
                    self.claim = None;
                    self.next_claim_ms = now_ms.saturating_add(CLAIM_BACKOFF_MS);
                    effects.push(Effect::Log(format!(
                        "INFO claim refused by the peer ({reason})"
                    )));
                }
            }
            Control::Abandon { claim_id } => {
                if let Some(grant) = self.durable.grant.clone()
                    && grant.claim_id == claim_id
                {
                    let mut next = self.durable.clone();
                    next.grant = None;
                    self.remember(next, store, effects);
                    {
                        effects.push(Effect::Log(format!(
                            "INFO the peer abandoned claim of epoch {}; grant cleared",
                            grant.epoch
                        )));
                    }
                }
            }
        }
    }

    fn on_claim(
        &mut self,
        now_ms: u64,
        claim_id: String,
        epoch: u64,
        claimant_incarnation: String,
        store: &mut dyn DurableStore,
        effects: &mut Vec<Effect>,
    ) {
        let refuse = |reason: &str, effects: &mut Vec<Effect>| {
            effects.push(Effect::Send(Control::Refuse {
                claim_id: claim_id.clone(),
                reason: reason.to_string(),
            }));
        };
        // Idempotent re-send of an existing grant for the same claim.
        if let Some(grant) = &self.durable.grant {
            if grant.claim_id == claim_id && grant.epoch == epoch {
                effects.push(Effect::Send(Control::Grant {
                    claim_id,
                    epoch,
                    grantee_incarnation: grant.grantee_incarnation.clone(),
                }));
            } else {
                refuse("grant-outstanding", effects);
            }
            return;
        }
        // A cleanup-only node may grant: it never promotes, so its grant needs no durable
        // record to keep it from owning (the record is unavailable to it).
        let granter_ready = self.role == Role::Standby
            && self.zero_resource == Some(true)
            && !self.contradiction
            && (!self.shutdown || self.leaving_until.is_some())
            && self.pending == Pending::None
            && self.durable.incident.is_none()
            && !self.durable.holding;
        if !granter_ready {
            refuse("not-clean-standby", effects);
            return;
        }
        let Some(peer) = self.peer_clean_standby() else {
            refuse("claimant-not-clean", effects);
            return;
        };
        let claim_seq = peer.state_seq;
        if peer.incarnation != claimant_incarnation
            || peer.claim.as_ref().map(|c| c.claim_id.as_str()) != Some(claim_id.as_str())
        {
            // The claim message may overtake the announcement that carries it: hold it
            // and decide when that announcement arrives (or let the claimant time out).
            if peer.incarnation == claimant_incarnation {
                self.held_claim = Some((claim_id, epoch, claimant_incarnation, now_ms));
            } else {
                refuse("claim-not-announced", effects);
            }
            return;
        }
        if epoch <= self.durable.epoch || epoch <= self.durable.granted_high_water {
            refuse("stale-epoch", effects);
            return;
        }
        if let Some(mine) = self.claim.clone() {
            // Contention: the lower node id keeps its claim.
            if self.cfg.node_id < self.cfg.peer_id {
                refuse("contending", effects);
                return;
            }
            self.claim = None;
            self.next_claim_ms = now_ms.saturating_add(CLAIM_BACKOFF_MS);
            effects.push(Effect::Send(Control::Abandon {
                claim_id: mine.claim_id,
            }));
        }
        let mut next = self.durable.clone();
        next.grant = Some(Grant {
            claim_id: claim_id.clone(),
            epoch,
            grantee: self.cfg.peer_id.clone(),
            grantee_incarnation: claimant_incarnation.clone(),
            claim_state_seq: claim_seq,
        });
        next.granted_high_water = epoch;
        next.epoch = epoch;
        next.owner = Some(self.cfg.peer_id.clone());
        if !self.store_ok {
            self.durable = next;
            effects.push(Effect::Log(
                "INFO cleanup-only node grants without a durable record (it never owns)".into(),
            ));
        } else if !self.save(next, store, effects) {
            refuse("store", effects);
            return;
        }
        effects.push(Effect::Log(format!(
            "INFO granted epoch {epoch} to the peer (durable before the answer)"
        )));
        effects.push(Effect::Send(Control::Grant {
            claim_id,
            epoch,
            grantee_incarnation: claimant_incarnation,
        }));
    }

    fn on_grant(
        &mut self,
        now_ms: u64,
        claim_id: String,
        epoch: u64,
        grantee_incarnation: String,
        store: &mut dyn DurableStore,
        effects: &mut Vec<Effect>,
    ) {
        let Some(claim) = self.claim.clone() else {
            return; // A late grant of an abandoned claim is ignored.
        };
        if claim.claim_id != claim_id || claim.epoch != epoch {
            return;
        }
        self.claim = None;
        let fresh = now_ms.saturating_sub(claim.sent_ms) <= CLAIM_TIMEOUT_MS;
        // The granter announces the granted epoch (owner: this node) as soon as it is
        // durable, so that knowledge may arrive before the grant itself.
        let epoch_fits = epoch > self.durable.epoch
            || (epoch == self.durable.epoch
                && self.durable.owner.as_deref() == Some(self.cfg.node_id.as_str()));
        let usable = fresh
            && grantee_incarnation == self.incarnation
            && self.clean_standby()
            && self.durable.grant.is_none()
            && epoch_fits;
        if !usable {
            effects.push(Effect::Send(Control::Abandon { claim_id }));
            self.next_claim_ms = now_ms.saturating_add(CLAIM_BACKOFF_MS);
            effects.push(Effect::Log(
                "INFO a grant arrived but a gate no longer holds; abandoned".into(),
            ));
            return;
        }
        self.begin_promotion(
            epoch,
            Basis::Grant {
                claim_id,
                granter: self.cfg.peer_id.clone(),
            },
            store,
            effects,
        );
    }

    fn maybe_claim(&mut self, now_ms: u64, effects: &mut Vec<Effect>) {
        if let Some(claim) = &self.claim {
            if now_ms.saturating_sub(claim.sent_ms) > CLAIM_TIMEOUT_MS {
                let claim_id = claim.claim_id.clone();
                self.claim = None;
                self.next_claim_ms = now_ms.saturating_add(CLAIM_BACKOFF_MS);
                effects.push(Effect::Send(Control::Abandon { claim_id }));
                effects.push(Effect::Log("INFO claim timed out; abandoned".into()));
            }
            return;
        }
        let ready = self.clean_standby()
            && !self.incompatible
            && self.durable.grant.is_none()
            && self.eligible()
            && now_ms >= self.next_claim_ms;
        let peer = self.peer_clean_standby().cloned();
        let peer_ready = peer.as_ref().is_some_and(|p| {
            p.grant.is_none() && (p.claim.is_none() || self.cfg.node_id < self.cfg.peer_id)
        });
        if !(ready && peer_ready) {
            self.bootstrap_since = None;
            return;
        }
        let since = *self.bootstrap_since.get_or_insert(now_ms);
        let mut dwell = self.cfg.bootstrap_dwell_ms;
        if !self.cfg.preferred {
            dwell = dwell.saturating_add(self.cfg.bootstrap_defer_ms);
        }
        let handover = peer.as_ref().is_some_and(|p| p.leaving);
        let automatic =
            self.cfg.policy.auto_bootstrap && (handover || now_ms.saturating_sub(since) >= dwell);
        if !(automatic || self.requested) {
            return;
        }
        let peer = peer.expect("checked");
        let Some(epoch) = self.durable.epoch.max(peer.epoch).checked_add(1) else {
            effects.push(Effect::Log("ERROR epoch exhausted; no claim".into()));
            return;
        };
        let Some(claim_id) = crate::node_mutation::generate_uuid() else {
            effects.push(Effect::Log("ERROR no randomness for a claim id".into()));
            return;
        };
        self.requested = false;
        self.claim = Some(OutClaim {
            claim_id: claim_id.clone(),
            epoch,
            sent_ms: now_ms,
        });
        // Publish the claim before sending it (the granter requires it announced).
        self.publish(effects);
        effects.push(Effect::Log(format!(
            "INFO claiming epoch {epoch} from the connected peer (both Standby, zero resources)"
        )));
        effects.push(Effect::Send(Control::Claim {
            claim_id,
            epoch,
            claimant_incarnation: self.incarnation.clone(),
        }));
    }

    // ---- promotion and resources --------------------------------------------------------

    fn begin_promotion(
        &mut self,
        epoch: u64,
        basis: Basis,
        store: &mut dyn DurableStore,
        effects: &mut Vec<Effect>,
    ) {
        let mut next = self.durable.clone();
        next.epoch = epoch;
        next.owner = Some(self.cfg.node_id.clone());
        next.holding = true;
        next.intent = Some(PromotionIntent {
            epoch,
            basis: basis.clone(),
        });
        match &basis {
            Basis::Fence {
                incident_seq,
                op_id,
            } => {
                let Some(incident) = next.incident.take() else {
                    effects.push(Effect::Log("ERROR fence basis without incident".into()));
                    return;
                };
                if incident.seq != *incident_seq || &incident.op_id != op_id {
                    effects.push(Effect::Log("ERROR fence basis does not match".into()));
                    return;
                }
                next.push_history(FenceRecord {
                    seq: incident.seq,
                    attempt: incident.attempt,
                    op_id: incident.op_id,
                    target: incident.target,
                    base_epoch: incident.base_epoch,
                    outcome: "confirmed-consumed".into(),
                });
            }
            Basis::Operator { attestation_id } => next.consume_attestation(attestation_id),
            Basis::Grant { .. } => {}
        }
        self.incident_rt = None;
        if !self.save(next, store, effects) {
            effects.push(Effect::Log(
                "ERROR the ownership intent could not be written; no resource action".into(),
            ));
            return;
        }
        self.role = Role::Promoting;
        self.zero_resource = Some(false);
        self.abort_promotion = false;
        self.pending = Pending::Acquire;
        effects.push(Effect::Log(format!(
            "INFO promoting at epoch {epoch} ({}); the intent is durable before any resource \
             action",
            describe_basis(&basis)
        )));
        self.publish(effects);
        effects.push(Effect::Acquire { epoch });
    }

    fn on_acquire(&mut self, result: AcquireResult, effects: &mut Vec<Effect>) {
        if self.pending != Pending::Acquire {
            return;
        }
        self.pending = Pending::None;
        if result == AcquireResult::Acquired && !self.abort_promotion && !self.shutdown {
            self.role = Role::Active;
            self.start_failures = 0;
            effects.push(Effect::Log(format!(
                "INFO active at epoch {} (internal promotion complete; not a proof of service \
                 reachability)",
                self.durable.epoch
            )));
            return;
        }
        let reason = if self.abort_promotion {
            "promotion-aborted"
        } else if self.shutdown {
            "shutdown"
        } else {
            self.count_failure_after_release = true;
            "acquire-failed"
        };
        self.abort_promotion = false;
        self.role = Role::Demoting;
        self.pending = Pending::Release { reason };
        effects.push(Effect::Log(format!(
            "WARN promotion not completed ({reason}); releasing"
        )));
        effects.push(Effect::Release { reason });
    }

    fn on_release(
        &mut self,
        now_ms: u64,
        zero_resource: bool,
        store: &mut dyn DurableStore,
        effects: &mut Vec<Effect>,
    ) {
        let Pending::Release { reason } = self.pending.clone() else {
            return;
        };
        self.pending = Pending::None;
        if self.count_failure_after_release {
            self.count_failure_after_release = false;
            self.start_failures = self.start_failures.saturating_add(1);
            if self.start_failures >= self.cfg.max_start_failures {
                effects.push(Effect::Log(format!(
                    "WARN {} failed promotions: this node is not eligible to own until it is \
                     restarted",
                    self.start_failures
                )));
            }
        }
        if !zero_resource {
            self.zero_resource = Some(false);
            self.role = Role::Blocked;
            self.next_cleanup_ms = now_ms.saturating_add(CLEANUP_RETRY_MS);
            effects.push(Effect::Log(format!(
                "ERROR local cleanup ({reason}) could not confirm service stopped and VIP \
                 absent; Blocked (retrying; the peer never takes over cooperatively while \
                 this node may hold resources)"
            )));
            if self.shutdown {
                effects.push(Effect::Log(
                    "ERROR shutting down with resources possibly held".into(),
                ));
                effects.push(Effect::Exit);
            }
            return;
        }
        self.zero_resource = Some(true);
        if self.store_ok
            && (self.durable.holding
                || self.durable.intent.is_some()
                || self.durable.owner.as_deref() == Some(&self.cfg.node_id))
        {
            let mut next = self.durable.clone();
            next.holding = false;
            next.intent = None;
            if next.owner.as_deref() == Some(&self.cfg.node_id) {
                next.owner = None;
            }
            if self.save(next, store, effects) {
                effects.push(Effect::Log(format!(
                    "INFO ownership of epoch {} released (service stopped and VIP absent \
                     confirmed, then recorded)",
                    self.durable.epoch
                )));
            }
        }
        self.role = Role::Standby;
        if !self.shutdown && reason == "health-failover" && self.peer_connected() {
            // The peer sees `leaving` and claims at once; this node grants as a clean Standby.
            self.leaving_until = Some(now_ms.saturating_add(HANDOVER_GRACE_MS));
            self.leaving_epoch = self.durable.epoch;
            effects.push(Effect::Log(
                "INFO resources released for the health failover; the connected peer may take \
                 over"
                    .into(),
            ));
        }
        if self.shutdown {
            if (reason == "shutdown" || reason == "health-failover")
                && self.peer_connected()
                && self.leaving_until.is_none()
            {
                self.leaving_until = Some(now_ms.saturating_add(HANDOVER_GRACE_MS));
                self.leaving_epoch = self.durable.epoch;
                effects.push(Effect::Log(format!(
                    "INFO resources released for shutdown; staying up to {} s so the \
                     connected peer can take over",
                    HANDOVER_GRACE_MS / 1000
                )));
            } else {
                effects.push(Effect::Exit);
            }
        }
    }

    fn on_shutdown(&mut self, effects: &mut Vec<Effect>) {
        self.shutdown = true;
        if let Some(claim) = self.claim.take() {
            effects.push(Effect::Send(Control::Abandon {
                claim_id: claim.claim_id,
            }));
        }
        if self.pending != Pending::None {
            if self.pending == Pending::Acquire {
                self.abort_promotion = true;
            }
            return; // Completes after the running operation.
        }
        match self.role {
            Role::Standby if self.zero_resource == Some(true) => effects.push(Effect::Exit),
            _ => {
                self.role = Role::Demoting;
                self.pending = Pending::Release { reason: "shutdown" };
                effects.push(Effect::Release { reason: "shutdown" });
            }
        }
    }

    // ---- fence takeover -----------------------------------------------------------------

    fn may_own_peer(&self) -> bool {
        let observed = self.peer.state.as_ref().is_some_and(|state| {
            self.peer.consecutive >= 2 && !(state.role == Role::Standby && state.zero_resource)
        });
        observed || self.durable.grant.is_some()
    }

    fn takeover_base_ready(&self) -> bool {
        self.clean_standby() && self.claim.is_none() && self.loss.is_some() && !self.incompatible
    }

    /// Operator requests need only that the peer is not reachable now (a node that came
    /// back alone after a total outage never saw the peer in this process). The loss
    /// episode then starts at the request: a later return of the peer retires anything
    /// opened under it, exactly as for an automatic incident.
    fn operator_base_ready(&mut self, now_ms: u64) -> bool {
        if self.peer_connected()
            || self.incompatible
            || !(self.clean_standby() && self.claim.is_none())
        {
            return false;
        }
        if self.loss.is_none() {
            self.loss_generation = self.loss_generation.saturating_add(1);
            self.loss = Some(Loss {
                since_ms: now_ms,
                generation: self.loss_generation,
            });
        }
        true
    }

    fn maybe_open_incident(
        &mut self,
        now_ms: u64,
        operator: bool,
        store: &mut dyn DurableStore,
        effects: &mut Vec<Effect>,
    ) -> bool {
        let Some(loss) = self.loss else { return false };
        let peer_incarnation = self.peer.state.as_ref().map(|s| s.incarnation.clone());
        let Some(op_id) = crate::node_mutation::generate_uuid() else {
            effects.push(Effect::Log(
                "ERROR no randomness for a fence operation id".into(),
            ));
            return false;
        };
        let Some(seq) = self.durable.incident_seq.checked_add(1) else {
            return false;
        };
        let mut next = self.durable.clone();
        next.incident_seq = seq;
        next.incident = Some(Incident {
            seq,
            target: self.cfg.peer_id.clone(),
            base_epoch: self.durable.epoch,
            peer_incarnation,
            attempt: 1,
            op_id: op_id.clone(),
            state: IncidentState::Requested,
            operator,
        });
        if !self.save(next, store, effects) {
            return false;
        }
        self.incident_rt = Some(IncidentRuntime {
            seq,
            loss_generation: loss.generation,
            cycle_started_ms: now_ms,
            actions: 1,
            polls: 0,
            next_ms: now_ms,
        });
        if !operator {
            self.cycles.push_back(now_ms);
        }
        self.pending = Pending::Fence {
            op_id: op_id.clone(),
        };
        effects.push(Effect::Log(format!(
            "WARN fencing the peer (incident {seq}, attempt 1, op {op_id}, {}); a fence \
             request accepted is not a stop: promotion waits for verify",
            if operator {
                "operator request"
            } else {
                "automatic"
            }
        )));
        effects.push(Effect::RunFence {
            incident_seq: seq,
            attempt: 1,
            op_id,
        });
        true
    }

    fn maybe_takeover(
        &mut self,
        now_ms: u64,
        store: &mut dyn DurableStore,
        effects: &mut Vec<Effect>,
    ) {
        if !self.takeover_base_ready() || self.durable.incident.is_some() {
            return;
        }
        let policy = &self.cfg.policy;
        if !policy.auto_takeover
            || self.durable.fence_stopped
            || !self.eligible()
            || !self.may_own_peer()
        {
            // An ineligible node never fences: it could not own afterwards.
            return;
        }
        let loss = self.loss.expect("checked");
        let dwell_done = now_ms.saturating_sub(loss.since_ms) >= self.cfg.dwell_ms;
        let uptime_done = now_ms.saturating_sub(self.started_ms) >= self.cfg.min_uptime_ms;
        if !(uptime_done && (dwell_done || self.requested)) {
            return;
        }
        while self
            .cycles
            .front()
            .is_some_and(|t| now_ms.saturating_sub(*t) >= CYCLE_WINDOW_MS)
        {
            self.cycles.pop_front();
        }
        if self.cycles.len() >= CYCLE_LIMIT {
            return;
        }
        self.requested = false;
        self.maybe_open_incident(now_ms, false, store, effects);
    }

    fn on_operator_fence(
        &mut self,
        now_ms: u64,
        target: &str,
        store: &mut dyn DurableStore,
        effects: &mut Vec<Effect>,
    ) {
        let refusal = if target != self.cfg.peer_id {
            Some("the target is not the configured peer")
        } else if !self.cfg.policy.operator_fence_takeover {
            Some("no independent fence device is declared")
        } else if self.incompatible {
            Some("the peer is alive with another configuration (config mismatch)")
        } else if self.peer_connected() {
            Some("the peer is connected (use a cooperative switchover)")
        } else if !self.operator_base_ready(now_ms) {
            Some("this node is not a clean Standby with a lost peer")
        } else if !self.eligible() {
            Some("this node is not eligible to own")
        } else if self.operator_fences >= OPERATOR_FENCE_LIMIT {
            Some("the per-process limit of operator fence requests is reached")
        } else if self.durable.incident.is_some() {
            Some("a fence incident is already open")
        } else {
            None
        };
        if let Some(why) = refusal {
            effects.push(Effect::Log(format!(
                "WARN operator fence request refused: {why}"
            )));
            return;
        }
        self.operator_fences += 1;
        self.maybe_open_incident(now_ms, true, store, effects);
    }

    fn on_operator_attest(
        &mut self,
        now_ms: u64,
        attestation_id: &str,
        target: &str,
        store: &mut dyn DurableStore,
        effects: &mut Vec<Effect>,
    ) {
        let refusal = if target != self.cfg.peer_id {
            Some("the target is not the configured peer")
        } else if !crate::node_mutation::is_canonical_uuid_v4(attestation_id) {
            Some("the attestation id is not a canonical UUIDv4")
        } else if self
            .durable
            .consumed_attestations
            .iter()
            .any(|id| id == attestation_id)
        {
            Some("the attestation was already used")
        } else if self.incompatible {
            Some("the peer is alive with another configuration (config mismatch)")
        } else if self.peer_connected() {
            Some("the peer is connected (use a cooperative switchover)")
        } else if self.durable.incident.is_some() || !self.operator_base_ready(now_ms) {
            Some("this node is not a clean Standby with a lost peer")
        } else if !self.eligible() {
            Some("this node is not eligible to own")
        } else {
            None
        };
        if let Some(why) = refusal {
            effects.push(Effect::Log(format!(
                "WARN operator attestation refused: {why}"
            )));
            return;
        }
        let Some(epoch) = self.durable.epoch.checked_add(1) else {
            return;
        };
        effects.push(Effect::Log(format!(
            "WARN operator attests the peer is stopped (attestation {attestation_id}); manual \
             failover at epoch {epoch} on the operator's responsibility"
        )));
        self.begin_promotion(
            epoch,
            Basis::Operator {
                attestation_id: attestation_id.to_string(),
            },
            store,
            effects,
        );
    }

    fn incident_matches(&self, op_id: &str) -> Option<Incident> {
        self.durable
            .incident
            .clone()
            .filter(|incident| incident.op_id == op_id)
    }

    fn on_fence_action(
        &mut self,
        now_ms: u64,
        op_id: &str,
        outcome: FenceAction,
        store: &mut dyn DurableStore,
        effects: &mut Vec<Effect>,
    ) {
        if self.pending
            == (Pending::Fence {
                op_id: op_id.to_string(),
            })
        {
            self.pending = Pending::None;
        }
        let Some(incident) = self.incident_matches(op_id) else {
            effects.push(Effect::Log(format!(
                "INFO fence action result for op {op_id} ignored (no matching open incident)"
            )));
            return;
        };
        if incident.state != IncidentState::Requested {
            return;
        }
        let mut next = self.durable.clone();
        let mut updated = incident.clone();
        if outcome == FenceAction::SpawnFailed {
            updated.state = IncidentState::Unknown {
                reason: "spawn-failed".into(),
            };
        } else {
            updated.state = IncidentState::Verifying {
                action: format!("{outcome:?}"),
            };
        }
        next.incident = Some(updated);
        if !self.save(next, store, effects) {
            self.incident_rt = None;
            return;
        }
        if let Some(rt) = self.incident_rt.as_mut() {
            rt.polls = 0;
            rt.next_ms = now_ms;
        }
        effects.push(Effect::Log(format!(
            "INFO fence action of op {op_id} returned {outcome:?} (an acceptance report only)"
        )));
        if outcome == FenceAction::SpawnFailed {
            self.schedule_next_attempt(now_ms, store, effects);
        }
    }

    fn on_verify(
        &mut self,
        now_ms: u64,
        op_id: &str,
        verdict: Verdict,
        store: &mut dyn DurableStore,
        effects: &mut Vec<Effect>,
    ) {
        if self.pending
            == (Pending::Verify {
                op_id: op_id.to_string(),
            })
        {
            self.pending = Pending::None;
        }
        let Some(incident) = self.incident_matches(op_id) else {
            effects.push(Effect::Log(format!(
                "INFO verify result for op {op_id} ignored (stale: no matching open incident)"
            )));
            return;
        };
        if !matches!(incident.state, IncidentState::Verifying { .. }) {
            return;
        }
        match verdict {
            Verdict::Isolated => {
                let mut next = self.durable.clone();
                let mut confirmed = incident.clone();
                confirmed.state = IncidentState::Confirmed;
                next.incident = Some(confirmed);
                if !self.save(next, store, effects) {
                    return;
                }
                effects.push(Effect::Log(format!(
                    "INFO verify observed the peer stopped (incident {}, op {op_id})",
                    incident.seq
                )));
                self.promote_from_confirmed(now_ms, &incident, store, effects);
            }
            Verdict::NotIsolated => {
                self.fence_stopped = true;
                let mut next = self.durable.clone();
                next.fence_stopped = true;
                self.remember(next, store, effects);
                self.retire_incident("not-isolated", store, effects);
                effects.push(Effect::Log(format!(
                    "ERROR verify reports the peer is NOT stopped (op {op_id}); it is not \
                     fenced again automatically until it returns; no promotion"
                )));
            }
            Verdict::Inconclusive => {
                let polls = self
                    .incident_rt
                    .as_ref()
                    .map_or(u32::MAX, |rt| rt.polls + 1);
                if let Some(rt) = self.incident_rt.as_mut() {
                    rt.polls = polls;
                    rt.next_ms = now_ms.saturating_add(VERIFY_INTERVAL_MS);
                }
                if polls >= self.cfg.verify_polls {
                    let mut next = self.durable.clone();
                    let mut unknown = incident.clone();
                    unknown.state = IncidentState::Unknown {
                        reason: "verify-inconclusive".into(),
                    };
                    next.incident = Some(unknown);
                    if self.save(next, store, effects) {
                        effects.push(Effect::Log(format!(
                            "WARN verification of op {op_id} inconclusive after {polls} polls; \
                             no promotion"
                        )));
                        self.schedule_next_attempt(now_ms, store, effects);
                    }
                }
            }
        }
    }

    /// The only fence-based promotion: the incident is Confirmed by this process, for the
    /// current operation, against the unchanged durable epoch, while the same loss episode
    /// is still open (the peer never came back), and the node is a clean Standby.
    fn promote_from_confirmed(
        &mut self,
        _now_ms: u64,
        incident: &Incident,
        store: &mut dyn DurableStore,
        effects: &mut Vec<Effect>,
    ) {
        let same_episode = match (&self.incident_rt, &self.loss) {
            (Some(rt), Some(loss)) => {
                rt.seq == incident.seq && rt.loss_generation == loss.generation
            }
            _ => false,
        };
        let refusal = if !same_episode {
            Some("the loss episode changed (the peer was reachable meanwhile)")
        } else if incident.base_epoch != self.durable.epoch {
            Some("the durable epoch changed since the incident opened")
        } else if incident.target != self.cfg.peer_id {
            Some("the incident targets another node")
        } else if self.durable.op_id_recorded(&incident.op_id) {
            Some("the operation id was already used")
        } else if !(self.role == Role::Standby
            && self.zero_resource == Some(true)
            && !self.contradiction
            && !self.shutdown
            && self.store_ok
            && self.claim.is_none())
        {
            Some("this node is not a clean Standby")
        } else if !self.eligible() {
            Some("this node is not eligible to own")
        } else {
            None
        };
        if let Some(why) = refusal {
            self.retire_incident("confirmed-unused", store, effects);
            effects.push(Effect::Log(format!(
                "WARN confirmed fence of op {} not used: {why}",
                incident.op_id
            )));
            return;
        }
        let Some(epoch) = incident.base_epoch.checked_add(1) else {
            return;
        };
        self.begin_promotion(
            epoch,
            Basis::Fence {
                incident_seq: incident.seq,
                op_id: incident.op_id.clone(),
            },
            store,
            effects,
        );
    }

    /// The next attempt of the cycle (fresh operation id), or the end of the cycle.
    fn schedule_next_attempt(
        &mut self,
        now_ms: u64,
        store: &mut dyn DurableStore,
        effects: &mut Vec<Effect>,
    ) {
        let Some(rt) = self.incident_rt.as_mut() else {
            return;
        };
        let operator = self.durable.incident.as_ref().is_some_and(|i| i.operator);
        if operator || rt.actions >= self.cfg.max_fence_actions {
            let outcome = if operator {
                "operator-attempt-unresolved"
            } else {
                "budget-exhausted"
            };
            self.retire_incident(outcome, store, effects);
            effects.push(Effect::Log(format!(
                "WARN fence cycle ended without a confirmed stop ({outcome}); no promotion \
                 (operator intervention, or SIGUSR1 / an operator request for another attempt)"
            )));
            return;
        }
        let spacing = FENCE_SPACING_MS[(rt.actions as usize - 1).min(FENCE_SPACING_MS.len() - 1)];
        rt.next_ms = now_ms.saturating_add(spacing);
    }

    fn drive_incident(
        &mut self,
        now_ms: u64,
        store: &mut dyn DurableStore,
        effects: &mut Vec<Effect>,
    ) {
        let Some(incident) = self.durable.incident.clone() else {
            return;
        };
        let Some(rt) = self.incident_rt.clone() else {
            // An incident without runtime state is not driven (it cannot have been opened
            // by this process): retire it.
            self.retire_incident("retired-no-runtime", store, effects);
            return;
        };
        if self.loss.map(|loss| loss.generation) != Some(rt.loss_generation) {
            self.retire_incident("retired-episode-changed", store, effects);
            return;
        }
        if !incident.operator
            && now_ms.saturating_sub(rt.cycle_started_ms) > self.cfg.cycle_timeout_ms
        {
            self.retire_incident("cycle-timeout", store, effects);
            effects.push(Effect::Log(
                "WARN fence cycle timed out without a confirmed stop; no promotion".into(),
            ));
            return;
        }
        if now_ms < rt.next_ms {
            return;
        }
        match incident.state {
            IncidentState::Verifying { .. } => {
                let poll = rt.polls + 1;
                self.pending = Pending::Verify {
                    op_id: incident.op_id.clone(),
                };
                effects.push(Effect::RunVerify {
                    incident_seq: incident.seq,
                    attempt: incident.attempt,
                    op_id: incident.op_id,
                    poll,
                });
            }
            IncidentState::Unknown { .. } => {
                let Some(op_id) = crate::node_mutation::generate_uuid() else {
                    return;
                };
                let attempt = incident.attempt.saturating_add(1);
                let mut next = self.durable.clone();
                let mut renewed = incident.clone();
                renewed.attempt = attempt;
                renewed.op_id = op_id.clone();
                renewed.state = IncidentState::Requested;
                next.push_history(FenceRecord {
                    seq: incident.seq,
                    attempt: incident.attempt,
                    op_id: incident.op_id.clone(),
                    target: incident.target.clone(),
                    base_epoch: incident.base_epoch,
                    outcome: "superseded".into(),
                });
                next.incident = Some(renewed);
                if !self.save(next, store, effects) {
                    return;
                }
                if let Some(rt) = self.incident_rt.as_mut() {
                    rt.actions += 1;
                    rt.polls = 0;
                }
                self.pending = Pending::Fence {
                    op_id: op_id.clone(),
                };
                effects.push(Effect::Log(format!(
                    "WARN fence attempt {attempt} of incident {} (op {op_id})",
                    incident.seq
                )));
                effects.push(Effect::RunFence {
                    incident_seq: incident.seq,
                    attempt,
                    op_id,
                });
            }
            // Requested is driven by the running action; Confirmed is consumed or retired
            // immediately; Failed is retired.
            _ => {}
        }
    }

    // ---- evaluation ---------------------------------------------------------------------

    fn evaluate(&mut self, now_ms: u64, store: &mut dyn DurableStore, effects: &mut Vec<Effect>) {
        if self.pending != Pending::None {
            return;
        }
        if self.shutdown {
            if let Some(until) = self.leaving_until {
                let taken_over = self.peer.state.as_ref().is_some_and(|p| {
                    matches!(p.role, Role::Active | Role::Promoting) && p.epoch > self.leaving_epoch
                });
                if now_ms >= until || taken_over || !self.peer_connected() {
                    self.leaving_until = None;
                    effects.push(Effect::Log(if taken_over {
                        "INFO the peer took over; exiting".to_string()
                    } else {
                        "INFO handover window over; exiting".to_string()
                    }));
                    effects.push(Effect::Exit);
                }
            } else if !self.exit_sent
                && self.role == Role::Standby
                && self.zero_resource == Some(true)
            {
                // A shutdown requested during a fence or verify step ends after it.
                effects.push(Effect::Exit);
            }
            return;
        }
        if let Some(until) = self.leaving_until {
            // A health-failover handover window (not a shutdown): it ends on time, when the
            // peer took over, or when the peer is gone.
            let taken_over = self.peer.state.as_ref().is_some_and(|p| {
                matches!(p.role, Role::Active | Role::Promoting) && p.epoch > self.leaving_epoch
            });
            if now_ms >= until || taken_over || !self.peer_connected() {
                self.leaving_until = None;
            }
        }
        if self.role == Role::Blocked && now_ms >= self.next_cleanup_ms {
            self.role = Role::Demoting;
            self.pending = Pending::Release { reason: "retry" };
            effects.push(Effect::Release { reason: "retry" });
            return;
        }
        if self.role != Role::Standby {
            return;
        }
        if !self.store_ok && (self.durable.incident.is_some() || self.incident_rt.is_some()) {
            // A record that cannot be written ends every fence incident (cleanup-only).
            self.durable.incident = None;
            self.incident_rt = None;
            effects.push(Effect::Log(
                "WARN fence incident abandoned: the record cannot be written".into(),
            ));
            return;
        }
        if self.durable.incident.is_some() {
            if self.requested
                && matches!(
                    self.durable.incident.as_ref().map(|i| &i.state),
                    Some(IncidentState::Unknown { .. })
                )
                && let Some(rt) = self.incident_rt.as_mut()
            {
                rt.next_ms = now_ms;
                self.requested = false;
            }
            self.drive_incident(now_ms, store, effects);
            return;
        }
        if self.peer_connected() {
            self.maybe_claim(now_ms, effects);
        } else {
            self.bootstrap_since = None;
            if self.claim.is_some() {
                self.maybe_claim(now_ms, effects);
            }
            self.maybe_takeover(now_ms, store, effects);
        }
    }
}

fn describe_basis(basis: &Basis) -> String {
    match basis {
        Basis::Grant { granter, .. } => format!("granted by {granter}"),
        Basis::Fence {
            incident_seq,
            op_id,
        } => {
            format!("confirmed fence of incident {incident_seq}, op {op_id}")
        }
        Basis::Operator { attestation_id } => format!("operator attestation {attestation_id}"),
    }
}
