//! Automatic failover trigger (contract A-2 / A-9, final review R6 / R7 / R12).
//!
//! This module only decides *when to ask* for a promotion attempt. It is a
//! pure state machine over plain data: it reads no clock (time is injected as
//! milliseconds), does no I/O, spawns nothing and holds no handle to anything
//! that can mutate a resource, a lease or a fencing incident. A request it
//! produces enters the one existing attempt path
//! (the Daemon's single promotion-attempt entry), which re-evaluates every
//! gate every time; automation is never a gate bypass (INV-AF-1).
//!
//! Two independent trigger classes, mutually exclusive by the peer assessment:
//!
//! * **Fence path** — the peer is `CommunicationLost`. Only after this process
//!   itself observed the peer as `Active` at least twice in a row and then
//!   lost it (F-3), only with `fencing.backend = command`, only after the loss
//!   has lasted `dwell_sec` and the daemon has run `MIN_UPTIME_MS`. Budgets:
//!   `max_fence_actions` fence actions, 8 attempt requests with exponential
//!   spacing, `cycle_timeout_sec` per cycle, 3 cycles per 10 minutes per
//!   process. A fence action is counted from the runtime's own count of the
//!   actions it ran (`FenceActivity`), not inferred from the incident, so an
//!   incident retired before the next poll cannot hide one (Phase 1-J29 B1).
//!   A `FAILED` (not isolated) verdict stops the machine: a live peer is
//!   never fenced again automatically until its authenticated return
//!   (`Healthy`) or a new process, even across a new loss episode and even
//!   if no poll saw the `FAILED` incident (Phase 1-J29 C1).
//! * **Bootstrap path** — the peer is `Healthy` and reports `Standby`. The
//!   preferred node asks after `bootstrap_dwell_sec`, the other after an
//!   additional `bootstrap_defer_sec`. The dwell and the deferral only decide
//!   *whether to try*; they are never part of a safety decision (BAP-9/10).
//!   No fence budget is used.
//!
//! There is no failback: nothing is ever requested while this node is
//! `Active`, and nothing is requested against a healthy Active peer.

use crate::failure_assessment::PeerFailureAssessment;
use crate::state_machine::NodeState;
use std::collections::VecDeque;

/// A daemon younger than this never triggers (no guess from a fresh restart).
pub(crate) const MIN_UPTIME_MS: u64 = 30_000;
/// Attempt requests per cycle.
const ATTEMPT_REQUEST_LIMIT: u32 = 8;
/// Requests rejected before any incident opened, per fence episode.
const PRE_INCIDENT_LIMIT: u32 = 20;
const PRE_INCIDENT_SPACING_MS: u64 = 5_000;
/// Spacing before the n-th request of a cycle (the last value repeats).
const SPACING_MS: [u64; 5] = [2_000, 5_000, 15_000, 30_000, 60_000];
const PROCESS_WINDOW_MS: u64 = 600_000;
const PROCESS_CYCLE_LIMIT: usize = 3;
const NOT_ISOLATED: &str =
    "verification reports the peer is not isolated; it is not fenced again automatically";

/// What the machine was configured with (from `[failover]` and `node.preferred`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AutoConfig {
    pub(crate) enabled: bool,
    pub(crate) preferred: bool,
    pub(crate) dwell_ms: u64,
    pub(crate) bootstrap_dwell_ms: u64,
    pub(crate) bootstrap_defer_ms: u64,
    pub(crate) max_fence_actions: u32,
    pub(crate) cycle_timeout_ms: u64,
}

/// The kind of durable fencing incident, as the trigger needs to see it.
/// (Constructed from the durable image by the Linux runtime only.)
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IncidentKind {
    /// `UNKNOWN` (not attempted, or verification inconclusive).
    Unknown,
    Requested,
    Verifying,
    Confirmed,
    /// `FAILED`: verification showed the peer is not isolated.
    Failed,
}

/// The incident's identity and progress. Only equality is used (change
/// detection); the numbers carry no authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IncidentFacts {
    pub(crate) seq: u64,
    pub(crate) attempt_token: u64,
    pub(crate) kind: IncidentKind,
}

/// What the fencing steps of this process did, counted by the runtime at the
/// step itself (Phase 1-J29). Monotonic within one process, never persisted:
/// a new process starts at zero (A-9). Plain counts, never evidence.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct FenceActivity {
    /// Fence actions started (counted immediately before the bounded action
    /// process is spawned, whatever its outcome).
    pub(crate) actions_run: u64,
    /// `FAILED` (not isolated) verification verdicts committed.
    pub(crate) not_isolated_verdicts: u64,
}

/// The current peer loss episode (`observer session`, `loss generation`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LossEpisode {
    pub(crate) observer_session: String,
    pub(crate) generation: u64,
    /// The local loss evidence is still fresh (Rev5 §10).
    pub(crate) fresh: bool,
}

/// Everything one poll knows (plain data).
#[derive(Debug, Clone)]
pub(crate) struct AutoInputs {
    pub(crate) now_ms: u64,
    pub(crate) uptime_ms: u64,
    pub(crate) running: bool,
    pub(crate) shutdown: bool,
    pub(crate) attempt_in_flight: bool,
    /// Standby, no phase, readiness `Safe`.
    pub(crate) standby_safe: bool,
    pub(crate) node_state: NodeState,
    pub(crate) backend_is_command: bool,
    pub(crate) assessment: PeerFailureAssessment,
    pub(crate) loss: Option<LossEpisode>,
    /// This process observed the peer as `Active` on at least two consecutive
    /// accepted heartbeats, and no non-Active one since (F-3).
    pub(crate) peer_active_confirmed: bool,
    pub(crate) peer_node_state: Option<NodeState>,
    pub(crate) incident: Option<IncidentFacts>,
    /// The runtime's fencing activity counts (B1 / C1).
    pub(crate) activity: FenceActivity,
    pub(crate) bootstrap_session_open: bool,
    pub(crate) bootstrap_session_attested: bool,
}

/// Which entry class a request belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AutoOrigin {
    Fence,
    Bootstrap,
}

impl AutoOrigin {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Fence => "peer lost: fence and take over",
            Self::Bootstrap => "cold start: bootstrap admission",
        }
    }
}

/// The machine's answer for one poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AutoDecision {
    /// Nothing to do and nothing worth saying.
    Idle,
    /// A trigger condition is forming or a cycle is waiting.
    Wait(&'static str),
    /// Ask for one promotion attempt through the single attempt path.
    /// `first` marks the first request of a cycle (for one log line).
    Request { origin: AutoOrigin, first: bool },
    /// The machine stopped for this episode; reported exactly once.
    Exhausted(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Pending {
    /// `FenceActivity::actions_run` when the request was made.
    actions_before: u64,
    could_fence: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Cycle {
    started_ms: u64,
    requests: u32,
    last_request_ms: Option<u64>,
    fence_actions: u32,
    pre_incident_rejects: u32,
    pending: Option<Pending>,
}

impl Cycle {
    fn new(now_ms: u64) -> Self {
        Self {
            started_ms: now_ms,
            requests: 0,
            last_request_ms: None,
            fence_actions: 0,
            pre_incident_rejects: 0,
            pending: None,
        }
    }

    fn spacing_ms(&self) -> u64 {
        let index = (self.requests as usize)
            .saturating_sub(1)
            .min(SPACING_MS.len() - 1);
        SPACING_MS[index]
    }
}

#[derive(Debug, Default)]
struct FenceTrack {
    episode: Option<(String, u64)>,
    dwell_since_ms: Option<u64>,
    cycle: Option<Cycle>,
    latched: bool,
}

#[derive(Debug, Default)]
struct BootstrapTrack {
    since_ms: Option<u64>,
    cycle: Option<Cycle>,
    latched: bool,
}

/// The trigger state machine (in memory only; nothing is persisted).
#[derive(Debug)]
pub(crate) struct AutoFailover {
    config: AutoConfig,
    fence: FenceTrack,
    bootstrap: BootstrapTrack,
    process_cycles: VecDeque<u64>,
    /// A `FAILED` (not isolated) incident stopped the fence path. Unlike the
    /// per-episode latch it survives a new episode that formed without the
    /// peer's authenticated return (a §10.5 invalidation): only `Healthy`
    /// clears it, or a new process (Phase 1-J28 H-2).
    not_isolated_hold: bool,
    /// The last `FenceActivity::not_isolated_verdicts` this machine saw: a
    /// newer count sets the hold even if no poll saw the `FAILED` incident
    /// (Phase 1-J29 C1).
    not_isolated_seen: u64,
}

impl AutoFailover {
    pub(crate) fn new(config: AutoConfig) -> Self {
        Self {
            config,
            fence: FenceTrack::default(),
            bootstrap: BootstrapTrack::default(),
            process_cycles: VecDeque::new(),
            not_isolated_hold: false,
            not_isolated_seen: 0,
        }
    }

    /// One poll. Time moves only through `inputs.now_ms`.
    pub(crate) fn poll(&mut self, inputs: &AutoInputs) -> AutoDecision {
        if !self.config.enabled {
            return AutoDecision::Idle;
        }
        // Whatever the assessment, freshness or cycle: a `FAILED` incident
        // seen once holds the fence path (the incident is retired soon after
        // its episode ends, so it may never be seen again).
        if inputs
            .incident
            .is_some_and(|incident| incident.kind == IncidentKind::Failed)
        {
            self.not_isolated_hold = true;
        }
        // C1: a `FAILED` verdict committed since the last poll holds too,
        // even if the incident was retired before any poll saw it.
        if inputs.activity.not_isolated_verdicts > self.not_isolated_seen {
            self.not_isolated_seen = inputs.activity.not_isolated_verdicts;
            self.not_isolated_hold = true;
        }
        match inputs.assessment {
            PeerFailureAssessment::CommunicationLost => {
                self.reset_bootstrap();
                self.poll_fence(inputs)
            }
            PeerFailureAssessment::Healthy => {
                // The peer's authenticated return ends a `FAILED` hold.
                self.not_isolated_hold = false;
                self.reset_fence();
                self.poll_bootstrap(inputs)
            }
            _ => {
                self.reset_fence();
                self.reset_bootstrap();
                AutoDecision::Idle
            }
        }
    }

    fn common(&self, inputs: &AutoInputs) -> bool {
        inputs.running
            && !inputs.shutdown
            && !inputs.attempt_in_flight
            && inputs.standby_safe
            && inputs.node_state == NodeState::Standby
            && inputs.uptime_ms >= MIN_UPTIME_MS
    }

    fn reset_fence(&mut self) {
        self.fence = FenceTrack::default();
    }

    fn reset_bootstrap(&mut self) {
        // The latch and the cycle belong to one run of "conditions hold".
        self.bootstrap.since_ms = None;
        self.bootstrap.cycle = None;
        self.bootstrap.latched = false;
    }

    fn prune_process_cycles(&mut self, now_ms: u64) {
        while self
            .process_cycles
            .front()
            .is_some_and(|started| now_ms.saturating_sub(*started) >= PROCESS_WINDOW_MS)
        {
            self.process_cycles.pop_front();
        }
    }

    // ---- fence path ------------------------------------------------------

    fn poll_fence(&mut self, inputs: &AutoInputs) -> AutoDecision {
        let key = inputs
            .loss
            .as_ref()
            .map(|loss| (loss.observer_session.clone(), loss.generation));
        if self.fence.episode != key {
            // A new episode (or none): nothing carries over, a latch included.
            self.fence = FenceTrack {
                episode: key,
                ..FenceTrack::default()
            };
        }
        if self.fence.latched {
            return AutoDecision::Idle;
        }
        if self.not_isolated_hold {
            self.fence.latched = true;
            return AutoDecision::Exhausted(NOT_ISOLATED);
        }
        let fresh = inputs.loss.as_ref().is_some_and(|loss| loss.fresh);
        if !self.common(inputs) || !inputs.backend_is_command || !fresh {
            self.fence.dwell_since_ms = None;
            return AutoDecision::Idle;
        }
        if !inputs.peer_active_confirmed {
            // F-3: no guess about a peer this process never saw Active.
            self.fence.dwell_since_ms = None;
            return AutoDecision::Idle;
        }
        let dwell_since = *self.fence.dwell_since_ms.get_or_insert(inputs.now_ms);
        if self.fence.cycle.is_none() {
            if inputs.now_ms.saturating_sub(dwell_since) < self.config.dwell_ms {
                return AutoDecision::Wait("waiting for the loss to last long enough");
            }
            self.prune_process_cycles(inputs.now_ms);
            if self.process_cycles.len() >= PROCESS_CYCLE_LIMIT {
                self.fence.latched = true;
                return AutoDecision::Exhausted("3 automatic cycles in 10 minutes already");
            }
            self.process_cycles.push_back(inputs.now_ms);
            self.fence.cycle = Some(Cycle::new(inputs.now_ms));
        }
        let max_fence = self.config.max_fence_actions;
        let cycle_timeout = self.config.cycle_timeout_ms;
        let cycle = self.fence.cycle.as_mut().expect("cycle exists");

        // Account the previous request now that its attempt has returned:
        // the fence actions the runtime ran since the request (B1), whatever
        // happened to the incident since; none ran is a reject.
        if let Some(pending) = cycle.pending.take() {
            let ran = inputs
                .activity
                .actions_run
                .saturating_sub(pending.actions_before);
            if ran > 0 {
                cycle.fence_actions = cycle
                    .fence_actions
                    .saturating_add(u32::try_from(ran).unwrap_or(u32::MAX));
            } else if pending.could_fence {
                cycle.pre_incident_rejects += 1;
            }
        }
        if inputs.now_ms.saturating_sub(cycle.started_ms) >= cycle_timeout {
            self.fence.latched = true;
            return AutoDecision::Exhausted("the automatic cycle timed out");
        }
        let will_fence = match inputs.incident.map(|incident| incident.kind) {
            Some(IncidentKind::Failed) => {
                self.fence.latched = true;
                self.not_isolated_hold = true;
                return AutoDecision::Exhausted(NOT_ISOLATED);
            }
            Some(IncidentKind::Requested | IncidentKind::Verifying) => {
                return AutoDecision::Wait("fence action in progress; waiting for verification");
            }
            Some(IncidentKind::Confirmed) => false,
            Some(IncidentKind::Unknown) | None => true,
        };
        if will_fence && cycle.fence_actions >= max_fence {
            self.fence.latched = true;
            return AutoDecision::Exhausted("the fence action budget is used up");
        }
        if cycle.pre_incident_rejects >= PRE_INCIDENT_LIMIT {
            self.fence.latched = true;
            return AutoDecision::Exhausted("too many attempts were rejected before a fence");
        }
        if cycle.requests >= ATTEMPT_REQUEST_LIMIT {
            self.fence.latched = true;
            return AutoDecision::Exhausted("the attempt request budget (8) is used up");
        }
        if let Some(last) = cycle.last_request_ms {
            let mut spacing = cycle.spacing_ms();
            if cycle.pre_incident_rejects > 0 {
                spacing = spacing.max(PRE_INCIDENT_SPACING_MS);
            }
            if inputs.now_ms.saturating_sub(last) < spacing {
                return AutoDecision::Wait("spacing between automatic attempts");
            }
        }
        let first = cycle.requests == 0;
        cycle.requests += 1;
        cycle.last_request_ms = Some(inputs.now_ms);
        cycle.pending = Some(Pending {
            actions_before: inputs.activity.actions_run,
            could_fence: will_fence,
        });
        AutoDecision::Request {
            origin: AutoOrigin::Fence,
            first,
        }
    }

    // ---- bootstrap path --------------------------------------------------

    fn poll_bootstrap(&mut self, inputs: &AutoInputs) -> AutoDecision {
        let conditions = self.common(inputs)
            && inputs.peer_node_state == Some(NodeState::Standby)
            && inputs.node_state == NodeState::Standby;
        if !conditions {
            self.reset_bootstrap();
            return AutoDecision::Idle;
        }
        if self.bootstrap.latched {
            return AutoDecision::Idle;
        }
        let since = *self.bootstrap.since_ms.get_or_insert(inputs.now_ms);
        let wait = self.config.bootstrap_dwell_ms
            + if self.config.preferred {
                0
            } else {
                self.config.bootstrap_defer_ms
            };
        if inputs.now_ms.saturating_sub(since) < wait {
            return AutoDecision::Wait("waiting before asking to become Active");
        }
        if self.bootstrap.cycle.is_none() {
            self.bootstrap.cycle = Some(Cycle::new(inputs.now_ms));
        }
        let cycle_timeout = self.config.cycle_timeout_ms;
        let cycle = self.bootstrap.cycle.as_mut().expect("cycle exists");
        cycle.pending = None;
        if inputs.now_ms.saturating_sub(cycle.started_ms) >= cycle_timeout {
            self.bootstrap.latched = true;
            return AutoDecision::Exhausted("the bootstrap cycle timed out");
        }
        if cycle.requests >= ATTEMPT_REQUEST_LIMIT {
            self.bootstrap.latched = true;
            return AutoDecision::Exhausted("the attempt request budget (8) is used up");
        }
        if inputs.bootstrap_session_open && !inputs.bootstrap_session_attested {
            return AutoDecision::Wait("waiting for the peer's probe response");
        }
        if let Some(last) = cycle.last_request_ms
            && inputs.now_ms.saturating_sub(last) < cycle.spacing_ms()
        {
            return AutoDecision::Wait("spacing between automatic attempts");
        }
        let first = cycle.requests == 0;
        cycle.requests += 1;
        cycle.last_request_ms = Some(inputs.now_ms);
        AutoDecision::Request {
            origin: AutoOrigin::Bootstrap,
            first,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEC: u64 = 1_000;

    fn config(preferred: bool) -> AutoConfig {
        AutoConfig {
            enabled: true,
            preferred,
            dwell_ms: 10 * SEC,
            bootstrap_dwell_ms: 20 * SEC,
            bootstrap_defer_ms: 15 * SEC,
            max_fence_actions: 2,
            cycle_timeout_ms: 120 * SEC,
        }
    }

    fn lost(now_ms: u64) -> AutoInputs {
        AutoInputs {
            now_ms,
            uptime_ms: now_ms + 60 * SEC,
            running: true,
            shutdown: false,
            attempt_in_flight: false,
            standby_safe: true,
            node_state: NodeState::Standby,
            backend_is_command: true,
            assessment: PeerFailureAssessment::CommunicationLost,
            loss: Some(LossEpisode {
                observer_session: "s1".into(),
                generation: 1,
                fresh: true,
            }),
            peer_active_confirmed: true,
            peer_node_state: Some(NodeState::Active),
            incident: None,
            activity: FenceActivity::default(),
            bootstrap_session_open: false,
            bootstrap_session_attested: false,
        }
    }

    fn healthy_standby(now_ms: u64) -> AutoInputs {
        AutoInputs {
            assessment: PeerFailureAssessment::Healthy,
            loss: None,
            peer_active_confirmed: false,
            peer_node_state: Some(NodeState::Standby),
            ..lost(now_ms)
        }
    }

    fn incident(kind: IncidentKind, seq: u64, token: u64) -> Option<IncidentFacts> {
        Some(IncidentFacts {
            seq,
            attempt_token: token,
            kind,
        })
    }

    fn is_request(decision: AutoDecision) -> bool {
        matches!(decision, AutoDecision::Request { .. })
    }

    // ---- AT-1..AT-6: every precondition ---------------------------------

    #[test]
    fn nothing_is_requested_unless_every_precondition_holds() {
        let breakers: [(&str, fn(&mut AutoInputs)); 11] = [
            ("not running", |i| i.running = false),
            ("shutdown", |i| i.shutdown = true),
            ("attempt in flight", |i| i.attempt_in_flight = true),
            ("not standby-safe", |i| i.standby_safe = false),
            ("node active", |i| i.node_state = NodeState::Active),
            ("young daemon", |i| i.uptime_ms = MIN_UPTIME_MS - 1),
            ("backend none", |i| i.backend_is_command = false),
            ("loss not fresh", |i| {
                i.loss.as_mut().unwrap().fresh = false;
            }),
            ("no loss episode", |i| i.loss = None),
            ("peer never seen Active (F-3)", |i| {
                i.peer_active_confirmed = false
            }),
            ("peer healthy", |i| {
                i.assessment = PeerFailureAssessment::Healthy
            }),
        ];
        for (name, breaker) in breakers {
            let mut machine = AutoFailover::new(config(true));
            for step in 0..40u64 {
                let mut inputs = lost(step * SEC);
                breaker(&mut inputs);
                // The bootstrap path needs a healthy Standby peer; the
                // "peer healthy" row must not satisfy it either.
                inputs.peer_node_state = Some(NodeState::Active);
                let decision = machine.poll(&inputs);
                assert!(!is_request(decision), "{name} at {step}: {decision:?}");
            }
        }
    }

    #[test]
    fn disabled_machine_is_silent() {
        let mut machine = AutoFailover::new(AutoConfig {
            enabled: false,
            ..config(true)
        });
        for step in 0..200u64 {
            assert_eq!(machine.poll(&lost(step * SEC)), AutoDecision::Idle);
            assert_eq!(
                machine.poll(&healthy_standby(step * SEC)),
                AutoDecision::Idle
            );
        }
    }

    // ---- fence path: dwell, cycle, budgets ------------------------------

    #[test]
    fn fence_request_comes_only_after_the_dwell() {
        let mut machine = AutoFailover::new(config(false));
        for step in 0..10u64 {
            let decision = machine.poll(&lost(step * SEC));
            assert!(
                matches!(decision, AutoDecision::Wait(_)),
                "{step}: {decision:?}"
            );
        }
        assert_eq!(
            machine.poll(&lost(10 * SEC)),
            AutoDecision::Request {
                origin: AutoOrigin::Fence,
                first: true
            }
        );
    }

    #[test]
    fn dwell_restarts_when_a_precondition_drops() {
        let mut machine = AutoFailover::new(config(true));
        assert!(matches!(machine.poll(&lost(0)), AutoDecision::Wait(_)));
        let mut broken = lost(5 * SEC);
        broken.standby_safe = false;
        assert_eq!(machine.poll(&broken), AutoDecision::Idle);
        // 5 s later the first dwell would have expired; the restarted one has not.
        assert!(matches!(
            machine.poll(&lost(11 * SEC)),
            AutoDecision::Wait(_)
        ));
        assert!(is_request(machine.poll(&lost(21 * SEC))));
    }

    #[test]
    fn full_fence_cycle_unknown_then_confirmed() {
        let mut machine = AutoFailover::new(config(true));
        machine.poll(&lost(0));
        // 1st request: no incident yet.
        assert!(is_request(machine.poll(&lost(10 * SEC))));
        // The attempt opened an incident and ran the fence action.
        let mut verifying = lost(11 * SEC);
        verifying.incident = incident(IncidentKind::Verifying, 1, 1);
        verifying.activity.actions_run = 1; // J29: the runtime counted it
        assert!(matches!(machine.poll(&verifying), AutoDecision::Wait(_)));
        // CONFIRMED: ask for the attempt that proceeds (spacing 2 s passed).
        let mut confirmed = lost(14 * SEC);
        confirmed.incident = incident(IncidentKind::Confirmed, 1, 1);
        confirmed.activity.actions_run = 1;
        assert_eq!(
            machine.poll(&confirmed),
            AutoDecision::Request {
                origin: AutoOrigin::Fence,
                first: false
            }
        );
        // The attempt succeeded: this node is Active now. Nothing more.
        let mut active = lost(15 * SEC);
        active.node_state = NodeState::Active;
        active.standby_safe = false;
        assert_eq!(machine.poll(&active), AutoDecision::Idle);
    }

    #[test]
    fn confirmed_incident_is_requested_without_a_fence_budget() {
        let mut machine = AutoFailover::new(AutoConfig {
            max_fence_actions: 1,
            ..config(true)
        });
        machine.poll(&lost(0));
        assert!(is_request(machine.poll(&lost(10 * SEC))));
        let mut verifying = lost(12 * SEC);
        verifying.incident = incident(IncidentKind::Verifying, 1, 1);
        machine.poll(&verifying);
        let mut confirmed = lost(20 * SEC);
        confirmed.incident = incident(IncidentKind::Confirmed, 1, 1);
        assert!(is_request(machine.poll(&confirmed)));
    }

    #[test]
    fn failed_verification_stops_without_refencing() {
        let mut machine = AutoFailover::new(config(true));
        machine.poll(&lost(0));
        assert!(is_request(machine.poll(&lost(10 * SEC))));
        let mut failed = lost(20 * SEC);
        failed.incident = incident(IncidentKind::Failed, 1, 1);
        assert!(matches!(
            machine.poll(&failed),
            AutoDecision::Exhausted(reason) if reason.contains("not isolated")
        ));
        // Latched for the episode: silent, whatever happens next.
        for step in 21..400u64 {
            let mut inputs = lost(step * SEC);
            inputs.incident = incident(IncidentKind::Unknown, 2, 0);
            assert_eq!(machine.poll(&inputs), AutoDecision::Idle, "{step}");
        }
    }

    #[test]
    fn fence_actions_are_capped_by_max_fence_actions() {
        let mut machine = AutoFailover::new(config(true));
        machine.poll(&lost(0));
        let mut now = 10 * SEC;
        let mut token = 0;
        let mut requests = 0;
        let mut exhausted = false;
        for _ in 0..30 {
            let mut inputs = lost(now);
            inputs.incident = if token == 0 {
                None
            } else {
                incident(IncidentKind::Unknown, 1, token)
            };
            // J29: the runtime's count of the fence actions it ran.
            inputs.activity.actions_run = token;
            match machine.poll(&inputs) {
                AutoDecision::Request { .. } => {
                    requests += 1;
                    token += 1; // the attempt ran one fence action
                }
                AutoDecision::Exhausted(reason) => {
                    assert!(reason.contains("fence action budget"), "{reason}");
                    exhausted = true;
                    break;
                }
                _ => {}
            }
            now += 5 * SEC;
        }
        assert!(exhausted);
        assert_eq!(
            requests, 2,
            "exactly max_fence_actions fence-bearing requests"
        );
    }

    #[test]
    fn rejected_attempts_before_an_incident_do_not_use_the_fence_budget() {
        let mut machine = AutoFailover::new(AutoConfig {
            cycle_timeout_ms: 10_000 * SEC,
            ..config(true)
        });
        machine.poll(&lost(0));
        let mut now = 10 * SEC;
        let mut requests = 0;
        let mut stop = None;
        for _ in 0..700 {
            // The incident never opens (e.g. the Witness holder is foreign).
            match machine.poll(&lost(now)) {
                AutoDecision::Request { .. } => requests += 1,
                AutoDecision::Exhausted(reason) => {
                    stop = Some(reason);
                    break;
                }
                _ => {}
            }
            now += SEC;
        }
        // Bounded by the 8-request budget (spacing 2,5,15,30,60 s), never by
        // the fence budget, and never unbounded.
        assert_eq!(requests, 8);
        assert!(stop.unwrap().contains("request budget"));
    }

    #[test]
    fn spacing_between_requests_is_exponential_and_capped() {
        let mut machine = AutoFailover::new(AutoConfig {
            cycle_timeout_ms: 100_000 * SEC,
            ..config(true)
        });
        machine.poll(&lost(0));
        let mut now = 10 * SEC;
        let mut times = Vec::new();
        for _ in 0..2_000 {
            // A CONFIRMED incident whose attempts keep being blocked later
            // (e.g. the Witness lease is not granted): no fence involved.
            let mut inputs = lost(now);
            inputs.incident = incident(IncidentKind::Confirmed, 1, 1);
            if is_request(machine.poll(&inputs)) {
                times.push(now);
            }
            now += SEC;
        }
        let gaps: Vec<u64> = times.windows(2).map(|w| (w[1] - w[0]) / SEC).collect();
        assert_eq!(gaps, [2, 5, 15, 30, 60, 60, 60]);
    }

    #[test]
    fn cycle_timeout_stops_the_cycle() {
        let mut machine = AutoFailover::new(config(true));
        machine.poll(&lost(0));
        assert!(is_request(machine.poll(&lost(10 * SEC))));
        let mut verifying = lost(60 * SEC);
        verifying.incident = incident(IncidentKind::Verifying, 1, 1);
        assert!(matches!(machine.poll(&verifying), AutoDecision::Wait(_)));
        let mut late = lost(131 * SEC);
        late.incident = incident(IncidentKind::Verifying, 1, 1);
        assert!(matches!(
            machine.poll(&late),
            AutoDecision::Exhausted(reason) if reason.contains("timed out")
        ));
    }

    #[test]
    fn at_most_three_cycles_per_ten_minutes_per_process() {
        let mut machine = AutoFailover::new(config(true));
        let mut now = 0;
        let mut started = 0;
        for episode in 1..=4u64 {
            let inputs = |t: u64| {
                let mut i = lost(t);
                i.loss.as_mut().unwrap().generation = episode;
                i
            };
            machine.poll(&inputs(now));
            now += 10 * SEC;
            match machine.poll(&inputs(now)) {
                AutoDecision::Request { first: true, .. } => started += 1,
                AutoDecision::Exhausted(reason) => {
                    assert!(reason.contains("3 automatic cycles"), "{reason}");
                    assert_eq!(episode, 4);
                }
                other => panic!("episode {episode}: {other:?}"),
            }
            // The peer comes back, then is lost again as a new episode.
            now += 30 * SEC;
            machine.poll(&healthy_standby(now));
            now += 5 * SEC;
        }
        assert_eq!(started, 3);
        // The window rolls: 10 minutes after the oldest cycle a new one may start.
        now += 700 * SEC;
        let mut inputs = lost(now);
        inputs.loss.as_mut().unwrap().generation = 9;
        machine.poll(&inputs);
        inputs.now_ms += 10 * SEC;
        assert!(is_request(machine.poll(&inputs)));
    }

    #[test]
    fn peer_return_ends_the_episode_and_clears_a_latch() {
        let mut machine = AutoFailover::new(config(true));
        machine.poll(&lost(0));
        assert!(is_request(machine.poll(&lost(10 * SEC))));
        let mut failed = lost(12 * SEC);
        failed.incident = incident(IncidentKind::Failed, 1, 1);
        assert!(matches!(machine.poll(&failed), AutoDecision::Exhausted(_)));
        // Peer returns: not an episode any more (the bootstrap path may start
        // its own, independent dwell).
        assert!(!is_request(machine.poll(&healthy_standby(20 * SEC))));
        // A fresh episode (new generation) starts a new dwell.
        let mut again = lost(100 * SEC);
        again.loss.as_mut().unwrap().generation = 2;
        assert!(matches!(machine.poll(&again), AutoDecision::Wait(_)));
        again.now_ms += 10 * SEC;
        assert!(is_request(machine.poll(&again)));
    }

    // ---- bootstrap path --------------------------------------------------

    #[test]
    fn preferred_asks_after_dwell_and_the_other_after_the_deferral() {
        for (preferred, expected_s) in [(true, 20u64), (false, 35)] {
            let mut machine = AutoFailover::new(config(preferred));
            let mut first_request = None;
            for step in 0..60u64 {
                if is_request(machine.poll(&healthy_standby(step * SEC))) && first_request.is_none()
                {
                    first_request = Some(step);
                }
            }
            assert_eq!(first_request, Some(expected_s), "preferred={preferred}");
        }
    }

    #[test]
    fn bootstrap_waits_for_the_probe_and_then_asks_again() {
        let mut machine = AutoFailover::new(config(true));
        for step in 0..20u64 {
            machine.poll(&healthy_standby(step * SEC));
        }
        assert!(matches!(
            machine.poll(&healthy_standby(20 * SEC)),
            AutoDecision::Request {
                origin: AutoOrigin::Bootstrap,
                first: true
            }
        ));
        // Attempt 1 anchored; the probe is pending.
        let mut pending = healthy_standby(23 * SEC);
        pending.bootstrap_session_open = true;
        assert!(matches!(machine.poll(&pending), AutoDecision::Wait(_)));
        // The probe was acked; spacing passed: attempt 2.
        let mut attested = healthy_standby(24 * SEC);
        attested.bootstrap_session_open = true;
        attested.bootstrap_session_attested = true;
        assert!(matches!(
            machine.poll(&attested),
            AutoDecision::Request {
                origin: AutoOrigin::Bootstrap,
                first: false
            }
        ));
    }

    #[test]
    fn bootstrap_uses_no_fence_budget_and_no_command_backend() {
        let mut machine = AutoFailover::new(AutoConfig {
            max_fence_actions: 1,
            ..config(true)
        });
        let mut requested = false;
        for step in 0..30u64 {
            let mut inputs = healthy_standby(step * SEC);
            inputs.backend_is_command = false;
            requested |= is_request(machine.poll(&inputs));
        }
        assert!(requested);
    }

    #[test]
    fn bootstrap_never_asks_against_an_active_or_unknown_peer() {
        for peer in [
            Some(NodeState::Active),
            Some(NodeState::Candidate),
            Some(NodeState::RecoveryPending),
            None,
        ] {
            let mut machine = AutoFailover::new(config(true));
            for step in 0..120u64 {
                let mut inputs = healthy_standby(step * SEC);
                inputs.peer_node_state = peer;
                assert!(!is_request(machine.poll(&inputs)), "{peer:?} {step}");
            }
        }
    }

    #[test]
    fn bootstrap_dwell_restarts_when_the_peer_stops_being_standby() {
        let mut machine = AutoFailover::new(config(true));
        for step in 0..15u64 {
            machine.poll(&healthy_standby(step * SEC));
        }
        let mut busy = healthy_standby(15 * SEC);
        busy.peer_node_state = Some(NodeState::Candidate);
        machine.poll(&busy);
        for step in 16..35u64 {
            assert!(
                !is_request(machine.poll(&healthy_standby(step * SEC))),
                "{step}"
            );
        }
        assert!(is_request(machine.poll(&healthy_standby(36 * SEC))));
    }

    #[test]
    fn bootstrap_budget_is_bounded() {
        let mut machine = AutoFailover::new(AutoConfig {
            cycle_timeout_ms: 100_000 * SEC,
            ..config(true)
        });
        let mut requests = 0;
        let mut exhausted = 0;
        for step in 0..3_000u64 {
            match machine.poll(&healthy_standby(step * SEC)) {
                AutoDecision::Request { .. } => requests += 1,
                AutoDecision::Exhausted(_) => exhausted += 1,
                _ => {}
            }
        }
        assert_eq!(requests, 8);
        assert_eq!(exhausted, 1, "reported exactly once");
    }

    #[test]
    fn fence_and_bootstrap_paths_are_mutually_exclusive() {
        let mut machine = AutoFailover::new(config(true));
        for step in 0..120u64 {
            let lost_decision = machine.poll(&lost(step * SEC));
            if let AutoDecision::Request { origin, .. } = lost_decision {
                assert_eq!(origin, AutoOrigin::Fence);
            }
        }
        let mut machine = AutoFailover::new(config(true));
        for step in 0..120u64 {
            if let AutoDecision::Request { origin, .. } = machine.poll(&healthy_standby(step * SEC))
            {
                assert_eq!(origin, AutoOrigin::Bootstrap);
            }
        }
    }

    // ---- module hygiene ---------------------------------------------------

    #[test]
    fn module_is_pure() {
        let source = include_str!("auto_failover.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for forbidden in [
            "Instant",
            "SystemTime",
            "Duration",
            "std::fs",
            "std::process",
            "std::net",
            "thread",
            "sleep",
            "AtomicBool",
            "execute_promotion_attempt",
            "NodeMutationStore",
            "WitnessSession",
            "fencing_backend",
        ] {
            assert!(!production.contains(forbidden), "{forbidden}");
        }
    }
}

// Phase 1-J28 TEST-ONLY: the automatic fence path over long and repeated partitions.
#[cfg(test)]
#[path = "j28_auto_fencing_tests.rs"]
mod j28_auto_fencing_tests;

// Phase 1-J29 TEST-ONLY: fence accounting from the runtime's counts (B1) and the FAILED hold (C1).
#[cfg(test)]
#[path = "j29_auto_fencing_tests.rs"]
mod j29_auto_fencing_tests;
