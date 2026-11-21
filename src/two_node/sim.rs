//! Deterministic simulation of two two-node controllers (test-only).
//!
//! The world models what the controllers cannot see: the physical resources of each node
//! (VIP, service), power and process state, per-segment and per-direction link state with
//! FIFO delivery, an independent fence device and the durable records. Every step checks
//! the safety invariants:
//!
//! * S-1 at most one node holds the VIP;
//! * S-2 at most one node runs the service (one writer);
//! * S-3 at most one controller is Active;
//! * S-4 an epoch is owned (Promoting/Active) by at most one node ever;
//! * S-5 at the moment a node starts promoting, the other node holds no resource.
//!
//! Assumptions that the safety model states explicitly are modelled as such: the fence
//! device is truthful (verify says `isolated` only while the target is powered off) unless a
//! test deliberately breaks it, and an operator attests a peer stopped only when it is.

use super::config::{FencingDevice, FencingPath, LINK_TIMEOUT_MS, PathAssessment, TwoNodePolicy};
use super::controller::{
    AcquireResult, Controller, ControllerConfig, Effect, Event, FenceAction, Verdict,
};
use super::store::{DurableStore, LoadError, OwnershipState};
use super::wire::{Control, PeerMessage, PeerState, Role};
use std::collections::{BTreeMap, VecDeque};

pub const STEP_MS: u64 = 100;
const TICK_EVERY: u64 = 2;
const ANNOUNCE_EVERY_MS: u64 = 500;
const FENCE_ACTION_MS: u64 = 1_500;
const VERIFY_MS: u64 = 500;
const ACQUIRE_MS: u64 = 700;
const RELEASE_MS: u64 = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceMode {
    /// Powers the target off and reports success.
    Works,
    /// Reports failure, the target keeps running.
    Fails,
    /// The action times out; the target keeps running.
    TimesOut,
    /// Reports success but the target keeps running (accepted is not stopped).
    AcceptsWithoutStop,
    /// Reports success; the target powers off only after `delay` (ACPI-like).
    SlowStop { delay_ms: u64 },
    /// Verify is always inconclusive (and the action does nothing).
    Unreachable,
}

#[derive(Debug, Default, Clone)]
pub struct MemStore {
    pub bytes: Option<Vec<u8>>,
    pub fail_saves: bool,
    pub saves: u64,
}

impl DurableStore for MemStore {
    fn save(&mut self, state: &OwnershipState) -> Result<(), String> {
        if self.fail_saves {
            return Err("injected save failure".into());
        }
        self.bytes = Some(state.encode()?);
        self.saves += 1;
        Ok(())
    }
}

#[derive(Debug, Clone)]
enum Op {
    Fence { op_id: String, outcome: FenceAction },
    Verify { op_id: String },
    Acquire,
    Release,
}

struct Node {
    id: String,
    ctl: Option<Controller>,
    powered: bool,
    vip: bool,
    service: bool,
    store: MemStore,
    starts: u64,
    op: Option<(Op, u64)>,
    published: Option<PeerState>,
    acquire_fails: bool,
    release_fails: bool,
    sent_seq: Vec<u64>,
    last_announce_ms: Vec<u64>,
    /// When the current process started: a link is fresh for it only after that.
    process_started_ms: u64,
}

#[derive(Debug, Clone)]
enum Msg {
    Announce(PeerState),
    Control {
        msg_id: String,
        incarnation: String,
        body: Control,
    },
}

#[derive(Debug, Clone, Copy)]
pub struct Direction {
    pub a_to_b: bool,
    pub b_to_a: bool,
}

pub struct World {
    pub now_ms: u64,
    nodes: [Node; 2],
    pub links: Vec<Direction>,
    last_bidirectional: Vec<u64>,
    queues: Vec<[VecDeque<(u64, Msg)>; 2]>,
    pub fence_mode: FenceMode,
    pub fence_path_shared: bool,
    pending_power_off: Vec<(u64, usize)>,
    epoch_owner: BTreeMap<u64, String>,
    pub violations: Vec<String>,
    pub logs: Vec<String>,
    policy: TwoNodePolicy,
    msg_counter: u64,
    pub promotions: Vec<(u64, String, u64)>,
    pub verbose: bool,
    pub tweak: Option<fn(&mut ControllerConfig)>,
    /// Set once a durable record was corrupted, a save failed or an operator request was
    /// used: epoch uniqueness (S-4) is then not checked (S-6 still is).
    pub knowledge_lost: bool,
    /// Delivery order of one batch: `false` = the runtime's order (the latest announcement,
    /// then the control messages); `true` = control messages first (another link may be
    /// faster). Both orders must be safe.
    pub controls_first: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct Layout {
    pub segments: usize,
    pub fencing: bool,
    pub fence_path_shared: bool,
    pub auto: bool,
}

pub fn policy_for(layout: Layout) -> TwoNodePolicy {
    TwoNodePolicy {
        paths: PathAssessment {
            segments: layout.segments,
            interfaces: layout.segments,
            links: layout.segments,
        },
        fencing_device: if layout.fencing {
            FencingDevice::Independent
        } else {
            FencingDevice::None
        },
        fencing_path: layout.fencing.then_some(if layout.fence_path_shared {
            FencingPath::Shared
        } else {
            FencingPath::Separate
        }),
        auto_takeover: layout.auto && layout.fencing,
        auto_bootstrap: layout.auto,
        operator_fence_takeover: layout.fencing,
        operator_attested_takeover: true,
    }
}

fn cfg(node: &str, peer: &str, preferred: bool, policy: &TwoNodePolicy) -> ControllerConfig {
    ControllerConfig {
        cluster_id: "sim".into(),
        node_id: node.into(),
        peer_id: peer.into(),
        preferred,
        policy: policy.clone(),
        dwell_ms: 10_000,
        bootstrap_dwell_ms: 4_000,
        bootstrap_defer_ms: 3_000,
        max_fence_actions: 2,
        verify_polls: 10,
        cycle_timeout_ms: 120_000,
        max_start_failures: 3,
        min_uptime_ms: crate::two_node::controller::MIN_UPTIME_MS,
    }
}

impl World {
    pub fn new(layout: Layout) -> Self {
        let policy = policy_for(layout);
        let make = |id: &str| {
            let mut store = MemStore::default();
            store.save(&OwnershipState::fresh("sim", id)).unwrap();
            Node {
                id: id.into(),
                ctl: None,
                powered: false,
                vip: false,
                service: false,
                store,
                starts: 0,
                op: None,
                published: None,
                acquire_fails: false,
                release_fails: false,
                sent_seq: vec![0; layout.segments],
                last_announce_ms: vec![0; layout.segments],
                process_started_ms: 0,
            }
        };
        Self {
            now_ms: 0,
            nodes: [make("node-a"), make("node-b")],
            links: vec![
                Direction {
                    a_to_b: true,
                    b_to_a: true
                };
                layout.segments
            ],
            last_bidirectional: vec![0; layout.segments],
            queues: (0..layout.segments)
                .map(|_| [VecDeque::new(), VecDeque::new()])
                .collect(),
            fence_mode: FenceMode::Works,
            fence_path_shared: layout.fence_path_shared,
            pending_power_off: Vec::new(),
            epoch_owner: BTreeMap::new(),
            violations: Vec::new(),
            logs: Vec::new(),
            policy,
            msg_counter: 0,
            promotions: Vec::new(),
            verbose: false,
            tweak: None,
            knowledge_lost: false,
            controls_first: false,
        }
    }

    pub fn power_on(&mut self, i: usize) {
        if self.nodes[i].powered {
            return;
        }
        self.nodes[i].powered = true;
        self.start_process(i);
    }

    /// Power loss (or a completed fence): the OS stops, resources vanish with it.
    pub fn power_off(&mut self, i: usize) {
        let node = &mut self.nodes[i];
        node.powered = false;
        node.ctl = None;
        node.vip = false;
        node.service = false;
        node.op = None;
        node.published = None;
    }

    /// Only the Mikagami process dies: the service and the VIP stay.
    pub fn kill_process(&mut self, i: usize) {
        let node = &mut self.nodes[i];
        node.ctl = None;
        node.op = None;
        node.published = None;
    }

    pub fn start_process(&mut self, i: usize) {
        if !self.nodes[i].powered || self.nodes[i].ctl.is_some() {
            return;
        }
        let peer = 1 - i;
        let (id, peer_id) = (self.nodes[i].id.clone(), self.nodes[peer].id.clone());
        let loaded = match &self.nodes[i].store.bytes {
            None => Err(LoadError::Missing),
            Some(bytes) => OwnershipState::decode(bytes, "sim", &id),
        };
        self.nodes[i].starts += 1;
        self.nodes[i].process_started_ms = self.now_ms;
        let incarnation = format!("{id}-inc{}", self.nodes[i].starts);
        let mut config = cfg(&id, &peer_id, i == 0, &self.policy);
        if let Some(tweak) = self.tweak {
            tweak(&mut config);
        }
        let now = self.now_ms;
        let node = &mut self.nodes[i];
        let (ctl, effects) = Controller::start(config, incarnation, loaded, now, &mut node.store);
        node.ctl = Some(ctl);
        node.sent_seq.iter_mut().for_each(|s| *s = 0);
        self.apply(i, effects);
    }

    /// An operator re-initialises the record (`two-node init --replace-corrupt`).
    pub fn nodes_store_reset(&mut self, i: usize, id: &str) {
        self.nodes[i].store.bytes = Some(OwnershipState::fresh("sim", id).encode().unwrap());
    }

    pub fn corrupt_store(&mut self, i: usize) {
        self.knowledge_lost = true;
        self.nodes[i].store.bytes = Some(b"garbage".to_vec());
    }

    pub fn set_store_failure(&mut self, i: usize, fail: bool) {
        if fail {
            self.knowledge_lost = true;
        }
        self.nodes[i].store.fail_saves = fail;
    }

    pub fn set_acquire_fails(&mut self, i: usize, fails: bool) {
        self.nodes[i].acquire_fails = fails;
    }

    pub fn set_release_fails(&mut self, i: usize, fails: bool) {
        self.nodes[i].release_fails = fails;
    }

    pub fn set_link(&mut self, segment: usize, a_to_b: bool, b_to_a: bool) {
        self.links[segment] = Direction { a_to_b, b_to_a };
        if !a_to_b {
            self.queues[segment][0].clear();
        }
        if !b_to_a {
            self.queues[segment][1].clear();
        }
    }

    pub fn set_all_links(&mut self, up: bool) {
        for segment in 0..self.links.len() {
            self.set_link(segment, up, up);
        }
    }

    pub fn role(&self, i: usize) -> Option<Role> {
        self.nodes[i].ctl.as_ref().map(Controller::role)
    }

    pub fn controller(&self, i: usize) -> Option<&Controller> {
        self.nodes[i].ctl.as_ref()
    }

    pub fn holds(&self, i: usize) -> (bool, bool) {
        (self.nodes[i].vip, self.nodes[i].service)
    }

    pub fn powered(&self, i: usize) -> bool {
        self.nodes[i].powered
    }

    pub fn durable(&self, i: usize) -> Option<OwnershipState> {
        self.nodes[i]
            .store
            .bytes
            .as_ref()
            .and_then(|b| OwnershipState::decode(b, "sim", &self.nodes[i].id).ok())
    }

    pub fn send_event(&mut self, i: usize, event: Event) {
        let now = self.now_ms;
        let node = &mut self.nodes[i];
        let Some(ctl) = node.ctl.as_mut() else { return };
        let effects = ctl.handle(now, event, &mut node.store);
        self.apply(i, effects);
    }

    fn apply(&mut self, i: usize, effects: Vec<Effect>) {
        let (sends, others): (Vec<Effect>, Vec<Effect>) = effects
            .into_iter()
            .partition(|e| matches!(e, Effect::Send(_) | Effect::Publish(_)));
        let mut ordered: Vec<Effect> = Vec::new();
        let publishes: Vec<Effect> = sends
            .iter()
            .filter(|e| matches!(e, Effect::Publish(_)))
            .cloned()
            .collect();
        let controls: Vec<Effect> = sends
            .into_iter()
            .filter(|e| matches!(e, Effect::Send(_)))
            .collect();
        if self.controls_first {
            ordered.extend(controls);
            ordered.extend(publishes);
        } else {
            ordered.extend(publishes);
            ordered.extend(controls);
        }
        ordered.extend(others);
        for effect in ordered {
            match effect {
                Effect::Publish(state) => {
                    self.nodes[i].published = Some(state.clone());
                    // Announce immediately on every link (the runtime does the same).
                    for segment in 0..self.links.len() {
                        self.enqueue(i, segment, Msg::Announce(state.clone()));
                        self.nodes[i].last_announce_ms[segment] = self.now_ms;
                    }
                }
                Effect::Send(body) => {
                    self.msg_counter += 1;
                    let msg_id = format!("m{}", self.msg_counter);
                    let incarnation = self.nodes[i]
                        .ctl
                        .as_ref()
                        .map(|c| c.incarnation().to_string())
                        .unwrap_or_default();
                    for segment in 0..self.links.len() {
                        self.enqueue(
                            i,
                            segment,
                            Msg::Control {
                                msg_id: msg_id.clone(),
                                incarnation: incarnation.clone(),
                                body: body.clone(),
                            },
                        );
                    }
                }
                Effect::RunFence { op_id, .. } => {
                    let target = 1 - i;
                    let reachable = !self.fence_path_shared || self.segment_up(0);
                    let outcome = match (self.fence_mode, reachable) {
                        (_, false) | (FenceMode::Unreachable, _) => FenceAction::TimedOut,
                        (FenceMode::Works, _) => {
                            self.pending_power_off
                                .push((self.now_ms + FENCE_ACTION_MS / 2, target));
                            FenceAction::ReportedSuccess
                        }
                        (FenceMode::SlowStop { delay_ms }, _) => {
                            self.pending_power_off
                                .push((self.now_ms + delay_ms, target));
                            FenceAction::ReportedSuccess
                        }
                        (FenceMode::Fails, _) => FenceAction::ReportedFailure,
                        (FenceMode::TimesOut, _) => FenceAction::TimedOut,
                        (FenceMode::AcceptsWithoutStop, _) => FenceAction::ReportedSuccess,
                    };
                    self.nodes[i].op =
                        Some((Op::Fence { op_id, outcome }, self.now_ms + FENCE_ACTION_MS));
                }
                Effect::RunVerify { op_id, .. } => {
                    self.nodes[i].op = Some((Op::Verify { op_id }, self.now_ms + VERIFY_MS));
                }
                Effect::Acquire { epoch } => {
                    let peer = 1 - i;
                    if self.nodes[peer].vip || self.nodes[peer].service {
                        self.violations.push(format!(
                            "S-5 at {} ms: {} promotes (epoch {epoch}) while {} holds resources",
                            self.now_ms, self.nodes[i].id, self.nodes[peer].id
                        ));
                    }
                    let id = self.nodes[i].id.clone();
                    match self.epoch_owner.get(&epoch) {
                        Some(owner) if owner != &id && !self.knowledge_lost => {
                            self.violations.push(format!(
                                "S-4 at {} ms: epoch {epoch} owned by {owner} and {id}",
                                self.now_ms
                            ))
                        }
                        _ => {
                            self.epoch_owner.insert(epoch, id.clone());
                        }
                    }
                    self.promotions.push((self.now_ms, id, epoch));
                    self.nodes[i].op = Some((Op::Acquire, self.now_ms + ACQUIRE_MS));
                }
                Effect::Release { .. } => {
                    self.nodes[i].op = Some((Op::Release, self.now_ms + RELEASE_MS));
                }
                Effect::Log(line) => {
                    if self.verbose {
                        eprintln!("[{:>7}] {}: {line}", self.now_ms, self.nodes[i].id);
                    }
                    self.logs
                        .push(format!("[{}] {}: {line}", self.now_ms, self.nodes[i].id));
                }
                Effect::Exit => {
                    self.nodes[i].ctl = None;
                    self.nodes[i].op = None;
                    self.nodes[i].published = None;
                }
            }
        }
    }

    fn enqueue(&mut self, from: usize, segment: usize, msg: Msg) {
        let up = if from == 0 {
            self.links[segment].a_to_b
        } else {
            self.links[segment].b_to_a
        };
        let peer = 1 - from;
        if up && self.nodes[peer].powered {
            self.queues[segment][from].push_back((self.now_ms + STEP_MS, msg));
        }
    }

    fn segment_up(&self, segment: usize) -> bool {
        self.links[segment].a_to_b && self.links[segment].b_to_a
    }

    /// Per process (like the runtime, whose link state starts empty): a link is fresh for
    /// node `i` only through exchanges after its current process started.
    fn link_view(&self, i: usize) -> Vec<bool> {
        let started = self.nodes[i].process_started_ms;
        (0..self.links.len())
            .map(|segment| {
                let last = self.last_bidirectional[segment];
                last > started && self.now_ms.saturating_sub(last) <= LINK_TIMEOUT_MS
            })
            .collect()
    }

    pub fn step(&mut self) {
        self.now_ms += STEP_MS;
        let now = self.now_ms;
        // Delayed power-offs of the fence device.
        let due: Vec<usize> = self
            .pending_power_off
            .iter()
            .filter(|(t, _)| *t <= now)
            .map(|(_, i)| *i)
            .collect();
        self.pending_power_off.retain(|(t, _)| *t > now);
        for i in due {
            self.power_off(i);
        }
        // Bidirectional link freshness (both processes up and exchanging).
        for segment in 0..self.links.len() {
            if self.segment_up(segment) && self.nodes.iter().all(|n| n.powered && n.ctl.is_some()) {
                self.last_bidirectional[segment] = now;
            }
        }
        // Periodic announcements.
        for i in 0..2 {
            if let Some(state) = self.nodes[i].published.clone() {
                for segment in 0..self.links.len() {
                    if now.saturating_sub(self.nodes[i].last_announce_ms[segment])
                        >= ANNOUNCE_EVERY_MS
                    {
                        self.nodes[i].last_announce_ms[segment] = now;
                        self.enqueue(i, segment, Msg::Announce(state.clone()));
                    }
                }
            }
        }
        // Delivery (FIFO per segment and direction).
        for segment in 0..self.links.len() {
            for from in 0..2 {
                while let Some((at, _)) = self.queues[segment][from].front() {
                    if *at > now {
                        break;
                    }
                    let (_, msg) = self.queues[segment][from].pop_front().unwrap();
                    let to = 1 - from;
                    if self.nodes[to].ctl.is_none() || self.nodes[from].ctl.is_none() {
                        continue;
                    }
                    let message = match msg {
                        Msg::Announce(state) => PeerMessage::Announce(state),
                        Msg::Control {
                            msg_id,
                            incarnation,
                            body,
                        } => PeerMessage::Control {
                            msg_id,
                            from_incarnation: incarnation,
                            body,
                        },
                    };
                    self.send_event(to, Event::Peer(message));
                }
            }
        }
        // Completions of long operations.
        for i in 0..2 {
            let Some((op, at)) = self.nodes[i].op.clone() else {
                continue;
            };
            if at > now || self.nodes[i].ctl.is_none() {
                continue;
            }
            self.nodes[i].op = None;
            let event = match op {
                Op::Fence { op_id, outcome } => Event::FenceActionDone { op_id, outcome },
                Op::Verify { op_id } => {
                    let target = 1 - i;
                    let reachable = !self.fence_path_shared || self.segment_up(0);
                    let verdict = if !reachable || self.fence_mode == FenceMode::Unreachable {
                        Verdict::Inconclusive
                    } else if self.nodes[target].powered {
                        Verdict::NotIsolated
                    } else {
                        Verdict::Isolated
                    };
                    // A slow stop shows as not-yet-stopped while pending: inconclusive.
                    let verdict = if verdict == Verdict::NotIsolated
                        && self.pending_power_off.iter().any(|(_, t)| *t == target)
                    {
                        Verdict::Inconclusive
                    } else {
                        verdict
                    };
                    Event::VerifyDone { op_id, verdict }
                }
                Op::Acquire => {
                    self.nodes[i].vip = true;
                    if self.nodes[i].acquire_fails {
                        Event::AcquireDone(AcquireResult::Failed)
                    } else {
                        self.nodes[i].service = true;
                        Event::AcquireDone(AcquireResult::Acquired)
                    }
                }
                Op::Release => {
                    self.nodes[i].service = false;
                    if self.nodes[i].release_fails {
                        Event::ReleaseDone {
                            zero_resource: false,
                        }
                    } else {
                        self.nodes[i].vip = false;
                        Event::ReleaseDone {
                            zero_resource: true,
                        }
                    }
                }
            };
            self.send_event(i, event);
        }
        // Ticks and link views.
        if (now / STEP_MS).is_multiple_of(TICK_EVERY) {
            for i in 0..2 {
                if self.nodes[i].ctl.is_some() {
                    let view = self.link_view(i);
                    if self.nodes[i].ctl.as_ref().unwrap().links() != view.as_slice() {
                        self.send_event(i, Event::Links(view));
                    }
                    self.send_event(i, Event::Tick);
                }
            }
        }
        self.check();
    }

    pub fn run_for(&mut self, ms: u64) {
        let end = self.now_ms + ms;
        while self.now_ms < end {
            self.step();
        }
    }

    /// Runs until `predicate` holds or `ms` elapse; returns whether it held.
    pub fn run_until(&mut self, ms: u64, predicate: impl Fn(&World) -> bool) -> bool {
        let end = self.now_ms + ms;
        while self.now_ms < end {
            self.step();
            if predicate(self) {
                return true;
            }
        }
        predicate(self)
    }

    fn check(&mut self) {
        let vips = self.nodes.iter().filter(|n| n.vip).count();
        let services = self.nodes.iter().filter(|n| n.service).count();
        let actives = self
            .nodes
            .iter()
            .filter(|n| n.ctl.as_ref().is_some_and(|c| c.role() == Role::Active))
            .count();
        if vips > 1 {
            self.violations
                .push(format!("S-1 at {} ms: VIP on both nodes", self.now_ms));
        }
        if services > 1 {
            self.violations
                .push(format!("S-2 at {} ms: service on both nodes", self.now_ms));
        }
        if actives > 1 {
            self.violations
                .push(format!("S-3 at {} ms: two Active controllers", self.now_ms));
        }
        let owning = self
            .nodes
            .iter()
            .filter(|n| {
                n.ctl
                    .as_ref()
                    .is_some_and(|c| matches!(c.role(), Role::Active | Role::Promoting))
            })
            .count();
        if owning > 1 {
            self.violations.push(format!(
                "S-6 at {} ms: two nodes own an epoch (Promoting/Active) at once",
                self.now_ms
            ));
        }
    }

    pub fn active(&self) -> Option<usize> {
        (0..2).find(|i| self.role(*i) == Some(Role::Active))
    }

    pub fn assert_safe(&self) {
        assert!(
            self.violations.is_empty(),
            "safety violations: {:#?}\nlast logs:\n{}",
            self.violations,
            self.logs
                .iter()
                .rev()
                .take(60)
                .rev()
                .cloned()
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    pub fn log_contains(&self, needle: &str) -> bool {
        self.logs.iter().any(|line| line.contains(needle))
    }
}

/// A small deterministic PRNG (xorshift64*), so every random run is reproducible by seed.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    pub fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

#[cfg(test)]
mod tests;
