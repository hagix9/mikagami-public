//! The two-node I/O driver: peer links, fence commands, local resources, operator requests
//! and the status file around the pure [`Controller`].
//!
//! Threads: one per peer link (connect or accept, authenticated session, heartbeat
//! announcements, acknowledgement-based freshness) and the controller thread, which runs
//! every long operation (fence, verify, resource actions) synchronously, one at a time. The
//! link threads keep announcing while the controller thread is busy, and they only ever
//! send what the controller published: they never decide anything.

// The production entry and its resource backends are Linux-only; elsewhere only the tests
// use the driver.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use super::config::{HEARTBEAT_INTERVAL_MS, LINK_TIMEOUT_MS, LinkConfig, LinkEndpoint};
use super::controller::{AcquireResult, Controller, Effect, Event, FenceAction, Verdict};
use super::store::DurableStore;
use super::wire::{self, Control, LinkSession, PeerMessage, PeerState, WireBody};
use crate::framing::{DecodeResult, decode_frame, encode_frame};
use crate::security::Psk;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A control message is re-offered to a link that (re)connects within this time.
const CONTROL_TTL: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const READ_SLICE: Duration = Duration::from_millis(100);
const RECONNECT_PAUSE: Duration = Duration::from_millis(500);
/// An incompatible peer counts as alive this long after its last refused `Hello` (both
/// sides keep reconnecting every [`RECONNECT_PAUSE`]).
const INCOMPATIBLE_FRESH: Duration = Duration::from_millis(LINK_TIMEOUT_MS * 3);
const LOOP_SLICE: Duration = Duration::from_millis(200);
const STATUS_REFRESH: Duration = Duration::from_secs(5);
const MAX_REQUEST_BYTES: u64 = 4096;

// ---- seams --------------------------------------------------------------------------------

/// Runs one bounded fence action or verify poll (production: `fencing_backend`).
pub(crate) trait FenceRunner {
    fn fence(&mut self, incident_seq: u64, attempt: u32, op_id: &str) -> FenceAction;
    fn verify(&mut self, incident_seq: u64, attempt: u32, op_id: &str) -> Verdict;
}

/// Local resources (production: `ResourceExecutor`). `release` returns `true` only for a
/// trusted observation of service stopped and VIP absent.
pub(crate) trait ResourceOps {
    fn acquire(&mut self) -> AcquireResult;
    fn release(&mut self) -> bool;
    /// The last observed state of every resource (name, state), for the status file. It
    /// runs nothing: it reports what the last acquire or release observed.
    fn resource_states(&self) -> Vec<(String, String)> {
        Vec::new()
    }
    /// One `[health] command` run while Active: `Some(true)` healthy, `Some(false)`
    /// unhealthy, `None` unknown.
    fn observe_health(&mut self) -> Option<bool> {
        None
    }
    /// `[health] on_failure = "restart"`: stop the services (reverse order, the VIP stays),
    /// start them again (in order) and check health.
    fn restart(&mut self) -> RestartOutcome {
        RestartOutcome::NotSupported
    }
}

/// The result of a local restart of the services.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RestartOutcome {
    /// Every service stopped, started again and the health check passed.
    Restarted,
    /// A stop was not confirmed (the resources are uncertain).
    StopUnconfirmed(String),
    /// A start or the health check after it failed (services may be down; the VIP is up).
    StartFailed(String),
    NotSupported,
}

impl ResourceOps for Box<dyn ResourceOps> {
    fn acquire(&mut self) -> AcquireResult {
        (**self).acquire()
    }
    fn release(&mut self) -> bool {
        (**self).release()
    }
    fn resource_states(&self) -> Vec<(String, String)> {
        (**self).resource_states()
    }
    fn observe_health(&mut self) -> Option<bool> {
        (**self).observe_health()
    }
    fn restart(&mut self) -> RestartOutcome {
        (**self).restart()
    }
}

fn health_bool(observation: crate::resource_executor::HealthObservation) -> Option<bool> {
    if observation.is_healthy() {
        Some(true)
    } else if observation.is_unhealthy() {
        Some(false)
    } else {
        None
    }
}

/// No fence device: every step reports nothing usable (the controller never asks for one
/// when the policy has no independent device).
pub(crate) struct NoFence;

impl FenceRunner for NoFence {
    fn fence(&mut self, _: u64, _: u32, _: &str) -> FenceAction {
        FenceAction::SpawnFailed
    }
    fn verify(&mut self, _: u64, _: u32, _: &str) -> Verdict {
        Verdict::Inconclusive
    }
}

/// The production fence runner: the existing bounded command backend. The fence operation
/// id is passed as `MIKAGAMI_FENCE_INCIDENT` and the attempt as `MIKAGAMI_FENCE_ATTEMPT`, so
/// a helper can bind its verify to the same operation.
pub(crate) struct CommandFenceRunner {
    backend: crate::fencing_backend::CommandBackend,
    settings: crate::fencing_backend::CommandFencing,
    cluster: String,
    target: String,
}

impl CommandFenceRunner {
    pub(crate) fn new(
        settings: crate::fencing_backend::CommandFencing,
        cluster: &str,
        target: &str,
    ) -> Self {
        Self {
            backend: crate::fencing_backend::CommandBackend::system(),
            settings,
            cluster: cluster.to_string(),
            target: target.to_string(),
        }
    }

    /// The exact step request of one fence action or verify poll: the operation id is the
    /// step's incident id (`MIKAGAMI_FENCE_INCIDENT`) and the attempt its token
    /// (`MIKAGAMI_FENCE_ATTEMPT`), so a helper binds the verify of an attempt to the record of
    /// that attempt's own action and to nothing else.
    #[cfg(test)]
    pub(crate) fn request(
        &self,
        kind: crate::fencing_backend::StepKind,
        incident_seq: u64,
        attempt: u32,
        op_id: &str,
    ) -> crate::fencing_backend::StepRequest<'_> {
        step_request(
            &self.settings,
            &self.cluster,
            &self.target,
            kind,
            incident_seq,
            attempt,
            op_id,
        )
    }

    fn step(
        &mut self,
        kind: crate::fencing_backend::StepKind,
        incident_seq: u64,
        attempt: u32,
        op_id: &str,
    ) -> Option<crate::fencing_backend::StepOutcome> {
        // The controller only ever produces canonical UUIDv4 operation ids and attempts >= 1;
        // anything else never reaches a helper.
        if !crate::node_mutation::is_canonical_uuid_v4(op_id) || attempt == 0 {
            eprintln!("mikagami: ERROR malformed fence operation identity; step refused");
            return None;
        }
        let request = step_request(
            &self.settings,
            &self.cluster,
            &self.target,
            kind,
            incident_seq,
            attempt,
            op_id,
        );
        let report = self.backend.run_step(&request);
        match report {
            Ok(report) => {
                for line in self.backend.step_log_lines(&report) {
                    eprintln!("mikagami: {line}");
                }
                Some(report.outcome)
            }
            Err(violation) => {
                eprintln!(
                    "mikagami: ERROR fencing step invariant violation: {}",
                    violation.into_observation_invariant()
                );
                None
            }
        }
    }
}

fn step_request<'a>(
    settings: &'a crate::fencing_backend::CommandFencing,
    cluster: &'a str,
    target: &'a str,
    kind: crate::fencing_backend::StepKind,
    incident_seq: u64,
    attempt: u32,
    op_id: &str,
) -> crate::fencing_backend::StepRequest<'a> {
    use crate::fencing_backend::{StepIdentity, StepKind, StepRequest};
    let (argv, timeout) = match kind {
        StepKind::Action => (&settings.fence, settings.fence_timeout),
        _ => (&settings.verify, settings.verify_timeout),
    };
    StepRequest {
        argv,
        timeout,
        identity: StepIdentity {
            incident_seq,
            incident_id: crate::fencing::IncidentId::generated(op_id.to_string()),
            attempt_token: u64::from(attempt),
        },
        cluster,
        target_node: target,
    }
}

/// A fence action's step outcome as the controller sees it: only an acceptance report. A
/// missing or mismatched outcome (no step, a verify outcome) is `SpawnFailed`.
pub(crate) fn action_outcome(outcome: Option<crate::fencing_backend::StepOutcome>) -> FenceAction {
    use crate::fencing::ActionOutcome;
    use crate::fencing_backend::StepOutcome;
    match outcome {
        Some(StepOutcome::Action(ActionOutcome::ReportedSuccess)) => FenceAction::ReportedSuccess,
        Some(StepOutcome::Action(ActionOutcome::ReportedFailure)) => FenceAction::ReportedFailure,
        Some(StepOutcome::Action(ActionOutcome::TimedOut)) => FenceAction::TimedOut,
        Some(StepOutcome::Action(ActionOutcome::Signal)) => FenceAction::Signal,
        _ => FenceAction::SpawnFailed,
    }
}

/// A verify poll's outcome: `Isolated` only for the backend's exact `isolated` answer (exit 0,
/// before the deadline); a timeout, `UNKNOWN`, any other output or no step is inconclusive.
pub(crate) fn verify_verdict(outcome: Option<crate::fencing_backend::StepOutcome>) -> Verdict {
    use crate::fencing_backend::{StepOutcome, VerifyOutcome};
    match outcome {
        Some(StepOutcome::Verify(VerifyOutcome::Isolated)) => Verdict::Isolated,
        Some(StepOutcome::Verify(VerifyOutcome::NotIsolated)) => Verdict::NotIsolated,
        _ => Verdict::Inconclusive,
    }
}

impl FenceRunner for CommandFenceRunner {
    fn fence(&mut self, incident_seq: u64, attempt: u32, op_id: &str) -> FenceAction {
        let outcome = self.step(
            crate::fencing_backend::StepKind::Action,
            incident_seq,
            attempt,
            op_id,
        );
        action_outcome(outcome)
    }

    fn verify(&mut self, incident_seq: u64, attempt: u32, op_id: &str) -> Verdict {
        let outcome = self.step(
            crate::fencing_backend::StepKind::Verify,
            incident_seq,
            attempt,
            op_id,
        );
        verify_verdict(outcome)
    }
}

/// The production resource operations, in the order of the Witness topology's workflow:
/// VIP, service, health, GARP to acquire; service stop then VIP release to clean up. Only
/// trusted observations count (a command's return alone proves nothing).
pub(crate) struct ExecutorOps<N, S>
where
    N: crate::resource_executor::NetworkBackend,
    S: crate::resource_executor::ServiceBackend,
{
    executor: crate::resource_executor::ResourceExecutor<N, S>,
}

impl<N, S> ExecutorOps<N, S>
where
    N: crate::resource_executor::NetworkBackend,
    S: crate::resource_executor::ServiceBackend,
{
    pub(crate) fn new(executor: crate::resource_executor::ResourceExecutor<N, S>) -> Self {
        Self { executor }
    }

    /// The acquisition steps; `Err` names the step that stopped it and what was observed
    /// (run 2n-20261118b: every promotion failed and the journal could not say where).
    fn acquire_steps(&mut self) -> Result<(), String> {
        use crate::resource_executor::{ActionDiagnostic, GarpOutcome};
        let vip = self.executor.acquire_vip();
        if !vip.observation().is_present()
            || matches!(vip.diagnostic(), ActionDiagnostic::Interrupted)
        {
            return Err(format!(
                "vip (observed {:?}, request {:?})",
                vip.observation(),
                vip.diagnostic()
            ));
        }
        let service = self.executor.start_service();
        if !service.observation().is_running()
            || !matches!(service.diagnostic(), ActionDiagnostic::Success)
        {
            return Err(format!(
                "service start (observed {:?}, request {:?})",
                service.observation(),
                service.diagnostic()
            ));
        }
        let health = self.executor.observe_health();
        if !health.is_healthy() {
            return Err(format!(
                "health check right after the service start (observed {health:?}; the service \
                 must answer when its start returns)"
            ));
        }
        let garp = self.executor.send_garp();
        if garp.outcome() != GarpOutcome::Succeeded {
            return Err(format!("gratuitous ARP ({:?})", garp.diagnostic()));
        }
        Ok(())
    }
}

impl<N, S> ResourceOps for ExecutorOps<N, S>
where
    N: crate::resource_executor::NetworkBackend,
    S: crate::resource_executor::ServiceBackend,
{
    fn acquire(&mut self) -> AcquireResult {
        match self.acquire_steps() {
            Ok(()) => AcquireResult::Acquired,
            Err(step) => {
                eprintln!("mikagami: WARN resource acquisition failed at {step}");
                AcquireResult::Failed
            }
        }
    }

    fn release(&mut self) -> bool {
        if !self.executor.stop_service().observation().is_stopped() {
            return false;
        }
        self.executor.release_vip().observation().is_absent()
    }

    fn observe_health(&mut self) -> Option<bool> {
        health_bool(self.executor.observe_health())
    }

    fn restart(&mut self) -> RestartOutcome {
        use crate::resource_executor::ActionDiagnostic;
        let stopped = self.executor.stop_service();
        if !stopped.observation().is_stopped() {
            return RestartOutcome::StopUnconfirmed(format!(
                "service (observed {:?})",
                stopped.observation()
            ));
        }
        let started = self.executor.start_service();
        if !started.observation().is_running()
            || !matches!(started.diagnostic(), ActionDiagnostic::Success)
        {
            return RestartOutcome::StartFailed(format!(
                "service (observed {:?})",
                started.observation()
            ));
        }
        match health_bool(self.executor.observe_health()) {
            Some(true) => RestartOutcome::Restarted,
            other => RestartOutcome::StartFailed(format!("health after the restart ({other:?})")),
        }
    }
}

// ---- resource group -------------------------------------------------------------------------

/// The network half of a service member's executor: never used (a member never touches the
/// VIP), and if it were, it would report nothing trustworthy.
pub(crate) struct NoNetwork;

impl crate::resource_executor::sealed::NetworkBackend for NoNetwork {}

impl crate::resource_executor::NetworkBackend for NoNetwork {
    fn request_vip_acquire(&mut self) -> crate::resource_executor::ActionDiagnostic {
        crate::resource_executor::ActionDiagnostic::Interrupted
    }
    fn observe_vip(&mut self) -> crate::resource_executor::RawVipObservation {
        crate::resource_executor::RawVipObservation::Unavailable
    }
    fn request_vip_release(&mut self) -> crate::resource_executor::ActionDiagnostic {
        crate::resource_executor::ActionDiagnostic::Interrupted
    }
    fn send_garp(
        &mut self,
    ) -> (
        crate::resource_executor::ActionDiagnostic,
        crate::resource_executor::RawGarpOutcome,
    ) {
        (
            crate::resource_executor::ActionDiagnostic::Interrupted,
            crate::resource_executor::RawGarpOutcome::Failed,
        )
    }
}

/// The service half of the VIP's executor: never used, reports nothing trustworthy.
pub(crate) struct NoService;

impl crate::resource_executor::sealed::ServiceBackend for NoService {}

impl crate::resource_executor::ServiceBackend for NoService {
    fn request_service_start(&mut self) -> crate::resource_executor::ActionDiagnostic {
        crate::resource_executor::ActionDiagnostic::Interrupted
    }
    fn observe_service(&mut self) -> crate::resource_executor::RawServiceObservation {
        crate::resource_executor::RawServiceObservation::Unavailable
    }
    fn request_service_stop(&mut self) -> crate::resource_executor::ActionDiagnostic {
        crate::resource_executor::ActionDiagnostic::Interrupted
    }
    fn observe_health(&mut self) -> crate::resource_executor::RawHealthObservation {
        crate::resource_executor::RawHealthObservation::Unavailable
    }
}

pub(crate) enum GroupMember<S> {
    Service {
        name: String,
        executor: crate::resource_executor::ResourceExecutor<NoNetwork, S>,
    },
    Vip {
        name: String,
    },
}

/// A resource group (`[[group.resource]]`): every resource is started in the configured
/// order and confirmed by its own observation (a command's return alone proves nothing);
/// then `[health]` must pass; only then is the VIP announced (gratuitous ARP). The release
/// goes in reverse order and stops at the first resource whose stop is not confirmed (the
/// resources before it are kept; the release is not reported as zero-resource, so the
/// controller keeps the cleanup obligation and never hands the service over).
pub(crate) struct GroupOps<N, S> {
    vip: crate::resource_executor::ResourceExecutor<N, NoService>,
    members: Vec<GroupMember<S>>,
    states: Vec<(String, String)>,
}

impl<N, S> GroupOps<N, S>
where
    N: crate::resource_executor::NetworkBackend,
    S: crate::resource_executor::ServiceBackend,
{
    pub(crate) fn new(network: N, members: Vec<GroupMember<S>>) -> Self {
        let states = members
            .iter()
            .map(|m| (Self::name_of(m).to_string(), "unknown".to_string()))
            .collect();
        Self {
            vip: crate::resource_executor::ResourceExecutor::new(network, NoService),
            members,
            states,
        }
    }

    fn name_of(member: &GroupMember<S>) -> &str {
        match member {
            GroupMember::Service { name, .. } | GroupMember::Vip { name } => name,
        }
    }

    fn record(&mut self, index: usize, state: &str) {
        if let Some(slot) = self.states.get_mut(index) {
            slot.1 = state.to_string();
        }
    }

    fn service_state(observation: crate::resource_executor::ServiceObservation) -> &'static str {
        if observation.is_running() {
            "running"
        } else if observation.is_stopped() {
            "stopped"
        } else {
            "unknown"
        }
    }

    fn vip_state(observation: crate::resource_executor::VipObservation) -> &'static str {
        if observation.is_present() {
            "present"
        } else if observation.is_absent() {
            "absent"
        } else {
            "unknown"
        }
    }

    /// `Err` names the resource or step that stopped the acquisition.
    pub(crate) fn acquire_steps(&mut self) -> Result<(), String> {
        use crate::resource_executor::{ActionDiagnostic, GarpOutcome};
        let mut last_service = None;
        for index in 0..self.members.len() {
            match &mut self.members[index] {
                GroupMember::Vip { name } => {
                    let name = name.clone();
                    let vip = self.vip.acquire_vip();
                    self.record(index, Self::vip_state(vip.observation()));
                    if !vip.observation().is_present()
                        || matches!(vip.diagnostic(), ActionDiagnostic::Interrupted)
                    {
                        return Err(format!(
                            "{name} (vip: observed {:?}, request {:?})",
                            vip.observation(),
                            vip.diagnostic()
                        ));
                    }
                }
                GroupMember::Service { name, executor } => {
                    let name = name.clone();
                    let started = executor.start_service();
                    self.record(index, Self::service_state(started.observation()));
                    if !started.observation().is_running()
                        || !matches!(started.diagnostic(), ActionDiagnostic::Success)
                    {
                        return Err(format!(
                            "{name} (start: observed {:?}, request {:?})",
                            started.observation(),
                            started.diagnostic()
                        ));
                    }
                    last_service = Some(index);
                }
            }
        }
        // The group health check (`[health] command`, the same for every member) runs once
        // every resource is up, before the VIP is announced.
        let Some(GroupMember::Service { executor, .. }) =
            last_service.and_then(|i| self.members.get_mut(i))
        else {
            return Err("health (the group has no service)".into());
        };
        let health = executor.observe_health();
        if !health.is_healthy() {
            return Err(format!(
                "health check after every resource started (observed {health:?}); the VIP is \
                 not announced"
            ));
        }
        let garp = self.vip.send_garp();
        if garp.outcome() != GarpOutcome::Succeeded {
            return Err(format!("gratuitous ARP ({:?})", garp.diagnostic()));
        }
        Ok(())
    }

    pub(crate) fn release_steps(&mut self) -> Result<(), String> {
        for index in (0..self.members.len()).rev() {
            match &mut self.members[index] {
                GroupMember::Vip { name } => {
                    let name = name.clone();
                    let released = self.vip.release_vip();
                    self.record(index, Self::vip_state(released.observation()));
                    if !released.observation().is_absent() {
                        return Err(format!(
                            "{name} (vip release: observed {:?})",
                            released.observation()
                        ));
                    }
                }
                GroupMember::Service { name, executor } => {
                    let name = name.clone();
                    let stopped = executor.stop_service();
                    self.record(index, Self::service_state(stopped.observation()));
                    if !stopped.observation().is_stopped() {
                        return Err(format!(
                            "{name} (stop: observed {:?}); the resources before it are kept",
                            stopped.observation()
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

impl<N, S> ResourceOps for GroupOps<N, S>
where
    N: crate::resource_executor::NetworkBackend,
    S: crate::resource_executor::ServiceBackend,
{
    fn acquire(&mut self) -> AcquireResult {
        match self.acquire_steps() {
            Ok(()) => AcquireResult::Acquired,
            Err(step) => {
                eprintln!("mikagami: WARN resource group acquisition failed at {step}");
                AcquireResult::Failed
            }
        }
    }

    fn release(&mut self) -> bool {
        match self.release_steps() {
            Ok(()) => true,
            Err(step) => {
                eprintln!("mikagami: WARN resource group release not confirmed at {step}");
                false
            }
        }
    }

    fn resource_states(&self) -> Vec<(String, String)> {
        self.states.clone()
    }

    fn observe_health(&mut self) -> Option<bool> {
        let executor = self.members.iter_mut().rev().find_map(|m| match m {
            GroupMember::Service { executor, .. } => Some(executor),
            GroupMember::Vip { .. } => None,
        })?;
        health_bool(executor.observe_health())
    }

    fn restart(&mut self) -> RestartOutcome {
        use crate::resource_executor::ActionDiagnostic;
        for index in (0..self.members.len()).rev() {
            if let GroupMember::Service { name, executor } = &mut self.members[index] {
                let name = name.clone();
                let stopped = executor.stop_service();
                self.record(index, Self::service_state(stopped.observation()));
                if !stopped.observation().is_stopped() {
                    return RestartOutcome::StopUnconfirmed(format!(
                        "{name} (observed {:?})",
                        stopped.observation()
                    ));
                }
            }
        }
        for index in 0..self.members.len() {
            if let GroupMember::Service { name, executor } = &mut self.members[index] {
                let name = name.clone();
                let started = executor.start_service();
                self.record(index, Self::service_state(started.observation()));
                if !started.observation().is_running()
                    || !matches!(started.diagnostic(), ActionDiagnostic::Success)
                {
                    return RestartOutcome::StartFailed(format!(
                        "{name} (observed {:?})",
                        started.observation()
                    ));
                }
            }
        }
        match self.observe_health() {
            Some(true) => RestartOutcome::Restarted,
            other => RestartOutcome::StartFailed(format!("health after the restart ({other:?})")),
        }
    }
}

// ---- links --------------------------------------------------------------------------------

struct OutControl {
    id: u64,
    msg_id: String,
    body: Control,
    created: Instant,
}

/// When an incompatible `Hello` was refused, and the peer's configuration summary.
type IncompatibleSeen = (Instant, Option<String>);

/// What the controller publishes and the links read; and what the links report.
pub(crate) struct LinkShared {
    announce: Mutex<Option<PeerState>>,
    controls: Mutex<VecDeque<OutControl>>,
    next_control: AtomicU64,
    last_fresh: Vec<Mutex<Option<Instant>>>,
    /// Per link: when an authenticated `Hello` of the peer with a different configuration
    /// summary was last refused, and the peer's summary.
    incompatible: Vec<Mutex<Option<IncompatibleSeen>>>,
    pub(crate) stop: AtomicBool,
}

impl LinkShared {
    pub(crate) fn new(links: usize) -> Arc<Self> {
        Arc::new(Self {
            announce: Mutex::new(None),
            controls: Mutex::new(VecDeque::new()),
            next_control: AtomicU64::new(1),
            last_fresh: (0..links).map(|_| Mutex::new(None)).collect(),
            incompatible: (0..links).map(|_| Mutex::new(None)).collect(),
            stop: AtomicBool::new(false),
        })
    }

    fn link_up(&self, index: usize) -> bool {
        self.last_fresh[index]
            .lock()
            .ok()
            .and_then(|guard| *guard)
            .is_some_and(|t| t.elapsed() <= Duration::from_millis(LINK_TIMEOUT_MS))
    }

    pub(crate) fn links_up(&self) -> Vec<bool> {
        (0..self.last_fresh.len())
            .map(|i| self.link_up(i))
            .collect()
    }

    fn mark_incompatible(&self, index: usize, peer_summary: Option<String>) {
        if let Ok(mut guard) = self.incompatible[index].lock() {
            *guard = Some((Instant::now(), peer_summary));
        }
    }

    /// The peer's summary when an incompatible `Hello` was refused on any link within
    /// [`INCOMPATIBLE_FRESH`] (the peer is alive with another configuration).
    pub(crate) fn peer_incompatible(&self) -> Option<Option<String>> {
        self.incompatible.iter().find_map(|slot| {
            slot.lock().ok().and_then(|guard| {
                guard
                    .as_ref()
                    .filter(|(at, _)| at.elapsed() <= INCOMPATIBLE_FRESH)
                    .map(|(_, summary)| summary.clone())
            })
        })
    }

    fn set_fresh(&self, index: usize, value: Option<Instant>) {
        if let Ok(mut guard) = self.last_fresh[index].lock() {
            *guard = value;
        }
    }

    fn publish(&self, state: PeerState) {
        if let Ok(mut guard) = self.announce.lock() {
            *guard = Some(state);
        }
    }

    fn queue_control(&self, body: Control) -> Option<()> {
        let msg_id = crate::node_mutation::generate_uuid()?;
        let id = self.next_control.fetch_add(1, Ordering::SeqCst);
        let mut controls = self.controls.lock().ok()?;
        controls.retain(|c| c.created.elapsed() < CONTROL_TTL);
        controls.push_back(OutControl {
            id,
            msg_id,
            body,
            created: Instant::now(),
        });
        Some(())
    }
}

#[derive(Clone)]
pub(crate) struct LinkIdentity {
    pub(crate) cluster: String,
    pub(crate) local: String,
    pub(crate) peer: String,
    pub(crate) incarnation: String,
    /// The configuration summary of a shared configuration file (`None`: per-node file).
    pub(crate) config: Option<String>,
}

/// Starts one thread per link. They stop when `shared.stop` is set.
pub(crate) fn spawn_links(
    identity: &LinkIdentity,
    links: &[LinkConfig],
    psk: &Psk,
    shared: &Arc<LinkShared>,
    inbound: &Sender<PeerMessage>,
) -> Vec<std::thread::JoinHandle<()>> {
    links
        .iter()
        .map(|link| {
            let identity = identity.clone();
            let link = link.clone();
            let psk = psk.clone();
            let shared = Arc::clone(shared);
            let inbound = inbound.clone();
            std::thread::Builder::new()
                .name(format!("mkg-link-{}", link.index))
                .spawn(move || link_worker(identity, link, psk, shared, inbound))
                .expect("spawn link thread")
        })
        .collect()
}

fn link_worker(
    identity: LinkIdentity,
    link: LinkConfig,
    psk: Psk,
    shared: Arc<LinkShared>,
    inbound: Sender<PeerMessage>,
) {
    let mut listener: Option<TcpListener> = None;
    let mut bind_logged = false;
    while !shared.stop.load(Ordering::SeqCst) {
        let stream = match &link.endpoint {
            LinkEndpoint::Dial(address) => {
                TcpStream::connect_timeout(address, CONNECT_TIMEOUT).ok()
            }
            LinkEndpoint::Listen(address) => {
                if listener.is_none() {
                    match TcpListener::bind(address) {
                        Ok(bound) => {
                            let _ = bound.set_nonblocking(true);
                            listener = Some(bound);
                        }
                        Err(error) => {
                            if !bind_logged {
                                eprintln!(
                                    "mikagami: ERROR link {} ({}) cannot listen on {address}: {error}",
                                    link.index, link.segment
                                );
                                bind_logged = true;
                            }
                        }
                    }
                }
                listener.as_ref().and_then(|l| match l.accept() {
                    Ok((stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        Some(stream)
                    }
                    Err(_) => None,
                })
            }
        };
        if let Some(stream) = stream {
            if let Err(why) = run_session(&identity, &link, &psk, &shared, &inbound, stream)
                && std::env::var_os("MKG_TWO_NODE_DEBUG").is_some()
            {
                eprintln!("mikagami: DEBUG link {} session ended: {why}", link.index);
            }
            shared.set_fresh(usize::from(link.index), None);
        }
        std::thread::sleep(RECONNECT_PAUSE);
    }
}

fn write_envelope(
    stream: &mut TcpStream,
    psk: &Psk,
    envelope: &wire::Envelope,
) -> std::io::Result<()> {
    let payload = wire::encode(psk, envelope);
    let frame = encode_frame(&payload).map_err(|_| std::io::Error::other("frame too large"))?;
    stream.write_all(&frame)
}

fn run_session(
    identity: &LinkIdentity,
    link: &LinkConfig,
    psk: &Psk,
    shared: &LinkShared,
    inbound: &Sender<PeerMessage>,
    mut stream: TcpStream,
) -> Result<(), String> {
    let index = usize::from(link.index);
    stream.set_nodelay(true).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(READ_SLICE))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| e.to_string())?;
    let nonce = wire::fresh_nonce().ok_or("no randomness")?;
    let mut session = LinkSession::new(
        &identity.cluster,
        &identity.local,
        &identity.peer,
        link.index,
        nonce,
        identity.incarnation.clone(),
    )
    .with_config(identity.config.clone());
    let mut sent: VecDeque<(u64, Instant)> = VecDeque::new();
    let (seq, hello) = session
        .outgoing(WireBody::Hello {
            incarnation: identity.incarnation.clone(),
            config: identity.config.clone(),
        })
        .ok_or("hello")?;
    write_envelope(&mut stream, psk, &hello).map_err(|e| e.to_string())?;
    sent.push_back((seq, Instant::now()));
    let mut last_rx = Instant::now();
    let mut last_announce: Option<(u64, Instant)> = None;
    let mut last_control = shared
        .controls
        .lock()
        .map(|c| {
            c.iter()
                .filter(|c| c.created.elapsed() >= CONTROL_TTL)
                .map(|c| c.id)
                .max()
                .unwrap_or(0)
        })
        .unwrap_or(0);
    let mut buffer: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut acked = 0u64;
    loop {
        if shared.stop.load(Ordering::SeqCst) {
            return Ok(());
        }
        if session.established() {
            // Announce first (so a control message never overtakes the state it relies on).
            let current = shared.announce.lock().map_err(|_| "poisoned")?.clone();
            if let Some(state) = current {
                let due = match last_announce {
                    None => true,
                    Some((seq, at)) => {
                        seq != state.state_seq
                            || at.elapsed() >= Duration::from_millis(HEARTBEAT_INTERVAL_MS)
                    }
                };
                if due {
                    let state_seq = state.state_seq;
                    let (seq, envelope) = session
                        .outgoing(WireBody::Announce { state })
                        .ok_or("sequence")?;
                    write_envelope(&mut stream, psk, &envelope).map_err(|e| e.to_string())?;
                    sent.push_back((seq, Instant::now()));
                    last_announce = Some((state_seq, Instant::now()));
                }
            }
            let pending: Vec<(u64, String, Control)> = shared
                .controls
                .lock()
                .map_err(|_| "poisoned")?
                .iter()
                .filter(|c| c.id > last_control && c.created.elapsed() < CONTROL_TTL)
                .map(|c| (c.id, c.msg_id.clone(), c.body.clone()))
                .collect();
            for (id, msg_id, body) in pending {
                let (seq, envelope) = session
                    .outgoing(WireBody::Control {
                        msg_id,
                        incarnation: identity.incarnation.clone(),
                        body,
                    })
                    .ok_or("sequence")?;
                write_envelope(&mut stream, psk, &envelope).map_err(|e| e.to_string())?;
                sent.push_back((seq, Instant::now()));
                last_control = id;
            }
            while sent.len() > 256 {
                sent.pop_front();
            }
        }
        match stream.read(&mut chunk) {
            Ok(0) => return Err("closed".into()),
            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(e) => return Err(e.to_string()),
        }
        loop {
            let (payload, consumed) = match decode_frame(&buffer).map_err(|e| format!("{e:?}"))? {
                DecodeResult::Incomplete => break,
                DecodeResult::Complete { payload, consumed } => (payload.to_vec(), consumed),
            };
            buffer.drain(..consumed);
            let envelope = wire::decode(psk, &payload).map_err(|e| format!("{e:?}"))?;
            let message = match session.accept(envelope) {
                Ok(message) => message,
                Err(wire::WireError::ConfigMismatch { peer }) => {
                    shared.mark_incompatible(index, peer);
                    return Err("configuration mismatch".into());
                }
                Err(e) => return Err(format!("{e:?}")),
            };
            last_rx = Instant::now();
            if session.peer_ack > acked {
                acked = session.peer_ack;
                if let Some((_, at)) = sent.iter().find(|(seq, _)| *seq == acked)
                    && at.elapsed() <= Duration::from_millis(LINK_TIMEOUT_MS)
                {
                    shared.set_fresh(index, Some(Instant::now()));
                }
            }
            if let Some(message) = message
                && inbound.send(message).is_err()
            {
                return Ok(());
            }
        }
        if !session.established() && last_rx.elapsed() > CONNECT_TIMEOUT {
            return Err("no hello".into());
        }
        if last_rx.elapsed() > Duration::from_millis(LINK_TIMEOUT_MS * 2) {
            return Err("silent".into());
        }
    }
}

// ---- operator requests --------------------------------------------------------------------

/// One operator request file (written by `mikagami two-node takeover`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OperatorRequest {
    pub(crate) version: u32,
    pub(crate) cluster: String,
    pub(crate) target: String,
    pub(crate) kind: OperatorKind,
    pub(crate) attestation_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum OperatorKind {
    /// The operator attests that the peer's OS is stopped (manual failover).
    AttestPeerStopped,
    /// The operator asks this node to fence the peer and promote after verify.
    Fence,
}

/// Reads and removes every request file in `dir`. A file must be a regular file (not a
/// symlink) owned by this process's effective user, not group/other writable, and small.
pub(crate) fn take_operator_requests(
    dir: &Path,
    cluster: &str,
) -> (Vec<OperatorRequest>, Vec<String>) {
    use std::os::unix::fs::MetadataExt;
    let mut requests = Vec::new();
    let mut problems = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return (requests, problems);
    };
    let euid = unsafe { libc::geteuid() };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    paths.sort();
    for path in paths {
        let verdict = (|| -> Result<OperatorRequest, String> {
            let metadata = std::fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
            if !metadata.file_type().is_file() {
                return Err("not a regular file".into());
            }
            if metadata.uid() != euid || metadata.mode() & 0o022 != 0 {
                return Err("wrong owner or writable by group/other".into());
            }
            if metadata.len() > MAX_REQUEST_BYTES {
                return Err("too large".into());
            }
            let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
            let request: OperatorRequest =
                serde_json::from_slice(&bytes).map_err(|_| "malformed".to_string())?;
            if request.version != 1 || request.cluster != cluster {
                return Err("wrong version or cluster".into());
            }
            Ok(request)
        })();
        let _ = std::fs::remove_file(&path);
        match verdict {
            Ok(request) => requests.push(request),
            Err(why) => problems.push(format!("{}: {why}", path.display())),
        }
    }
    (requests, problems)
}

// ---- status -------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LinkStatusView {
    pub(crate) index: u8,
    pub(crate) segment: String,
    pub(crate) role: String,
    pub(crate) interface: String,
    pub(crate) up: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StatusView {
    pub(crate) node: String,
    pub(crate) peer: String,
    pub(crate) incarnation: String,
    pub(crate) role: String,
    pub(crate) epoch: u64,
    pub(crate) owner: Option<String>,
    pub(crate) record_ok: bool,
    pub(crate) contradiction: bool,
    pub(crate) peer_connected: bool,
    /// The resources of a group as last observed (name, state); empty for one [service].
    #[serde(default)]
    pub(crate) resources: Vec<(String, String)>,
    /// The Active's health monitor.
    #[serde(default)]
    pub(crate) health: Option<HealthView>,
    /// An authenticated peer with a different configuration was refused recently.
    #[serde(default)]
    pub(crate) config_mismatch: bool,
    pub(crate) links: Vec<LinkStatusView>,
    pub(crate) incident: Option<String>,
    pub(crate) grant_outstanding: bool,
    pub(crate) updated_unix: u64,
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn write_status(path: &Path, status: &StatusView) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("tmp");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .open(&temporary)?;
    file.write_all(&serde_json::to_vec_pretty(status).map_err(std::io::Error::other)?)?;
    file.write_all(b"\n")?;
    drop(file);
    std::fs::rename(&temporary, path)
}

// ---- the driver ---------------------------------------------------------------------------

/// Runs the controller with its effects. Generic over the seams so the same loop runs in
/// tests with fakes.
pub(crate) struct Driver<F: FenceRunner, R: ResourceOps> {
    pub(crate) controller: Controller,
    store: Box<dyn DurableStore + Send>,
    fence: F,
    ops: R,
    shared: Arc<LinkShared>,
    inbound: Receiver<PeerMessage>,
    origin: Instant,
    links: Vec<LinkConfig>,
    status_path: Option<PathBuf>,
    operator_dir: Option<PathBuf>,
    cluster: String,
    peer: String,
    /// The live control-lock check before every protected effect (production) — `Err`
    /// stops protected effects and ends the loop.
    guard: Box<dyn Fn() -> Result<(), String> + Send>,
    last_links: Vec<bool>,
    /// The last incompatibility handed to the controller (with the peer's summary).
    last_incompatible: Option<Option<String>>,
    /// This node's configuration summary (for naming the differing sections).
    config_summary: Option<String>,
    /// The health monitor of the Active (`None`: not monitored, for example in tests).
    health: Option<HealthMonitor>,
    last_status: Option<(StatusView, Instant)>,
    pub(crate) exited: bool,
    pub(crate) failed: bool,
}

/// `[health]` of the Active (two-node): how often, the hysteresis, and what to do.
#[derive(Debug, Clone)]
pub(crate) struct HealthPolicy {
    pub(crate) action: crate::config::HealthAction,
    pub(crate) failure_threshold: u32,
    pub(crate) success_threshold: u32,
    pub(crate) restart_limit: u32,
}

impl HealthPolicy {
    pub(crate) fn from_config(config: &crate::config::Config) -> Self {
        Self {
            action: config.health.on_failure,
            failure_threshold: config.health.failure_threshold,
            success_threshold: config.health.success_threshold,
            restart_limit: config.health.restart_limit,
        }
    }
}

/// The interval of the health check while Active.
pub(crate) const HEALTH_INTERVAL: Duration = Duration::from_secs(2);
/// A refused health failover is asked again at most this often while unhealthy.
const HEALTH_FAILOVER_RETRY: Duration = Duration::from_secs(30);

struct HealthMonitor {
    policy: HealthPolicy,
    filter: crate::health_hysteresis::HealthHysteresis,
    last_check: Option<Instant>,
    restarts: VecDeque<Instant>,
    last_failover_request: Option<Instant>,
    view: HealthView,
}

/// The health part of the status file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HealthView {
    /// `unknown`, `healthy` or `unhealthy` (the stable state after the thresholds).
    pub(crate) state: String,
    pub(crate) consecutive_failures: u32,
    pub(crate) consecutive_successes: u32,
    pub(crate) on_failure: String,
    pub(crate) restarts_in_window: u32,
    pub(crate) last_check_unix: u64,
    pub(crate) last_action: Option<String>,
}

impl HealthMonitor {
    fn new(policy: HealthPolicy) -> Self {
        let filter = crate::health_hysteresis::HealthHysteresis::new(
            policy.failure_threshold,
            policy.success_threshold,
        );
        let on_failure = format!("{:?}", policy.action).to_lowercase();
        Self {
            policy,
            filter,
            last_check: None,
            restarts: VecDeque::new(),
            last_failover_request: None,
            view: HealthView {
                state: "unknown".into(),
                on_failure,
                ..HealthView::default()
            },
        }
    }

    /// A new hysteresis (after a role change or a restart); the history of actions stays.
    fn reset(&mut self) {
        self.filter = crate::health_hysteresis::HealthHysteresis::new(
            self.policy.failure_threshold,
            self.policy.success_threshold,
        );
        self.view.state = "unknown".into();
        self.view.consecutive_failures = 0;
        self.view.consecutive_successes = 0;
    }
}

pub(crate) struct DriverParts<F: FenceRunner, R: ResourceOps> {
    pub(crate) controller_config: super::controller::ControllerConfig,
    pub(crate) incarnation: String,
    pub(crate) loaded: Result<super::store::OwnershipState, super::store::LoadError>,
    pub(crate) store: Box<dyn DurableStore + Send>,
    pub(crate) fence: F,
    pub(crate) ops: R,
    pub(crate) shared: Arc<LinkShared>,
    pub(crate) inbound: Receiver<PeerMessage>,
    pub(crate) links: Vec<LinkConfig>,
    pub(crate) status_path: Option<PathBuf>,
    pub(crate) operator_dir: Option<PathBuf>,
    pub(crate) guard: Box<dyn Fn() -> Result<(), String> + Send>,
    pub(crate) config_summary: Option<String>,
    pub(crate) health: Option<HealthPolicy>,
}

impl<F: FenceRunner, R: ResourceOps> Driver<F, R> {
    pub(crate) fn start(parts: DriverParts<F, R>) -> Self {
        let DriverParts {
            controller_config,
            incarnation,
            loaded,
            mut store,
            fence,
            ops,
            shared,
            inbound,
            links,
            status_path,
            operator_dir,
            guard,
            config_summary,
            health,
        } = parts;
        let cluster = controller_config.cluster_id.clone();
        let peer = controller_config.peer_id.clone();
        let origin = Instant::now();
        let (controller, effects) =
            Controller::start(controller_config, incarnation, loaded, 0, store.as_mut());
        let link_count = links.len();
        let mut driver = Self {
            controller,
            store,
            fence,
            ops,
            shared,
            inbound,
            origin,
            links,
            status_path,
            operator_dir,
            cluster,
            peer,
            guard,
            last_links: vec![false; link_count],
            last_incompatible: None,
            config_summary,
            health: health.map(HealthMonitor::new),
            last_status: None,
            exited: false,
            failed: false,
        };
        driver.execute(effects);
        driver
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    pub(crate) fn handle(&mut self, event: Event) {
        if self.exited {
            return;
        }
        let now = self.now_ms();
        let effects = self.controller.handle(now, event, self.store.as_mut());
        self.execute(effects);
    }

    fn protected(&mut self) -> bool {
        match (self.guard)() {
            Ok(()) => true,
            Err(error) => {
                if !self.failed {
                    eprintln!(
                        "mikagami: ERROR the control lock became unsafe ({error}); no further \
                         protected effect, stopping"
                    );
                }
                self.failed = true;
                false
            }
        }
    }

    fn execute(&mut self, effects: Vec<Effect>) {
        let mut queue: VecDeque<Effect> = effects.into();
        while let Some(effect) = queue.pop_front() {
            let follow = match effect {
                Effect::Publish(state) => {
                    self.shared.publish(state);
                    None
                }
                Effect::Send(body) => {
                    if self.shared.queue_control(body).is_none() {
                        eprintln!("mikagami: ERROR could not queue a control message");
                    }
                    None
                }
                Effect::RunFence {
                    incident_seq,
                    attempt,
                    op_id,
                } => {
                    let outcome = if self.protected() {
                        self.fence.fence(incident_seq, attempt, &op_id)
                    } else {
                        FenceAction::SpawnFailed
                    };
                    Some(Event::FenceActionDone { op_id, outcome })
                }
                Effect::RunVerify {
                    incident_seq,
                    attempt,
                    op_id,
                    ..
                } => {
                    let verdict = if self.protected() {
                        self.fence.verify(incident_seq, attempt, &op_id)
                    } else {
                        Verdict::Inconclusive
                    };
                    Some(Event::VerifyDone { op_id, verdict })
                }
                Effect::Acquire { .. } => {
                    let result = if self.protected() {
                        self.ops.acquire()
                    } else {
                        AcquireResult::Failed
                    };
                    Some(Event::AcquireDone(result))
                }
                Effect::Release { .. } => {
                    let zero = if self.protected() {
                        self.ops.release()
                    } else {
                        false
                    };
                    Some(Event::ReleaseDone {
                        zero_resource: zero,
                    })
                }
                Effect::Log(line) => {
                    eprintln!("mikagami: {line}");
                    None
                }
                Effect::Exit => {
                    self.exited = true;
                    None
                }
            };
            if let Some(event) = follow
                && !self.exited
            {
                // A step may have taken seconds: hand the controller what arrived and the
                // current link state first, so a peer that answered meanwhile retires the
                // incident before its result is applied.
                let mut events: Vec<Event> = Vec::new();
                if matches!(
                    event,
                    Event::FenceActionDone { .. } | Event::VerifyDone { .. }
                ) {
                    while let Ok(message) = self.inbound.try_recv() {
                        events.push(Event::Peer(message));
                    }
                    let links = self.shared.links_up();
                    if links != self.last_links {
                        self.last_links = links.clone();
                        events.push(Event::Links(links));
                    }
                    if let Some(event) = self.incompatible_change() {
                        events.push(event);
                    }
                }
                events.push(event);
                for event in events {
                    let now = self.now_ms();
                    queue.extend(self.controller.handle(now, event, self.store.as_mut()));
                }
            }
        }
        self.refresh_status(false);
    }

    /// The change of the peer's incompatibility since the last call, logged once per change
    /// with the differing sections.
    fn incompatible_change(&mut self) -> Option<Event> {
        let now = self.shared.peer_incompatible();
        if now.is_some() == self.last_incompatible.is_some() {
            return None;
        }
        match &now {
            Some(peer) => {
                let sections = match (&self.config_summary, peer) {
                    (Some(mine), Some(theirs)) => {
                        super::shared::differing_sections(mine, theirs).join(", ")
                    }
                    (Some(_), None) => "the peer uses a per-node configuration file".to_string(),
                    (None, _) => "this node uses a per-node configuration file".to_string(),
                };
                eprintln!(
                    "mikagami: ERROR config mismatch: the peer {} is alive but its configuration \
                     differs ({sections}); it is not admitted, this is not a peer loss: no \
                     fence, takeover or bootstrap until both nodes use the same configuration",
                    self.peer
                );
            }
            None => eprintln!("mikagami: INFO config mismatch with the peer no longer observed"),
        }
        self.last_incompatible = now.clone();
        Some(Event::PeerIncompatible(now.is_some()))
    }

    fn refresh_incompatible(&mut self) {
        if let Some(event) = self.incompatible_change() {
            self.handle(event);
        }
    }

    /// The Active's periodic health check and its `on_failure` action. Never runs on a node
    /// that is not Active (its state is reset there).
    fn monitor_health(&mut self) {
        use crate::config::HealthAction;
        use crate::health_hysteresis::{HealthTransition, RawHealth, StableHealth};
        if self.exited || self.failed {
            return;
        }
        let Some(mut monitor) = self.health.take() else {
            return;
        };
        if self.controller.role() != wire::Role::Active {
            if monitor.last_check.is_some() {
                monitor.reset();
                monitor.last_check = None;
            }
            self.health = Some(monitor);
            return;
        }
        if monitor
            .last_check
            .is_some_and(|at| at.elapsed() < HEALTH_INTERVAL)
        {
            self.health = Some(monitor);
            return;
        }
        monitor.last_check = Some(Instant::now());
        monitor.view.last_check_unix = unix_now();
        let raw = match self.ops.observe_health() {
            Some(true) => RawHealth::Healthy,
            Some(false) => RawHealth::Unhealthy,
            None => RawHealth::Unknown,
        };
        let transition = monitor.filter.observe(raw);
        let (failures, successes) = monitor.filter.counts();
        monitor.view.consecutive_failures = failures;
        monitor.view.consecutive_successes = successes;
        monitor.view.state = match monitor.filter.stable() {
            StableHealth::Unknown => "unknown",
            StableHealth::Healthy => "healthy",
            StableHealth::Unhealthy => "unhealthy",
        }
        .into();
        let mut event = None;
        match transition {
            Some(HealthTransition::Recovered) => {
                eprintln!("mikagami: INFO health recovered");
            }
            Some(HealthTransition::BecameUnhealthy {
                consecutive_failures,
            }) => {
                eprintln!(
                    "mikagami: WARN health unhealthy after {consecutive_failures} consecutive \
                     failures (on_failure = {})",
                    monitor.view.on_failure
                );
                match monitor.policy.action {
                    HealthAction::Warn => {}
                    HealthAction::Restart => {
                        let window = Duration::from_secs(crate::config::HEALTH_RESTART_WINDOW_SEC);
                        while monitor
                            .restarts
                            .front()
                            .is_some_and(|at| at.elapsed() >= window)
                        {
                            monitor.restarts.pop_front();
                        }
                        if monitor.restarts.len() >= monitor.policy.restart_limit as usize {
                            monitor.view.last_action =
                                Some("restart limit reached (warn only)".into());
                            eprintln!(
                                "mikagami: WARN health restart limit ({} per {} s) reached; \
                                 warn only",
                                monitor.policy.restart_limit,
                                crate::config::HEALTH_RESTART_WINDOW_SEC
                            );
                        } else if !self.protected() {
                            // The control lock is gone: no restart (a protected effect).
                            self.health = Some(monitor);
                            return;
                        } else {
                            monitor.restarts.push_back(Instant::now());
                            match self.ops.restart() {
                                RestartOutcome::Restarted => {
                                    eprintln!("mikagami: INFO health restart done; healthy");
                                    monitor.view.last_action = Some("restarted".into());
                                    monitor.reset();
                                }
                                RestartOutcome::NotSupported => {
                                    monitor.view.last_action = Some("restart not supported".into());
                                }
                                RestartOutcome::StopUnconfirmed(why)
                                | RestartOutcome::StartFailed(why) => {
                                    eprintln!(
                                        "mikagami: WARN health restart failed at {why}; releasing \
                                         the resources"
                                    );
                                    monitor.view.last_action =
                                        Some(format!("restart failed at {why}; released"));
                                    event = Some(Event::LocalResourceFailure);
                                }
                            }
                        }
                        monitor.view.restarts_in_window =
                            u32::try_from(monitor.restarts.len()).unwrap_or(u32::MAX);
                    }
                    HealthAction::Failover => {
                        monitor.last_failover_request = Some(Instant::now());
                        monitor.view.last_action = Some("failover requested".into());
                        event = Some(Event::HealthFailover);
                    }
                }
            }
            None => {
                if monitor.policy.action == HealthAction::Failover
                    && monitor.filter.stable() == StableHealth::Unhealthy
                    && monitor
                        .last_failover_request
                        .is_none_or(|at| at.elapsed() >= HEALTH_FAILOVER_RETRY)
                {
                    monitor.last_failover_request = Some(Instant::now());
                    monitor.view.last_action = Some("failover requested again".into());
                    event = Some(Event::HealthFailover);
                }
            }
        }
        self.health = Some(monitor);
        if let Some(event) = event {
            self.handle(event);
        }
    }

    /// One loop slice: inbound messages, link status, operator signals, tick.
    pub(crate) fn step(&mut self, promotion_signal: bool, shutdown_signal: bool) {
        if shutdown_signal {
            self.handle(Event::Shutdown);
        }
        if promotion_signal {
            self.on_promotion_signal();
        }
        let deadline = Instant::now() + LOOP_SLICE;
        while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
            match self.inbound.recv_timeout(remaining) {
                Ok(message) => self.handle(Event::Peer(message)),
                Err(_) => break,
            }
            if self.exited {
                return;
            }
        }
        let links = self.shared.links_up();
        if links != self.last_links {
            self.last_links = links.clone();
            self.handle(Event::Links(links));
        }
        self.refresh_incompatible();
        self.handle(Event::Tick);
        self.monitor_health();
        if self.failed && !self.exited {
            // The control lock is gone: stop without further protected effects.
            self.exited = true;
        }
        self.refresh_status(false);
    }

    fn on_promotion_signal(&mut self) {
        let mut handled = false;
        if let Some(dir) = self.operator_dir.clone() {
            let (requests, problems) = take_operator_requests(&dir, &self.cluster);
            for problem in problems {
                eprintln!("mikagami: WARN operator request ignored: {problem}");
            }
            for request in requests {
                handled = true;
                match request.kind {
                    OperatorKind::AttestPeerStopped => self.handle(Event::OperatorAttest {
                        attestation_id: request.attestation_id,
                        target: request.target,
                    }),
                    OperatorKind::Fence => self.handle(Event::OperatorFence {
                        target: request.target,
                    }),
                }
            }
        }
        if !handled {
            self.handle(Event::PromotionRequest);
        }
    }

    pub(crate) fn status(&self) -> StatusView {
        let durable = self.controller.durable();
        let up = self.controller.links().to_vec();
        StatusView {
            node: durable.node_id.clone(),
            peer: self.peer.clone(),
            incarnation: self.controller.incarnation().to_string(),
            role: self.controller.role().as_str().to_string(),
            epoch: durable.epoch,
            owner: durable.owner.clone(),
            record_ok: self.controller.store_ok(),
            contradiction: self.controller.contradiction(),
            peer_connected: self.controller.peer_connected(),
            config_mismatch: self.controller.peer_incompatible(),
            resources: self.ops.resource_states(),
            health: self.health.as_ref().map(|monitor| monitor.view.clone()),
            links: self
                .links
                .iter()
                .map(|l| LinkStatusView {
                    index: l.index,
                    segment: l.segment.clone(),
                    role: l.role.as_str().to_string(),
                    interface: l.interface.clone(),
                    up: up.get(usize::from(l.index)).copied().unwrap_or(false),
                })
                .collect(),
            incident: durable
                .incident
                .as_ref()
                .map(|i| format!("seq {} attempt {} {:?}", i.seq, i.attempt, i.state)),
            grant_outstanding: durable.grant.is_some(),
            updated_unix: 0,
        }
    }

    fn refresh_status(&mut self, force: bool) {
        let Some(path) = self.status_path.clone() else {
            return;
        };
        let current = self.status();
        let due = match &self.last_status {
            None => true,
            Some((last, at)) => force || last != &current || at.elapsed() >= STATUS_REFRESH,
        };
        if !due {
            return;
        }
        let mut stamped = current.clone();
        stamped.updated_unix = unix_now();
        if let Err(error) = write_status(&path, &stamped) {
            eprintln!("mikagami: WARN status file {}: {error}", path.display());
        }
        self.last_status = Some((current, Instant::now()));
    }
}

// ---- production entry ----------------------------------------------------------------------

static SHUTDOWN: AtomicBool = AtomicBool::new(false);
static PROMOTION: AtomicBool = AtomicBool::new(false);

extern "C" fn on_shutdown(_: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

extern "C" fn on_promotion(_: libc::c_int) {
    PROMOTION.store(true, Ordering::SeqCst);
}

fn install_signals() {
    // SAFETY: plain flag-setting handlers are async-signal safe (no allocation or locking).
    unsafe {
        let shutdown: extern "C" fn(libc::c_int) = on_shutdown;
        let promotion: extern "C" fn(libc::c_int) = on_promotion;
        libc::signal(libc::SIGINT, shutdown as libc::sighandler_t);
        libc::signal(libc::SIGTERM, shutdown as libc::sighandler_t);
        libc::signal(libc::SIGUSR1, promotion as libc::sighandler_t);
    }
}

/// The control-lock and manual-barrier start gate (the same rule as the Witness topology).
fn control_gate(
    config: &crate::config::Config,
) -> Result<crate::control_lock::ControlLock, String> {
    let lock = crate::control_lock::ControlLock::acquire(
        Path::new(&config.control.lock_path),
        crate::attestation::ROOT_UID,
    )
    .map_err(|error| format!("refusing to start the two-node daemon: {error}"))?;
    lock.verify()
        .map_err(|error| format!("refusing to start the two-node daemon: {error}"))?;
    match crate::manual_barrier::check(
        Path::new(&config.control.manual_barrier_path),
        crate::attestation::ROOT_UID,
        &config.cluster.id,
        &config.node.id,
    ) {
        Ok(crate::manual_barrier::BarrierState::Clear) => Ok(lock),
        Ok(crate::manual_barrier::BarrierState::Open(record)) => Err(format!(
            "refusing to start the two-node daemon: a manual operation ({}) may still be in \
             flight on this node",
            record.op_id
        )),
        Err(error) => Err(format!(
            "refusing to start the two-node daemon: the manual-operation barrier is not \
             provably clear: {error}"
        )),
    }
}

/// `daemon run` for `cluster.topology = "two-node"` (Linux).
#[cfg(target_os = "linux")]
pub(crate) fn run_daemon(config: crate::config::Config, arping: &Path) -> Result<(), String> {
    use crate::config::ServiceManager;
    use crate::resource_executor::{
        ExternalServiceBackend, LinuxNetworkBackend, LinuxNetworkConfig,
        LinuxSystemdServiceBackend, ResourceExecutor, ServiceAdapter,
    };
    use std::sync::mpsc::channel;
    install_signals();
    let two_node = config
        .two_node
        .clone()
        .ok_or("not a two-node configuration")?;
    let lock = Arc::new(control_gate(&config)?);
    let psk = Psk::load(Path::new(&config.security.psk_file))
        .map_err(|error| format!("could not load the PSK: {error}"))?;
    let settings = crate::fencing_backend::FencingSettings::startup(config.fencing.as_ref())
        .map_err(|error| error.to_string())?;
    for warning in config.startup_warnings() {
        crate::operator_log::warn_startup(&warning);
    }
    let network = LinuxNetworkBackend::new(
        LinuxNetworkConfig::from_cidr(
            config.vip.interface.clone(),
            &config.vip.address,
            arping.to_path_buf(),
            config.vip.arp_count,
        )
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let health_timeout = Duration::from_secs(config.health.timeout_sec);
    // One service backend per configured service (the single [service], or each service of
    // the group), all with the same [health] command.
    let backend = |service: &crate::config::ServiceConfig| -> Result<ServiceAdapter, String> {
        let start_timeout = Duration::from_secs(service.start_timeout_sec);
        let stop_timeout = Duration::from_secs(service.stop_timeout_sec);
        Ok(match service.manager {
            ServiceManager::Systemd => ServiceAdapter::Systemd(
                LinuxSystemdServiceBackend::new(
                    service.unit.clone().ok_or("service unit is required")?,
                    start_timeout,
                    stop_timeout,
                    config.health.command.clone(),
                    health_timeout,
                )
                .map_err(|error| error.to_string())?,
            ),
            ServiceManager::Command => ServiceAdapter::External(
                ExternalServiceBackend::new(
                    service.start.clone().ok_or("service start is required")?,
                    service.stop.clone().ok_or("service stop is required")?,
                    service.status.clone().ok_or("service status is required")?,
                    config.health.command.clone(),
                    start_timeout,
                    stop_timeout,
                    health_timeout,
                )
                .map_err(|error| error.to_string())?,
            ),
        })
    };
    let ops: Box<dyn ResourceOps> = match &config.group {
        None => Box::new(ExecutorOps::new(ResourceExecutor::new(
            network,
            backend(&config.service)?,
        ))),
        Some(group) => {
            let mut members = Vec::new();
            for resource in &group.resources {
                members.push(match &resource.kind {
                    crate::config::GroupResourceKind::Vip => GroupMember::Vip {
                        name: resource.name.clone(),
                    },
                    crate::config::GroupResourceKind::Service(service) => GroupMember::Service {
                        name: resource.name.clone(),
                        executor: ResourceExecutor::new(NoNetwork, backend(service)?),
                    },
                });
            }
            Box::new(GroupOps::new(network, members))
        }
    };
    let controller_config = super::controller::ControllerConfig::from_config(&config)
        .ok_or("not a two-node configuration")?;
    let store = super::store::FileStore::new(&two_node.state_path);
    let loaded = store.load(&config.cluster.id, &config.node.id);
    let incarnation = crate::node_mutation::generate_uuid().ok_or("no randomness")?;
    let shared = LinkShared::new(two_node.links.len());
    let (sender, receiver) = channel();
    let identity = LinkIdentity {
        cluster: config.cluster.id.clone(),
        local: config.node.id.clone(),
        peer: config.peer.id.clone(),
        incarnation: incarnation.clone(),
        config: two_node.config_summary.clone(),
    };
    let threads = spawn_links(&identity, &two_node.links, &psk, &shared, &sender);
    drop(sender);
    let guard_lock = Arc::clone(&lock);
    let guard: Box<dyn Fn() -> Result<(), String> + Send> =
        Box::new(move || guard_lock.verify().map_err(|e| e.to_string()));
    let common = Common {
        controller_config,
        incarnation,
        loaded,
        store: Box::new(super::store::FileStore::new(&two_node.state_path)),
        shared: Arc::clone(&shared),
        inbound: receiver,
        links: two_node.links.clone(),
        status_path: Some(PathBuf::from(&two_node.status_path)),
        operator_dir: Some(PathBuf::from(&two_node.operator_dir)),
        guard,
        config_summary: two_node.config_summary.clone(),
        health: Some(HealthPolicy::from_config(&config)),
    };
    let failed = match settings.command().cloned() {
        Some(command) => run_loop(Driver::start(common.into_parts(
            CommandFenceRunner::new(command, &config.cluster.id, &config.peer.id),
            ops,
        ))),
        None => run_loop(Driver::start(common.into_parts(NoFence, ops))),
    };
    shared.stop.store(true, Ordering::SeqCst);
    for thread in threads {
        let _ = thread.join();
    }
    drop(lock);
    if failed {
        Err("the two-node daemon stopped on a safety boundary (see the log)".into())
    } else {
        Ok(())
    }
}

/// The fence-independent part of [`DriverParts`].
pub(crate) struct Common {
    pub(crate) controller_config: super::controller::ControllerConfig,
    pub(crate) incarnation: String,
    pub(crate) loaded: Result<super::store::OwnershipState, super::store::LoadError>,
    pub(crate) store: Box<dyn DurableStore + Send>,
    pub(crate) shared: Arc<LinkShared>,
    pub(crate) inbound: Receiver<PeerMessage>,
    pub(crate) links: Vec<LinkConfig>,
    pub(crate) status_path: Option<PathBuf>,
    pub(crate) operator_dir: Option<PathBuf>,
    pub(crate) guard: Box<dyn Fn() -> Result<(), String> + Send>,
    pub(crate) config_summary: Option<String>,
    pub(crate) health: Option<HealthPolicy>,
}

impl Common {
    pub(crate) fn into_parts<F: FenceRunner, R: ResourceOps>(
        self,
        fence: F,
        ops: R,
    ) -> DriverParts<F, R> {
        DriverParts {
            controller_config: self.controller_config,
            incarnation: self.incarnation,
            loaded: self.loaded,
            store: self.store,
            fence,
            ops,
            shared: self.shared,
            inbound: self.inbound,
            links: self.links,
            status_path: self.status_path,
            operator_dir: self.operator_dir,
            guard: self.guard,
            config_summary: self.config_summary,
            health: self.health,
        }
    }
}

#[cfg(target_os = "linux")]
fn run_loop<F: FenceRunner, R: ResourceOps>(mut driver: Driver<F, R>) -> bool {
    while !driver.exited {
        let promotion = PROMOTION.swap(false, Ordering::SeqCst);
        let shutdown = SHUTDOWN.swap(false, Ordering::SeqCst);
        driver.step(promotion, shutdown);
    }
    driver.failed
}

/// Non-Linux platforms have no production resource backends.
#[cfg(not(target_os = "linux"))]
pub(crate) fn run_daemon(_config: crate::config::Config, _arping: &Path) -> Result<(), String> {
    let _ = (
        install_signals as fn(),
        control_gate as fn(&crate::config::Config) -> _,
    );
    Err("the two-node daemon is supported on Linux only".into())
}

#[cfg(test)]
mod tests;
