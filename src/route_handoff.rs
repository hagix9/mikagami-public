//! v0.7 G-2 route handoff (RH): moving the GCE alias IP route to the new Active after an internal
//! promotion (`G2_SAFETY_CONTRACT.md` R4.1).
//!
//! This module is the platform-independent core: the RH record and its durable store, the state
//! machine, the step selection with the lease-renewal execution budget, and the fixed grammar of
//! the helper's answers. The Linux runtime only supplies a [`RhPlatform`] (node state, lease
//! timing, the one bounded helper step); nothing here touches the network.
//!
//! Safety rules (contract R4.1):
//!
//! - RH never changes `NodeState`, `PromotionPhase` or `PromotionAttemptResult`. It starts only
//!   after `PromotionAttemptResult::Succeeded` and is a separate record.
//! - The one automatic GCE write is `route-assign`, at most once per term, and only when the
//!   clearance's mint-time provenance is `ConfirmedBy::Backend` (G-A2) and the helper's own fence
//!   records prove the stop and the alias removal of the same incident and attempt (G-A3, checked
//!   by `route-check` before `sent = yes` and again by `route-assign`).
//! - `sent` is durable before the helper is spawned and never goes back to `no`. A `sent` RH is
//!   never confirmed without the matching operation observed `DONE` without error (C-5).
//! - `ROUTE_CONFIRMED` needs the new NIC to hold every protected range and the peer to hold none,
//!   in two observation cycles at least `confirm_hold` apart (C-2..C-4), while this node is still
//!   the Active of the same term (C-1). It is never reported as the switchover's success: service
//!   reachability is not checked by this node.
//! - A step runs only right after a successful lease renewal, as the last blocking work of the
//!   loop iteration, with at least `RH_MIN_LEASE_REMAINING` left on the lease immediately before the
//!   spawn, and with the RH-only deadline set of the command backend (`RH_STEP_RETURN_BUDGET`).
//! - No automatic retry of the write, no removal, no rollback, no demotion. Failures and unknown
//!   outcomes are shown as operator-required states.

// The driver is called from the Linux runtime; on a non-Linux development host only the tests and
// the read-only status path use it.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The RH record and intent format version. Any other version is not read as a record.
pub(crate) const RH_RECORD_VERSION: u32 = 1;

/// `S` (contract R4.1 §5.1): the latest return of a route step after its start. The command
/// backend's RH-only deadline set sums to exactly this (asserted there).
pub(crate) const RH_STEP_RETURN_BUDGET: Duration = Duration::from_millis(3_000);
/// `Q`: the lease renewal request timeout (`config::LEASE_REQUEST_TIMEOUT_SEC`).
pub(crate) const RH_RENEW_REQUEST_TIMEOUT: Duration =
    Duration::from_secs(crate::config::LEASE_REQUEST_TIMEOUT_SEC);
/// `ε`: the margin left before the safe deadline after a worst-case renewal.
pub(crate) const RH_MARGIN: Duration = Duration::from_millis(1_000);
/// `G = S + Q + ε` (contract R4.1 §5.1): the lease time that must remain immediately before a
/// route step is spawned.
pub(crate) const RH_MIN_LEASE_REMAINING: Duration = Duration::from_millis(
    RH_STEP_RETURN_BUDGET.as_millis() as u64
        + RH_RENEW_REQUEST_TIMEOUT.as_millis() as u64
        + RH_MARGIN.as_millis() as u64,
);
/// The cadence of the read-only observation once confirmed, past the deadline, or while an
/// operator decision is pending.
pub(crate) const RH_SLOW_INTERVAL: Duration = Duration::from_secs(30);
/// r17 (contract R5 R-5): the least time from the original request to its one re-issue.
pub(crate) const RH_REISSUE_MIN_AFTER_SEND: Duration = Duration::from_secs(20);
/// r17 (contract R5 R-5): the re-issue window closes this long before the RH deadline, leaving
/// time for the confirmation (C-4 hold and the operation DONE) and for the operator procedure.
pub(crate) const RH_REISSUE_DEADLINE_MARGIN: Duration = Duration::from_secs(60);
/// r17 (contract R5 R-4): complete lists without the term's operation before a re-issue.
pub(crate) const RH_REISSUE_ABSENT_READS: u32 = 2;
/// r17: a readiness older than this (the re-issue was held by the lease, lock or step conditions)
/// is dropped; the next complete absent cycle may arm it again from fresh observations.
pub(crate) const RH_REISSUE_READY_MAX_AGE: Duration = Duration::from_secs(10);
/// Largest record or intent file read back (they are a few hundred bytes).
const RH_MAX_FILE_BYTES: u64 = 16 * 1024;

const _: () = assert!(RH_MIN_LEASE_REMAINING.as_millis() == 6_000);

// ---------------------------------------------------------------------------------------------
// Record
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum RhConfirmation {
    Backend,
    Operator,
}

/// Where the promotion that started this RH came from (mint-time provenance, G-A1/G-A2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum RhOrigin {
    Fencing {
        incident_seq: u64,
        incident_id: String,
        attempt_token: u64,
        confirmed_by: RhConfirmation,
    },
    Bootstrap,
    /// No provenance reached the RH (never automates).
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum NotAutomatedReason {
    Bootstrap,
    OperatorAttested,
    NoProvenance,
}

impl NotAutomatedReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::Bootstrap => "bootstrap",
            Self::OperatorAttested => "operator-attested",
            Self::NoProvenance => "no-provenance",
        }
    }
}

/// The RH states of contract R4.1 §1.2. `sent` is kept beside the state, never inside it, so no
/// transition can reset it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum RhState {
    NotAutomated { reason: NotAutomatedReason },
    IntentRecorded,
    Requested,
    Observing,
    RouteConfirmed { at_unix_ms: u64 },
    RoutePartial,
    RouteLost,
    RouteFailed,
    RouteUnknown,
    Abandoned { reason: String },
}

impl RhState {
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Self::NotAutomated { .. } => "NOT_AUTOMATED",
            Self::IntentRecorded => "INTENT_RECORDED",
            Self::Requested => "REQUESTED",
            Self::Observing => "OBSERVING",
            Self::RouteConfirmed { .. } => "ROUTE_CONFIRMED",
            Self::RoutePartial => "ROUTE_PARTIAL",
            Self::RouteLost => "ROUTE_LOST",
            Self::RouteFailed => "ROUTE_FAILED",
            Self::RouteUnknown => "ROUTE_UNKNOWN",
            Self::Abandoned { .. } => "ABANDONED",
        }
    }

    /// States that need an operator decision (contract §1.2).
    pub(crate) fn operator_required(&self) -> bool {
        matches!(
            self,
            Self::NotAutomated { .. }
                | Self::RoutePartial
                | Self::RouteLost
                | Self::RouteFailed
                | Self::RouteUnknown
        )
    }

    fn terminal(&self) -> bool {
        matches!(self, Self::Abandoned { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RhRecord {
    pub(crate) version: u32,
    pub(crate) cluster: String,
    pub(crate) node: String,
    pub(crate) peer_node: String,
    pub(crate) term: u64,
    pub(crate) origin: RhOrigin,
    pub(crate) state: RhState,
    /// Monotonic: `true` from the durable write before `route-assign` is spawned, for ever.
    pub(crate) sent: bool,
    /// `route-check` answered `ok` for this record's incident and attempt.
    pub(crate) checked: bool,
    pub(crate) reason: String,
    pub(crate) updated_unix_ms: u64,
    /// The last complete observation cycle (audit M-1): when, and what C-2 (own), C-3 (peer)
    /// and, for a sent RH, C-5 (op) showed. Display only.
    #[serde(default)]
    pub(crate) last_observed_unix_ms: Option<u64>,
    #[serde(default)]
    pub(crate) last_cycle: Option<String>,
    /// r17 (contract R5 R-2): monotonic, `true` from the durable write before `route-reissue` is
    /// spawned, for ever. At most one re-issue per term.
    #[serde(default)]
    pub(crate) reissued: bool,
    /// r17 (contract R5 R-3): monotonic, `true` once an operation of this term's request was
    /// seen (pending, done or ambiguous). No re-issue afterwards.
    #[serde(default)]
    pub(crate) op_seen: bool,
}

impl RhRecord {
    fn sent_label(&self) -> &'static str {
        if self.sent { "sent" } else { "not-sent" }
    }

    /// The one-line operator description of the record (status and journal).
    pub(crate) fn describe(&self) -> String {
        let state = match &self.state {
            RhState::NotAutomated { reason } => format!("NOT_AUTOMATED({})", reason.as_str()),
            RhState::Abandoned { reason } => format!("ABANDONED({reason})"),
            RhState::RouteConfirmed { at_unix_ms } => format!("ROUTE_CONFIRMED(at={at_unix_ms})"),
            other => other.name().to_string(),
        };
        format!("{state} ({}) term={}", self.sent_label(), self.term)
    }
}

/// The binding the helper reads (`route-check`, `route-observe`, `route-assign`): written once,
/// durably, before the first step of the term. The helper's own configuration stays authoritative
/// for every instance identity; this file only names the attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RhIntent {
    pub(crate) version: u32,
    pub(crate) cluster: String,
    pub(crate) node: String,
    pub(crate) peer_node: String,
    pub(crate) term: u64,
    pub(crate) origin: RhOrigin,
}

// ---------------------------------------------------------------------------------------------
// Durable store
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RhStoreError {
    Untrusted(String),
    Io(String),
    Unreadable(String),
}

impl fmt::Display for RhStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Untrusted(detail) => write!(formatter, "untrusted route directory: {detail}"),
            Self::Io(detail) => write!(formatter, "route record I/O failure: {detail}"),
            Self::Unreadable(detail) => write!(formatter, "unreadable route record: {detail}"),
        }
    }
}

fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

/// The RH directory (`route.intent_dir`): owned by the effective user, mode 0700, not a symlink.
/// One record file and one intent file per term. Shared with the helper, which validates the
/// same properties before it reads an intent.
#[derive(Debug, Clone)]
pub(crate) struct RhStore {
    dir: PathBuf,
}

impl RhStore {
    pub(crate) fn open(dir: &Path) -> Result<Self, RhStoreError> {
        let metadata = fs::symlink_metadata(dir)
            .map_err(|error| RhStoreError::Untrusted(format!("{}: {error}", dir.display())))?;
        if !metadata.is_dir() || metadata.uid() != effective_uid() || metadata.mode() & 0o077 != 0 {
            return Err(RhStoreError::Untrusted(format!(
                "{} must be a directory owned by this user with mode 0700",
                dir.display()
            )));
        }
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    pub(crate) fn record_path(&self, term: u64) -> PathBuf {
        self.dir.join(format!("rh-{term}.json"))
    }

    pub(crate) fn intent_path(&self, term: u64) -> PathBuf {
        self.dir.join(format!("rh-{term}.intent.json"))
    }

    fn write_atomic(&self, path: &Path, text: &str) -> Result<(), RhStoreError> {
        let io = |error: std::io::Error| RhStoreError::Io(error.to_string());
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| RhStoreError::Io("bad record name".to_string()))?;
        let temporary = self.dir.join(format!(".tmp-{name}-{}", std::process::id()));
        let _ = fs::remove_file(&temporary);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)
            .map_err(io)?;
        file.write_all(text.as_bytes()).map_err(io)?;
        file.write_all(b"\n").map_err(io)?;
        file.sync_all().map_err(io)?;
        drop(file);
        fs::rename(&temporary, path).map_err(io)?;
        File::open(&self.dir)
            .and_then(|directory| directory.sync_all())
            .map_err(io)
    }

    pub(crate) fn save(&self, record: &RhRecord) -> Result<(), RhStoreError> {
        let text = serde_json::to_string_pretty(record)
            .map_err(|error| RhStoreError::Io(error.to_string()))?;
        self.write_atomic(&self.record_path(record.term), &text)
    }

    /// Writes the term's intent once. An existing intent must be identical (never rebound).
    pub(crate) fn write_intent(&self, intent: &RhIntent) -> Result<(), RhStoreError> {
        let path = self.intent_path(intent.term);
        match read_bounded(&path) {
            Ok(Some(text)) => {
                let existing: RhIntent = serde_json::from_str(&text)
                    .map_err(|error| RhStoreError::Unreadable(error.to_string()))?;
                return if &existing == intent {
                    Ok(())
                } else {
                    Err(RhStoreError::Unreadable(
                        "an intent of this term with another binding exists".to_string(),
                    ))
                };
            }
            Ok(None) => {}
            Err(error) => return Err(error),
        }
        let text = serde_json::to_string_pretty(intent)
            .map_err(|error| RhStoreError::Io(error.to_string()))?;
        self.write_atomic(&path, &text)
    }

    pub(crate) fn load(&self, term: u64) -> Result<Option<RhRecord>, RhStoreError> {
        let Some(text) = read_bounded(&self.record_path(term))? else {
            return Ok(None);
        };
        let record: RhRecord = serde_json::from_str(&text)
            .map_err(|error| RhStoreError::Unreadable(error.to_string()))?;
        if record.version != RH_RECORD_VERSION || record.term != term {
            return Err(RhStoreError::Unreadable(
                "the record's version or term does not match its name".to_string(),
            ));
        }
        Ok(Some(record))
    }

    /// The terms of every record file (`rh-<term>.json`), ascending.
    pub(crate) fn terms(&self) -> Result<Vec<u64>, RhStoreError> {
        let mut terms = Vec::new();
        for entry in fs::read_dir(&self.dir).map_err(|error| RhStoreError::Io(error.to_string()))? {
            let entry = entry.map_err(|error| RhStoreError::Io(error.to_string()))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if let Some(term) = name
                .strip_prefix("rh-")
                .and_then(|rest| rest.strip_suffix(".json"))
                .filter(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|digits| digits.parse::<u64>().ok())
            {
                terms.push(term);
            }
        }
        terms.sort_unstable();
        Ok(terms)
    }

    /// Startup (contract §1.2, S-7, L-4): a restarted node is not the Active of any earlier term,
    /// so every non-terminal record becomes `ABANDONED(restart)`. Nothing is sent. An unreadable
    /// record is left untouched and reported; it never blocks the start and never affects a new
    /// term (each term has its own file).
    pub(crate) fn sweep_after_restart(&self, now_unix_ms: u64) -> RhSweep {
        let mut sweep = RhSweep::default();
        let terms = match self.terms() {
            Ok(terms) => terms,
            Err(error) => {
                sweep.unreadable.push(error.to_string());
                return sweep;
            }
        };
        for term in terms {
            match self.load(term) {
                Ok(Some(mut record)) if !record.state.terminal() => {
                    record.state = RhState::Abandoned {
                        reason: "restart".to_string(),
                    };
                    record.reason = "the daemon restarted; nothing is resent".to_string();
                    record.updated_unix_ms = now_unix_ms;
                    match self.save(&record) {
                        Ok(()) => sweep.abandoned.push(term),
                        Err(error) => sweep.unreadable.push(format!("term {term}: {error}")),
                    }
                }
                Ok(_) => {}
                Err(error) => sweep.unreadable.push(format!("term {term}: {error}")),
            }
        }
        sweep
    }

    /// Read-only: the newest readable record (status).
    pub(crate) fn latest(&self) -> Result<Option<RhRecord>, RhStoreError> {
        match self.terms()?.last() {
            Some(term) => self.load(*term),
            None => Ok(None),
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct RhSweep {
    pub(crate) abandoned: Vec<u64>,
    pub(crate) unreadable: Vec<String>,
}

fn read_bounded(path: &Path) -> Result<Option<String>, RhStoreError> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(RhStoreError::Io(error.to_string())),
    };
    let metadata = file
        .metadata()
        .map_err(|error| RhStoreError::Io(error.to_string()))?;
    if !metadata.is_file() || metadata.len() > RH_MAX_FILE_BYTES {
        return Err(RhStoreError::Unreadable(
            "not a regular file of the expected size".to_string(),
        ));
    }
    let mut text = String::new();
    file.take(RH_MAX_FILE_BYTES)
        .read_to_string(&mut text)
        .map_err(|error| RhStoreError::Unreadable(error.to_string()))?;
    Ok(Some(text))
}

/// Mode check helper for tests and the helper's validator.
pub(crate) fn private_file_mode(path: &Path) -> Option<u32> {
    fs::symlink_metadata(path)
        .ok()
        .map(|metadata| metadata.permissions().mode() & 0o777)
}

// ---------------------------------------------------------------------------------------------
// Helper answers (fixed grammar)
// ---------------------------------------------------------------------------------------------

/// What one route step gave the RH: the helper's stdout when it exited 0 in time with no
/// integrity fault, or nothing (timeout, signal, non-zero exit, spawn failure, overflow: every
/// such step is inconclusive and is read as no answer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RhAnswer {
    Output(Vec<u8>),
    NoAnswer,
}

/// The helper subcommand of one route step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RhStep {
    Check,
    ObserveOwn,
    ObservePeer,
    ObserveOp,
    Assign,
    /// r17: the term's one re-issue of the identical request (contract R5 §R).
    Reissue,
}

impl RhStep {
    /// The helper's argv words for this step (after the helper path).
    pub(crate) fn words(self) -> &'static [&'static str] {
        match self {
            Self::Check => &["route-check"],
            Self::ObserveOwn => &["route-observe", "--part", "own"],
            Self::ObservePeer => &["route-observe", "--part", "peer"],
            Self::ObserveOp => &["route-observe", "--part", "op"],
            Self::Assign => &["route-assign"],
            Self::Reissue => &["route-reissue"],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Own {
    All,
    Some,
    None,
    /// Identity mismatch or the configured NIC is missing: C-2 cannot hold.
    Bad,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Peer {
    Absent,
    Present,
    /// Identity mismatch, deleted (404): C-3 cannot hold.
    Bad,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    None,
    Intent,
    Pending,
    DoneOk,
    DoneError,
    Refused,
    Unknown,
    Mismatch,
    NotNeeded,
    /// r17: a provably complete operation list without this term's request (never proof that
    /// nothing was sent).
    Absent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Check {
    Ok,
    Refused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Assign {
    Accepted,
    NotNeeded,
    Refused,
    Unknown,
    Already,
}

/// Exactly one line, the exact words; anything else is not an answer.
fn line(outcome: &RhAnswer) -> Option<&str> {
    let RhAnswer::Output(bytes) = outcome else {
        return None;
    };
    let text = std::str::from_utf8(bytes).ok()?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    (!text.contains('\n')).then_some(text)
}

fn parse_check(outcome: &RhAnswer) -> Option<Check> {
    match line(outcome)? {
        "ok" => Some(Check::Ok),
        "refused" => Some(Check::Refused),
        _ => None,
    }
}

fn parse_own(outcome: &RhAnswer) -> Option<Own> {
    match line(outcome)? {
        "own all" => Some(Own::All),
        "own some" => Some(Own::Some),
        "own none" => Some(Own::None),
        "own mismatch" | "own missing-nic" => Some(Own::Bad),
        _ => None,
    }
}

fn parse_peer(outcome: &RhAnswer) -> Option<Peer> {
    match line(outcome)? {
        "peer absent" => Some(Peer::Absent),
        "peer present" => Some(Peer::Present),
        "peer mismatch" | "peer missing" | "peer unknown" => Some(Peer::Bad),
        _ => None,
    }
}

fn parse_op(outcome: &RhAnswer) -> Option<Op> {
    match line(outcome)? {
        "op none" => Some(Op::None),
        "op intent" => Some(Op::Intent),
        "op pending" => Some(Op::Pending),
        "op done-ok" => Some(Op::DoneOk),
        "op done-error" => Some(Op::DoneError),
        "op refused" => Some(Op::Refused),
        "op unknown" => Some(Op::Unknown),
        "op mismatch" => Some(Op::Mismatch),
        "op not-needed" => Some(Op::NotNeeded),
        "op absent" => Some(Op::Absent),
        _ => None,
    }
}

fn parse_assign(outcome: &RhAnswer) -> Option<Assign> {
    match line(outcome)? {
        "accepted" => Some(Assign::Accepted),
        "not-needed" => Some(Assign::NotNeeded),
        "refused" | "blocked" => Some(Assign::Refused),
        "unknown" => Some(Assign::Unknown),
        text if text.starts_with("already ") => Some(Assign::Already),
        _ => None,
    }
}

// ---------------------------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------------------------

/// The node's state as the RH sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NodeClass {
    /// `NodeState::Active` with no operation in progress.
    Active,
    /// `Degraded` / `QuorumUnknown` (or Active with an operation in progress): hold, no step.
    ActiveHold,
    /// Anything else: the RH of this term is abandoned.
    Other,
}

/// What the runtime knows at the RH tick (read-only facts).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RhFacts {
    pub(crate) now_ms: u64,
    pub(crate) unix_ms: u64,
    pub(crate) node: NodeClass,
    /// The installed lease's term, when one is installed.
    pub(crate) lease_term: Option<u64>,
    pub(crate) lease_usable: bool,
    /// A renewal of this loop iteration was answered `AcceptedSuccess`.
    pub(crate) renewed_this_tick: bool,
    /// Another bounded process step already ran in this loop iteration.
    pub(crate) other_step_this_tick: bool,
    pub(crate) pending_reap_free: bool,
    pub(crate) control_lock_safe: bool,
}

/// The runtime side of the RH.
pub(crate) trait RhPlatform {
    fn facts(&mut self) -> RhFacts;
    /// `time_until_expiry` of the installed lease, read immediately before a spawn.
    fn lease_remaining(&mut self) -> Option<Duration>;
    fn control_lock_safe(&mut self) -> bool;
    /// Run one bounded route step (the RH-only deadline set). `Err` is a fatal runtime fault
    /// (the pending-reap invariant), returned unchanged to the daemon.
    fn spawn_route_step(
        &mut self,
        step: RhStep,
        record: &RhRecord,
        intent: &Path,
    ) -> Result<RhAnswer, String>;
    fn journal(&mut self, record: &RhRecord, warn: bool);
    /// One diagnostic measurement line per step (never evidence or a decision input).
    fn measured(&mut self, _line: &str) {}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RhSettings {
    /// C-4: the least time between the first and the confirming observation cycle.
    pub(crate) confirm_hold: Duration,
    /// After this, a non-confirmed RH is shown as `ROUTE_UNKNOWN` (no write follows).
    pub(crate) deadline: Duration,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Cycle {
    own: Option<Own>,
    peer: Option<Peer>,
    op: Option<Op>,
}

/// What one RH tick did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RhTick {
    Idle,
    Held(&'static str),
    Stepped(RhStep),
    Abandoned,
}

/// One term's RH, owned by the runtime of the Active node.
#[derive(Debug)]
pub(crate) struct RhDriver {
    record: RhRecord,
    store: RhStore,
    settings: RhSettings,
    started_ms: u64,
    not_before_ms: u64,
    cycle: Cycle,
    first_ok_ms: Option<u64>,
    /// The `own` part of the current cycle, kept for the decision to send (`route-assign` uses the
    /// helper's own record of the same observation).
    own_before_send: Option<Own>,
    /// r17: when this process spawned the term's `route-assign` (monotonic ms). In memory only:
    /// after a restart the RH is abandoned and never re-issues.
    sent_at_ms: Option<u64>,
    /// r17 (R-4): complete absent lists in a row, and the time of the first of them.
    absent_reads: u32,
    absent_first_ms: Option<u64>,
    /// r17: the last complete cycle met R-3..R-7; the next allowed step is the re-issue.
    reissue_ready: bool,
    /// r17: when that cycle completed (monotonic ms).
    reissue_ready_ms: Option<u64>,
}

pub(crate) struct RhBegin {
    pub(crate) cluster: String,
    pub(crate) node: String,
    pub(crate) peer_node: String,
    pub(crate) term: u64,
    pub(crate) origin: RhOrigin,
    pub(crate) now_ms: u64,
    pub(crate) unix_ms: u64,
}

impl RhDriver {
    /// Starts the RH of the term just promoted into (contract §1.2 start, §2 G-A1/G-A2). The
    /// record is durable before this returns `Ok`; an intent is written only for an automated RH.
    pub(crate) fn begin(
        store: RhStore,
        settings: RhSettings,
        begin: RhBegin,
    ) -> Result<Self, RhStoreError> {
        let automated = matches!(
            begin.origin,
            RhOrigin::Fencing {
                confirmed_by: RhConfirmation::Backend,
                ..
            }
        );
        let state = match &begin.origin {
            RhOrigin::Fencing {
                confirmed_by: RhConfirmation::Backend,
                ..
            } => RhState::IntentRecorded,
            RhOrigin::Fencing {
                confirmed_by: RhConfirmation::Operator,
                ..
            } => RhState::NotAutomated {
                reason: NotAutomatedReason::OperatorAttested,
            },
            RhOrigin::Bootstrap => RhState::NotAutomated {
                reason: NotAutomatedReason::Bootstrap,
            },
            RhOrigin::Unknown => RhState::NotAutomated {
                reason: NotAutomatedReason::NoProvenance,
            },
        };
        let mut record = RhRecord {
            version: RH_RECORD_VERSION,
            cluster: begin.cluster,
            node: begin.node,
            peer_node: begin.peer_node,
            term: begin.term,
            origin: begin.origin,
            state,
            sent: false,
            checked: false,
            reason: if automated {
                "promotion committed internally; the route is not moved yet".to_string()
            } else {
                "promotion committed internally; no automatic route change for this origin"
                    .to_string()
            },
            updated_unix_ms: begin.unix_ms,
            last_observed_unix_ms: None,
            last_cycle: None,
            reissued: false,
            op_seen: false,
        };
        // An earlier record of the same term (never in practice: a term is promoted into once per
        // process) is never overwritten with a fresh `sent = false`.
        match store.load(record.term) {
            Ok(Some(existing)) => {
                record.sent |= existing.sent;
                record.reissued |= existing.reissued;
                record.op_seen |= existing.op_seen;
                if existing.sent {
                    record.state = RhState::RouteUnknown;
                    record.reason = "a record of this term already shows a send".to_string();
                }
            }
            Ok(None) => {}
            // Audit L-4: an unreadable record of this term is left as it is and the RH does not
            // start (it might hold a send marker).
            Err(error) => return Err(error),
        }
        // The intent is the helper's input for every step, automated or observation-only.
        store.write_intent(&RhIntent {
            version: RH_RECORD_VERSION,
            cluster: record.cluster.clone(),
            node: record.node.clone(),
            peer_node: record.peer_node.clone(),
            term: record.term,
            origin: record.origin.clone(),
        })?;
        store.save(&record)?;
        Ok(Self {
            record,
            store,
            settings,
            started_ms: begin.now_ms,
            not_before_ms: begin.now_ms,
            cycle: Cycle::default(),
            first_ok_ms: None,
            own_before_send: None,
            sent_at_ms: None,
            absent_reads: 0,
            absent_first_ms: None,
            reissue_ready: false,
            reissue_ready_ms: None,
        })
    }

    pub(crate) fn record(&self) -> &RhRecord {
        &self.record
    }

    pub(crate) fn term(&self) -> u64 {
        self.record.term
    }

    fn deadline_passed(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.started_ms) >= self.settings.deadline.as_millis() as u64
    }

    fn set(&mut self, platform: &mut dyn RhPlatform, state: RhState, reason: &str, unix_ms: u64) {
        let changed = self.record.state != state || self.record.reason != reason;
        self.record.state = state;
        self.record.reason = reason.to_string();
        self.record.updated_unix_ms = unix_ms;
        if changed {
            // A failed save keeps the in-memory state (it only ever moves away from success);
            // `sent` was made durable before any spawn that could have sent.
            let _ = self.store.save(&self.record);
            let warn = self.record.state.operator_required()
                || matches!(self.record.state, RhState::Abandoned { .. });
            platform.journal(&self.record, warn);
        }
    }

    /// One RH tick: at most one bounded step (contract §5.1 conditions 1-4).
    pub(crate) fn tick(&mut self, platform: &mut dyn RhPlatform) -> Result<RhTick, String> {
        if self.record.state.terminal() {
            return Ok(RhTick::Idle);
        }
        let facts = platform.facts();
        // Leaving the Active of this term abandons the RH (no write afterwards).
        match facts.node {
            NodeClass::Other => {
                self.set(
                    platform,
                    RhState::Abandoned {
                        reason: "demoted".to_string(),
                    },
                    "this node is no longer the Active; nothing is sent",
                    facts.unix_ms,
                );
                return Ok(RhTick::Abandoned);
            }
            NodeClass::ActiveHold => return Ok(RhTick::Held("not plain Active")),
            NodeClass::Active => {}
        }
        match facts.lease_term {
            Some(term) if term == self.record.term => {}
            Some(_) => {
                self.set(
                    platform,
                    RhState::Abandoned {
                        reason: "term-changed".to_string(),
                    },
                    "the installed lease belongs to another term; nothing is sent",
                    facts.unix_ms,
                );
                return Ok(RhTick::Abandoned);
            }
            None => {
                self.set(
                    platform,
                    RhState::Abandoned {
                        reason: "lease-lost".to_string(),
                    },
                    "no lease is installed; nothing is sent",
                    facts.unix_ms,
                );
                return Ok(RhTick::Abandoned);
            }
        }
        // The deadline is a display rule only (no write follows it).
        if self.deadline_passed(facts.now_ms) {
            match self.record.state {
                RhState::IntentRecorded if !self.record.sent => self.set(
                    platform,
                    RhState::RouteFailed,
                    "the deadline passed before the request could be sent; nothing was sent",
                    facts.unix_ms,
                ),
                RhState::Observing | RhState::Requested => self.set(
                    platform,
                    RhState::RouteUnknown,
                    "the route was not confirmed before the deadline",
                    facts.unix_ms,
                ),
                _ => {}
            }
        }
        if !facts.lease_usable {
            return Ok(RhTick::Held("lease not usable"));
        }
        if !facts.renewed_this_tick {
            return Ok(RhTick::Held("no renewal in this iteration"));
        }
        if facts.other_step_this_tick {
            return Ok(RhTick::Held("another step ran in this iteration"));
        }
        if !facts.pending_reap_free {
            return Ok(RhTick::Held("pending-reap slot occupied"));
        }
        if !facts.control_lock_safe {
            return Ok(RhTick::Held("control lock not safe"));
        }
        if facts.now_ms < self.not_before_ms {
            return Ok(RhTick::Held("waiting"));
        }
        let Some(step) = self.choose_step() else {
            return Ok(RhTick::Idle);
        };
        // G = S + Q + ε, read immediately before the spawn.
        let remaining_ok = |platform: &mut dyn RhPlatform| {
            platform
                .lease_remaining()
                .is_some_and(|remaining| remaining >= RH_MIN_LEASE_REMAINING)
        };
        if !remaining_ok(platform) {
            return Ok(RhTick::Held("lease remaining below the step budget"));
        }
        if step == RhStep::Assign {
            // G-A4 / G-A5: still this term's Active, lock safe, never sent before.
            if self.record.sent || !self.record.checked {
                return Ok(RhTick::Held("assign not allowed"));
            }
            self.record.sent = true;
            self.record.reason = "the request is about to be sent".to_string();
            self.record.updated_unix_ms = facts.unix_ms;
            if let Err(error) = self.store.save(&self.record) {
                // Nothing is spawned. The durable file may or may not show the send (an atomic
                // rename may have happened); the in-memory record keeps `sent = true`, so this
                // term never sends, and the state says nothing was sent by this process.
                self.set(
                    platform,
                    RhState::RouteFailed,
                    &format!("the send marker was not persisted; nothing was sent: {error}"),
                    facts.unix_ms,
                );
                return Ok(RhTick::Held("send marker not persisted"));
            }
            if !platform.control_lock_safe() || !remaining_ok(platform) {
                self.set(
                    platform,
                    RhState::RouteFailed,
                    "the lock or the lease budget changed before the send; nothing was sent",
                    facts.unix_ms,
                );
                return Ok(RhTick::Held("re-check before send failed"));
            }
            self.sent_at_ms = Some(facts.now_ms);
        }
        if step == RhStep::Reissue {
            // r17 R-2, R-3, R-5, R-8: still allowed at the spawn, from a fresh readiness; the
            // marker is durable first.
            let fresh = self.reissue_ready_ms.is_some_and(|ready| {
                facts.now_ms.saturating_sub(ready) <= RH_REISSUE_READY_MAX_AGE.as_millis() as u64
            });
            self.reissue_ready = false;
            if !fresh || !self.reissue_allowed(facts.now_ms) {
                return Ok(RhTick::Held("re-issue not allowed"));
            }
            self.record.reissued = true;
            self.record.reason = "the identical request is about to be re-issued".to_string();
            self.record.updated_unix_ms = facts.unix_ms;
            if let Err(error) = self.store.save(&self.record) {
                // Nothing is spawned; the in-memory marker keeps this term from ever re-issuing.
                self.set(
                    platform,
                    RhState::RouteUnknown,
                    &format!("the re-issue marker was not persisted; nothing was re-sent: {error}"),
                    facts.unix_ms,
                );
                return Ok(RhTick::Held("re-issue marker not persisted"));
            }
            if !platform.control_lock_safe() || !remaining_ok(platform) {
                self.set(
                    platform,
                    RhState::RouteUnknown,
                    "the lock or the lease budget changed before the re-issue; nothing was \
                     re-sent; no further send",
                    facts.unix_ms,
                );
                return Ok(RhTick::Held("re-check before re-issue failed"));
            }
        }
        let intent = self.store.intent_path(self.record.term);
        // Diagnostic measurement of the §5.1 budget (never an input to a decision): the lease time
        // left immediately before the spawn and at the return, and the step's wall time with and
        // without the record write and journal line that follow it.
        let lease_before = platform.lease_remaining();
        let started = platform.facts().now_ms;
        let outcome = platform.spawn_route_step(step, &self.record, &intent)?;
        let after = platform.facts();
        let lease_after = platform.lease_remaining();
        self.apply(platform, step, &outcome, &after);
        let applied = platform.facts().now_ms;
        let ms = |value: Option<Duration>| {
            value.map_or("unknown".to_string(), |value| value.as_millis().to_string())
        };
        platform.measured(&format!(
            "route step {} answered={} step_ms={} with_record_ms={} lease_ms_before_spawn={} \
             lease_ms_at_return={} state={}",
            step.words().join(" "),
            matches!(outcome, RhAnswer::Output(_)),
            after.now_ms.saturating_sub(started),
            applied.saturating_sub(started),
            ms(lease_before),
            ms(lease_after),
            self.record.state.name(),
        ));
        Ok(RhTick::Stepped(step))
    }

    fn choose_step(&self) -> Option<RhStep> {
        match &self.record.state {
            RhState::Abandoned { .. } => None,
            RhState::IntentRecorded => Some(if !self.record.checked {
                RhStep::Check
            } else if self.own_before_send.is_none() {
                RhStep::ObserveOwn
            } else {
                RhStep::Assign
            }),
            RhState::RouteUnknown if self.reissue_ready => Some(RhStep::Reissue),
            _ => Some(if self.cycle.own.is_none() {
                RhStep::ObserveOwn
            } else if self.cycle.peer.is_none() {
                RhStep::ObservePeer
            } else if self.record.sent && self.cycle.op.is_none() {
                RhStep::ObserveOp
            } else {
                // A complete cycle is evaluated when its last part arrives; reaching here means
                // the cycle was left over: restart it.
                RhStep::ObserveOwn
            }),
        }
    }

    fn apply(
        &mut self,
        platform: &mut dyn RhPlatform,
        step: RhStep,
        outcome: &RhAnswer,
        facts: &RhFacts,
    ) {
        let now = facts.now_ms;
        let unix = facts.unix_ms;
        match step {
            RhStep::Check => match parse_check(outcome) {
                Some(Check::Ok) => {
                    self.record.checked = true;
                    self.record.updated_unix_ms = unix;
                    let _ = self.store.save(&self.record);
                }
                Some(Check::Refused) => self.set(
                    platform,
                    RhState::RouteFailed,
                    "no-fence-evidence: the helper's records do not prove both the stop and the \
                     alias removal of this incident; nothing was sent",
                    unix,
                ),
                // Inconclusive: retried at a later renewal; nothing was sent.
                None => {}
            },
            RhStep::ObserveOwn if self.record.state == RhState::IntentRecorded => {
                match parse_own(outcome) {
                    Some(Own::All) => {
                        // The ranges are already on this NIC: nothing to send (§1.2).
                        self.own_before_send = None;
                        self.cycle = Cycle {
                            own: Some(Own::All),
                            ..Cycle::default()
                        };
                        self.set(
                            platform,
                            RhState::Observing,
                            "the protected ranges are already on this node's NIC; nothing was sent",
                            unix,
                        );
                    }
                    Some(own @ (Own::Some | Own::None)) => self.own_before_send = Some(own),
                    Some(Own::Bad) => self.set(
                        platform,
                        RhState::RouteFailed,
                        "this node's instance or NIC does not match the helper configuration; \
                         nothing was sent",
                        unix,
                    ),
                    None => {}
                }
            }
            RhStep::Assign => {
                self.own_before_send = None;
                self.cycle = Cycle::default();
                self.first_ok_ms = None;
                match parse_assign(outcome) {
                    Some(Assign::Accepted) => self.set(
                        platform,
                        RhState::Observing,
                        "the alias update was accepted (not proof); observing",
                        unix,
                    ),
                    Some(Assign::NotNeeded) => self.set(
                        platform,
                        RhState::Observing,
                        "the helper found nothing to add; observing",
                        unix,
                    ),
                    Some(Assign::Refused) => self.set(
                        platform,
                        RhState::RouteFailed,
                        "the helper or GCE refused the alias update",
                        unix,
                    ),
                    Some(Assign::Already) | Some(Assign::Unknown) | None => self.set(
                        platform,
                        RhState::RouteUnknown,
                        "the outcome of the alias update is unknown; it is not resent",
                        unix,
                    ),
                }
            }
            RhStep::Reissue => {
                self.cycle = Cycle::default();
                self.first_ok_ms = None;
                self.absent_reads = 0;
                self.absent_first_ms = None;
                match parse_assign(outcome) {
                    Some(Assign::Accepted) => self.set(
                        platform,
                        RhState::Observing,
                        "the re-issued identical alias update was accepted (not proof); observing",
                        unix,
                    ),
                    Some(Assign::Refused) => self.set(
                        platform,
                        RhState::RouteUnknown,
                        "the helper refused the re-issue before sending it; the original \
                         outcome stays unknown; no further send",
                        unix,
                    ),
                    Some(Assign::NotNeeded | Assign::Already | Assign::Unknown) | None => self.set(
                        platform,
                        RhState::RouteUnknown,
                        "the outcome of the re-issued alias update is unknown; no further send",
                        unix,
                    ),
                }
            }
            RhStep::ObserveOwn => match parse_own(outcome) {
                Some(own) => self.cycle.own = Some(own),
                None => self.break_cycle(platform, facts),
            },
            RhStep::ObservePeer => match parse_peer(outcome) {
                Some(peer) => {
                    self.cycle.peer = Some(peer);
                    if !self.record.sent {
                        self.evaluate(platform, facts);
                    }
                }
                None => self.break_cycle(platform, facts),
            },
            RhStep::ObserveOp => match parse_op(outcome) {
                Some(op) => {
                    self.cycle.op = Some(op);
                    self.evaluate(platform, facts);
                }
                None => self.break_cycle(platform, facts),
            },
        }
    }

    /// An inconclusive read breaks the continuity of the observation (C-4 restarts). A confirmed
    /// route that can no longer be observed is not kept as confirmed (audit M-1).
    fn break_cycle(&mut self, platform: &mut dyn RhPlatform, facts: &RhFacts) {
        self.cycle = Cycle::default();
        self.first_ok_ms = None;
        // r17 R-4: an inconclusive read restarts the count of absent lists.
        self.absent_reads = 0;
        self.absent_first_ms = None;
        self.reissue_ready = false;
        self.not_before_ms = facts.now_ms;
        if matches!(self.record.state, RhState::RouteConfirmed { .. }) {
            self.set(
                platform,
                RhState::RouteUnknown,
                "the helper gave no answer; the confirmed route can no longer be observed",
                facts.unix_ms,
            );
        }
    }

    /// Audit L-4: a newer promotion of this process replaces this RH; nothing is sent for it.
    pub(crate) fn abandon_superseded(&mut self, unix_ms: u64) {
        if !self.record.state.terminal() {
            self.record.state = RhState::Abandoned {
                reason: "superseded".to_string(),
            };
            self.record.reason = "a newer promotion of this process replaced it".to_string();
            self.record.updated_unix_ms = unix_ms;
            let _ = self.store.save(&self.record);
        }
    }

    /// r17 (contract R5 R-2, R-3, R-5): the re-issue is still possible at `now_ms`.
    fn reissue_allowed(&self, now_ms: u64) -> bool {
        let Some(sent_at) = self.sent_at_ms else {
            return false;
        };
        let window_end = (self.settings.deadline.as_millis() as u64)
            .checked_sub(RH_REISSUE_DEADLINE_MARGIN.as_millis() as u64)
            .map(|end| self.started_ms.saturating_add(end));
        self.record.state == RhState::RouteUnknown
            && self.record.sent
            && !self.record.reissued
            && !self.record.op_seen
            && now_ms.saturating_sub(sent_at) >= RH_REISSUE_MIN_AFTER_SEND.as_millis() as u64
            && window_end.is_some_and(|end| now_ms < end)
    }

    /// r17: one complete cycle of a sent RH. Records an operation of the term as seen (R-3),
    /// counts complete absent lists (R-4), and marks the re-issue ready when R-3..R-7 hold in this
    /// cycle: own none (the helper re-checks the exact base, R-6), peer absent (R-7), op absent.
    fn track_reissue(&mut self, own: Own, peer: Peer, op: Option<Op>, now: u64) {
        self.reissue_ready = false;
        if !self.record.sent {
            return;
        }
        if matches!(
            op,
            Some(Op::Pending | Op::DoneOk | Op::DoneError | Op::Mismatch)
        ) && !self.record.op_seen
        {
            self.record.op_seen = true;
            let _ = self.store.save(&self.record);
        }
        if op == Some(Op::Absent) {
            self.absent_reads = self.absent_reads.saturating_add(1);
            self.absent_first_ms.get_or_insert(now);
        } else {
            self.absent_reads = 0;
            self.absent_first_ms = None;
            return;
        }
        let hold = self.settings.confirm_hold.as_millis() as u64;
        self.reissue_ready = own == Own::None
            && peer == Peer::Absent
            && self.absent_reads >= RH_REISSUE_ABSENT_READS
            && self
                .absent_first_ms
                .is_some_and(|first| now.saturating_sub(first) >= hold)
            && self.reissue_allowed(now);
        self.reissue_ready_ms = self.reissue_ready.then_some(now);
    }

    fn evaluate(&mut self, platform: &mut dyn RhPlatform, facts: &RhFacts) {
        let cycle = std::mem::take(&mut self.cycle);
        let (Some(own), Some(peer)) = (cycle.own, cycle.peer) else {
            return;
        };
        let op = cycle.op;
        let now = facts.now_ms;
        let unix = facts.unix_ms;
        // Audit M-1: the facts of every complete cycle are durable for the status.
        self.record.last_observed_unix_ms = Some(unix);
        self.record.last_cycle = Some(format!(
            "own={} peer={}{}",
            match own {
                Own::All => "all",
                Own::Some => "some",
                Own::None => "none",
                Own::Bad => "unidentified",
            },
            match peer {
                Peer::Absent => "absent",
                Peer::Present => "present",
                Peer::Bad => "unknown",
            },
            match op {
                None => String::new(),
                Some(op) => format!(" op={op:?}").to_lowercase(),
            }
        ));
        let _ = self.store.save(&self.record);
        let hold = self.settings.confirm_hold.as_millis() as u64;
        let slow = RH_SLOW_INTERVAL.as_millis() as u64;
        self.track_reissue(own, peer, op, now);
        let ok = own == Own::All
            && peer == Peer::Absent
            && (!self.record.sent || op == Some(Op::DoneOk));
        if ok {
            match self.first_ok_ms {
                None => {
                    self.first_ok_ms = Some(now);
                    self.not_before_ms = now.saturating_add(hold);
                }
                Some(first) if now.saturating_sub(first) >= hold => {
                    // C-1, after the observation: still this term's Active with a usable lease.
                    if facts.node == NodeClass::Active
                        && facts.lease_term == Some(self.record.term)
                        && facts.lease_usable
                    {
                        let already = matches!(self.record.state, RhState::RouteConfirmed { .. });
                        if !already {
                            self.set(
                                platform,
                                RhState::RouteConfirmed { at_unix_ms: unix },
                                if self.record.sent {
                                    "route confirmed by the control plane (this node's NIC holds \
                                     every range, the peer none, the request's operation DONE); \
                                     service reachability is not checked by this node"
                                } else {
                                    "route confirmed by observation only (nothing was sent); \
                                     service reachability is not checked by this node"
                                },
                                unix,
                            );
                        }
                        // Keep observing slowly, from a fresh hold.
                        self.first_ok_ms = Some(now);
                        self.not_before_ms = now.saturating_add(slow.max(hold));
                    } else {
                        self.first_ok_ms = None;
                    }
                }
                Some(first) => self.not_before_ms = first.saturating_add(hold),
            }
            return;
        }
        self.first_ok_ms = None;
        let state = &self.record.state;
        let (next, reason): (Option<RhState>, &str) =
            if matches!(state, RhState::RouteConfirmed { .. }) || *state == RhState::RouteLost {
                (
                    Some(RhState::RouteLost),
                    "the confirmed route is no longer observed (this node's ranges or the peer's \
                 absence)",
                )
            } else if *state != RhState::Observing {
                // §1.2: only OBSERVING is refined by an observation; NOT_AUTOMATED (for example a
                // Bootstrap Admission with the ranges on the peer, §5), ROUTE_FAILED, ROUTE_PARTIAL
                // and ROUTE_UNKNOWN keep their state (and reason) until the route is confirmed.
                // The observation itself is still recorded in `last_cycle` for the status.
                (None, "")
            } else if own == Own::Some {
                (
                    Some(RhState::RoutePartial),
                    "only some protected ranges are on this node's NIC; nothing is corrected \
                 automatically",
                )
            } else if self.record.sent && op == Some(Op::DoneError) && own == Own::None {
                (
                    Some(RhState::RouteFailed),
                    "the alias update operation finished with an error",
                )
            } else if self.record.sent && op == Some(Op::Refused) {
                (Some(RhState::RouteFailed), "the alias update was refused")
            } else if peer != Peer::Absent {
                (
                    Some(RhState::RouteUnknown),
                    "the peer still holds a protected range or cannot be identified",
                )
            } else if own == Own::Bad {
                (
                    Some(RhState::RouteUnknown),
                    "this node's instance or NIC does not match the helper configuration",
                )
            } else if self.record.sent
                && matches!(
                    op,
                    Some(
                        Op::Mismatch
                            | Op::Unknown
                            | Op::Intent
                            | Op::None
                            | Op::NotNeeded
                            | Op::Absent
                    )
                )
            {
                (
                    Some(RhState::RouteUnknown),
                    "the request's operation cannot be matched; observation alone never confirms a \
                 sent request",
                )
            } else if self.record.sent && own == Own::All && op == Some(Op::DoneError) {
                (
                    Some(RhState::RouteUnknown),
                    "the ranges are present but the request's operation reports an error",
                )
            } else {
                (None, "")
            };
        if let Some(next) = next {
            self.set(platform, next, reason, unix);
        }
        let waiting = self.reissue_ready
            || (!self.record.state.operator_required() && !self.deadline_passed(now));
        self.not_before_ms = if waiting {
            now
        } else {
            now.saturating_add(slow)
        };
    }
}

/// The validated `[route]` settings of a daemon (absent: no route handoff at all).
#[derive(Debug, Clone)]
pub(crate) struct RouteSettings {
    pub(crate) helper: String,
    pub(crate) helper_config: String,
    pub(crate) store: RhStore,
    pub(crate) settings: RhSettings,
}

impl RouteSettings {
    /// Daemon startup, after the runtime owner trust-checked the helper through the command
    /// backend: open the RH directory and abandon every record a previous process left open
    /// (S-7). A failure refuses the daemon; an unreadable record does not (L-4).
    pub(crate) fn startup(
        config: &crate::config::Config,
        now_unix_ms: u64,
    ) -> Result<Option<Self>, String> {
        let Some(route) = &config.route else {
            return Ok(None);
        };
        let store = RhStore::open(Path::new(&route.intent_dir)).map_err(|e| e.to_string())?;
        let sweep = store.sweep_after_restart(now_unix_ms);
        for term in &sweep.abandoned {
            crate::operator_log::warn_route_handoff(&format!(
                "route handoff of term {term} abandoned at startup (restart); nothing is resent"
            ));
        }
        for detail in &sweep.unreadable {
            crate::operator_log::warn_route_handoff(&format!(
                "an unreadable route handoff record was left untouched: {detail}"
            ));
        }
        Ok(Some(Self {
            helper: route.helper.clone(),
            helper_config: route.helper_config.clone(),
            store,
            settings: RhSettings {
                confirm_hold: Duration::from_secs(route.confirm_hold_sec),
                deadline: Duration::from_secs(route.deadline_sec),
            },
        }))
    }

    /// The helper argv of one step: the helper, the step words, its configuration and the
    /// term's intent (never a shell line).
    pub(crate) fn argv(&self, step: RhStep, intent: &Path) -> Vec<String> {
        let mut argv = vec![self.helper.clone()];
        argv.extend(step.words().iter().map(|word| (*word).to_string()));
        argv.push("--config".to_string());
        argv.push(self.helper_config.clone());
        argv.push("--intent".to_string());
        argv.push(intent.display().to_string());
        argv
    }
}

/// The step identity of a route step (the command backend's `MIKAGAMI_*` values). A fencing
/// origin names its incident and attempt; any other origin has none, so a fixed synthetic
/// identity derived from the cluster and term is used (the helper reads it only as a label and
/// never automates such an RH).
pub(crate) fn step_identity(record: &RhRecord) -> (u64, String, u64) {
    match &record.origin {
        RhOrigin::Fencing {
            incident_seq,
            incident_id,
            attempt_token,
            confirmed_by: RhConfirmation::Backend,
        } => (*incident_seq, incident_id.clone(), *attempt_token),
        RhOrigin::Fencing { .. } | RhOrigin::Bootstrap | RhOrigin::Unknown => {
            use sha2::{Digest, Sha256};
            let mut hash = Sha256::new();
            hash.update(b"mikagami-g2-route-observe-only\0");
            hash.update(record.cluster.as_bytes());
            hash.update(b"\0");
            hash.update(record.term.to_string().as_bytes());
            let digest = hash.finalize();
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&digest[..16]);
            bytes[6] = (bytes[6] & 0x0f) | 0x40;
            bytes[8] = (bytes[8] & 0x3f) | 0x80;
            let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
            (
                0,
                format!(
                    "{}-{}-{}-{}-{}",
                    &hex[0..8],
                    &hex[8..12],
                    &hex[12..16],
                    &hex[16..20],
                    &hex[20..32]
                ),
                1,
            )
        }
    }
}

/// The status lines of an RH record (read-only; never an input to a decision).
pub(crate) fn status_lines(record: Option<&RhRecord>) -> Vec<String> {
    let Some(record) = record else {
        return vec![
            "route.handoff: none".to_string(),
            "route.switchover: not applicable (no route handoff recorded)".to_string(),
        ];
    };
    let mut lines = vec![format!("route.handoff: {}", record.describe())];
    lines.push(format!("route.reason: {}", record.reason));
    lines.push(match (&record.last_observed_unix_ms, &record.last_cycle) {
        (Some(at), Some(cycle)) => format!("route.last_observation: at={at} {cycle}"),
        _ => "route.last_observation: none yet".to_string(),
    });
    if record.state.operator_required() {
        lines.push("route.operator_action: required (see the runbook for this state)".to_string());
    }
    // Contract §1.1: this node never reports the switchover as complete.
    lines.push(
        match record.state {
            RhState::RouteConfirmed { .. } => {
                "route.switchover: NOT complete as far as this node can tell: the route is \
                 confirmed by control-plane observation; service reachability (an external \
                 check) is not verified by this node"
            }
            _ => "route.switchover: NOT complete: the route is not confirmed",
        }
        .to_string(),
    );
    lines
}

#[cfg(test)]
mod tests {
    //! G-2 route handoff tests (contract R4.1 §7), against a fake platform and a real temporary store.

    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_dir(name: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "rh-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    const TERM: u64 = 8;

    fn backend_origin() -> RhOrigin {
        RhOrigin::Fencing {
            incident_seq: 3,
            incident_id: "11111111-1111-4111-8111-111111111111".to_string(),
            attempt_token: 2,
            confirmed_by: RhConfirmation::Backend,
        }
    }

    fn settings() -> RhSettings {
        RhSettings {
            confirm_hold: Duration::from_secs(10),
            deadline: Duration::from_secs(120),
        }
    }

    fn out(text: &str) -> RhAnswer {
        RhAnswer::Output(format!("{text}\n").into_bytes())
    }

    /// A scripted platform: each step pops the next answer for its kind.
    struct Fake {
        facts: RhFacts,
        remaining: Option<Duration>,
        lock_safe: bool,
        answers: VecDeque<(RhStep, RhAnswer)>,
        steps: Vec<RhStep>,
        sent_seen_on_assign: Vec<bool>,
        /// r17: the durable `reissued` marker seen when `route-reissue` is spawned.
        reissued_seen_on_reissue: Vec<bool>,
        store_dir: PathBuf,
        journal: Vec<(String, bool)>,
        /// Advance the clock by this much per step (the step's duration).
        step_ms: u64,
    }

    impl Fake {
        fn new(store_dir: &Path) -> Self {
            Self {
                facts: RhFacts {
                    now_ms: 1_000,
                    unix_ms: 1_700_000_000_000,
                    node: NodeClass::Active,
                    lease_term: Some(TERM),
                    lease_usable: true,
                    renewed_this_tick: true,
                    other_step_this_tick: false,
                    pending_reap_free: true,
                    control_lock_safe: true,
                },
                remaining: Some(Duration::from_millis(7_900)),
                lock_safe: true,
                answers: VecDeque::new(),
                steps: Vec::new(),
                sent_seen_on_assign: Vec::new(),
                reissued_seen_on_reissue: Vec::new(),
                store_dir: store_dir.to_path_buf(),
                journal: Vec::new(),
                step_ms: 500,
            }
        }

        fn script(&mut self, step: RhStep, answer: RhAnswer) {
            self.answers.push_back((step, answer));
        }

        fn advance(&mut self, ms: u64) {
            self.facts.now_ms += ms;
            self.facts.unix_ms += ms;
        }
    }

    impl RhPlatform for Fake {
        fn facts(&mut self) -> RhFacts {
            self.facts
        }
        fn lease_remaining(&mut self) -> Option<Duration> {
            self.remaining
        }
        fn control_lock_safe(&mut self) -> bool {
            self.lock_safe
        }
        fn spawn_route_step(
            &mut self,
            step: RhStep,
            record: &RhRecord,
            intent: &Path,
        ) -> Result<RhAnswer, String> {
            assert!(intent.starts_with(&self.store_dir));
            assert!(intent.exists(), "the intent is durable before any step");
            if step == RhStep::Assign {
                // The durable record shows the send before the helper runs.
                let durable = RhStore::open(&self.store_dir)
                    .unwrap()
                    .load(record.term)
                    .unwrap()
                    .unwrap();
                self.sent_seen_on_assign.push(durable.sent);
            }
            if step == RhStep::Reissue {
                let durable = RhStore::open(&self.store_dir)
                    .unwrap()
                    .load(record.term)
                    .unwrap()
                    .unwrap();
                self.reissued_seen_on_reissue.push(durable.reissued);
            }
            self.steps.push(step);
            self.advance(self.step_ms);
            // Past the script, every step is inconclusive (a read that never answers).
            let Some((expected, answer)) = self.answers.pop_front() else {
                return Ok(RhAnswer::NoAnswer);
            };
            assert_eq!(expected, step, "the step order");
            Ok(answer)
        }
        fn journal(&mut self, record: &RhRecord, warn: bool) {
            self.journal.push((record.describe(), warn));
        }
    }

    fn begin(dir: &Path, origin: RhOrigin) -> RhDriver {
        RhDriver::begin(
            RhStore::open(dir).unwrap(),
            settings(),
            RhBegin {
                cluster: "c".to_string(),
                node: "node-b".to_string(),
                peer_node: "node-a".to_string(),
                term: TERM,
                origin,
                now_ms: 1_000,
                unix_ms: 1_700_000_000_000,
            },
        )
        .unwrap()
    }

    /// Ticks once per "renewal" (3 s apart), as the daemon would.
    fn run(driver: &mut RhDriver, fake: &mut Fake, ticks: usize) {
        for _ in 0..ticks {
            driver.tick(fake).unwrap();
            fake.advance(3_000);
        }
    }

    fn durable(dir: &Path) -> RhRecord {
        RhStore::open(dir).unwrap().load(TERM).unwrap().unwrap()
    }

    /// The normal path: check → own → sent=yes → assign → own/peer/op ×2 (hold) → ROUTE_CONFIRMED.
    #[test]
    fn g2_normal_path_sends_once_and_confirms_after_the_hold() {
        let dir = temp_dir("normal");
        let mut driver = begin(&dir, backend_origin());
        assert_eq!(driver.record().state, RhState::IntentRecorded);
        assert!(!driver.record().sent);
        let mut fake = Fake::new(&dir);
        fake.script(RhStep::Check, out("ok"));
        fake.script(RhStep::ObserveOwn, out("own none"));
        fake.script(RhStep::Assign, out("accepted"));
        for _ in 0..3 {
            fake.script(RhStep::ObserveOwn, out("own all"));
            fake.script(RhStep::ObservePeer, out("peer absent"));
            fake.script(RhStep::ObserveOp, out("op done-ok"));
        }
        run(&mut driver, &mut fake, 30);
        assert_eq!(
            fake.steps.iter().filter(|s| **s == RhStep::Assign).count(),
            1,
            "exactly one send per term"
        );
        assert_eq!(fake.sent_seen_on_assign, vec![true]);
        assert!(matches!(
            driver.record().state,
            RhState::RouteConfirmed { .. }
        ));
        assert!(driver.record().sent);
        let record = durable(&dir);
        assert!(record.sent && matches!(record.state, RhState::RouteConfirmed { .. }));
        // Never reported as the switchover's success.
        let status = status_lines(Some(&record)).join("\n");
        assert!(status.contains("NOT complete"));
        assert!(status.contains("service reachability"));
        assert!(!status.to_lowercase().contains("switchover: complete"));
    }

    #[test]
    fn g2_confirmation_needs_two_cycles_at_least_the_hold_apart() {
        let dir = temp_dir("hold");
        let mut driver = begin(&dir, backend_origin());
        let mut fake = Fake::new(&dir);
        fake.script(RhStep::Check, out("ok"));
        fake.script(RhStep::ObserveOwn, out("own none"));
        fake.script(RhStep::Assign, out("accepted"));
        fake.script(RhStep::ObserveOwn, out("own all"));
        fake.script(RhStep::ObservePeer, out("peer absent"));
        fake.script(RhStep::ObserveOp, out("op done-ok"));
        // One good cycle only: not confirmed, however many ticks without a second cycle.
        run(&mut driver, &mut fake, 6);
        assert_eq!(driver.record().state, RhState::Observing);
    }

    #[test]
    fn g2_sent_is_durable_before_the_spawn_and_never_reset() {
        let dir = temp_dir("sent");
        let mut driver = begin(&dir, backend_origin());
        let mut fake = Fake::new(&dir);
        fake.script(RhStep::Check, out("ok"));
        fake.script(RhStep::ObserveOwn, out("own none"));
        fake.script(RhStep::Assign, RhAnswer::NoAnswer);
        for _ in 0..6 {
            fake.script(RhStep::ObserveOwn, out("own none"));
            fake.script(RhStep::ObservePeer, out("peer absent"));
            fake.script(RhStep::ObserveOp, out("op unknown"));
        }
        run(&mut driver, &mut fake, 25);
        assert_eq!(fake.sent_seen_on_assign, vec![true]);
        assert_eq!(
            fake.steps.iter().filter(|s| **s == RhStep::Assign).count(),
            1
        );
        assert!(driver.record().sent && durable(&dir).sent);
        assert_eq!(driver.record().state, RhState::RouteUnknown);
    }

    /// C-5: after a send, an observation alone (ranges present, peer absent) never confirms.
    #[test]
    fn g2_sent_rh_needs_the_operation_done_ok() {
        for op in [
            "op unknown",
            "op mismatch",
            "op none",
            "op intent",
            "op pending",
            "op done-error",
        ] {
            let dir = temp_dir("c5");
            let mut driver = begin(&dir, backend_origin());
            let mut fake = Fake::new(&dir);
            fake.script(RhStep::Check, out("ok"));
            fake.script(RhStep::ObserveOwn, out("own none"));
            fake.script(RhStep::Assign, out("accepted"));
            for _ in 0..8 {
                fake.script(RhStep::ObserveOwn, out("own all"));
                fake.script(RhStep::ObservePeer, out("peer absent"));
                fake.script(RhStep::ObserveOp, out(op));
            }
            run(&mut driver, &mut fake, 30);
            assert!(
                !matches!(driver.record().state, RhState::RouteConfirmed { .. }),
                "{op} must not confirm a sent RH"
            );
        }
    }

    #[test]
    fn g2_t8_ba_and_no_provenance_never_send() {
        for (origin, reason) in [
            (
                RhOrigin::Fencing {
                    incident_seq: 3,
                    incident_id: "11111111-1111-4111-8111-111111111111".to_string(),
                    attempt_token: 2,
                    confirmed_by: RhConfirmation::Operator,
                },
                NotAutomatedReason::OperatorAttested,
            ),
            (RhOrigin::Bootstrap, NotAutomatedReason::Bootstrap),
            (RhOrigin::Unknown, NotAutomatedReason::NoProvenance),
        ] {
            let dir = temp_dir("na");
            let mut driver = begin(&dir, origin);
            assert_eq!(driver.record().state, RhState::NotAutomated { reason });
            let mut fake = Fake::new(&dir);
            // Observation only; the ranges are not here.
            for _ in 0..6 {
                fake.script(RhStep::ObserveOwn, out("own none"));
                fake.script(RhStep::ObservePeer, out("peer absent"));
            }
            run(&mut driver, &mut fake, 12);
            assert!(!fake.steps.contains(&RhStep::Assign));
            assert!(!fake.steps.contains(&RhStep::Check));
            assert!(!driver.record().sent);
            assert!(driver.record().state.operator_required());
        }
    }

    /// Step 2-2-R1 E2E finding: §1.2 lets NOT_AUTOMATED leave only for ROUTE_CONFIRMED, and §5
    /// requires NOT_AUTOMATED for a BA with the ranges on the peer. An observation of the peer
    /// holding the ranges (or of only some ranges here) keeps the state and its reason.
    #[test]
    fn g2_not_automated_keeps_its_state_when_the_peer_holds_the_ranges() {
        for (origin, reason) in [
            (
                RhOrigin::Fencing {
                    incident_seq: 3,
                    incident_id: "11111111-1111-4111-8111-111111111111".to_string(),
                    attempt_token: 2,
                    confirmed_by: RhConfirmation::Operator,
                },
                NotAutomatedReason::OperatorAttested,
            ),
            (RhOrigin::Bootstrap, NotAutomatedReason::Bootstrap),
            (RhOrigin::Unknown, NotAutomatedReason::NoProvenance),
        ] {
            let dir = temp_dir("na-peer");
            let mut driver = begin(&dir, origin);
            let before = driver.record().reason.clone();
            let mut fake = Fake::new(&dir);
            for own in ["own none", "own some", "own none"] {
                fake.script(RhStep::ObserveOwn, out(own));
                fake.script(RhStep::ObservePeer, out("peer present"));
            }
            run(&mut driver, &mut fake, 12);
            let want = RhState::NotAutomated { reason };
            assert_eq!(driver.record().state, want);
            assert_eq!(durable(&dir).state, want);
            assert_eq!(driver.record().reason, before);
            assert!(driver.record().last_cycle.is_some());
            assert!(!fake.steps.contains(&RhStep::Assign));
            assert!(!driver.record().sent);
        }
    }

    /// BA with the ranges already on this node (initial bring-up): confirmed by observation only.
    #[test]
    fn g2_ba_with_the_ranges_on_this_node_confirms_without_sending() {
        let dir = temp_dir("ba-own");
        let mut driver = begin(&dir, RhOrigin::Bootstrap);
        let mut fake = Fake::new(&dir);
        for _ in 0..3 {
            fake.script(RhStep::ObserveOwn, out("own all"));
            fake.script(RhStep::ObservePeer, out("peer absent"));
        }
        run(&mut driver, &mut fake, 12);
        assert!(matches!(
            driver.record().state,
            RhState::RouteConfirmed { .. }
        ));
        assert!(!driver.record().sent);
        assert!(!fake.steps.contains(&RhStep::Assign));
    }

    #[test]
    fn g2_route_check_refusal_sends_nothing() {
        let dir = temp_dir("refused");
        let mut driver = begin(&dir, backend_origin());
        let mut fake = Fake::new(&dir);
        fake.script(RhStep::Check, out("refused"));
        for _ in 0..4 {
            fake.script(RhStep::ObserveOwn, out("own none"));
            fake.script(RhStep::ObservePeer, out("peer absent"));
        }
        run(&mut driver, &mut fake, 10);
        assert_eq!(driver.record().state, RhState::RouteFailed);
        assert!(!driver.record().sent && !durable(&dir).sent);
        assert!(!fake.steps.contains(&RhStep::Assign));
    }

    #[test]
    fn g2_already_present_before_send_is_not_sent() {
        let dir = temp_dir("present");
        let mut driver = begin(&dir, backend_origin());
        let mut fake = Fake::new(&dir);
        fake.script(RhStep::Check, out("ok"));
        fake.script(RhStep::ObserveOwn, out("own all"));
        fake.script(RhStep::ObservePeer, out("peer absent"));
        fake.script(RhStep::ObserveOwn, out("own all"));
        fake.script(RhStep::ObservePeer, out("peer absent"));
        run(&mut driver, &mut fake, 12);
        assert!(!fake.steps.contains(&RhStep::Assign));
        assert!(!driver.record().sent);
        assert!(matches!(
            driver.record().state,
            RhState::RouteConfirmed { .. }
        ));
    }

    #[test]
    fn g2_partial_assignment_is_partial_and_not_corrected() {
        let dir = temp_dir("partial");
        let mut driver = begin(&dir, backend_origin());
        let mut fake = Fake::new(&dir);
        fake.script(RhStep::Check, out("ok"));
        fake.script(RhStep::ObserveOwn, out("own none"));
        fake.script(RhStep::Assign, out("accepted"));
        for _ in 0..6 {
            fake.script(RhStep::ObserveOwn, out("own some"));
            fake.script(RhStep::ObservePeer, out("peer absent"));
            fake.script(RhStep::ObserveOp, out("op done-ok"));
        }
        run(&mut driver, &mut fake, 20);
        assert_eq!(driver.record().state, RhState::RoutePartial);
        assert_eq!(
            fake.steps.iter().filter(|s| **s == RhStep::Assign).count(),
            1
        );
    }

    /// A fingerprint conflict (412) or IAM refusal (403) is a refused update: FAILED, no resend.
    #[test]
    fn g2_refused_update_fails_without_resend() {
        let dir = temp_dir("412");
        let mut driver = begin(&dir, backend_origin());
        let mut fake = Fake::new(&dir);
        fake.script(RhStep::Check, out("ok"));
        fake.script(RhStep::ObserveOwn, out("own none"));
        fake.script(RhStep::Assign, out("refused"));
        for _ in 0..6 {
            fake.script(RhStep::ObserveOwn, out("own none"));
            fake.script(RhStep::ObservePeer, out("peer absent"));
            fake.script(RhStep::ObserveOp, out("op refused"));
        }
        run(&mut driver, &mut fake, 20);
        assert_eq!(driver.record().state, RhState::RouteFailed);
        assert!(driver.record().sent);
        assert_eq!(
            fake.steps.iter().filter(|s| **s == RhStep::Assign).count(),
            1
        );
    }

    /// S-6: the peer (old Active) shows a protected range again: never confirmed.
    #[test]
    fn g2_peer_range_reappearing_blocks_confirmation() {
        let dir = temp_dir("stale");
        let mut driver = begin(&dir, backend_origin());
        let mut fake = Fake::new(&dir);
        fake.script(RhStep::Check, out("ok"));
        fake.script(RhStep::ObserveOwn, out("own none"));
        fake.script(RhStep::Assign, out("accepted"));
        for _ in 0..6 {
            fake.script(RhStep::ObserveOwn, out("own all"));
            fake.script(RhStep::ObservePeer, out("peer present"));
            fake.script(RhStep::ObserveOp, out("op done-ok"));
        }
        run(&mut driver, &mut fake, 20);
        assert_eq!(driver.record().state, RhState::RouteUnknown);
    }

    #[test]
    fn g2_confirmed_then_lost_is_reported_lost() {
        let dir = temp_dir("lost");
        let mut driver = begin(&dir, RhOrigin::Bootstrap);
        let mut fake = Fake::new(&dir);
        for _ in 0..2 {
            fake.script(RhStep::ObserveOwn, out("own all"));
            fake.script(RhStep::ObservePeer, out("peer absent"));
        }
        fake.script(RhStep::ObserveOwn, out("own none"));
        fake.script(RhStep::ObservePeer, out("peer absent"));
        run(&mut driver, &mut fake, 25);
        assert_eq!(driver.record().state, RhState::RouteLost);
    }

    #[test]
    fn g2_budget_conditions_hold_every_step() {
        let dir = temp_dir("budget");
        let mut driver = begin(&dir, backend_origin());
        let mut fake = Fake::new(&dir);
        for (field, value) in [
            ("renewed", false),
            ("other", true),
            ("reap", false),
            ("lock", false),
            ("usable", false),
        ] {
            let mut facts = fake.facts;
            match field {
                "renewed" => facts.renewed_this_tick = value,
                "other" => facts.other_step_this_tick = value,
                "reap" => facts.pending_reap_free = value,
                "lock" => facts.control_lock_safe = value,
                _ => facts.lease_usable = value,
            }
            let saved = fake.facts;
            fake.facts = facts;
            assert!(
                matches!(driver.tick(&mut fake).unwrap(), RhTick::Held(_)),
                "{field}"
            );
            fake.facts = saved;
        }
        // G boundary: 5,999 ms holds, 6,000 ms steps.
        fake.remaining = Some(Duration::from_millis(5_999));
        assert!(matches!(driver.tick(&mut fake).unwrap(), RhTick::Held(_)));
        fake.remaining = None;
        assert!(matches!(driver.tick(&mut fake).unwrap(), RhTick::Held(_)));
        fake.remaining = Some(Duration::from_millis(6_000));
        fake.script(RhStep::Check, out("ok"));
        assert_eq!(
            driver.tick(&mut fake).unwrap(),
            RhTick::Stepped(RhStep::Check)
        );
        assert!(fake.steps == vec![RhStep::Check]);
    }

    #[test]
    fn g2_lease_budget_lost_between_marker_and_spawn_sends_nothing() {
        let dir = temp_dir("recheck");
        let mut driver = begin(&dir, backend_origin());
        let mut fake = Fake::new(&dir);
        fake.script(RhStep::Check, out("ok"));
        fake.script(RhStep::ObserveOwn, out("own none"));
        run(&mut driver, &mut fake, 2);
        fake.lock_safe = false;
        driver.tick(&mut fake).unwrap();
        assert!(!fake.steps.contains(&RhStep::Assign));
        assert_eq!(driver.record().state, RhState::RouteFailed);
        // The marker stays: this term never sends.
        assert!(driver.record().sent);
        fake.lock_safe = true;
        run(&mut driver, &mut fake, 6);
        assert!(!fake.steps.contains(&RhStep::Assign));
    }

    #[test]
    fn g2_leaving_active_or_term_abandons_without_sending() {
        for case in ["demoted", "term", "no-lease"] {
            let dir = temp_dir("abandon");
            let mut driver = begin(&dir, backend_origin());
            let mut fake = Fake::new(&dir);
            match case {
                "demoted" => fake.facts.node = NodeClass::Other,
                "term" => fake.facts.lease_term = Some(TERM + 2),
                _ => fake.facts.lease_term = None,
            }
            assert_eq!(driver.tick(&mut fake).unwrap(), RhTick::Abandoned);
            assert!(matches!(durable(&dir).state, RhState::Abandoned { .. }));
            assert!(fake.steps.is_empty());
            assert_eq!(driver.tick(&mut fake).unwrap(), RhTick::Idle);
        }
    }

    #[test]
    fn g2_degraded_holds_and_resumes() {
        let dir = temp_dir("hold-degraded");
        let mut driver = begin(&dir, backend_origin());
        let mut fake = Fake::new(&dir);
        fake.facts.node = NodeClass::ActiveHold;
        assert!(matches!(driver.tick(&mut fake).unwrap(), RhTick::Held(_)));
        assert_eq!(driver.record().state, RhState::IntentRecorded);
        fake.facts.node = NodeClass::Active;
        fake.script(RhStep::Check, out("ok"));
        assert_eq!(
            driver.tick(&mut fake).unwrap(),
            RhTick::Stepped(RhStep::Check)
        );
    }

    #[test]
    fn g2_restart_abandons_every_open_record_and_tolerates_a_corrupt_one() {
        let dir = temp_dir("restart");
        let mut driver = begin(&dir, backend_origin());
        let mut fake = Fake::new(&dir);
        fake.script(RhStep::Check, out("ok"));
        fake.script(RhStep::ObserveOwn, out("own none"));
        fake.script(RhStep::Assign, out("accepted"));
        run(&mut driver, &mut fake, 3);
        assert!(durable(&dir).sent);
        drop(driver);
        fs::write(dir.join("rh-3.json"), "{not json").unwrap();
        let store = RhStore::open(&dir).unwrap();
        let sweep = store.sweep_after_restart(1);
        assert_eq!(sweep.abandoned, vec![TERM]);
        assert_eq!(sweep.unreadable.len(), 1);
        let record = durable(&dir);
        assert!(record.sent, "a restart never clears the send marker");
        assert!(matches!(record.state, RhState::Abandoned { .. }));
        // A new term is unaffected.
        let next = RhDriver::begin(
            store,
            settings(),
            RhBegin {
                cluster: "c".to_string(),
                node: "node-b".to_string(),
                peer_node: "node-a".to_string(),
                term: TERM + 2,
                origin: backend_origin(),
                now_ms: 1,
                unix_ms: 1,
            },
        )
        .unwrap();
        assert!(!next.record().sent);
        assert_eq!(next.record().state, RhState::IntentRecorded);
    }

    #[test]
    fn g2_a_second_begin_of_the_same_term_keeps_the_send() {
        let dir = temp_dir("rebegin");
        let mut driver = begin(&dir, backend_origin());
        let mut fake = Fake::new(&dir);
        fake.script(RhStep::Check, out("ok"));
        fake.script(RhStep::ObserveOwn, out("own none"));
        fake.script(RhStep::Assign, out("accepted"));
        run(&mut driver, &mut fake, 3);
        let again = begin(&dir, backend_origin());
        assert!(again.record().sent);
        assert_eq!(again.record().state, RhState::RouteUnknown);
    }

    #[test]
    fn g2_an_intent_is_never_rebound() {
        let dir = temp_dir("rebind");
        let _ = begin(&dir, backend_origin());
        let error = RhDriver::begin(
            RhStore::open(&dir).unwrap(),
            settings(),
            RhBegin {
                cluster: "c".to_string(),
                node: "node-b".to_string(),
                peer_node: "node-a".to_string(),
                term: TERM,
                origin: RhOrigin::Fencing {
                    incident_seq: 4,
                    incident_id: "22222222-2222-4222-8222-222222222222".to_string(),
                    attempt_token: 1,
                    confirmed_by: RhConfirmation::Backend,
                },
                now_ms: 1,
                unix_ms: 1,
            },
        )
        .unwrap_err();
        assert!(matches!(error, RhStoreError::Unreadable(_)));
    }

    #[test]
    fn g2_store_is_private_and_refuses_an_open_directory() {
        let dir = temp_dir("private");
        let _ = begin(&dir, backend_origin());
        assert_eq!(
            private_file_mode(&dir.join(format!("rh-{TERM}.json"))),
            Some(0o600)
        );
        assert_eq!(
            private_file_mode(&dir.join(format!("rh-{TERM}.intent.json"))),
            Some(0o600)
        );
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            RhStore::open(&dir),
            Err(RhStoreError::Untrusted(_))
        ));
    }

    #[test]
    fn g2_grammar_is_exact() {
        for bad in ["ok ", "OK", "ok\nok", "", "accepted extra"] {
            assert!(parse_check(&out(bad)).is_none() || bad == "ok", "{bad:?}");
        }
        assert!(parse_assign(&RhAnswer::NoAnswer).is_none());
        assert!(parse_own(&RhAnswer::NoAnswer).is_none());
        assert_eq!(
            parse_assign(&out("already accepted")),
            Some(Assign::Already)
        );
    }

    #[test]
    fn g2_deadline_turns_waiting_into_unknown_without_a_write() {
        let dir = temp_dir("deadline");
        let mut driver = begin(&dir, backend_origin());
        let mut fake = Fake::new(&dir);
        fake.script(RhStep::Check, out("ok"));
        fake.script(RhStep::ObserveOwn, out("own none"));
        fake.script(RhStep::Assign, out("accepted"));
        for _ in 0..40 {
            fake.script(RhStep::ObserveOwn, out("own none"));
            fake.script(RhStep::ObservePeer, out("peer absent"));
            fake.script(RhStep::ObserveOp, out("op pending"));
        }
        run(&mut driver, &mut fake, 60);
        assert_eq!(driver.record().state, RhState::RouteUnknown);
        assert_eq!(
            fake.steps.iter().filter(|s| **s == RhStep::Assign).count(),
            1
        );
    }

    /// Audit M-1: a confirmed route that can no longer be observed (no helper answer) is not
    /// kept as confirmed, and every complete cycle leaves its facts for the status.
    #[test]
    fn g2_confirmed_route_without_answers_is_not_kept_confirmed() {
        let dir = temp_dir("m1");
        let mut driver = begin(&dir, RhOrigin::Bootstrap);
        let mut fake = Fake::new(&dir);
        for _ in 0..2 {
            fake.script(RhStep::ObserveOwn, out("own all"));
            fake.script(RhStep::ObservePeer, out("peer absent"));
        }
        run(&mut driver, &mut fake, 8);
        assert!(matches!(
            driver.record().state,
            RhState::RouteConfirmed { .. }
        ));
        let record = durable(&dir);
        assert_eq!(record.last_cycle.as_deref(), Some("own=all peer=absent"));
        assert!(record.last_observed_unix_ms.is_some());
        let status = status_lines(Some(&record)).join("\n");
        assert!(status.contains("route.last_observation: at="), "{status}");
        assert!(status.contains("ROUTE_CONFIRMED(at="), "{status}");
        // The script is exhausted: every later read gives no answer.
        run(&mut driver, &mut fake, 30);
        assert_eq!(driver.record().state, RhState::RouteUnknown);
        assert_eq!(durable(&dir).state, RhState::RouteUnknown);
    }

    /// Audit M-1: a failed peer describe ("peer unknown") is C-3 not holding: never confirmed,
    /// and a confirmed route becomes lost.
    #[test]
    fn g2_peer_unknown_blocks_and_loses_confirmation() {
        let dir = temp_dir("peer-unknown");
        let mut driver = begin(&dir, RhOrigin::Bootstrap);
        let mut fake = Fake::new(&dir);
        for _ in 0..2 {
            fake.script(RhStep::ObserveOwn, out("own all"));
            fake.script(RhStep::ObservePeer, out("peer absent"));
        }
        fake.script(RhStep::ObserveOwn, out("own all"));
        fake.script(RhStep::ObservePeer, out("peer unknown"));
        run(&mut driver, &mut fake, 25);
        assert_eq!(driver.record().state, RhState::RouteLost);
    }

    /// Audit L-4: an unreadable record of the same term is never overwritten (it may hold a
    /// send marker), and a newer promotion supersedes an open RH durably.
    #[test]
    fn g2_unreadable_same_term_record_refuses_begin_and_superseded_is_durable() {
        let dir = temp_dir("l4");
        fs::write(dir.join(format!("rh-{TERM}.json")), "{broken").unwrap();
        assert!(
            RhDriver::begin(
                RhStore::open(&dir).unwrap(),
                settings(),
                RhBegin {
                    cluster: "c".to_string(),
                    node: "node-b".to_string(),
                    peer_node: "node-a".to_string(),
                    term: TERM,
                    origin: backend_origin(),
                    now_ms: 1,
                    unix_ms: 1,
                },
            )
            .is_err()
        );
        assert_eq!(
            fs::read_to_string(dir.join(format!("rh-{TERM}.json"))).unwrap(),
            "{broken"
        );
        let other = temp_dir("l4b");
        let mut driver = begin(&other, backend_origin());
        driver.abandon_superseded(5);
        let record = RhStore::open(&other).unwrap().load(TERM).unwrap().unwrap();
        assert_eq!(
            record.state,
            RhState::Abandoned {
                reason: "superseded".to_string()
            }
        );
    }

    #[test]
    fn g2_budget_constant_is_s_plus_q_plus_margin() {
        assert_eq!(RH_STEP_RETURN_BUDGET, Duration::from_millis(3_000));
        assert_eq!(
            crate::fencing_backend::ROUTE_STEP_RETURN_BUDGET,
            RH_STEP_RETURN_BUDGET
        );
        assert_eq!(RH_MIN_LEASE_REMAINING, Duration::from_millis(6_000));
    }

    // ---- r17: the requestId lookup and the one re-issue (contract R5) ---------------------------

    fn r17_settings() -> RhSettings {
        RhSettings {
            confirm_hold: Duration::from_secs(10),
            deadline: Duration::from_secs(300),
        }
    }

    fn r17_begin(dir: &Path, settings: RhSettings) -> RhDriver {
        RhDriver::begin(
            RhStore::open(dir).unwrap(),
            settings,
            RhBegin {
                cluster: "c".to_string(),
                node: "node-b".to_string(),
                peer_node: "node-a".to_string(),
                term: TERM,
                origin: backend_origin(),
                now_ms: 1_000,
                unix_ms: 1_700_000_000_000,
            },
        )
        .unwrap()
    }

    /// check → own none → `route-assign` answers unknown (the run r case).
    fn r17_timed_out(fake: &mut Fake) {
        fake.script(RhStep::Check, out("ok"));
        fake.script(RhStep::ObserveOwn, out("own none"));
        fake.script(RhStep::Assign, out("unknown"));
    }

    fn r17_cycle(fake: &mut Fake, own: &str, peer: &str, op: &str) {
        fake.script(RhStep::ObserveOwn, out(own));
        fake.script(RhStep::ObservePeer, out(peer));
        fake.script(RhStep::ObserveOp, out(op));
    }

    fn count(fake: &Fake, step: RhStep) -> usize {
        fake.steps.iter().filter(|s| **s == step).count()
    }

    #[test]
    fn r17_timeout_then_two_absent_lists_reissue_once_and_confirm() {
        let dir = temp_dir("r17-ok");
        let mut driver = r17_begin(&dir, r17_settings());
        let mut fake = Fake::new(&dir);
        r17_timed_out(&mut fake);
        r17_cycle(&mut fake, "own none", "peer absent", "op absent");
        r17_cycle(&mut fake, "own none", "peer absent", "op absent");
        fake.script(RhStep::Reissue, out("accepted"));
        for _ in 0..3 {
            r17_cycle(&mut fake, "own all", "peer absent", "op done-ok");
        }
        run(&mut driver, &mut fake, 60);
        assert_eq!(count(&fake, RhStep::Assign), 1);
        assert_eq!(count(&fake, RhStep::Reissue), 1, "exactly one re-issue");
        assert_eq!(
            fake.reissued_seen_on_reissue,
            vec![true],
            "marker durable first"
        );
        // UNKNOWN (the timeout) -> OBSERVING (the re-issue accepted) -> ROUTE_CONFIRMED (C-1..C-5).
        // (After the script ends, the reads stop answering and the confirmed route is no longer
        // kept, as before r17.)
        let states: Vec<&str> = fake
            .journal
            .iter()
            .map(|(line, _)| line.split(' ').next().unwrap())
            .collect();
        assert_eq!(
            &states[..2],
            &["ROUTE_UNKNOWN", "OBSERVING"][..],
            "{:?}",
            fake.journal
        );
        assert!(
            states[2].starts_with("ROUTE_CONFIRMED(at="),
            "{:?}",
            fake.journal
        );
        let record = durable(&dir);
        assert!(record.sent && record.reissued);
        // The re-issue came after the two absent lists, never before.
        let first_reissue = fake
            .steps
            .iter()
            .position(|s| *s == RhStep::Reissue)
            .unwrap();
        let ops_before = fake.steps[..first_reissue]
            .iter()
            .filter(|s| **s == RhStep::ObserveOp)
            .count();
        assert_eq!(ops_before, 2);
    }

    #[test]
    fn r17_a_seen_operation_forbids_the_reissue_for_ever() {
        for seen in ["op pending", "op done-error", "op mismatch", "op done-ok"] {
            let dir = temp_dir("r17-seen");
            let mut driver = r17_begin(&dir, r17_settings());
            let mut fake = Fake::new(&dir);
            r17_timed_out(&mut fake);
            r17_cycle(&mut fake, "own none", "peer absent", seen);
            for _ in 0..6 {
                r17_cycle(&mut fake, "own none", "peer absent", "op absent");
            }
            run(&mut driver, &mut fake, 80);
            assert_eq!(count(&fake, RhStep::Reissue), 0, "{seen}");
            assert!(durable(&dir).op_seen, "{seen}");
            assert_eq!(count(&fake, RhStep::Assign), 1);
        }
    }

    #[test]
    fn r17_an_incomplete_list_restarts_the_absent_count() {
        let dir = temp_dir("r17-restart-count");
        let mut driver = r17_begin(&dir, r17_settings());
        let mut fake = Fake::new(&dir);
        r17_timed_out(&mut fake);
        r17_cycle(&mut fake, "own none", "peer absent", "op absent");
        r17_cycle(&mut fake, "own none", "peer absent", "op unknown");
        r17_cycle(&mut fake, "own none", "peer absent", "op absent");
        // Past the script every read is inconclusive: the count never reaches two again.
        run(&mut driver, &mut fake, 80);
        assert_eq!(count(&fake, RhStep::Reissue), 0);
        assert_eq!(driver.record().state, RhState::RouteUnknown);
        assert!(!durable(&dir).reissued);
    }

    #[test]
    fn r17_own_or_peer_not_clear_blocks_the_reissue() {
        for (own, peer) in [
            ("own some", "peer absent"),
            ("own all", "peer absent"),
            ("own mismatch", "peer absent"),
            ("own none", "peer present"),
            ("own none", "peer unknown"),
        ] {
            let dir = temp_dir("r17-clear");
            let mut driver = r17_begin(&dir, r17_settings());
            let mut fake = Fake::new(&dir);
            r17_timed_out(&mut fake);
            for _ in 0..5 {
                r17_cycle(&mut fake, own, peer, "op absent");
            }
            run(&mut driver, &mut fake, 80);
            assert_eq!(count(&fake, RhStep::Reissue), 0, "{own} {peer}");
        }
    }

    #[test]
    fn r17_no_reissue_outside_the_window() {
        // deadline 70 s: the window closes 10 s after the start, before any absent list.
        let dir = temp_dir("r17-window");
        let mut driver = r17_begin(
            &dir,
            RhSettings {
                confirm_hold: Duration::from_secs(10),
                deadline: Duration::from_secs(70),
            },
        );
        let mut fake = Fake::new(&dir);
        r17_timed_out(&mut fake);
        for _ in 0..5 {
            r17_cycle(&mut fake, "own none", "peer absent", "op absent");
        }
        run(&mut driver, &mut fake, 80);
        assert_eq!(count(&fake, RhStep::Reissue), 0);
        // A deadline shorter than the margin never opens a window.
        let dir = temp_dir("r17-window-short");
        let mut driver = r17_begin(
            &dir,
            RhSettings {
                confirm_hold: Duration::from_secs(10),
                deadline: Duration::from_secs(50),
            },
        );
        let mut fake = Fake::new(&dir);
        r17_timed_out(&mut fake);
        for _ in 0..5 {
            r17_cycle(&mut fake, "own none", "peer absent", "op absent");
        }
        run(&mut driver, &mut fake, 80);
        assert_eq!(count(&fake, RhStep::Reissue), 0);
    }

    #[test]
    fn r17_window_boundaries_are_exact() {
        let dir = temp_dir("r17-bounds");
        let driver = r17_begin(&dir, r17_settings());
        let mut d = driver;
        d.record.state = RhState::RouteUnknown;
        d.record.sent = true;
        d.sent_at_ms = Some(1_000);
        // 20 s after the send, until (start 1 s + 300 s - 60 s) = 241 s exclusive.
        assert!(!d.reissue_allowed(20_999));
        assert!(d.reissue_allowed(21_000));
        assert!(d.reissue_allowed(240_999));
        assert!(!d.reissue_allowed(241_000));
        d.record.reissued = true;
        assert!(!d.reissue_allowed(30_000));
        d.record.reissued = false;
        d.record.op_seen = true;
        assert!(!d.reissue_allowed(30_000));
        d.record.op_seen = false;
        d.sent_at_ms = None;
        assert!(!d.reissue_allowed(30_000), "not after a restart");
        d.sent_at_ms = Some(1_000);
        d.record.state = RhState::Observing;
        assert!(!d.reissue_allowed(30_000));
    }

    #[test]
    fn r17_the_absent_lists_must_be_a_hold_apart() {
        let dir = temp_dir("r17-hold");
        let mut d = r17_begin(&dir, r17_settings());
        d.record.state = RhState::RouteUnknown;
        d.record.sent = true;
        d.sent_at_ms = Some(1_000);
        d.track_reissue(Own::None, Peer::Absent, Some(Op::Absent), 30_000);
        assert!(!d.reissue_ready, "one list");
        d.track_reissue(Own::None, Peer::Absent, Some(Op::Absent), 39_999);
        assert!(!d.reissue_ready, "9.999 s apart");
        d.track_reissue(Own::None, Peer::Absent, Some(Op::Absent), 40_000);
        assert!(d.reissue_ready, "10 s apart");
        d.track_reissue(Own::None, Peer::Absent, Some(Op::Unknown), 41_000);
        assert!(
            !d.reissue_ready && d.absent_reads == 0,
            "reset by an incomplete list"
        );
    }

    #[test]
    fn r17_no_third_send_after_the_reissue() {
        for answer in [
            out("unknown"),
            out("refused"),
            out("blocked"),
            out("already intent"),
            RhAnswer::NoAnswer,
        ] {
            let dir = temp_dir("r17-third");
            let mut driver = r17_begin(&dir, r17_settings());
            let mut fake = Fake::new(&dir);
            r17_timed_out(&mut fake);
            r17_cycle(&mut fake, "own none", "peer absent", "op absent");
            r17_cycle(&mut fake, "own none", "peer absent", "op absent");
            fake.script(RhStep::Reissue, answer.clone());
            for _ in 0..8 {
                r17_cycle(&mut fake, "own none", "peer absent", "op absent");
            }
            run(&mut driver, &mut fake, 120);
            assert_eq!(count(&fake, RhStep::Assign), 1, "{answer:?}");
            assert_eq!(count(&fake, RhStep::Reissue), 1, "{answer:?}");
            assert_eq!(driver.record().state, RhState::RouteUnknown, "{answer:?}");
            assert!(durable(&dir).reissued);
        }
    }

    #[test]
    fn r17_a_restarted_process_never_reissues() {
        let dir = temp_dir("r17-restart");
        let mut driver = r17_begin(&dir, r17_settings());
        let mut fake = Fake::new(&dir);
        r17_timed_out(&mut fake);
        run(&mut driver, &mut fake, 3);
        assert!(durable(&dir).sent);
        // The same term begun again (a new process would not even be the Active; the strongest
        // case): the record shows a send, so the RH is ROUTE_UNKNOWN with no send time.
        let mut again = r17_begin(&dir, r17_settings());
        assert_eq!(again.record().state, RhState::RouteUnknown);
        let mut fake = Fake::new(&dir);
        for _ in 0..6 {
            r17_cycle(&mut fake, "own none", "peer absent", "op absent");
        }
        run(&mut again, &mut fake, 80);
        assert_eq!(count(&fake, RhStep::Reissue), 0);
        assert_eq!(count(&fake, RhStep::Assign), 0);
    }

    #[test]
    fn r17_lock_or_lease_change_at_the_reissue_sends_nothing() {
        for change in ["lock", "lease-lost", "hold"] {
            let dir = temp_dir("r17-recheck");
            let mut driver = r17_begin(&dir, r17_settings());
            let mut fake = Fake::new(&dir);
            r17_timed_out(&mut fake);
            r17_cycle(&mut fake, "own none", "peer absent", "op absent");
            r17_cycle(&mut fake, "own none", "peer absent", "op absent");
            let mut guard = 0;
            while !driver.reissue_ready {
                driver.tick(&mut fake).unwrap();
                fake.advance(3_000);
                guard += 1;
                assert!(guard < 60, "the re-issue never became ready");
            }
            match change {
                "lock" => fake.lock_safe = false,
                "lease-lost" => fake.facts.lease_term = None,
                _ => fake.facts.node = NodeClass::ActiveHold,
            }
            for _ in 0..30 {
                driver.tick(&mut fake).unwrap();
                fake.advance(3_000);
            }
            assert_eq!(count(&fake, RhStep::Reissue), 0, "{change}");
            match change {
                "lock" => {
                    assert!(
                        durable(&dir).reissued,
                        "the marker was written before the re-check"
                    );
                    assert_eq!(driver.record().state, RhState::RouteUnknown);
                }
                "lease-lost" => assert!(matches!(driver.record().state, RhState::Abandoned { .. })),
                _ => assert!(!durable(&dir).reissued),
            }
        }
    }

    #[test]
    fn r17_a_stale_readiness_is_dropped() {
        let dir = temp_dir("r17-stale");
        let mut driver = r17_begin(&dir, r17_settings());
        let mut fake = Fake::new(&dir);
        r17_timed_out(&mut fake);
        r17_cycle(&mut fake, "own none", "peer absent", "op absent");
        r17_cycle(&mut fake, "own none", "peer absent", "op absent");
        let mut guard = 0;
        while !driver.reissue_ready {
            driver.tick(&mut fake).unwrap();
            fake.advance(3_000);
            guard += 1;
            assert!(guard < 60);
        }
        // Held (no renewal) longer than the readiness lasts, then allowed again: no re-issue from
        // the old observations; the RH goes back to observing.
        fake.facts.renewed_this_tick = false;
        for _ in 0..4 {
            driver.tick(&mut fake).unwrap();
            fake.advance(3_000);
        }
        fake.facts.renewed_this_tick = true;
        driver.tick(&mut fake).unwrap();
        assert_eq!(count(&fake, RhStep::Reissue), 0);
        assert!(!driver.reissue_ready);
        assert!(!durable(&dir).reissued);
    }
}
