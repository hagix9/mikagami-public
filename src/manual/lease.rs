//! Durable ownership record and operation lease of the manual control plane.
//!
//! One file on the Witness host records the durable owner of the VIP, an
//! epoch that increases on every ownership change, a fencing sequence `seq`
//! that increases on every lock grant, and at most one in-flight move
//! operation. Every transition is an atomic, fsync'ed replace performed under
//! an exclusive lock.
//!
//! Safety rules enforced here (independent of the controller's behaviour):
//!
//! * A move may start only from the recorded owner at the observed epoch.
//! * The controller records each phase *before* it performs the step (write
//!   ahead), and phases advance one step at a time. Once a mutating phase was
//!   recorded, the operation never expires by time: only `commit`, `abort`
//!   (after verified restoration) or `reconcile` (after verified observation
//!   *and* an explicit operator abandon of that very operation) can clear it.
//!   A crashed controller therefore leaves a visible, blocking record instead
//!   of a silently expired lock.
//! * An operation that has not yet recorded a mutating phase expires after
//!   its TTL, which is only a liveness aid (no resource was touched). The
//!   expiry compares the Witness wall clock with itself; a clock that steps
//!   backwards only delays a takeover (liveness), a clock that steps forwards
//!   can end an `Acquired` lock early, which is safe because the old holder's
//!   next phase record is then refused (its `op_id` is gone).
//! * `seq` is the fencing token: every `acquire` (including a takeover) and
//!   every `reconcile` increases it. Node agents remember the highest token
//!   they accepted for a mutating call and refuse smaller ones.
//! * The file is strict (unknown or missing keys are errors), carries a
//!   content checksum, and a missing file next to an initialisation sentinel
//!   is never treated as "new". A damaged or foreign state file is never
//!   repaired or reset: every request is refused until an operator inspects
//!   it.
//! * The file cannot prove that it is not an *older copy* of itself (a
//!   restored snapshot). That is detected outside the file: the controller
//!   compares `seq`/`epoch` with the fencing high-water mark kept on the
//!   nodes (see `fence.rs`).

use super::exclusion::ExclusiveProof;
use super::fsutil::{self, StoreLock};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Duration;

pub(crate) const SCHEMA: &str = "mkg-lease/v3";
const HISTORY_LIMIT: usize = 50;
const LOCK_WAIT: Duration = Duration::from_secs(10);
pub(crate) const MIN_TTL_SECS: u64 = 30;
pub(crate) const MAX_TTL_SECS: u64 = 3600;
/// Largest `evidence` value accepted (serialized). The read limit of the
/// file is far above the largest state this allows to be written.
pub(crate) const MAX_EVIDENCE_BYTES: usize = 8 * 1024;
/// A state larger than this is never written (reads accept up to 4 MiB).
const MAX_STATE_BYTES: usize = 1 << 20;
const READ_LIMIT: u64 = 4 << 20;
/// A mutating operation may be abandoned by `reconcile` only after the
/// controller has been silent for this long. A live controller can be quiet
/// for several minutes inside one step (cloud change 180 s + settle 90 s +
/// reads), so this is a plausibility guard in addition to, never instead of,
/// the operator naming the operation.
pub(crate) const ABANDON_QUIET_SECS: u64 = 900;

/// A key that must be present; `null` is spelled out.
fn required<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Phase {
    /// The lock is held; no resource has been touched.
    Acquired,
    /// The source service is about to be / is being stopped.
    SourceQuiescing,
    /// The source alias is about to be / has been removed.
    SourceReleased,
    /// The target alias is about to be / is being added.
    TargetAssigning,
    /// The target holds the alias; its service is about to be started.
    TargetAssigned,
    /// The target service runs and serves; the commit is next.
    TargetStarted,
}

impl Phase {
    /// `true` once the controller may have changed any resource.
    pub(crate) fn mutating(self) -> bool {
        self >= Self::SourceQuiescing
    }

    /// The only phase that may follow this one.
    pub(crate) fn next(self) -> Option<Self> {
        match self {
            Self::Acquired => Some(Self::SourceQuiescing),
            Self::SourceQuiescing => Some(Self::SourceReleased),
            Self::SourceReleased => Some(Self::TargetAssigning),
            Self::TargetAssigning => Some(Self::TargetAssigned),
            Self::TargetAssigned => Some(Self::TargetStarted),
            Self::TargetStarted => None,
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        serde_json::from_value(Value::String(value.to_string())).ok()
    }

    pub(crate) fn name(self) -> String {
        serde_json::to_value(self)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Op {
    pub(crate) op_id: String,
    pub(crate) source: String,
    pub(crate) target: String,
    pub(crate) phase: Phase,
    pub(crate) controller: String,
    pub(crate) started_at: u64,
    pub(crate) expires_at: u64,
    pub(crate) epoch_at_start: u64,
    /// The fencing token of this operation (the lease `seq` at its grant).
    pub(crate) seq: u64,
    /// Witness clock of the last record written for this operation.
    pub(crate) last_seen: u64,
    pub(crate) evidence: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HistoryEntry {
    pub(crate) kind: String,
    #[serde(deserialize_with = "required")]
    pub(crate) op_id: Option<String>,
    #[serde(deserialize_with = "required")]
    pub(crate) from: Option<String>,
    #[serde(deserialize_with = "required")]
    pub(crate) to: Option<String>,
    pub(crate) epoch: u64,
    pub(crate) at: u64,
    pub(crate) note: String,
    pub(crate) evidence: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LeaseState {
    pub(crate) schema: String,
    pub(crate) cluster: String,
    pub(crate) resource: String,
    #[serde(deserialize_with = "required")]
    pub(crate) owner: Option<String>,
    pub(crate) epoch: u64,
    /// Fencing sequence: increases on every lock grant and every reconcile.
    pub(crate) seq: u64,
    #[serde(deserialize_with = "required")]
    pub(crate) op: Option<Op>,
    pub(crate) history: Vec<HistoryEntry>,
    pub(crate) updated_at: u64,
    /// SHA-256 of the compact serialization with this field empty.
    pub(crate) checksum: String,
}

impl LeaseState {
    fn blank(cluster: &str) -> Self {
        Self {
            schema: SCHEMA.to_string(),
            cluster: cluster.to_string(),
            resource: "vip".to_string(),
            owner: None,
            epoch: 0,
            seq: 0,
            op: None,
            history: Vec::new(),
            updated_at: 0,
            checksum: String::new(),
        }
    }

    fn push_history(&mut self, entry: HistoryEntry) {
        self.history.push(entry);
        if self.history.len() > HISTORY_LIMIT {
            let excess = self.history.len() - HISTORY_LIMIT;
            self.history.drain(..excess);
        }
    }

    pub(crate) fn compute_checksum(&self) -> String {
        let mut copy = self.clone();
        copy.checksum = String::new();
        match serde_json::to_vec(&copy) {
            Ok(bytes) => fsutil::sha256_hex(&bytes),
            Err(_) => String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LeaseError {
    /// A rule forbids the request; the stored state is unchanged.
    Refused(String),
    /// The state could not be read or written safely.
    Storage(String),
}

impl std::fmt::Display for LeaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(message) => write!(f, "{message}"),
            Self::Storage(message) => write!(f, "lease storage error: {message}"),
        }
    }
}

fn refuse<T>(message: impl Into<String>) -> Result<T, LeaseError> {
    Err(LeaseError::Refused(message.into()))
}

fn check_evidence(evidence: &Value) -> Result<(), LeaseError> {
    let size = serde_json::to_vec(evidence).map_or(usize::MAX, |b| b.len());
    if size > MAX_EVIDENCE_BYTES {
        return refuse(format!(
            "evidence is {size} bytes; at most {MAX_EVIDENCE_BYTES} are accepted"
        ));
    }
    Ok(())
}

/// The lease file plus its lock and its initialisation sentinel.
pub(crate) struct LeaseStore {
    path: PathBuf,
    cluster: String,
    nodes: Vec<String>,
    owner_uid: u32,
    lock_wait: Duration,
}

impl LeaseStore {
    pub(crate) fn new(path: PathBuf, cluster: &str, nodes: Vec<String>, owner_uid: u32) -> Self {
        Self {
            path,
            cluster: cluster.to_string(),
            nodes,
            owner_uid,
            lock_wait: LOCK_WAIT,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_lock_wait(mut self, wait: Duration) -> Self {
        self.lock_wait = wait;
        self
    }

    fn sentinel_path(&self) -> PathBuf {
        let mut name = self
            .path
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_default();
        name.push(".initialised");
        self.path.with_file_name(name)
    }

    fn lock(&self) -> Result<StoreLock, LeaseError> {
        StoreLock::acquire(&self.path, self.owner_uid, self.lock_wait).map_err(LeaseError::Storage)
    }

    fn sentinel_exists(&self) -> Result<bool, LeaseError> {
        match fs::symlink_metadata(self.sentinel_path()) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(LeaseError::Storage(format!("sentinel: {e}"))),
        }
    }

    fn load(&self) -> Result<LeaseState, LeaseError> {
        match fs::symlink_metadata(&self.path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // A store that was initialised once never silently becomes
                // "new" again: that would hand out epoch 1 a second time.
                if self.sentinel_exists()? {
                    return Err(LeaseError::Storage(
                        "the state file is missing although this store was initialised before \
                         (sentinel present); not treating it as new — inspect the host, restore \
                         the file, or re-initialise explicitly with `resource init vip --reinit`"
                            .to_string(),
                    ));
                }
                return Ok(LeaseState::blank(&self.cluster));
            }
            Err(e) => return Err(LeaseError::Storage(e.to_string())),
            Ok(_) => {}
        }
        fsutil::check_trusted_file(&self.path, self.owner_uid)
            .map_err(|e| LeaseError::Storage(format!("state file {e}")))?;
        let bytes = fsutil::read_regular_nofollow(&self.path, READ_LIMIT)
            .map_err(|e| LeaseError::Storage(format!("cannot read state: {e}")))?;
        let state: LeaseState = serde_json::from_slice(&bytes)
            .map_err(|e| LeaseError::Storage(format!("state is damaged: {e}")))?;
        if state.schema != SCHEMA {
            return Err(LeaseError::Storage(format!(
                "unsupported state schema {:?}",
                state.schema
            )));
        }
        if state.cluster != self.cluster {
            return Err(LeaseError::Storage(
                "state belongs to another cluster; refusing".to_string(),
            ));
        }
        if state.checksum != state.compute_checksum() {
            return Err(LeaseError::Storage(
                "state checksum mismatch (edited or damaged); refusing".to_string(),
            ));
        }
        if let Some(owner) = &state.owner
            && !self.nodes.contains(owner)
        {
            return Err(LeaseError::Storage(
                "state names an unknown owner; refusing".to_string(),
            ));
        }
        if let Some(op) = &state.op
            && (!self.nodes.contains(&op.source)
                || !self.nodes.contains(&op.target)
                || op.seq > state.seq
                || op.epoch_at_start > state.epoch)
        {
            return Err(LeaseError::Storage(
                "the recorded operation is inconsistent with the record; refusing".to_string(),
            ));
        }
        Ok(state)
    }

    /// Remove temporary files of interrupted writes. Every writer holds the
    /// store lock, so any such file seen under the lock is an orphan.
    fn remove_orphans(&self) {
        let Some(dir) = self.path.parent() else {
            return;
        };
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(".lease-")
                && name.ends_with(".tmp")
                && entry.file_type().is_ok_and(|t| t.is_file())
            {
                let _ = fs::remove_file(entry.path());
            }
        }
    }

    fn save(&self, state: &mut LeaseState) -> Result<(), LeaseError> {
        state.checksum = state.compute_checksum();
        let mut bytes =
            serde_json::to_vec_pretty(state).map_err(|e| LeaseError::Storage(e.to_string()))?;
        bytes.push(b'\n');
        if bytes.len() > MAX_STATE_BYTES {
            return refuse("the state would exceed its size limit; not written");
        }
        let dir = self
            .path
            .parent()
            .ok_or_else(|| LeaseError::Storage("state path has no parent".to_string()))?;
        let tmp = dir.join(format!(".lease-{}.tmp", super::proto::random_hex(8)));
        let write = || -> io::Result<()> {
            let mut file = fsutil::create_new(&tmp, 0o600)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&tmp, &self.path)?;
            fsutil::fsync_dir(dir)
        };
        write().map_err(|e| {
            let _ = fs::remove_file(&tmp);
            LeaseError::Storage(format!("cannot persist state: {e}"))
        })
    }

    /// Read-only snapshot (still taken under the lock for a consistent view).
    pub(crate) fn status(&self) -> Result<LeaseState, LeaseError> {
        let _guard = self.lock()?;
        self.load()
    }

    /// Apply `change` to the current state and persist the result if it
    /// succeeds. A refused change leaves the stored state byte-identical.
    fn update<F>(&self, change: F) -> Result<LeaseState, LeaseError>
    where
        F: FnOnce(&mut LeaseState) -> Result<(), LeaseError>,
    {
        let _guard = self.lock()?;
        let mut state = self.load()?;
        change(&mut state)?;
        self.remove_orphans();
        self.save(&mut state)?;
        Ok(state)
    }

    fn known(&self, node: &str) -> Result<(), LeaseError> {
        if self.nodes.iter().any(|n| n == node) {
            Ok(())
        } else {
            refuse(format!("unknown node {node:?}"))
        }
    }

    /// Create the ownership record. With `reinit` a store whose file is gone
    /// (sentinel present) may be created anew; the sequence and epoch then
    /// start above the floors the caller read from the nodes' fencing marks,
    /// so a re-created record can never look older than what the nodes saw.
    pub(crate) fn init(
        &self,
        _proof: &ExclusiveProof,
        owner: &str,
        now: u64,
        reinit: bool,
        seq_floor: u64,
        epoch_floor: u64,
    ) -> Result<LeaseState, LeaseError> {
        self.known(owner)?;
        let _guard = self.lock()?;
        let existing = fs::symlink_metadata(&self.path).is_ok();
        let was_initialised = self.sentinel_exists()?;
        let mut state = if existing {
            self.load()?
        } else {
            if was_initialised && !reinit {
                return refuse(
                    "the state file is missing although this store was initialised before; \
                     re-initialising needs the explicit --reinit",
                );
            }
            LeaseState::blank(&self.cluster)
        };
        if reinit && existing {
            return refuse("--reinit is only for a missing state file; the record exists");
        }
        if state.owner.is_some() || !state.history.is_empty() {
            return refuse("already initialised; use reconcile to change a recorded owner");
        }
        state.owner = Some(owner.to_string());
        state.epoch = epoch_floor.max(1);
        state.seq = seq_floor.max(1);
        state.updated_at = now;
        let epoch = state.epoch;
        state.push_history(HistoryEntry {
            kind: if was_initialised { "reinit" } else { "init" }.to_string(),
            op_id: None,
            from: None,
            to: Some(owner.to_string()),
            epoch,
            at: now,
            note: String::new(),
            evidence: Value::Null,
        });
        // The sentinel first: if the state write then fails, "missing state"
        // is reported instead of silently starting over.
        if !was_initialised {
            fsutil::write_new_durable(&self.sentinel_path(), b"initialised\n", 0o600)
                .map_err(|e| LeaseError::Storage(format!("sentinel: {e}")))?;
        }
        self.remove_orphans();
        self.save(&mut state)?;
        Ok(state)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn acquire(
        &self,
        _proof: &ExclusiveProof,
        op_id: &str,
        source: &str,
        target: &str,
        ttl_secs: u64,
        controller: &str,
        expect_epoch: u64,
        now: u64,
    ) -> Result<LeaseState, LeaseError> {
        self.known(source)?;
        self.known(target)?;
        if source == target {
            return refuse("source and target are the same node");
        }
        let ttl = ttl_secs.clamp(MIN_TTL_SECS, MAX_TTL_SECS);
        self.update(|state| {
            let Some(owner) = state.owner.clone() else {
                return refuse("ownership is not initialised; run `resource init vip` first");
            };
            if let Some(op) = &state.op {
                if op.op_id == op_id {
                    return refuse("operation id already in use");
                }
                if op.phase.mutating() {
                    return refuse(format!(
                        "unresolved operation {} is in phase {} (source {}, target {}); \
                         run `resource reconcile vip` after inspecting the nodes",
                        op.op_id,
                        op.phase.name(),
                        op.source,
                        op.target
                    ));
                }
                if op.expires_at > now {
                    return refuse(format!("another move holds the lock (op {})", op.op_id));
                }
                // An expired operation that never touched a resource.
                let expired = op.clone();
                state.push_history(HistoryEntry {
                    kind: "expired".to_string(),
                    op_id: Some(expired.op_id),
                    from: Some(expired.source),
                    to: Some(expired.target),
                    epoch: state.epoch,
                    at: now,
                    note: "lock expired before any mutating phase".to_string(),
                    evidence: Value::Null,
                });
                state.op = None;
            }
            if owner != source {
                return refuse(format!(
                    "source {source:?} is not the recorded owner {owner:?}"
                ));
            }
            if state.epoch != expect_epoch {
                return refuse(format!(
                    "epoch changed (expected {expect_epoch}, recorded {})",
                    state.epoch
                ));
            }
            let Some(seq) = state.seq.checked_add(1) else {
                return refuse("the fencing sequence is exhausted");
            };
            // The commit will need the next epoch; refuse now, before
            // anything is changed, when there is none (audit NV-10).
            if state.epoch.checked_add(1).is_none() {
                return refuse("the epoch is exhausted");
            }
            state.seq = seq;
            state.op = Some(Op {
                op_id: op_id.to_string(),
                source: source.to_string(),
                target: target.to_string(),
                phase: Phase::Acquired,
                controller: controller.chars().take(64).collect(),
                started_at: now,
                expires_at: now.saturating_add(ttl),
                epoch_at_start: state.epoch,
                seq,
                last_seen: now,
                evidence: Value::Null,
            });
            state.updated_at = now;
            Ok(())
        })
    }

    /// Record the next phase before the controller performs it. Only the
    /// same phase again (to attach evidence) or its direct successor is
    /// accepted.
    pub(crate) fn phase(
        &self,
        _proof: &ExclusiveProof,
        op_id: &str,
        phase: Phase,
        evidence: Option<Value>,
        now: u64,
    ) -> Result<LeaseState, LeaseError> {
        if let Some(value) = &evidence {
            check_evidence(value)?;
        }
        self.update(|state| {
            let epoch = state.epoch;
            let Some(op) = state.op.as_mut() else {
                return refuse("no operation in progress");
            };
            if op.op_id != op_id {
                return refuse(format!(
                    "operation {} holds the lock, not {op_id}",
                    op.op_id
                ));
            }
            if op.epoch_at_start != epoch {
                return refuse("the epoch changed since the operation started");
            }
            if !op.phase.mutating() && op.expires_at <= now {
                return refuse("the operation lock expired before it mutated anything");
            }
            if phase != op.phase && Some(phase) != op.phase.next() {
                return refuse(format!(
                    "phase {} cannot follow {}",
                    phase.name(),
                    op.phase.name()
                ));
            }
            op.phase = phase;
            op.last_seen = now;
            if let Some(value) = evidence {
                op.evidence = value;
            }
            state.updated_at = now;
            Ok(())
        })
    }

    /// Finish a verified move: the target becomes the durable owner.
    pub(crate) fn commit(
        &self,
        _proof: &ExclusiveProof,
        op_id: &str,
        new_owner: &str,
        evidence: Value,
        now: u64,
    ) -> Result<LeaseState, LeaseError> {
        self.known(new_owner)?;
        check_evidence(&evidence)?;
        self.update(|state| {
            let Some(op) = state.op.clone() else {
                return refuse("no operation in progress");
            };
            if op.op_id != op_id {
                return refuse(format!(
                    "operation {} holds the lock, not {op_id}",
                    op.op_id
                ));
            }
            if op.epoch_at_start != state.epoch {
                return refuse("the epoch changed since the operation started");
            }
            if op.target != new_owner {
                return refuse("the new owner is not the operation's target");
            }
            if op.phase != Phase::TargetStarted {
                return refuse(format!(
                    "cannot commit from phase {} (target start not recorded)",
                    op.phase.name()
                ));
            }
            if state.owner.as_deref() != Some(op.source.as_str()) {
                return refuse("the recorded owner changed during the operation");
            }
            let Some(epoch) = state.epoch.checked_add(1) else {
                return refuse("the epoch is exhausted");
            };
            state.owner = Some(new_owner.to_string());
            state.epoch = epoch;
            state.push_history(HistoryEntry {
                kind: "move".to_string(),
                op_id: Some(op.op_id),
                from: Some(op.source),
                to: Some(new_owner.to_string()),
                epoch,
                at: now,
                note: String::new(),
                evidence,
            });
            state.op = None;
            state.updated_at = now;
            Ok(())
        })
    }

    /// Clear an operation after the controller verified that every resource
    /// is back at the recorded owner (or was never touched).
    pub(crate) fn abort(
        &self,
        _proof: &ExclusiveProof,
        op_id: &str,
        restored_owner: &str,
        reason: &str,
        now: u64,
    ) -> Result<LeaseState, LeaseError> {
        self.known(restored_owner)?;
        self.update(|state| {
            let Some(op) = state.op.clone() else {
                return refuse("no operation in progress");
            };
            if op.op_id != op_id {
                return refuse(format!(
                    "operation {} holds the lock, not {op_id}",
                    op.op_id
                ));
            }
            if op.epoch_at_start != state.epoch {
                return refuse("the epoch changed since the operation started");
            }
            if state.owner.as_deref() != Some(restored_owner) {
                return refuse("restored owner differs from the recorded owner");
            }
            state.push_history(HistoryEntry {
                kind: "abort".to_string(),
                op_id: Some(op.op_id),
                from: Some(op.source),
                to: Some(op.target),
                epoch: state.epoch,
                at: now,
                note: reason.chars().take(200).collect(),
                evidence: Value::Null,
            });
            state.op = None;
            state.updated_at = now;
            Ok(())
        })
    }

    /// Adopt an observed, verified state as the durable truth and clear any
    /// in-flight operation. The epoch and the sequence always increase so a
    /// reconciliation is visible in the history and fences the old holder.
    ///
    /// The caller states the epoch and the operation it observed; if either
    /// changed in the meantime (another controller moved on) nothing is
    /// written. A *mutating* operation is cut only when the caller names that
    /// very operation (`abandon`) and its controller has been silent for
    /// [`ABANDON_QUIET_SECS`]; an unexpired `Acquired` operation is never cut.
    /// `floors` is `(seq, epoch)`: the new values are at least these (taken
    /// from the nodes' fencing marks).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn reconcile(
        &self,
        _proof: &ExclusiveProof,
        observed_owner: &str,
        expect_epoch: u64,
        expect_op: Option<&str>,
        abandon: Option<&str>,
        floors: (u64, u64),
        reason: &str,
        evidence: Value,
        now: u64,
    ) -> Result<LeaseState, LeaseError> {
        self.known(observed_owner)?;
        check_evidence(&evidence)?;
        self.update(|state| {
            if state.owner.is_none() {
                return refuse("ownership is not initialised; run `resource init vip` first");
            }
            if state.epoch != expect_epoch
                || state.op.as_ref().map(|op| op.op_id.as_str()) != expect_op
            {
                return refuse(
                    "the record changed since it was observed (another controller acted); \
                     re-observe and retry",
                );
            }
            if let Some(op) = &state.op {
                if !op.phase.mutating() {
                    if op.expires_at > now {
                        return refuse(format!(
                            "operation {} is still in progress (not yet mutating); wait or \
                             let it expire",
                            op.op_id
                        ));
                    }
                } else {
                    if abandon != Some(op.op_id.as_str()) {
                        return refuse(format!(
                            "operation {} is in phase {}; cutting a mutating operation needs \
                             the operator to name it (--abandon-op {})",
                            op.op_id,
                            op.phase.name(),
                            op.op_id
                        ));
                    }
                    let quiet = now.saturating_sub(op.last_seen);
                    if quiet < ABANDON_QUIET_SECS {
                        return refuse(format!(
                            "operation {} was active {quiet} s ago; its controller may still be \
                             running (wait at least {ABANDON_QUIET_SECS} s of silence)",
                            op.op_id
                        ));
                    }
                }
            }
            let Some(epoch) = state.epoch.checked_add(1) else {
                return refuse("the epoch is exhausted");
            };
            let Some(seq) = state.seq.checked_add(1) else {
                return refuse("the fencing sequence is exhausted");
            };
            // Never below what the nodes have already seen (a restored older
            // copy of the record is repaired this way, with evidence).
            let (seq_floor, epoch_floor) = floors;
            let (seq, epoch) = (seq.max(seq_floor), epoch.max(epoch_floor));
            let from = state.owner.clone();
            let op_id = state.op.as_ref().map(|op| op.op_id.clone());
            state.owner = Some(observed_owner.to_string());
            state.epoch = epoch;
            state.seq = seq;
            state.push_history(HistoryEntry {
                kind: "reconcile".to_string(),
                op_id,
                from,
                to: Some(observed_owner.to_string()),
                epoch,
                at: now,
                note: reason.chars().take(200).collect(),
                evidence,
            });
            state.op = None;
            state.updated_at = now;
            Ok(())
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::manual::fsutil::tests::{my_uid, temp_dir};
    use std::os::unix::fs::PermissionsExt;

    pub(crate) fn store(label: &str) -> (LeaseStore, PathBuf) {
        let dir = temp_dir(label);
        (
            LeaseStore::new(
                dir.join("lease.json"),
                "test",
                vec!["node-a".to_string(), "node-b".to_string()],
                my_uid(),
            ),
            dir,
        )
    }

    fn init(store: &LeaseStore, owner: &str, now: u64) -> Result<LeaseState, LeaseError> {
        store.init(&ExclusiveProof::for_test(), owner, now, false, 0, 0)
    }

    fn initialised(label: &str) -> (LeaseStore, PathBuf) {
        let (store, dir) = store(label);
        init(&store, "node-a", 1000).unwrap();
        (store, dir)
    }

    /// Walk an operation through the phases, one step at a time.
    fn advance(store: &LeaseStore, op: &str, upto: Phase, now: u64) {
        let mut phase = Phase::Acquired;
        while phase != upto {
            phase = phase.next().expect("phase order");
            store
                .phase(&ExclusiveProof::for_test(), op, phase, None, now)
                .unwrap();
        }
    }

    /// Rewrite the state file with a valid checksum.
    fn edit(dir: &std::path::Path, change: impl FnOnce(&mut LeaseState)) {
        let path = dir.join("lease.json");
        let mut state: LeaseState = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        change(&mut state);
        state.checksum = state.compute_checksum();
        fs::write(&path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();
    }

    #[test]
    fn init_is_once_only_and_requires_a_known_node() {
        let (store, dir) = store("lease-init");
        assert!(matches!(
            init(&store, "node-z", 1),
            Err(LeaseError::Refused(_))
        ));
        let state = init(&store, "node-a", 1).unwrap();
        assert_eq!((state.owner.as_deref(), state.epoch), (Some("node-a"), 1));
        assert!(matches!(
            init(&store, "node-b", 2),
            Err(LeaseError::Refused(_))
        ));
        assert_eq!(store.status().unwrap().owner.as_deref(), Some("node-a"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn acquire_requires_owner_epoch_and_distinct_nodes() {
        let (store, dir) = initialised("lease-acq");
        let acquire = |op: &str, s: &str, t: &str, epoch: u64| {
            store.acquire(
                &ExclusiveProof::for_test(),
                op,
                s,
                t,
                60,
                "ctl",
                epoch,
                1000,
            )
        };
        assert!(
            acquire("op1", "node-b", "node-a", 1).is_err(),
            "not the owner"
        );
        assert!(acquire("op1", "node-a", "node-a", 1).is_err(), "same node");
        assert!(
            acquire("op1", "node-a", "node-b", 2).is_err(),
            "stale epoch"
        );
        assert!(
            acquire("op1", "node-a", "node-x", 1).is_err(),
            "unknown node"
        );
        let state = acquire("op1", "node-a", "node-b", 1).unwrap();
        assert_eq!(state.op.unwrap().phase, Phase::Acquired);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn second_acquire_is_refused_while_the_first_is_live() {
        let (store, dir) = initialised("lease-two");
        store
            .acquire(
                &ExclusiveProof::for_test(),
                "op1",
                "node-a",
                "node-b",
                60,
                "c1",
                1,
                1000,
            )
            .unwrap();
        let refused = store.acquire(
            &ExclusiveProof::for_test(),
            "op2",
            "node-a",
            "node-b",
            60,
            "c2",
            1,
            1010,
        );
        assert!(matches!(refused, Err(LeaseError::Refused(m)) if m.contains("holds the lock")));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn an_operation_id_is_never_reused() {
        // Mutant M16: dropping the op_id reuse check.
        let (store, dir) = initialised("lease-opid");
        store
            .acquire(
                &ExclusiveProof::for_test(),
                "op1",
                "node-a",
                "node-b",
                60,
                "c1",
                1,
                1000,
            )
            .unwrap();
        let again = store.acquire(
            &ExclusiveProof::for_test(),
            "op1",
            "node-a",
            "node-b",
            60,
            "c1",
            1,
            5000,
        );
        assert!(matches!(again, Err(LeaseError::Refused(m)) if m.contains("already in use")));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn unmutated_operation_expires_but_a_mutating_one_never_does() {
        let (store, dir) = initialised("lease-expiry");
        store
            .acquire(
                &ExclusiveProof::for_test(),
                "op1",
                "node-a",
                "node-b",
                60,
                "c",
                1,
                1000,
            )
            .unwrap();
        // Past the TTL and still in Acquired: takeover is allowed.
        store
            .acquire(
                &ExclusiveProof::for_test(),
                "op2",
                "node-a",
                "node-b",
                60,
                "c",
                1,
                2000,
            )
            .unwrap();
        store
            .phase(
                &ExclusiveProof::for_test(),
                "op2",
                Phase::SourceQuiescing,
                None,
                2001,
            )
            .unwrap();
        // Far past the TTL, but a mutating phase was recorded: blocked.
        let refused = store.acquire(
            &ExclusiveProof::for_test(),
            "op3",
            "node-a",
            "node-b",
            60,
            "c",
            1,
            9_999_999,
        );
        assert!(
            matches!(refused, Err(LeaseError::Refused(m)) if m.contains("unresolved operation op2"))
        );
        let state = store.status().unwrap();
        assert!(state.history.iter().any(|h| h.kind == "expired"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn phases_advance_one_step_at_a_time_and_only_for_the_holder() {
        // B-08. Skipping a step is refused: the controller records each phase
        // before acting, so a skipped record means a skipped action.
        let (store, dir) = initialised("lease-phase");
        store
            .acquire(
                &ExclusiveProof::for_test(),
                "op1",
                "node-a",
                "node-b",
                60,
                "c",
                1,
                1000,
            )
            .unwrap();
        assert!(
            store
                .phase(
                    &ExclusiveProof::for_test(),
                    "other",
                    Phase::SourceQuiescing,
                    None,
                    1001
                )
                .is_err()
        );
        for skipped in [
            Phase::SourceReleased,
            Phase::TargetAssigning,
            Phase::TargetAssigned,
            Phase::TargetStarted,
        ] {
            let r = store.phase(&ExclusiveProof::for_test(), "op1", skipped, None, 1001);
            assert!(
                matches!(&r, Err(LeaseError::Refused(m)) if m.contains("cannot follow")),
                "{skipped:?}: {r:?}"
            );
        }
        store
            .phase(
                &ExclusiveProof::for_test(),
                "op1",
                Phase::SourceQuiescing,
                None,
                1001,
            )
            .unwrap();
        // The same phase again (to attach evidence) is fine; backwards is not.
        store
            .phase(
                &ExclusiveProof::for_test(),
                "op1",
                Phase::SourceQuiescing,
                Some(json_note()),
                1002,
            )
            .unwrap();
        store
            .phase(
                &ExclusiveProof::for_test(),
                "op1",
                Phase::SourceReleased,
                None,
                1003,
            )
            .unwrap();
        assert!(
            store
                .phase(
                    &ExclusiveProof::for_test(),
                    "op1",
                    Phase::SourceQuiescing,
                    None,
                    1004
                )
                .is_err()
        );
        let op = store.status().unwrap().op.unwrap();
        assert_eq!(op.phase, Phase::SourceReleased);
        assert_eq!(op.last_seen, 1003);
        fs::remove_dir_all(dir).unwrap();
    }

    fn json_note() -> Value {
        serde_json::json!({"note": 1})
    }

    #[test]
    fn expired_unmutated_lock_cannot_start_mutating() {
        let (store, dir) = initialised("lease-late");
        store
            .acquire(
                &ExclusiveProof::for_test(),
                "op1",
                "node-a",
                "node-b",
                60,
                "c",
                1,
                1000,
            )
            .unwrap();
        let late = store.phase(
            &ExclusiveProof::for_test(),
            "op1",
            Phase::SourceQuiescing,
            None,
            5000,
        );
        assert!(matches!(late, Err(LeaseError::Refused(m)) if m.contains("expired")));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn commit_needs_target_started_and_changes_owner_and_epoch() {
        let (store, dir) = initialised("lease-commit");
        store
            .acquire(
                &ExclusiveProof::for_test(),
                "op1",
                "node-a",
                "node-b",
                60,
                "c",
                1,
                1000,
            )
            .unwrap();
        advance(&store, "op1", Phase::TargetAssigned, 1001);
        assert!(
            store
                .commit(
                    &ExclusiveProof::for_test(),
                    "op1",
                    "node-b",
                    Value::Null,
                    1002
                )
                .is_err()
        );
        store
            .phase(
                &ExclusiveProof::for_test(),
                "op1",
                Phase::TargetStarted,
                None,
                1003,
            )
            .unwrap();
        assert!(
            store
                .commit(
                    &ExclusiveProof::for_test(),
                    "op1",
                    "node-a",
                    Value::Null,
                    1004
                )
                .is_err(),
            "not the target"
        );
        assert!(
            store
                .commit(
                    &ExclusiveProof::for_test(),
                    "other",
                    "node-b",
                    Value::Null,
                    1004
                )
                .is_err()
        );
        let state = store
            .commit(
                &ExclusiveProof::for_test(),
                "op1",
                "node-b",
                serde_json::json!({"k": 1}),
                1005,
            )
            .unwrap();
        assert_eq!((state.owner.as_deref(), state.epoch), (Some("node-b"), 2));
        assert!(state.op.is_none());
        assert_eq!(state.history.last().unwrap().kind, "move");
        // The next move starts from the new owner at the new epoch only.
        assert!(
            store
                .acquire(
                    &ExclusiveProof::for_test(),
                    "op2",
                    "node-a",
                    "node-b",
                    60,
                    "c",
                    2,
                    1100
                )
                .is_err()
        );
        store
            .acquire(
                &ExclusiveProof::for_test(),
                "op2",
                "node-b",
                "node-a",
                60,
                "c",
                2,
                1100,
            )
            .unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn abort_clears_the_operation_without_changing_owner_or_epoch() {
        let (store, dir) = initialised("lease-abort");
        store
            .acquire(
                &ExclusiveProof::for_test(),
                "op1",
                "node-a",
                "node-b",
                60,
                "c",
                1,
                1000,
            )
            .unwrap();
        advance(&store, "op1", Phase::SourceReleased, 1001);
        assert!(
            store
                .abort(&ExclusiveProof::for_test(), "op1", "node-b", "x", 1002)
                .is_err(),
            "wrong restored owner"
        );
        let state = store
            .abort(
                &ExclusiveProof::for_test(),
                "op1",
                "node-a",
                "target failed",
                1003,
            )
            .unwrap();
        assert_eq!((state.owner.as_deref(), state.epoch), (Some("node-a"), 1));
        assert!(state.op.is_none());
        assert_eq!(state.history.last().unwrap().kind, "abort");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_epoch_recorded_at_the_start_is_checked_by_every_later_step() {
        // B-08 / audit B-L6.
        let (store, dir) = initialised("lease-epoch-at-start");
        store
            .acquire(
                &ExclusiveProof::for_test(),
                "op1",
                "node-a",
                "node-b",
                60,
                "c",
                1,
                1000,
            )
            .unwrap();
        advance(&store, "op1", Phase::TargetStarted, 1001);
        edit(&dir, |s| s.epoch = 7);
        for r in [
            store.phase(
                &ExclusiveProof::for_test(),
                "op1",
                Phase::TargetStarted,
                None,
                1002,
            ),
            store.commit(
                &ExclusiveProof::for_test(),
                "op1",
                "node-b",
                Value::Null,
                1002,
            ),
            store.abort(&ExclusiveProof::for_test(), "op1", "node-a", "x", 1002),
        ] {
            assert!(
                matches!(&r, Err(LeaseError::Refused(m)) if m.contains("epoch changed")),
                "{r:?}"
            );
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reconcile_adopts_the_observed_owner_and_bumps_epoch_and_sequence() {
        let (store, dir) = initialised("lease-reconcile");
        store
            .acquire(
                &ExclusiveProof::for_test(),
                "op1",
                "node-a",
                "node-b",
                60,
                "c",
                1,
                1000,
            )
            .unwrap();
        advance(&store, "op1", Phase::TargetStarted, 1001);
        let before = store.status().unwrap();
        let state = store
            .reconcile(
                &ExclusiveProof::for_test(),
                "node-b",
                1,
                Some("op1"),
                Some("op1"),
                (0, 0),
                "commit lost",
                Value::Null,
                1001 + ABANDON_QUIET_SECS,
            )
            .unwrap();
        assert_eq!((state.owner.as_deref(), state.epoch), (Some("node-b"), 2));
        assert_eq!(state.seq, before.seq + 1, "the fencing sequence advances");
        assert!(state.op.is_none());
        assert_eq!(state.history.last().unwrap().kind, "reconcile");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reconcile_is_compare_and_swap_on_epoch_and_operation() {
        let (store, dir) = initialised("lease-reconcile-cas");
        store
            .acquire(
                &ExclusiveProof::for_test(),
                "op1",
                "node-a",
                "node-b",
                60,
                "c",
                1,
                1000,
            )
            .unwrap();
        advance(&store, "op1", Phase::TargetStarted, 1001);
        let late = 1001 + ABANDON_QUIET_SECS;
        // Observed a different operation / epoch: refused, record untouched.
        for (epoch, op) in [(1, None), (1, Some("other")), (2, Some("op1"))] {
            let r = store.reconcile(
                &ExclusiveProof::for_test(),
                "node-b",
                epoch,
                op,
                Some("op1"),
                (0, 0),
                "x",
                Value::Null,
                late,
            );
            assert!(matches!(r, Err(LeaseError::Refused(_))), "{epoch} {op:?}");
        }
        assert!(store.status().unwrap().op.is_some());
        store
            .reconcile(
                &ExclusiveProof::for_test(),
                "node-b",
                1,
                Some("op1"),
                Some("op1"),
                (0, 0),
                "x",
                Value::Null,
                late,
            )
            .unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reconcile_cuts_a_mutating_operation_only_when_named_and_silent() {
        // B-01 at the lease level (the agent refuses on its own, B-08).
        let (store, dir) = initialised("lease-reconcile-live");
        store
            .acquire(
                &ExclusiveProof::for_test(),
                "op1",
                "node-a",
                "node-b",
                600,
                "c",
                1,
                1000,
            )
            .unwrap();
        advance(&store, "op1", Phase::SourceReleased, 1100);
        let rec = |abandon: Option<&str>, now: u64| {
            store.reconcile(
                &ExclusiveProof::for_test(),
                "node-a",
                1,
                Some("op1"),
                abandon,
                (0, 0),
                "x",
                Value::Null,
                now,
            )
        };
        let quiet = 1100 + ABANDON_QUIET_SECS;
        let not_named = rec(None, quiet);
        assert!(matches!(&not_named, Err(LeaseError::Refused(m)) if m.contains("--abandon-op")));
        let wrong = rec(Some("other"), quiet);
        assert!(matches!(&wrong, Err(LeaseError::Refused(m)) if m.contains("--abandon-op")));
        let too_soon = rec(Some("op1"), quiet - 1);
        assert!(matches!(&too_soon, Err(LeaseError::Refused(m)) if m.contains("may still be")));
        assert!(store.status().unwrap().op.is_some());
        rec(Some("op1"), quiet).unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reconcile_never_cuts_a_live_acquired_operation_but_clears_an_expired_one() {
        let (store, dir) = initialised("lease-reconcile-acquired");
        store
            .acquire(
                &ExclusiveProof::for_test(),
                "op1",
                "node-a",
                "node-b",
                60,
                "c",
                1,
                1000,
            )
            .unwrap();
        let rec = |abandon: Option<&str>, now: u64| {
            store.reconcile(
                &ExclusiveProof::for_test(),
                "node-a",
                1,
                Some("op1"),
                abandon,
                (0, 0),
                "x",
                Value::Null,
                now,
            )
        };
        let live = rec(Some("op1"), 1010);
        assert!(matches!(&live, Err(LeaseError::Refused(m)) if m.contains("still in progress")));
        rec(None, 1100).unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_sequence_grows_on_every_grant_and_reconcile_and_honours_floors() {
        let (store, dir) = store("lease-seq");
        let state = store
            .init(&ExclusiveProof::for_test(), "node-a", 1, false, 40, 5)
            .unwrap();
        assert_eq!((state.seq, state.epoch), (40, 5), "floors apply to init");
        let a = store
            .acquire(
                &ExclusiveProof::for_test(),
                "op1",
                "node-a",
                "node-b",
                60,
                "c",
                5,
                1000,
            )
            .unwrap();
        assert_eq!(a.op.as_ref().unwrap().seq, 41);
        // A takeover of an expired Acquired lock gets a newer token.
        let b = store
            .acquire(
                &ExclusiveProof::for_test(),
                "op2",
                "node-a",
                "node-b",
                60,
                "c",
                5,
                2000,
            )
            .unwrap();
        assert_eq!(b.op.as_ref().unwrap().seq, 42);
        assert_eq!(b.seq, 42);
        // Phases, commit and abort keep it.
        advance(&store, "op2", Phase::SourceReleased, 2001);
        assert_eq!(store.status().unwrap().seq, 42);
        let aborted = store
            .abort(&ExclusiveProof::for_test(), "op2", "node-a", "x", 2002)
            .unwrap();
        assert_eq!(aborted.seq, 42);
        store
            .acquire(
                &ExclusiveProof::for_test(),
                "op3",
                "node-a",
                "node-b",
                60,
                "c",
                5,
                3000,
            )
            .unwrap();
        advance(&store, "op3", Phase::TargetStarted, 3001);
        let moved = store
            .commit(
                &ExclusiveProof::for_test(),
                "op3",
                "node-b",
                Value::Null,
                3002,
            )
            .unwrap();
        assert_eq!((moved.seq, moved.epoch), (43, 6));
        // Reconcile: at least one more, never below the floors.
        let r = store
            .reconcile(
                &ExclusiveProof::for_test(),
                "node-b",
                6,
                None,
                None,
                (100, 50),
                "x",
                Value::Null,
                4000,
            )
            .unwrap();
        assert_eq!((r.seq, r.epoch), (100, 50));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn refused_changes_leave_the_file_byte_identical() {
        let (store, dir) = initialised("lease-identical");
        let before = fs::read(dir.join("lease.json")).unwrap();
        let _ = store.acquire(
            &ExclusiveProof::for_test(),
            "op1",
            "node-b",
            "node-a",
            60,
            "c",
            1,
            1000,
        );
        let _ = store.commit(
            &ExclusiveProof::for_test(),
            "nope",
            "node-b",
            Value::Null,
            1000,
        );
        let _ = init(&store, "node-b", 5);
        assert_eq!(fs::read(dir.join("lease.json")).unwrap(), before);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn damaged_foreign_or_symlinked_state_is_never_repaired() {
        let (store, dir) = initialised("lease-damaged");
        let path = dir.join("lease.json");
        let good = fs::read(&path).unwrap();
        fs::write(&path, b"{ not json").unwrap();
        assert!(matches!(store.status(), Err(LeaseError::Storage(_))));
        assert!(matches!(
            store.acquire(
                &ExclusiveProof::for_test(),
                "op",
                "node-a",
                "node-b",
                60,
                "c",
                1,
                1
            ),
            Err(LeaseError::Storage(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), b"{ not json", "no repair");
        // Foreign cluster, with a valid checksum so that only the cluster
        // check can refuse it.
        fs::write(&path, &good).unwrap();
        edit(&dir, |s| s.cluster = "other".to_string());
        let r = store.status();
        assert!(matches!(&r, Err(LeaseError::Storage(m)) if m.contains("another cluster")));
        // Unknown owner.
        fs::write(&path, &good).unwrap();
        edit(&dir, |s| s.owner = Some("node-q".to_string()));
        let r = store.status();
        assert!(matches!(&r, Err(LeaseError::Storage(m)) if m.contains("unknown owner")));
        // Another schema version (mutant M14: the schema check removed).
        fs::write(&path, &good).unwrap();
        edit(&dir, |s| s.schema = "mkg-lease/v2".to_string());
        let r = store.status();
        assert!(matches!(&r, Err(LeaseError::Storage(m)) if m.contains("schema")));
        // Symlinked state file.
        fs::remove_file(&path).unwrap();
        let real = dir.join("real.json");
        fs::write(&real, &good).unwrap();
        std::os::unix::fs::symlink(&real, &path).unwrap();
        assert!(matches!(store.status(), Err(LeaseError::Storage(_))));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_symlinked_lock_file_is_refused_and_its_target_untouched() {
        let (store, dir) = initialised("lease-lock-symlink");
        let victim = dir.join("victim");
        fs::write(&victim, "precious").unwrap();
        let lock = dir.join("lease.json.lock");
        fs::remove_file(&lock).unwrap();
        std::os::unix::fs::symlink(&victim, &lock).unwrap();
        assert!(matches!(store.status(), Err(LeaseError::Storage(_))));
        assert!(
            store
                .acquire(
                    &ExclusiveProof::for_test(),
                    "op",
                    "node-a",
                    "node-b",
                    60,
                    "c",
                    1,
                    1
                )
                .is_err()
        );
        assert_eq!(fs::read_to_string(&victim).unwrap(), "precious");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn unlinking_the_lock_file_does_not_admit_a_second_holder() {
        // B-03 / audit B-L1. The directory lock holds although the lock file
        // is gone; a replaced lock file is refused, too.
        let (store, dir) = initialised("lease-b03");
        let quick = LeaseStore::new(
            dir.join("lease.json"),
            "test",
            vec!["node-a".to_string(), "node-b".to_string()],
            my_uid(),
        )
        .with_lock_wait(Duration::from_millis(200));
        let held = store.lock().unwrap();
        fs::remove_file(dir.join("lease.json.lock")).unwrap();
        assert!(
            matches!(quick.status(), Err(LeaseError::Storage(m)) if m.contains("busy")),
            "a second holder entered the critical section"
        );
        drop(held);
        quick.status().expect("the lock is free again");
        // Replacing the lock file by another inode while a holder waits for
        // it is detected by the inode comparison.
        fs::remove_file(dir.join("lease.json.lock")).unwrap();
        fs::write(dir.join("lease.json.lock"), b"").unwrap();
        quick.status().expect("a fresh lock file is simply used");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_missing_state_file_of_an_initialised_store_is_not_a_fresh_start() {
        // B-05 / audit B-L4.
        let (store, dir) = initialised("lease-b05");
        store
            .acquire(
                &ExclusiveProof::for_test(),
                "op1",
                "node-a",
                "node-b",
                60,
                "c",
                1,
                1000,
            )
            .unwrap();
        advance(&store, "op1", Phase::TargetStarted, 1001);
        store
            .commit(
                &ExclusiveProof::for_test(),
                "op1",
                "node-b",
                Value::Null,
                1002,
            )
            .unwrap();
        assert_eq!(store.status().unwrap().epoch, 2);
        fs::remove_file(dir.join("lease.json")).unwrap();
        assert!(matches!(store.status(), Err(LeaseError::Storage(m)) if m.contains("sentinel")));
        assert!(
            store
                .acquire(
                    &ExclusiveProof::for_test(),
                    "op2",
                    "node-b",
                    "node-a",
                    60,
                    "c",
                    2,
                    2000
                )
                .is_err()
        );
        let plain = init(&store, "node-a", 20);
        assert!(
            matches!(&plain, Err(LeaseError::Refused(m)) if m.contains("--reinit")),
            "{plain:?}"
        );
        // The explicit re-initialisation starts above the given floors.
        let state = store
            .init(&ExclusiveProof::for_test(), "node-b", 30, true, 9, 3)
            .unwrap();
        assert_eq!((state.seq, state.epoch), (9, 3));
        assert_eq!(state.history.last().unwrap().kind, "reinit");
        // It is not a way to overwrite an existing record.
        assert!(
            store
                .init(&ExclusiveProof::for_test(), "node-a", 31, true, 0, 0)
                .is_err()
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_fresh_directory_is_new_and_a_store_without_sentinel_stays_new() {
        let (store, dir) = store("lease-fresh");
        assert!(store.status().unwrap().owner.is_none());
        assert!(
            store
                .init(&ExclusiveProof::for_test(), "node-a", 1, true, 0, 0)
                .is_ok(),
            "--reinit on a store that never existed is just an init"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn every_key_is_required_and_unknown_keys_are_damage() {
        // B-07 / audit B-L3. Checked on the parser itself, so that the
        // checksum cannot be what refuses the file.
        let (store, dir) = initialised("lease-b07");
        store
            .acquire(
                &ExclusiveProof::for_test(),
                "op1",
                "node-a",
                "node-b",
                60,
                "c",
                1,
                1000,
            )
            .unwrap();
        let path = dir.join("lease.json");
        let good: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert!(serde_json::from_value::<LeaseState>(good.clone()).is_ok());
        for key in ["op", "owner", "seq", "checksum", "history", "epoch"] {
            let mut v = good.clone();
            v.as_object_mut().unwrap().remove(key);
            assert!(
                serde_json::from_value::<LeaseState>(v).is_err(),
                "missing {key} accepted"
            );
        }
        let mut v = good.clone();
        v["surprise"] = Value::Bool(true);
        assert!(serde_json::from_value::<LeaseState>(v).is_err());
        for key in ["seq", "last_seen", "evidence", "controller"] {
            let mut v = good.clone();
            v["op"].as_object_mut().unwrap().remove(key);
            assert!(
                serde_json::from_value::<LeaseState>(v).is_err(),
                "op without {key} accepted"
            );
        }
        let mut v = good.clone();
        v["history"][0].as_object_mut().unwrap().remove("note");
        assert!(serde_json::from_value::<LeaseState>(v).is_err());
        // And through the store: the file with a key removed is refused.
        let mut v = good;
        v.as_object_mut().unwrap().remove("op");
        fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
        assert!(matches!(store.status(), Err(LeaseError::Storage(_))));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_checksum_detects_edits_and_orphaned_temp_files_are_removed() {
        // B-09.
        let (store, dir) = initialised("lease-b09");
        let path = dir.join("lease.json");
        let good = fs::read_to_string(&path).unwrap();
        let tampered = good.replace("\"updated_at\": 1000", "\"updated_at\": 1001");
        assert_ne!(tampered, good);
        fs::write(&path, tampered).unwrap();
        let r = store.status();
        assert!(
            matches!(&r, Err(LeaseError::Storage(m)) if m.contains("checksum")),
            "{r:?}"
        );
        fs::write(&path, good).unwrap();
        // A write that died leaves a temp file; the next write removes it.
        let orphan = dir.join(".lease-deadbeef.tmp");
        fs::write(&orphan, "partial").unwrap();
        store
            .acquire(
                &ExclusiveProof::for_test(),
                "op1",
                "node-a",
                "node-b",
                60,
                "c",
                1,
                1000,
            )
            .unwrap();
        assert!(!orphan.exists(), "orphan temp file kept");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn evidence_is_capped_so_the_store_can_never_be_bricked() {
        // E-11 / audit B-L9.
        let (store, dir) = initialised("lease-e11");
        let big = serde_json::json!({"x": "a".repeat(MAX_EVIDENCE_BYTES + 1)});
        let mut owner = "node-a";
        let mut epoch = 1;
        for i in 0..8u64 {
            let target = if owner == "node-a" {
                "node-b"
            } else {
                "node-a"
            };
            let op = format!("move-op{i:08}");
            store
                .acquire(
                    &ExclusiveProof::for_test(),
                    &op,
                    owner,
                    target,
                    60,
                    "c",
                    epoch,
                    10,
                )
                .unwrap();
            advance(&store, &op, Phase::TargetStarted, 11);
            let refused = store.commit(&ExclusiveProof::for_test(), &op, target, big.clone(), 12);
            assert!(
                matches!(&refused, Err(LeaseError::Refused(m)) if m.contains("evidence")),
                "{refused:?}"
            );
            assert!(
                store
                    .phase(
                        &ExclusiveProof::for_test(),
                        &op,
                        Phase::TargetStarted,
                        Some(big.clone()),
                        12
                    )
                    .is_err()
            );
            let ok = serde_json::json!({"x": "a".repeat(MAX_EVIDENCE_BYTES - 64)});
            store
                .commit(&ExclusiveProof::for_test(), &op, target, ok, 13)
                .unwrap();
            owner = target;
            epoch += 1;
        }
        assert!(store.status().is_ok(), "the store stays readable");
        assert!(
            fs::metadata(dir.join("lease.json")).unwrap().len() < MAX_STATE_BYTES as u64,
            "the file stays below the write limit"
        );
        let r = store.reconcile(
            &ExclusiveProof::for_test(),
            "node-a",
            epoch,
            None,
            None,
            (0, 0),
            "x",
            big,
            2000,
        );
        assert!(matches!(r, Err(LeaseError::Refused(_))));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_state_directory_and_file_must_be_private_and_owned() {
        // B-06 / audit B-L5.
        let (store, dir) = initialised("lease-b06");
        fs::set_permissions(dir.join("lease.json"), fs::Permissions::from_mode(0o666)).unwrap();
        assert!(matches!(store.status(), Err(LeaseError::Storage(m)) if m.contains("writable")));
        fs::set_permissions(dir.join("lease.json"), fs::Permissions::from_mode(0o600)).unwrap();
        store.status().unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(store.status(), Err(LeaseError::Storage(m)) if m.contains("writable")));
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let foreign = LeaseStore::new(
            dir.join("lease.json"),
            "test",
            vec!["node-a".to_string(), "node-b".to_string()],
            my_uid() + 1,
        );
        assert!(matches!(foreign.status(), Err(LeaseError::Storage(_))));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn wall_clock_steps_only_affect_liveness_of_an_unmutated_lock() {
        // B-10 / audit B-L7. The Witness clock is the only clock involved.
        let (store, dir) = initialised("lease-clock");
        store
            .acquire(
                &ExclusiveProof::for_test(),
                "op1",
                "node-a",
                "node-b",
                300,
                "c1",
                1,
                200_000,
            )
            .unwrap();
        // Forward step: the old Acquired lock is taken over, and its holder
        // is refused afterwards (safe).
        store
            .acquire(
                &ExclusiveProof::for_test(),
                "op2",
                "node-a",
                "node-b",
                300,
                "c2",
                1,
                200_400,
            )
            .unwrap();
        let old = store.phase(
            &ExclusiveProof::for_test(),
            "op1",
            Phase::SourceQuiescing,
            None,
            200_401,
        );
        assert!(old.is_err(), "the displaced holder must be refused");
        // Backward step of a day: the dead Acquired lock of op2 simply waits
        // (liveness only, nothing was touched).
        let back = 200_400 - 86_400 + 5000;
        let blocked = store.acquire(
            &ExclusiveProof::for_test(),
            "op3",
            "node-a",
            "node-b",
            300,
            "c3",
            1,
            back,
        );
        assert!(matches!(blocked, Err(LeaseError::Refused(m)) if m.contains("holds the lock")));
        // A mutating lock never expires, however far the clock jumps.
        store
            .phase(
                &ExclusiveProof::for_test(),
                "op2",
                Phase::SourceQuiescing,
                None,
                200_500,
            )
            .unwrap();
        let r = store.acquire(
            &ExclusiveProof::for_test(),
            "op4",
            "node-a",
            "node-b",
            300,
            "c4",
            1,
            u64::MAX / 2,
        );
        assert!(r.is_err());
        // The expiry arithmetic cannot overflow.
        let (store2, dir2) = initialised("lease-clock-max");
        store2
            .acquire(
                &ExclusiveProof::for_test(),
                "op1",
                "node-a",
                "node-b",
                3600,
                "c",
                1,
                u64::MAX - 10,
            )
            .unwrap();
        fs::remove_dir_all(dir).unwrap();
        fs::remove_dir_all(dir2).unwrap();
    }

    #[test]
    fn a_refused_write_to_a_read_only_directory_keeps_the_old_state() {
        // audit B-L8.
        let (store, dir) = initialised("lease-b08-ro");
        let before = fs::read(dir.join("lease.json")).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
        let r = store.acquire(
            &ExclusiveProof::for_test(),
            "move-op1aaaaa",
            "node-a",
            "node-b",
            60,
            "c",
            1,
            5,
        );
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(r, Err(LeaseError::Storage(_))), "{r:?}");
        assert_eq!(fs::read(dir.join("lease.json")).unwrap(), before);
        let tmps: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(tmps.is_empty());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn concurrent_acquires_admit_exactly_one_holder() {
        let (store, dir) = initialised("lease-race");
        let store = std::sync::Arc::new(store);
        let mut handles = Vec::new();
        for i in 0..8 {
            let store = store.clone();
            handles.push(std::thread::spawn(move || {
                store
                    .acquire(
                        &ExclusiveProof::for_test(),
                        &format!("op-{i}"),
                        "node-a",
                        "node-b",
                        60,
                        "c",
                        1,
                        1000,
                    )
                    .is_ok()
            }));
        }
        let winners = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|ok| *ok)
            .count();
        assert_eq!(winners, 1);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn history_is_bounded() {
        let (store, dir) = initialised("lease-history");
        let mut owner = "node-a";
        let mut epoch = 1;
        for i in 0..(HISTORY_LIMIT + 10) {
            let target = if owner == "node-a" {
                "node-b"
            } else {
                "node-a"
            };
            let op = format!("op-{i}");
            store
                .acquire(
                    &ExclusiveProof::for_test(),
                    &op,
                    owner,
                    target,
                    60,
                    "c",
                    epoch,
                    1000,
                )
                .unwrap();
            advance(&store, &op, Phase::TargetStarted, 1001);
            store
                .commit(&ExclusiveProof::for_test(), &op, target, Value::Null, 1002)
                .unwrap();
            owner = target;
            epoch += 1;
        }
        let state = store.status().unwrap();
        assert_eq!(state.history.len(), HISTORY_LIMIT);
        assert_eq!(state.epoch, epoch);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn phase_names_round_trip() {
        for phase in [
            Phase::Acquired,
            Phase::SourceQuiescing,
            Phase::SourceReleased,
            Phase::TargetAssigning,
            Phase::TargetAssigned,
            Phase::TargetStarted,
        ] {
            assert_eq!(Phase::parse(&phase.name()), Some(phase));
        }
        assert_eq!(Phase::parse("bogus"), None);
        assert!(!Phase::Acquired.mutating());
        assert!(Phase::SourceQuiescing.mutating());
        // `next` walks the whole order and ends.
        let mut phase = Phase::Acquired;
        let mut steps = 0;
        while let Some(next) = phase.next() {
            assert!(next > phase);
            phase = next;
            steps += 1;
        }
        assert_eq!((phase, steps), (Phase::TargetStarted, 5));
    }
}
