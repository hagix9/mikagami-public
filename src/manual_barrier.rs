//! The durable manual-operation barrier shared by the two control planes.
//!
//! The control lock (`control_lock`) is a *process* exclusion: it is released
//! by the kernel when the manual agent exits, including after SIGKILL. An
//! asynchronous operation (a GCE alias update, a queued service action) can
//! still land after that process is gone. This module closes that gap with a
//! record that survives the process:
//!
//! 1. before the manual controller sends the first mutating request of a
//!    logical move, the node agent writes one open record on each reachable
//!    node involved;
//! 2. only after the controller has observed the final state and the move is
//!    committed (or verified rolled back) does it ask the agents to delete
//!    the records;
//! 3. the HA daemon refuses to start while an open record exists on its host.
//!
//! The record is never expired by time. A stale record is still a refusal:
//! time passing is not evidence that a cloud operation did not land. Only an
//! explicit, verified cleanup (the existing `resource reconcile vip` path)
//! removes it. A malformed, unreadable, symlinked, wrongly owned or
//! multi-linked file is also a refusal, never "no record".
//!
//! The contract is deliberately tiny and has no dependency on the manual
//! plane's lease/ownership code or on the HA engine. The agent writes and the
//! daemon reads the same JSON shape; neither imports the other's control
//! logic.

use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub(crate) const DEFAULT_BARRIER_PATH: &str = "/var/lib/mikagami/control/manual-operation.json";
pub(crate) const SCHEMA: &str = "mkg-manual-operation/v1";
const MAX_RECORD_BYTES: u64 = 4096;

/// The open operation record. `state` is always `open`; the file is removed
/// on resolution (a resolved tombstone would need its own authenticity).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManualOperation {
    pub(crate) schema: String,
    pub(crate) cluster: String,
    pub(crate) node: String,
    pub(crate) op_id: String,
    pub(crate) source: String,
    pub(crate) target: String,
    pub(crate) epoch: u64,
    pub(crate) controller: String,
    pub(crate) created_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BarrierState {
    Clear,
    Open(ManualOperation),
}

impl BarrierState {
    #[allow(dead_code)]
    pub(crate) fn is_open(&self) -> bool {
        matches!(self, Self::Open(_))
    }
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn valid_op_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

impl ManualOperation {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.schema != SCHEMA {
            return Err(format!("unknown barrier schema {:?}", self.schema));
        }
        if !valid_name(&self.cluster) || !valid_name(&self.node) {
            return Err("barrier cluster/node name is invalid".to_string());
        }
        if !valid_name(&self.source) || !valid_name(&self.target) {
            return Err("barrier source/target name is invalid".to_string());
        }
        if !valid_op_id(&self.op_id) {
            return Err("barrier op_id is invalid".to_string());
        }
        if self.epoch == 0 {
            return Err("barrier epoch must be at least 1".to_string());
        }
        if self.controller.is_empty()
            || self.controller.len() > 64
            || self.controller.chars().any(char::is_control)
        {
            return Err("barrier controller is invalid".to_string());
        }
        if self.created_at == 0 {
            return Err("barrier created_at must be set".to_string());
        }
        Ok(())
    }
}

/// Read and validate the barrier. `Ok(Clear)` is returned only when the file
/// does not exist. Every other uncertainty is an `Err`; the caller must refuse.
pub(crate) fn check(
    path: &Path,
    expected_uid: u32,
    cluster: &str,
    node: &str,
) -> Result<BarrierState, String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(BarrierState::Clear),
        Err(error) => {
            return Err(format!(
                "the manual-operation barrier {} cannot be inspected: {error}",
                path.display()
            ));
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "the manual-operation barrier {} is a symlink",
            path.display()
        ));
    }
    if !metadata.is_file() {
        return Err(format!(
            "the manual-operation barrier {} is not a regular file",
            path.display()
        ));
    }
    if metadata.uid() != expected_uid {
        return Err(format!(
            "the manual-operation barrier {} is owned by uid {}, not {}",
            path.display(),
            metadata.uid(),
            expected_uid
        ));
    }
    if metadata.nlink() != 1 {
        return Err(format!(
            "the manual-operation barrier {} has {} hard links, not 1",
            path.display(),
            metadata.nlink()
        ));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(format!(
            "the manual-operation barrier {} is not private (mode {:o})",
            path.display(),
            metadata.mode() & 0o777
        ));
    }
    if metadata.len() > MAX_RECORD_BYTES {
        return Err(format!(
            "the manual-operation barrier {} is too large",
            path.display()
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| {
            format!(
                "the manual-operation barrier {} cannot be opened: {error}",
                path.display()
            )
        })?;
    crate::control_lock::check_local_fs(&file).map_err(|error| {
        format!("the manual-operation barrier is on an unusable filesystem: {error}")
    })?;
    let mut bytes = Vec::new();
    file.take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("the manual-operation barrier cannot be read: {error}"))?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err("the manual-operation barrier is too large".to_string());
    }
    let record: ManualOperation = serde_json::from_slice(&bytes)
        .map_err(|error| format!("the manual-operation barrier is malformed: {error}"))?;
    record.validate()?;
    if record.cluster != cluster {
        return Err(format!(
            "the manual-operation barrier belongs to cluster {:?}, not {:?}",
            record.cluster, cluster
        ));
    }
    if record.node != node {
        return Err(format!(
            "the manual-operation barrier belongs to node {:?}, not {:?}",
            record.node, node
        ));
    }
    Ok(BarrierState::Open(record))
}

/// Create the open record. The caller must already hold the shared control
/// lock (the agent does this in `require_exclusive`). An existing record is
/// accepted only when it is the same operation (idempotent retry after a lost
/// response); any other open record refuses a new one.
pub(crate) fn begin(
    path: &Path,
    expected_uid: u32,
    record: &ManualOperation,
) -> Result<(), String> {
    record.validate()?;
    match check(path, expected_uid, &record.cluster, &record.node)? {
        BarrierState::Open(existing)
            if existing.op_id == record.op_id
                && existing.cluster == record.cluster
                && existing.node == record.node
                && existing.source == record.source
                && existing.target == record.target
                && existing.epoch == record.epoch
                && existing.controller == record.controller =>
        {
            return Ok(());
        }
        BarrierState::Open(existing) => {
            return Err(format!(
                "another manual operation {} is still unresolved on this node",
                existing.op_id
            ));
        }
        BarrierState::Clear => {}
    }
    let parent = path
        .parent()
        .ok_or_else(|| "the manual-operation barrier has no parent".to_string())?;
    crate::control_lock::ensure_private_dir(parent, expected_uid)
        .map_err(|error| format!("the manual-operation barrier directory: {error}"))?;
    let bytes = serde_json::to_vec_pretty(record)
        .map_err(|error| format!("cannot encode the manual-operation barrier: {error}"))?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err("the manual-operation barrier is too large".to_string());
    }
    let temp = temp_path(path);
    let result = write_new_durable(&temp, &bytes, expected_uid);
    if let Err(error) = result {
        let _ = fs::remove_file(&temp);
        return Err(error);
    }
    // `rename` replaces the (absent) final name atomically. The caller holds
    // the control lock, so there is no second agent writer.
    fs::rename(&temp, path).map_err(|error| {
        let _ = fs::remove_file(&temp);
        format!(
            "cannot publish the manual-operation barrier {}: {error}",
            path.display()
        )
    })?;
    if let Some(parent) = path.parent() {
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("cannot fsync the barrier directory: {error}"))?;
    }
    // Re-read the published record; a failure here is a refusal, not a
    // silently accepted write.
    match check(path, expected_uid, &record.cluster, &record.node)? {
        BarrierState::Open(published) if published == *record => Ok(()),
        BarrierState::Open(_) => {
            Err("the published barrier does not match the request".to_string())
        }
        BarrierState::Clear => {
            Err("the barrier disappeared immediately after it was written".to_string())
        }
    }
}

/// Remove the record for `op_id` after verified completion. A missing record
/// is success (idempotent). A different operation, or an unreadable record,
/// is refused and left in place.
pub(crate) fn resolve(
    path: &Path,
    expected_uid: u32,
    cluster: &str,
    node: &str,
    op_id: &str,
) -> Result<(), String> {
    match check(path, expected_uid, cluster, node)? {
        BarrierState::Clear => Ok(()),
        BarrierState::Open(record) if record.op_id == op_id => {
            fs::remove_file(path).map_err(|error| {
                format!(
                    "cannot remove the manual-operation barrier {}: {error}",
                    path.display()
                )
            })?;
            if let Some(parent) = path.parent() {
                File::open(parent)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|error| format!("cannot fsync the barrier directory: {error}"))?;
            }
            Ok(())
        }
        BarrierState::Open(record) => Err(format!(
            "the barrier belongs to operation {}, not {op_id}",
            record.op_id
        )),
    }
}

fn temp_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "manual-operation".to_string());
    path.with_file_name(format!(
        ".{name}.tmp.{}.{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos())
    ))
}

fn write_new_durable(path: &Path, bytes: &[u8], expected_uid: u32) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("cannot set the barrier mode: {error}"))?;
    crate::control_lock::check_local_fs(&file).map_err(|error| {
        format!("the manual-operation barrier is on an unusable filesystem: {error}")
    })?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect the barrier: {error}"))?;
    if metadata.uid() != expected_uid {
        return Err(format!(
            "the barrier writer has uid {}, not {}",
            metadata.uid(),
            expected_uid
        ));
    }
    file.write_all(bytes)
        .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("cannot fsync {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn temp_dir(label: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "mkg-barrier-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn uid() -> u32 {
        unsafe { libc::geteuid() }
    }

    fn record(op: &str) -> ManualOperation {
        ManualOperation {
            schema: SCHEMA.to_string(),
            cluster: "test".to_string(),
            node: "node-a".to_string(),
            op_id: op.to_string(),
            source: "node-a".to_string(),
            target: "node-b".to_string(),
            epoch: 3,
            controller: "mkg-v0.5".to_string(),
            created_at: 1_700_000_000,
        }
    }

    #[test]
    fn an_open_record_blocks_until_it_is_resolved() {
        let dir = temp_dir("open");
        let path = dir.join("manual-operation.json");
        assert_eq!(
            check(&path, uid(), "test", "node-a").unwrap(),
            BarrierState::Clear
        );
        begin(&path, uid(), &record("move-1")).unwrap();
        let state = check(&path, uid(), "test", "node-a").unwrap();
        assert!(matches!(&state, BarrierState::Open(r) if r.op_id == "move-1"));
        // Idempotent same operation; a different one is refused.
        begin(&path, uid(), &record("move-1")).unwrap();
        assert!(begin(&path, uid(), &record("move-2")).is_err());
        // Same op_id with a different target/epoch is NOT the same operation.
        let mut changed = record("move-1");
        changed.target = "node-c".to_string();
        assert!(begin(&path, uid(), &changed).is_err());
        let mut changed = record("move-1");
        changed.epoch = 9;
        assert!(begin(&path, uid(), &changed).is_err());
        assert!(resolve(&path, uid(), "test", "node-a", "move-2").is_err());
        resolve(&path, uid(), "test", "node-a", "move-1").unwrap();
        assert_eq!(
            check(&path, uid(), "test", "node-a").unwrap(),
            BarrierState::Clear
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_malformed_wrong_owner_or_wrong_node_record_is_a_refusal() {
        let dir = temp_dir("bad");
        let path = dir.join("manual-operation.json");
        fs::write(&path, b"not json").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(check(&path, uid(), "test", "node-a").is_err());
        assert!(resolve(&path, uid(), "test", "node-a", "move-1").is_err());
        assert!(path.exists(), "a malformed record must not be deleted");
        fs::remove_file(&path).unwrap();

        begin(&path, uid(), &record("move-1")).unwrap();
        assert!(check(&path, uid(), "test", "node-b").is_err());
        assert!(check(&path, uid(), "other", "node-a").is_err());
        assert!(resolve(&path, uid(), "test", "node-b", "move-1").is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_symlink_or_hard_link_is_refused() {
        let dir = temp_dir("links");
        let target = dir.join("target.json");
        fs::write(&target, b"{}").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let path = dir.join("manual-operation.json");
        symlink(&target, &path).unwrap();
        assert!(check(&path, uid(), "test", "node-a").is_err());
        fs::remove_file(&path).unwrap();
        begin(&path, uid(), &record("move-1")).unwrap();
        fs::hard_link(&path, dir.join("second.json")).unwrap();
        assert!(check(&path, uid(), "test", "node-a").is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_group_writable_record_is_refused() {
        let dir = temp_dir("mode");
        let path = dir.join("manual-operation.json");
        begin(&path, uid(), &record("move-1")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(check(&path, uid(), "test", "node-a").is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_root_path_with_missing_private_components_is_created_private() {
        let dir = temp_dir("create");
        let path = dir.join("control").join("manual-operation.json");
        begin(&path, uid(), &record("move-1")).unwrap();
        assert_eq!(
            fs::metadata(path.parent().unwrap()).unwrap().mode() & 0o777,
            0o700
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
