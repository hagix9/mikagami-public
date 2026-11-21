//! External Recovery Metadata v1 and the persistence transaction boundary.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

pub const RECOVERY_FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreKind {
    Node,
    Witness,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryMetadata {
    pub recovery_format_version: u32,
    pub store_kind: StoreKind,
    pub cluster_id: String,
    pub node_or_witness_id: String,
    pub transaction_id: String,
    pub operation_class: String,
    pub canonical_path_identity: String,
    pub expected_old_sha256: String,
    pub candidate_new_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inspection {
    Absent,
    Active(RecoveryMetadata),
    Invalid(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalFingerprint {
    Missing,
    Old,
    New,
    Neither,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetailedInspection {
    Absent,
    Active {
        metadata: RecoveryMetadata,
        canonical: CanonicalFingerprint,
    },
    Invalid(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultPoint {
    RecoveryTempFsync = 1,
    RecoveryInstall = 2,
    RecoveryParentFsync = 3,
    CandidateTempFsync = 4,
    CanonicalInstall = 5,
    CanonicalInstallBeforeMutation = 9,
    CanonicalParentFsync = 6,
    RecoveryUnlink = 7,
    CleanupParentFsync = 8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitResult {
    PreCommitFailure(String),
    ConfirmedCommitted,
    CommitOutcomeUnknown(String),
    CleanupOutcomeUnknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryError(pub String);

impl std::fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for RecoveryError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpectedOldToken {
    Absent,
    Bytes(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedSnapshot<T> {
    pub parsed_state: T,
    pub expected_old: ExpectedOldToken,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedStorePath {
    canonical_io_path: PathBuf,
    resolved_parent: PathBuf,
    path_identity: PathBuf,
    marker_path: PathBuf,
}

impl ResolvedStorePath {
    pub fn canonical_io_path(&self) -> &Path {
        &self.canonical_io_path
    }

    pub fn resolved_parent(&self) -> &Path {
        &self.resolved_parent
    }

    pub fn path_identity(&self) -> &Path {
        &self.path_identity
    }

    pub fn marker_path(&self) -> &Path {
        &self.marker_path
    }
}

#[cfg(test)]
thread_local! {
    static TEST_FAULTS: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum TestHookPoint {
    AfterInspection,
    AfterPrepare,
}

#[cfg(test)]
struct TestTransactionHook {
    path: PathBuf,
    point: TestHookPoint,
    entered: Arc<std::sync::Barrier>,
    release: Arc<std::sync::Barrier>,
}

#[cfg(test)]
struct TestLockHook {
    path: PathBuf,
    reached: Arc<std::sync::Barrier>,
    proceed: Arc<std::sync::Barrier>,
    acquired: std::sync::mpsc::Sender<()>,
}

#[cfg(test)]
static TEST_TRANSACTION_HOOK: OnceLock<Mutex<Option<TestTransactionHook>>> = OnceLock::new();

#[cfg(test)]
static TEST_LOCK_HOOK: OnceLock<Mutex<Option<TestLockHook>>> = OnceLock::new();

#[cfg(test)]
static TEST_HOOK_SERIAL: OnceLock<Mutex<()>> = OnceLock::new();

#[cfg(test)]
thread_local! {
    static TEST_FSYNC_TARGETS: std::cell::RefCell<Vec<PathBuf>> = const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
fn test_transaction_hook() -> &'static Mutex<Option<TestTransactionHook>> {
    TEST_TRANSACTION_HOOK.get_or_init(|| Mutex::new(None))
}

#[cfg(test)]
fn test_lock_hook() -> &'static Mutex<Option<TestLockHook>> {
    TEST_LOCK_HOOK.get_or_init(|| Mutex::new(None))
}

#[cfg(test)]
fn test_hook_serial() -> &'static Mutex<()> {
    TEST_HOOK_SERIAL.get_or_init(|| Mutex::new(()))
}

#[cfg(test)]
#[cfg(test)]
fn before_transaction_lock(path: &ResolvedStorePath) {
    let hook = test_lock_hook()
        .lock()
        .expect("test lock hook")
        .as_ref()
        .filter(|hook| hook.path == path.path_identity)
        .map(|hook| (Arc::clone(&hook.reached), Arc::clone(&hook.proceed)));
    if let Some((reached, proceed)) = hook {
        reached.wait();
        proceed.wait();
    }
}

#[cfg(test)]
fn after_transaction_lock(path: &ResolvedStorePath) {
    let sender = test_lock_hook()
        .lock()
        .expect("test lock hook")
        .as_ref()
        .filter(|hook| hook.path == path.path_identity)
        .map(|hook| hook.acquired.clone());
    if let Some(sender) = sender {
        sender.send(()).expect("lock acquisition notification");
    }
}

#[cfg(test)]
fn pause_at_test_hook(path: &Path, point: TestHookPoint) {
    let hook = test_transaction_hook().lock().expect("test hook lock");
    if hook
        .as_ref()
        .is_some_and(|hook| hook.point == point && path_key(path).ok().as_ref() == Some(&hook.path))
    {
        let hook = hook.as_ref().expect("test hook");
        hook.entered.wait();
        hook.release.wait();
    }
}

struct PathTransactionState {
    lock: Mutex<()>,
    uncertain: AtomicBool,
}

static PATH_TRANSACTIONS: OnceLock<Mutex<HashMap<PathBuf, Arc<PathTransactionState>>>> =
    OnceLock::new();

fn path_registry() -> &'static Mutex<HashMap<PathBuf, Arc<PathTransactionState>>> {
    PATH_TRANSACTIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn normalize_lexical(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                result.pop();
            }
            Component::RootDir | Component::Prefix(_) | Component::Normal(_) => {
                result.push(component.as_os_str());
            }
        }
    }
    result
}

#[cfg(test)]
fn path_key(path: &Path) -> Result<PathBuf, RecoveryError> {
    Ok(resolve_store_path(path)?.path_identity)
}

#[cfg(test)]
fn path_identity(path: &Path) -> String {
    resolve_store_path(path)
        .expect("resolved path")
        .path_identity
        .to_string_lossy()
        .into_owned()
}

fn component_queue(path: &Path) -> Vec<OsString> {
    path.components()
        .filter_map(|component| match component {
            Component::CurDir | Component::RootDir | Component::Prefix(_) => None,
            Component::ParentDir => Some(OsString::from("..")),
            Component::Normal(value) => Some(value.to_os_string()),
        })
        .collect()
}

pub(crate) fn resolve_store_path(path: &Path) -> Result<ResolvedStorePath, RecoveryError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| RecoveryError(error.to_string()))?
            .join(path)
    };
    let mut resolved = if absolute.is_absolute() {
        PathBuf::from(std::path::MAIN_SEPARATOR.to_string())
    } else {
        return Err(RecoveryError("path is not absolute".into()));
    };
    let mut queue = component_queue(&absolute);
    let mut symlink_depth = 0usize;
    while let Some(component) = queue.first().cloned() {
        queue.remove(0);
        if component == ".." {
            resolved.pop();
            if resolved.as_os_str().is_empty() {
                resolved.push(std::path::MAIN_SEPARATOR.to_string());
            }
            continue;
        }
        let candidate = resolved.join(&component);
        let is_final = queue.is_empty();
        match fs::symlink_metadata(&candidate) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                if is_final {
                    return Err(RecoveryError(
                        "canonical state must not be a symlink".into(),
                    ));
                }
                symlink_depth += 1;
                if symlink_depth > 40 {
                    return Err(RecoveryError("too many symlink expansions".into()));
                }
                let target =
                    fs::read_link(&candidate).map_err(|error| RecoveryError(error.to_string()))?;
                let mut target_queue = component_queue(&target);
                target_queue.extend(queue);
                queue = target_queue;
                if target.is_absolute() {
                    resolved = PathBuf::from(std::path::MAIN_SEPARATOR.to_string());
                }
            }
            Ok(metadata) => {
                if !is_final && !metadata.file_type().is_dir() {
                    return Err(RecoveryError("path component is not a directory".into()));
                }
                resolved.push(component);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound && is_final => {
                resolved.push(component);
            }
            Err(error) => return Err(RecoveryError(error.to_string())),
        }
    }
    let canonical = normalize_lexical(&resolved);
    let parent = canonical
        .parent()
        .ok_or_else(|| RecoveryError("canonical path has no parent".into()))?
        .to_path_buf();
    let marker = PathBuf::from(format!("{}.recovery", canonical.display()));
    Ok(ResolvedStorePath {
        canonical_io_path: canonical.clone(),
        resolved_parent: parent,
        path_identity: canonical,
        marker_path: marker,
    })
}

fn transaction_state(
    resolved: &ResolvedStorePath,
) -> Result<Arc<PathTransactionState>, RecoveryError> {
    let key = resolved.path_identity.clone();
    let registry = path_registry()
        .lock()
        .map_err(|_| RecoveryError("recovery path registry is poisoned".into()))?;
    if let Some(state) = registry.get(&key) {
        return Ok(Arc::clone(state));
    }
    drop(registry);
    let mut registry = path_registry()
        .lock()
        .map_err(|_| RecoveryError("recovery path registry is poisoned".into()))?;
    Ok(Arc::clone(registry.entry(key).or_insert_with(|| {
        Arc::new(PathTransactionState {
            lock: Mutex::new(()),
            uncertain: AtomicBool::new(false),
        })
    })))
}

fn mark_uncertain(path: &Path) {
    if let Ok(resolved) = resolve_store_path(path)
        && let Ok(state) = transaction_state(&resolved)
    {
        state.uncertain.store(true, Ordering::Release);
    }
}

fn mark_uncertain_resolved(resolved: &ResolvedStorePath) {
    if let Ok(state) = transaction_state(resolved) {
        state.uncertain.store(true, Ordering::Release);
    }
}

pub fn is_uncertain(path: &Path) -> bool {
    resolve_store_path(path)
        .and_then(|resolved| transaction_state(&resolved))
        .map(|state| state.uncertain.load(Ordering::Acquire))
        .unwrap_or(true)
}

fn with_transaction<T>(
    canonical: &Path,
    operation: impl FnOnce(&ResolvedStorePath) -> Result<T, RecoveryError>,
) -> Result<T, RecoveryError> {
    let resolved = resolve_store_path(canonical)?;
    let state = transaction_state(&resolved)?;
    #[cfg(test)]
    before_transaction_lock(&resolved);
    let _guard = state
        .lock
        .lock()
        .map_err(|_| RecoveryError("recovery transaction lock is poisoned".into()))?;
    #[cfg(test)]
    after_transaction_lock(&resolved);
    operation(&resolved)
}

#[cfg(test)]
pub fn inject_fault_once(point: FaultPoint) {
    TEST_FAULTS.with(|faults| *faults.borrow_mut() = vec![point as u8]);
}

#[cfg(test)]
pub fn inject_fault_sequence_once(points: &[FaultPoint]) {
    TEST_FAULTS.with(|faults| {
        *faults.borrow_mut() = points.iter().map(|point| *point as u8).collect();
    });
}

fn fault(point: FaultPoint) -> io::Result<()> {
    let _ = point;
    #[cfg(test)]
    if TEST_FAULTS.with(|faults| {
        let mut faults = faults.borrow_mut();
        if faults.first().copied() == Some(point as u8) {
            faults.remove(0);
            true
        } else {
            false
        }
    }) {
        return Err(io::Error::other("injected persistence fault"));
    }
    Ok(())
}

pub fn marker_path(canonical: &Path) -> PathBuf {
    if let Ok(resolved) = resolve_store_path(canonical) {
        return resolved.marker_path;
    }
    let canonical = {
        let absolute = if canonical.is_absolute() {
            canonical.to_path_buf()
        } else {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(canonical)
        };
        normalize_lexical(&absolute)
    };
    PathBuf::from(format!("{}.recovery", canonical.display()))
}

fn temp_path(path: &Path, suffix: &str, transaction_id: &str) -> PathBuf {
    path.with_file_name(format!(
        ".{}.{}-{}",
        path.file_name().and_then(|v| v.to_str()).unwrap_or("state"),
        suffix,
        transaction_id
    ))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn fingerprint(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(&hasher.finalize())
}

fn generate_uuid() -> Result<String, RecoveryError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|_| RecoveryError("transaction_id generation failed".into()))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    ))
}

fn inspect_unlocked(
    resolved: &ResolvedStorePath,
    kind: StoreKind,
    cluster: &str,
    identity: &str,
) -> Inspection {
    let marker = resolved.marker_path();
    let metadata = match fs::symlink_metadata(marker) {
        Ok(value) if value.file_type().is_symlink() || !value.file_type().is_file() => {
            return Inspection::Invalid("recovery path is not a regular file".into());
        }
        Ok(value) => {
            #[cfg(unix)]
            if value.permissions().mode() & 0o077 != 0 {
                return Inspection::Invalid("recovery path permissions are too broad".into());
            }
            match File::open(marker).and_then(|mut f| {
                let mut s = String::new();
                f.read_to_string(&mut s)?;
                Ok(s)
            }) {
                Ok(s) => match toml::from_str::<RecoveryMetadata>(&s) {
                    Ok(v) => v,
                    Err(e) => return Inspection::Invalid(e.to_string()),
                },
                Err(e) => return Inspection::Invalid(e.to_string()),
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Inspection::Absent,
        Err(e) => return Inspection::Invalid(e.to_string()),
    };
    if metadata.recovery_format_version != RECOVERY_FORMAT_VERSION
        || metadata.store_kind != kind
        || metadata.cluster_id != cluster
        || metadata.node_or_witness_id != identity
        || metadata.canonical_path_identity != resolved.path_identity().to_string_lossy()
        || metadata.transaction_id.trim().is_empty()
        || metadata.expected_old_sha256.len() != 64
        || metadata.candidate_new_sha256.len() != 64
        || !metadata
            .expected_old_sha256
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
        || !metadata
            .candidate_new_sha256
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
    {
        return Inspection::Invalid("recovery metadata identity or structure mismatch".into());
    }
    Inspection::Active(metadata)
}

pub fn inspect(canonical: &Path, kind: StoreKind, cluster: &str, identity: &str) -> Inspection {
    with_transaction(canonical, |resolved| {
        Ok(inspect_unlocked(resolved, kind, cluster, identity))
    })
    .unwrap_or_else(|error| Inspection::Invalid(error.0))
}

pub fn inspect_detailed(
    canonical: &Path,
    kind: StoreKind,
    cluster: &str,
    identity: &str,
) -> DetailedInspection {
    with_transaction(canonical, |resolved| {
        let inspection = inspect_unlocked(resolved, kind, cluster, identity);
        let result = match inspection {
            Inspection::Absent => DetailedInspection::Absent,
            Inspection::Invalid(reason) => DetailedInspection::Invalid(reason),
            Inspection::Active(metadata) => {
                let canonical = match fs::symlink_metadata(resolved.canonical_io_path()) {
                    Ok(value) if value.file_type().is_symlink() || !value.file_type().is_file() => {
                        CanonicalFingerprint::Neither
                    }
                    Ok(_) => match fs::read(resolved.canonical_io_path()) {
                        Ok(bytes) => {
                            let digest = fingerprint(&bytes);
                            if digest == metadata.expected_old_sha256 {
                                CanonicalFingerprint::Old
                            } else if digest == metadata.candidate_new_sha256 {
                                CanonicalFingerprint::New
                            } else {
                                CanonicalFingerprint::Neither
                            }
                        }
                        Err(_) => CanonicalFingerprint::Neither,
                    },
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        CanonicalFingerprint::Missing
                    }
                    Err(_) => CanonicalFingerprint::Neither,
                };
                DetailedInspection::Active {
                    metadata,
                    canonical,
                }
            }
        };
        Ok(result)
    })
    .unwrap_or_else(|error| DetailedInspection::Invalid(error.0))
}

pub fn read_snapshot_with_token(
    canonical: &Path,
    kind: StoreKind,
    cluster: &str,
    identity: &str,
) -> Result<Option<LoadedSnapshot<Vec<u8>>>, RecoveryError> {
    with_transaction(canonical, |resolved| {
        let state = transaction_state(resolved)?;
        if state.uncertain.load(Ordering::Acquire) {
            return Err(RecoveryError("persistence outcome is uncertain".into()));
        }
        match inspect_unlocked(resolved, kind, cluster, identity) {
            Inspection::Absent => {}
            Inspection::Active(_) => {
                return Err(RecoveryError("active recovery metadata".into()));
            }
            Inspection::Invalid(reason) => return Err(RecoveryError(reason)),
        }
        #[cfg(test)]
        pause_at_test_hook(resolved.canonical_io_path(), TestHookPoint::AfterInspection);
        match fs::symlink_metadata(resolved.canonical_io_path()) {
            Ok(metadata)
                if metadata.file_type().is_symlink() || !metadata.file_type().is_file() =>
            {
                return Err(RecoveryError(
                    "canonical state must be a regular file".into(),
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(RecoveryError(error.to_string())),
        }
        match fs::read(resolved.canonical_io_path()) {
            Ok(bytes) => Ok(Some(LoadedSnapshot {
                expected_old: ExpectedOldToken::Bytes(fingerprint(&bytes)),
                parsed_state: bytes,
            })),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(RecoveryError(error.to_string())),
        }
    })
}

pub fn read_snapshot(
    canonical: &Path,
    kind: StoreKind,
    cluster: &str,
    identity: &str,
) -> Result<Option<Vec<u8>>, RecoveryError> {
    Ok(
        read_snapshot_with_token(canonical, kind, cluster, identity)?
            .map(|snapshot| snapshot.parsed_state),
    )
}

fn write_synced(path: &Path, bytes: &[u8], fault_point: FaultPoint) -> Result<(), RecoveryError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| RecoveryError(e.to_string()))?;
    file.write_all(bytes)
        .map_err(|e| RecoveryError(e.to_string()))?;
    fault(fault_point).map_err(|e| RecoveryError(e.to_string()))?;
    file.sync_all().map_err(|e| RecoveryError(e.to_string()))
}

fn sync_parent(path: &Path, point: FaultPoint) -> Result<(), RecoveryError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    #[cfg(test)]
    if point == FaultPoint::CanonicalParentFsync {
        TEST_FSYNC_TARGETS.with(|targets| targets.borrow_mut().push(parent.to_path_buf()));
    }
    fault(point).map_err(|e| RecoveryError(e.to_string()))?;
    File::open(parent)
        .map_err(|e| RecoveryError(e.to_string()))?
        .sync_all()
        .map_err(|e| RecoveryError(e.to_string()))
}

fn cleanup_precanonical_marker(marker: &Path) -> Result<(), String> {
    fault(FaultPoint::RecoveryUnlink)
        .map_err(|error| format!("pre-canonical recovery cleanup is ambiguous: {error}"))?;
    fs::remove_file(marker)
        .map_err(|error| format!("pre-canonical recovery cleanup failed: {error}"))?;
    sync_parent(marker, FaultPoint::CleanupParentFsync)
        .map_err(|error| format!("pre-canonical recovery cleanup is ambiguous: {}", error.0))?;
    Ok(())
}

fn precanonical_failure(canonical: &Path, marker: &Path, reason: String) -> CommitResult {
    match cleanup_precanonical_marker(marker) {
        Ok(()) => CommitResult::PreCommitFailure(reason),
        Err(cleanup_reason) => {
            mark_uncertain(canonical);
            CommitResult::CommitOutcomeUnknown(cleanup_reason)
        }
    }
}

fn read_expected_old(canonical: &Path, create_only: bool) -> Result<Vec<u8>, CommitResult> {
    if create_only {
        match fs::symlink_metadata(canonical) {
            Ok(_) => Err(CommitResult::PreCommitFailure(
                "canonical state already exists".into(),
            )),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(error) => Err(CommitResult::PreCommitFailure(error.to_string())),
        }
    } else {
        fs::read(canonical).map_err(|error| {
            CommitResult::PreCommitFailure(format!("cannot read expected canonical state: {error}"))
        })
    }
}

fn cleanup_alias(path: &Path) {
    let _ = fs::remove_file(path);
    let _ = File::open(path.parent().unwrap_or_else(|| Path::new(".")))
        .and_then(|directory| directory.sync_all());
}

#[allow(clippy::too_many_arguments)]
fn persist_locked(
    resolved: &ResolvedStorePath,
    kind: StoreKind,
    cluster: &str,
    identity: &str,
    operation_class: &str,
    expected_old: &ExpectedOldToken,
    new_bytes: &[u8],
    create_only: bool,
) -> Result<CommitResult, RecoveryError> {
    let state = transaction_state(resolved)?;
    if state.uncertain.load(Ordering::Acquire) {
        return Ok(CommitResult::CommitOutcomeUnknown(
            "persistence outcome is uncertain".into(),
        ));
    }
    match fs::symlink_metadata(resolved.canonical_io_path()) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_file() => {
            return Ok(CommitResult::PreCommitFailure(
                "canonical state must be a regular file".into(),
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound && create_only => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(CommitResult::PreCommitFailure(
                "canonical state is absent".into(),
            ));
        }
        Err(error) => return Ok(CommitResult::PreCommitFailure(error.to_string())),
    }
    let current_old = match read_expected_old(resolved.canonical_io_path(), create_only) {
        Ok(bytes) => bytes,
        Err(result) => return Ok(result),
    };
    let current_token = if create_only {
        ExpectedOldToken::Absent
    } else {
        ExpectedOldToken::Bytes(fingerprint(&current_old))
    };
    if &current_token != expected_old {
        return Ok(CommitResult::PreCommitFailure(
            "canonical state changed before persistence".into(),
        ));
    }
    match inspect_unlocked(resolved, kind, cluster, identity) {
        Inspection::Absent => {}
        Inspection::Active(_) => {
            let result = CommitResult::CommitOutcomeUnknown("recovery is already active".into());
            mark_uncertain_resolved(resolved);
            return Ok(result);
        }
        Inspection::Invalid(e) => {
            mark_uncertain_resolved(resolved);
            return Ok(CommitResult::CommitOutcomeUnknown(e));
        }
    }
    let parent = resolved.resolved_parent();
    fs::create_dir_all(parent).map_err(|e| RecoveryError(e.to_string()))?;
    let marker = resolved.marker_path();
    let metadata = RecoveryMetadata {
        recovery_format_version: RECOVERY_FORMAT_VERSION,
        store_kind: kind,
        cluster_id: cluster.into(),
        node_or_witness_id: identity.into(),
        transaction_id: generate_uuid()?,
        operation_class: operation_class.into(),
        canonical_path_identity: resolved.path_identity().to_string_lossy().into_owned(),
        expected_old_sha256: fingerprint(&current_old),
        candidate_new_sha256: fingerprint(new_bytes),
    };
    let marker_tmp = temp_path(marker, "prepare", &metadata.transaction_id);
    let marker_bytes = toml::to_string(&metadata).map_err(|e| RecoveryError(e.to_string()))?;
    if let Err(e) = write_synced(
        &marker_tmp,
        marker_bytes.as_bytes(),
        FaultPoint::RecoveryTempFsync,
    ) {
        let _ = fs::remove_file(&marker_tmp);
        return Ok(CommitResult::PreCommitFailure(e.0));
    }
    let install = fs::hard_link(&marker_tmp, marker);
    if let Err(e) = install {
        let _ = fs::remove_file(&marker_tmp);
        if e.kind() == io::ErrorKind::AlreadyExists {
            mark_uncertain_resolved(resolved);
            return Ok(CommitResult::CommitOutcomeUnknown(
                "recovery marker already exists".into(),
            ));
        }
        return Ok(CommitResult::PreCommitFailure(e.to_string()));
    }
    if fault(FaultPoint::RecoveryInstall).is_err() {
        let result =
            CommitResult::CommitOutcomeUnknown("recovery marker install is ambiguous".into());
        mark_uncertain_resolved(resolved);
        return Ok(result);
    }
    if let Err(e) = sync_parent(marker, FaultPoint::RecoveryParentFsync) {
        mark_uncertain_resolved(resolved);
        return Ok(CommitResult::CommitOutcomeUnknown(e.0));
    }
    cleanup_alias(&marker_tmp);

    #[cfg(test)]
    pause_at_test_hook(resolved.canonical_io_path(), TestHookPoint::AfterPrepare);

    let candidate = temp_path(
        resolved.canonical_io_path(),
        "candidate",
        &metadata.transaction_id,
    );
    if let Err(e) = write_synced(&candidate, new_bytes, FaultPoint::CandidateTempFsync) {
        let _ = fs::remove_file(&candidate);
        return Ok(precanonical_failure(
            resolved.canonical_io_path(),
            marker,
            e.0,
        ));
    }
    if fault(FaultPoint::CanonicalInstallBeforeMutation).is_err() {
        let _ = fs::remove_file(&candidate);
        return Ok(precanonical_failure(
            resolved.canonical_io_path(),
            marker,
            "canonical install failed before namespace mutation".into(),
        ));
    }
    let install = if create_only {
        fs::hard_link(&candidate, resolved.canonical_io_path())
    } else {
        fs::rename(&candidate, resolved.canonical_io_path())
    };
    if let Err(e) = install {
        let _ = fs::remove_file(&candidate);
        return Ok(precanonical_failure(
            resolved.canonical_io_path(),
            marker,
            e.to_string(),
        ));
    }
    if create_only {
        cleanup_alias(&candidate);
    }
    if fault(FaultPoint::CanonicalInstall).is_err() {
        let result = CommitResult::CommitOutcomeUnknown("canonical install is ambiguous".into());
        mark_uncertain_resolved(resolved);
        return Ok(result);
    }
    if let Err(e) = sync_parent(
        resolved.canonical_io_path(),
        FaultPoint::CanonicalParentFsync,
    ) {
        mark_uncertain_resolved(resolved);
        return Ok(CommitResult::CommitOutcomeUnknown(e.0));
    }
    if fault(FaultPoint::RecoveryUnlink).is_err() {
        let result =
            CommitResult::CleanupOutcomeUnknown("recovery marker cleanup is ambiguous".into());
        mark_uncertain_resolved(resolved);
        return Ok(result);
    }
    if let Err(e) = fs::remove_file(marker) {
        mark_uncertain_resolved(resolved);
        return Ok(CommitResult::CleanupOutcomeUnknown(e.to_string()));
    }
    if let Err(e) = sync_parent(marker, FaultPoint::CleanupParentFsync) {
        mark_uncertain_resolved(resolved);
        return Ok(CommitResult::CleanupOutcomeUnknown(e.0));
    }
    Ok(CommitResult::ConfirmedCommitted)
}

#[allow(clippy::too_many_arguments)]
pub fn persist(
    canonical: &Path,
    kind: StoreKind,
    cluster: &str,
    identity: &str,
    operation_class: &str,
    old_bytes: &[u8],
    new_bytes: &[u8],
    create_only: bool,
) -> Result<CommitResult, RecoveryError> {
    let expected_old = if create_only {
        ExpectedOldToken::Absent
    } else {
        ExpectedOldToken::Bytes(fingerprint(old_bytes))
    };
    persist_with_expected_old(
        canonical,
        kind,
        cluster,
        identity,
        operation_class,
        &expected_old,
        new_bytes,
        create_only,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn persist_with_expected_old(
    canonical: &Path,
    kind: StoreKind,
    cluster: &str,
    identity: &str,
    operation_class: &str,
    expected_old: &ExpectedOldToken,
    new_bytes: &[u8],
    create_only: bool,
) -> Result<CommitResult, RecoveryError> {
    with_transaction(canonical, |resolved| {
        persist_locked(
            resolved,
            kind,
            cluster,
            identity,
            operation_class,
            expected_old,
            new_bytes,
            create_only,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier, mpsc};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn path(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        std::env::temp_dir().join(format!("mikagami-recovery-{name}-{suffix}"))
    }

    fn cleanup(path: &Path) {
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(marker_path(path));
    }

    fn install_test_hook(path: &Path, point: TestHookPoint) -> (Arc<Barrier>, Arc<Barrier>) {
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let key = path_key(path).expect("path identity");
        *test_transaction_hook().lock().expect("test hook lock") = Some(TestTransactionHook {
            path: key,
            point,
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        });
        (entered, release)
    }

    fn clear_test_hook() {
        *test_transaction_hook().lock().expect("test hook lock") = None;
    }

    fn install_lock_hook(path: &Path) -> (Arc<Barrier>, Arc<Barrier>, mpsc::Receiver<()>) {
        let reached = Arc::new(Barrier::new(2));
        let proceed = Arc::new(Barrier::new(2));
        let (acquired_tx, acquired_rx) = mpsc::channel();
        let key = path_key(path).expect("path identity");
        *test_lock_hook().lock().expect("test lock hook") = Some(TestLockHook {
            path: key,
            reached: Arc::clone(&reached),
            proceed: Arc::clone(&proceed),
            acquired: acquired_tx,
        });
        (reached, proceed, acquired_rx)
    }

    fn clear_lock_hook() {
        *test_lock_hook().lock().expect("test lock hook") = None;
    }

    #[test]
    fn persist_installs_and_cleans_v1_metadata() {
        let canonical = path("commit");
        let result = persist(
            &canonical,
            StoreKind::Node,
            "cluster",
            "node-a",
            "mutation",
            b"old",
            b"new",
            true,
        )
        .expect("persist");

        assert_eq!(result, CommitResult::ConfirmedCommitted);
        assert_eq!(fs::read(&canonical).expect("canonical"), b"new");
        assert_eq!(
            inspect(&canonical, StoreKind::Node, "cluster", "node-a"),
            Inspection::Absent
        );
        let parent = canonical.parent().expect("parent");
        let basename = canonical.file_name().expect("basename").to_string_lossy();
        assert!(
            !fs::read_dir(parent)
                .expect("parent entries")
                .flatten()
                .any(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(&format!(".{basename}.")))
        );
        cleanup(&canonical);
    }

    #[test]
    fn invalid_metadata_is_not_treated_as_absent() {
        let canonical = path("invalid");
        let marker = marker_path(&canonical);
        fs::write(&marker, "not valid recovery metadata").expect("marker");

        assert!(matches!(
            inspect(&canonical, StoreKind::Node, "cluster", "node-a"),
            Inspection::Invalid(_)
        ));
        cleanup(&canonical);
    }

    #[test]
    fn candidate_fsync_failure_cleans_prepare_and_returns_precommit_failure() {
        let canonical = path("candidate-fsync");
        inject_fault_once(FaultPoint::CandidateTempFsync);
        let result = persist(
            &canonical,
            StoreKind::Node,
            "cluster",
            "node-a",
            "mutation",
            b"old",
            b"new",
            true,
        )
        .expect("persist");

        assert!(matches!(result, CommitResult::PreCommitFailure(_)));
        assert_eq!(
            inspect(&canonical, StoreKind::Node, "cluster", "node-a"),
            Inspection::Absent
        );
        assert!(!canonical.exists());
        assert_eq!(
            persist(
                &canonical,
                StoreKind::Node,
                "cluster",
                "node-a",
                "retry",
                b"old",
                b"new",
                true,
            )
            .expect("retry"),
            CommitResult::ConfirmedCommitted
        );
        cleanup(&canonical);
    }

    #[test]
    fn definite_canonical_install_failure_cleans_prepare_and_preserves_old_namespace() {
        let canonical = path("canonical-install-failure");
        fs::write(&canonical, b"old").expect("canonical");
        inject_fault_once(FaultPoint::CanonicalInstallBeforeMutation);
        let result = persist(
            &canonical,
            StoreKind::Node,
            "cluster",
            "node-a",
            "mutation",
            b"old",
            b"new",
            false,
        )
        .expect("persist");

        assert!(matches!(result, CommitResult::PreCommitFailure(_)));
        assert_eq!(fs::read(&canonical).expect("canonical"), b"old");
        assert_eq!(
            inspect(&canonical, StoreKind::Node, "cluster", "node-a"),
            Inspection::Absent
        );
        cleanup(&canonical);
    }

    #[test]
    fn existing_prepare_marker_is_not_overwritten() {
        let canonical = path("marker-no-overwrite");
        let marker = marker_path(&canonical);
        let metadata = RecoveryMetadata {
            recovery_format_version: RECOVERY_FORMAT_VERSION,
            store_kind: StoreKind::Node,
            cluster_id: "cluster".into(),
            node_or_witness_id: "node-a".into(),
            transaction_id: "00000000-0000-4000-8000-000000000001".into(),
            operation_class: "existing".into(),
            canonical_path_identity: path_identity(&canonical),
            expected_old_sha256: fingerprint(&[]),
            candidate_new_sha256: fingerprint(b"existing"),
        };
        let bytes = toml::to_string(&metadata).expect("metadata");
        fs::write(&marker, &bytes).expect("marker");
        #[cfg(unix)]
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).expect("permissions");
        let result = persist(
            &canonical,
            StoreKind::Node,
            "cluster",
            "node-a",
            "new",
            b"old",
            b"new",
            true,
        )
        .expect("persist");
        assert!(matches!(result, CommitResult::CommitOutcomeUnknown(_)));
        assert_eq!(fs::read(&marker).expect("marker"), bytes.as_bytes());
        assert!(!canonical.exists());
        cleanup(&canonical);
    }

    #[test]
    fn stale_candidate_does_not_change_canonical_or_allow_retry() {
        let canonical = path("stale-candidate");
        fs::write(&canonical, b"old").expect("canonical");
        assert_eq!(
            persist(
                &canonical,
                StoreKind::Node,
                "cluster",
                "node-a",
                "first",
                b"old",
                b"new",
                false,
            )
            .expect("persist"),
            CommitResult::ConfirmedCommitted
        );
        let result = persist(
            &canonical,
            StoreKind::Node,
            "cluster",
            "node-a",
            "stale",
            b"old",
            b"stale-new",
            false,
        )
        .expect("stale persist");
        assert!(matches!(result, CommitResult::PreCommitFailure(_)));
        assert_eq!(fs::read(&canonical).expect("canonical"), b"new");
        assert_eq!(
            inspect(&canonical, StoreKind::Node, "cluster", "node-a"),
            Inspection::Absent
        );
        cleanup(&canonical);
    }

    #[test]
    fn stale_candidate_is_not_reused_after_restart_style_retry() {
        let canonical = path("stale-candidate-restart");
        let stale = canonical.with_file_name(format!(
            ".{}.candidate-stale",
            canonical.file_name().expect("basename").to_string_lossy()
        ));
        fs::write(&stale, b"stale candidate").expect("stale candidate");
        assert_eq!(
            persist(
                &canonical,
                StoreKind::Node,
                "cluster",
                "node-a",
                "restart",
                b"old",
                b"new",
                true,
            )
            .expect("persist"),
            CommitResult::ConfirmedCommitted
        );
        assert_eq!(fs::read(&canonical).expect("canonical"), b"new");
        assert_eq!(
            fs::read(&stale).expect("stale candidate"),
            b"stale candidate"
        );
        let _ = fs::remove_file(stale);
        cleanup(&canonical);
    }

    #[test]
    fn equivalent_path_spellings_share_the_recovery_transaction_lock() {
        let canonical = path("shared-lock");
        let alias = canonical
            .parent()
            .expect("parent")
            .join(".")
            .join(canonical.file_name().expect("basename"));
        let state =
            transaction_state(&resolve_store_path(&canonical).expect("state path")).expect("state");
        let guard = state.lock.lock().expect("lock");
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            started_tx.send(()).expect("started");
            let state = transaction_state(&resolve_store_path(&alias).expect("alias path"))
                .expect("alias state");
            let _guard = state.lock.lock().expect("alias lock");
            done_tx.send(()).expect("done");
        });
        started_rx.recv().expect("started");
        assert!(done_rx.try_recv().is_err());
        drop(guard);
        done_rx.recv().expect("done");
        thread.join().expect("thread");
    }

    #[cfg(unix)]
    #[test]
    fn parent_symlink_dotdot_uses_one_resolved_io_and_recovery_domain() {
        let root = path("resolved-parent-symlink");
        let real_parent = root.join("real");
        let real_sub = real_parent.join("sub");
        let base = root.join("base");
        let link = base.join("link");
        fs::create_dir_all(&real_sub).expect("real subtree");
        fs::create_dir_all(&base).expect("base");
        std::os::unix::fs::symlink(&real_sub, &link).expect("parent symlink");

        let direct = real_parent.join("state");
        let alias = link.join("..").join("state");
        let resolved_direct = resolve_store_path(&direct).expect("direct resolution");
        let resolved_alias = resolve_store_path(&alias).expect("alias resolution");
        assert_eq!(resolved_alias, resolved_direct);
        assert_eq!(
            resolved_alias.canonical_io_path(),
            resolved_direct.canonical_io_path()
        );
        assert_eq!(
            resolved_alias.path_identity(),
            resolved_direct.path_identity()
        );
        assert_eq!(
            resolved_alias.marker_path().parent(),
            Some(resolved_direct.resolved_parent())
        );
        assert_eq!(
            resolved_alias.resolved_parent(),
            resolved_direct.resolved_parent()
        );

        assert_eq!(
            persist(
                &alias,
                StoreKind::Node,
                "cluster",
                "node-a",
                "initialization",
                b"",
                b"new",
                true,
            )
            .expect("alias initialization"),
            CommitResult::ConfirmedCommitted
        );
        assert_eq!(fs::read(&direct).expect("direct canonical"), b"new");
        assert_eq!(fs::read(&alias).expect("alias canonical"), b"new");
        assert_eq!(marker_path(&alias), marker_path(&direct));
        assert!(!marker_path(&direct).exists());

        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn uncertainty_is_shared_between_parent_symlink_alias_and_direct_path() {
        for direction in ["alias", "direct"] {
            let root = path(&format!("uncertainty-{direction}"));
            let real_parent = root.join("real");
            let real_sub = real_parent.join("sub");
            let base = root.join("base");
            let link = base.join("link");
            fs::create_dir_all(&real_sub).expect("real subtree");
            fs::create_dir_all(&base).expect("base");
            std::os::unix::fs::symlink(&real_sub, &link).expect("parent symlink");
            let direct = real_parent.join("state");
            let alias = link.join("..").join("state");
            let writer = if direction == "alias" {
                &alias
            } else {
                &direct
            };
            let reader = if direction == "alias" {
                &direct
            } else {
                &alias
            };

            inject_fault_once(FaultPoint::CanonicalParentFsync);
            assert!(matches!(
                persist(
                    writer,
                    StoreKind::Node,
                    "cluster",
                    "node-a",
                    "mutation",
                    b"",
                    b"new",
                    true,
                )
                .expect("ambiguous persist"),
                CommitResult::CommitOutcomeUnknown(_)
            ));
            assert!(is_uncertain(reader));
            assert!(read_snapshot(reader, StoreKind::Node, "cluster", "node-a").is_err());
            assert_eq!(marker_path(&alias), marker_path(&direct));

            let _ = fs::remove_dir_all(root);
        }
    }

    #[cfg(unix)]
    #[test]
    fn final_canonical_symlink_is_rejected_and_missing_final_through_alias_initializes() {
        let root = path("final-component-safety");
        let real_parent = root.join("real");
        let real_sub = real_parent.join("sub");
        let base = root.join("base");
        let link = base.join("link");
        fs::create_dir_all(&real_sub).expect("real subtree");
        fs::create_dir_all(&base).expect("base");
        std::os::unix::fs::symlink(&real_sub, &link).expect("parent symlink");

        let direct = real_parent.join("state");
        let alias = link.join("..").join("state");
        let target = real_parent.join("target");
        fs::write(&target, b"target").expect("target");
        std::os::unix::fs::symlink(&target, &direct).expect("final symlink");
        assert!(
            persist(
                &alias,
                StoreKind::Node,
                "cluster",
                "node-a",
                "mutation",
                b"",
                b"new",
                true,
            )
            .is_err()
        );
        fs::remove_file(&direct).expect("remove final symlink");
        assert_eq!(
            persist(
                &alias,
                StoreKind::Node,
                "cluster",
                "node-a",
                "initialization",
                b"",
                b"new",
                true,
            )
            .expect("missing final initialization"),
            CommitResult::ConfirmedCommitted
        );
        assert_eq!(fs::read(&direct).unwrap(), b"new");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn expected_absence_initialization_cannot_overwrite_new_canonical_state() {
        let canonical = path("initialization-race");
        assert_eq!(
            persist(
                &canonical,
                StoreKind::Node,
                "cluster",
                "node-a",
                "initialization",
                b"",
                b"state-b",
                true,
            )
            .expect("first initialization"),
            CommitResult::ConfirmedCommitted
        );
        assert!(matches!(
            persist(
                &canonical,
                StoreKind::Node,
                "cluster",
                "node-a",
                "initialization",
                b"",
                b"stale-state-a",
                true,
            )
            .expect("stale initialization"),
            CommitResult::PreCommitFailure(_)
        ));
        assert_eq!(fs::read(&canonical).unwrap(), b"state-b");
        assert!(!marker_path(&canonical).exists());
        cleanup(&canonical);
    }

    #[test]
    fn reader_blocks_writer_at_recovery_transaction_boundary() {
        let _serial = test_hook_serial().lock().expect("test hook serial");
        let root = path("reader-writer-boundary");
        fs::create_dir_all(&root).expect("root");
        let real_parent = root.join("real");
        let alias_parent = root.join("alias");
        fs::create_dir_all(&real_parent).expect("real parent");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real_parent, &alias_parent).expect("parent symlink");
        let canonical = real_parent.join("state");
        fs::write(&canonical, b"old").expect("canonical");
        let reader_path = alias_parent.join("child").join("..").join("state");
        fs::create_dir_all(alias_parent.join("child")).expect("child");
        assert_eq!(
            path_key(&canonical).expect("canonical key"),
            path_key(&reader_path).expect("reader key")
        );
        let (entered, release) = install_test_hook(&reader_path, TestHookPoint::AfterInspection);
        let (reader_tx, reader_rx) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            reader_tx
                .send(read_snapshot(
                    &reader_path,
                    StoreKind::Node,
                    "cluster",
                    "node-a",
                ))
                .expect("reader result");
        });
        entered.wait();

        let writer_alias = alias_parent.join("child").join("..").join("state");
        let (lock_reached, lock_proceed, acquired_rx) = install_lock_hook(&writer_alias);
        let (writer_tx, writer_rx) = mpsc::channel();
        let writer = std::thread::spawn(move || {
            writer_tx
                .send(persist(
                    &writer_alias,
                    StoreKind::Node,
                    "cluster",
                    "node-a",
                    "mutation",
                    b"old",
                    b"new",
                    false,
                ))
                .expect("writer result");
        });
        lock_reached.wait();
        lock_proceed.wait();
        assert!(acquired_rx.try_recv().is_err());

        release.wait();
        assert_eq!(
            reader_rx.recv().expect("reader result").unwrap(),
            Some(b"old".to_vec())
        );
        assert_eq!(
            writer_rx.recv().expect("writer result").unwrap(),
            CommitResult::ConfirmedCommitted
        );
        reader.join().expect("reader");
        writer.join().expect("writer");
        assert!(acquired_rx.recv().is_ok());
        clear_test_hook();
        clear_lock_hook();
        cleanup(&canonical);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn writer_blocks_reader_until_recovery_transaction_resolves() {
        let _serial = test_hook_serial().lock().expect("test hook serial");
        let root = path("writer-reader-boundary");
        fs::create_dir_all(&root).expect("root");
        let real_parent = root.join("real");
        let alias_parent = root.join("alias");
        fs::create_dir_all(&real_parent).expect("real parent");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real_parent, &alias_parent).expect("parent symlink");
        let canonical = real_parent.join("state");
        fs::write(&canonical, b"old").expect("canonical");
        let writer_path = canonical.clone();
        let reader_path = alias_parent.join("child").join("..").join("state");
        fs::create_dir_all(alias_parent.join("child")).expect("child");
        assert_eq!(
            path_key(&canonical).expect("canonical key"),
            path_key(&reader_path).expect("reader key")
        );
        let (entered, release) = install_test_hook(&writer_path, TestHookPoint::AfterPrepare);
        let (writer_tx, writer_rx) = mpsc::channel();
        let writer = std::thread::spawn(move || {
            writer_tx
                .send(persist(
                    &writer_path,
                    StoreKind::Node,
                    "cluster",
                    "node-a",
                    "mutation",
                    b"old",
                    b"new",
                    false,
                ))
                .expect("writer result");
        });
        entered.wait();
        assert!(marker_path(&canonical).exists());

        let (lock_reached, lock_proceed, acquired_rx) = install_lock_hook(&reader_path);
        let (reader_tx, reader_rx) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            reader_tx
                .send(read_snapshot(
                    &reader_path,
                    StoreKind::Node,
                    "cluster",
                    "node-a",
                ))
                .expect("reader result");
        });
        lock_reached.wait();
        lock_proceed.wait();
        assert!(acquired_rx.try_recv().is_err());

        release.wait();
        assert_eq!(
            writer_rx.recv().expect("writer result").unwrap(),
            CommitResult::ConfirmedCommitted
        );
        assert_eq!(
            reader_rx.recv().expect("reader result").unwrap(),
            Some(b"new".to_vec())
        );
        writer.join().expect("writer");
        reader.join().expect("reader");
        assert!(!marker_path(&canonical).exists());
        clear_test_hook();
        clear_lock_hook();
        cleanup(&canonical);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn precommit_cleanup_failure_is_uncertain_and_keeps_marker() {
        let canonical = path("precommit-cleanup-failure");
        inject_fault_sequence_once(&[FaultPoint::CandidateTempFsync, FaultPoint::RecoveryUnlink]);
        let result = persist(
            &canonical,
            StoreKind::Node,
            "cluster",
            "node-a",
            "mutation",
            b"old",
            b"new",
            true,
        )
        .expect("persist");

        assert!(matches!(result, CommitResult::CommitOutcomeUnknown(_)));
        assert!(matches!(
            inspect(&canonical, StoreKind::Node, "cluster", "node-a"),
            Inspection::Active(_)
        ));
        assert!(is_uncertain(&canonical));
        cleanup(&canonical);
    }

    #[test]
    fn canonical_parent_fsync_failure_poisoned_store_and_preserved_marker() {
        let _serial = test_hook_serial().lock().expect("test hook serial");
        let root = path("canonical-fsync");
        let real = root.join("real");
        fs::create_dir_all(&real).expect("real parent");
        let canonical = real.join("state");
        TEST_FSYNC_TARGETS.with(|targets| targets.borrow_mut().clear());
        inject_fault_once(FaultPoint::CanonicalParentFsync);
        let result = persist(
            &canonical,
            StoreKind::Node,
            "cluster",
            "node-a",
            "mutation",
            b"old",
            b"new",
            true,
        )
        .expect("persist");

        assert!(matches!(result, CommitResult::CommitOutcomeUnknown(_)));
        TEST_FSYNC_TARGETS.with(|targets| {
            assert_eq!(
                *targets.borrow(),
                vec![
                    fs::canonicalize(canonical.parent().expect("canonical parent"))
                        .expect("resolved canonical parent")
                ]
            );
        });
        assert_ne!(
            canonical.parent().expect("canonical parent"),
            canonical
                .parent()
                .and_then(Path::parent)
                .unwrap_or_else(|| Path::new("."))
        );
        assert!(matches!(
            inspect(&canonical, StoreKind::Node, "cluster", "node-a"),
            Inspection::Active(_)
        ));
        assert!(is_uncertain(&canonical));
        assert!(matches!(
            persist(
                &canonical,
                StoreKind::Node,
                "cluster",
                "node-a",
                "retry",
                b"old",
                b"new",
                true,
            )
            .expect("second handle"),
            CommitResult::CommitOutcomeUnknown(_)
        ));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn detailed_inspection_classifies_old_new_and_neither_without_mutation() {
        let canonical = path("inspect-detail");
        fs::write(&canonical, b"old").expect("canonical");
        let marker = marker_path(&canonical);
        let metadata = RecoveryMetadata {
            recovery_format_version: RECOVERY_FORMAT_VERSION,
            store_kind: StoreKind::Node,
            cluster_id: "cluster".into(),
            node_or_witness_id: "node-a".into(),
            transaction_id: "00000000-0000-4000-8000-000000000001".into(),
            operation_class: "mutation".into(),
            canonical_path_identity: path_identity(&canonical),
            expected_old_sha256: fingerprint(b"old"),
            candidate_new_sha256: fingerprint(b"new"),
        };
        fs::write(&marker, toml::to_string(&metadata).expect("metadata")).expect("marker");
        #[cfg(unix)]
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).expect("permissions");
        assert!(matches!(
            inspect_detailed(&canonical, StoreKind::Node, "cluster", "node-a"),
            DetailedInspection::Active {
                canonical: CanonicalFingerprint::Old,
                ..
            }
        ));
        fs::write(&canonical, b"new").expect("candidate");
        assert!(matches!(
            inspect_detailed(&canonical, StoreKind::Node, "cluster", "node-a"),
            DetailedInspection::Active {
                canonical: CanonicalFingerprint::New,
                ..
            }
        ));
        fs::write(&canonical, b"other").expect("neither");
        assert!(matches!(
            inspect_detailed(&canonical, StoreKind::Node, "cluster", "node-a"),
            DetailedInspection::Active {
                canonical: CanonicalFingerprint::Neither,
                ..
            }
        ));
        cleanup(&canonical);
    }

    #[test]
    fn cleanup_parent_fsync_failure_poisoned_store_after_marker_removal() {
        let canonical = path("cleanup-fsync");
        inject_fault_once(FaultPoint::CleanupParentFsync);
        let result = persist(
            &canonical,
            StoreKind::Witness,
            "cluster",
            "witness",
            "mutation",
            b"old",
            b"new",
            true,
        )
        .expect("persist");

        assert!(matches!(result, CommitResult::CleanupOutcomeUnknown(_)));
        assert_eq!(
            inspect(&canonical, StoreKind::Witness, "cluster", "witness"),
            Inspection::Absent
        );
        assert!(is_uncertain(&canonical));
        cleanup(&canonical);
    }
}
