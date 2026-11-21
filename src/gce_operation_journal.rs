//! Unwired journal prototype. Send authorization remains disabled.
//! Never use this model to authorize a real API request or promotion.
//!
//! The journal is anchored below a directory that an administrator provisions
//! outside the journal writer's control. The writer only receives a
//! [`JournalStore`] built from that fixed, protected location. There is no
//! public constructor that turns an arbitrary descriptor or path into a
//! trusted anchor.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::{CString, OsStr};
use std::fs::{self, File, OpenOptions};
#[cfg(test)]
use std::io::{BufRead, BufReader};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
#[cfg(test)]
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
#[cfg(test)]
use std::os::unix::net::UnixListener;
#[cfg(test)]
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
#[cfg(test)]
use std::thread;
use std::time::Duration;

/// The only production anchor path. It is deliberately below `/var/lib`
/// (persistent) and its parent must be root-owned, so the service UID cannot
/// rename or replace the anchor itself. An administrator creates this
/// directory with the journal service UID as owner and mode 0700.
pub const SYSTEM_ANCHOR_PATH: &str = "/var/lib/mikagami/operation-journal";

const JOURNAL_DIR: &str = "journal";
const JOURNAL_FILE: &str = "journal.json";
const LOCK_FILE: &str = "journal.lock";
const PENDING_FILE: &str = "journal.pending";
const ANCHOR_FILE: &str = "journal.anchor";
const ANCHOR_PENDING_FILE: &str = "journal.anchor.pending";
const MAX_RECORD_BYTES: u64 = 65_536;
const MAX_ANCHOR_BYTES: u64 = 4_096;
const MAX_CAS_MESSAGE_BYTES: usize = 16_384;

const MAX_CAS_STATE_BYTES: u64 = 65_536;

/// Revision 0 is the provisioned anchor's initial state. It is not a journal
/// record; the first journal record uses revision 1.
pub const ANCHOR_GENESIS_DIGEST: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum State {
    Prepared,
    MayHaveBeenSent,
    OperationKnown,
    Pending,
    DoneObserved,
    TerminatedObserved,
    ProofEstablished,
    Unresolved,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attempt {
    pub attempt_id: String,
    pub generation: u64,
    pub term: u64,
    pub lease_id: String,
    pub project: String,
    pub zone: String,
    pub instance: String,
    pub instance_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub schema: u32,
    pub journal_id: String,
    pub attempt: Attempt,
    pub state: State,
    pub operation: Option<(String, String)>,
    pub revision: u64,
}

impl Record {
    pub fn transition(
        &self,
        attempt: &Attempt,
        next: State,
        operation: Option<(String, String)>,
    ) -> Option<Self> {
        if self.schema != 1 || &self.attempt != attempt || self.revision == u64::MAX {
            return None;
        }
        let valid = matches!(
            (self.state, next),
            (State::Prepared, State::MayHaveBeenSent)
                | (State::MayHaveBeenSent, State::OperationKnown)
                | (State::OperationKnown, State::Pending)
                | (State::OperationKnown, State::DoneObserved)
                | (State::Pending, State::DoneObserved)
                | (State::DoneObserved, State::TerminatedObserved)
                | (State::TerminatedObserved, State::ProofEstablished)
                | (
                    State::MayHaveBeenSent
                        | State::OperationKnown
                        | State::Pending
                        | State::DoneObserved
                        | State::TerminatedObserved,
                    State::Unresolved
                )
                | (
                    State::Prepared
                        | State::MayHaveBeenSent
                        | State::OperationKnown
                        | State::Pending
                        | State::DoneObserved
                        | State::TerminatedObserved
                        | State::Unresolved,
                    State::Blocked
                )
        );
        if !valid {
            return None;
        }
        let op = if next == State::OperationKnown {
            let pair = operation?;
            if pair.0.is_empty() || pair.1.is_empty() || self.operation.is_some() {
                return None;
            }
            Some(pair)
        } else {
            if operation.is_some() {
                return None;
            }
            self.operation.clone()
        };
        Some(Self {
            schema: 1,
            journal_id: self.journal_id.clone(),
            attempt: self.attempt.clone(),
            state: next,
            operation: op,
            revision: self.revision + 1,
        })
    }

    /// An in-memory model cannot confer a durable one-shot send capability.
    pub fn send_authorized(&self) -> bool {
        false
    }
}

/// Identity of the directory tree that contains one journal. The values are
/// captured only after the trusted provisioning walk has validated the whole
/// anchor path. They are persisted inside the checksummed envelope, so a
/// replaced anchor, journal directory or lock file makes an existing journal
/// unopenable instead of triggering automatic re-initialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreIdentity {
    schema: u32,
    #[serde(default, skip_serializing_if = "is_false")]
    anchor_required: bool,
    anchor_dev: u64,
    anchor_ino: u64,
    directory_dev: u64,
    directory_ino: u64,
    lock_dev: u64,
    lock_ino: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    record: Record,
    #[serde(default)]
    store: Option<StoreIdentity>,
    checksum: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AnchorIdentity(String);

impl AnchorIdentity {
    pub fn from_hex(value: impl Into<String>) -> Result<Self, ()> {
        let value = value.into();
        if valid_hex64(&value) {
            Ok(Self(value))
        } else {
            Err(())
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn valid_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A snapshot of an external monotonic anchor. `revision` is the number of
/// committed journal records; `digest` binds the record content at that
/// revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorState {
    pub identity: AnchorIdentity,
    pub revision: u64,
    pub digest: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorError {
    Unavailable,
    Corrupt,
    Conflict,
    Exhausted,
    Internal,
    /// The request may have reached the backend; the outcome is not known.
    /// Callers must re-observe and must not unconditionally retry.
    Unknown,
    Unauthorized,
    Protocol,
    /// The transport could not authenticate the peer before any request byte
    /// was written (`TransportError::AuthFailure`). A rejection that arrives
    /// after request bytes were written is not this variant: transports must
    /// report it as `TransportError::Unknown`, which surfaces as `Unknown`.
    AuthFailure,
    /// The peer authenticated but is not authorized for this identity/op.
    Forbidden,
    /// The request carried a session fence that is no longer current. Nothing
    /// was committed, and the session can never commit again.
    Fenced,
    /// This client holds a session that its owner (a journal or an
    /// assessment) has not ended; another caller may not replace it (J16).
    /// Nothing was sent.
    Busy,
}

/// External monotonic anchor contract.
///
/// `advance` MUST be a conditional compare-and-advance: it succeeds only if the
/// stored state is exactly `expected`, and it must durably store revision
/// `expected.revision + 1` with `next_digest` before returning. It MUST NOT
/// silently repair or rewind. Implementations that cannot provide this contract
/// (for example a file on the same VM disk) are test fakes only.
pub trait MonotonicAnchor: Send + Sync {
    fn identity(&self) -> AnchorIdentity;
    fn read(&self) -> Result<AnchorState, AnchorError>;
    /// Linearizing observation used before any decision. After this returns
    /// `Ok`, no request issued under an earlier session can commit. There is no
    /// default: an implementation may return `read()` only if its backend
    /// serializes every request through one ordered queue, and must say so.
    fn begin_session(&self) -> Result<AnchorState, AnchorError>;
    fn advance(
        &self,
        expected: &AnchorState,
        next_digest: &str,
    ) -> Result<AnchorState, AnchorError>;
    /// Drop any session this client holds, so that nothing more can be sent
    /// under it (J14, J11 IA-01). Anchors without sessions have nothing to
    /// drop.
    fn end_session(&self) {}
    /// The fence of the session this client holds, for anchors that have
    /// fences.
    fn current_fence(&self) -> Option<u64> {
        None
    }
    /// `begin_session` together with the fence that this very session
    /// obtained (not one read separately afterwards). `None` for anchors
    /// without fences: such a session proves nothing about older requests.
    fn begin_fenced_session(&self) -> Result<(AnchorState, Option<u64>), AnchorError> {
        self.begin_session().map(|state| (state, None))
    }
}

/// Only this module can implement `FencedAnchor` (J17-IA-02): a wrapper
/// elsewhere could otherwise pair a genuine lease with a state from a plain
/// read.
mod fenced_sealed {
    pub trait Sealed {}
}

/// An external anchor with fenced, owned sessions (protocol v2; J17). Unlike
/// `MonotonicAnchor`, nothing here has a default: an implementation cannot
/// silently stand in a plain read for a fenced BeginSession, nor an unowned
/// advance for an owned one. Journals and the recovery assessment in
/// production accept only this trait (`JournalStore::system_with_anchor`).
/// The trait is sealed: its only implementation is `NetworkCasAnchor`.
pub trait FencedAnchor: fenced_sealed::Sealed + Send + Sync {
    fn identity(&self) -> AnchorIdentity;
    fn read(&self) -> Result<AnchorState, AnchorError>;
    /// Begin a fenced session that only the returned lease can use or end.
    /// After this returns `Ok`, no request of an earlier session can commit.
    fn begin_owned_session(&self) -> Result<FencedSession, AnchorError>;
    /// Advance under the session that `lease` began. Sends nothing, and
    /// returns `Fenced`, unless that session is the one this client holds.
    fn advance_owned(
        &self,
        lease: &SessionLease,
        expected: &AnchorState,
        next_digest: &str,
    ) -> Result<AnchorState, AnchorError>;
    /// End the session that `lease` began, and only that one. Local and
    /// non-blocking; nothing is sent. Returns whether that session was still
    /// held. Dropping the lease ends it the same way.
    fn end_owned_session(&self, lease: SessionLease) -> bool;
}

/// Local proof that the caller began a session (J16), and the owner of it
/// (J17): dropping the lease ends that session on the client that issued it,
/// locally (no I/O), also during a panic unwind. Neither `Clone` nor `Copy`;
/// its id is issued once per process and never reused, and it names the one
/// client it belongs to. It is no credential and authorizes nothing at the
/// CAS, whose fence stays the only server-side check.
pub struct SessionLease {
    id: u64,
    slot: std::sync::Weak<std::sync::Mutex<SessionSlot>>,
}

impl std::fmt::Debug for SessionLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionLease")
            .field("id", &self.id)
            .finish()
    }
}

impl Drop for SessionLease {
    /// Ends the session this lease began, if the client still holds it. Takes
    /// only the client's slot mutex, which is never held across I/O; sends
    /// nothing and cannot fail.
    fn drop(&mut self) {
        if let Some(slot) = self.slot.upgrade() {
            slot.lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .end_lease(self.id);
        }
    }
}

/// Lease ids are unique within the process and never reused, so that a lease
/// of one client or of an earlier session can never match a later session.
static NEXT_SESSION_LEASE: std::sync::Mutex<u64> = std::sync::Mutex::new(1);

fn next_session_lease_id() -> Result<u64, AnchorError> {
    let mut next = NEXT_SESSION_LEASE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let id = *next;
    *next = id.checked_add(1).ok_or(AnchorError::Internal)?;
    Ok(id)
}

/// A session begun by `FencedAnchor::begin_owned_session`. The fence is not
/// optional: an anchor without fences cannot produce one. Only this module
/// can build one (J17-IA-02).
#[derive(Debug)]
pub struct FencedSession {
    pub state: AnchorState,
    pub fence: u64,
    pub lease: SessionLease,
    sealed: (),
}

/// The external anchor of a journal store (J17). Production stores hold only
/// a fenced anchor. The unfenced J5-J10 anchors (test fakes and the v1
/// `CasAnchor`) exist in test builds only.
#[derive(Clone)]
enum ExternalAnchor {
    Fenced(Arc<dyn FencedAnchor>),
    #[cfg(test)]
    Legacy(Arc<dyn MonotonicAnchor>),
}

/// A session begun through `ExternalAnchor`: a fenced session has a fence and
/// a lease, a legacy one neither.
struct BegunSession {
    state: AnchorState,
    fence: Option<u64>,
    lease: Option<SessionLease>,
}

impl ExternalAnchor {
    fn identity(&self) -> AnchorIdentity {
        match self {
            Self::Fenced(anchor) => anchor.identity(),
            #[cfg(test)]
            Self::Legacy(anchor) => anchor.identity(),
        }
    }

    fn read(&self) -> Result<AnchorState, AnchorError> {
        match self {
            Self::Fenced(anchor) => anchor.read(),
            #[cfg(test)]
            Self::Legacy(anchor) => anchor.read(),
        }
    }

    fn begin(&self) -> Result<BegunSession, AnchorError> {
        match self {
            Self::Fenced(anchor) => anchor.begin_owned_session().map(|session| BegunSession {
                state: session.state,
                fence: Some(session.fence),
                lease: Some(session.lease),
            }),
            #[cfg(test)]
            Self::Legacy(anchor) => {
                anchor
                    .begin_fenced_session()
                    .map(|(state, fence)| BegunSession {
                        state,
                        fence,
                        lease: None,
                    })
            }
        }
    }

    /// A fenced anchor needs the lease of the session; without one nothing
    /// is sent.
    fn advance(
        &self,
        lease: Option<&SessionLease>,
        expected: &AnchorState,
        next_digest: &str,
    ) -> Result<AnchorState, AnchorError> {
        match (self, lease) {
            (Self::Fenced(anchor), Some(lease)) => {
                anchor.advance_owned(lease, expected, next_digest)
            }
            (Self::Fenced(_), None) => Err(AnchorError::Fenced),
            #[cfg(test)]
            (Self::Legacy(anchor), _) => anchor.advance(expected, next_digest),
        }
    }

    /// Whether the session was still held. A legacy anchor owns nothing.
    fn end(&self, lease: Option<SessionLease>) -> bool {
        match (self, lease) {
            (Self::Fenced(anchor), Some(lease)) => anchor.end_owned_session(lease),
            (Self::Fenced(_), None) => false,
            #[cfg(test)]
            (Self::Legacy(anchor), _) => {
                anchor.end_session();
                false
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AnchorMetadata {
    identity: AnchorIdentity,
    revision: u64,
    digest: String,
}

fn anchor_digest(
    record: &Record,
    store: &StoreIdentity,
    identity: &AnchorIdentity,
    revision: u64,
) -> Result<String, ()> {
    #[derive(Serialize)]
    struct Input<'a> {
        record: &'a Record,
        store: &'a StoreIdentity,
        identity: &'a str,
        revision: u64,
    }
    let data = serde_json::to_vec(&Input {
        record,
        store,
        identity: identity.as_str(),
        revision,
    })
    .map_err(|_| ())?;
    Ok(format!("{:x}", Sha256::digest(&data)))
}

fn valid_anchor_state(state: &AnchorState) -> bool {
    valid_hex64(state.digest.as_str())
        && if state.revision == 0 {
            state.digest == ANCHOR_GENESIS_DIGEST
        } else {
            state.digest != ANCHOR_GENESIS_DIGEST
        }
}

fn valid_anchor_metadata(meta: &AnchorMetadata) -> bool {
    meta.revision > 0 && valid_hex64(meta.digest.as_str()) && meta.digest != ANCHOR_GENESIS_DIGEST
}

#[derive(Serialize)]
struct Signed<'a> {
    record: &'a Record,
    store: &'a StoreIdentity,
}

fn safe_component(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
}

fn valid(r: &Record) -> bool {
    r.schema == 1
        && r.revision > 0
        && r.attempt.generation > 0
        && r.attempt.term > 0
        && [
            &r.journal_id,
            &r.attempt.attempt_id,
            &r.attempt.lease_id,
            &r.attempt.project,
            &r.attempt.zone,
            &r.attempt.instance,
            &r.attempt.instance_id,
        ]
        .iter()
        .all(|s| safe_component(s))
        && r.attempt.instance_id.bytes().all(|c| c.is_ascii_digit())
        && match (&r.state, &r.operation) {
            (State::Prepared | State::MayHaveBeenSent, None) => true,
            (
                State::OperationKnown
                | State::Pending
                | State::DoneObserved
                | State::TerminatedObserved
                | State::ProofEstablished,
                Some((id, name)),
            ) => safe_component(id) && safe_component(name),
            (State::Unresolved | State::Blocked, None) => true,
            (State::Unresolved | State::Blocked, Some((id, name))) => {
                safe_component(id) && safe_component(name)
            }
            _ => false,
        }
}

fn valid_store(s: &StoreIdentity) -> bool {
    s.schema == 1
}

fn signed_checksum(record: &Record, store: &StoreIdentity) -> Result<String, ()> {
    let data = serde_json::to_vec(&Signed { record, store }).map_err(|_| ())?;
    Ok(format!("{:x}", Sha256::digest(&data)))
}

fn encode(r: &Record, store: &StoreIdentity) -> Result<Vec<u8>, ()> {
    if !valid(r) || !valid_store(store) {
        return Err(());
    }
    let checksum = signed_checksum(r, store)?;
    serde_json::to_vec(&Envelope {
        record: r.clone(),
        store: Some(*store),
        checksum,
    })
    .map_err(|_| ())
}

fn decode(bytes: &[u8]) -> Result<(Record, StoreIdentity), ()> {
    let e: Envelope = serde_json::from_slice(bytes).map_err(|_| ())?;
    let store = e.store.ok_or(())?;
    if !valid(&e.record)
        || !valid_store(&store)
        || e.checksum != signed_checksum(&e.record, &store)?
    {
        return Err(());
    }
    Ok((e.record, store))
}

fn trusted(meta: &fs::Metadata, directory: bool, service_uid: u32) -> bool {
    // Owner-only; the uid is pinned by provisioning, not re-read from the
    // process environment after a possible privilege change.
    meta.uid() == service_uid
        && meta.mode() & 0o077 == 0
        && if directory {
            meta.is_dir()
        } else {
            meta.is_file() && meta.nlink() == 1
        }
}

fn open_at(dir: &File, name: &OsStr, flags: i32, mode: u32) -> std::io::Result<File> {
    let name = CString::new(name.as_bytes())
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    loop {
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                mode as libc::c_uint,
            )
        };
        if fd >= 0 {
            return Ok(unsafe { File::from_raw_fd(fd) });
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn sync_file(file: &File) -> Result<(), ()> {
    loop {
        match file.sync_all() {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(()),
        }
    }
}

fn open_root_dir() -> Result<File, ()> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open("/")
        .map_err(|_| ())
}

fn normal_components(path: &Path) -> Option<Vec<&OsStr>> {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => components.push(name),
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => return None,
        }
    }
    if components.is_empty() {
        None
    } else {
        Some(components)
    }
}

fn same_inode(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

fn file_metadata(file: &File) -> Result<fs::Metadata, ()> {
    loop {
        match file.metadata() {
            Ok(metadata) => return Ok(metadata),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(()),
        }
    }
}

fn lock_exclusive(file: &File) -> Result<(), ()> {
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(());
        }
    }
}

fn named_exists(dir: &File, name: &str) -> Result<bool, ()> {
    match open_at(dir, OsStr::new(name), libc::O_RDONLY | libc::O_NONBLOCK, 0) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        // A symlink or any other inspection failure is not "absent".
        Err(_) => Err(()),
    }
}

fn pending_present(dir: &File) -> Result<bool, ()> {
    named_exists(dir, PENDING_FILE)
}

fn named_matches(dir: &File, name: &str, expected: &fs::Metadata) -> bool {
    let Ok(named) = open_at(dir, OsStr::new(name), libc::O_RDONLY | libc::O_NONBLOCK, 0) else {
        return false;
    };
    let Ok(metadata) = file_metadata(&named) else {
        return false;
    };
    same_inode(&metadata, expected)
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn is_local_filesystem(magic: u64) -> bool {
    !matches!(
        magic,
        0x6969        // NFS
            | 0xff53_4d42 // CIFS
            | 0x517b     // SMB
            | 0x6573_5546 // FUSE
            | 0x794c_7630 // overlayfs
            | 0x0102_1997 // 9p
            | 0x5346_414f // AFS
            | 0xfe53_4d42 // SMB2
    )
}

#[cfg(target_os = "linux")]
fn local_filesystem(file: &File) -> bool {
    let mut statfs: libc::statfs = unsafe { std::mem::zeroed() };
    loop {
        // SAFETY: `statfs` is valid writable storage and `file` owns the descriptor.
        if unsafe { libc::fstatfs(file.as_raw_fd(), &mut statfs) } == 0 {
            break;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return false;
        }
    }
    is_local_filesystem(statfs.f_type as u64)
}

#[cfg(not(target_os = "linux"))]
fn local_filesystem(_file: &File) -> bool {
    // Production is Linux-only. The macOS development host still exercises the
    // path, ownership, inode and lock checks; it cannot attest Linux fs magic.
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Boundary {
    /// Every ancestor is root-owned and not group/world writable; the final
    /// anchor is service-owned and private. Therefore the service UID cannot
    /// rename the anchor, and re-opening the fixed path finds the same inode.
    AdministratorProtected,
    /// Test-only. The development host has no second UID, so the same UID owns
    /// the ancestors. This proves the path/inode checks but not production
    /// namespace immutability.
    #[cfg(test)]
    TestSameUid,
}

fn anchor_component_ok(
    meta: &fs::Metadata,
    last: bool,
    service_uid: u32,
    boundary: Boundary,
) -> bool {
    if !meta.is_dir() {
        return false;
    }
    let writable = meta.mode() & 0o022 != 0;
    #[cfg(test)]
    let sticky = meta.mode() & 0o1000 != 0;
    #[cfg(test)]
    let sticky_test_root = boundary == Boundary::TestSameUid && sticky;
    #[cfg(not(test))]
    let sticky_test_root = false;
    if writable && !sticky_test_root {
        return false;
    }
    if last {
        meta.uid() == service_uid && meta.mode() & 0o077 == 0
    } else {
        match boundary {
            Boundary::AdministratorProtected => meta.uid() == 0,
            #[cfg(test)]
            Boundary::TestSameUid => meta.uid() == service_uid || meta.uid() == 0,
        }
    }
}

/// A descriptor and identity captured by a provisioning walk that started at
/// `/` and validated every component. The type has no public constructor; the
/// only production path is [`JournalStore::system`].
struct TrustedAnchor {
    fd: File,
    path: PathBuf,
    dev: u64,
    ino: u64,
    chain: Vec<(PathBuf, u64, u64)>,
    service_uid: u32,
    boundary: Boundary,
}

impl TrustedAnchor {
    fn provision(path: &Path, service_uid: u32, boundary: Boundary) -> Result<Self, ()> {
        if !path.is_absolute() {
            return Err(());
        }
        let components = normal_components(path).ok_or(())?;
        let mut current = open_root_dir()?;
        let mut chain = Vec::with_capacity(components.len());
        let mut current_path = PathBuf::from("/");
        let mut last_metadata = None;
        for (index, component) in components.iter().enumerate() {
            current_path.push(component);
            let next = open_at(&current, component, libc::O_RDONLY | libc::O_DIRECTORY, 0)
                .map_err(|_| ())?;
            let metadata = file_metadata(&next)?;
            if !anchor_component_ok(
                &metadata,
                index + 1 == components.len(),
                service_uid,
                boundary,
            ) {
                return Err(());
            }
            chain.push((current_path.clone(), metadata.dev(), metadata.ino()));
            last_metadata = Some(metadata);
            current = next;
        }
        let metadata = last_metadata.ok_or(())?;
        if boundary == Boundary::AdministratorProtected && !local_filesystem(&current) {
            return Err(());
        }
        let anchor = Self {
            fd: current,
            path: path.to_path_buf(),
            dev: metadata.dev(),
            ino: metadata.ino(),
            chain,
            service_uid,
            boundary,
        };
        anchor.verify()?;
        Ok(anchor)
    }

    fn verify(&self) -> Result<(), ()> {
        let metadata = file_metadata(&self.fd)?;
        if !anchor_component_ok(&metadata, true, self.service_uid, self.boundary)
            || (metadata.dev(), metadata.ino()) != (self.dev, self.ino)
        {
            return Err(());
        }
        if self.boundary == Boundary::AdministratorProtected && !local_filesystem(&self.fd) {
            return Err(());
        }
        let components = normal_components(&self.path).ok_or(())?;
        if components.len() != self.chain.len() {
            return Err(());
        }
        let mut current = open_root_dir()?;
        let mut current_path = PathBuf::from("/");
        for (index, component) in components.iter().enumerate() {
            current_path.push(component);
            let next = open_at(&current, component, libc::O_RDONLY | libc::O_DIRECTORY, 0)
                .map_err(|_| ())?;
            let metadata = file_metadata(&next)?;
            if !anchor_component_ok(
                &metadata,
                index + 1 == components.len(),
                self.service_uid,
                self.boundary,
            ) {
                return Err(());
            }
            let (pinned_path, dev, ino) = &self.chain[index];
            if current_path != *pinned_path || (metadata.dev(), metadata.ino()) != (*dev, *ino) {
                return Err(());
            }
            current = next;
        }
        let current_metadata = file_metadata(&current)?;
        if !same_inode(&current_metadata, &metadata)
            || (current_metadata.dev(), current_metadata.ino()) != (self.dev, self.ino)
        {
            return Err(());
        }
        Ok(())
    }
}

/// The only handle that can initialize or open a journal. It is produced from
/// the fixed, administrator-provisioned path; test builds additionally have a
/// path-based constructor that is compiled out of production.
pub struct JournalStore {
    anchor: Arc<TrustedAnchor>,
    external: Option<ExternalAnchor>,
}

/// What a test store may be built with (J17): a protocol v2 client becomes a
/// fenced external anchor, any other `MonotonicAnchor` (the J5-J10 fakes and
/// the v1 `CasAnchor`) a legacy one.
#[cfg(test)]
trait IntoExternal {
    fn into_external(self) -> ExternalAnchor;
}

#[cfg(test)]
impl IntoExternal for Arc<NetworkCasAnchor> {
    fn into_external(self) -> ExternalAnchor {
        ExternalAnchor::Fenced(self)
    }
}

#[cfg(test)]
impl IntoExternal for Arc<dyn FencedAnchor> {
    fn into_external(self) -> ExternalAnchor {
        ExternalAnchor::Fenced(self)
    }
}

#[cfg(test)]
impl IntoExternal for Arc<dyn MonotonicAnchor> {
    fn into_external(self) -> ExternalAnchor {
        ExternalAnchor::Legacy(self)
    }
}

#[cfg(test)]
impl IntoExternal for Arc<CasAnchor> {
    fn into_external(self) -> ExternalAnchor {
        ExternalAnchor::Legacy(self)
    }
}

impl JournalStore {
    /// Open the production anchor. This does not create it: an administrator
    /// must first create the fixed directory tree with the documented owner
    /// and mode. This legacy constructor has no external monotonic anchor and
    /// therefore rejects journals that carry a J5 anchor checkpoint.
    pub fn system() -> Result<Self, ()> {
        let service_uid = unsafe { libc::geteuid() };
        let anchor = TrustedAnchor::provision(
            Path::new(SYSTEM_ANCHOR_PATH),
            service_uid,
            Boundary::AdministratorProtected,
        )?;
        Ok(Self {
            anchor: Arc::new(anchor),
            external: None,
        })
    }

    /// Open the fixed production path with an external monotonic anchor.
    /// This is the J5-shaped constructor; it is not wired into production.
    /// Only a fenced (protocol v2) anchor is accepted (J17): an unfenced one,
    /// such as the v1 `CasAnchor`, does not implement `FencedAnchor`.
    pub fn system_with_anchor(external: Arc<dyn FencedAnchor>) -> Result<Self, ()> {
        let service_uid = unsafe { libc::geteuid() };
        let anchor = TrustedAnchor::provision(
            Path::new(SYSTEM_ANCHOR_PATH),
            service_uid,
            Boundary::AdministratorProtected,
        )?;
        Ok(Self {
            anchor: Arc::new(anchor),
            external: Some(ExternalAnchor::Fenced(external)),
        })
    }

    /// The fixed production path with any test anchor, including the
    /// unfenced J5-J10 fakes (J17: `system_with_anchor` takes a fenced
    /// anchor only). Test builds only.
    #[cfg(test)]
    fn system_with_test_anchor(external: impl IntoExternal) -> Result<Self, ()> {
        let service_uid = unsafe { libc::geteuid() };
        let anchor = TrustedAnchor::provision(
            Path::new(SYSTEM_ANCHOR_PATH),
            service_uid,
            Boundary::AdministratorProtected,
        )?;
        Ok(Self {
            anchor: Arc::new(anchor),
            external: Some(external.into_external()),
        })
    }

    #[cfg(test)]
    fn for_test(anchor: &Path) -> Result<Self, ()> {
        let service_uid = unsafe { libc::geteuid() };
        let anchor = TrustedAnchor::provision(anchor, service_uid, Boundary::TestSameUid)?;
        Ok(Self {
            anchor: Arc::new(anchor),
            external: None,
        })
    }

    #[cfg(test)]
    fn for_test_with_anchor(anchor: &Path, external: impl IntoExternal) -> Result<Self, ()> {
        let service_uid = unsafe { libc::geteuid() };
        let anchor = TrustedAnchor::provision(anchor, service_uid, Boundary::TestSameUid)?;
        Ok(Self {
            anchor: Arc::new(anchor),
            external: Some(external.into_external()),
        })
    }

    #[cfg(test)]
    fn for_test_with_uid(anchor: &Path, service_uid: u32) -> Result<Self, ()> {
        let anchor = TrustedAnchor::provision(anchor, service_uid, Boundary::TestSameUid)?;
        Ok(Self {
            anchor: Arc::new(anchor),
            external: None,
        })
    }

    /// Test-only constructor that exercises the production boundary policy
    /// against an isolated, root-owned temporary parent. This never changes the
    /// fixed `SYSTEM_ANCHOR_PATH`.
    #[cfg(test)]
    fn for_test_protected(anchor: &Path) -> Result<Self, ()> {
        let service_uid = unsafe { libc::geteuid() };
        let anchor =
            TrustedAnchor::provision(anchor, service_uid, Boundary::AdministratorProtected)?;
        Ok(Self {
            anchor: Arc::new(anchor),
            external: None,
        })
    }

    #[cfg(test)]
    fn for_test_protected_with_anchor(
        anchor: &Path,
        external: impl IntoExternal,
    ) -> Result<Self, ()> {
        let service_uid = unsafe { libc::geteuid() };
        let anchor =
            TrustedAnchor::provision(anchor, service_uid, Boundary::AdministratorProtected)?;
        Ok(Self {
            anchor: Arc::new(anchor),
            external: Some(external.into_external()),
        })
    }

    /// Create a brand-new journal. This never replaces an existing record.
    pub fn initialize(&self, record: Record) -> Result<Journal, ()> {
        Journal::initialize(&self.anchor, self.external.as_ref(), record)
    }

    /// Re-open an existing journal. This never creates a missing journal and
    /// never re-initializes an identity mismatch.
    pub fn open(&self) -> Result<Journal, ()> {
        Journal::open(&self.anchor, self.external.as_ref())
    }
}

struct Held {
    anchor_lock: File,
    directory: File,
    lock: File,
    identity: StoreIdentity,
}

fn ensure_journal_dir(anchor: &File, create: bool, service_uid: u32) -> Result<File, ()> {
    match open_at(
        anchor,
        OsStr::new(JOURNAL_DIR),
        libc::O_RDONLY | libc::O_DIRECTORY,
        0,
    ) {
        Ok(directory) => {
            let metadata = file_metadata(&directory)?;
            if !trusted(&metadata, true, service_uid) {
                return Err(());
            }
            Ok(directory)
        }
        Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
            let name = CString::new(JOURNAL_DIR).map_err(|_| ())?;
            loop {
                if unsafe { libc::mkdirat(anchor.as_raw_fd(), name.as_ptr(), 0o700) } == 0 {
                    break;
                }
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                if error.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(());
                }
                break;
            }
            let directory = open_at(
                anchor,
                OsStr::new(JOURNAL_DIR),
                libc::O_RDONLY | libc::O_DIRECTORY,
                0,
            )
            .map_err(|_| ())?;
            let metadata = file_metadata(&directory)?;
            if !trusted(&metadata, true, service_uid) {
                return Err(());
            }
            Ok(directory)
        }
        Err(_) => Err(()),
    }
}

fn acquire(
    anchor: &TrustedAnchor,
    create_journal_dir: bool,
    create_lock: bool,
    anchor_required: bool,
) -> Result<Held, ()> {
    // Anchor namespace must still be the pinned one before any locking.
    anchor.verify()?;
    let anchor_lock = open_at(
        &anchor.fd,
        OsStr::new("."),
        libc::O_RDONLY | libc::O_DIRECTORY,
        0,
    )
    .map_err(|_| ())?;
    let anchor_metadata = file_metadata(&anchor_lock)?;
    let anchor_fd_metadata = file_metadata(&anchor.fd)?;
    if !same_inode(&anchor_metadata, &anchor_fd_metadata) {
        return Err(());
    }
    // One lock on the stable anchor serializes every cooperating writer, even
    // when a journal directory is replaced by a different inode.
    lock_exclusive(&anchor_lock)?;
    // Re-check after taking the lock: a replacement that happened before the
    // lock is rejected before any journal state is read or written.
    anchor.verify()?;

    let directory = ensure_journal_dir(&anchor.fd, create_journal_dir, anchor.service_uid)?;
    lock_exclusive(&directory)?;
    let directory_metadata = file_metadata(&directory)?;
    if !trusted(&directory_metadata, true, anchor.service_uid)
        || directory_metadata.dev() != anchor.dev
    {
        return Err(());
    }
    let current_directory = open_at(
        &anchor.fd,
        OsStr::new(JOURNAL_DIR),
        libc::O_RDONLY | libc::O_DIRECTORY,
        0,
    )
    .map_err(|_| ())?;
    let current_directory_metadata = file_metadata(&current_directory)?;
    if !same_inode(&directory_metadata, &current_directory_metadata)
        || !trusted(&current_directory_metadata, true, anchor.service_uid)
    {
        return Err(());
    }
    if anchor.boundary == Boundary::AdministratorProtected && !local_filesystem(&directory) {
        return Err(());
    }

    let flags = libc::O_RDWR | libc::O_NONBLOCK | if create_lock { libc::O_CREAT } else { 0 };
    let lock = open_at(&directory, OsStr::new(LOCK_FILE), flags, 0o600).map_err(|_| ())?;
    let lock_metadata = file_metadata(&lock)?;
    if !trusted(&lock_metadata, false, anchor.service_uid)
        || lock_metadata.dev() != directory_metadata.dev()
    {
        return Err(());
    }
    if anchor.boundary == Boundary::AdministratorProtected && !local_filesystem(&lock) {
        return Err(());
    }
    lock_exclusive(&lock)?;
    // The lock must still be the inode we locked. A replacement after this
    // point is detected by Journal::guard_intact before every update.
    if !named_matches(&directory, LOCK_FILE, &lock_metadata) {
        return Err(());
    }
    let named_lock = open_at(
        &directory,
        OsStr::new(LOCK_FILE),
        libc::O_RDONLY | libc::O_NONBLOCK,
        0,
    )
    .map_err(|_| ())?;
    let named_metadata = file_metadata(&named_lock)?;
    if !trusted(&named_metadata, false, anchor.service_uid)
        || !same_inode(&named_metadata, &lock_metadata)
    {
        return Err(());
    }
    let identity = StoreIdentity {
        schema: 1,
        anchor_required,
        anchor_dev: anchor.dev,
        anchor_ino: anchor.ino,
        directory_dev: directory_metadata.dev(),
        directory_ino: directory_metadata.ino(),
        lock_dev: lock_metadata.dev(),
        lock_ino: lock_metadata.ino(),
    };
    Ok(Held {
        anchor_lock,
        directory,
        lock,
        identity,
    })
}

fn read_record(dir: &File, service_uid: u32) -> Result<(Record, StoreIdentity), ()> {
    let mut file = open_at(
        dir,
        OsStr::new(JOURNAL_FILE),
        libc::O_RDONLY | libc::O_NONBLOCK,
        0,
    )
    .map_err(|_| ())?;
    let metadata = file_metadata(&file)?;
    let directory_metadata = file_metadata(dir)?;
    if !trusted(&metadata, false, service_uid)
        || metadata.dev() != directory_metadata.dev()
        || metadata.len() > MAX_RECORD_BYTES
    {
        return Err(());
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(());
    }
    decode(&bytes)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnchorCheckpointEnvelope {
    schema: u32,
    identity: AnchorIdentity,
    revision: u64,
    digest: String,
    checksum: String,
}

fn anchor_checkpoint_checksum(
    identity: &AnchorIdentity,
    revision: u64,
    digest: &str,
) -> Result<String, ()> {
    #[derive(Serialize)]
    struct Input<'a> {
        schema: u32,
        identity: &'a AnchorIdentity,
        revision: u64,
        digest: &'a str,
    }
    let data = serde_json::to_vec(&Input {
        schema: 1,
        identity,
        revision,
        digest,
    })
    .map_err(|_| ())?;
    Ok(format!("{:x}", Sha256::digest(&data)))
}

fn encode_anchor_checkpoint(meta: &AnchorMetadata) -> Result<Vec<u8>, ()> {
    if !valid_anchor_metadata(meta) {
        return Err(());
    }
    let checksum = anchor_checkpoint_checksum(&meta.identity, meta.revision, &meta.digest)?;
    serde_json::to_vec(&AnchorCheckpointEnvelope {
        schema: 1,
        identity: meta.identity.clone(),
        revision: meta.revision,
        digest: meta.digest.clone(),
        checksum,
    })
    .map_err(|_| ())
}

fn decode_anchor_checkpoint(bytes: &[u8]) -> Result<AnchorMetadata, ()> {
    let envelope: AnchorCheckpointEnvelope = serde_json::from_slice(bytes).map_err(|_| ())?;
    let meta = AnchorMetadata {
        identity: envelope.identity,
        revision: envelope.revision,
        digest: envelope.digest,
    };
    if envelope.schema != 1
        || !valid_anchor_metadata(&meta)
        || envelope.checksum
            != anchor_checkpoint_checksum(&meta.identity, meta.revision, &meta.digest)?
    {
        return Err(());
    }
    Ok(meta)
}

fn read_anchor_checkpoint(dir: &File, service_uid: u32) -> Result<AnchorMetadata, ()> {
    let mut file = open_at(
        dir,
        OsStr::new(ANCHOR_FILE),
        libc::O_RDONLY | libc::O_NONBLOCK,
        0,
    )
    .map_err(|_| ())?;
    let metadata = file_metadata(&file)?;
    let directory_metadata = file_metadata(dir)?;
    if !trusted(&metadata, false, service_uid)
        || metadata.dev() != directory_metadata.dev()
        || metadata.len() > MAX_ANCHOR_BYTES
    {
        return Err(());
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_ANCHOR_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() as u64 > MAX_ANCHOR_BYTES {
        return Err(());
    }
    decode_anchor_checkpoint(&bytes)
}

fn anchor_checkpoint_present(dir: &File) -> Result<bool, ()> {
    named_exists(dir, ANCHOR_FILE)
}

fn anchor_checkpoint_pending_present(dir: &File) -> Result<bool, ()> {
    named_exists(dir, ANCHOR_PENDING_FILE)
}

fn write_anchor_checkpoint(
    dir: &File,
    meta: &AnchorMetadata,
    initial: bool,
    service_uid: u32,
) -> Result<(), ()> {
    let bytes = encode_anchor_checkpoint(meta)?;
    let directory_metadata = file_metadata(dir)?;
    fault(6)?;
    let mut file = open_at(
        dir,
        OsStr::new(ANCHOR_PENDING_FILE),
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )
    .map_err(|_| ())?;
    fault(7)?;
    let pending_metadata = file_metadata(&file)?;
    if !trusted(&pending_metadata, false, service_uid)
        || pending_metadata.dev() != directory_metadata.dev()
        || !named_matches(dir, ANCHOR_PENDING_FILE, &pending_metadata)
    {
        return Err(());
    }
    file.write_all(&bytes).map_err(|_| ())?;
    fault(8)?;
    sync_file(&file)?;
    if !named_matches(dir, ANCHOR_PENDING_FILE, &pending_metadata) {
        return Err(());
    }

    let pending = CString::new(ANCHOR_PENDING_FILE).map_err(|_| ())?;
    let target = CString::new(ANCHOR_FILE).map_err(|_| ())?;
    if initial {
        loop {
            if unsafe {
                libc::linkat(
                    dir.as_raw_fd(),
                    pending.as_ptr(),
                    dir.as_raw_fd(),
                    target.as_ptr(),
                    0,
                )
            } == 0
            {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(());
            }
        }
        if !named_matches(dir, ANCHOR_FILE, &pending_metadata) {
            let _ = unsafe { libc::unlinkat(dir.as_raw_fd(), target.as_ptr(), 0) };
            return Err(());
        }
        if !named_matches(dir, ANCHOR_PENDING_FILE, &pending_metadata) {
            let _ = unsafe { libc::unlinkat(dir.as_raw_fd(), target.as_ptr(), 0) };
            return Err(());
        }
        loop {
            if unsafe { libc::unlinkat(dir.as_raw_fd(), pending.as_ptr(), 0) } == 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(());
            }
        }
    } else {
        loop {
            if unsafe {
                libc::renameat(
                    dir.as_raw_fd(),
                    pending.as_ptr(),
                    dir.as_raw_fd(),
                    target.as_ptr(),
                )
            } == 0
            {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(());
            }
        }
    }

    let target_file = open_at(
        dir,
        OsStr::new(ANCHOR_FILE),
        libc::O_RDONLY | libc::O_NONBLOCK,
        0,
    )
    .map_err(|_| ())?;
    let target_metadata = file_metadata(&target_file)?;
    if !same_inode(&target_metadata, &pending_metadata)
        || !trusted(&target_metadata, false, service_uid)
        || target_metadata.dev() != directory_metadata.dev()
    {
        return Err(());
    }
    fault(9)?;
    sync_file(dir)?;
    Ok(())
}

#[cfg(test)]
thread_local! {
    static INJECT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}

fn fault(point: u8) -> Result<(), ()> {
    #[cfg(test)]
    if INJECT.with(|value| value.get() == point) {
        return Err(());
    }
    let _ = point;
    Ok(())
}

/// Test-only process crash hook used by the J5 crash-window children.
fn crash_if(point: &str) {
    #[cfg(test)]
    if std::env::var("MKG_J5_CRASH_POINT").ok().as_deref() == Some(point) {
        unsafe { libc::kill(libc::getpid(), libc::SIGKILL) };
        loop {
            unsafe { libc::pause() };
        }
    }
    let _ = point;
}

fn write_record(
    dir: &File,
    record: &Record,
    store: &StoreIdentity,
    initial: bool,
    service_uid: u32,
) -> Result<(), ()> {
    let bytes = encode(record, store)?;
    let directory_metadata = file_metadata(dir)?;
    fault(1)?;
    let mut file = open_at(
        dir,
        OsStr::new(PENDING_FILE),
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )
    .map_err(|_| ())?;
    fault(2)?;
    let pending_metadata = file_metadata(&file)?;
    if !trusted(&pending_metadata, false, service_uid)
        || pending_metadata.dev() != directory_metadata.dev()
        || !named_matches(dir, PENDING_FILE, &pending_metadata)
    {
        return Err(());
    }
    file.write_all(&bytes).map_err(|_| ())?;
    fault(3)?;
    sync_file(&file)?;
    // The name must still refer to the inode we wrote before committing it.
    if !named_matches(dir, PENDING_FILE, &pending_metadata) {
        return Err(());
    }
    fault(4)?;

    let pending = CString::new(PENDING_FILE).map_err(|_| ())?;
    let target = CString::new(JOURNAL_FILE).map_err(|_| ())?;
    if initial {
        // linkat is a no-replace create. If a journal already exists, this
        // returns EEXIST and the existing record is untouched.
        loop {
            if unsafe {
                libc::linkat(
                    dir.as_raw_fd(),
                    pending.as_ptr(),
                    dir.as_raw_fd(),
                    target.as_ptr(),
                    0,
                )
            } == 0
            {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(());
            }
        }
        // We created the target with linkat, so it is safe to remove it if the
        // post-link identity check fails.
        if !named_matches(dir, JOURNAL_FILE, &pending_metadata) {
            let _ = unsafe { libc::unlinkat(dir.as_raw_fd(), target.as_ptr(), 0) };
            return Err(());
        }
        // If the pending name was swapped after the link, do not unlink an
        // attacker-controlled name; remove the target link we just created.
        if !named_matches(dir, PENDING_FILE, &pending_metadata) {
            let _ = unsafe { libc::unlinkat(dir.as_raw_fd(), target.as_ptr(), 0) };
            return Err(());
        }
        loop {
            if unsafe { libc::unlinkat(dir.as_raw_fd(), pending.as_ptr(), 0) } == 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(());
            }
        }
    } else {
        loop {
            if unsafe {
                libc::renameat(
                    dir.as_raw_fd(),
                    pending.as_ptr(),
                    dir.as_raw_fd(),
                    target.as_ptr(),
                )
            } == 0
            {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(());
            }
        }
    }

    let target_file = open_at(
        dir,
        OsStr::new(JOURNAL_FILE),
        libc::O_RDONLY | libc::O_NONBLOCK,
        0,
    )
    .map_err(|_| ())?;
    let target_metadata = file_metadata(&target_file)?;
    if !same_inode(&target_metadata, &pending_metadata)
        || !trusted(&target_metadata, false, service_uid)
        || target_metadata.dev() != directory_metadata.dev()
    {
        return Err(());
    }
    fault(5)?;
    sync_file(dir)?;
    Ok(())
}

/// A held journal. `send_authorized` is always false; this prototype cannot
/// issue a durable one-shot capability and is not wired into production.
pub struct Journal {
    anchor: Arc<TrustedAnchor>,
    anchor_lock: File,
    directory: File,
    lock: File,
    identity: StoreIdentity,
    external: Option<ExternalAnchor>,
    /// The session this handle began on `external` (J16). Taken when the
    /// handle ends it: on failure, `close` or drop (dropping the lease ends
    /// it as well, J17).
    session: Option<SessionLease>,
    anchor_meta: Option<AnchorMetadata>,
    poisoned: bool,
    record: Record,
}

/// What `Journal::close` found (J16).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionClose {
    /// The handle still held its session, and ended it.
    Ended,
    /// There was nothing to end: no external anchor, an anchor without
    /// owned sessions, or the handle already ended its session after a
    /// failure (J17: no other caller can end or replace it).
    NotHeld,
}

impl Drop for Journal {
    /// Ends the session this handle began, so that nothing more can be sent
    /// under it. Local only: it sends nothing, never waits for the network
    /// and cannot fail.
    fn drop(&mut self) {
        self.end_own_session();
    }
}

impl Journal {
    /// End this handle's session, and only it: a session that someone else
    /// began later is left alone.
    fn end_own_session(&mut self) -> SessionClose {
        let lease = self.session.take();
        match &self.external {
            Some(external) if external.end(lease) => SessionClose::Ended,
            _ => SessionClose::NotHeld,
        }
    }

    /// Normal end of a journal (J16): the session ends and nothing more can
    /// be sent under it. The record on disk is unchanged.
    pub fn close(mut self) -> SessionClose {
        self.end_own_session()
    }

    fn initialize(
        anchor: &Arc<TrustedAnchor>,
        external: Option<&ExternalAnchor>,
        record: Record,
    ) -> Result<Self, ()> {
        if record.state != State::Prepared
            || record.revision != 1
            || record.operation.is_some()
            || !valid(&record)
        {
            return Err(());
        }
        let held = acquire(anchor, true, true, external.is_some())?;
        // Never overwrite an existing journal, anchor checkpoint, or pending
        // file. A missing journal is the only initialization case.
        if named_exists(&held.directory, JOURNAL_FILE)?
            || pending_present(&held.directory)?
            || anchor_checkpoint_present(&held.directory)?
            || anchor_checkpoint_pending_present(&held.directory)?
        {
            return Err(());
        }

        let (external_owned, session, anchor_meta) = match external {
            Some(external_anchor) => {
                let identity = external_anchor.identity();
                let BegunSession { state, lease, .. } = external_anchor.begin().map_err(|_| ())?;
                if !valid_anchor_state(&state)
                    || state.identity != identity
                    || state.revision != 0
                    || state.digest != ANCHOR_GENESIS_DIGEST
                {
                    external_anchor.end(lease);
                    return Err(());
                }
                let Ok(digest) = anchor_digest(&record, &held.identity, &identity, 1) else {
                    external_anchor.end(lease);
                    return Err(());
                };
                let meta = AnchorMetadata {
                    identity: identity.clone(),
                    revision: 1,
                    digest,
                };
                let Ok(next) = external_anchor.advance(lease.as_ref(), &state, &meta.digest) else {
                    external_anchor.end(lease);
                    return Err(());
                };
                if next.identity != meta.identity
                    || next.revision != meta.revision
                    || next.digest != meta.digest
                {
                    external_anchor.end(lease);
                    return Err(());
                }
                crash_if("after_anchor");
                (Some(external_anchor.clone()), lease, Some(meta))
            }
            None => (None, None, None),
        };

        let end = |session: Option<SessionLease>| {
            if let Some(external) = &external_owned {
                external.end(session);
            }
        };
        if write_record(
            &held.directory,
            &record,
            &held.identity,
            true,
            anchor.service_uid,
        )
        .is_err()
        {
            end(session);
            return Err(());
        }
        if let Some(meta) = &anchor_meta {
            crash_if("after_journal");
            if write_anchor_checkpoint(&held.directory, meta, true, anchor.service_uid).is_err() {
                end(session);
                return Err(());
            }
            crash_if("after_checkpoint");
        }
        let mut journal = Self {
            anchor: Arc::clone(anchor),
            anchor_lock: held.anchor_lock,
            directory: held.directory,
            lock: held.lock,
            identity: held.identity,
            external: external_owned,
            session,
            anchor_meta,
            poisoned: false,
            record,
        };
        // A replacement that raced with the initial write is a failure, not a
        // successfully initialized journal.
        if !journal.guard_intact() {
            #[cfg(test)]
            J9B_OPEN_STAGE.store(9, std::sync::atomic::Ordering::SeqCst);
            journal.end_own_session();
            return Err(());
        }
        Ok(journal)
    }

    fn open(anchor: &Arc<TrustedAnchor>, external: Option<&ExternalAnchor>) -> Result<Self, ()> {
        let held = acquire(anchor, false, false, external.is_some())?;
        // A leftover local temporary file means a write may have been
        // interrupted. An anchor checkpoint pending file is equally unknown.
        if pending_present(&held.directory)? || anchor_checkpoint_pending_present(&held.directory)?
        {
            #[cfg(test)]
            J9B_OPEN_STAGE.store(1, std::sync::atomic::Ordering::SeqCst);
            return Err(());
        }
        let (record, identity) = match read_record(&held.directory, anchor.service_uid) {
            Ok(value) => value,
            Err(_) => {
                #[cfg(test)]
                J9B_OPEN_STAGE.store(2, std::sync::atomic::Ordering::SeqCst);
                return Err(());
            }
        };
        if identity != held.identity || identity.anchor_required != external.is_some() {
            #[cfg(test)]
            J9B_OPEN_STAGE.store(3, std::sync::atomic::Ordering::SeqCst);
            return Err(());
        }

        let (external_owned, session, anchor_meta) = match external {
            Some(external_anchor) => {
                if !anchor_checkpoint_present(&held.directory)? {
                    #[cfg(test)]
                    J9B_OPEN_STAGE.store(4, std::sync::atomic::Ordering::SeqCst);
                    return Err(());
                }
                let meta = read_anchor_checkpoint(&held.directory, anchor.service_uid)?;
                if external_anchor.identity() != meta.identity {
                    #[cfg(test)]
                    J9B_OPEN_STAGE.store(5, std::sync::atomic::Ordering::SeqCst);
                    return Err(());
                }
                if meta.revision != record.revision
                    || anchor_digest(&record, &held.identity, &meta.identity, meta.revision)?
                        != meta.digest
                {
                    #[cfg(test)]
                    J9B_OPEN_STAGE.store(6, std::sync::atomic::Ordering::SeqCst);
                    return Err(());
                }
                // Stage 7 is the first external observation of this handle. It
                // starts a fenced session so that no earlier session's in-flight
                // advance can commit after the comparison below.
                let BegunSession { state, lease, .. } = match external_anchor.begin() {
                    Ok(session) => session,
                    Err(_) => {
                        #[cfg(test)]
                        J9B_OPEN_STAGE.store(7, std::sync::atomic::Ordering::SeqCst);
                        return Err(());
                    }
                };
                #[cfg(test)]
                J9A_EXTERNAL_READ.store(true, std::sync::atomic::Ordering::SeqCst);
                if !valid_anchor_state(&state)
                    || state.identity != meta.identity
                    || state.revision != meta.revision
                    || state.digest != meta.digest
                {
                    #[cfg(test)]
                    J9A_EXTERNAL_MISMATCH.store(true, std::sync::atomic::Ordering::SeqCst);
                    #[cfg(test)]
                    J9B_OPEN_STAGE.store(8, std::sync::atomic::Ordering::SeqCst);
                    external_anchor.end(lease);
                    return Err(());
                }
                (Some(external_anchor.clone()), lease, Some(meta))
            }
            None => {
                // A J5 journal must not be openable through the legacy
                // constructor, even if the caller ignores the checkpoint.
                if anchor_checkpoint_present(&held.directory)?
                    || anchor_checkpoint_pending_present(&held.directory)?
                {
                    return Err(());
                }
                (None, None, None)
            }
        };

        let mut journal = Self {
            anchor: Arc::clone(anchor),
            anchor_lock: held.anchor_lock,
            directory: held.directory,
            lock: held.lock,
            identity: held.identity,
            external: external_owned,
            session,
            anchor_meta,
            poisoned: false,
            record,
        };
        // Re-open must also prove that the namespace and external anchor still
        // name the record/inodes that were read. A replacement during the read
        // fails closed.
        if !journal.guard_intact() {
            #[cfg(test)]
            J9B_OPEN_STAGE.store(9, std::sync::atomic::Ordering::SeqCst);
            journal.end_own_session();
            return Err(());
        }
        Ok(journal)
    }

    fn guard_intact(&self) -> bool {
        if self.anchor.verify().is_err() {
            return false;
        }
        let Ok(anchor_metadata) = file_metadata(&self.anchor.fd) else {
            return false;
        };
        let Ok(anchor_lock_metadata) = file_metadata(&self.anchor_lock) else {
            return false;
        };
        if !same_inode(&anchor_metadata, &anchor_lock_metadata) {
            return false;
        }
        let Ok(directory_metadata) = file_metadata(&self.directory) else {
            return false;
        };
        if !trusted(&directory_metadata, true, self.anchor.service_uid)
            || directory_metadata.dev() != self.anchor.dev
        {
            return false;
        }
        let Ok(current_directory) = open_at(
            &self.anchor.fd,
            OsStr::new(JOURNAL_DIR),
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        ) else {
            return false;
        };
        let Ok(current_directory_metadata) = file_metadata(&current_directory) else {
            return false;
        };
        if !same_inode(&directory_metadata, &current_directory_metadata) {
            return false;
        }
        let Ok(lock_metadata) = file_metadata(&self.lock) else {
            return false;
        };
        if !trusted(&lock_metadata, false, self.anchor.service_uid)
            || lock_metadata.dev() != directory_metadata.dev()
        {
            return false;
        }
        let Ok(current_lock) = open_at(
            &self.directory,
            OsStr::new(LOCK_FILE),
            libc::O_RDONLY | libc::O_NONBLOCK,
            0,
        ) else {
            return false;
        };
        let Ok(current_lock_metadata) = file_metadata(&current_lock) else {
            return false;
        };
        if !trusted(&current_lock_metadata, false, self.anchor.service_uid)
            || !same_inode(&lock_metadata, &current_lock_metadata)
        {
            return false;
        }
        let expected = StoreIdentity {
            schema: 1,
            anchor_required: self.identity.anchor_required,
            anchor_dev: self.anchor.dev,
            anchor_ino: self.anchor.ino,
            directory_dev: directory_metadata.dev(),
            directory_ino: directory_metadata.ino(),
            lock_dev: lock_metadata.dev(),
            lock_ino: lock_metadata.ino(),
        };
        if expected != self.identity {
            return false;
        }
        if anchor_checkpoint_pending_present(&self.directory).unwrap_or(true) {
            return false;
        }
        match (&self.external, &self.anchor_meta) {
            (Some(external_anchor), Some(meta)) => {
                if external_anchor.identity() != meta.identity
                    || meta.revision != self.record.revision
                {
                    return false;
                }
                let Ok(checkpoint) =
                    read_anchor_checkpoint(&self.directory, self.anchor.service_uid)
                else {
                    return false;
                };
                if checkpoint != *meta {
                    return false;
                }
                let Ok(digest) =
                    anchor_digest(&self.record, &self.identity, &meta.identity, meta.revision)
                else {
                    return false;
                };
                if digest != meta.digest {
                    return false;
                }
                let Ok(state) = external_anchor.read() else {
                    return false;
                };
                state.identity == meta.identity
                    && state.revision == meta.revision
                    && state.digest == meta.digest
            }
            (None, None) => !anchor_checkpoint_present(&self.directory).unwrap_or(true),
            _ => false,
        }
    }

    pub fn advance(
        &mut self,
        attempt: &Attempt,
        next: State,
        operation: Option<(String, String)>,
    ) -> Result<(), ()> {
        if self.poisoned {
            return Err(());
        }
        if !self.guard_intact() {
            self.poison();
            return Err(());
        }
        match read_record(&self.directory, self.anchor.service_uid) {
            Ok((current, store)) if current == self.record && store == self.identity => {}
            _ => {
                self.poison();
                return Err(());
            }
        }
        let current_state = match (&self.external, &self.anchor_meta) {
            (Some(external_anchor), Some(meta)) => {
                if external_anchor.identity() != meta.identity {
                    self.poison();
                    return Err(());
                }
                let state = match external_anchor.read() {
                    Ok(state) => state,
                    Err(_) => {
                        self.poison();
                        return Err(());
                    }
                };
                if state.identity != meta.identity
                    || state.revision != meta.revision
                    || state.digest != meta.digest
                {
                    self.poison();
                    return Err(());
                }
                Some(state)
            }
            (None, None) => None,
            _ => {
                self.poison();
                return Err(());
            }
        };
        let record = self.record.transition(attempt, next, operation).ok_or(())?;
        match (&self.external, &self.anchor_meta) {
            (Some(external_anchor), Some(meta)) => {
                let next_revision = meta.revision.checked_add(1).ok_or(())?;
                if record.revision != next_revision {
                    self.poison();
                    return Err(());
                }
                let next_meta = AnchorMetadata {
                    identity: meta.identity.clone(),
                    revision: next_revision,
                    digest: anchor_digest(&record, &self.identity, &meta.identity, next_revision)?,
                };
                let expected = match current_state {
                    Some(state) => state,
                    None => {
                        self.poison();
                        return Err(());
                    }
                };
                let next_state = match external_anchor.advance(
                    self.session.as_ref(),
                    &expected,
                    &next_meta.digest,
                ) {
                    Ok(state) => state,
                    Err(_) => {
                        self.poison();
                        return Err(());
                    }
                };
                if next_state.identity != next_meta.identity
                    || next_state.revision != next_meta.revision
                    || next_state.digest != next_meta.digest
                {
                    self.poison();
                    return Err(());
                }
                crash_if("after_anchor");
                if write_record(
                    &self.directory,
                    &record,
                    &self.identity,
                    false,
                    self.anchor.service_uid,
                )
                .is_err()
                {
                    self.poison();
                    return Err(());
                }
                crash_if("after_journal");
                if write_anchor_checkpoint(
                    &self.directory,
                    &next_meta,
                    false,
                    self.anchor.service_uid,
                )
                .is_err()
                {
                    self.poison();
                    return Err(());
                }
                crash_if("after_checkpoint");
                self.record = record;
                self.anchor_meta = Some(next_meta);
            }
            (None, None) => {
                if write_record(
                    &self.directory,
                    &record,
                    &self.identity,
                    false,
                    self.anchor.service_uid,
                )
                .is_err()
                {
                    self.poison();
                    return Err(());
                }
                self.record = record;
            }
            _ => {
                self.poison();
                return Err(());
            }
        }
        if !self.guard_intact() {
            self.poison();
            return Err(());
        }
        Ok(())
    }

    /// A failed handle is never used again, and the session it opened is
    /// dropped from the client, so that no caller holding the same anchor
    /// can send under it either (J14, J11 IA-01).
    fn poison(&mut self) {
        self.poisoned = true;
        self.end_own_session();
    }

    /// Read-only view of the last record this handle committed.
    pub fn record(&self) -> &Record {
        &self.record
    }

    /// This incomplete prototype cannot issue a capability, including on restart.
    pub fn send_authorized(&self) -> bool {
        false
    }
}

// Protocol v1 (J5-J9): the unfenced CAS over a local Unix socket. Test builds
// only (J17): its server always was, and its client cannot stand in for a
// fenced v2 session (`FencedAnchor`), so production has no use for it.
#[cfg(test)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", deny_unknown_fields)]
enum CasRequest {
    Read {
        request_id: String,
        identity: AnchorIdentity,
        token: String,
    },
    Advance {
        request_id: String,
        identity: AnchorIdentity,
        token: String,
        expected: AnchorState,
        next_revision: u64,
        next_digest: String,
    },
}

#[cfg(test)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", deny_unknown_fields)]
enum CasResponse {
    State {
        request_id: String,
        state: AnchorState,
    },
    Committed {
        request_id: String,
        state: AnchorState,
    },
    Conflict {
        request_id: String,
        state: AnchorState,
    },
    Rejected {
        request_id: String,
        reason: CasReject,
    },
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum CasReject {
    Unauthorized,
    Identity,
    Conflict,
    InvalidDigest,
    Overflow,
    Corrupt,
}

fn cas_request_id() -> Result<String, AnchorError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| AnchorError::Internal)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Client for the localhost-independent CAS server (protocol v1, test builds
/// only, J17). It never retries a timed-out/closed Advance; an Unknown result
/// requires explicit re-observation. It has no fence and does not implement
/// `FencedAnchor`, so no production journal or assessment can use it.
#[cfg(test)]
pub struct CasAnchor {
    socket: PathBuf,
    identity: AnchorIdentity,
    token: String,
    timeout: Duration,
}

#[cfg(test)]
impl CasAnchor {
    pub fn new(
        socket: PathBuf,
        identity: AnchorIdentity,
        token: String,
        timeout: Duration,
    ) -> Result<Self, ()> {
        if token.is_empty() {
            return Err(());
        }
        Ok(Self {
            socket,
            identity,
            token,
            timeout,
        })
    }

    fn exchange(&self, request: &CasRequest) -> Result<CasResponse, AnchorError> {
        let mut stream = UnixStream::connect(&self.socket).map_err(|_| AnchorError::Unavailable)?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|_| AnchorError::Internal)?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|_| AnchorError::Internal)?;
        let mut bytes = serde_json::to_vec(request).map_err(|_| AnchorError::Internal)?;
        bytes.push(b'\n');
        if stream.write_all(&bytes).is_err() {
            return Err(AnchorError::Unknown);
        }
        if stream.flush().is_err() {
            return Err(AnchorError::Unknown);
        }
        let mut reader = BufReader::new(stream);
        let mut bytes = Vec::new();
        match (&mut reader)
            .take(MAX_CAS_MESSAGE_BYTES as u64 + 1)
            .read_until(b'\n', &mut bytes)
        {
            Ok(0) => Err(AnchorError::Unknown),
            Ok(_) if bytes.len() > MAX_CAS_MESSAGE_BYTES => Err(AnchorError::Protocol),
            Ok(_) => {
                let line = String::from_utf8(bytes).map_err(|_| AnchorError::Protocol)?;
                serde_json::from_str(&line).map_err(|_| AnchorError::Protocol)
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                Err(AnchorError::Unknown)
            }
            Err(_) => Err(AnchorError::Unknown),
        }
    }
}

#[cfg(test)]
impl MonotonicAnchor for CasAnchor {
    fn identity(&self) -> AnchorIdentity {
        self.identity.clone()
    }

    /// v1 has no fence. This is a plain read, which linearizes only because the
    /// v1 test server handles one connection at a time in accept order on a
    /// directly connected local Unix socket. It does not hold through SSH
    /// socket forwarding or any network hop, and delays in the kernel accept
    /// backlog are not verified. Use protocol v2 (`NetworkCasAnchor`) for any
    /// remote backend.
    fn begin_session(&self) -> Result<AnchorState, AnchorError> {
        self.read()
    }

    fn read(&self) -> Result<AnchorState, AnchorError> {
        let request_id = cas_request_id()?;
        let request = CasRequest::Read {
            request_id: request_id.clone(),
            identity: self.identity.clone(),
            token: self.token.clone(),
        };
        match self.exchange(&request)? {
            CasResponse::State {
                request_id: response_id,
                state,
            } if response_id == request_id => {
                if !valid_anchor_state(&state) || state.identity != self.identity {
                    return Err(AnchorError::Corrupt);
                }
                Ok(state)
            }
            CasResponse::Rejected {
                request_id: response_id,
                reason,
            } if response_id == request_id => Err(match reason {
                CasReject::Unauthorized => AnchorError::Unauthorized,
                CasReject::Identity => AnchorError::Corrupt,
                CasReject::Corrupt => AnchorError::Corrupt,
                _ => AnchorError::Protocol,
            }),
            _ => Err(AnchorError::Protocol),
        }
    }

    fn advance(
        &self,
        expected: &AnchorState,
        next_digest: &str,
    ) -> Result<AnchorState, AnchorError> {
        let request_id = cas_request_id()?;
        let next_revision = expected
            .revision
            .checked_add(1)
            .ok_or(AnchorError::Exhausted)?;
        let request = CasRequest::Advance {
            request_id: request_id.clone(),
            identity: self.identity.clone(),
            token: self.token.clone(),
            expected: expected.clone(),
            next_revision,
            next_digest: next_digest.to_string(),
        };
        match self.exchange(&request)? {
            CasResponse::Committed {
                request_id: response_id,
                state,
            } if response_id == request_id => {
                if !valid_anchor_state(&state)
                    || state.identity != expected.identity
                    || state.revision != next_revision
                    || state.digest != next_digest
                {
                    return Err(AnchorError::Protocol);
                }
                Ok(state)
            }
            CasResponse::Conflict {
                request_id: response_id,
                state,
            } if response_id == request_id => {
                if !valid_anchor_state(&state) || state.identity != self.identity {
                    return Err(AnchorError::Corrupt);
                }
                Err(AnchorError::Conflict)
            }
            CasResponse::Rejected {
                request_id: response_id,
                reason,
            } if response_id == request_id => Err(match reason {
                CasReject::Unauthorized => AnchorError::Unauthorized,
                CasReject::Identity => AnchorError::Corrupt,
                CasReject::Conflict => AnchorError::Conflict,
                CasReject::InvalidDigest => AnchorError::Protocol,
                CasReject::Overflow => AnchorError::Exhausted,
                CasReject::Corrupt => AnchorError::Corrupt,
            }),
            _ => Err(AnchorError::Protocol),
        }
    }
}

// Protocol v2 (Phase 1-J11). Fenced sessions over an abstract transport.
// No network transport exists; the only server is the `#[cfg(test)]`
// reference model in `cas_v2_reference`. Normative description:
// prototype/v0.7/phase1-journal/j10/CAS_PROTOCOL.md.

/// The only protocol version this code speaks. Anything else, including a
/// missing `v` (protocol v1), is rejected rather than interpreted.
pub const CAS_PROTOCOL_VERSION: u32 = 2;

/// Committed requests remembered for duplicate detection and inquiry.
pub const CAS_LEDGER_CAPACITY: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", deny_unknown_fields)]
pub enum CasV2Request {
    Read {
        v: u32,
        request_id: String,
        identity: AnchorIdentity,
    },
    /// Durably increments the identity's fence before replying. Every request
    /// carrying an older fence is refused from then on.
    BeginSession {
        v: u32,
        request_id: String,
        identity: AnchorIdentity,
    },
    Advance {
        v: u32,
        request_id: String,
        identity: AnchorIdentity,
        fence: u64,
        expected: AnchorState,
        next_revision: u64,
        next_digest: String,
    },
    /// Ledger lookup. Never a basis for a decision without a prior
    /// `BeginSession`.
    Inquire {
        v: u32,
        request_id: String,
        identity: AnchorIdentity,
        target_request_id: String,
    },
}

impl CasV2Request {
    pub fn request_id(&self) -> &str {
        match self {
            Self::Read { request_id, .. }
            | Self::BeginSession { request_id, .. }
            | Self::Advance { request_id, .. }
            | Self::Inquire { request_id, .. } => request_id,
        }
    }

    pub fn identity(&self) -> &AnchorIdentity {
        match self {
            Self::Read { identity, .. }
            | Self::BeginSession { identity, .. }
            | Self::Advance { identity, .. }
            | Self::Inquire { identity, .. } => identity,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", deny_unknown_fields)]
pub enum CasV2Response {
    State {
        v: u32,
        request_id: String,
        state: AnchorState,
    },
    Session {
        v: u32,
        request_id: String,
        state: AnchorState,
        fence: u64,
    },
    Committed {
        v: u32,
        request_id: String,
        state: AnchorState,
        replayed: bool,
    },
    Conflict {
        v: u32,
        request_id: String,
        state: AnchorState,
    },
    Fenced {
        v: u32,
        request_id: String,
        current_fence: u64,
    },
    InquiryResult {
        v: u32,
        request_id: String,
        found: bool,
        resulting_revision: Option<u64>,
    },
    Rejected {
        v: u32,
        request_id: String,
        reason: CasV2Reject,
    },
}

impl CasV2Response {
    fn request_id(&self) -> &str {
        match self {
            Self::State { request_id, .. }
            | Self::Session { request_id, .. }
            | Self::Committed { request_id, .. }
            | Self::Conflict { request_id, .. }
            | Self::Fenced { request_id, .. }
            | Self::InquiryResult { request_id, .. }
            | Self::Rejected { request_id, .. } => request_id,
        }
    }

    fn version(&self) -> u32 {
        match self {
            Self::State { v, .. }
            | Self::Session { v, .. }
            | Self::Committed { v, .. }
            | Self::Conflict { v, .. }
            | Self::Fenced { v, .. }
            | Self::InquiryResult { v, .. }
            | Self::Rejected { v, .. } => *v,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CasV2Reject {
    Forbidden,
    UnknownIdentity,
    InvalidRequest,
    Exhausted,
    RequestIdReuse,
    Version,
    NotReady,
    Corrupt,
}

/// Decode one v2 request. The version is checked on an untyped view first,
/// so a v1 request (no `v`) or any other version is refused as `Version`
/// instead of being parsed under v2 rules. The error carries the request id
/// when one could be read, for echoing.
pub fn cas_v2_decode_request(bytes: &[u8]) -> Result<CasV2Request, (String, CasV2Reject)> {
    if bytes.len() > MAX_CAS_MESSAGE_BYTES {
        return Err((String::new(), CasV2Reject::InvalidRequest));
    }
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| (String::new(), CasV2Reject::InvalidRequest))?;
    let request_id = value
        .get("request_id")
        .and_then(|id| id.as_str())
        .filter(|id| id.len() <= 64)
        .unwrap_or("")
        .to_string();
    if value.get("v").and_then(|v| v.as_u64()) != Some(u64::from(CAS_PROTOCOL_VERSION)) {
        return Err((request_id, CasV2Reject::Version));
    }
    let request: CasV2Request = serde_json::from_value(value)
        .map_err(|_| (request_id.clone(), CasV2Reject::InvalidRequest))?;
    if !valid_request_id(request.request_id()) {
        return Err((request_id, CasV2Reject::InvalidRequest));
    }
    Ok(request)
}

fn valid_request_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Identifies an Advance body for duplicate detection. It excludes the
/// request id and contains no secret.
pub fn cas_v2_body_hash(
    identity: &AnchorIdentity,
    fence: u64,
    expected: &AnchorState,
    next_revision: u64,
    next_digest: &str,
) -> Result<String, ()> {
    #[derive(Serialize)]
    struct Body<'a> {
        identity: &'a AnchorIdentity,
        fence: u64,
        expected: &'a AnchorState,
        next_revision: u64,
        next_digest: &'a str,
    }
    let data = serde_json::to_vec(&Body {
        identity,
        fence,
        expected,
        next_revision,
        next_digest,
    })
    .map_err(|_| ())?;
    Ok(format!("{:x}", Sha256::digest(&data)))
}

/// Why an exchange produced no response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportError {
    /// Nothing was written; the peer cannot have seen the request.
    NotSent,
    /// Peer authentication failed before any request byte was written. A
    /// transport that learns of a rejection only after it started writing (for
    /// example a TLS 1.3 alert for the client certificate) must return
    /// `Unknown` instead.
    AuthFailure,
    /// Request bytes may have been written. The outcome is not known; this is
    /// never evidence that the request was not, or will not be, processed.
    Unknown,
}

/// One request, one response. A successful exchange carries bytes only; it
/// authorizes nothing.
pub trait CasTransport: Send + Sync {
    fn exchange(&self, request: &[u8]) -> Result<Vec<u8>, TransportError>;
}

/// Answer to `Inquire`. Diagnostic only: a ledger miss does not prove that a
/// request was not committed, and nothing may be concluded from it without a
/// `BeginSession` first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InquiryOutcome {
    pub found: bool,
    pub resulting_revision: Option<u64>,
}

/// Protocol v2 client. It never retries. Any advance outcome other than
/// success clears the session fence, so a further advance needs a new
/// `begin_session` (normally a new `Journal::open`).
pub struct NetworkCasAnchor {
    transport: Arc<dyn CasTransport>,
    identity: AnchorIdentity,
    /// Held across the exchange of `begin_session` and `advance`, so one
    /// client never uses a fence while a session change is in flight.
    exchange_lock: std::sync::Mutex<()>,
    /// The session this client holds. Never held across I/O, so ending a
    /// session never waits for the network (J16). Shared (weakly) with the
    /// leases this client issues, so that dropping a lease can end its
    /// session (J17).
    session: Arc<std::sync::Mutex<SessionSlot>>,
    last_advance_request_id: std::sync::Mutex<Option<String>>,
    /// The fence of the last session this client established. Kept when the
    /// session is dropped, so that a later assessment can tell whether the
    /// CAS went back (J14 RecoveryContext::previous_fence). Not persisted.
    last_session_fence: std::sync::Mutex<Option<u64>>,
}

/// One fenced session of a `NetworkCasAnchor` (J16). `lease` is `None` for
/// a session begun through the unowned `begin_session`, which a direct
/// `advance` may use; an owned session is usable only with its lease.
#[derive(Debug)]
struct HeldSession {
    fence: u64,
    lease: Option<u64>,
}

#[derive(Debug, Default)]
struct SessionSlot {
    held: Option<HeldSession>,
    /// The session an advance is using right now, taken out of `held`.
    in_flight: Option<HeldSession>,
    /// The session in flight was ended meanwhile: it is not reinstated, even
    /// if the advance commits.
    in_flight_ended: bool,
}

impl SessionSlot {
    /// End a session begun through the unowned `begin_session`. An owned
    /// session is left alone: only its lease can end it (J17).
    fn end_unowned(&mut self) {
        if matches!(self.held, Some(HeldSession { lease: None, .. })) {
            self.held = None;
        }
        if matches!(self.in_flight, Some(HeldSession { lease: None, .. })) {
            self.in_flight_ended = true;
        }
    }

    /// End the owned session of lease `id`, held or in flight. Returns
    /// whether it was still held.
    fn end_lease(&mut self, id: u64) -> bool {
        let owns = |session: &Option<HeldSession>| matches!(session, Some(HeldSession { lease: Some(owner), .. }) if *owner == id);
        if owns(&self.held) {
            self.held = None;
            true
        } else if owns(&self.in_flight) && !self.in_flight_ended {
            self.in_flight_ended = true;
            true
        } else {
            false
        }
    }
}

impl NetworkCasAnchor {
    pub fn new(transport: Arc<dyn CasTransport>, identity: AnchorIdentity) -> Self {
        Self {
            transport,
            identity,
            exchange_lock: std::sync::Mutex::new(()),
            session: Arc::new(std::sync::Mutex::new(SessionSlot::default())),
            last_advance_request_id: std::sync::Mutex::new(None),
            last_session_fence: std::sync::Mutex::new(None),
        }
    }

    fn slot(&self) -> std::sync::MutexGuard<'_, SessionSlot> {
        self.session
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The fence of the session this client holds and that no advance is
    /// using right now.
    pub fn current_fence(&self) -> Option<u64> {
        self.slot().held.as_ref().map(|held| held.fence)
    }

    /// Whether this client holds a session that a direct `advance` could
    /// use, that is, one begun through the unowned `begin_session` (J16).
    pub fn holds_unowned_session(&self) -> bool {
        matches!(self.slot().held, Some(HeldSession { lease: None, .. }))
    }

    /// The fence of the last session this client established, even after
    /// the session was dropped.
    pub fn last_session_fence(&self) -> Option<u64> {
        *self
            .last_session_fence
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn identity(&self) -> AnchorIdentity {
        self.identity.clone()
    }

    pub fn read(&self) -> Result<AnchorState, AnchorError> {
        let request_id = cas_request_id()?;
        let request = CasV2Request::Read {
            v: CAS_PROTOCOL_VERSION,
            request_id,
            identity: self.identity.clone(),
        };
        match self.exchange(&request)? {
            CasV2Response::State { state, .. } => self.checked_state(state),
            CasV2Response::Rejected { reason, .. } => Err(v2_reject_error(reason)),
            _ => Err(AnchorError::Protocol),
        }
    }

    /// Whether `lease` was issued by this client.
    fn issued_here(&self, lease: &SessionLease) -> bool {
        std::sync::Weak::ptr_eq(&lease.slot, &Arc::downgrade(&self.session))
    }

    /// A fenced session that only the returned lease can use or end. The
    /// lease is made before anything is sent: if its id cannot be issued,
    /// nothing is sent; if the begin fails, the lease ends nothing.
    pub fn begin_owned_session(&self) -> Result<FencedSession, AnchorError> {
        let lease = SessionLease {
            id: next_session_lease_id()?,
            slot: Arc::downgrade(&self.session),
        };
        let (state, fence) = self.begin_session_fenced(Some(lease.id))?;
        Ok(FencedSession {
            state,
            fence,
            lease,
            sealed: (),
        })
    }

    pub fn advance_owned(
        &self,
        lease: &SessionLease,
        expected: &AnchorState,
        next_digest: &str,
    ) -> Result<AnchorState, AnchorError> {
        if !self.issued_here(lease) {
            return Err(AnchorError::Fenced);
        }
        self.advance_in_session(Some(lease.id), expected, next_digest)
    }

    /// End the session of `lease` (consumed: a lease ends once). A lease of
    /// another client ends nothing here and returns `false`; being consumed,
    /// it is dropped, which ends its session on the client that issued it.
    pub fn end_owned_session(&self, lease: SessionLease) -> bool {
        if !self.issued_here(&lease) {
            return false;
        }
        // The slot guard is released at the end of this statement, before
        // the lease is dropped (its Drop takes the same mutex; J17-IA-01).
        let held = self.slot().end_lease(lease.id);
        drop(lease);
        held
    }

    /// Begin a session; a lease id makes it an owned one. Refused, with
    /// nothing sent, while this client holds an owned session (J16-IA-01):
    /// its owner must end it first. Under `exchange_lock`, no advance is in
    /// flight here.
    fn begin_session_fenced(&self, lease: Option<u64>) -> Result<(AnchorState, u64), AnchorError> {
        let _exchange = self
            .exchange_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Cleared before sending: if this call fails in any way, including an
        // unknown outcome, the client holds no fence at all.
        {
            let mut slot = self.slot();
            if matches!(slot.held, Some(HeldSession { lease: Some(_), .. })) {
                return Err(AnchorError::Busy);
            }
            slot.held = None;
            slot.in_flight = None;
            slot.in_flight_ended = false;
        }
        let request_id = cas_request_id()?;
        let request = CasV2Request::BeginSession {
            v: CAS_PROTOCOL_VERSION,
            request_id,
            identity: self.identity.clone(),
        };
        match self.exchange(&request)? {
            CasV2Response::Session {
                state,
                fence: new_fence,
                ..
            } => {
                // Fence 0 is the provisioned value; a session always moves it.
                if new_fence == 0 {
                    return Err(AnchorError::Protocol);
                }
                let state = self.checked_state(state)?;
                self.slot().held = Some(HeldSession {
                    fence: new_fence,
                    lease,
                });
                *self
                    .last_session_fence
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(new_fence);
                Ok((state, new_fence))
            }
            CasV2Response::Rejected { reason, .. } => Err(v2_reject_error(reason)),
            _ => Err(AnchorError::Protocol),
        }
    }

    /// Request id of the most recent advance attempt, for inquiry after an
    /// unknown outcome.
    pub fn last_advance_request_id(&self) -> Option<String> {
        self.last_advance_request_id
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub fn inquire(&self, target_request_id: &str) -> Result<InquiryOutcome, AnchorError> {
        let request_id = cas_request_id()?;
        let request = CasV2Request::Inquire {
            v: CAS_PROTOCOL_VERSION,
            request_id: request_id.clone(),
            identity: self.identity.clone(),
            target_request_id: target_request_id.to_string(),
        };
        match self.exchange(&request)? {
            CasV2Response::InquiryResult {
                found,
                resulting_revision,
                ..
            } if found == resulting_revision.is_some() => Ok(InquiryOutcome {
                found,
                resulting_revision,
            }),
            CasV2Response::Rejected { reason, .. } => Err(v2_reject_error(reason)),
            _ => Err(AnchorError::Protocol),
        }
    }

    fn exchange(&self, request: &CasV2Request) -> Result<CasV2Response, AnchorError> {
        let bytes = serde_json::to_vec(request).map_err(|_| AnchorError::Internal)?;
        if bytes.len() > MAX_CAS_MESSAGE_BYTES {
            return Err(AnchorError::Internal);
        }
        let reply = self
            .transport
            .exchange(&bytes)
            .map_err(|error| match error {
                TransportError::NotSent => AnchorError::Unavailable,
                TransportError::AuthFailure => AnchorError::AuthFailure,
                TransportError::Unknown => AnchorError::Unknown,
            })?;
        // Everything below happens after the request was sent. Each failure is
        // reported as `Protocol` for diagnosis and is equivalent to `Unknown`
        // for recovery.
        if reply.len() > MAX_CAS_MESSAGE_BYTES {
            return Err(AnchorError::Protocol);
        }
        let response: CasV2Response =
            serde_json::from_slice(&reply).map_err(|_| AnchorError::Protocol)?;
        if response.version() != CAS_PROTOCOL_VERSION
            || response.request_id() != request.request_id()
        {
            return Err(AnchorError::Protocol);
        }
        Ok(response)
    }

    fn checked_state(&self, state: AnchorState) -> Result<AnchorState, AnchorError> {
        if !valid_anchor_state(&state) || state.identity != self.identity {
            return Err(AnchorError::Corrupt);
        }
        Ok(state)
    }
}

fn v2_reject_error(reason: CasV2Reject) -> AnchorError {
    match reason {
        CasV2Reject::Forbidden | CasV2Reject::UnknownIdentity => AnchorError::Forbidden,
        CasV2Reject::InvalidRequest | CasV2Reject::RequestIdReuse | CasV2Reject::Version => {
            AnchorError::Protocol
        }
        CasV2Reject::Exhausted => AnchorError::Exhausted,
        CasV2Reject::NotReady => AnchorError::Unavailable,
        CasV2Reject::Corrupt => AnchorError::Corrupt,
    }
}

/// The unowned, J11-J15 interface, for direct callers. It can neither use
/// nor end a session that a lease owns.
impl MonotonicAnchor for NetworkCasAnchor {
    fn identity(&self) -> AnchorIdentity {
        NetworkCasAnchor::identity(self)
    }

    /// Drops the unowned session this client holds. An owned session (of a
    /// journal or an assessment) is not touched: holding the same client is
    /// no authority to end someone else's session (J17).
    fn end_session(&self) {
        self.slot().end_unowned();
    }

    fn current_fence(&self) -> Option<u64> {
        NetworkCasAnchor::current_fence(self)
    }

    fn read(&self) -> Result<AnchorState, AnchorError> {
        NetworkCasAnchor::read(self)
    }

    fn begin_session(&self) -> Result<AnchorState, AnchorError> {
        self.begin_session_fenced(None).map(|(state, _)| state)
    }

    fn begin_fenced_session(&self) -> Result<(AnchorState, Option<u64>), AnchorError> {
        self.begin_session_fenced(None)
            .map(|(state, fence)| (state, Some(fence)))
    }

    /// An unowned advance: only a session begun through `begin_session` can
    /// be used. A session that a journal owns sends nothing (J16).
    fn advance(
        &self,
        expected: &AnchorState,
        next_digest: &str,
    ) -> Result<AnchorState, AnchorError> {
        self.advance_in_session(None, expected, next_digest)
    }
}

impl fenced_sealed::Sealed for NetworkCasAnchor {}

impl FencedAnchor for NetworkCasAnchor {
    fn identity(&self) -> AnchorIdentity {
        NetworkCasAnchor::identity(self)
    }

    fn read(&self) -> Result<AnchorState, AnchorError> {
        NetworkCasAnchor::read(self)
    }

    fn begin_owned_session(&self) -> Result<FencedSession, AnchorError> {
        NetworkCasAnchor::begin_owned_session(self)
    }

    fn advance_owned(
        &self,
        lease: &SessionLease,
        expected: &AnchorState,
        next_digest: &str,
    ) -> Result<AnchorState, AnchorError> {
        NetworkCasAnchor::advance_owned(self, lease, expected, next_digest)
    }

    fn end_owned_session(&self, lease: SessionLease) -> bool {
        NetworkCasAnchor::end_owned_session(self, lease)
    }
}

impl NetworkCasAnchor {
    fn advance_in_session(
        &self,
        lease: Option<u64>,
        expected: &AnchorState,
        next_digest: &str,
    ) -> Result<AnchorState, AnchorError> {
        let _exchange = self
            .exchange_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // No session of this caller, no request: nothing is sent without the
        // current fence of a session the caller may use.
        let current = {
            let mut slot = self.slot();
            match &slot.held {
                Some(held) if held.lease == lease => {}
                _ => return Err(AnchorError::Fenced),
            }
            let held = slot.held.take();
            let current = held.as_ref().map(|held| held.fence);
            slot.in_flight = held;
            slot.in_flight_ended = false;
            current
        };
        let Some(current) = current else {
            return Err(AnchorError::Fenced);
        };
        let result = self.send_advance(current, expected, next_digest);
        // From here the session stays dropped unless the advance commits and
        // nothing ended the session meanwhile.
        let mut slot = self.slot();
        let in_flight = slot.in_flight.take();
        if result.is_ok() && !slot.in_flight_ended && slot.held.is_none() {
            slot.held = in_flight;
        }
        slot.in_flight_ended = false;
        result
    }

    fn send_advance(
        &self,
        current: u64,
        expected: &AnchorState,
        next_digest: &str,
    ) -> Result<AnchorState, AnchorError> {
        let next_revision = expected
            .revision
            .checked_add(1)
            .ok_or(AnchorError::Exhausted)?;
        let request_id = cas_request_id()?;
        *self
            .last_advance_request_id
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(request_id.clone());
        let request = CasV2Request::Advance {
            v: CAS_PROTOCOL_VERSION,
            request_id,
            identity: self.identity.clone(),
            fence: current,
            expected: expected.clone(),
            next_revision,
            next_digest: next_digest.to_string(),
        };
        match self.exchange(&request)? {
            // A fresh request id can never be a replay; `replayed: true` here
            // means the server is confused, so fail closed.
            CasV2Response::Committed {
                state,
                replayed: false,
                ..
            } => {
                if !valid_anchor_state(&state)
                    || state.identity != expected.identity
                    || state.revision != next_revision
                    || state.digest != next_digest
                {
                    return Err(AnchorError::Protocol);
                }
                Ok(state)
            }
            CasV2Response::Conflict { state, .. } => {
                self.checked_state(state)?;
                Err(AnchorError::Conflict)
            }
            CasV2Response::Fenced { .. } => Err(AnchorError::Fenced),
            CasV2Response::Rejected { reason, .. } => Err(v2_reject_error(reason)),
            _ => Err(AnchorError::Protocol),
        }
    }
}

// Phase 1-J12: TLS 1.3 mutual authentication and server-side authorization
// for protocol v2. Prototype only: the TLS crates are dev-dependencies, so
// none of this can be linked into the mikagami binary. Normative description:
// prototype/v0.7/phase1-journal/j12/TLS_DESIGN.md and ACL_POLICY.md.

/// ALPN of protocol v2 over TLS. Both ends require it after the handshake; a
/// peer that negotiated no ALPN, or another one, is refused.
pub const CAS_TLS_ALPN: &[u8] = b"mikagami-cas/2";

/// Scheme of every principal and server name carried in a URI SAN.
pub const CAS_PRINCIPAL_PREFIX: &str = "mikagami-cas://";

const MAX_PEM_BYTES: u64 = 65_536;
const MAX_PRINCIPAL_BYTES: usize = 255;

/// The single place that selects the crypto provider. `ring` is the
/// prototype choice (J12 DEPENDENCY_AUDIT.md); the production choice is
/// Owner decision OD-J10-3.
fn cas_crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Why TLS material or policy could not be loaded. Carries no file contents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CasTlsError {
    /// Missing, not a regular file, a symlink, wrong owner or permissive mode.
    File,
    /// The path is not absolute and plain, or a directory above the file is a
    /// symlink, not owned by root or this uid, or writable by group or others
    /// (J16).
    Directory,
    /// Not the expected PEM content (or more than one key).
    Pem,
    /// rustls refused the configuration.
    Config,
    /// The ACL file is malformed or violates a structural rule.
    Acl,
}

/// A directory above a TLS or ACL file (J16): a directory owned by root or
/// this euid that neither group nor others can write, so that no other uid
/// can rename, replace or add an entry on the way to the file. Test builds
/// also accept a root-owned sticky directory (the system temporary directory
/// of the Linux test host), as the anchor walk does.
fn protected_ancestor_ok(is_dir: bool, uid: u32, mode: u32, euid: u32) -> bool {
    if !is_dir || (uid != 0 && uid != euid) {
        return false;
    }
    let writable = mode & 0o022 != 0;
    #[cfg(test)]
    let sticky_test_root = uid == 0 && mode & 0o1000 != 0;
    #[cfg(not(test))]
    let sticky_test_root = false;
    !writable || sticky_test_root
}

fn protected_ancestor(metadata: &fs::Metadata, euid: u32) -> bool {
    protected_ancestor_ok(metadata.is_dir(), metadata.uid(), metadata.mode(), euid)
}

#[cfg(test)]
thread_local! {
    /// J16 test hook: runs after the walk to the parent of a TLS or ACL file
    /// and before the file is opened through the parent's descriptor.
    static J16_AFTER_WALK: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Open the parent directory of `path` by a walk from `/` (J16, closes J13
/// RR-J13-20): every component is opened with `O_NOFOLLOW` through the
/// descriptor of the one before it and checked by `protected_ancestor_ok`.
/// Returns that descriptor and the file name. The path must be absolute and
/// plain (no `.` or `..`).
fn open_protected_parent(path: &Path, euid: u32) -> Result<(File, &OsStr), CasTlsError> {
    if !path.is_absolute() {
        return Err(CasTlsError::Directory);
    }
    let components = normal_components(path).ok_or(CasTlsError::Directory)?;
    let (name, directories) = components.split_last().ok_or(CasTlsError::Directory)?;
    let mut current = open_root_dir().map_err(|_| CasTlsError::Directory)?;
    let root = file_metadata(&current).map_err(|_| CasTlsError::Directory)?;
    if !protected_ancestor(&root, euid) {
        return Err(CasTlsError::Directory);
    }
    for component in directories {
        let next = open_at(&current, component, libc::O_RDONLY | libc::O_DIRECTORY, 0)
            .map_err(|_| CasTlsError::Directory)?;
        let metadata = file_metadata(&next).map_err(|_| CasTlsError::Directory)?;
        if !protected_ancestor(&metadata, euid) {
            return Err(CasTlsError::Directory);
        }
        current = next;
    }
    #[cfg(test)]
    J16_AFTER_WALK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().as_mut() {
            hook();
        }
    });
    Ok((current, name))
}

/// Read a file through a descriptor that refuses symlinks and never blocks on
/// open (a FIFO path cannot stall the caller), then check the descriptor:
/// regular file with one link, owned by this effective uid, at most 64 KiB,
/// not writable by group or others, and for a secret not readable by them
/// either. The file is opened through the descriptor of its verified parent
/// (`open_protected_parent`), so the directories checked are the ones used,
/// and the descriptor checked is the one read.
fn read_protected_file(path: &Path, secret: bool) -> Result<Vec<u8>, CasTlsError> {
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    let (parent, name) = open_protected_parent(path, euid)?;
    let file = open_at(&parent, name, libc::O_RDONLY | libc::O_NONBLOCK, 0)
        .map_err(|_| CasTlsError::File)?;
    let metadata = file_metadata(&file).map_err(|_| CasTlsError::File)?;
    let forbidden = if secret { 0o077 } else { 0o022 };
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != euid
        || metadata.mode() & forbidden != 0
        || metadata.len() > MAX_PEM_BYTES
    {
        return Err(CasTlsError::File);
    }
    let mut bytes = Vec::new();
    file.take(MAX_PEM_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| CasTlsError::File)?;
    if bytes.len() as u64 > MAX_PEM_BYTES {
        return Err(CasTlsError::File);
    }
    Ok(bytes)
}

fn parse_certificates(
    pem: &[u8],
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, CasTlsError> {
    use rustls::pki_types::pem::PemObject;
    let certificates = rustls::pki_types::CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CasTlsError::Pem)?;
    if certificates.is_empty() {
        return Err(CasTlsError::Pem);
    }
    Ok(certificates)
}

/// A certificate chain and its private key. There is deliberately no `Debug`
/// derive and no accessor for the key: the key only leaves this type into a
/// rustls configuration.
pub struct CasTlsIdentity {
    chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
}

impl std::fmt::Debug for CasTlsIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CasTlsIdentity")
            .field("chain_len", &self.chain.len())
            .field("key", &"<redacted>")
            .finish()
    }
}

impl CasTlsIdentity {
    /// Load a PEM chain (leaf first) and a PEM private key. The key file must
    /// be private to this uid (mode `0600` or stricter).
    pub fn load(chain: &Path, key: &Path) -> Result<Self, CasTlsError> {
        let chain_pem = read_protected_file(chain, false)?;
        let key_pem = read_protected_file(key, true)?;
        Self::from_pem(&chain_pem, &key_pem)
    }

    fn from_pem(chain_pem: &[u8], key_pem: &[u8]) -> Result<Self, CasTlsError> {
        use rustls::pki_types::pem::PemObject;
        let chain = parse_certificates(chain_pem)?;
        let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(key_pem)
            .map_err(|_| CasTlsError::Pem)?;
        Ok(Self { chain, key })
    }
}

/// Load trust anchors (the private CA bundle). Several CAs may be present
/// during a rotation.
pub fn cas_load_roots(path: &Path) -> Result<rustls::RootCertStore, CasTlsError> {
    let pem = read_protected_file(path, false)?;
    let mut roots = rustls::RootCertStore::empty();
    for certificate in parse_certificates(&pem)? {
        roots.add(certificate).map_err(|_| CasTlsError::Pem)?;
    }
    Ok(roots)
}

/// Load certificate revocation lists (one PEM file may hold several).
pub fn cas_load_crls(
    path: &Path,
) -> Result<Vec<rustls::pki_types::CertificateRevocationListDer<'static>>, CasTlsError> {
    use rustls::pki_types::pem::PemObject;
    let pem = read_protected_file(path, false)?;
    let crls = rustls::pki_types::CertificateRevocationListDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CasTlsError::Pem)?;
    if crls.is_empty() {
        return Err(CasTlsError::Pem);
    }
    Ok(crls)
}

/// Client configuration: TLS 1.3 only, server verified against `roots` and
/// revocation-checked against `crls` (required, non-empty; a server whose
/// issuer has no CRL here, or whose CRL is past its nextUpdate, is refused),
/// client certificate presented, ALPN fixed, no resumption, no early data.
pub fn cas_client_tls_config(
    roots: rustls::RootCertStore,
    crls: Vec<rustls::pki_types::CertificateRevocationListDer<'static>>,
    identity: CasTlsIdentity,
) -> Result<Arc<rustls::ClientConfig>, CasTlsError> {
    // rustls skips revocation checking entirely when given no CRL; refuse that.
    if crls.is_empty() {
        return Err(CasTlsError::Config);
    }
    let provider = cas_crypto_provider();
    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::clone(&provider),
    )
    .with_crls(crls)
    .enforce_revocation_expiration()
    .build()
    .map_err(|_| CasTlsError::Config)?;
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| CasTlsError::Config)?
        .with_webpki_verifier(verifier)
        .with_client_auth_cert(identity.chain, identity.key)
        .map_err(|_| CasTlsError::Config)?;
    config.alpn_protocols = vec![CAS_TLS_ALPN.to_vec()];
    config.resumption = rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    Ok(Arc::new(config))
}

/// Server configuration: TLS 1.3 only, a client certificate chaining to
/// `client_roots` is mandatory, revocation checked against `crls` (required,
/// non-empty; a client whose issuer has no CRL here is refused, and so is one
/// whose CRL is past its nextUpdate), ALPN fixed, no session tickets, no
/// session cache, no early data.
pub fn cas_server_tls_config(
    client_roots: rustls::RootCertStore,
    crls: Vec<rustls::pki_types::CertificateRevocationListDer<'static>>,
    identity: CasTlsIdentity,
) -> Result<Arc<rustls::ServerConfig>, CasTlsError> {
    // rustls skips revocation checking entirely when given no CRL; refuse that.
    if crls.is_empty() {
        return Err(CasTlsError::Config);
    }
    let provider = cas_crypto_provider();
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(client_roots),
        Arc::clone(&provider),
    )
    .with_crls(crls)
    .enforce_revocation_expiration()
    .build()
    .map_err(|_| CasTlsError::Config)?;
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| CasTlsError::Config)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(identity.chain, identity.key)
        .map_err(|_| CasTlsError::Config)?;
    config.alpn_protocols = vec![CAS_TLS_ALPN.to_vec()];
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    Ok(Arc::new(config))
}

fn valid_principal(value: &str) -> bool {
    value.len() <= MAX_PRINCIPAL_BYTES
        && value.len() > CAS_PRINCIPAL_PREFIX.len()
        && value.starts_with(CAS_PRINCIPAL_PREFIX)
        && value[CAS_PRINCIPAL_PREFIX.len()..]
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-._/".contains(&b))
}

/// The principal named by a certificate that rustls has already verified: the
/// certificate must carry exactly one URI SAN, and it must be a well-formed
/// `mikagami-cas://` name. Anything else names no principal.
pub fn cas_principal_of(certificate: &rustls::pki_types::CertificateDer<'_>) -> Option<String> {
    let certificate = webpki::EndEntityCert::try_from(certificate).ok()?;
    let mut uris = certificate.valid_uri_names();
    let uri = uris.next()?;
    if uris.next().is_some() || !valid_principal(uri) {
        return None;
    }
    Some(uri.to_string())
}

/// What an authorization grant may do. `Read` also covers `Inquire`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CasOp {
    Read,
    Session,
    Advance,
}

impl CasOp {
    fn of(request: &CasV2Request) -> Self {
        match request {
            CasV2Request::Read { .. } | CasV2Request::Inquire { .. } => Self::Read,
            CasV2Request::BeginSession { .. } => Self::Session,
            CasV2Request::Advance { .. } => Self::Advance,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CasAclFile {
    grant: Vec<CasAclGrant>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CasAclGrant {
    principal: String,
    identity: AnchorIdentity,
    ops: Vec<CasOp>,
}

/// Server-side authorization, separate from TLS authentication: a verified
/// certificate names a principal, and only an explicit grant for that
/// principal and that identity permits an operation.
#[derive(Debug)]
pub struct CasAcl {
    grants: std::collections::BTreeMap<(String, String), std::collections::BTreeSet<CasOp>>,
}

impl CasAcl {
    /// Parse and check the policy. Refused (the server must not start):
    /// malformed principals or identities, empty or repeated op lists, a
    /// repeated (principal, identity) pair, `session` without `advance` or the
    /// reverse, and more than one principal holding `advance` for one
    /// identity.
    pub fn from_toml(text: &str) -> Result<Self, CasTlsError> {
        let file: CasAclFile = toml::from_str(text).map_err(|_| CasTlsError::Acl)?;
        let mut grants = std::collections::BTreeMap::new();
        let mut writers = std::collections::BTreeMap::new();
        for grant in file.grant {
            if !valid_principal(&grant.principal) || !valid_hex64(grant.identity.as_str()) {
                return Err(CasTlsError::Acl);
            }
            let ops: std::collections::BTreeSet<CasOp> = grant.ops.iter().copied().collect();
            if ops.is_empty() || ops.len() != grant.ops.len() {
                return Err(CasTlsError::Acl);
            }
            if ops.contains(&CasOp::Session) != ops.contains(&CasOp::Advance) {
                return Err(CasTlsError::Acl);
            }
            if ops.contains(&CasOp::Advance)
                && writers
                    .insert(grant.identity.as_str().to_string(), grant.principal.clone())
                    .is_some()
            {
                return Err(CasTlsError::Acl);
            }
            let key = (grant.principal, grant.identity.as_str().to_string());
            if grants.insert(key, ops).is_some() {
                return Err(CasTlsError::Acl);
            }
        }
        Ok(Self { grants })
    }

    /// `Ok` only if `principal` holds the operation of `request` on the
    /// request's identity.
    pub fn authorize(&self, principal: &str, request: &CasV2Request) -> Result<(), CasV2Reject> {
        let key = (
            principal.to_string(),
            request.identity().as_str().to_string(),
        );
        match self.grants.get(&key) {
            Some(ops) if ops.contains(&CasOp::of(request)) => Ok(()),
            _ => Err(CasV2Reject::Forbidden),
        }
    }
}

fn write_frame(writer: &mut impl Write, payload: &[u8]) -> std::io::Result<()> {
    let length = u32::try_from(payload.len())
        .ok()
        .filter(|length| *length as usize <= MAX_CAS_MESSAGE_BYTES)
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(payload);
    writer.write_all(&frame)?;
    writer.flush()
}

fn read_frame(reader: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let mut header = [0u8; 4];
    reader.read_exact(&mut header)?;
    let length = u32::from_be_bytes(header) as usize;
    if length > MAX_CAS_MESSAGE_BYTES {
        // A kind of its own, so that the server can tell an oversized frame
        // from a TLS protocol error (which rustls reports as InvalidData).
        return Err(std::io::Error::from(std::io::ErrorKind::FileTooLarge));
    }
    let mut payload = vec![0u8; length];
    reader.read_exact(&mut payload)?;
    Ok(payload)
}

/// Protocol v2 over TLS: one TCP connection and one TLS session per request.
pub struct TlsTransport {
    address: std::net::SocketAddr,
    server_name: rustls::pki_types::ServerName<'static>,
    config: Arc<rustls::ClientConfig>,
    connect_timeout: Duration,
    io_timeout: Duration,
}

impl std::fmt::Debug for TlsTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsTransport")
            .field("address", &self.address)
            .field("server_name", &self.server_name)
            .field("connect_timeout", &self.connect_timeout)
            .field("io_timeout", &self.io_timeout)
            .finish_non_exhaustive()
    }
}

impl TlsTransport {
    /// `server_name` is the DNS SAN the CAS server certificate must carry.
    pub fn new(
        address: std::net::SocketAddr,
        server_name: &str,
        config: Arc<rustls::ClientConfig>,
        connect_timeout: Duration,
        io_timeout: Duration,
    ) -> Result<Self, CasTlsError> {
        let server_name = rustls::pki_types::ServerName::try_from(server_name.to_string())
            .map_err(|_| CasTlsError::Config)?;
        if !matches!(server_name, rustls::pki_types::ServerName::DnsName(_)) {
            return Err(CasTlsError::Config);
        }
        Ok(Self {
            address,
            server_name,
            config,
            connect_timeout,
            io_timeout,
        })
    }
}

/// A handshake error carrying a rustls error is an authentication or
/// negotiation refusal; any other is a transport failure. Both happen before
/// a request byte is written.
fn handshake_error(error: &std::io::Error) -> TransportError {
    match error.get_ref() {
        Some(inner) if inner.downcast_ref::<rustls::Error>().is_some() => {
            TransportError::AuthFailure
        }
        _ => TransportError::NotSent,
    }
}

impl CasTransport for TlsTransport {
    fn exchange(&self, request: &[u8]) -> Result<Vec<u8>, TransportError> {
        if request.len() > MAX_CAS_MESSAGE_BYTES {
            return Err(TransportError::NotSent);
        }
        let mut tcp = std::net::TcpStream::connect_timeout(&self.address, self.connect_timeout)
            .map_err(|_| TransportError::NotSent)?;
        tcp.set_read_timeout(Some(self.io_timeout))
            .and_then(|()| tcp.set_write_timeout(Some(self.io_timeout)))
            .and_then(|()| tcp.set_nodelay(true))
            .map_err(|_| TransportError::NotSent)?;
        let mut connection =
            rustls::ClientConnection::new(Arc::clone(&self.config), self.server_name.clone())
                .map_err(|_| TransportError::NotSent)?;
        // Handshake only: no request byte has been handed to rustls yet.
        while connection.is_handshaking() {
            connection
                .complete_io(&mut tcp)
                .map_err(|error| handshake_error(&error))?;
        }
        if connection.alpn_protocol() != Some(CAS_TLS_ALPN)
            || connection.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
        {
            return Err(TransportError::AuthFailure);
        }
        // From the first request byte on, every failure is Unknown: in TLS 1.3
        // the server may still reject our certificate after we start writing,
        // and a request that reached the server may have been processed.
        let mut stream = rustls::Stream::new(&mut connection, &mut tcp);
        write_frame(&mut stream, request).map_err(|_| TransportError::Unknown)?;
        read_frame(&mut stream).map_err(|_| TransportError::Unknown)
    }
}

/// A server socket whose every read and write is bounded by the per-call
/// timeout and, while a deadline is set, by the time left until it. rustls
/// reads the socket many times during a handshake and a frame; bounding each
/// read by the time left ends the whole sequence by the deadline, however
/// slowly the peer sends (J12 RR-J12-16).
pub struct CasDeadlineSocket {
    tcp: std::net::TcpStream,
    io_timeout: Duration,
    deadline: Option<std::time::Instant>,
}

impl CasDeadlineSocket {
    fn budget(&self) -> std::io::Result<Duration> {
        let Some(deadline) = self.deadline else {
            return Ok(self.io_timeout);
        };
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return Err(std::io::Error::from(std::io::ErrorKind::TimedOut));
        }
        Ok(left.min(self.io_timeout))
    }

    fn expired(&self) -> bool {
        self.deadline
            .is_some_and(|deadline| std::time::Instant::now() >= deadline)
    }
}

impl Read for CasDeadlineSocket {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let budget = self.budget()?;
        self.tcp.set_read_timeout(Some(budget))?;
        self.tcp.read(buf)
    }
}

impl Write for CasDeadlineSocket {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let budget = self.budget()?;
        self.tcp.set_write_timeout(Some(budget))?;
        self.tcp.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.tcp.flush()
    }
}

/// A TLS connection whose handshake completed and whose peer names a
/// principal. Produced only by [`cas_tls_accept`] and [`cas_tls_accept_until`].
pub struct CasTlsSession {
    stream: rustls::StreamOwned<rustls::ServerConnection, CasDeadlineSocket>,
    principal: String,
}

impl CasTlsSession {
    pub fn principal(&self) -> &str {
        &self.principal
    }
}

/// Why a connection did not produce a request for the CAS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CasServeOutcome {
    /// The handshake failed: no or untrusted client certificate, revoked or
    /// expired certificate, wrong TLS version, I/O failure.
    HandshakeFailed,
    /// Handshake completed without the required ALPN or TLS version.
    ProtocolMismatch,
    /// The verified client certificate names no valid principal.
    NoPrincipal,
    /// No complete request frame arrived.
    NoRequest,
    /// The frame header announced more than the request size limit; the
    /// body was not read.
    Oversized,
    /// The handshake and the request frame did not complete by the deadline.
    Deadline,
    /// Answered with a rejection before reaching the CAS.
    Refused(CasV2Reject),
    /// Handed to the CAS; `responded` is false if the CAS gave no reply or the
    /// reply could not be written.
    Forwarded { principal: String, responded: bool },
}

/// Complete the server side of the handshake and identify the principal. A
/// connection that fails here never reaches request decoding.
pub fn cas_tls_accept(
    tcp: std::net::TcpStream,
    config: Arc<rustls::ServerConfig>,
    io_timeout: Duration,
) -> Result<CasTlsSession, CasServeOutcome> {
    cas_tls_accept_until(tcp, config, io_timeout, None)
}

/// [`cas_tls_accept`] with an overall deadline that also bounds the request
/// frame read by [`CasTlsSession::read_request`].
pub fn cas_tls_accept_until(
    tcp: std::net::TcpStream,
    config: Arc<rustls::ServerConfig>,
    io_timeout: Duration,
    deadline: Option<std::time::Instant>,
) -> Result<CasTlsSession, CasServeOutcome> {
    let connection =
        rustls::ServerConnection::new(config).map_err(|_| CasServeOutcome::HandshakeFailed)?;
    let socket = CasDeadlineSocket {
        tcp,
        io_timeout,
        deadline,
    };
    let mut stream = rustls::StreamOwned::new(connection, socket);
    while stream.conn.is_handshaking() {
        if let Err(_error) = stream.conn.complete_io(&mut stream.sock) {
            return Err(if stream.sock.expired() {
                CasServeOutcome::Deadline
            } else {
                CasServeOutcome::HandshakeFailed
            });
        }
    }
    if stream.conn.alpn_protocol() != Some(CAS_TLS_ALPN)
        || stream.conn.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
    {
        return Err(CasServeOutcome::ProtocolMismatch);
    }
    let principal = stream
        .conn
        .peer_certificates()
        .and_then(|chain| chain.first())
        .and_then(cas_principal_of)
        .ok_or(CasServeOutcome::NoPrincipal)?;
    Ok(CasTlsSession { stream, principal })
}

impl CasTlsSession {
    /// Read one request frame (the caller may stop after this).
    pub fn read_request(&mut self) -> Result<Vec<u8>, CasServeOutcome> {
        read_frame(&mut self.stream).map_err(|error| {
            if self.stream.sock.expired() {
                CasServeOutcome::Deadline
            } else if error.kind() == std::io::ErrorKind::FileTooLarge {
                CasServeOutcome::Oversized
            } else {
                CasServeOutcome::NoRequest
            }
        })
    }

    fn reply(&mut self, payload: &[u8]) -> bool {
        // The deadline bounds the request; the reply has its own timeout.
        self.stream.sock.deadline = None;
        let written = write_frame(&mut self.stream, payload).is_ok();
        self.stream.conn.send_close_notify();
        let _ = self.stream.flush();
        written
    }

    fn refuse(&mut self, request_id: String, reason: CasV2Reject) -> CasServeOutcome {
        if let Ok(bytes) = serde_json::to_vec(&CasV2Response::Rejected {
            v: CAS_PROTOCOL_VERSION,
            request_id,
            reason,
        }) {
            self.reply(&bytes);
        }
        CasServeOutcome::Refused(reason)
    }

    /// Decode, check the version and authorize `request`. A refusal is
    /// answered here; only an authorized, decoded value is returned.
    fn admit(&mut self, request: &[u8], acl: &CasAcl) -> Result<CasV2Request, CasServeOutcome> {
        let decoded = match cas_v2_decode_request(request) {
            Ok(decoded) => decoded,
            Err((request_id, reason)) => return Err(self.refuse(request_id, reason)),
        };
        if let Err(reason) = acl.authorize(&self.principal, &decoded) {
            return Err(self.refuse(decoded.request_id().to_string(), reason));
        }
        Ok(decoded)
    }

    /// Decode, check the version and authorize `request`; only then hand the
    /// re-encoded, authorized request to `cas`. A refusal is answered here and
    /// never reaches the CAS.
    pub fn serve(
        &mut self,
        request: &[u8],
        acl: &CasAcl,
        cas: &dyn Fn(&[u8]) -> Option<Vec<u8>>,
    ) -> CasServeOutcome {
        let decoded = match self.admit(request, acl) {
            Ok(decoded) => decoded,
            Err(outcome) => return outcome,
        };
        // Re-encode the decoded value, so the CAS acts on exactly what was
        // authorized and never re-parses the client's bytes.
        let Ok(authorized) = serde_json::to_vec(&decoded) else {
            return self.refuse(
                decoded.request_id().to_string(),
                CasV2Reject::InvalidRequest,
            );
        };
        let responded = match cas(&authorized) {
            Some(reply) => self.reply(&reply),
            None => false,
        };
        CasServeOutcome::Forwarded {
            principal: self.principal.clone(),
            responded,
        }
    }
}

// J13-BEGIN: Phase 1-J13 durable network CAS server. Prototype only: like the
// rest of this module it is compiled only through the integration-test shim,
// so none of it is linked into the mikagami binary, and nothing here starts a
// thread or reads the environment. The caller supplies the threads (see
// `CasNetworkServer::serve`). Normative description:
// prototype/v0.7/phase1-journal/j13/DURABILITY_CONTRACT.md, NETWORK_SERVER.md
// and FILESYSTEM_SAFETY.md.

/// The only production location of the CAS store. Like the journal anchor it
/// is created by an administrator (owner: the CAS service uid, mode 0700,
/// every ancestor root-owned and not group or world writable).
pub const CAS_SYSTEM_STORE_PATH: &str = "/var/lib/mikagami-cas/store";

const CAS_REGISTRY_FILE: &str = "cas-store.json";
const CAS_STATE_PREFIX: &str = "state-";
const CAS_STATE_SUFFIX: &str = ".json";
const CAS_TEMP_MARKER: &str = ".tmp-";
const CAS_REGISTRY_SCHEMA: u32 = 1;
const CAS_STATE_SCHEMA: u32 = 2;
const MAX_CAS_IDENTITIES: usize = 256;
const MAX_CAS_REGISTRY_BYTES: u64 = 65_536;

/// Why the store cannot be created, provisioned or opened, or why it stopped.
/// Carries no file contents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CasStoreError {
    /// The store directory, or a file in it, is not owned and protected as
    /// required, is a symlink or a hard link, is not a regular file, lies on
    /// another device, or no longer is the inode that was opened.
    Untrusted,
    /// Another instance (or an administrative operation) holds the store.
    Locked,
    /// The registry, or the state of a registered identity, is missing. This
    /// is never treated as a genesis.
    Missing,
    /// Format, schema, checksum or internal consistency check failed.
    Corrupt,
    /// The directory holds a name that the registry does not account for.
    Unexpected,
    /// The store or the identity already exists.
    Exists,
    /// An I/O operation failed.
    Io,
    /// A durable write failed earlier; this instance serves nothing more.
    Halted,
}

/// One remembered Advance. `resulting_digest` lets a replay return the
/// original result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CasLedgerEntry {
    pub request_id: String,
    pub body_hash: String,
    pub resulting_revision: u64,
    pub resulting_digest: String,
}

/// Everything durable about one identity. One file, replaced by one rename.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CasDurableState {
    pub state: AnchorState,
    pub fence: u64,
    pub ledger: std::collections::VecDeque<CasLedgerEntry>,
}

#[derive(Serialize)]
struct CasStateBody<'a> {
    schema: u32,
    identity: &'a AnchorIdentity,
    revision: u64,
    digest: &'a str,
    fence: u64,
    ledger: &'a std::collections::VecDeque<CasLedgerEntry>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CasStateDocument {
    schema: u32,
    identity: AnchorIdentity,
    revision: u64,
    digest: String,
    fence: u64,
    ledger: std::collections::VecDeque<CasLedgerEntry>,
    checksum: String,
}

#[derive(Serialize)]
struct CasRegistryBody<'a> {
    schema: u32,
    identities: &'a [AnchorIdentity],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CasRegistryDocument {
    schema: u32,
    identities: Vec<AnchorIdentity>,
    checksum: String,
}

fn cas_state_checksum(durable: &CasDurableState) -> Result<String, ()> {
    let data = serde_json::to_vec(&CasStateBody {
        schema: CAS_STATE_SCHEMA,
        identity: &durable.state.identity,
        revision: durable.state.revision,
        digest: &durable.state.digest,
        fence: durable.fence,
        ledger: &durable.ledger,
    })
    .map_err(|_| ())?;
    Ok(format!("{:x}", Sha256::digest(&data)))
}

fn cas_registry_checksum(identities: &[AnchorIdentity]) -> Result<String, ()> {
    let data = serde_json::to_vec(&CasRegistryBody {
        schema: CAS_REGISTRY_SCHEMA,
        identities,
    })
    .map_err(|_| ())?;
    Ok(format!("{:x}", Sha256::digest(&data)))
}

/// Internal consistency of a state, beyond its checksum: the ledger is the
/// tail of the Advance history, so it is empty exactly at revision 0 and
/// otherwise ends at the current revision with consecutive revisions.
fn valid_durable(durable: &CasDurableState) -> bool {
    let state = &durable.state;
    if !valid_hex64(state.identity.as_str())
        || !valid_anchor_state(state)
        || durable.ledger.len() > CAS_LEDGER_CAPACITY
        || durable.ledger.is_empty() != (state.revision == 0)
    {
        return false;
    }
    let mut ids = std::collections::BTreeSet::new();
    let Some(first) = state
        .revision
        .checked_add(1)
        .and_then(|next| next.checked_sub(durable.ledger.len() as u64))
    else {
        return false;
    };
    for (index, entry) in durable.ledger.iter().enumerate() {
        if !valid_request_id(&entry.request_id)
            || !ids.insert(entry.request_id.as_str())
            || !valid_hex64(&entry.body_hash)
            || !valid_hex64(&entry.resulting_digest)
            || entry.resulting_digest == ANCHOR_GENESIS_DIGEST
            || entry.resulting_revision != first + index as u64
        {
            return false;
        }
    }
    durable
        .ledger
        .back()
        .is_none_or(|last| last.resulting_digest == state.digest)
}

fn encode_cas_state(durable: &CasDurableState) -> Result<Vec<u8>, ()> {
    if !valid_durable(durable) {
        return Err(());
    }
    let bytes = serde_json::to_vec(&CasStateDocument {
        schema: CAS_STATE_SCHEMA,
        identity: durable.state.identity.clone(),
        revision: durable.state.revision,
        digest: durable.state.digest.clone(),
        fence: durable.fence,
        ledger: durable.ledger.clone(),
        checksum: cas_state_checksum(durable)?,
    })
    .map_err(|_| ())?;
    if bytes.len() as u64 > MAX_CAS_STATE_BYTES {
        return Err(());
    }
    Ok(bytes)
}

fn decode_cas_state(bytes: &[u8]) -> Result<CasDurableState, CasStoreError> {
    let document: CasStateDocument =
        serde_json::from_slice(bytes).map_err(|_| CasStoreError::Corrupt)?;
    if document.schema != CAS_STATE_SCHEMA {
        return Err(CasStoreError::Corrupt);
    }
    let durable = CasDurableState {
        state: AnchorState {
            identity: document.identity,
            revision: document.revision,
            digest: document.digest,
        },
        fence: document.fence,
        ledger: document.ledger,
    };
    if !valid_durable(&durable)
        || cas_state_checksum(&durable).map_err(|_| CasStoreError::Corrupt)? != document.checksum
    {
        return Err(CasStoreError::Corrupt);
    }
    Ok(durable)
}

fn encode_cas_registry(identities: &[AnchorIdentity]) -> Result<Vec<u8>, ()> {
    serde_json::to_vec(&CasRegistryDocument {
        schema: CAS_REGISTRY_SCHEMA,
        identities: identities.to_vec(),
        checksum: cas_registry_checksum(identities)?,
    })
    .map_err(|_| ())
}

fn decode_cas_registry(bytes: &[u8]) -> Result<Vec<AnchorIdentity>, CasStoreError> {
    let document: CasRegistryDocument =
        serde_json::from_slice(bytes).map_err(|_| CasStoreError::Corrupt)?;
    let sorted = document
        .identities
        .windows(2)
        .all(|pair| pair[0].as_str() < pair[1].as_str());
    if document.schema != CAS_REGISTRY_SCHEMA
        || document.identities.len() > MAX_CAS_IDENTITIES
        || !sorted
        || !document
            .identities
            .iter()
            .all(|identity| valid_hex64(identity.as_str()))
        || cas_registry_checksum(&document.identities).map_err(|_| CasStoreError::Corrupt)?
            != document.checksum
    {
        return Err(CasStoreError::Corrupt);
    }
    Ok(document.identities)
}

fn cas_state_name(identity: &AnchorIdentity) -> String {
    format!("{CAS_STATE_PREFIX}{}{CAS_STATE_SUFFIX}", identity.as_str())
}

/// Names in a directory, read through the descriptor itself (never through
/// the path), without `.` and `..`.
fn list_directory(dir: &File) -> Result<Vec<String>, ()> {
    #[cfg(target_os = "linux")]
    fn errno() -> *mut libc::c_int {
        // SAFETY: returns the calling thread's errno slot.
        unsafe { libc::__errno_location() }
    }
    #[cfg(target_os = "macos")]
    fn errno() -> *mut libc::c_int {
        // SAFETY: returns the calling thread's errno slot.
        unsafe { libc::__error() }
    }
    // SAFETY: F_DUPFD_CLOEXEC has no preconditions; the new descriptor is
    // close-on-exec, owned by the directory stream from here on and closed by
    // closedir.
    let fd = unsafe { libc::fcntl(dir.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if fd < 0 {
        return Err(());
    }
    // SAFETY: `fd` is a valid descriptor that this function owns.
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        // SAFETY: fdopendir failed, so `fd` is still ours to close.
        unsafe { libc::close(fd) };
        return Err(());
    }
    // The duplicate shares the file offset with `dir`; start from the top.
    // SAFETY: `stream` is a valid, open directory stream.
    unsafe { libc::rewinddir(stream) };
    let mut names = Vec::new();
    let result = loop {
        // SAFETY: errno is thread-local; clearing it lets a null return be
        // classified as end of stream or error.
        unsafe { *errno() = 0 };
        // SAFETY: `stream` is a valid, open directory stream.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            // SAFETY: errno is thread-local.
            break if unsafe { *errno() } == 0 {
                Ok(())
            } else {
                Err(())
            };
        }
        // SAFETY: readdir returned a valid entry whose name is NUL-terminated.
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
        match name.to_str() {
            Ok(".") | Ok("..") => {}
            Ok(name) => names.push(name.to_string()),
            Err(_) => break Err(()),
        }
    };
    // SAFETY: `stream` is valid and not used after this call.
    unsafe { libc::closedir(stream) };
    result.map(|()| names)
}

fn cas_rename(dir: &File, from: &str, to: &str) -> Result<(), ()> {
    let from = CString::new(from).map_err(|_| ())?;
    let to = CString::new(to).map_err(|_| ())?;
    loop {
        // SAFETY: both names are NUL-terminated; `dir` is an open directory.
        if unsafe { libc::renameat(dir.as_raw_fd(), from.as_ptr(), dir.as_raw_fd(), to.as_ptr()) }
            == 0
        {
            return Ok(());
        }
        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return Err(());
        }
    }
}

fn cas_link(dir: &File, from: &str, to: &str) -> Result<(), ()> {
    let from = CString::new(from).map_err(|_| ())?;
    let to = CString::new(to).map_err(|_| ())?;
    loop {
        // SAFETY: both names are NUL-terminated; `dir` is an open directory.
        if unsafe {
            libc::linkat(
                dir.as_raw_fd(),
                from.as_ptr(),
                dir.as_raw_fd(),
                to.as_ptr(),
                0,
            )
        } == 0
        {
            return Ok(());
        }
        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return Err(());
        }
    }
}

fn cas_unlink(dir: &File, name: &str) -> Result<(), ()> {
    let name = CString::new(name).map_err(|_| ())?;
    loop {
        // SAFETY: `name` is NUL-terminated; `dir` is an open directory.
        if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } == 0 {
            return Ok(());
        }
        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return Err(());
        }
    }
}

/// The steps of one durable write, in order. Test builds can inject a
/// failure, a process kill or a pause at each of them; production builds
/// ignore them (`CasStore::hook`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CasStorePoint {
    /// A request is about to take its identity lock.
    BeforeLock,
    /// A request found its identity lock held and is about to wait.
    Contended,
    /// All checks passed; the durable write is about to start.
    BeforeCommit,
    /// The temporary file exists and holds the complete new state.
    TempWritten,
    /// About to fsync the temporary file.
    BeforeFileSync,
    /// About to rename the temporary file over the state file.
    BeforeRename,
    /// Renamed; about to fsync the directory.
    BeforeDirSync,
    /// The write is durable; memory is updated and nothing is sent yet.
    Committed,
}

fn cas_op_name(request: &CasV2Request) -> &'static str {
    match request {
        CasV2Request::Read { .. } => "Read",
        CasV2Request::BeginSession { .. } => "BeginSession",
        CasV2Request::Advance { .. } => "Advance",
        CasV2Request::Inquire { .. } => "Inquire",
    }
}

struct CasSlot {
    durable: CasDurableState,
    /// The descriptor of the current state file: the one read at open, then
    /// the one written by the last successful commit. Its inode is what the
    /// path must still name before the next rename.
    file: File,
    metadata: fs::Metadata,
}

/// Durable CAS state for a fixed set of identities in one trusted directory.
/// An open store holds an exclusive lock on the directory inode, so a second
/// instance, or an administrative operation, cannot run at the same time.
pub struct CasStore {
    root: TrustedAnchor,
    _lock: File,
    /// One mutex per registered identity, built at open, never lazily.
    slots: std::collections::BTreeMap<String, std::sync::Mutex<CasSlot>>,
    halted: std::sync::Mutex<bool>,
    leftover_temporaries: usize,
    #[cfg(test)]
    hooks: cas_store_hooks::Hooks,
}

impl std::fmt::Debug for CasStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CasStore")
            .field("identities", &self.slots.len())
            .field("halted", &self.halted())
            .finish_non_exhaustive()
    }
}

/// Lock the directory inode itself: a lock file could be replaced, the pinned
/// directory cannot without `TrustedAnchor::verify` failing.
fn cas_lock_store(root: &TrustedAnchor) -> Result<File, CasStoreError> {
    root.verify().map_err(|()| CasStoreError::Untrusted)?;
    let lock = open_at(
        &root.fd,
        OsStr::new("."),
        libc::O_RDONLY | libc::O_DIRECTORY,
        0,
    )
    .map_err(|_| CasStoreError::Io)?;
    let lock_metadata = file_metadata(&lock).map_err(|()| CasStoreError::Io)?;
    let root_metadata = file_metadata(&root.fd).map_err(|()| CasStoreError::Io)?;
    if !same_inode(&lock_metadata, &root_metadata) {
        return Err(CasStoreError::Untrusted);
    }
    lock_exclusive(&lock).map_err(|()| CasStoreError::Locked)?;
    root.verify().map_err(|()| CasStoreError::Untrusted)?;
    Ok(lock)
}

/// Open a file of the store for reading and check it: regular, one link,
/// owned by the service uid, private, on the store's device, not too large.
fn cas_open_member(
    root: &TrustedAnchor,
    name: &str,
    limit: u64,
) -> Result<(File, fs::Metadata, Vec<u8>), CasStoreError> {
    let file = match open_at(
        &root.fd,
        OsStr::new(name),
        libc::O_RDONLY | libc::O_NONBLOCK,
        0,
    ) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(CasStoreError::Missing);
        }
        Err(_) => return Err(CasStoreError::Untrusted),
    };
    let metadata = file_metadata(&file).map_err(|()| CasStoreError::Io)?;
    if !trusted(&metadata, false, root.service_uid) || metadata.dev() != root.dev {
        return Err(CasStoreError::Untrusted);
    }
    if metadata.len() > limit {
        return Err(CasStoreError::Corrupt);
    }
    let mut bytes = Vec::new();
    (&file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| CasStoreError::Io)?;
    if bytes.len() as u64 > limit {
        return Err(CasStoreError::Corrupt);
    }
    Ok((file, metadata, bytes))
}

/// temp (O_CREAT|O_EXCL, 0600) -> write -> fsync -> publish -> dir fsync.
/// `replace` is the inode the name must still be (rename), or `None` for a
/// no-replace publication (link, then unlink the temporary name). Returns the
/// written descriptor, which is the new file under `name`.
fn cas_write_member(
    root: &TrustedAnchor,
    name: &str,
    bytes: &[u8],
    replace: Option<&fs::Metadata>,
    hook: &dyn Fn(CasStorePoint) -> Result<(), ()>,
) -> Result<(File, fs::Metadata), ()> {
    root.verify()?;
    if let Some(current) = replace
        && !named_matches(&root.fd, name, current)
    {
        return Err(());
    }
    let temp = format!(
        "{name}{CAS_TEMP_MARKER}{}",
        cas_request_id().map_err(|_| ())?
    );
    let mut file = open_at(
        &root.fd,
        OsStr::new(&temp),
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )
    .map_err(|_| ())?;
    let metadata = file_metadata(&file)?;
    if !trusted(&metadata, false, root.service_uid)
        || metadata.dev() != root.dev
        || !named_matches(&root.fd, &temp, &metadata)
    {
        return Err(());
    }
    file.write_all(bytes).map_err(|_| ())?;
    hook(CasStorePoint::TempWritten)?;
    hook(CasStorePoint::BeforeFileSync)?;
    sync_file(&file)?;
    // Both names must still be what this write saw, immediately before the
    // name is switched.
    root.verify()?;
    if !named_matches(&root.fd, &temp, &metadata) {
        return Err(());
    }
    if let Some(current) = replace
        && !named_matches(&root.fd, name, current)
    {
        return Err(());
    }
    hook(CasStorePoint::BeforeRename)?;
    match replace {
        Some(_) => cas_rename(&root.fd, &temp, name)?,
        None => {
            cas_link(&root.fd, &temp, name)?;
            if !named_matches(&root.fd, name, &metadata) {
                return Err(());
            }
            cas_unlink(&root.fd, &temp)?;
        }
    }
    let published = file_metadata(&file)?;
    if !named_matches(&root.fd, name, &metadata) || !trusted(&published, false, root.service_uid) {
        return Err(());
    }
    hook(CasStorePoint::BeforeDirSync)?;
    sync_file(&root.fd)?;
    Ok((file, published))
}

impl CasStore {
    /// Create an empty store (registry with no identity) in the fixed
    /// production directory. Administrative and local only: no network
    /// operation reaches this.
    pub fn create_system() -> Result<(), CasStoreError> {
        Self::create_in(Self::system_root()?)
    }

    /// Add one new identity at genesis (revision 0, fence 0) and return it.
    /// The identity is drawn from the operating system's CSPRNG here, never
    /// chosen by the caller (J10 CAS-12). Administrative and local only.
    /// Refused while a server holds the store.
    pub fn provision_new_system() -> Result<AnchorIdentity, CasStoreError> {
        Self::provision_new_in(Self::system_root()?)
    }

    fn provision_new_in(root: TrustedAnchor) -> Result<AnchorIdentity, CasStoreError> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| CasStoreError::Io)?;
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let identity = AnchorIdentity::from_hex(hex).map_err(|()| CasStoreError::Io)?;
        Self::provision_in(root, &identity)?;
        Ok(identity)
    }

    /// Open the production store for serving.
    pub fn open_system() -> Result<Self, CasStoreError> {
        Self::open_in(Self::system_root()?)
    }

    fn system_root() -> Result<TrustedAnchor, CasStoreError> {
        // SAFETY: geteuid has no preconditions.
        let service_uid = unsafe { libc::geteuid() };
        TrustedAnchor::provision(
            Path::new(CAS_SYSTEM_STORE_PATH),
            service_uid,
            Boundary::AdministratorProtected,
        )
        .map_err(|()| CasStoreError::Untrusted)
    }

    #[cfg(test)]
    fn test_root(path: &Path) -> Result<TrustedAnchor, CasStoreError> {
        // SAFETY: geteuid has no preconditions.
        let service_uid = unsafe { libc::geteuid() };
        TrustedAnchor::provision(path, service_uid, Boundary::TestSameUid)
            .map_err(|()| CasStoreError::Untrusted)
    }

    #[cfg(test)]
    pub(crate) fn create_for_test(path: &Path) -> Result<(), CasStoreError> {
        Self::create_in(Self::test_root(path)?)
    }

    #[cfg(test)]
    pub(crate) fn provision_new_for_test(path: &Path) -> Result<AnchorIdentity, CasStoreError> {
        Self::provision_new_in(Self::test_root(path)?)
    }

    /// Test-only: a fixed identity, so that fixtures can name it. Refused for
    /// an identity the registry already names, even if its state is gone.
    #[cfg(test)]
    pub(crate) fn provision_for_test(
        path: &Path,
        identity: &AnchorIdentity,
    ) -> Result<(), CasStoreError> {
        Self::provision_in(Self::test_root(path)?, identity)
    }

    #[cfg(test)]
    pub(crate) fn open_for_test(path: &Path) -> Result<Self, CasStoreError> {
        Self::open_in(Self::test_root(path)?)
    }

    fn create_in(root: TrustedAnchor) -> Result<(), CasStoreError> {
        let _lock = cas_lock_store(&root)?;
        let names = list_directory(&root.fd).map_err(|()| CasStoreError::Io)?;
        if !names.is_empty() {
            return Err(CasStoreError::Exists);
        }
        let bytes = encode_cas_registry(&[]).map_err(|()| CasStoreError::Io)?;
        cas_write_member(&root, CAS_REGISTRY_FILE, &bytes, None, &|_| Ok(()))
            .map_err(|()| CasStoreError::Io)?;
        Ok(())
    }

    fn provision_in(root: TrustedAnchor, identity: &AnchorIdentity) -> Result<(), CasStoreError> {
        if !valid_hex64(identity.as_str()) {
            return Err(CasStoreError::Corrupt);
        }
        let _lock = cas_lock_store(&root)?;
        let (_, registry_metadata, bytes) =
            cas_open_member(&root, CAS_REGISTRY_FILE, MAX_CAS_REGISTRY_BYTES)?;
        let mut identities = decode_cas_registry(&bytes)?;
        let name = cas_state_name(identity);
        if identities.contains(identity) {
            return Err(CasStoreError::Exists);
        }
        if identities.len() >= MAX_CAS_IDENTITIES {
            return Err(CasStoreError::Corrupt);
        }
        match named_exists(&root.fd, &name) {
            Ok(false) => {}
            Ok(true) => return Err(CasStoreError::Exists),
            Err(()) => return Err(CasStoreError::Untrusted),
        }
        let genesis = CasDurableState {
            state: AnchorState {
                identity: identity.clone(),
                revision: 0,
                digest: ANCHOR_GENESIS_DIGEST.to_string(),
            },
            fence: 0,
            ledger: std::collections::VecDeque::new(),
        };
        let state = encode_cas_state(&genesis).map_err(|()| CasStoreError::Io)?;
        // State first, registry second: a crash in between leaves a state
        // file the registry does not name, which `open` refuses (Unexpected).
        cas_write_member(&root, &name, &state, None, &|_| Ok(()))
            .map_err(|()| CasStoreError::Io)?;
        identities.push(identity.clone());
        identities.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        let registry = encode_cas_registry(&identities).map_err(|()| CasStoreError::Io)?;
        cas_write_member(
            &root,
            CAS_REGISTRY_FILE,
            &registry,
            Some(&registry_metadata),
            &|_| Ok(()),
        )
        .map_err(|()| CasStoreError::Io)?;
        Ok(())
    }

    /// Lock, then validate every name in the directory and every registered
    /// state, then fsync each state through the descriptor it was read from,
    /// the registry and the directory, and only then serve. A missing state
    /// of a registered identity is an error, never a genesis.
    fn open_in(root: TrustedAnchor) -> Result<Self, CasStoreError> {
        let lock = cas_lock_store(&root)?;
        let (registry, _, bytes) =
            cas_open_member(&root, CAS_REGISTRY_FILE, MAX_CAS_REGISTRY_BYTES)?;
        let identities = decode_cas_registry(&bytes)?;
        let names = list_directory(&root.fd).map_err(|()| CasStoreError::Io)?;
        let expected: std::collections::BTreeSet<String> = identities
            .iter()
            .map(cas_state_name)
            .chain(std::iter::once(CAS_REGISTRY_FILE.to_string()))
            .collect();
        let mut leftover_temporaries = 0;
        for name in &names {
            if expected.contains(name) {
                continue;
            }
            // A temporary file never has authority: it was not renamed, or a
            // provisioning link was not completed. It is reported, not used
            // and not removed.
            match name.split_once(CAS_TEMP_MARKER) {
                Some((base, suffix)) if expected.contains(base) && valid_request_id(suffix) => {
                    leftover_temporaries += 1;
                }
                _ => return Err(CasStoreError::Unexpected),
            }
        }
        let mut slots = std::collections::BTreeMap::new();
        for identity in &identities {
            let (file, metadata, bytes) =
                cas_open_member(&root, &cas_state_name(identity), MAX_CAS_STATE_BYTES)?;
            let durable = decode_cas_state(&bytes)?;
            if &durable.state.identity != identity {
                return Err(CasStoreError::Corrupt);
            }
            // A rename whose directory fsync failed before a restart becomes
            // durable here, before anything read from it is reported.
            sync_file(&file).map_err(|()| CasStoreError::Io)?;
            slots.insert(
                identity.as_str().to_string(),
                std::sync::Mutex::new(CasSlot {
                    durable,
                    file,
                    metadata,
                }),
            );
        }
        sync_file(&registry).map_err(|()| CasStoreError::Io)?;
        sync_file(&root.fd).map_err(|()| CasStoreError::Io)?;
        root.verify().map_err(|()| CasStoreError::Untrusted)?;
        Ok(Self {
            root,
            _lock: lock,
            slots,
            halted: std::sync::Mutex::new(false),
            leftover_temporaries,
            #[cfg(test)]
            hooks: cas_store_hooks::Hooks::default(),
        })
    }

    pub fn identities(&self) -> Vec<AnchorIdentity> {
        self.slots
            .keys()
            .filter_map(|key| AnchorIdentity::from_hex(key.clone()).ok())
            .collect()
    }

    pub fn leftover_temporaries(&self) -> usize {
        self.leftover_temporaries
    }

    pub fn halted(&self) -> bool {
        *self
            .halted
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn halt(&self) {
        *self
            .halted
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = true;
    }

    /// The in-memory state of `identity`, which is always what the disk holds
    /// after the last successful commit. `None` once halted.
    pub fn snapshot(&self, identity: &AnchorIdentity) -> Option<CasDurableState> {
        let slot = self.lock_slot(self.slots.get(identity.as_str())?, "Snapshot")?;
        if self.halted() {
            return None;
        }
        Some(slot.durable.clone())
    }

    fn hook(&self, point: CasStorePoint, op: &'static str) -> Result<(), ()> {
        #[cfg(test)]
        let result = self.hooks.fire(point, op);
        #[cfg(not(test))]
        let result = {
            let _ = (point, op);
            Ok(())
        };
        result
    }

    /// A poisoned slot means a thread panicked inside its critical section,
    /// possibly between the rename and the in-memory update: memory may no
    /// longer match the disk. The store halts instead of using it.
    fn lock_slot<'a>(
        &self,
        slot: &'a std::sync::Mutex<CasSlot>,
        op: &'static str,
    ) -> Option<std::sync::MutexGuard<'a, CasSlot>> {
        let locked = match slot.try_lock() {
            Ok(guard) => Ok(guard),
            Err(std::sync::TryLockError::Poisoned(_)) => Err(()),
            Err(std::sync::TryLockError::WouldBlock) => {
                let _ = self.hook(CasStorePoint::Contended, op);
                slot.lock().map_err(|_| ())
            }
        };
        match locked {
            Ok(guard) => Some(guard),
            Err(()) => {
                self.halt();
                None
            }
        }
    }

    /// Durable write of `next` for the slot, then the in-memory update. Any
    /// failure halts the whole store without touching memory: the disk may
    /// hold the old or the new state, and only a fresh open may tell.
    fn commit(&self, slot: &mut CasSlot, next: CasDurableState, op: &'static str) -> Option<()> {
        let written = encode_cas_state(&next).and_then(|bytes| {
            cas_write_member(
                &self.root,
                &cas_state_name(&next.state.identity),
                &bytes,
                Some(&slot.metadata),
                &|point| self.hook(point, op),
            )
        });
        match written {
            Ok((file, metadata)) => {
                *slot = CasSlot {
                    durable: next,
                    file,
                    metadata,
                };
                if self.hook(CasStorePoint::Committed, op).is_err() {
                    // Durable, but the reply is withheld: the client sees an
                    // unknown outcome, exactly as after a lost response.
                    self.halt();
                    return None;
                }
                Some(())
            }
            Err(()) => {
                self.halt();
                None
            }
        }
    }

    /// Execute one request that has already been decoded and authorized.
    /// It takes the decoded value, never bytes, so the request executed is
    /// the request authorized. `None` means no reply: the store is halted, or
    /// a durable write failed just now.
    pub fn handle(&self, request: &CasV2Request) -> Option<CasV2Response> {
        let v = CAS_PROTOCOL_VERSION;
        let op = cas_op_name(request);
        let request_id = request.request_id().to_string();
        let rejected = |request_id: String, reason: CasV2Reject| {
            Some(CasV2Response::Rejected {
                v,
                request_id,
                reason,
            })
        };
        if self.halted() {
            return None;
        }
        let identity = request.identity();
        let Some(slot) = self.slots.get(identity.as_str()) else {
            return rejected(request_id, CasV2Reject::UnknownIdentity);
        };
        self.hook(CasStorePoint::BeforeLock, op).ok()?;
        let mut slot = self.lock_slot(slot, op)?;
        // Checked again under the lock: a write that failed while this
        // request waited has halted the store.
        if self.halted() {
            return None;
        }
        match request {
            CasV2Request::Read { .. } => Some(CasV2Response::State {
                v,
                request_id,
                state: slot.durable.state.clone(),
            }),
            CasV2Request::Inquire {
                target_request_id, ..
            } => {
                let entry = slot
                    .durable
                    .ledger
                    .iter()
                    .find(|entry| &entry.request_id == target_request_id);
                Some(CasV2Response::InquiryResult {
                    v,
                    request_id,
                    found: entry.is_some(),
                    resulting_revision: entry.map(|entry| entry.resulting_revision),
                })
            }
            CasV2Request::BeginSession { .. } => {
                let Some(fence) = slot.durable.fence.checked_add(1) else {
                    return rejected(request_id, CasV2Reject::Exhausted);
                };
                let mut next = slot.durable.clone();
                next.fence = fence;
                self.hook(CasStorePoint::BeforeCommit, op).ok()?;
                self.commit(&mut slot, next, op)?;
                Some(CasV2Response::Session {
                    v,
                    request_id,
                    state: slot.durable.state.clone(),
                    fence,
                })
            }
            CasV2Request::Advance {
                fence,
                expected,
                next_revision,
                next_digest,
                ..
            } => {
                let Ok(body_hash) =
                    cas_v2_body_hash(identity, *fence, expected, *next_revision, next_digest)
                else {
                    return rejected(request_id, CasV2Reject::InvalidRequest);
                };
                if let Some(entry) = slot
                    .durable
                    .ledger
                    .iter()
                    .find(|entry| entry.request_id == request_id)
                {
                    if entry.body_hash != body_hash {
                        return rejected(request_id, CasV2Reject::RequestIdReuse);
                    }
                    // The original result; nothing changes.
                    return Some(CasV2Response::Committed {
                        v,
                        request_id,
                        state: AnchorState {
                            identity: identity.clone(),
                            revision: entry.resulting_revision,
                            digest: entry.resulting_digest.clone(),
                        },
                        replayed: true,
                    });
                }
                // Fence 0 is the provisioned value, never a session: an
                // Advance needs a BeginSession first, even at genesis.
                if *fence == 0 || *fence != slot.durable.fence {
                    return Some(CasV2Response::Fenced {
                        v,
                        request_id,
                        current_fence: slot.durable.fence,
                    });
                }
                if !valid_hex64(next_digest)
                    || next_digest == ANCHOR_GENESIS_DIGEST
                    || &expected.identity != identity
                {
                    return rejected(request_id, CasV2Reject::InvalidRequest);
                }
                let Some(expected_next) = expected.revision.checked_add(1) else {
                    return rejected(request_id, CasV2Reject::Exhausted);
                };
                if *next_revision != expected_next {
                    return rejected(request_id, CasV2Reject::InvalidRequest);
                }
                if expected != &slot.durable.state {
                    return Some(CasV2Response::Conflict {
                        v,
                        request_id,
                        state: slot.durable.state.clone(),
                    });
                }
                let mut next = slot.durable.clone();
                next.state = AnchorState {
                    identity: identity.clone(),
                    revision: *next_revision,
                    digest: next_digest.clone(),
                };
                next.ledger.push_back(CasLedgerEntry {
                    request_id: request_id.clone(),
                    body_hash,
                    resulting_revision: *next_revision,
                    resulting_digest: next_digest.clone(),
                });
                while next.ledger.len() > CAS_LEDGER_CAPACITY {
                    next.ledger.pop_front();
                }
                self.hook(CasStorePoint::BeforeCommit, op).ok()?;
                self.commit(&mut slot, next, op)?;
                Some(CasV2Response::Committed {
                    v,
                    request_id,
                    state: slot.durable.state.clone(),
                    replayed: false,
                })
            }
        }
    }
}

/// Limits of one server instance. All are mandatory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CasServerLimits {
    /// Connections being served at once; one more is closed unanswered.
    pub max_connections: usize,
    /// From accept to a complete request frame: the TLS handshake and the
    /// frame together must finish within this, however slowly bytes arrive.
    pub handshake_deadline: Duration,
    /// Bound of each single socket read or write.
    pub io_timeout: Duration,
}

impl CasServerLimits {
    fn valid(&self) -> bool {
        let bound = Duration::from_secs(60);
        (1..=1024).contains(&self.max_connections)
            && !self.handshake_deadline.is_zero()
            && !self.io_timeout.is_zero()
            && self.handshake_deadline <= bound
            && self.io_timeout <= bound
    }
}

/// Paths of the TLS material and the ACL. Each is read through a descriptor
/// that refuses symlinks and FIFOs and checks owner, mode and size.
#[derive(Clone, Debug)]
pub struct CasServerFiles {
    pub certificate: PathBuf,
    pub key: PathBuf,
    pub client_roots: PathBuf,
    pub crls: PathBuf,
    pub acl: PathBuf,
}

/// Why a server did not start. The listener is created only after every
/// one of these checks passed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CasStartError {
    Limits,
    Tls(CasTlsError),
    /// The ACL file is unsafe, malformed, or grants on an identity the store
    /// does not hold.
    Acl,
    Bind,
}

/// How `serve` ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CasServeExit {
    Shutdown,
    /// A durable write failed. The process must exit; a restart re-reads the
    /// disk. Nothing in memory may be served again.
    Halted,
    /// The listener failed in a way that would repeat; nothing was lost.
    AcceptFailed,
}

/// Operational events. They name principals, identities, operations and
/// outcomes only; no key, certificate, request body or file content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CasEvent {
    Ready {
        identities: usize,
        leftover_temporaries: usize,
    },
    /// Closed before the handshake: at the connection limit, or not
    /// accepting any more.
    ConnectionRefused,
    Connection(CasServeOutcome),
    Authorized {
        principal: String,
        identity: String,
        op: CasOp,
    },
    Halted,
    ShutdownRequested,
    Stopped(CasServeExit),
}

impl std::fmt::Display for CasEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ready {
                identities,
                leftover_temporaries,
            } => write!(
                f,
                "cas ready identities={identities} leftover_temporaries={leftover_temporaries}"
            ),
            Self::ConnectionRefused => write!(f, "cas connection refused"),
            Self::Connection(outcome) => write!(f, "cas connection {outcome:?}"),
            Self::Authorized {
                principal,
                identity,
                op,
            } => write!(
                f,
                "cas authorized principal={principal} identity={identity} op={op:?}"
            ),
            Self::Halted => write!(f, "cas halted after a failed durable write"),
            Self::ShutdownRequested => write!(f, "cas shutdown requested"),
            Self::Stopped(exit) => write!(f, "cas stopped {exit:?}"),
        }
    }
}

struct CasAdmission {
    active: usize,
    accepting: bool,
    address: Option<std::net::SocketAddr>,
}

/// The network CAS server: TLS 1.3 with mandatory client certificates and
/// CRLs, the server-side ACL, and the durable store. Management operations
/// (create, provision) are `CasStore` functions and are not reachable from
/// the protocol.
pub struct CasNetworkServer {
    store: CasStore,
    tls: Arc<rustls::ServerConfig>,
    acl: CasAcl,
    limits: CasServerLimits,
    admission: std::sync::Mutex<CasAdmission>,
    idle: std::sync::Condvar,
    events: Arc<dyn Fn(&CasEvent) + Send + Sync>,
}

impl std::fmt::Debug for CasNetworkServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CasNetworkServer")
            .field("store", &self.store)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

/// One admitted connection, to be run on a thread the caller provides.
pub struct CasConnection {
    server: Arc<CasNetworkServer>,
    tcp: Option<std::net::TcpStream>,
}

impl Drop for CasConnection {
    fn drop(&mut self) {
        let mut admission = self.server.admission();
        admission.active -= 1;
        self.server.idle.notify_all();
    }
}

impl CasNetworkServer {
    /// Checks, in order: limits; TLS material and CRLs; the ACL file (owner,
    /// mode, no symlink) and that every grant names an identity of `store`.
    /// `store` is already locked and validated. Nothing listens yet.
    pub fn start(
        store: CasStore,
        files: &CasServerFiles,
        limits: CasServerLimits,
        events: Arc<dyn Fn(&CasEvent) + Send + Sync>,
    ) -> Result<Self, CasStartError> {
        if !limits.valid() {
            return Err(CasStartError::Limits);
        }
        let identity =
            CasTlsIdentity::load(&files.certificate, &files.key).map_err(CasStartError::Tls)?;
        let roots = cas_load_roots(&files.client_roots).map_err(CasStartError::Tls)?;
        let crls = cas_load_crls(&files.crls).map_err(CasStartError::Tls)?;
        let tls = cas_server_tls_config(roots, crls, identity).map_err(CasStartError::Tls)?;
        let text = read_protected_file(&files.acl, false).map_err(|_| CasStartError::Acl)?;
        let text = String::from_utf8(text).map_err(|_| CasStartError::Acl)?;
        let acl = CasAcl::from_toml(&text).map_err(|_| CasStartError::Acl)?;
        if !acl
            .grants
            .keys()
            .all(|(_, identity)| store.slots.contains_key(identity))
        {
            return Err(CasStartError::Acl);
        }
        let server = Self {
            tls,
            acl,
            limits,
            admission: std::sync::Mutex::new(CasAdmission {
                active: 0,
                accepting: true,
                address: None,
            }),
            idle: std::sync::Condvar::new(),
            events,
            store,
        };
        server.emit(&CasEvent::Ready {
            identities: server.store.slots.len(),
            leftover_temporaries: server.store.leftover_temporaries,
        });
        Ok(server)
    }

    pub fn store(&self) -> &CasStore {
        &self.store
    }

    /// Release the store (and its lock) after `serve` returned and every
    /// connection has finished.
    pub fn into_store(self) -> CasStore {
        self.store
    }

    fn emit(&self, event: &CasEvent) {
        (self.events)(event);
    }

    fn admission(&self) -> std::sync::MutexGuard<'_, CasAdmission> {
        self.admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Create the listener. Only possible on a server that passed `start`.
    pub fn bind(
        &self,
        address: std::net::SocketAddr,
    ) -> Result<std::net::TcpListener, CasStartError> {
        let listener = std::net::TcpListener::bind(address).map_err(|_| CasStartError::Bind)?;
        let local = listener.local_addr().map_err(|_| CasStartError::Bind)?;
        self.admission().address = Some(local);
        Ok(listener)
    }

    /// Stop accepting. Connections already admitted run to completion.
    pub fn shutdown(&self) {
        self.emit(&CasEvent::ShutdownRequested);
        self.stop_accepting();
    }

    fn stop_accepting(&self) {
        let address = {
            let mut admission = self.admission();
            admission.accepting = false;
            admission.address
        };
        // Wake a blocked accept; the woken connection is closed unanswered.
        if let Some(address) = address {
            let _ = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(1));
        }
    }

    /// Wait until no admitted connection remains, at most `limit`.
    pub fn wait_idle(&self, limit: Duration) -> bool {
        let admission = self.admission();
        let (admission, _) = self
            .idle
            .wait_timeout_while(admission, limit, |admission| admission.active > 0)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        admission.active == 0
    }

    pub fn active_connections(&self) -> usize {
        self.admission().active
    }

    /// Accept until shut down or halted. Each admitted connection is handed to
    /// `dispatch`, which runs it (normally on its own thread). A connection
    /// beyond the limit is closed before the handshake.
    pub fn serve(
        self: &Arc<Self>,
        listener: &std::net::TcpListener,
        dispatch: &mut dyn FnMut(CasConnection),
    ) -> CasServeExit {
        let exit = loop {
            let accepted = listener.accept();
            if self.store.halted() {
                break CasServeExit::Halted;
            }
            let tcp = match accepted {
                Ok((tcp, _)) => tcp,
                // One connection failed before it was accepted; others may not.
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                // Anything else (for example no descriptor left) would repeat
                // at once; stop instead of spinning.
                Err(_) => break CasServeExit::AcceptFailed,
            };
            let admitted = {
                let mut admission = self.admission();
                if !admission.accepting {
                    None
                } else if admission.active >= self.limits.max_connections {
                    Some(false)
                } else {
                    admission.active += 1;
                    Some(true)
                }
            };
            match admitted {
                None => break CasServeExit::Shutdown,
                Some(false) => {
                    self.emit(&CasEvent::ConnectionRefused);
                    drop(tcp);
                }
                Some(true) => dispatch(CasConnection {
                    server: Arc::clone(self),
                    tcp: Some(tcp),
                }),
            }
        };
        self.emit(&CasEvent::Stopped(exit));
        exit
    }
}

impl CasConnection {
    pub fn run(mut self) {
        let outcome = self.serve_once();
        self.server.emit(&CasEvent::Connection(outcome));
        if self.server.store.halted() {
            self.server.emit(&CasEvent::Halted);
            self.server.stop_accepting();
        }
    }

    fn serve_once(&mut self) -> CasServeOutcome {
        let Some(tcp) = self.tcp.take() else {
            return CasServeOutcome::HandshakeFailed;
        };
        let server = &self.server;
        let deadline = std::time::Instant::now() + server.limits.handshake_deadline;
        let mut session = match cas_tls_accept_until(
            tcp,
            Arc::clone(&server.tls),
            server.limits.io_timeout,
            Some(deadline),
        ) {
            Ok(session) => session,
            Err(outcome) => return outcome,
        };
        let request = match session.read_request() {
            Ok(request) => request,
            Err(outcome) => return outcome,
        };
        let decoded = match session.admit(&request, &server.acl) {
            Ok(decoded) => decoded,
            Err(outcome) => return outcome,
        };
        server.emit(&CasEvent::Authorized {
            principal: session.principal.clone(),
            identity: decoded.identity().as_str().to_string(),
            op: CasOp::of(&decoded),
        });
        // The store executes the authorized value itself; the request bytes
        // are not parsed a second time anywhere.
        let responded = match server.store.handle(&decoded) {
            Some(response) => match serde_json::to_vec(&response) {
                Ok(bytes) => session.reply(&bytes),
                Err(_) => false,
            },
            None => false,
        };
        CasServeOutcome::Forwarded {
            principal: session.principal.clone(),
            responded,
        }
    }
}
// J13-END

// J14-BEGIN: Phase 1-J14 recovery assessment (R-A) and repair plans (R-B,
// dry-run only). Nothing here writes the journal or the CAS state: the only
// external effect is the fenced BeginSession, which invalidates every older
// session of the identity, including that of a journal still running
// elsewhere (which then fails closed). A repair is planned and reported, never applied
// (Owner decision OD-J10-7 is pending; see `JournalStore::apply_recovery`).
// Normative description: prototype/v0.7/phase1-journal/j14/RECOVERY_CONTRACT.md
// and R0_R6_DECISION_TABLE.md.

/// The J10 R-B write-ahead intent. This code never creates it; a file of this
/// name is a format it does not implement, so it fails closed.
const INTENT_FILE: &str = "journal.intent";
const RECOVERY_PLAN_FILE: &str = "recovery-plan.json";

/// `journal.json`, as the assessment found it. `digest` is the anchor digest
/// the record would have at its own revision (J10 `d(J)`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum LocalRecord {
    Missing,
    Invalid,
    Present { revision: u64, digest: String },
}

/// `journal.anchor` (J10 `A`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum LocalCheckpoint {
    Missing,
    Invalid,
    Present { revision: u64, digest: String },
}

/// `journal.intent` (J10 `I`). The J14 observer reports only `Absent` or
/// `Unsupported`; `Present` exists so that the decision table is complete
/// for the R-B rows, which are evaluated but never acted on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum IntentObservation {
    Absent,
    Present { revision: u64, digest: String },
    Unsupported,
}

/// The fenced BeginSession of the assessment (J10 `s`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum SessionObservation {
    /// Not attempted: the local state already decides, or names another
    /// identity, so no fence is spent on it.
    NotAttempted,
    /// Durably committed and answered. Only with a fence does this mean
    /// that no request of an earlier session can commit any more.
    Established {
        revision: u64,
        digest: String,
        fence: Option<u64>,
    },
    /// The request may have been processed. Nothing may be concluded.
    Unknown,
    /// No answer that says anything: nothing was sent (unreachable, the peer
    /// failed authentication before any request byte, a local failure), or
    /// the server answered NotReady. Nothing may be concluded either.
    NotSent,
    /// The CAS refused (not authorized, corrupt, exhausted, ...).
    Refused,
}

/// `Inquire` for a request id the caller knows. Evidence only: a miss is
/// never proof that a request did not commit (the ledger keeps 64 entries).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum InquiryObservation {
    NotAsked,
    Found { resulting_revision: u64 },
    NotFound,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RecoveryObservation {
    /// The record's store identity is this store, and the checkpoint names
    /// the configured anchor identity.
    pub identity_consistent: bool,
    pub record: LocalRecord,
    pub checkpoint: LocalCheckpoint,
    /// `journal.pending` (J10 `P`).
    pub pending: bool,
    /// `journal.anchor.pending` (J10 `AP`).
    pub checkpoint_pending: bool,
    pub intent: IntentObservation,
    pub session: SessionObservation,
    /// A fence this caller held earlier. A session that does not exceed it
    /// means the CAS went back in time.
    pub previous_fence: Option<u64>,
    pub inquiry: InquiryObservation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum RecoveryRow {
    R0,
    R1,
    R2,
    R3,
    R4,
    R5,
    R6,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum RecoveryClass {
    /// R0: nothing to repair. A normal open starts its own session.
    Consistent,
    /// R1–R6: a repair is defined, but applying it needs the Owner's
    /// approval. Until then the journal stays closed.
    RepairablePendingOwnerApproval,
    /// No row applies, or the evidence contradicts itself. A person must
    /// investigate; nothing is repaired automatically.
    Unrecoverable,
    /// The CAS side could not be fixed by a session. Nothing may be
    /// concluded; assess again when the CAS is reachable.
    Undecidable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum RecoveryReason {
    Consistent,
    RowMatched,
    IdentityMismatch,
    RecordMissing,
    RecordInvalid,
    CheckpointMissing,
    CheckpointInvalid,
    CheckpointRecordMismatch,
    CheckpointAhead,
    JournalFarAhead,
    BothPendingFiles,
    PendingWithoutIntent,
    CheckpointPendingWithoutAdvance,
    PendingWithJournalAhead,
    UnsupportedIntent,
    IntentInconsistent,
    SessionUnknown,
    CasUnreachable,
    SessionRefused,
    /// The anchor reported no fence for the session: it may be a plain read,
    /// which proves nothing about older requests (J10 CAS-04, CAS-11).
    NoFence,
    FenceRegression,
    LedgerAheadOfState,
    DigestMismatch,
    CasBehind,
    CasAheadWithoutEvidence,
    CasFarAhead,
}

/// One step of a repair plan. Steps are descriptions; nothing executes them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum PlanStep {
    /// Re-check, under the journal lock and a new session, that every
    /// observation still holds; otherwise abandon the plan.
    ReverifyObservation,
    UnlinkPending,
    UnlinkCheckpointPending,
    WriteRecordFromIntent {
        revision: u64,
    },
    WriteCheckpoint {
        revision: u64,
    },
    UnlinkIntent,
    SyncDirectory,
    /// After the repair, a normal open must succeed (J = A = s).
    VerifyByOpen,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum ApprovalStatus {
    NotRequired,
    PendingOwnerApproval,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RecoveryDecision {
    pub row: Option<RecoveryRow>,
    pub class: RecoveryClass,
    pub reason: RecoveryReason,
    pub plan: Vec<PlanStep>,
    pub approval: ApprovalStatus,
}

impl RecoveryDecision {
    fn closed(class: RecoveryClass, reason: RecoveryReason) -> Self {
        Self {
            row: None,
            class,
            reason,
            plan: Vec::new(),
            approval: ApprovalStatus::NotRequired,
        }
    }

    fn row(row: RecoveryRow, steps: &[PlanStep]) -> Self {
        let mut plan = vec![PlanStep::ReverifyObservation];
        plan.extend_from_slice(steps);
        plan.extend_from_slice(&[PlanStep::SyncDirectory, PlanStep::VerifyByOpen]);
        Self {
            row: Some(row),
            class: RecoveryClass::RepairablePendingOwnerApproval,
            reason: RecoveryReason::RowMatched,
            plan,
            approval: ApprovalStatus::PendingOwnerApproval,
        }
    }

    /// Never true: recovery classifies, it authorizes nothing.
    pub fn send_authorized(&self) -> bool {
        false
    }
}

/// The J10 R0–R6 table (DURABILITY_AND_ROLLBACK.md §3.4). Every combination
/// it does not list is closed: `Unrecoverable` with the most specific reason,
/// or `Undecidable` when the CAS side is not known. Inquiry evidence can only
/// make a result more cautious, never less.
pub fn decide_recovery(observation: &RecoveryObservation) -> RecoveryDecision {
    use RecoveryClass::{Undecidable, Unrecoverable};
    use RecoveryReason as Why;
    let closed = RecoveryDecision::closed;
    if !observation.identity_consistent {
        return closed(Unrecoverable, Why::IdentityMismatch);
    }
    let (j, jd) = match &observation.record {
        LocalRecord::Present { revision, digest } => (*revision, digest.as_str()),
        LocalRecord::Missing => return closed(Unrecoverable, Why::RecordMissing),
        LocalRecord::Invalid => return closed(Unrecoverable, Why::RecordInvalid),
    };
    let (a, ad) = match &observation.checkpoint {
        LocalCheckpoint::Present { revision, digest } => (*revision, digest.as_str()),
        // J10 §3.6 CI2 (journal 1, no checkpoint) is not read as R4 here.
        LocalCheckpoint::Missing => return closed(Unrecoverable, Why::CheckpointMissing),
        LocalCheckpoint::Invalid => return closed(Unrecoverable, Why::CheckpointInvalid),
    };
    if observation.intent == IntentObservation::Unsupported {
        return closed(Unrecoverable, Why::UnsupportedIntent);
    }
    if observation.pending && observation.checkpoint_pending {
        return closed(Unrecoverable, Why::BothPendingFiles);
    }
    if a > j {
        return closed(Unrecoverable, Why::CheckpointAhead);
    }
    if j > a.saturating_add(1) {
        return closed(Unrecoverable, Why::JournalFarAhead);
    }
    if j == a && ad != jd {
        return closed(Unrecoverable, Why::CheckpointRecordMismatch);
    }
    let (s, sd, fence) = match &observation.session {
        SessionObservation::Established {
            revision,
            digest,
            fence,
        } => (*revision, digest.as_str(), *fence),
        SessionObservation::Unknown => return closed(Undecidable, Why::SessionUnknown),
        SessionObservation::NotSent => return closed(Undecidable, Why::CasUnreachable),
        // Without a session the local state alone decided nothing here.
        SessionObservation::NotAttempted => return closed(Undecidable, Why::SessionUnknown),
        SessionObservation::Refused => return closed(Unrecoverable, Why::SessionRefused),
    };
    let Some(fence) = fence else {
        return closed(Undecidable, Why::NoFence);
    };
    if let Some(previous) = observation.previous_fence
        && fence <= previous
    {
        return closed(Unrecoverable, Why::FenceRegression);
    }
    if let InquiryObservation::Found { resulting_revision } = observation.inquiry
        && resulting_revision > s
    {
        // The ledger remembers a commit beyond the state: the state went back.
        return closed(Unrecoverable, Why::LedgerAheadOfState);
    }
    // Where the CAS stands relative to the journal, for the closing reasons.
    let mismatch = |base: u64, expected_digest: &str| {
        if s < base {
            Why::CasBehind
        } else if s == base && sd != expected_digest {
            Why::DigestMismatch
        } else if s == base + 1 {
            Why::CasAheadWithoutEvidence
        } else {
            Why::CasFarAhead
        }
    };
    let p = observation.pending;
    let ap = observation.checkpoint_pending;
    if j == a {
        let n = j;
        match &observation.intent {
            IntentObservation::Absent => {
                if p {
                    return closed(Unrecoverable, Why::PendingWithoutIntent);
                }
                if ap {
                    return closed(Unrecoverable, Why::CheckpointPendingWithoutAdvance);
                }
                if s == n && sd == ad {
                    return RecoveryDecision {
                        row: Some(RecoveryRow::R0),
                        class: RecoveryClass::Consistent,
                        reason: Why::Consistent,
                        plan: Vec::new(),
                        approval: ApprovalStatus::NotRequired,
                    };
                }
                closed(Unrecoverable, mismatch(n, ad))
            }
            IntentObservation::Present {
                revision: i,
                digest: id,
            } => {
                let Some(next) = n.checked_add(1) else {
                    return closed(Unrecoverable, Why::IntentInconsistent);
                };
                if *i == next && !ap {
                    if !p && s == n && sd == ad {
                        return RecoveryDecision::row(RecoveryRow::R1, &[PlanStep::UnlinkIntent]);
                    }
                    if s == next && sd == id {
                        let mut steps = Vec::new();
                        if p {
                            steps.push(PlanStep::UnlinkPending);
                        }
                        steps.extend_from_slice(&[
                            PlanStep::WriteRecordFromIntent { revision: next },
                            PlanStep::WriteCheckpoint { revision: next },
                            PlanStep::UnlinkIntent,
                        ]);
                        let row = if p { RecoveryRow::R3 } else { RecoveryRow::R2 };
                        return RecoveryDecision::row(row, &steps);
                    }
                    if p {
                        return closed(Unrecoverable, Why::PendingWithoutIntent);
                    }
                    return closed(
                        Unrecoverable,
                        if s == next {
                            Why::DigestMismatch
                        } else {
                            mismatch(n, ad)
                        },
                    );
                }
                if *i == n && id == ad && !p && !ap && s == n && sd == ad {
                    return RecoveryDecision::row(RecoveryRow::R6, &[PlanStep::UnlinkIntent]);
                }
                closed(Unrecoverable, Why::IntentInconsistent)
            }
            IntentObservation::Unsupported => closed(Unrecoverable, Why::UnsupportedIntent),
        }
    } else {
        // j == a + 1: the record was written, the checkpoint was not.
        let next = j;
        let intent_ok = match &observation.intent {
            IntentObservation::Absent => true,
            IntentObservation::Present {
                revision: i,
                digest: id,
            } => *i == next && id == jd,
            IntentObservation::Unsupported => false,
        };
        if !intent_ok {
            return closed(Unrecoverable, Why::IntentInconsistent);
        }
        if p {
            return closed(Unrecoverable, Why::PendingWithJournalAhead);
        }
        if s == next && sd == jd {
            let mut steps = Vec::new();
            if ap {
                steps.push(PlanStep::UnlinkCheckpointPending);
            }
            steps.push(PlanStep::WriteCheckpoint { revision: next });
            if observation.intent != IntentObservation::Absent {
                steps.push(PlanStep::UnlinkIntent);
            }
            let row = if ap { RecoveryRow::R5 } else { RecoveryRow::R4 };
            return RecoveryDecision::row(row, &steps);
        }
        closed(Unrecoverable, mismatch(next, jd))
    }
}

/// `Inquire` access for the assessment (implemented by `NetworkCasAnchor`).
pub trait CasInquiry {
    fn inquire_request(&self, request_id: &str) -> Result<InquiryOutcome, AnchorError>;
}

impl CasInquiry for NetworkCasAnchor {
    fn inquire_request(&self, request_id: &str) -> Result<InquiryOutcome, AnchorError> {
        self.inquire(request_id)
    }
}

/// What the caller knows from before the assessment.
#[derive(Default)]
pub struct RecoveryContext<'a> {
    /// A fence the caller held in an earlier session of this identity.
    pub previous_fence: Option<u64>,
    /// A request id whose outcome is unknown, and how to ask about it.
    pub known_request: Option<(&'a str, &'a dyn CasInquiry)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryError {
    /// The store has no external anchor; there is nothing to compare with.
    NoExternalAnchor,
    /// The external anchor has no fenced, owned sessions (a legacy, test-only
    /// store: the J5-J10 fakes or the v1 `CasAnchor`). An assessment needs a
    /// fenced session; nothing was sent (J17).
    NoFencedAnchor,
    /// The journal could not be locked or inspected (for example, it is open
    /// elsewhere, or its namespace is not the provisioned one).
    Store,
    /// Repairs need the Owner's approval (OD-J10-7); nothing was written.
    PendingOwnerApproval,
    /// The dry-run report could not be written.
    Report,
}

/// The assessment: what was observed, what it means. Contains no secret:
/// revisions, digests, fences, file presence and the decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RecoveryReport {
    pub identity: AnchorIdentity,
    pub observation: RecoveryObservation,
    pub decision: RecoveryDecision,
}

impl RecoveryReport {
    pub fn to_json(&self) -> Result<Vec<u8>, RecoveryError> {
        serde_json::to_vec_pretty(self).map_err(|_| RecoveryError::Report)
    }
}

fn session_observation(
    result: Result<AnchorState, AnchorError>,
    configured: &AnchorIdentity,
    fence: Option<u64>,
) -> SessionObservation {
    match result {
        Ok(state) if valid_anchor_state(&state) && &state.identity == configured => {
            SessionObservation::Established {
                revision: state.revision,
                digest: state.digest,
                fence,
            }
        }
        // A reply that is not a valid state of this identity is as good as
        // none: the request was sent.
        Ok(_) => SessionObservation::Unknown,
        Err(AnchorError::Unknown | AnchorError::Protocol) => SessionObservation::Unknown,
        // Not sent, or the server answered NotReady (both map to
        // Unavailable), or nothing left this client (Internal).
        Err(
            AnchorError::Unavailable
            | AnchorError::AuthFailure
            | AnchorError::Internal
            | AnchorError::Busy,
        ) => SessionObservation::NotSent,
        Err(_) => SessionObservation::Refused,
    }
}

impl JournalStore {
    /// R-A: observe the journal under its lock, start a fenced session, and
    /// classify. Writes nothing locally. The session's fence is dropped from
    /// the client afterwards, so nothing can be sent under it; a normal open
    /// starts a session of its own.
    pub fn assess_recovery(
        &self,
        context: &RecoveryContext<'_>,
    ) -> Result<RecoveryReport, RecoveryError> {
        let external = match self.external.as_ref() {
            None => return Err(RecoveryError::NoExternalAnchor),
            Some(ExternalAnchor::Fenced(anchor)) => anchor,
            #[cfg(test)]
            Some(ExternalAnchor::Legacy(_)) => return Err(RecoveryError::NoFencedAnchor),
        };
        let held = acquire(&self.anchor, false, false, true).map_err(|()| RecoveryError::Store)?;
        let directory = &held.directory;
        let uid = self.anchor.service_uid;
        let configured = external.identity();
        let pending = pending_present(directory).map_err(|()| RecoveryError::Store)?;
        let checkpoint_pending =
            anchor_checkpoint_pending_present(directory).map_err(|()| RecoveryError::Store)?;
        let intent = match named_exists(directory, INTENT_FILE) {
            Ok(false) => IntentObservation::Absent,
            _ => IntentObservation::Unsupported,
        };
        let mut identity_consistent = true;
        let record = match named_exists(directory, JOURNAL_FILE) {
            Ok(false) => LocalRecord::Missing,
            Ok(true) => match read_record(directory, uid) {
                Ok((record, store)) => {
                    if store != held.identity || !store.anchor_required {
                        identity_consistent = false;
                    }
                    match anchor_digest(&record, &held.identity, &configured, record.revision) {
                        Ok(digest) => LocalRecord::Present {
                            revision: record.revision,
                            digest,
                        },
                        Err(()) => LocalRecord::Invalid,
                    }
                }
                Err(()) => LocalRecord::Invalid,
            },
            Err(()) => LocalRecord::Invalid,
        };
        let checkpoint = match anchor_checkpoint_present(directory) {
            Ok(false) => LocalCheckpoint::Missing,
            Ok(true) => match read_anchor_checkpoint(directory, uid) {
                Ok(meta) => {
                    if meta.identity != configured {
                        identity_consistent = false;
                    }
                    LocalCheckpoint::Present {
                        revision: meta.revision,
                        digest: meta.digest,
                    }
                }
                Err(()) => LocalCheckpoint::Invalid,
            },
            Err(()) => LocalCheckpoint::Invalid,
        };
        // A session moves the fence. It is spent only on a readable journal
        // of this identity, where it can decide something.
        let worth_a_session = identity_consistent
            && matches!(record, LocalRecord::Present { .. })
            && matches!(checkpoint, LocalCheckpoint::Present { .. })
            && intent != IntentObservation::Unsupported
            && !(pending && checkpoint_pending);
        // The lease ends the session when it is dropped, also if anything
        // below panics (J17).
        let (mut session, lease) = if worth_a_session {
            match external.begin_owned_session() {
                Ok(FencedSession {
                    state,
                    fence,
                    lease,
                    ..
                }) => (
                    session_observation(Ok(state), &configured, Some(fence)),
                    Some(lease),
                ),
                Err(error) => (session_observation(Err(error), &configured, None), None),
            }
        } else {
            (SessionObservation::NotAttempted, None)
        };
        crash_if("recovery_after_session");
        // Only after a session is an inquiry worth anything (J10 CAS-04).
        let inquiry = match (&session, context.known_request) {
            (SessionObservation::Established { .. }, Some((request_id, inquirer))) => {
                match inquirer.inquire_request(request_id) {
                    Ok(InquiryOutcome {
                        found: true,
                        resulting_revision: Some(revision),
                    }) => InquiryObservation::Found {
                        resulting_revision: revision,
                    },
                    Ok(InquiryOutcome { found: false, .. }) => InquiryObservation::NotFound,
                    _ => InquiryObservation::Failed,
                }
            }
            _ => InquiryObservation::NotAsked,
        };
        // J16: if another caller of this client replaced or ended the session
        // during the assessment, the observation may be stale; nothing may be
        // concluded from it.
        if let Some(lease) = lease
            && !external.end_owned_session(lease)
            && matches!(session, SessionObservation::Established { .. })
        {
            session = SessionObservation::Unknown;
        }
        let observation = RecoveryObservation {
            identity_consistent,
            record,
            checkpoint,
            pending,
            checkpoint_pending,
            intent,
            session,
            previous_fence: context.previous_fence,
            inquiry,
        };
        let decision = decide_recovery(&observation);
        drop(held);
        Ok(RecoveryReport {
            identity: configured,
            observation,
            decision,
        })
    }

    /// Write the dry-run report as `recovery-plan.json` in `directory`,
    /// which must be a directory of this uid outside the journal store (not
    /// the anchor and not the journal directory). One descriptor is used
    /// throughout: temp (O_EXCL, 0600) → write → fsync → rename → directory
    /// fsync, and the path must still name that directory at the end. A
    /// crash leaves the previous report or a temporary file, never a partial
    /// report; the temporary file is not removed (it has no authority).
    pub fn write_recovery_plan(
        &self,
        report: &RecoveryReport,
        directory: &Path,
    ) -> Result<PathBuf, RecoveryError> {
        let bytes = report.to_json()?;
        let dir = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory)
            .map_err(|_| RecoveryError::Report)?;
        let metadata = file_metadata(&dir).map_err(|()| RecoveryError::Report)?;
        let anchor = file_metadata(&self.anchor.fd).map_err(|()| RecoveryError::Report)?;
        let inside = match open_at(
            &self.anchor.fd,
            OsStr::new(JOURNAL_DIR),
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        ) {
            Ok(journal) => file_metadata(&journal)
                .map(|journal| same_inode(&journal, &metadata))
                .unwrap_or(true),
            Err(error) => error.kind() != std::io::ErrorKind::NotFound,
        };
        if !trusted(&metadata, true, self.anchor.service_uid)
            || same_inode(&anchor, &metadata)
            || inside
        {
            return Err(RecoveryError::Report);
        }
        let temp = format!(
            "{RECOVERY_PLAN_FILE}{CAS_TEMP_MARKER}{}",
            cas_request_id().map_err(|_| RecoveryError::Report)?
        );
        let mut file = open_at(
            &dir,
            OsStr::new(&temp),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )
        .map_err(|_| RecoveryError::Report)?;
        file.write_all(&bytes).map_err(|_| RecoveryError::Report)?;
        sync_file(&file).map_err(|()| RecoveryError::Report)?;
        crash_if("dry_run_after_temp");
        let target = directory.join(RECOVERY_PLAN_FILE);
        fs::rename(directory.join(&temp), &target).map_err(|_| RecoveryError::Report)?;
        let renamed = open_at(
            &dir,
            OsStr::new(RECOVERY_PLAN_FILE),
            libc::O_RDONLY | libc::O_NONBLOCK,
            0,
        )
        .map_err(|_| RecoveryError::Report)?;
        let written = file_metadata(&file).map_err(|()| RecoveryError::Report)?;
        if !same_inode(
            &file_metadata(&renamed).map_err(|()| RecoveryError::Report)?,
            &written,
        ) {
            return Err(RecoveryError::Report);
        }
        sync_file(&dir).map_err(|()| RecoveryError::Report)?;
        Ok(target)
    }

    /// R-B and the J10 R-A roll-forward write the journal. Both need the
    /// Owner's approval (OD-J10-7, OD-J14-1), which this prototype does not
    /// have: this always refuses, before touching anything.
    pub fn apply_recovery(&self, _report: &RecoveryReport) -> Result<(), RecoveryError> {
        Err(RecoveryError::PendingOwnerApproval)
    }
}
// J14-END

#[cfg(test)]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CasStateFile {
    schema: u32,
    identity: AnchorIdentity,
    revision: u64,
    digest: String,
    checksum: String,
}

#[cfg(test)]
type CasInode = (u64, u64);

#[cfg(test)]
fn cas_lock_root() -> Result<PathBuf, ()> {
    // Deliberately NOT std::env::temp_dir(): TMPDIR must not change the lock
    // namespace. A production deployment should point this at a service-owned
    // /run or /var/lib directory.
    let root = std::env::var_os("MKG_CAS_LOCK_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/mikagami-cas-locks"));
    match fs::symlink_metadata(&root) {
        Ok(meta) => {
            if !trusted(&meta, true, unsafe { libc::geteuid() }) {
                return Err(());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(&root).map_err(|_| ())?;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).map_err(|_| ())?;
        }
        Err(_) => return Err(()),
    }
    Ok(root)
}

#[cfg(test)]
fn open_cas_lock(path: &Path) -> Result<File, ()> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(path)
        .map_err(|_| ())?;
    let metadata = file_metadata(&file)?;
    if !trusted(&metadata, false, unsafe { libc::geteuid() }) {
        return Err(());
    }
    Ok(file)
}

#[cfg(test)]
fn cas_path_lock(root: &Path, kind: &str, path: &Path) -> Result<File, ()> {
    let digest = format!("{:x}", Sha256::digest(path.as_os_str().as_bytes()));
    let file = open_cas_lock(&root.join(format!("{kind}-{digest}.lock")))?;
    lock_exclusive(&file)?;
    Ok(file)
}

#[cfg(test)]
fn cas_state_inode(path: &Path) -> Result<CasInode, ()> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| ())?;
    let metadata = file_metadata(&file)?;
    if !trusted(&metadata, false, unsafe { libc::geteuid() }) {
        return Err(());
    }
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(test)]
fn read_cas_state(path: &Path) -> Result<(AnchorState, CasInode), ()> {
    if let Some(parent) = path.parent() {
        let meta = fs::symlink_metadata(parent).map_err(|_| ())?;
        if !trusted(&meta, true, unsafe { libc::geteuid() }) {
            return Err(());
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| ())?;
    let metadata = file_metadata(&file)?;
    if !trusted(&metadata, false, unsafe { libc::geteuid() })
        || metadata.len() > MAX_CAS_STATE_BYTES
    {
        return Err(());
    }
    let inode = (metadata.dev(), metadata.ino());
    let mut bytes = Vec::new();
    file.take(MAX_CAS_STATE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() as u64 > MAX_CAS_STATE_BYTES {
        return Err(());
    }
    let file: CasStateFile = serde_json::from_slice(&bytes).map_err(|_| ())?;
    let state = AnchorState {
        identity: file.identity,
        revision: file.revision,
        digest: file.digest,
    };
    let checksum = anchor_checkpoint_checksum(&state.identity, state.revision, &state.digest)?;
    if file.schema != 1 || file.checksum != checksum || !valid_anchor_state(&state) {
        return Err(());
    }
    Ok((state, inode))
}

#[cfg(test)]
fn write_cas_state(
    path: &Path,
    state: &AnchorState,
    expected: Option<CasInode>,
) -> Result<CasInode, ()> {
    if !valid_anchor_state(state) {
        return Err(());
    }
    let parent = path.parent().ok_or(())?;
    let parent_meta = fs::symlink_metadata(parent).map_err(|_| ())?;
    if !trusted(&parent_meta, true, unsafe { libc::geteuid() }) {
        return Err(());
    }
    match (expected, fs::symlink_metadata(path)) {
        (Some((dev, ino)), Ok(meta)) => {
            if !trusted(&meta, false, unsafe { libc::geteuid() })
                || meta.dev() != dev
                || meta.ino() != ino
            {
                return Err(());
            }
        }
        (None, Err(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err(()),
    }
    let checksum = anchor_checkpoint_checksum(&state.identity, state.revision, &state.digest)?;
    let bytes = serde_json::to_vec(&CasStateFile {
        schema: 1,
        identity: state.identity.clone(),
        revision: state.revision,
        digest: state.digest.clone(),
        checksum,
    })
    .map_err(|_| ())?;
    let temp = path.with_extension(format!(
        "tmp-{}-{}",
        std::process::id(),
        cas_request_id().map_err(|_| ())?
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(&temp)
        .map_err(|_| ())?;
    file.write_all(&bytes).map_err(|_| ())?;
    file.sync_all().map_err(|_| ())?;
    if cas_crash_at("during_commit") {
        cas_crash_now();
    }
    std::fs::rename(&temp, path).map_err(|_| ())?;
    File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|_| ())?;
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if !trusted(&metadata, false, unsafe { libc::geteuid() }) {
        return Err(());
    }
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(test)]
fn cas_crash_at(point: &str) -> bool {
    std::env::var("MKG_CAS_CRASH_AT").ok().as_deref() == Some(point)
}

#[cfg(test)]
fn cas_crash_now() {
    unsafe { libc::kill(libc::getpid(), libc::SIGKILL) };
    loop {
        unsafe { libc::pause() };
    }
}

#[cfg(test)]
fn cas_delay() {
    if let Ok(value) = std::env::var("MKG_CAS_DELAY_MS")
        && let Ok(milliseconds) = value.parse::<u64>()
    {
        thread::sleep(Duration::from_millis(milliseconds));
    }
}

#[cfg(test)]
fn cas_drop_response() -> bool {
    std::env::var("MKG_CAS_DROP_RESPONSE").is_ok()
}

#[cfg(test)]
fn cas_wrong_request_id() -> bool {
    std::env::var("MKG_CAS_WRONG_REQUEST_ID").is_ok()
}

#[cfg(test)]
fn handle_cas_request(
    state: &mut AnchorState,
    state_path: &Path,
    state_inode: &mut Option<CasInode>,
    identity: &AnchorIdentity,
    token: &str,
    request: CasRequest,
) -> Result<CasResponse, Option<CasResponse>> {
    let (request_id, request_identity, request_token) = match &request {
        CasRequest::Read {
            request_id,
            identity,
            token,
        }
        | CasRequest::Advance {
            request_id,
            identity,
            token,
            ..
        } => (request_id.clone(), identity.clone(), token.clone()),
    };
    if !constant_time_eq(&request_token, token) {
        return Ok(CasResponse::Rejected {
            request_id,
            reason: CasReject::Unauthorized,
        });
    }
    if &request_identity != identity {
        return Ok(CasResponse::Rejected {
            request_id,
            reason: CasReject::Identity,
        });
    }
    match request {
        CasRequest::Read { .. } => Ok(CasResponse::State {
            request_id,
            state: state.clone(),
        }),
        CasRequest::Advance {
            expected,
            next_revision,
            next_digest,
            ..
        } => {
            if !valid_hex64(&next_digest) || next_digest == ANCHOR_GENESIS_DIGEST {
                return Ok(CasResponse::Rejected {
                    request_id,
                    reason: CasReject::InvalidDigest,
                });
            }
            let Some(expected_next) = expected.revision.checked_add(1) else {
                return Ok(CasResponse::Rejected {
                    request_id,
                    reason: CasReject::Overflow,
                });
            };
            if next_revision != expected_next {
                return Ok(CasResponse::Rejected {
                    request_id,
                    reason: CasReject::Overflow,
                });
            }
            if &expected != state {
                return Ok(CasResponse::Conflict {
                    request_id,
                    state: state.clone(),
                });
            }
            if cas_crash_at("before_commit") {
                cas_crash_now();
            }
            let next = AnchorState {
                identity: identity.clone(),
                revision: next_revision,
                digest: next_digest,
            };
            match write_cas_state(state_path, &next, *state_inode) {
                Ok(inode) => *state_inode = Some(inode),
                Err(_) => {
                    // The on-disk outcome is unknown (rename may have happened
                    // but the directory fsync failed). Never continue with the
                    // old in-memory state; force a restart/re-observe.
                    cas_crash_now();
                }
            }
            *state = next.clone();
            if cas_crash_at("after_commit") {
                cas_crash_now();
            }
            if cas_drop_response() {
                return Err(None);
            }
            cas_delay();
            let response_id = if cas_wrong_request_id() {
                "wrong-request-id".to_string()
            } else {
                request_id
            };
            Ok(CasResponse::Committed {
                request_id: response_id,
                state: next,
            })
        }
    }
}

#[cfg(test)]
fn prepare_socket(socket: &Path) -> Result<(), ()> {
    let parent = socket.parent().ok_or(())?;
    let parent_meta = fs::symlink_metadata(parent).map_err(|_| ())?;
    if !trusted(&parent_meta, true, unsafe { libc::geteuid() }) {
        return Err(());
    }
    match fs::symlink_metadata(socket) {
        Ok(meta) => {
            if !meta.file_type().is_socket() {
                return Err(());
            }
            match UnixStream::connect(socket) {
                Ok(_) => return Err(()),
                Err(error)
                    if error.kind() == std::io::ErrorKind::ConnectionRefused
                        || error.kind() == std::io::ErrorKind::NotFound =>
                {
                    fs::remove_file(socket).map_err(|_| ())?;
                }
                Err(_) => return Err(()),
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(()),
    }
    Ok(())
}

#[cfg(test)]
fn run_cas_server(
    socket: &Path,
    state_path: &Path,
    identity: AnchorIdentity,
    token: String,
    ready: &Path,
) -> Result<(), ()> {
    // Locks are acquired before any state read/write. The lock namespace is
    // independent of TMPDIR and is keyed by identity, state inode, and socket
    // path.
    let lock_root = cas_lock_root()?;
    let identity_lock =
        open_cas_lock(&lock_root.join(format!("identity-{}.lock", identity.as_str())))?;
    lock_exclusive(&identity_lock)?;

    let state_exists = state_path.exists();
    let locked_inode = if state_exists {
        Some(cas_state_inode(state_path)?)
    } else {
        None
    };
    let state_lock = match locked_inode {
        Some((dev, ino)) => open_cas_lock(&lock_root.join(format!("state-{dev}-{ino}.lock")))?,
        None => cas_path_lock(&lock_root, "state-new", state_path)?,
    };
    lock_exclusive(&state_lock)?;

    let (mut state, state_inode) = if state_exists {
        let (state, inode) = read_cas_state(state_path)?;
        if Some(inode) != locked_inode {
            return Err(());
        }
        (state, inode)
    } else {
        let revision = std::env::var("MKG_CAS_INITIAL_REVISION")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        let digest = if revision == 0 {
            ANCHOR_GENESIS_DIGEST.to_string()
        } else {
            "f".repeat(64)
        };
        let state = AnchorState {
            identity: identity.clone(),
            revision,
            digest,
        };
        let inode = write_cas_state(state_path, &state, None)?;
        (state, inode)
    };
    let mut state_inode = Some(state_inode);
    if state.identity != identity {
        return Err(());
    }

    let socket_lock = cas_path_lock(&lock_root, "socket", socket)?;
    lock_exclusive(&socket_lock)?;
    prepare_socket(socket)?;
    let listener = UnixListener::bind(socket).map_err(|_| ())?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600)).map_err(|_| ())?;
    let mut ready_file = OpenOptions::new().write(true).open(ready).map_err(|_| ())?;
    ready_file.write_all(b"R").map_err(|_| ())?;
    ready_file.flush().map_err(|_| ())?;
    let _identity_lock = identity_lock;
    let _state_lock = state_lock;
    let _socket_lock = socket_lock;
    for connection in listener.incoming() {
        let Ok(mut stream) = connection else {
            continue;
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
        let mut line = String::new();
        let Ok(mut reader) = stream.try_clone() else {
            continue;
        };
        match BufReader::new(&mut reader)
            .take(MAX_CAS_MESSAGE_BYTES as u64 + 1)
            .read_line(&mut line)
        {
            Ok(0) => continue,
            Ok(_) if line.len() > MAX_CAS_MESSAGE_BYTES || !line.ends_with('\n') => continue,
            Ok(_) => {}
            Err(_) => continue,
        }
        let Ok(request) = serde_json::from_str::<CasRequest>(&line) else {
            continue;
        };
        match handle_cas_request(
            &mut state,
            state_path,
            &mut state_inode,
            &identity,
            &token,
            request,
        ) {
            Ok(response) => {
                if let Ok(mut bytes) = serde_json::to_vec(&response) {
                    bytes.push(b'\n');
                    if bytes.len() <= MAX_CAS_MESSAGE_BYTES {
                        let _ = stream.write_all(&bytes);
                        let _ = stream.flush();
                    }
                }
            }
            Err(None) => {}
            Err(Some(_)) => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Child, Command, Stdio};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    const CHILD_WRITER: &str = "gce_operation_journal::tests::jt_child_writer";
    const CHILD_CONTENDER: &str = "gce_operation_journal::tests::jt_child_contender";
    const CHILD_CRASH: &str = "gce_operation_journal::tests::crash_child";

    fn uid() -> u32 {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() }
    }

    /// Tests spawn helper processes. Between fork and exec a child briefly
    /// inherits open file descriptions (including flock descriptors), so a
    /// helper from one test could transiently hold another test's lock. Keep
    /// journal tests serial; this is test isolation, not a production lock.
    fn test_guard() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct FakeAnchorFile {
        schema: u32,
        identity: AnchorIdentity,
        revision: u64,
        digest: String,
        checksum: String,
    }

    fn fake_anchor_checksum(
        identity: &AnchorIdentity,
        revision: u64,
        digest: &str,
    ) -> Result<String, ()> {
        #[derive(Serialize)]
        struct Input<'a> {
            schema: u32,
            identity: &'a AnchorIdentity,
            revision: u64,
            digest: &'a str,
        }
        let data = serde_json::to_vec(&Input {
            schema: 1,
            identity,
            revision,
            digest,
        })
        .map_err(|_| ())?;
        Ok(format!("{:x}", Sha256::digest(&data)))
    }

    /// Deterministic test-only fake. It is a file on the same VM and therefore
    /// is NOT independent rollback protection; real deployments need TPM or an
    /// external monotonic service.
    struct FileAnchor {
        path: PathBuf,
        identity: AnchorIdentity,
        lock: Mutex<()>,
        unavailable: AtomicBool,
        fail_next: AtomicBool,
    }

    impl FileAnchor {
        fn new(path: &Path, identity: AnchorIdentity) -> Self {
            let anchor = Self {
                path: path.to_path_buf(),
                identity,
                lock: Mutex::new(()),
                unavailable: AtomicBool::new(false),
                fail_next: AtomicBool::new(false),
            };
            if !path.exists() {
                let state = AnchorState {
                    identity: anchor.identity.clone(),
                    revision: 0,
                    digest: ANCHOR_GENESIS_DIGEST.to_string(),
                };
                anchor.write_state(&state).unwrap();
            } else {
                anchor.read().unwrap();
            }
            anchor
        }

        fn set_unavailable(&self, value: bool) {
            self.unavailable.store(value, Ordering::SeqCst);
        }

        fn fail_next_advance(&self) {
            self.fail_next.store(true, Ordering::SeqCst);
        }

        fn set_state(&self, state: &AnchorState) {
            self.write_state(state).unwrap();
        }

        fn write_state(&self, state: &AnchorState) -> Result<(), AnchorError> {
            if !valid_anchor_state(state) || state.identity != self.identity {
                return Err(AnchorError::Internal);
            }
            let checksum = fake_anchor_checksum(&state.identity, state.revision, &state.digest)
                .map_err(|_| AnchorError::Internal)?;
            let bytes = serde_json::to_vec(&FakeAnchorFile {
                schema: 1,
                identity: state.identity.clone(),
                revision: state.revision,
                digest: state.digest.clone(),
                checksum,
            })
            .map_err(|_| AnchorError::Internal)?;
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            for _ in 0..16 {
                let temp = self.path.with_extension(format!(
                    "tmp-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
                let mut file = match OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&temp)
                {
                    Ok(file) => file,
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(_) => return Err(AnchorError::Unavailable),
                };
                let result = (|| -> std::io::Result<()> {
                    file.write_all(&bytes)?;
                    file.sync_all()?;
                    std::fs::rename(&temp, &self.path)?;
                    if let Some(parent) = self.path.parent() {
                        File::open(parent)?.sync_all()?;
                    }
                    Ok(())
                })();
                if result.is_err() {
                    let _ = std::fs::remove_file(&temp);
                    return Err(AnchorError::Internal);
                }
                return Ok(());
            }
            Err(AnchorError::Unavailable)
        }
    }

    impl IntoExternal for Arc<FileAnchor> {
        fn into_external(self) -> ExternalAnchor {
            ExternalAnchor::Legacy(self)
        }
    }

    impl MonotonicAnchor for FileAnchor {
        fn identity(&self) -> AnchorIdentity {
            self.identity.clone()
        }

        /// In-process fake: a call that has returned has no request left in
        /// flight, and `advance` publishes by atomic rename under `self.lock`,
        /// so a read observes a complete state. There is no fence to bump.
        fn begin_session(&self) -> Result<AnchorState, AnchorError> {
            self.read()
        }

        fn read(&self) -> Result<AnchorState, AnchorError> {
            if self.unavailable.load(Ordering::SeqCst) {
                return Err(AnchorError::Unavailable);
            }
            let bytes = std::fs::read(&self.path).map_err(|_| AnchorError::Unavailable)?;
            let file: FakeAnchorFile =
                serde_json::from_slice(&bytes).map_err(|_| AnchorError::Corrupt)?;
            let state = AnchorState {
                identity: file.identity,
                revision: file.revision,
                digest: file.digest,
            };
            let checksum = fake_anchor_checksum(&state.identity, state.revision, &state.digest)
                .map_err(|_| AnchorError::Corrupt)?;
            if file.schema != 1
                || file.checksum != checksum
                || !valid_anchor_state(&state)
                || state.identity != self.identity
            {
                return Err(AnchorError::Corrupt);
            }
            Ok(state)
        }

        fn advance(
            &self,
            expected: &AnchorState,
            next_digest: &str,
        ) -> Result<AnchorState, AnchorError> {
            let _guard = self
                .lock
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if self.unavailable.load(Ordering::SeqCst) {
                return Err(AnchorError::Unavailable);
            }
            if self.fail_next.swap(false, Ordering::SeqCst) {
                return Err(AnchorError::Unavailable);
            }
            if !valid_hex64(next_digest) || next_digest == ANCHOR_GENESIS_DIGEST {
                return Err(AnchorError::Internal);
            }
            let current = self.read()?;
            if &current != expected {
                return Err(AnchorError::Conflict);
            }
            let revision = current
                .revision
                .checked_add(1)
                .ok_or(AnchorError::Exhausted)?;
            let next = AnchorState {
                identity: current.identity,
                revision,
                digest: next_digest.to_string(),
            };
            self.write_state(&next)?;
            Ok(next)
        }
    }

    const CHILD_CAS_SERVER: &str = "gce_operation_journal::tests::j6_cas_server_child";
    const CHILD_CAS_CLIENT: &str = "gce_operation_journal::tests::j6_cas_client_child";

    fn j6_identity() -> AnchorIdentity {
        AnchorIdentity::from_hex(format!("{:064x}", 0x6a6a_0000_u64)).unwrap()
    }

    fn j6_token() -> String {
        "6a".repeat(32)
    }

    struct CasServer {
        child: Option<Child>,
        socket: PathBuf,
        state: PathBuf,
        identity: AnchorIdentity,
        token: String,
    }

    impl CasServer {
        fn stop(&mut self) {
            if let Some(mut child) = self.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
            let _ = std::fs::remove_file(&self.socket);
        }
    }

    impl Drop for CasServer {
        fn drop(&mut self) {
            self.stop();
        }
    }

    fn start_cas_server(
        base: &Path,
        socket: &Path,
        state: &Path,
        identity: &AnchorIdentity,
        token: &str,
        envs: &[(&str, String)],
    ) -> CasServer {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let ready = base.join(format!(
            "cas-{}-{}.ready",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        make_fifo(&ready);
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", CHILD_CAS_SERVER, "--nocapture"])
            .env("MKG_CAS_SOCKET", socket)
            .env("MKG_CAS_STATE", state)
            .env("MKG_CAS_IDENTITY", identity.as_str())
            .env("MKG_CAS_TOKEN", token)
            .env("MKG_CAS_READY", &ready)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (key, value) in envs {
            command.env(key, value);
        }
        let child = command.spawn().unwrap();
        assert_eq!(read_fifo(&ready), b'R');
        CasServer {
            child: Some(child),
            socket: socket.to_path_buf(),
            state: state.to_path_buf(),
            identity: identity.clone(),
            token: token.to_string(),
        }
    }

    struct CasFixture {
        base: PathBuf,
        anchor: PathBuf,
        socket: PathBuf,
        state: PathBuf,
        identity: AnchorIdentity,
        token: String,
        server: Option<CasServer>,
    }

    impl CasFixture {
        fn new() -> Self {
            Self::new_with_env(&[])
        }

        fn new_with_env(envs: &[(&str, String)]) -> Self {
            let base = unique_base("j6");
            let anchor = base.join("anchor");
            fs::create_dir(&anchor).unwrap();
            set_mode(&anchor, 0o700);
            let identity = j6_identity();
            let token = j6_token();
            let socket = base.join("cas.sock");
            let state = base.join("cas.state");
            let server = start_cas_server(&base, &socket, &state, &identity, &token, envs);
            Self {
                base,
                anchor,
                socket,
                state,
                identity,
                token,
                server: Some(server),
            }
        }

        fn restart(&mut self, envs: &[(&str, String)]) {
            if let Some(mut server) = self.server.take() {
                server.stop();
            }
            let server = start_cas_server(
                &self.base,
                &self.socket,
                &self.state,
                &self.identity,
                &self.token,
                envs,
            );
            self.server = Some(server);
        }

        fn stop_server(&mut self) {
            if let Some(mut server) = self.server.take() {
                server.stop();
            }
        }

        fn client(&self) -> Arc<CasAnchor> {
            Arc::new(
                CasAnchor::new(
                    self.socket.clone(),
                    self.identity.clone(),
                    self.token.clone(),
                    Duration::from_millis(1_000),
                )
                .unwrap(),
            )
        }

        fn client_with_timeout(&self, timeout_ms: u64) -> Arc<CasAnchor> {
            Arc::new(
                CasAnchor::new(
                    self.socket.clone(),
                    self.identity.clone(),
                    self.token.clone(),
                    Duration::from_millis(timeout_ms),
                )
                .unwrap(),
            )
        }

        fn store(&self) -> JournalStore {
            JournalStore::for_test_with_anchor(&self.anchor, self.client()).unwrap()
        }

        fn legacy_store(&self) -> JournalStore {
            JournalStore::for_test(&self.anchor).unwrap()
        }

        fn journal(&self) -> PathBuf {
            self.anchor.join(JOURNAL_DIR)
        }

        fn journal_file(&self) -> PathBuf {
            self.journal().join(JOURNAL_FILE)
        }

        fn sidecar(&self) -> PathBuf {
            self.journal().join(ANCHOR_FILE)
        }

        fn cleanup(mut self) {
            self.stop_server();
            set_mode(&self.base, 0o700);
            let _ = fs::remove_dir_all(&self.base);
        }
    }

    #[test]
    fn j6_cas_server_child() {
        let Ok(socket) = std::env::var("MKG_CAS_SOCKET") else {
            return;
        };
        let state = PathBuf::from(std::env::var("MKG_CAS_STATE").unwrap());
        let identity =
            AnchorIdentity::from_hex(std::env::var("MKG_CAS_IDENTITY").unwrap()).unwrap();
        let token = std::env::var("MKG_CAS_TOKEN").unwrap();
        let ready = PathBuf::from(std::env::var("MKG_CAS_READY").unwrap());
        run_cas_server(&PathBuf::from(socket), &state, identity, token, &ready).unwrap();
    }

    struct J5Fixture {
        base: PathBuf,
        anchor: PathBuf,
        anchor_path: PathBuf,
        identity: AnchorIdentity,
    }

    fn j5_identity() -> AnchorIdentity {
        AnchorIdentity::from_hex(format!("{:064x}", 0x5a17_0000_u64)).unwrap()
    }

    impl J5Fixture {
        fn new() -> Self {
            let base = unique_base("j5");
            let anchor = base.join("anchor");
            fs::create_dir(&anchor).unwrap();
            set_mode(&anchor, 0o700);
            let identity = j5_identity();
            let anchor_path = base.join("monotonic.anchor");
            Self {
                base,
                anchor,
                anchor_path,
                identity,
            }
        }

        fn from_base(base: PathBuf) -> Self {
            let anchor = base.join("anchor");
            let anchor_path = base.join("monotonic.anchor");
            Self {
                base,
                anchor,
                anchor_path,
                identity: j5_identity(),
            }
        }

        fn anchor(&self) -> Arc<FileAnchor> {
            Arc::new(FileAnchor::new(&self.anchor_path, self.identity.clone()))
        }

        fn store_with(&self, anchor: Arc<FileAnchor>) -> JournalStore {
            JournalStore::for_test_with_anchor(&self.anchor, anchor).unwrap()
        }

        fn store_with_proxy(&self, anchor: Arc<dyn MonotonicAnchor>) -> JournalStore {
            JournalStore::for_test_with_anchor(&self.anchor, anchor).unwrap()
        }

        fn store(&self) -> JournalStore {
            self.store_with(self.anchor())
        }

        fn legacy_store(&self) -> JournalStore {
            JournalStore::for_test(&self.anchor).unwrap()
        }

        fn initialize(&self, record: Record) -> Result<Journal, ()> {
            self.store().initialize(record)
        }

        fn open(&self) -> Result<Journal, ()> {
            self.store().open()
        }

        fn journal(&self) -> PathBuf {
            self.anchor.join(JOURNAL_DIR)
        }

        fn journal_file(&self) -> PathBuf {
            self.journal().join(JOURNAL_FILE)
        }

        fn sidecar(&self) -> PathBuf {
            self.journal().join(ANCHOR_FILE)
        }

        fn sidecar_pending(&self) -> PathBuf {
            self.journal().join(ANCHOR_PENDING_FILE)
        }

        fn cleanup(self) {
            set_mode(&self.base, 0o700);
            let _ = fs::remove_dir_all(&self.base);
        }
    }

    fn set_mode(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn unique_base(label: &str) -> PathBuf {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let base = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "mkg-j4t-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&base).unwrap();
        set_mode(&base, 0o700);
        base
    }

    struct Fixture {
        base: PathBuf,
        anchor: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let base = unique_base("store");
            let anchor = base.join("anchor");
            fs::create_dir(&anchor).unwrap();
            set_mode(&anchor, 0o700);
            Self { base, anchor }
        }

        fn from_base(base: PathBuf) -> Self {
            let anchor = base.join("anchor");
            Self { base, anchor }
        }

        fn journal(&self) -> PathBuf {
            self.anchor.join(JOURNAL_DIR)
        }

        fn journal_file(&self) -> PathBuf {
            self.journal().join(JOURNAL_FILE)
        }

        fn lock(&self) -> PathBuf {
            self.journal().join(LOCK_FILE)
        }

        fn pending(&self) -> PathBuf {
            self.journal().join(PENDING_FILE)
        }

        fn store(&self) -> JournalStore {
            JournalStore::for_test(&self.anchor).unwrap()
        }

        fn initialize(&self, record: Record) -> Result<Journal, ()> {
            self.store().initialize(record)
        }

        fn open(&self) -> Result<Journal, ()> {
            self.store().open()
        }

        fn cleanup(self) {
            set_mode(&self.base, 0o700);
            let _ = fs::remove_dir_all(&self.base);
        }
    }

    fn record() -> Record {
        Record {
            schema: 1,
            journal_id: "synthetic-journal".into(),
            attempt: Attempt {
                attempt_id: "a".into(),
                generation: 1,
                term: 1,
                lease_id: "synthetic".into(),
                project: "example".into(),
                zone: "zone-a".into(),
                instance: "node-a".into(),
                instance_id: "123".into(),
            },
            state: State::Prepared,
            operation: None,
            revision: 1,
        }
    }

    fn make_fifo(path: &Path) {
        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    }

    fn read_fifo(path: &Path) -> u8 {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)
            .unwrap();
        let mut pollfd = libc::pollfd {
            fd: file.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut pollfd, 1, 15_000) };
        assert_eq!(ready, 1, "fifo {} timed out", path.display());
        let mut byte = [0u8; 1];
        file.read_exact(&mut byte).unwrap();
        byte[0]
    }

    fn write_fifo(path: &Path, byte: u8) {
        let mut file = OpenOptions::new().write(true).open(path).unwrap();
        file.write_all(&[byte]).unwrap();
        file.flush().unwrap();
    }

    fn spawn_child(test: &str, fixture: &Fixture, action: &str, paths: &[(&str, &Path)]) -> Child {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", test, "--nocapture"])
            .env("MKG_JT_BASE", &fixture.base)
            .env("MKG_JT_ACTION", action)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        for (key, path) in paths {
            command.env(key, path);
        }
        command.spawn().unwrap()
    }

    struct Writer {
        child: Child,
        go: PathBuf,
        done: PathBuf,
    }

    impl Drop for Writer {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn start_writer(fixture: &Fixture, action: &str) -> Writer {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let prefix = format!("{action}-{}", NEXT.fetch_add(1, Ordering::Relaxed));
        let ready = fixture.base.join(format!("{prefix}.ready"));
        let go = fixture.base.join(format!("{prefix}.go"));
        let done = fixture.base.join(format!("{prefix}.done"));
        make_fifo(&ready);
        make_fifo(&go);
        make_fifo(&done);
        let child = spawn_child(
            CHILD_WRITER,
            fixture,
            action,
            &[
                ("MKG_JT_READY", &ready),
                ("MKG_JT_GO", &go),
                ("MKG_JT_DONE", &done),
            ],
        );
        assert_eq!(read_fifo(&ready), b'R');
        Writer { child, go, done }
    }

    fn finish_writer(writer: &mut Writer) -> u8 {
        write_fifo(&writer.go, b'G');
        let result = read_fifo(&writer.done);
        assert!(writer.child.wait().unwrap().success());
        result
    }

    fn run_contender(fixture: &Fixture, action: &str) -> bool {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let done = fixture.base.join(format!(
            "contender-{action}-{}.done",
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        make_fifo(&done);
        let mut child = spawn_child(CHILD_CONTENDER, fixture, action, &[("MKG_JT_DONE", &done)]);
        let result = read_fifo(&done);
        assert!(child.wait().unwrap().success());
        result == b'1'
    }

    fn child_fixture() -> Option<Fixture> {
        std::env::var("MKG_JT_BASE")
            .ok()
            .map(|base| Fixture::from_base(PathBuf::from(base)))
    }

    #[test]
    fn jt_child_writer() {
        let _guard = test_guard();
        let Some(fixture) = child_fixture() else {
            return;
        };
        let action = std::env::var("MKG_JT_ACTION").unwrap();
        let ready = PathBuf::from(std::env::var("MKG_JT_READY").unwrap());
        let go = PathBuf::from(std::env::var("MKG_JT_GO").unwrap());
        let done = PathBuf::from(std::env::var("MKG_JT_DONE").unwrap());
        let mut journal = match action.as_str() {
            "initialize" => fixture.initialize(record()).unwrap(),
            "open" => fixture.open().unwrap(),
            other => panic!("unknown writer action {other}"),
        };
        write_fifo(&ready, b'R');
        let _ = read_fifo(&go);
        let result = journal.advance(&record().attempt, State::MayHaveBeenSent, None);
        write_fifo(&done, if result.is_err() { b'0' } else { b'1' });
    }

    #[test]
    fn jt_child_contender() {
        let _guard = test_guard();
        let Some(fixture) = child_fixture() else {
            return;
        };
        let action = std::env::var("MKG_JT_ACTION").unwrap();
        let done = PathBuf::from(std::env::var("MKG_JT_DONE").unwrap());
        let result = match action.as_str() {
            "open" => fixture.open().map(|_| ()),
            "initialize" => fixture.initialize(record()).map(|_| ()),
            other => panic!("unknown contender action {other}"),
        };
        write_fifo(&done, if result.is_ok() { b'1' } else { b'0' });
    }

    #[test]
    fn only_valid_success_path() {
        let _guard = test_guard();
        let mut r = record();
        let a = r.attempt.clone();
        for (s, o) in [
            (State::MayHaveBeenSent, None),
            (State::OperationKnown, Some(("1".into(), "op".into()))),
            (State::DoneObserved, None),
            (State::TerminatedObserved, None),
            (State::ProofEstablished, None),
        ] {
            r = r.transition(&a, s, o).unwrap();
            assert!(!r.send_authorized());
        }
    }

    #[test]
    fn stale_and_shortcut_refused() {
        let _guard = test_guard();
        let r = record();
        let mut a = r.attempt.clone();
        a.generation += 1;
        assert!(r.transition(&a, State::MayHaveBeenSent, None).is_none());
        assert!(
            r.transition(&r.attempt, State::ProofEstablished, None)
                .is_none()
        );
    }

    #[test]
    fn j01_j02_initialization_and_reopen() {
        let _guard = test_guard();
        let f = Fixture::new();
        let r = record();
        let j = f.initialize(r.clone()).unwrap();
        assert!(!j.send_authorized());
        drop(j);
        let j = f.open().unwrap();
        assert_eq!(j.record(), &r);
        assert!(!j.send_authorized());
        drop(j);
        f.cleanup();
    }

    #[test]
    fn j03_j04_j08_reopen_never_authorizes() {
        let _guard = test_guard();
        let f = Fixture::new();
        let r = record();
        let a = r.attempt.clone();
        let mut j = f.initialize(r).unwrap();
        j.advance(&a, State::MayHaveBeenSent, None).unwrap();
        assert!(!j.send_authorized());
        drop(j);
        let mut j = f.open().unwrap();
        assert_eq!(j.record().state, State::MayHaveBeenSent);
        assert!(!j.send_authorized());
        j.advance(
            &a,
            State::OperationKnown,
            Some(("123".into(), "op-1".into())),
        )
        .unwrap();
        drop(j);
        let j = f.open().unwrap();
        assert_eq!(j.record().state, State::OperationKnown);
        assert!(!j.send_authorized());
        drop(j);
        f.cleanup();
    }

    #[test]
    fn j09_done_is_not_proof() {
        let _guard = test_guard();
        let f = Fixture::new();
        let r = record();
        let a = r.attempt.clone();
        let mut j = f.initialize(r).unwrap();
        j.advance(&a, State::MayHaveBeenSent, None).unwrap();
        j.advance(&a, State::OperationKnown, Some(("123".into(), "op".into())))
            .unwrap();
        j.advance(&a, State::DoneObserved, None).unwrap();
        assert!(
            j.record()
                .transition(&a, State::ProofEstablished, None)
                .is_none()
        );
        drop(j);
        f.cleanup();
    }

    #[test]
    fn j10_j11_j12_corruption_missing_version_blocked() {
        let _guard = test_guard();
        let f = Fixture::new();
        assert!(f.open().is_err());
        let j = f.initialize(record()).unwrap();
        let identity = j.identity;
        drop(j);
        fs::write(f.journal_file(), b"not-json").unwrap();
        assert!(f.open().is_err());

        let mut r = record();
        r.schema = 2;
        assert!(encode(&r, &identity).is_err());
        let data = serde_json::to_vec(&Signed {
            record: &r,
            store: &identity,
        })
        .unwrap();
        let envelope = Envelope {
            record: r,
            store: Some(identity),
            checksum: format!("{:x}", Sha256::digest(&data)),
        };
        fs::write(f.journal_file(), serde_json::to_vec(&envelope).unwrap()).unwrap();
        assert!(f.open().is_err());
        f.cleanup();
    }

    #[test]
    fn concurrent_open_is_blocked() {
        let _guard = test_guard();
        let f = Fixture::new();
        let j = f.initialize(record()).unwrap();
        assert!(f.open().is_err());
        drop(j);
        assert!(f.open().is_ok());
        f.cleanup();
    }

    #[test]
    fn crash_child() {
        let _guard = test_guard();
        let Ok(base) = std::env::var("MKG_JT_CRASH_BASE") else {
            return;
        };
        let phase = std::env::var("MKG_JT_CRASH_PHASE").unwrap();
        let f = Fixture::from_base(PathBuf::from(base));
        let r = record();
        let a = r.attempt.clone();
        let mut j = f.initialize(r).unwrap();
        j.advance(&a, State::MayHaveBeenSent, None).unwrap();
        // The fake transport is test-only: the production send gate is disabled.
        if phase != "before" {
            let mut marker = File::create(f.base.join("fake-sent")).unwrap();
            marker.write_all(b"synthetic request").unwrap();
            marker.sync_all().unwrap();
        }
        if phase == "response" {
            // Operation ID is delivered to the test process but never journaled.
            let received_id = "synthetic-operation";
            assert!(!received_id.is_empty());
            let mut marker = File::create(f.base.join("fake-received")).unwrap();
            marker.write_all(received_id.as_bytes()).unwrap();
            marker.sync_all().unwrap();
        }
        let result = unsafe { libc::kill(libc::getpid(), libc::SIGKILL) };
        if result != 0 {
            // No panic here: a panic would make the parent observe a normal
            // test failure instead of the intended kill boundary. Exit 101 is
            // still a test failure because the parent requires SIGKILL.
            unsafe { libc::_exit(101) };
        }
        loop {
            // SIGKILL cannot be caught or ignored. Waiting here avoids a race
            // between a pending signal and the test harness's unwinding.
            unsafe { libc::pause() };
        }
    }

    #[test]
    fn jt10_crash_reopen_never_authorizes() {
        let _guard = test_guard();
        for phase in ["before", "sent", "response"] {
            let f = Fixture::new();
            let status = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", CHILD_CRASH, "--nocapture"])
                .env("MKG_JT_CRASH_BASE", &f.base)
                .env("MKG_JT_CRASH_PHASE", phase)
                .status()
                .unwrap();
            assert_eq!(status.signal(), Some(libc::SIGKILL), "{phase}");
            assert_eq!(f.base.join("fake-sent").exists(), phase != "before");
            assert_eq!(f.base.join("fake-received").exists(), phase == "response");
            let j = f.open().unwrap();
            assert_eq!(j.record().state, State::MayHaveBeenSent);
            assert_eq!(j.record().operation, None);
            assert!(!j.send_authorized());
            drop(j);
            f.cleanup();
        }
    }

    #[test]
    fn failed_persistence_latches_handle_closed() {
        let _guard = test_guard();
        let f = Fixture::new();
        let r = record();
        let a = r.attempt.clone();
        let mut j = f.initialize(r).unwrap();
        fs::write(f.pending(), b"synthetic interrupted write").unwrap();
        assert!(j.advance(&a, State::MayHaveBeenSent, None).is_err());
        fs::remove_file(f.pending()).unwrap();
        assert!(j.advance(&a, State::MayHaveBeenSent, None).is_err());
        assert!(!j.send_authorized());
        drop(j);
        f.cleanup();
    }

    #[test]
    fn injected_persistence_failures_latch_and_never_authorize() {
        let _guard = test_guard();
        for point in 1..=5 {
            let f = Fixture::new();
            let r = record();
            let a = r.attempt.clone();
            let mut j = f.initialize(r).unwrap();
            INJECT.with(|value| value.set(point));
            assert!(
                j.advance(&a, State::MayHaveBeenSent, None).is_err(),
                "{point}"
            );
            INJECT.with(|value| value.set(0));
            assert!(j.advance(&a, State::MayHaveBeenSent, None).is_err());
            assert!(!j.send_authorized());
            drop(j);
            f.cleanup();
        }
    }

    #[test]
    fn substituted_lock_is_detected_and_poisoned() {
        let _guard = test_guard();
        let f = Fixture::new();
        let r = record();
        let a = r.attempt.clone();
        let mut j = f.initialize(r).unwrap();
        fs::rename(f.lock(), f.journal().join("old.lock")).unwrap();
        fs::write(f.lock(), b"").unwrap();
        set_mode(&f.lock(), 0o600);
        assert!(j.advance(&a, State::MayHaveBeenSent, None).is_err());
        fs::remove_file(f.lock()).unwrap();
        fs::rename(f.journal().join("old.lock"), f.lock()).unwrap();
        assert!(j.advance(&a, State::MayHaveBeenSent, None).is_err());
        drop(j);
        f.cleanup();
    }

    #[test]
    fn replaced_directory_is_detected_and_poisoned() {
        let _guard = test_guard();
        let f = Fixture::new();
        let moved = f.base.join("journal.moved");
        let r = record();
        let a = r.attempt.clone();
        let mut j = f.initialize(r).unwrap();
        fs::rename(f.journal(), &moved).unwrap();
        fs::create_dir(f.journal()).unwrap();
        set_mode(&f.journal(), 0o700);
        assert!(j.advance(&a, State::MayHaveBeenSent, None).is_err());
        fs::remove_dir(f.journal()).unwrap();
        fs::rename(&moved, f.journal()).unwrap();
        assert!(j.advance(&a, State::MayHaveBeenSent, None).is_err());
        drop(j);
        f.cleanup();
    }

    #[test]
    fn replaced_lock_cannot_obtain_second_writer_on_same_directory() {
        let _guard = test_guard();
        let f = Fixture::new();
        let j = f.initialize(record()).unwrap();
        fs::rename(f.lock(), f.journal().join("previous.lock")).unwrap();
        fs::write(f.lock(), b"").unwrap();
        set_mode(&f.lock(), 0o600);
        assert!(f.open().is_err());
        drop(j);
        f.cleanup();
    }

    #[test]
    fn journal_symlink_and_hardlink_are_refused() {
        let _guard = test_guard();
        let f = Fixture::new();
        let j = f.initialize(record()).unwrap();
        drop(j);
        fs::rename(f.journal_file(), f.journal().join("old.json")).unwrap();
        symlink("old.json", f.journal_file()).unwrap();
        assert!(f.open().is_err());
        fs::remove_file(f.journal_file()).unwrap();
        fs::hard_link(f.journal().join("old.json"), f.journal_file()).unwrap();
        assert!(f.open().is_err());
        f.cleanup();
    }

    #[test]
    fn contention_child() {
        let _guard = test_guard();
        let Some(f) = child_fixture() else {
            return;
        };
        assert!(f.open().is_err());
    }

    #[test]
    fn another_process_cannot_open_locked_directory() {
        let _guard = test_guard();
        let f = Fixture::new();
        let j = f.initialize(record()).unwrap();
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "gce_operation_journal::tests::contention_child"])
            .env("MKG_JT_BASE", &f.base)
            .status()
            .unwrap();
        assert!(status.success());
        drop(j);
        f.cleanup();
    }

    #[test]
    fn insecure_permissions_are_refused() {
        let _guard = test_guard();
        let f = Fixture::new();
        let j = f.initialize(record()).unwrap();
        drop(j);
        set_mode(&f.journal_file(), 0o666);
        assert!(f.open().is_err());
        f.cleanup();
    }

    #[test]
    fn different_directory_inode_replacement_old_handle_blocks_before_update() {
        let _guard = test_guard();
        let f = Fixture::new();
        let r = record();
        let a = r.attempt.clone();
        let mut old = f.initialize(r.clone()).unwrap();
        let moved = f.base.join("journal.old");
        fs::rename(f.journal(), &moved).unwrap();
        fs::create_dir(f.journal()).unwrap();
        set_mode(&f.journal(), 0o700);
        assert!(f.initialize(r).is_err());
        assert!(old.advance(&a, State::MayHaveBeenSent, None).is_err());
        drop(old);
        f.cleanup();
    }

    #[test]
    fn provisioning_rejects_unsafe_anchor_paths() {
        let _guard = test_guard();
        let base = unique_base("provision");
        let anchor = base.join("anchor");
        fs::create_dir(&anchor).unwrap();
        set_mode(&anchor, 0o700);
        assert!(JournalStore::for_test(&anchor).is_ok());

        let alias = base.join("alias");
        symlink("anchor", &alias).unwrap();
        assert!(JournalStore::for_test(&alias).is_err());

        set_mode(&base, 0o777);
        assert!(JournalStore::for_test(&anchor).is_err());
        set_mode(&base, 0o700);

        assert!(JournalStore::for_test_with_uid(&anchor, uid() + 1).is_err());
        assert!(JournalStore::for_test(Path::new("relative-anchor")).is_err());
        base_cleanup(&base);
    }

    #[test]
    fn anchor_replacement_is_detected_without_reinitialization() {
        let _guard = test_guard();
        let f = Fixture::new();
        let store = f.store();
        let r = record();
        let a = r.attempt.clone();
        let mut j = store.initialize(r).unwrap();
        let moved = f.base.join("anchor.old");
        fs::rename(&f.anchor, &moved).unwrap();
        fs::create_dir(&f.anchor).unwrap();
        set_mode(&f.anchor, 0o700);
        assert!(store.open().is_err());
        assert!(j.advance(&a, State::MayHaveBeenSent, None).is_err());
        drop(j);
        f.cleanup();
    }

    #[test]
    fn initialize_never_overwrites_an_existing_journal() {
        let _guard = test_guard();
        let f = Fixture::new();
        let j = f.initialize(record()).unwrap();
        drop(j);
        let before = fs::read(f.journal_file()).unwrap();
        let mut other = record();
        other.journal_id = "other-journal".into();
        assert!(f.initialize(other).is_err());
        assert_eq!(fs::read(f.journal_file()).unwrap(), before);
        f.cleanup();
    }

    #[test]
    fn journal_directory_and_files_are_private() {
        let _guard = test_guard();
        let f = Fixture::new();
        let j = f.initialize(record()).unwrap();
        assert_eq!(fs::metadata(f.journal()).unwrap().mode() & 0o777, 0o700);
        assert_eq!(
            fs::metadata(f.journal_file()).unwrap().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::metadata(f.lock()).unwrap().mode() & 0o777, 0o600);
        drop(j);
        f.cleanup();
    }

    #[test]
    fn jt01_writer_b_is_refused_while_writer_a_holds() {
        let _guard = test_guard();
        let f = Fixture::new();
        let mut a = start_writer(&f, "initialize");
        assert!(!run_contender(&f, "open"));
        assert_eq!(finish_writer(&mut a), b'1');
        let j = f.open().unwrap();
        assert_eq!(j.record().state, State::MayHaveBeenSent);
        drop(j);
        f.cleanup();
    }

    #[test]
    fn jt02_writer_b_opens_after_writer_a_exits() {
        let _guard = test_guard();
        let f = Fixture::new();
        let mut a = start_writer(&f, "initialize");
        assert_eq!(finish_writer(&mut a), b'1');
        assert!(run_contender(&f, "open"));
        f.cleanup();
    }

    #[test]
    fn jt03_replaced_directory_is_refused_and_poisoned() {
        let _guard = test_guard();
        let f = Fixture::new();
        let mut a = start_writer(&f, "initialize");
        let moved = f.base.join("journal.replaced");
        fs::rename(f.journal(), &moved).unwrap();
        fs::create_dir(f.journal()).unwrap();
        set_mode(&f.journal(), 0o700);
        assert!(!run_contender(&f, "initialize"));
        assert_eq!(finish_writer(&mut a), b'0');
        assert!(f.open().is_err());
        f.cleanup();
    }

    #[test]
    fn jt04_different_directory_inode_cannot_create_second_writer() {
        let _guard = test_guard();
        let f = Fixture::new();
        let mut a = start_writer(&f, "initialize");
        let moved = f.base.join("journal.original");
        fs::rename(f.journal(), &moved).unwrap();
        fs::create_dir(f.journal()).unwrap();
        set_mode(&f.journal(), 0o700);
        assert!(!run_contender(&f, "initialize"));
        assert_eq!(finish_writer(&mut a), b'0');
        assert!(f.open().is_err());
        // Restoring the original directory demonstrates that neither writer
        // modified the old journal while the two names existed.
        fs::remove_dir(f.journal()).unwrap();
        fs::rename(&moved, f.journal()).unwrap();
        let j = f.open().unwrap();
        assert_eq!(j.record().state, State::Prepared);
        drop(j);
        f.cleanup();
    }

    #[test]
    fn jt05_lock_replacement_is_detected_and_persisted() {
        let _guard = test_guard();
        let f = Fixture::new();
        let mut a = start_writer(&f, "initialize");
        let old = f.base.join("lock.original");
        fs::rename(f.lock(), &old).unwrap();
        fs::write(f.lock(), b"").unwrap();
        set_mode(&f.lock(), 0o600);
        assert!(!run_contender(&f, "open"));
        assert_eq!(finish_writer(&mut a), b'0');
        assert!(f.open().is_err());
        fs::remove_file(f.lock()).unwrap();
        fs::rename(&old, f.lock()).unwrap();
        let j = f.open().unwrap();
        assert_eq!(j.record().state, State::Prepared);
        drop(j);
        f.cleanup();
    }

    #[test]
    fn jt06_pending_replacement_is_detected() {
        let _guard = test_guard();
        for kind in ["regular", "symlink", "hardlink", "mode"] {
            let f = Fixture::new();
            let mut a = start_writer(&f, "initialize");
            let pending = f.pending();
            match kind {
                "regular" => fs::write(&pending, b"synthetic").unwrap(),
                "symlink" => symlink(JOURNAL_FILE, &pending).unwrap(),
                "hardlink" => fs::hard_link(f.journal_file(), &pending).unwrap(),
                "mode" => {
                    fs::write(&pending, b"synthetic").unwrap();
                    set_mode(&pending, 0o666);
                }
                _ => unreachable!(),
            }
            assert!(!run_contender(&f, "open"), "{kind}");
            assert_eq!(finish_writer(&mut a), b'0', "{kind}");
            assert!(f.open().is_err(), "{kind}");
            fs::remove_file(&pending).unwrap();
            let j = f.open().unwrap();
            assert_eq!(j.record().state, State::Prepared, "{kind}");
            drop(j);
            f.cleanup();
        }
    }

    #[test]
    fn jt07_symlink_paths_are_refused() {
        let _guard = test_guard();
        let base = unique_base("symlink-anchor");
        let real = base.join("real");
        fs::create_dir(&real).unwrap();
        set_mode(&real, 0o700);
        let alias = base.join("anchor");
        symlink("real", &alias).unwrap();
        assert!(JournalStore::for_test(&alias).is_err());
        base_cleanup(&base);

        let f = Fixture::new();
        let j = f.initialize(record()).unwrap();
        drop(j);
        let moved = f.anchor.join("journal.real");
        fs::rename(f.journal(), &moved).unwrap();
        symlink("journal.real", f.journal()).unwrap();
        assert!(f.open().is_err());
        f.cleanup();

        let f = Fixture::new();
        let j = f.initialize(record()).unwrap();
        drop(j);
        fs::rename(f.journal_file(), f.journal().join("old.json")).unwrap();
        symlink("old.json", f.journal_file()).unwrap();
        assert!(f.open().is_err());
        f.cleanup();

        let f = Fixture::new();
        let j = f.initialize(record()).unwrap();
        drop(j);
        fs::rename(f.lock(), f.journal().join("old.lock")).unwrap();
        symlink("old.lock", f.lock()).unwrap();
        assert!(f.open().is_err());
        f.cleanup();
    }

    #[test]
    fn jt08_wrong_owner_or_permission_is_refused() {
        let _guard = test_guard();
        let f = Fixture::new();
        let j = f.initialize(record()).unwrap();
        drop(j);

        set_mode(&f.journal(), 0o777);
        assert!(f.open().is_err());
        set_mode(&f.journal(), 0o700);

        set_mode(&f.journal_file(), 0o666);
        assert!(f.open().is_err());
        set_mode(&f.journal_file(), 0o600);

        set_mode(&f.lock(), 0o666);
        assert!(f.open().is_err());
        set_mode(&f.lock(), 0o600);
        assert!(f.open().is_ok());

        set_mode(&f.base, 0o777);
        assert!(JournalStore::for_test(&f.anchor).is_err());
        set_mode(&f.base, 0o700);
        assert!(JournalStore::for_test_with_uid(&f.anchor, uid() + 1).is_err());
        assert!(JournalStore::for_test_with_uid(&f.anchor, uid()).is_ok());
        f.cleanup();
    }

    #[test]
    fn jt09_identity_mismatch_is_refused() {
        let _guard = test_guard();
        let f = Fixture::new();
        let j = f.initialize(record()).unwrap();
        let mut identity = j.identity;
        drop(j);
        identity.anchor_ino = identity.anchor_ino.wrapping_add(1);
        let r = record();
        let data = serde_json::to_vec(&Signed {
            record: &r,
            store: &identity,
        })
        .unwrap();
        let envelope = Envelope {
            record: r,
            store: Some(identity),
            checksum: format!("{:x}", Sha256::digest(&data)),
        };
        fs::write(f.journal_file(), serde_json::to_vec(&envelope).unwrap()).unwrap();
        assert!(f.open().is_err());
        f.cleanup();
    }

    #[test]
    fn production_policy_requires_root_owned_ancestors() {
        let _guard = test_guard();
        let root = fs::metadata("/").unwrap();
        assert!(anchor_component_ok(
            &root,
            false,
            uid(),
            Boundary::AdministratorProtected
        ));
        let f = Fixture::new();
        if uid() != 0 {
            let base = fs::metadata(&f.base).unwrap();
            assert!(!anchor_component_ok(
                &base,
                false,
                uid(),
                Boundary::AdministratorProtected
            ));
        }
        let anchor = fs::metadata(&f.anchor).unwrap();
        assert!(anchor_component_ok(
            &anchor,
            true,
            uid(),
            Boundary::AdministratorProtected
        ));
        f.cleanup();
    }

    #[test]
    fn anchor_permission_change_is_refused() {
        let _guard = test_guard();
        let f = Fixture::new();
        let store = f.store();
        let r = record();
        let a = r.attempt.clone();
        let mut j = store.initialize(r).unwrap();
        set_mode(&f.anchor, 0o777);
        assert!(store.open().is_err());
        assert!(j.advance(&a, State::MayHaveBeenSent, None).is_err());
        drop(j);
        set_mode(&f.anchor, 0o700);
        assert!(store.open().is_ok());
        f.cleanup();
    }

    #[test]
    fn open_does_not_create_or_initialize_missing_state() {
        let _guard = test_guard();
        let f = Fixture::new();
        fs::create_dir(f.journal()).unwrap();
        set_mode(&f.journal(), 0o700);
        assert!(f.open().is_err());
        assert!(!f.journal_file().exists());
        assert!(!f.lock().exists());
        f.cleanup();
    }

    #[test]
    fn initialize_refuses_a_preexisting_pending_file() {
        let _guard = test_guard();
        let f = Fixture::new();
        fs::create_dir(f.journal()).unwrap();
        set_mode(&f.journal(), 0o700);
        fs::write(f.pending(), b"synthetic").unwrap();
        assert!(f.initialize(record()).is_err());
        assert!(!f.journal_file().exists());
        f.cleanup();
    }

    #[test]
    fn a_hardlinked_lock_is_refused() {
        let _guard = test_guard();
        let f = Fixture::new();
        let j = f.initialize(record()).unwrap();
        drop(j);
        fs::hard_link(f.lock(), f.journal().join("second.lock")).unwrap();
        assert!(f.open().is_err());
        f.cleanup();
    }

    #[test]
    fn trusted_uid_is_pinned() {
        let _guard = test_guard();
        let f = Fixture::new();
        let j = f.initialize(record()).unwrap();
        drop(j);
        let metadata = fs::metadata(f.journal_file()).unwrap();
        assert!(trusted(&metadata, false, uid()));
        assert!(!trusted(&metadata, false, uid() + 1));
        // A real foreign-owned inode (not a journal path) exercises the same
        // owner predicate without requiring chown privileges.
        if let Ok(foreign) = fs::metadata("/etc/hosts")
            && foreign.uid() != uid()
        {
            assert!(!trusted(&foreign, false, uid()));
        }
        f.cleanup();
    }

    #[test]
    fn local_filesystem_magic_table() {
        for magic in [
            0xef53,      // ext4
            0x5846_5342, // XFS
            0x0102_1994, // tmpfs
            0x9123_683e, // btrfs
        ] {
            assert!(is_local_filesystem(magic), "0x{magic:x}");
        }
        for magic in [
            0x6969,
            0xff53_4d42,
            0x517b,
            0x6573_5546,
            0x794c_7630,
            0x0102_1997,
            0x5346_414f,
            0xfe53_4d42,
        ] {
            assert!(!is_local_filesystem(magic), "0x{magic:x}");
        }
    }

    #[test]
    fn production_boundary_rejects_test_owned_parent() {
        let _guard = test_guard();
        let f = Fixture::new();
        assert!(JournalStore::for_test_protected(&f.anchor).is_err());
        f.cleanup();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_filesystem_reported_local() {
        let _guard = test_guard();
        let f = Fixture::new();
        let directory = File::open(&f.anchor).unwrap();
        assert!(local_filesystem(&directory));
        let journal = f.initialize(record()).unwrap();
        drop(journal);
        let file = File::open(f.journal_file()).unwrap();
        assert!(local_filesystem(&file));
        f.cleanup();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_directory_fsync_succeeds() {
        let _guard = test_guard();
        let f = Fixture::new();
        let journal = f.initialize(record()).unwrap();
        drop(journal);
        let directory = File::open(f.journal()).unwrap();
        assert!(sync_file(&directory).is_ok());
        f.cleanup();
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires MKG_J4L_NONLOCAL_PATH on an overlayfs/network mount"]
    fn linux_nonlocal_filesystem_rejected() {
        let _guard = test_guard();
        let path = PathBuf::from(
            std::env::var("MKG_J4L_NONLOCAL_PATH")
                .expect("set MKG_J4L_NONLOCAL_PATH to a non-local filesystem path"),
        );
        let file = File::open(&path).unwrap();
        assert!(!local_filesystem(&file));
    }

    #[test]
    #[ignore = "known limitation: no external monotonic anchor detects rollback"]
    fn observed_rollback_to_older_valid_record_is_accepted() {
        let _guard = test_guard();
        let f = Fixture::new();
        let r = record();
        let a = r.attempt.clone();
        let j = f.initialize(r).unwrap();
        let first = fs::read(f.journal_file()).unwrap();
        drop(j);
        let mut j = f.open().unwrap();
        j.advance(&a, State::MayHaveBeenSent, None).unwrap();
        drop(j);
        // Restore the earlier valid envelope from the same store identity.
        fs::write(f.journal_file(), &first).unwrap();
        let j = f.open().unwrap();
        assert_eq!(j.record().state, State::Prepared);
        drop(j);
        f.cleanup();
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires MKG_J4L_PROTECTED_ANCHOR prepared by root"]
    fn linux_protected_anchor_provisioning() {
        let _guard = test_guard();
        let path = PathBuf::from(
            std::env::var("MKG_J4L_PROTECTED_ANCHOR")
                .expect("set MKG_J4L_PROTECTED_ANCHOR to a root-parented anchor"),
        );
        let anchor = fs::metadata(&path).unwrap();
        assert_eq!(anchor.uid(), uid());
        assert_eq!(anchor.mode() & 0o777, 0o700);
        let parent = fs::metadata(path.parent().unwrap()).unwrap();
        assert_eq!(parent.uid(), 0);
        assert_eq!(parent.mode() & 0o022, 0);

        let store = JournalStore::for_test_protected(&path).unwrap();
        let r = record();
        let a = r.attempt.clone();
        let mut journal = store.initialize(r).unwrap();
        journal.advance(&a, State::MayHaveBeenSent, None).unwrap();
        drop(journal);

        let journal = store.open().unwrap();
        assert_eq!(journal.record().state, State::MayHaveBeenSent);
        drop(journal);

        set_mode(&path, 0o777);
        assert!(store.open().is_err());
        set_mode(&path, 0o700);
        let journal = store.open().unwrap();
        assert_eq!(journal.record().state, State::MayHaveBeenSent);
        drop(journal);
        fs::remove_dir_all(path.join(JOURNAL_DIR)).unwrap();
    }

    #[test]
    fn j5_01_initialize_and_open_with_anchor() {
        let _guard = test_guard();
        let f = J5Fixture::new();
        let anchor = f.anchor();
        let store = f.store_with(Arc::clone(&anchor));
        let j = store.initialize(record()).unwrap();
        assert_eq!(j.record().state, State::Prepared);
        assert!(!j.send_authorized());
        drop(j);
        let state = anchor.read().unwrap();
        assert_eq!(state.revision, 1);
        assert_ne!(state.digest, ANCHOR_GENESIS_DIGEST);
        assert_eq!(fs::metadata(f.sidecar()).unwrap().mode() & 0o777, 0o600);
        let j = store.open().unwrap();
        assert_eq!(j.record().state, State::Prepared);
        assert!(!j.send_authorized());
        drop(j);
        assert!(f.legacy_store().open().is_err());
        f.cleanup();
    }

    #[test]
    fn j5_02_advance_with_anchor() {
        let _guard = test_guard();
        let f = J5Fixture::new();
        let anchor = f.anchor();
        let store = f.store_with(Arc::clone(&anchor));
        let r = record();
        let a = r.attempt.clone();
        let j = store.initialize(r).unwrap();
        drop(j);
        let mut j = store.open().unwrap();
        j.advance(&a, State::MayHaveBeenSent, None).unwrap();
        drop(j);
        let state = anchor.read().unwrap();
        assert_eq!(state.revision, 2);
        let j = store.open().unwrap();
        assert_eq!(j.record().state, State::MayHaveBeenSent);
        assert!(!j.send_authorized());
        drop(j);
        f.cleanup();
    }

    #[test]
    fn j5_03_old_record_and_sidecar_rollback_rejected() {
        let _guard = test_guard();
        let f = J5Fixture::new();
        let anchor = f.anchor();
        let store = f.store_with(Arc::clone(&anchor));
        let r = record();
        let a = r.attempt.clone();
        let j = store.initialize(r).unwrap();
        let old_journal = fs::read(f.journal_file()).unwrap();
        let old_sidecar = fs::read(f.sidecar()).unwrap();
        drop(j);
        let mut j = store.open().unwrap();
        j.advance(&a, State::MayHaveBeenSent, None).unwrap();
        drop(j);
        fs::write(f.journal_file(), old_journal).unwrap();
        fs::write(f.sidecar(), old_sidecar).unwrap();
        assert!(store.open().is_err());
        f.cleanup();
    }

    #[test]
    fn j5_04_anchor_only_progress_rejected() {
        let _guard = test_guard();
        let f = J5Fixture::new();
        let anchor = f.anchor();
        let store = f.store_with(Arc::clone(&anchor));
        let j = store.initialize(record()).unwrap();
        drop(j);
        let state = anchor.read().unwrap();
        anchor.advance(&state, &"1".repeat(64)).unwrap();
        assert!(store.open().is_err());
        f.cleanup();
    }

    #[test]
    fn j5_05_anchor_rollback_journal_ahead_rejected() {
        let _guard = test_guard();
        let f = J5Fixture::new();
        let anchor = f.anchor();
        let store = f.store_with(Arc::clone(&anchor));
        let r = record();
        let a = r.attempt.clone();
        let j = store.initialize(r).unwrap();
        let old_state = anchor.read().unwrap();
        drop(j);
        let mut j = store.open().unwrap();
        j.advance(&a, State::MayHaveBeenSent, None).unwrap();
        drop(j);
        anchor.set_state(&old_state);
        assert!(store.open().is_err());
        f.cleanup();
    }

    #[test]
    fn j5_06_anchor_unavailable_fails_closed() {
        let _guard = test_guard();
        let f = J5Fixture::new();
        let anchor = f.anchor();
        let store = f.store_with(Arc::clone(&anchor));
        let j = store.initialize(record()).unwrap();
        drop(j);
        anchor.set_unavailable(true);
        assert!(store.open().is_err());
        anchor.set_unavailable(false);
        assert!(store.open().is_ok());
        f.cleanup();
    }

    #[test]
    fn j5_07_sidecar_missing_or_pending_rejected() {
        let _guard = test_guard();
        let f = J5Fixture::new();
        let store = f.store();
        let j = store.initialize(record()).unwrap();
        drop(j);
        fs::rename(f.sidecar(), f.base.join("sidecar.saved")).unwrap();
        assert!(store.open().is_err());
        fs::rename(f.base.join("sidecar.saved"), f.sidecar()).unwrap();
        fs::write(f.sidecar_pending(), b"pending").unwrap();
        assert!(store.open().is_err());
        fs::remove_file(f.sidecar_pending()).unwrap();
        assert!(store.open().is_ok());
        f.cleanup();
    }

    #[test]
    fn j5_08_journal_dir_loss_cannot_reinitialize() {
        let _guard = test_guard();
        let f = J5Fixture::new();
        let store = f.store();
        let j = store.initialize(record()).unwrap();
        drop(j);
        fs::remove_dir_all(f.journal()).unwrap();
        assert!(store.open().is_err());
        assert!(store.initialize(record()).is_err());
        assert!(!f.journal_file().exists());
        f.cleanup();
    }

    #[test]
    fn j5_09_legacy_and_j5_modes_do_not_cross_open() {
        let _guard = test_guard();
        let legacy = Fixture::new();
        let j = legacy.initialize(record()).unwrap();
        drop(j);
        let legacy_anchor = J5Fixture::new();
        let j = legacy_anchor.store().initialize(record()).unwrap();
        drop(j);
        assert!(legacy_anchor.legacy_store().open().is_err());
        // Removing the sidecar must not downgrade the journal to legacy mode.
        fs::remove_file(legacy_anchor.sidecar()).unwrap();
        assert!(legacy_anchor.legacy_store().open().is_err());
        assert!(legacy_anchor.store().open().is_err());
        let empty = J5Fixture::new();
        assert!(empty.store().open().is_err());
        // A J5 store cannot adopt an unanchored legacy journal.
        let j5_on_legacy = J5Fixture::from_base(legacy.base.clone());
        assert!(j5_on_legacy.store().open().is_err());
        assert!(j5_on_legacy.store().initialize(record()).is_err());
        legacy.cleanup();
        legacy_anchor.cleanup();
        empty.cleanup();
    }

    #[test]
    fn j5_10_fault_after_anchor_denies_reopen() {
        let _guard = test_guard();
        let f = J5Fixture::new();
        let anchor = f.anchor();
        let store = f.store_with(Arc::clone(&anchor));
        let r = record();
        let a = r.attempt.clone();
        let j = store.initialize(r).unwrap();
        drop(j);
        let mut j = store.open().unwrap();
        INJECT.with(|value| value.set(1));
        assert!(j.advance(&a, State::MayHaveBeenSent, None).is_err());
        INJECT.with(|value| value.set(0));
        drop(j);
        assert_eq!(anchor.read().unwrap().revision, 2);
        assert!(store.open().is_err());
        f.cleanup();
    }

    #[test]
    fn j5_11_anchor_failure_before_journal_keeps_old_state() {
        let _guard = test_guard();
        let f = J5Fixture::new();
        let anchor = f.anchor();
        let store = f.store_with(Arc::clone(&anchor));
        let r = record();
        let a = r.attempt.clone();
        let j = store.initialize(r).unwrap();
        drop(j);
        let mut j = store.open().unwrap();
        anchor.fail_next_advance();
        assert!(j.advance(&a, State::MayHaveBeenSent, None).is_err());
        drop(j);
        assert_eq!(anchor.read().unwrap().revision, 1);
        assert!(store.open().is_ok());
        f.cleanup();
    }

    const CHILD_J5_WRITER: &str = "gce_operation_journal::tests::j5_child_writer";
    const CHILD_J5_CONTENDER: &str = "gce_operation_journal::tests::j5_child_contender";
    const CHILD_J5_CRASH: &str = "gce_operation_journal::tests::j5_crash_child";

    fn j5_child_fixture() -> Option<J5Fixture> {
        std::env::var("MKG_J5_BASE")
            .ok()
            .map(|base| J5Fixture::from_base(PathBuf::from(base)))
    }

    fn spawn_j5_child(
        test: &str,
        fixture: &J5Fixture,
        action: &str,
        paths: &[(&str, &Path)],
    ) -> Child {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", test, "--nocapture"])
            .env("MKG_J5_BASE", &fixture.base)
            .env("MKG_J5_ACTION", action)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        for (key, path) in paths {
            command.env(key, path);
        }
        command.spawn().unwrap()
    }

    struct J5Writer {
        child: Child,
        go: PathBuf,
        done: PathBuf,
    }

    impl Drop for J5Writer {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn start_j5_writer(fixture: &J5Fixture, action: &str) -> J5Writer {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let prefix = format!("{action}-{}", NEXT.fetch_add(1, Ordering::Relaxed));
        let ready = fixture.base.join(format!("{prefix}.ready"));
        let go = fixture.base.join(format!("{prefix}.go"));
        let done = fixture.base.join(format!("{prefix}.done"));
        make_fifo(&ready);
        make_fifo(&go);
        make_fifo(&done);
        let child = spawn_j5_child(
            CHILD_J5_WRITER,
            fixture,
            action,
            &[
                ("MKG_J5_READY", &ready),
                ("MKG_J5_GO", &go),
                ("MKG_J5_DONE", &done),
            ],
        );
        assert_eq!(read_fifo(&ready), b'R');
        J5Writer { child, go, done }
    }

    fn finish_j5_writer(writer: &mut J5Writer) -> u8 {
        write_fifo(&writer.go, b'G');
        let result = read_fifo(&writer.done);
        assert!(writer.child.wait().unwrap().success());
        result
    }

    fn run_j5_contender(fixture: &J5Fixture, action: &str) -> bool {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let done = fixture.base.join(format!(
            "j5-contender-{action}-{}.done",
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        make_fifo(&done);
        let mut child = spawn_j5_child(
            CHILD_J5_CONTENDER,
            fixture,
            action,
            &[("MKG_J5_DONE", &done)],
        );
        let result = read_fifo(&done);
        assert!(child.wait().unwrap().success());
        result == b'1'
    }

    #[test]
    fn j5_child_writer() {
        let Some(fixture) = j5_child_fixture() else {
            return;
        };
        let action = std::env::var("MKG_J5_ACTION").unwrap();
        let ready = PathBuf::from(std::env::var("MKG_J5_READY").unwrap());
        let go = PathBuf::from(std::env::var("MKG_J5_GO").unwrap());
        let done = PathBuf::from(std::env::var("MKG_J5_DONE").unwrap());
        let mut journal = match action.as_str() {
            "initialize" => fixture.store().initialize(record()).unwrap(),
            "open" => fixture.store().open().unwrap(),
            other => panic!("unknown J5 writer action {other}"),
        };
        write_fifo(&ready, b'R');
        let _ = read_fifo(&go);
        let result = journal.advance(&record().attempt, State::MayHaveBeenSent, None);
        write_fifo(&done, if result.is_err() { b'0' } else { b'1' });
    }

    #[test]
    fn j5_child_contender() {
        let Some(fixture) = j5_child_fixture() else {
            return;
        };
        let action = std::env::var("MKG_J5_ACTION").unwrap();
        let done = PathBuf::from(std::env::var("MKG_J5_DONE").unwrap());
        let result = match action.as_str() {
            "open" => fixture.store().open().map(|_| ()),
            "initialize" => fixture.store().initialize(record()).map(|_| ()),
            other => panic!("unknown J5 contender action {other}"),
        };
        write_fifo(&done, if result.is_ok() { b'1' } else { b'0' });
    }

    #[test]
    fn j5_crash_child() {
        let Some(fixture) = j5_child_fixture() else {
            return;
        };
        let action = std::env::var("MKG_J5_ACTION").unwrap();
        let store = fixture.store();
        match action.as_str() {
            "initialize" => {
                let _ = store.initialize(record()).unwrap();
            }
            "advance" => {
                let mut journal = store.open().unwrap();
                journal
                    .advance(&record().attempt, State::MayHaveBeenSent, None)
                    .unwrap();
            }
            other => panic!("unknown J5 crash action {other}"),
        }
    }

    #[test]
    fn j5_12_crash_windows_after_anchor_journal_checkpoint() {
        let _guard = test_guard();
        for action in ["initialize", "advance"] {
            for point in ["after_anchor", "after_journal", "after_checkpoint"] {
                let f = J5Fixture::new();
                if action == "advance" {
                    let j = f.store().initialize(record()).unwrap();
                    drop(j);
                }
                let status = Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", CHILD_J5_CRASH, "--nocapture"])
                    .env("MKG_J5_BASE", &f.base)
                    .env("MKG_J5_ACTION", action)
                    .env("MKG_J5_CRASH_POINT", point)
                    .status()
                    .unwrap();
                assert_eq!(status.signal(), Some(libc::SIGKILL), "{action}/{point}");
                let store = f.store();
                let opened = store.open();
                match point {
                    "after_checkpoint" => {
                        let j = opened.unwrap();
                        if action == "initialize" {
                            assert_eq!(j.record().state, State::Prepared);
                        } else {
                            assert_eq!(j.record().state, State::MayHaveBeenSent);
                        }
                        assert!(!j.send_authorized());
                    }
                    "after_anchor" | "after_journal" => {
                        assert!(opened.is_err(), "{action}/{point} must fail closed");
                    }
                    _ => unreachable!(),
                }
                f.cleanup();
            }
        }
    }

    #[test]
    fn j5_13_double_writer_with_anchor() {
        let _guard = test_guard();
        let f = J5Fixture::new();
        let mut a = start_j5_writer(&f, "initialize");
        assert!(!run_j5_contender(&f, "open"));
        assert_eq!(finish_j5_writer(&mut a), b'1');
        assert!(run_j5_contender(&f, "open"));
        f.cleanup();
    }

    #[test]
    fn j5_14_sidecar_corruption_rejected() {
        let _guard = test_guard();
        let f = J5Fixture::new();
        let store = f.store();
        let j = store.initialize(record()).unwrap();
        drop(j);
        fs::write(f.sidecar(), b"not-json").unwrap();
        assert!(store.open().is_err());
        f.cleanup();
    }

    #[test]
    fn j5_15_anchor_corruption_rejected() {
        let _guard = test_guard();
        let f = J5Fixture::new();
        let store = f.store();
        let j = store.initialize(record()).unwrap();
        drop(j);
        fs::write(&f.anchor_path, b"not-json").unwrap();
        assert!(store.open().is_err());
        f.cleanup();
    }

    #[test]
    fn j5_16_sidecar_identity_mismatch_rejected() {
        let _guard = test_guard();
        let f = J5Fixture::new();
        let store = f.store();
        let j = store.initialize(record()).unwrap();
        drop(j);
        let mut envelope: AnchorCheckpointEnvelope =
            serde_json::from_slice(&fs::read(f.sidecar()).unwrap()).unwrap();
        envelope.identity = AnchorIdentity::from_hex("f".repeat(64)).unwrap();
        envelope.checksum =
            anchor_checkpoint_checksum(&envelope.identity, envelope.revision, &envelope.digest)
                .unwrap();
        fs::write(f.sidecar(), serde_json::to_vec(&envelope).unwrap()).unwrap();
        assert!(store.open().is_err());
        f.cleanup();
    }

    #[test]
    fn j5_17_checkpoint_only_progress_rejected() {
        let _guard = test_guard();
        let f = J5Fixture::new();
        let anchor = f.anchor();
        let store = f.store_with(Arc::clone(&anchor));
        let j = store.initialize(record()).unwrap();
        let identity = j.identity;
        let record = j.record().clone();
        drop(j);
        let next_record = record
            .transition(&record.attempt, State::MayHaveBeenSent, None)
            .unwrap();
        let meta = AnchorMetadata {
            identity: j5_identity(),
            revision: 2,
            digest: anchor_digest(&next_record, &identity, &j5_identity(), 2).unwrap(),
        };
        let dir = File::open(f.journal()).unwrap();
        write_anchor_checkpoint(&dir, &meta, false, uid()).unwrap();
        assert!(store.open().is_err());
        f.cleanup();
    }

    #[test]
    #[ignore = "fake-only joint rollback observation; real external anchor is required"]
    fn j5_18_joint_journal_and_anchor_rollback_is_not_detected() {
        // Observation of the fake-only limitation. A real external monotonic
        // anchor cannot be rolled back together with the journal.
        let _guard = test_guard();
        let f = J5Fixture::new();
        let anchor = f.anchor();
        let store = f.store_with(Arc::clone(&anchor));
        let j = store.initialize(record()).unwrap();
        let old_journal = fs::read(f.journal_file()).unwrap();
        let old_sidecar = fs::read(f.sidecar()).unwrap();
        let old_state = anchor.read().unwrap();
        drop(j);
        let mut j = store.open().unwrap();
        j.advance(&record().attempt, State::MayHaveBeenSent, None)
            .unwrap();
        drop(j);
        fs::write(f.journal_file(), old_journal).unwrap();
        fs::write(f.sidecar(), old_sidecar).unwrap();
        anchor.set_state(&old_state);
        let j = store.open().unwrap();
        assert_eq!(j.record().state, State::Prepared);
        drop(j);
        f.cleanup();
    }

    #[test]
    fn j5_19_fault_points_fail_closed_or_commit_observable() {
        let _guard = test_guard();
        for point in 1..=9 {
            let f = J5Fixture::new();
            let anchor = f.anchor();
            let store = f.store_with(Arc::clone(&anchor));
            let j = store.initialize(record()).unwrap();
            drop(j);
            let mut j = store.open().unwrap();
            INJECT.with(|value| value.set(point));
            let advanced = j.advance(&record().attempt, State::MayHaveBeenSent, None);
            INJECT.with(|value| value.set(0));
            assert!(advanced.is_err(), "point {point}");
            drop(j);
            assert_eq!(anchor.read().unwrap().revision, 2, "point {point}");
            match store.open() {
                Ok(j) => {
                    assert_eq!(j.record().state, State::MayHaveBeenSent, "point {point}");
                    assert!(!j.send_authorized());
                }
                Err(()) => {
                    // Expected for points before the sidecar commit.
                }
            }
            f.cleanup();
        }
    }

    #[test]
    fn j5_20_journal_directory_rollback_rejected() {
        let _guard = test_guard();
        let f = J5Fixture::new();
        let anchor = f.anchor();
        let store = f.store_with(Arc::clone(&anchor));
        let j = store.initialize(record()).unwrap();
        let old_dir = f.base.join("journal.old");
        fs::create_dir(&old_dir).unwrap();
        for name in [JOURNAL_FILE, ANCHOR_FILE, LOCK_FILE] {
            fs::copy(f.journal().join(name), old_dir.join(name)).unwrap();
        }
        drop(j);
        let mut j = store.open().unwrap();
        j.advance(&record().attempt, State::MayHaveBeenSent, None)
            .unwrap();
        drop(j);
        fs::remove_dir_all(f.journal()).unwrap();
        fs::rename(&old_dir, f.journal()).unwrap();
        assert!(store.open().is_err());
        assert!(store.initialize(record()).is_err());
        f.cleanup();
    }

    #[test]
    fn j5_21_send_authorized_is_always_false() {
        let _guard = test_guard();
        let f = J5Fixture::new();
        let store = f.store();
        let j = store.initialize(record()).unwrap();
        assert!(!j.record().send_authorized());
        assert!(!j.send_authorized());
        drop(j);
        let mut j = store.open().unwrap();
        j.advance(&record().attempt, State::MayHaveBeenSent, None)
            .unwrap();
        assert!(!j.record().send_authorized());
        assert!(!j.send_authorized());
        drop(j);
        let j = store.open().unwrap();
        assert!(!j.send_authorized());
        drop(j);
        f.cleanup();
    }

    #[test]
    fn j5_22_pending_with_anchor_fails_closed() {
        let _guard = test_guard();
        let f = J5Fixture::new();
        let store = f.store();
        let j = store.initialize(record()).unwrap();
        drop(j);
        fs::write(f.journal().join(PENDING_FILE), b"synthetic").unwrap();
        assert!(store.open().is_err());
        fs::remove_file(f.journal().join(PENDING_FILE)).unwrap();
        assert!(store.open().is_ok());
        f.cleanup();
    }

    #[test]
    fn j5_23_anchor_unavailable_during_initialize() {
        let _guard = test_guard();
        let f = J5Fixture::new();
        let anchor = f.anchor();
        let store = f.store_with(Arc::clone(&anchor));
        anchor.set_unavailable(true);
        assert!(store.initialize(record()).is_err());
        assert!(!f.journal_file().exists());
        anchor.set_unavailable(false);
        assert!(store.initialize(record()).is_ok());
        f.cleanup();
    }

    #[test]
    fn j5_24_anchor_progress_while_open_poisoned() {
        let _guard = test_guard();
        let f = J5Fixture::new();
        let anchor = f.anchor();
        let store = f.store_with(Arc::clone(&anchor));
        let j = store.initialize(record()).unwrap();
        drop(j);
        let mut j = store.open().unwrap();
        let state = anchor.read().unwrap();
        anchor.advance(&state, &"2".repeat(64)).unwrap();
        assert!(
            j.advance(&record().attempt, State::MayHaveBeenSent, None)
                .is_err()
        );
        drop(j);
        assert!(store.open().is_err());
        f.cleanup();
    }

    #[test]
    fn j5_25_anchor_cas_conflict() {
        let _guard = test_guard();
        let f = J5Fixture::new();
        let anchor = f.anchor();
        let state = anchor.read().unwrap();
        let next = anchor.advance(&state, &"3".repeat(64)).unwrap();
        assert_eq!(next.revision, 1);
        assert_eq!(
            anchor.advance(&state, &"4".repeat(64)),
            Err(AnchorError::Conflict)
        );
        f.cleanup();
    }

    struct IdentityMismatchAnchor {
        inner: Arc<FileAnchor>,
        identity: AnchorIdentity,
    }

    impl IntoExternal for Arc<IdentityMismatchAnchor> {
        fn into_external(self) -> ExternalAnchor {
            ExternalAnchor::Legacy(self)
        }
    }

    impl MonotonicAnchor for IdentityMismatchAnchor {
        fn identity(&self) -> AnchorIdentity {
            self.identity.clone()
        }

        fn read(&self) -> Result<AnchorState, AnchorError> {
            self.inner.read()
        }

        fn begin_session(&self) -> Result<AnchorState, AnchorError> {
            self.inner.begin_session()
        }

        fn advance(
            &self,
            expected: &AnchorState,
            next_digest: &str,
        ) -> Result<AnchorState, AnchorError> {
            self.inner.advance(expected, next_digest)
        }
    }

    #[test]
    fn j5_26_backend_identity_mismatch_rejected() {
        let _guard = test_guard();
        let f = J5Fixture::new();
        let anchor = f.anchor();
        let store = f.store_with(Arc::clone(&anchor));
        let j = store.initialize(record()).unwrap();
        drop(j);
        let wrong = Arc::new(IdentityMismatchAnchor {
            inner: Arc::clone(&anchor),
            identity: AnchorIdentity::from_hex("e".repeat(64)).unwrap(),
        });
        let wrong_store = f.store_with_proxy(wrong);
        assert!(wrong_store.open().is_err());
        f.cleanup();
    }

    #[test]
    fn j5_28_legacy_store_identity_serialization_is_unchanged() {
        let _guard = test_guard();
        let f = Fixture::new();
        let j = f.initialize(record()).unwrap();
        drop(j);
        let text = fs::read_to_string(f.journal_file()).unwrap();
        assert!(!text.contains("anchor_required"));
        assert!(f.open().is_ok());
        f.cleanup();
    }

    #[test]
    fn j5_27_anchor_ahead_blocks_initialize() {
        let _guard = test_guard();
        let f = J5Fixture::new();
        let anchor = f.anchor();
        let store = f.store_with(Arc::clone(&anchor));
        let state = anchor.read().unwrap();
        anchor.advance(&state, &"5".repeat(64)).unwrap();
        assert!(store.initialize(record()).is_err());
        assert!(!f.journal_file().exists());
        f.cleanup();
    }

    #[test]
    fn j6_01_initial_cas_and_journal_integration() {
        let _guard = test_guard();
        let f = CasFixture::new();
        let client = f.client();
        let initial = client.read().unwrap();
        assert_eq!(initial.revision, 0);
        assert_eq!(initial.digest, ANCHOR_GENESIS_DIGEST);
        let next = client.advance(&initial, &"a".repeat(64)).unwrap();
        assert_eq!(next.revision, 1);
        let state = client.read().unwrap();
        assert_eq!(state, next);
        f.cleanup();

        let g = CasFixture::new();
        let store = g.store();
        let j = store.initialize(record()).unwrap();
        assert_eq!(j.record().state, State::Prepared);
        assert!(!j.send_authorized());
        drop(j);
        assert_eq!(g.client().read().unwrap().revision, 1);
        assert!(store.open().is_ok());
        g.cleanup();
    }

    #[test]
    fn j6_02_same_revision_conflict() {
        let _guard = test_guard();
        let f = CasFixture::new();
        let a = f.client();
        let b = f.client();
        let state = a.read().unwrap();
        a.advance(&state, &"a".repeat(64)).unwrap();
        assert_eq!(
            b.advance(&state, &"b".repeat(64)),
            Err(AnchorError::Conflict)
        );
        f.cleanup();
    }

    #[test]
    fn j6_03_old_revision_rejected() {
        let _guard = test_guard();
        let f = CasFixture::new();
        let client = f.client();
        let state = client.read().unwrap();
        client.advance(&state, &"a".repeat(64)).unwrap();
        assert_eq!(
            client.advance(&state, &"b".repeat(64)),
            Err(AnchorError::Conflict)
        );
        f.cleanup();
    }

    #[test]
    fn j6_04_invalid_digest_rejected() {
        let _guard = test_guard();
        let f = CasFixture::new();
        let client = f.client();
        let state = client.read().unwrap();
        assert!(client.advance(&state, "not-a-digest").is_err());
        assert_eq!(client.read().unwrap().revision, 0);
        f.cleanup();
    }

    #[test]
    fn j6_05_identity_mismatch_rejected() {
        let _guard = test_guard();
        let f = CasFixture::new();
        let wrong = Arc::new(
            CasAnchor::new(
                f.socket.clone(),
                AnchorIdentity::from_hex("f".repeat(64)).unwrap(),
                f.token.clone(),
                Duration::from_millis(1_000),
            )
            .unwrap(),
        );
        assert_eq!(wrong.read(), Err(AnchorError::Corrupt));
        f.cleanup();
    }

    #[test]
    fn j6_16_cas_server_restart_preserves_state() {
        let _guard = test_guard();
        let mut f = CasFixture::new();
        let client = f.client();
        let state = client.read().unwrap();
        client.advance(&state, &"a".repeat(64)).unwrap();
        f.stop_server();
        f.restart(&[]);
        let state = f.client().read().unwrap();
        assert_eq!(state.revision, 1);
        assert_eq!(state.digest, "a".repeat(64));
        f.cleanup();
    }

    #[test]
    fn j6_19_auth_rejected() {
        let _guard = test_guard();
        let f = CasFixture::new();
        let wrong = Arc::new(
            CasAnchor::new(
                f.socket.clone(),
                f.identity.clone(),
                "00".repeat(32),
                Duration::from_millis(1_000),
            )
            .unwrap(),
        );
        assert_eq!(wrong.read(), Err(AnchorError::Unauthorized));
        f.cleanup();
    }

    #[test]
    fn j6_22_revision_overflow_rejected() {
        let _guard = test_guard();
        let f = CasFixture::new_with_env(&[("MKG_CAS_INITIAL_REVISION", u64::MAX.to_string())]);
        let client = f.client();
        let state = client.read().unwrap();
        assert_eq!(state.revision, u64::MAX);
        assert_eq!(
            client.advance(&state, &"a".repeat(64)),
            Err(AnchorError::Exhausted)
        );
        f.cleanup();
    }

    #[test]
    fn j6_06_crash_before_cas_commit() {
        let _guard = test_guard();
        let mut f = CasFixture::new();
        let state = f.client().read().unwrap();
        f.restart(&[("MKG_CAS_CRASH_AT", "before_commit".to_string())]);
        assert_eq!(
            f.client().advance(&state, &"a".repeat(64)),
            Err(AnchorError::Unknown)
        );
        f.stop_server();
        f.restart(&[]);
        assert_eq!(f.client().read().unwrap().revision, 0);
        f.cleanup();
    }

    #[test]
    fn j6_07_crash_during_cas_commit() {
        let _guard = test_guard();
        let mut f = CasFixture::new();
        let state = f.client().read().unwrap();
        f.restart(&[("MKG_CAS_CRASH_AT", "during_commit".to_string())]);
        assert_eq!(
            f.client().advance(&state, &"a".repeat(64)),
            Err(AnchorError::Unknown)
        );
        f.stop_server();
        f.restart(&[]);
        assert_eq!(f.client().read().unwrap().revision, 0);
        f.cleanup();
    }

    #[test]
    fn j6_08_crash_after_durable_commit_before_response() {
        let _guard = test_guard();
        let mut f = CasFixture::new();
        let state = f.client().read().unwrap();
        f.restart(&[("MKG_CAS_CRASH_AT", "after_commit".to_string())]);
        assert_eq!(
            f.client().advance(&state, &"a".repeat(64)),
            Err(AnchorError::Unknown)
        );
        f.stop_server();
        f.restart(&[]);
        let observed = f.client().read().unwrap();
        assert_eq!(observed.revision, 1);
        assert_eq!(observed.digest, "a".repeat(64));
        f.cleanup();
    }

    #[test]
    fn j6_09_timeout_then_reobserve() {
        let _guard = test_guard();
        let mut f = CasFixture::new();
        let state = f.client().read().unwrap();
        f.restart(&[("MKG_CAS_DELAY_MS", "250".to_string())]);
        let client = f.client_with_timeout(50);
        assert_eq!(
            client.advance(&state, &"a".repeat(64)),
            Err(AnchorError::Unknown)
        );
        f.stop_server();
        f.restart(&[]);
        assert_eq!(f.client().read().unwrap().revision, 1);
        f.cleanup();
    }

    #[test]
    fn j6_10_old_or_wrong_request_id_rejected() {
        let _guard = test_guard();
        let mut f = CasFixture::new();
        let state = f.client().read().unwrap();
        f.restart(&[("MKG_CAS_WRONG_REQUEST_ID", "1".to_string())]);
        assert_eq!(
            f.client().advance(&state, &"a".repeat(64)),
            Err(AnchorError::Protocol)
        );
        assert_eq!(f.client().read().unwrap().revision, 1);
        f.cleanup();
    }

    #[test]
    fn j6_23_unknown_result_does_not_retry_or_advance_journal() {
        let _guard = test_guard();
        J9A_EXTERNAL_READ.store(false, std::sync::atomic::Ordering::SeqCst);
        J9A_EXTERNAL_MISMATCH.store(false, std::sync::atomic::Ordering::SeqCst);
        let mut f = CasFixture::new();
        let store = f.store();
        let j = store.initialize(record()).unwrap();
        drop(j);
        let old_state = f.client().read().unwrap();
        f.restart(&[("MKG_CAS_DROP_RESPONSE", "1".to_string())]);
        let mut j = store.open().unwrap();
        assert_eq!(
            j.advance(&record().attempt, State::MayHaveBeenSent, None),
            Err(())
        );
        drop(j);
        // The anchor committed, but the journal did not. The client must not retry
        // blindly; a retry with the old expected state conflicts.
        assert_eq!(f.client().read().unwrap().revision, old_state.revision + 1);
        assert_eq!(
            f.client().advance(&old_state, &"b".repeat(64)),
            Err(AnchorError::Conflict)
        );
        assert!(store.open().is_err());
        f.restart(&[]);
        assert!(store.open().is_err());
        f.cleanup();
    }

    struct CasClientHandle {
        child: Child,
        go: PathBuf,
        done: PathBuf,
    }

    impl Drop for CasClientHandle {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn start_cas_client(fixture: &CasFixture, digest: &str) -> CasClientHandle {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let prefix = format!("cas-client-{}", NEXT.fetch_add(1, Ordering::Relaxed));
        let ready = fixture.base.join(format!("{prefix}.ready"));
        let go = fixture.base.join(format!("{prefix}.go"));
        let done = fixture.base.join(format!("{prefix}.done"));
        make_fifo(&ready);
        make_fifo(&go);
        make_fifo(&done);
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CHILD_CAS_CLIENT, "--nocapture"])
            .env("MKG_CAS_SOCKET", &fixture.socket)
            .env("MKG_CAS_IDENTITY", fixture.identity.as_str())
            .env("MKG_CAS_TOKEN", &fixture.token)
            .env("MKG_CAS_READY", &ready)
            .env("MKG_CAS_GO", &go)
            .env("MKG_CAS_DONE", &done)
            .env("MKG_CAS_NEXT_DIGEST", digest)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        assert_eq!(read_fifo(&ready), b'R');
        CasClientHandle { child, go, done }
    }

    #[test]
    fn j6_cas_client_child() {
        let Ok(socket) = std::env::var("MKG_CAS_SOCKET") else {
            return;
        };
        let identity =
            AnchorIdentity::from_hex(std::env::var("MKG_CAS_IDENTITY").unwrap()).unwrap();
        let token = std::env::var("MKG_CAS_TOKEN").unwrap();
        let ready = PathBuf::from(std::env::var("MKG_CAS_READY").unwrap());
        let go = PathBuf::from(std::env::var("MKG_CAS_GO").unwrap());
        let done = PathBuf::from(std::env::var("MKG_CAS_DONE").unwrap());
        let digest = std::env::var("MKG_CAS_NEXT_DIGEST").unwrap();
        let client = CasAnchor::new(
            PathBuf::from(socket),
            identity,
            token,
            Duration::from_millis(2_000),
        )
        .unwrap();
        let state = client.read().unwrap();
        write_fifo(&ready, b'R');
        let _ = read_fifo(&go);
        let result = client.advance(&state, &digest);
        let code = match result {
            Ok(_) => b'1',
            Err(AnchorError::Conflict) => b'0',
            Err(_) => b'9',
        };
        write_fifo(&done, code);
    }

    #[test]
    fn j6_11_two_process_cas_race() {
        let _guard = test_guard();
        let f = CasFixture::new();
        let mut a = start_cas_client(&f, &"c".repeat(64));
        let mut b = start_cas_client(&f, &"d".repeat(64));
        write_fifo(&a.go, b'G');
        write_fifo(&b.go, b'G');
        let result_a = read_fifo(&a.done);
        let result_b = read_fifo(&b.done);
        assert!(a.child.wait().unwrap().success());
        assert!(b.child.wait().unwrap().success());
        let mut results = [result_a, result_b];
        results.sort();
        assert_eq!(results, [b'0', b'1']);
        assert_eq!(f.client().read().unwrap().revision, 1);
        f.cleanup();
    }

    #[test]
    fn j6_13_journal_only_rollback_rejected_with_cas() {
        let _guard = test_guard();
        let f = CasFixture::new();
        let store = f.store();
        let j = store.initialize(record()).unwrap();
        let old_journal = fs::read(f.journal_file()).unwrap();
        drop(j);
        let mut j = store.open().unwrap();
        j.advance(&record().attempt, State::MayHaveBeenSent, None)
            .unwrap();
        drop(j);
        fs::write(f.journal_file(), old_journal).unwrap();
        assert!(store.open().is_err());
        f.cleanup();
    }

    #[test]
    fn j6_14_journal_and_sidecar_rollback_rejected_with_cas() {
        let _guard = test_guard();
        let f = CasFixture::new();
        let store = f.store();
        let j = store.initialize(record()).unwrap();
        let old_journal = fs::read(f.journal_file()).unwrap();
        let old_sidecar = fs::read(f.sidecar()).unwrap();
        drop(j);
        let mut j = store.open().unwrap();
        j.advance(&record().attempt, State::MayHaveBeenSent, None)
            .unwrap();
        drop(j);
        fs::write(f.journal_file(), old_journal).unwrap();
        fs::write(f.sidecar(), old_sidecar).unwrap();
        assert!(store.open().is_err());
        f.cleanup();
    }

    #[test]
    fn j6_17_cas_state_rollback_rejected_by_journal_ahead() {
        let _guard = test_guard();
        J9A_EXTERNAL_READ.store(false, std::sync::atomic::Ordering::SeqCst);
        J9A_EXTERNAL_MISMATCH.store(false, std::sync::atomic::Ordering::SeqCst);
        let mut f = CasFixture::new();
        let store = f.store();
        let j = store.initialize(record()).unwrap();
        let old_state = fs::read(&f.state).unwrap();
        drop(j);
        let mut j = store.open().unwrap();
        j.advance(&record().attempt, State::MayHaveBeenSent, None)
            .unwrap();
        drop(j);
        f.stop_server();
        fs::write(&f.state, old_state).unwrap();
        f.restart(&[]);
        assert_eq!(f.client().read().unwrap().revision, 1);
        assert!(store.open().is_err());
        f.cleanup();
    }

    #[test]
    fn j6_18_server_stopped_fails_closed() {
        let _guard = test_guard();
        J9A_EXTERNAL_READ.store(false, std::sync::atomic::Ordering::SeqCst);
        J9A_EXTERNAL_MISMATCH.store(false, std::sync::atomic::Ordering::SeqCst);
        let mut f = CasFixture::new();
        let store = f.store();
        let j = store.initialize(record()).unwrap();
        f.stop_server();
        assert!(store.open().is_err());
        let mut j = j;
        assert!(
            j.advance(&record().attempt, State::MayHaveBeenSent, None)
                .is_err()
        );
        assert!(!j.send_authorized());
        drop(j);
        f.cleanup();
    }

    #[test]
    fn j6_20_legacy_downgrade_rejected_with_cas() {
        let _guard = test_guard();
        let f = CasFixture::new();
        let store = f.store();
        let j = store.initialize(record()).unwrap();
        drop(j);
        fs::remove_file(f.sidecar()).unwrap();
        assert!(f.legacy_store().open().is_err());
        assert!(store.open().is_err());
        f.cleanup();
    }

    #[test]
    fn j6_21_pending_rejected_with_cas() {
        let _guard = test_guard();
        let f = CasFixture::new();
        let store = f.store();
        let j = store.initialize(record()).unwrap();
        drop(j);
        fs::write(f.journal().join(PENDING_FILE), b"pending").unwrap();
        assert!(store.open().is_err());
        fs::remove_file(f.journal().join(PENDING_FILE)).unwrap();
        assert!(store.open().is_ok());
        f.cleanup();
    }

    #[test]
    fn j6_24_send_authorized_false_with_cas() {
        let _guard = test_guard();
        let f = CasFixture::new();
        let store = f.store();
        let j = store.initialize(record()).unwrap();
        assert!(!j.send_authorized());
        drop(j);
        let mut j = store.open().unwrap();
        j.advance(&record().attempt, State::MayHaveBeenSent, None)
            .unwrap();
        assert!(!j.record().send_authorized());
        assert!(!j.send_authorized());
        drop(j);
        f.cleanup();
    }

    #[test]
    fn j6_04b_sidecar_digest_mismatch_rejected_with_cas() {
        let _guard = test_guard();
        let f = CasFixture::new();
        let store = f.store();
        let j = store.initialize(record()).unwrap();
        drop(j);
        let mut envelope: AnchorCheckpointEnvelope =
            serde_json::from_slice(&fs::read(f.sidecar()).unwrap()).unwrap();
        envelope.digest = "e".repeat(64);
        envelope.checksum =
            anchor_checkpoint_checksum(&envelope.identity, envelope.revision, &envelope.digest)
                .unwrap();
        fs::write(f.sidecar(), serde_json::to_vec(&envelope).unwrap()).unwrap();
        assert!(store.open().is_err());
        f.cleanup();
    }

    #[test]
    #[ignore = "observation: CAS state + journal + sidecar rolled back together is not detectable without an external superior anchor"]
    fn j6_15_cas_journal_joint_rollback_is_not_detected() {
        let _guard = test_guard();
        J9A_EXTERNAL_READ.store(false, std::sync::atomic::Ordering::SeqCst);
        J9A_EXTERNAL_MISMATCH.store(false, std::sync::atomic::Ordering::SeqCst);
        let mut f = CasFixture::new();
        let store = f.store();
        let j = store.initialize(record()).unwrap();
        let old_journal = fs::read(f.journal_file()).unwrap();
        let old_sidecar = fs::read(f.sidecar()).unwrap();
        let old_state = fs::read(&f.state).unwrap();
        drop(j);
        let mut j = store.open().unwrap();
        j.advance(&record().attempt, State::MayHaveBeenSent, None)
            .unwrap();
        drop(j);
        f.stop_server();
        fs::write(f.journal_file(), old_journal).unwrap();
        fs::write(f.sidecar(), old_sidecar).unwrap();
        fs::write(&f.state, old_state).unwrap();
        f.restart(&[]);
        let j = store.open().unwrap();
        assert_eq!(j.record().state, State::Prepared);
        drop(j);
        f.cleanup();
    }

    fn raw_cas_advance(
        fixture: &CasFixture,
        expected: &AnchorState,
        next_revision: u64,
        digest: &str,
    ) -> CasResponse {
        let mut stream = UnixStream::connect(&fixture.socket).unwrap();
        let request = CasRequest::Advance {
            request_id: "raw-request".to_string(),
            identity: fixture.identity.clone(),
            token: fixture.token.clone(),
            expected: expected.clone(),
            next_revision,
            next_digest: digest.to_string(),
        };
        let mut bytes = serde_json::to_vec(&request).unwrap();
        bytes.push(b'\n');
        stream.write_all(&bytes).unwrap();
        stream.flush().unwrap();
        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }

    #[test]
    fn j6_22b_server_rejects_overflow() {
        let _guard = test_guard();
        let f = CasFixture::new_with_env(&[("MKG_CAS_INITIAL_REVISION", u64::MAX.to_string())]);
        let state = f.client().read().unwrap();
        match raw_cas_advance(&f, &state, u64::MAX, &"a".repeat(64)) {
            CasResponse::Rejected { reason, .. } => assert_eq!(reason, CasReject::Overflow),
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(f.client().read().unwrap().revision, u64::MAX);
        f.cleanup();
    }

    fn spawn_cas_server_raw(
        fixture: &CasFixture,
        socket: &Path,
        state: &Path,
        envs: &[(&str, String)],
    ) -> (Child, PathBuf) {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let ready = fixture.base.join(format!(
            "cas-raw-{}-{}.ready",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        make_fifo(&ready);
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", CHILD_CAS_SERVER, "--nocapture"])
            .env("MKG_CAS_SOCKET", socket)
            .env("MKG_CAS_STATE", state)
            .env("MKG_CAS_IDENTITY", fixture.identity.as_str())
            .env("MKG_CAS_TOKEN", &fixture.token)
            .env("MKG_CAS_READY", &ready)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (key, value) in envs {
            command.env(key, value);
        }
        (command.spawn().unwrap(), ready)
    }

    #[test]
    fn j7_dual_cas_server_rejected() {
        let _guard = test_guard();
        let f = CasFixture::new();
        let (mut same_socket, ready) = spawn_cas_server_raw(&f, &f.socket, &f.state, &[]);
        assert!(!same_socket.wait().unwrap().success());
        let _ = fs::remove_file(ready);
        let other_socket = f.base.join("other.sock");
        let (mut same_state, ready) = spawn_cas_server_raw(&f, &other_socket, &f.state, &[]);
        assert!(!same_state.wait().unwrap().success());
        let _ = fs::remove_file(ready);
        // A second server with a different state/socket but the same identity
        // must also be rejected by the host identity lock.
        let third_socket = f.base.join("third.sock");
        let third_state = f.base.join("third.state");
        let (mut same_identity, ready) = spawn_cas_server_raw(&f, &third_socket, &third_state, &[]);
        assert!(!same_identity.wait().unwrap().success());
        let _ = fs::remove_file(ready);
        // The original server still owns the state and serves reads.
        assert_eq!(f.client().read().unwrap().revision, 0);
        f.cleanup();
    }

    /// J7, J22 test-fix candidate (OD-J21-6): an oversized request is refused without effect.
    ///
    /// The request is a valid Advance padded with leading whitespace beyond the limit, so a server
    /// without the limit would commit it. The server stops reading at the limit and closes without
    /// an answer; the client's second write may therefore race with that close. Only that write may
    /// fail, and only with EPIPE or ECONNRESET (the J7 race, `J7_ROOT_CAUSE.md`). Proven instead of
    /// the write: (1) the limit was applied - (2) the valid request was not processed and (3) the
    /// state is unchanged, (4) no answer was sent, (5) the server stays up and (6) serves the
    /// following read and advance.
    #[test]
    fn j7_request_size_limit() {
        let _guard = test_guard();
        let f = CasFixture::new();
        let before = f.client().read().unwrap();
        assert_eq!(before.revision, 0);
        let request = serde_json::to_vec(&CasRequest::Advance {
            request_id: cas_request_id().unwrap(),
            identity: f.identity.clone(),
            token: f.token.clone(),
            expected: before.clone(),
            next_revision: 1,
            next_digest: "3".repeat(64),
        })
        .unwrap();
        let mut line = vec![b' '; MAX_CAS_MESSAGE_BYTES + 1];
        line.extend_from_slice(&request);
        line.push(b'\n');
        let (head, tail) = line.split_at(MAX_CAS_MESSAGE_BYTES + 1);
        let mut stream = UnixStream::connect(&f.socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        // The server reads all of `head` before it can decide, so this write always completes.
        stream.write_all(head).unwrap();
        match stream.write_all(tail) {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                ) => {}
            Err(error) => panic!("unexpected error on the write after the limit: {error}"),
        }
        let mut reply = Vec::new();
        match stream.read_to_end(&mut reply) {
            Ok(_) => assert!(reply.is_empty(), "an oversized request gets no answer"),
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
            Err(error) => panic!("unexpected error waiting for the close: {error}"),
        }
        drop(stream);
        let client = f.client();
        let after = client.read().unwrap();
        assert_eq!(
            (after.revision, &after.digest),
            (before.revision, &before.digest),
            "the oversized request changed nothing"
        );
        let advanced = client.advance(&after, &"4".repeat(64)).unwrap();
        assert_eq!(
            advanced.revision, 1,
            "the server still serves a valid request"
        );
        assert_eq!(f.client().read().unwrap().revision, 1);
        f.cleanup();
    }

    /// J22 (J7 C-3): the J7 failure made deterministic with the real CAS server. The server stops
    /// reading at the limit and closes without an answer; a write issued after that close fails with
    /// EPIPE every time, and the server keeps serving.
    #[test]
    fn j22_j7_write_after_the_server_closed_fails_with_epipe() {
        let _guard = test_guard();
        let f = CasFixture::new();
        for _ in 0..20 {
            let mut stream = UnixStream::connect(&f.socket).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .write_all(&vec![b'x'; MAX_CAS_MESSAGE_BYTES + 1])
                .unwrap();
            let mut reply = Vec::new();
            assert_eq!(
                stream.read_to_end(&mut reply).unwrap(),
                0,
                "the server closes without an answer"
            );
            let error = stream.write_all(b"\n").unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe, "{error}");
        }
        assert_eq!(f.client().read().unwrap().revision, 0);
        f.cleanup();
    }

    /// J22 (J7 C-3): the close points, through a controlled server (a Unix listener in the test):
    /// a close while the client's first write is still in progress fails that write; a close
    /// between the two writes fails the second; a close after both writes fails neither; a normal
    /// server reads the line and answers.
    #[test]
    fn j22_j7_controlled_close_points() {
        use std::sync::mpsc;
        #[derive(Clone, Copy, Debug)]
        enum Close {
            DuringFirstWrite,
            BetweenWrites,
            AfterBothWrites,
            AnswerLine,
        }
        let base = unique_base("j22-j7");
        for (index, close) in [
            Close::DuringFirstWrite,
            Close::BetweenWrites,
            Close::AfterBothWrites,
            Close::AnswerLine,
        ]
        .into_iter()
        .enumerate()
        {
            let socket = base.join(format!("controlled-{index}.sock"));
            let listener = UnixListener::bind(&socket).unwrap();
            let (closed_sender, closed) = mpsc::channel::<()>();
            let (written_sender, written) = mpsc::channel::<()>();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                match close {
                    Close::DuringFirstWrite => {
                        let mut some = [0u8; 100];
                        stream.read_exact(&mut some).unwrap();
                    }
                    Close::BetweenWrites => {
                        let mut limit = vec![0u8; MAX_CAS_MESSAGE_BYTES + 1];
                        stream.read_exact(&mut limit).unwrap();
                    }
                    Close::AfterBothWrites => {
                        // Read both writes first (a small send buffer, as on macOS, would
                        // otherwise block the client's first write), then close only after
                        // the client says both writes returned.
                        let mut all = vec![0u8; MAX_CAS_MESSAGE_BYTES + 2];
                        stream.read_exact(&mut all).unwrap();
                        written.recv().unwrap();
                    }
                    Close::AnswerLine => {
                        let mut line = String::new();
                        BufReader::new(&mut stream).read_line(&mut line).unwrap();
                        stream.write_all(b"answer\n").unwrap();
                    }
                }
                drop(stream);
                let _ = closed_sender.send(());
            });
            let mut stream = UnixStream::connect(&socket).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            match close {
                Close::DuringFirstWrite => {
                    // Larger than any socket buffer: the write is still in progress at the close.
                    let error = stream.write_all(&vec![b'x'; 8 << 20]).unwrap_err();
                    assert!(
                        matches!(
                            error.kind(),
                            std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                        ),
                        "{close:?}: {error}"
                    );
                }
                Close::BetweenWrites => {
                    stream
                        .write_all(&vec![b'x'; MAX_CAS_MESSAGE_BYTES + 1])
                        .unwrap();
                    closed.recv().unwrap();
                    let error = stream.write_all(b"\n").unwrap_err();
                    assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe, "{close:?}");
                }
                Close::AfterBothWrites => {
                    stream
                        .write_all(&vec![b'x'; MAX_CAS_MESSAGE_BYTES + 1])
                        .unwrap();
                    stream.write_all(b"\n").unwrap();
                    written_sender.send(()).unwrap();
                    closed.recv().unwrap();
                }
                Close::AnswerLine => {
                    stream.write_all(b"request\n").unwrap();
                    let mut answer = String::new();
                    BufReader::new(&mut stream).read_line(&mut answer).unwrap();
                    assert_eq!(answer, "answer\n");
                }
            }
            server.join().unwrap();
        }
        let _ = fs::remove_dir_all(&base);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root-owned mount namespace at /var/lib/mikagami/operation-journal"]
    fn j7_fixed_path_system_and_anchor() {
        let _guard = test_guard();
        let anchor_path = Path::new(SYSTEM_ANCHOR_PATH);
        let anchor = fs::metadata(anchor_path).unwrap();
        assert_eq!(anchor.uid(), uid());
        assert_eq!(anchor.mode() & 0o777, 0o700);
        let parent = fs::metadata(anchor_path.parent().unwrap()).unwrap();
        assert_eq!(parent.uid(), 0);
        assert_eq!(parent.mode() & 0o022, 0);

        let store = JournalStore::system().unwrap();
        let j = store.initialize(record()).unwrap();
        assert_eq!(j.record().state, State::Prepared);
        assert!(!j.send_authorized());
        drop(j);
        let j = store.open().unwrap();
        assert_eq!(j.record().state, State::Prepared);
        drop(j);
        fs::remove_dir_all(anchor_path.join(JOURNAL_DIR)).unwrap();

        let state_path =
            std::env::temp_dir().join(format!("mkg-j7-fixed-anchor-{}", std::process::id()));
        let fake = Arc::new(FileAnchor::new(&state_path, j6_identity()));
        let store = JournalStore::system_with_test_anchor(fake).unwrap();
        let j = store.initialize(record()).unwrap();
        assert_eq!(j.record().state, State::Prepared);
        assert!(!j.send_authorized());
        drop(j);
        let j = store.open().unwrap();
        assert_eq!(j.record().state, State::Prepared);
        drop(j);
        fs::remove_dir_all(anchor_path.join(JOURNAL_DIR)).unwrap();
        let _ = fs::remove_file(&state_path);
        let _ = fs::remove_file(state_path.with_extension("tmp"));
    }

    fn j8_state(identity: &AnchorIdentity) -> AnchorState {
        AnchorState {
            identity: identity.clone(),
            revision: 0,
            digest: ANCHOR_GENESIS_DIGEST.to_string(),
        }
    }

    #[test]
    fn j8_state_symlink_rejected() {
        let _guard = test_guard();
        let base = unique_base("j8-symlink");
        set_mode(&base, 0o700);
        let identity = j6_identity();
        let real = base.join("real.state");
        let link = base.join("link.state");
        write_cas_state(&real, &j8_state(&identity), None).unwrap();
        symlink(&real, &link).unwrap();
        assert!(read_cas_state(&link).is_err());
        assert!(write_cas_state(&link, &j8_state(&identity), None).is_err());
        assert!(read_cas_state(&real).is_ok());
        base_cleanup(&base);
    }

    #[test]
    fn j8_state_permission_rejected() {
        let _guard = test_guard();
        let base = unique_base("j8-perm");
        set_mode(&base, 0o700);
        let identity = j6_identity();
        let path = base.join("cas.state");
        write_cas_state(&path, &j8_state(&identity), None).unwrap();
        set_mode(&path, 0o644);
        assert!(read_cas_state(&path).is_err());
        set_mode(&path, 0o600);
        assert!(read_cas_state(&path).is_ok());
        base_cleanup(&base);
    }

    #[test]
    fn j8_state_hardlink_shared_inode() {
        let _guard = test_guard();
        let base = unique_base("j8-hardlink");
        set_mode(&base, 0o700);
        let identity = j6_identity();
        let first = base.join("first.state");
        let second = base.join("second.state");
        write_cas_state(&first, &j8_state(&identity), None).unwrap();
        fs::hard_link(&first, &second).unwrap();
        // A hardlink changes nlink to 2; trusted() rejects it.
        assert!(read_cas_state(&first).is_err());
        assert!(cas_state_inode(&second).is_err());
        base_cleanup(&base);
    }

    #[test]
    fn j8_state_inode_replacement_rejected() {
        let _guard = test_guard();
        let base = unique_base("j8-replace");
        set_mode(&base, 0o700);
        let identity = j6_identity();
        let path = base.join("cas.state");
        write_cas_state(&path, &j8_state(&identity), None).unwrap();
        let old = cas_state_inode(&path).unwrap();
        let replacement = base.join("replacement.state");
        let mut next = j8_state(&identity);
        next.revision = 1;
        next.digest = "a".repeat(64);
        write_cas_state(&replacement, &next, None).unwrap();
        fs::rename(&replacement, &path).unwrap();
        assert_ne!(cas_state_inode(&path).unwrap(), old);
        assert!(write_cas_state(&path, &j8_state(&identity), Some(old)).is_err());
        base_cleanup(&base);
    }

    #[test]
    fn j8_state_directory_rejected() {
        let _guard = test_guard();
        let base = unique_base("j8-dir");
        set_mode(&base, 0o700);
        let path = base.join("cas.state");
        fs::create_dir(&path).unwrap();
        assert!(read_cas_state(&path).is_err());
        assert!(write_cas_state(&path, &j8_state(&j6_identity()), None).is_err());
        base_cleanup(&base);
    }

    #[test]
    fn j8_tmpdir_does_not_split_identity_lock() {
        let _guard = test_guard();
        let f = CasFixture::new();
        let other_tmp = f.base.join("other-tmp");
        fs::create_dir(&other_tmp).unwrap();
        set_mode(&other_tmp, 0o700);
        let (mut second, ready) = spawn_cas_server_raw(
            &f,
            &f.socket,
            &f.state,
            &[("TMPDIR", other_tmp.to_string_lossy().to_string())],
        );
        assert!(!second.wait().unwrap().success());
        let _ = fs::remove_file(ready);
        assert_eq!(f.client().read().unwrap().revision, 0);
        f.cleanup();
    }

    #[test]
    fn j8_stale_socket_is_replaced_but_live_socket_is_not() {
        let _guard = test_guard();
        let base = unique_base("j8-socket");
        set_mode(&base, 0o700);
        let socket = base.join("cas.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        assert!(prepare_socket(&socket).is_err());
        drop(listener);
        assert!(prepare_socket(&socket).is_ok());
        assert!(!socket.exists());
        base_cleanup(&base);
    }

    #[test]
    fn j8_socket_symlink_and_non_socket_rejected() {
        let _guard = test_guard();
        let base = unique_base("j8-socket-bad");
        set_mode(&base, 0o700);
        let target = base.join("target");
        fs::write(&target, b"x").unwrap();
        let link = base.join("link.sock");
        symlink(&target, &link).unwrap();
        assert!(prepare_socket(&link).is_err());
        assert!(link.exists());
        let regular = base.join("regular.sock");
        fs::write(&regular, b"x").unwrap();
        assert!(prepare_socket(&regular).is_err());
        assert!(regular.exists());
        base_cleanup(&base);
    }

    #[test]
    fn j8_request_id_replay_is_rejected_by_cas() {
        let _guard = test_guard();
        let f = CasFixture::new();
        let state = f.client().read().unwrap();
        match raw_cas_advance(&f, &state, 1, &"a".repeat(64)) {
            CasResponse::Committed { .. } => {}
            other => panic!("unexpected {other:?}"),
        }
        match raw_cas_advance(&f, &state, 1, &"b".repeat(64)) {
            CasResponse::Conflict { .. } => {}
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(f.client().read().unwrap().revision, 1);
        f.cleanup();
    }

    #[test]
    fn j8_socket_directory_permission_rejected() {
        let _guard = test_guard();
        let base = unique_base("j8-socket-dir");
        set_mode(&base, 0o700);
        let open = base.join("open");
        fs::create_dir(&open).unwrap();
        set_mode(&open, 0o777);
        let socket = open.join("cas.sock");
        assert!(prepare_socket(&socket).is_err());
        set_mode(&open, 0o700);
        assert!(prepare_socket(&socket).is_ok());
        base_cleanup(&base);
    }

    #[test]
    fn j8_state_new_file_is_owner_only_single_link() {
        let _guard = test_guard();
        let base = unique_base("j8-publish");
        set_mode(&base, 0o700);
        let path = base.join("cas.state");
        write_cas_state(&path, &j8_state(&j6_identity()), None).unwrap();
        let meta = fs::symlink_metadata(&path).unwrap();
        assert!(meta.is_file());
        assert_eq!(meta.nlink(), 1);
        assert_eq!(meta.mode() & 0o777, 0o600);
        assert!(read_cas_state(&path).is_ok());
        base_cleanup(&base);
    }

    #[test]
    #[ignore = "advisory flock limitation: a same-UID actor that unlinks/replaces the lock file can create a second lock"]
    fn j8_lock_file_replacement_is_advisory() {
        let _guard = test_guard();
        let root = cas_lock_root().unwrap();
        let base = unique_base("j8-lock-replace");
        set_mode(&base, 0o700);
        let target = base.join("target");
        let first = cas_path_lock(&root, "j8-test", &target).unwrap();
        let digest = format!("{:x}", Sha256::digest(target.as_os_str().as_bytes()));
        let lock_path = root.join(format!("j8-test-{digest}.lock"));
        fs::remove_file(&lock_path).unwrap();
        let second = cas_path_lock(&root, "j8-test", &target).unwrap();
        drop(second);
        drop(first);
        base_cleanup(&base);
    }

    #[test]
    fn j8_sigkill_server_restart_cleans_stale_socket() {
        let _guard = test_guard();
        let mut f = CasFixture::new();
        let mut server = f.server.take().unwrap();
        let mut child = server.child.take().unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
        // Do not run Drop/CasServer::stop: leave the socket behind.
        std::mem::forget(server);
        assert!(f.socket.exists());
        let restarted = start_cas_server(&f.base, &f.socket, &f.state, &f.identity, &f.token, &[]);
        f.server = Some(restarted);
        assert_eq!(f.client().read().unwrap().revision, 0);
        f.cleanup();
    }

    #[test]
    fn j9a_old_journal_rejected_after_external_cas_advance() {
        let _guard = test_guard();
        J9A_EXTERNAL_READ.store(false, std::sync::atomic::Ordering::SeqCst);
        J9A_EXTERNAL_MISMATCH.store(false, std::sync::atomic::Ordering::SeqCst);
        let mut f = CasFixture::new();
        let store = f.store();
        let j = store.initialize(record()).unwrap();
        let old_journal = fs::read(f.journal_file()).unwrap();
        let old_sidecar = fs::read(f.sidecar()).unwrap();
        assert_eq!(j.record().revision, 1);
        assert!(!j.send_authorized());
        drop(j);

        // Advance both CAS and journal to revision 2, then stop/restart the CAS
        // server to show that its durable state survives the client lifecycle.
        let mut j = store.open().unwrap();
        j.advance(&record().attempt, State::MayHaveBeenSent, None)
            .unwrap();
        drop(j);
        let advanced = f.client().read().unwrap();
        assert_eq!(advanced.revision, 2);
        f.stop_server();
        f.restart(&[]);
        let after_restart = f.client().read().unwrap();
        assert_eq!(after_restart, advanced);
        let legit = f.store();
        assert!(legit.open().is_ok());
        drop(legit);

        // Restore the old journal+sidecar only. CAS is still revision 2.
        fs::write(f.journal_file(), old_journal).unwrap();
        fs::write(f.sidecar(), old_sidecar).unwrap();
        J9A_EXTERNAL_READ.store(false, std::sync::atomic::Ordering::SeqCst);
        J9A_EXTERNAL_MISMATCH.store(false, std::sync::atomic::Ordering::SeqCst);
        let fresh = f.store();
        assert!(fresh.open().is_err());
        assert!(J9A_EXTERNAL_READ.load(std::sync::atomic::Ordering::SeqCst));
        assert!(J9A_EXTERNAL_MISMATCH.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(f.client().read().unwrap().revision, 2);
        f.cleanup();
    }

    #[test]
    fn j9b_vm_client() {
        let Ok(anchor) = std::env::var("MKG_J9B_ANCHOR") else {
            return;
        };
        let Ok(socket) = std::env::var("MKG_J9B_CAS_SOCKET") else {
            return;
        };
        let identity =
            AnchorIdentity::from_hex(std::env::var("MKG_J9B_IDENTITY").unwrap()).unwrap();
        let token = std::env::var("MKG_J9B_TOKEN").unwrap();
        let action = std::env::var("MKG_J9B_ACTION").unwrap();
        let client = Arc::new(
            CasAnchor::new(
                PathBuf::from(socket),
                identity,
                token,
                Duration::from_secs(2),
            )
            .unwrap(),
        );
        let anchor_path = Path::new(&anchor);
        let store = JournalStore::for_test_with_anchor(anchor_path, client.clone()).unwrap();
        match action.as_str() {
            "init" => {
                let j = store.initialize(record()).unwrap();
                eprintln!(
                    "J9B_INIT_OK revision={} send={}",
                    j.record().revision,
                    j.send_authorized()
                );
            }
            "advance" => {
                let mut j = store.open().unwrap();
                j.advance(&record().attempt, State::MayHaveBeenSent, None)
                    .unwrap();
                eprintln!(
                    "J9B_ADVANCE_OK revision={} send={}",
                    j.record().revision,
                    j.send_authorized()
                );
            }
            "open" => {
                J9B_OPEN_STAGE.store(0, std::sync::atomic::Ordering::SeqCst);
                let result = store.open();
                eprintln!(
                    "J9B_OPEN result={} external_read={} external_mismatch={}",
                    if result.is_ok() { "OK" } else { "ERR" },
                    J9A_EXTERNAL_READ.load(std::sync::atomic::Ordering::SeqCst),
                    J9A_EXTERNAL_MISMATCH.load(std::sync::atomic::Ordering::SeqCst),
                );
                eprintln!(
                    "J9B_OPEN stage={}",
                    J9B_OPEN_STAGE.load(std::sync::atomic::Ordering::SeqCst)
                );
            }
            "state" => match client.read() {
                Ok(state) => eprintln!(
                    "J9B_STATE revision={} digest={}",
                    state.revision, state.digest
                ),
                Err(_) => eprintln!("J9B_STATE_ERR"),
            },
            "rebind" => {
                let service_uid = unsafe { libc::geteuid() };
                let trusted =
                    TrustedAnchor::provision(anchor_path, service_uid, Boundary::TestSameUid)
                        .unwrap();
                let held = acquire(&trusted, false, false, true).unwrap();
                let (record, _old_identity) = read_record(&held.directory, service_uid).unwrap();
                let old_meta = read_anchor_checkpoint(&held.directory, service_uid).unwrap();
                write_record(&held.directory, &record, &held.identity, false, service_uid).unwrap();
                let digest =
                    anchor_digest(&record, &held.identity, &old_meta.identity, record.revision)
                        .unwrap();
                let new_meta = AnchorMetadata {
                    identity: old_meta.identity,
                    revision: record.revision,
                    digest,
                };
                write_anchor_checkpoint(&held.directory, &new_meta, false, service_uid).unwrap();
                eprintln!("J9B_REBIND_OK revision={}", record.revision);
            }
            other => panic!("unknown J9B action: {other}"),
        }
    }

    /// J9C real-VM driver. `open`, `open-protected` and `open-legacy` call
    /// `JournalStore::open()` unchanged; `inspect` only stats and decodes files and never writes.
    /// There is no identity rebind. `forge-same-revision` models an attacker
    /// who can write the journal disk: it keeps the persisted StoreIdentity
    /// (asserted equal to the held one) and only changes record content.
    #[test]
    fn j9c_vm_client() {
        let Ok(anchor) = std::env::var("MKG_J9C_ANCHOR") else {
            return;
        };
        let action = std::env::var("MKG_J9C_ACTION").unwrap();
        // An empty value means "no expectation", so a driver script can pass
        // the variables unconditionally.
        let expect = std::env::var("MKG_J9C_EXPECT")
            .ok()
            .filter(|value| !value.is_empty());
        let expect_stage = std::env::var("MKG_J9C_EXPECT_STAGE")
            .ok()
            .filter(|value| !value.is_empty())
            .map(|value| value.parse::<u8>().unwrap());
        let anchor_path = Path::new(&anchor);
        let service_uid = unsafe { libc::geteuid() };
        let client = || {
            let socket = std::env::var("MKG_J9C_CAS_SOCKET").unwrap();
            let identity =
                AnchorIdentity::from_hex(std::env::var("MKG_J9C_IDENTITY").unwrap()).unwrap();
            // The synthetic token is read from a file so it never appears in
            // command lines or captured logs.
            let token = fs::read_to_string(std::env::var("MKG_J9C_TOKEN_FILE").unwrap())
                .unwrap()
                .trim()
                .to_string();
            Arc::new(
                CasAnchor::new(
                    PathBuf::from(socket),
                    identity,
                    token,
                    Duration::from_secs(2),
                )
                .unwrap(),
            )
        };
        let reset = || {
            J9A_EXTERNAL_READ.store(false, std::sync::atomic::Ordering::SeqCst);
            J9A_EXTERNAL_MISMATCH.store(false, std::sync::atomic::Ordering::SeqCst);
            J9B_OPEN_STAGE.store(0, std::sync::atomic::Ordering::SeqCst);
        };
        let report = |label: &str, result: &Result<Journal, ()>| {
            let stage = J9B_OPEN_STAGE.load(std::sync::atomic::Ordering::SeqCst);
            eprintln!(
                "J9C_{label} result={} stage={stage} external_read={} external_mismatch={}",
                if result.is_ok() { "OK" } else { "ERR" },
                J9A_EXTERNAL_READ.load(std::sync::atomic::Ordering::SeqCst),
                J9A_EXTERNAL_MISMATCH.load(std::sync::atomic::Ordering::SeqCst),
            );
            if let Ok(journal) = result {
                eprintln!(
                    "J9C_{label} revision={} send_authorized={}",
                    journal.record().revision,
                    journal.send_authorized()
                );
                assert!(!journal.send_authorized());
            }
            if let Some(expect) = &expect {
                assert_eq!(if result.is_ok() { "OK" } else { "ERR" }, expect);
            }
            if let Some(expect_stage) = expect_stage {
                assert_eq!(stage, expect_stage);
            }
        };
        match action.as_str() {
            "init" => {
                let store = JournalStore::for_test_with_anchor(anchor_path, client()).unwrap();
                let j = store.initialize(record()).unwrap();
                eprintln!(
                    "J9C_INIT_OK revision={} send_authorized={}",
                    j.record().revision,
                    j.send_authorized()
                );
                assert!(!j.send_authorized());
            }
            "advance" => {
                let store = JournalStore::for_test_with_anchor(anchor_path, client()).unwrap();
                let mut j = store.open().unwrap();
                let (next, operation) =
                    match std::env::var("MKG_J9C_NEXT").ok().as_deref().unwrap_or("") {
                        "" | "MayHaveBeenSent" => (State::MayHaveBeenSent, None),
                        "OperationKnown" => (
                            State::OperationKnown,
                            Some(("synthetic-operation".into(), "zone-a".into())),
                        ),
                        "Pending" => (State::Pending, None),
                        "Unresolved" => (State::Unresolved, None),
                        other => panic!("unsupported J9C next state: {other}"),
                    };
                // An UNKNOWN CAS outcome must surface as an error, never as a
                // retried or locally completed advance.
                let result = j.advance(&record().attempt, next, operation);
                eprintln!(
                    "J9C_ADVANCE result={} next={next:?} revision={} send_authorized={}",
                    if result.is_ok() { "OK" } else { "ERR" },
                    j.record().revision,
                    j.send_authorized()
                );
                assert!(!j.send_authorized());
                assert_eq!(
                    if result.is_ok() { "OK" } else { "ERR" },
                    expect.as_deref().unwrap_or("OK")
                );
            }
            "open" => {
                let store = JournalStore::for_test_with_anchor(anchor_path, client()).unwrap();
                reset();
                let result = store.open();
                report("OPEN", &result);
            }
            "open-protected" => {
                // Same open, but the anchor is provisioned under the production
                // boundary policy (root-owned ancestors, Linux local-fs check).
                let store =
                    JournalStore::for_test_protected_with_anchor(anchor_path, client()).unwrap();
                reset();
                let result = store.open();
                report("OPEN_PROTECTED", &result);
            }
            "open-legacy" => {
                let store = JournalStore::for_test(anchor_path).unwrap();
                reset();
                let result = store.open();
                report("OPEN_LEGACY", &result);
            }
            "state" => match client().read() {
                Ok(state) => eprintln!(
                    "J9C_CAS result=OK revision={} digest={}",
                    state.revision, state.digest
                ),
                Err(error) => {
                    eprintln!("J9C_CAS result=ERR error={error:?}");
                    if expect.as_deref() != Some("ERR") {
                        panic!("CAS read failed");
                    }
                }
            },
            "inspect" => {
                let directory = anchor_path.join(JOURNAL_DIR);
                let anchor_meta = fs::symlink_metadata(anchor_path).unwrap();
                let directory_meta = fs::symlink_metadata(&directory).unwrap();
                let lock_meta = fs::symlink_metadata(directory.join(LOCK_FILE)).unwrap();
                let (record, persisted) =
                    decode(&fs::read(directory.join(JOURNAL_FILE)).unwrap()).unwrap();
                let current = StoreIdentity {
                    schema: 1,
                    anchor_required: persisted.anchor_required,
                    anchor_dev: anchor_meta.dev(),
                    anchor_ino: anchor_meta.ino(),
                    directory_dev: directory_meta.dev(),
                    directory_ino: directory_meta.ino(),
                    lock_dev: lock_meta.dev(),
                    lock_ino: lock_meta.ino(),
                };
                for (label, identity) in [("persisted", &persisted), ("current", &current)] {
                    eprintln!(
                        "J9C_IDENTITY {label} anchor_required={} anchor={}:{} directory={}:{} lock={}:{}",
                        identity.anchor_required,
                        identity.anchor_dev,
                        identity.anchor_ino,
                        identity.directory_dev,
                        identity.directory_ino,
                        identity.lock_dev,
                        identity.lock_ino,
                    );
                }
                eprintln!("J9C_IDENTITY match={}", persisted == current);
                let directory_file = File::open(&directory).unwrap();
                let meta = read_anchor_checkpoint(&directory_file, service_uid).unwrap();
                let recomputed =
                    anchor_digest(&record, &persisted, &meta.identity, meta.revision).unwrap();
                eprintln!(
                    "J9C_LOCAL record_revision={} state={:?} sidecar_revision={} sidecar_digest={} digest_binds_persisted_identity={}",
                    record.revision,
                    record.state,
                    meta.revision,
                    meta.digest,
                    recomputed == meta.digest,
                );
            }
            "forge-same-revision" => {
                let trusted =
                    TrustedAnchor::provision(anchor_path, service_uid, Boundary::TestSameUid)
                        .unwrap();
                let held = acquire(&trusted, false, false, true).unwrap();
                let (mut record, persisted) = read_record(&held.directory, service_uid).unwrap();
                assert_eq!(persisted, held.identity);
                let old_meta = read_anchor_checkpoint(&held.directory, service_uid).unwrap();
                record.journal_id = "synthetic-forged-journal".into();
                write_record(&held.directory, &record, &held.identity, false, service_uid).unwrap();
                let digest =
                    anchor_digest(&record, &held.identity, &old_meta.identity, record.revision)
                        .unwrap();
                assert_ne!(digest, old_meta.digest);
                let new_meta = AnchorMetadata {
                    identity: old_meta.identity,
                    revision: record.revision,
                    digest,
                };
                write_anchor_checkpoint(&held.directory, &new_meta, false, service_uid).unwrap();
                eprintln!(
                    "J9C_FORGE_OK revision={} digest={}",
                    new_meta.revision, new_meta.digest
                );
            }
            other => panic!("unknown J9C action: {other}"),
        }
    }

    fn base_cleanup(base: &Path) {
        set_mode(base, 0o700);
        let _ = fs::remove_dir_all(base);
    }

    // Phase 1-J11: protocol v2, fenced BeginSession, transport abstraction.
    // All servers here are the in-process reference model; nothing listens on
    // a socket and nothing is sent anywhere.

    use super::cas_v2_reference::{CasV2Server, Durable, FaultPoint, Gate, TestTransport};
    use std::sync::mpsc;

    fn j11_identity() -> AnchorIdentity {
        AnchorIdentity::from_hex(format!("{:064x}", 0x1111_0000_u64)).unwrap()
    }

    fn rid(n: u8) -> String {
        format!("{n:032x}")
    }

    fn dg(c: char) -> String {
        c.to_string().repeat(64)
    }

    struct J11Fixture {
        base: PathBuf,
        anchor: PathBuf,
        state: PathBuf,
        transport: Arc<TestTransport>,
    }

    impl J11Fixture {
        fn new() -> Self {
            let base = unique_base("j11");
            let anchor = base.join("anchor");
            fs::create_dir(&anchor).unwrap();
            set_mode(&anchor, 0o700);
            let state = base.join("cas-v2.state");
            CasV2Server::provision(&state, &j11_identity()).unwrap();
            let server = Arc::new(CasV2Server::open(&state, &j11_identity()).unwrap());
            Self {
                base,
                anchor,
                state,
                transport: Arc::new(TestTransport::new(server)),
            }
        }

        fn server(&self) -> Arc<CasV2Server> {
            self.transport.server()
        }

        fn client(&self) -> Arc<NetworkCasAnchor> {
            let transport: Arc<dyn CasTransport> = self.transport.clone();
            Arc::new(NetworkCasAnchor::new(transport, j11_identity()))
        }

        fn store(&self, client: &Arc<NetworkCasAnchor>) -> JournalStore {
            JournalStore::for_test_with_anchor(&self.anchor, client.clone()).unwrap()
        }

        fn restart(&self) {
            let server = CasV2Server::open(&self.state, &j11_identity()).unwrap();
            self.transport.replace_server(Arc::new(server));
        }

        fn on_disk(&self) -> Durable {
            super::cas_v2_reference::read_state(&self.state).unwrap().0
        }

        fn received(&self) -> usize {
            self.server().received.load(Ordering::SeqCst)
        }

        fn journal_file(&self) -> PathBuf {
            self.anchor.join(JOURNAL_DIR).join(JOURNAL_FILE)
        }

        fn sidecar(&self) -> PathBuf {
            self.anchor.join(JOURNAL_DIR).join(ANCHOR_FILE)
        }

        fn cleanup(self) {
            base_cleanup(&self.base);
        }
    }

    fn raw(server: &CasV2Server, request: &CasV2Request) -> CasV2Response {
        let reply = server
            .handle(&serde_json::to_vec(request).unwrap())
            .unwrap();
        serde_json::from_slice(&reply).unwrap()
    }

    fn raw_value(server: &CasV2Server, value: serde_json::Value) -> CasV2Response {
        let reply = server.handle(&serde_json::to_vec(&value).unwrap()).unwrap();
        serde_json::from_slice(&reply).unwrap()
    }

    fn raw_begin(server: &CasV2Server, n: u8) -> (AnchorState, u64) {
        match raw(
            server,
            &CasV2Request::BeginSession {
                v: 2,
                request_id: rid(n),
                identity: j11_identity(),
            },
        ) {
            CasV2Response::Session { state, fence, .. } => (state, fence),
            other => panic!("unexpected {other:?}"),
        }
    }

    fn adv(fence: u64, expected: &AnchorState, digest: &str, request_id: String) -> CasV2Request {
        CasV2Request::Advance {
            v: 2,
            request_id,
            identity: j11_identity(),
            fence,
            expected: expected.clone(),
            next_revision: expected.revision + 1,
            next_digest: digest.to_string(),
        }
    }

    fn reset_stage() {
        J9B_OPEN_STAGE.store(0, Ordering::SeqCst);
    }

    fn stage() -> u8 {
        J9B_OPEN_STAGE.load(Ordering::SeqCst)
    }

    #[test]
    fn j11_t01_begin_session_advances_fence_durably() {
        let _guard = test_guard();
        let f = J11Fixture::new();
        let c = f.client();
        assert_eq!(c.current_fence(), None);
        let state = c.begin_session().unwrap();
        assert_eq!(
            (state.revision, state.digest.as_str()),
            (0, ANCHOR_GENESIS_DIGEST)
        );
        assert_eq!(c.current_fence(), Some(1));
        assert_eq!(f.on_disk().fence, 1);
        c.begin_session().unwrap();
        assert_eq!(c.current_fence(), Some(2));
        assert_eq!(f.on_disk().fence, 2);
        let other = f.client();
        other.begin_session().unwrap();
        assert_eq!(other.current_fence(), Some(3));
        // The fence lives on disk: a restarted server continues from it.
        f.restart();
        assert_eq!(f.server().snapshot().unwrap().fence, 3);
        other.begin_session().unwrap();
        assert_eq!(other.current_fence(), Some(4));
        assert_eq!(f.on_disk().state.revision, 0);
        f.cleanup();
    }

    #[test]
    fn j11_t02_old_fence_advance_is_refused() {
        let _guard = test_guard();
        let f = J11Fixture::new();
        let a = f.client();
        let b = f.client();
        let state = a.begin_session().unwrap();
        b.begin_session().unwrap();
        assert_eq!(a.advance(&state, &dg('a')), Err(AnchorError::Fenced));
        assert_eq!(a.current_fence(), None);
        match raw(&f.server(), &adv(1, &state, &dg('b'), rid(1))) {
            CasV2Response::Fenced { current_fence, .. } => assert_eq!(current_fence, 2),
            other => panic!("unexpected {other:?}"),
        }
        // A fence that was never issued is refused the same way.
        assert!(matches!(
            raw(&f.server(), &adv(99, &state, &dg('b'), rid(2))),
            CasV2Response::Fenced { .. }
        ));
        let durable = f.on_disk();
        assert_eq!((durable.state, durable.fence), (state.clone(), 2));
        assert!(durable.ledger.is_empty());
        // Without a session the client sends nothing at all.
        let c = f.client();
        let before = f.received();
        assert_eq!(c.advance(&state, &dg('c')), Err(AnchorError::Fenced));
        assert_eq!(f.received(), before);
        f.cleanup();
    }

    #[test]
    fn j11_t03_current_fence_advance_commits() {
        let _guard = test_guard();
        let f = J11Fixture::new();
        let c = f.client();
        let s0 = c.begin_session().unwrap();
        let s1 = c.advance(&s0, &dg('a')).unwrap();
        assert_eq!((s1.revision, s1.digest.clone()), (1, dg('a')));
        assert_eq!(c.current_fence(), Some(1));
        let s2 = c.advance(&s1, &dg('b')).unwrap();
        assert_eq!(s2.revision, 2);
        let durable = f.on_disk();
        assert_eq!(
            (durable.state, durable.fence, durable.ledger.len()),
            (s2, 1, 2)
        );
        // A stale expected state is a conflict, not a commit, and ends the session.
        assert_eq!(c.advance(&s0, &dg('c')), Err(AnchorError::Conflict));
        assert_eq!(c.current_fence(), None);
        assert_eq!(f.on_disk().state.revision, 2);
        f.cleanup();
    }

    /// Bounded wait for a gate or contention signal: a missing signal fails the
    /// test instead of hanging it (for example when a mutant bypasses the lock).
    fn wait(signal: &mpsc::Receiver<()>) {
        signal
            .recv_timeout(Duration::from_secs(10))
            .expect("expected interleaving signal did not arrive");
    }

    fn gate(op: &'static str) -> (Gate, mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (arrived, arrived_rx) = mpsc::channel();
        let (release_tx, release) = mpsc::channel();
        (
            Gate {
                op,
                arrived,
                release,
            },
            arrived_rx,
            release_tx,
        )
    }

    #[test]
    fn j11_t04a_begin_session_between_receive_and_processing_fences_advance() {
        let _guard = test_guard();
        let f = J11Fixture::new();
        let c = f.client();
        let s0 = c.begin_session().unwrap();
        let (g, arrived, release) = gate("Advance");
        *f.server().before_lock.lock().unwrap() = Some(g);
        let (client, expected) = (Arc::clone(&c), s0.clone());
        let advance = thread::spawn(move || client.advance(&expected, &dg('a')));
        // The advance was received and decoded but has not taken the lock.
        wait(&arrived);
        let other = f.client();
        other.begin_session().unwrap();
        assert_eq!(f.on_disk().fence, 2);
        release.send(()).unwrap();
        assert_eq!(advance.join().unwrap(), Err(AnchorError::Fenced));
        assert_eq!(f.on_disk().state, s0);
        f.cleanup();
    }

    #[test]
    fn j11_t04b_begin_session_waits_for_advance_in_critical_section() {
        let _guard = test_guard();
        let f = J11Fixture::new();
        let c = f.client();
        let s0 = c.begin_session().unwrap();
        let (g, adv_arrived, adv_release) = gate("Advance");
        *f.server().before_commit.lock().unwrap() = Some(g);
        let (client, expected) = (Arc::clone(&c), s0.clone());
        let advance = thread::spawn(move || client.advance(&expected, &dg('a')));
        // The advance passed every check and holds the identity lock.
        wait(&adv_arrived);
        let (contended_tx, contended) = mpsc::channel();
        *f.server().contended.lock().unwrap() = Some(("BeginSession", contended_tx));
        let other = f.client();
        let (done_tx, done) = mpsc::channel();
        let starter = Arc::clone(&other);
        let session = thread::spawn(move || {
            let result = starter.begin_session();
            done_tx.send(()).unwrap();
            result
        });
        // BeginSession found the identity lock held by the advance and is
        // waiting for it; it cannot complete before the advance is released.
        wait(&contended);
        assert!(matches!(done.try_recv(), Err(mpsc::TryRecvError::Empty)));
        assert_eq!(f.on_disk().fence, 1);
        assert_eq!(f.on_disk().state.revision, 0);
        adv_release.send(()).unwrap();
        let s1 = advance.join().unwrap().unwrap();
        let seen = session.join().unwrap().unwrap();
        // The session started after the commit and observes it.
        assert_eq!((seen.clone(), other.current_fence()), (s1.clone(), Some(2)));
        assert_eq!(c.advance(&s1, &dg('b')), Err(AnchorError::Fenced));
        let durable = f.on_disk();
        assert_eq!((durable.state.revision, durable.fence), (1, 2));
        f.cleanup();
    }

    #[test]
    fn j11_t04c_old_advance_arriving_during_begin_session_is_fenced() {
        let _guard = test_guard();
        let f = J11Fixture::new();
        let c = f.client();
        let s0 = c.begin_session().unwrap();
        let (g, bs_arrived, bs_release) = gate("BeginSession");
        *f.server().before_commit.lock().unwrap() = Some(g);
        let other = f.client();
        let starter = Arc::clone(&other);
        let session = thread::spawn(move || starter.begin_session());
        // BeginSession holds the lock; the new fence is not yet durable.
        wait(&bs_arrived);
        let (contended_tx, contended) = mpsc::channel();
        *f.server().contended.lock().unwrap() = Some(("Advance", contended_tx));
        let (client, expected) = (Arc::clone(&c), s0.clone());
        let advance = thread::spawn(move || client.advance(&expected, &dg('a')));
        // The old advance arrived while BeginSession held the lock and waits.
        wait(&contended);
        assert_eq!(f.on_disk().fence, 1);
        bs_release.send(()).unwrap();
        session.join().unwrap().unwrap();
        assert_eq!(advance.join().unwrap(), Err(AnchorError::Fenced));
        let durable = f.on_disk();
        assert_eq!((durable.state, durable.fence), (s0, 2));
        f.cleanup();
    }

    #[test]
    fn j11_t05_lost_begin_session_response() {
        let _guard = test_guard();
        let f = J11Fixture::new();
        let c = f.client();
        let s0 = c.begin_session().unwrap();
        f.transport.lose_next_response("BeginSession");
        assert_eq!(c.begin_session(), Err(AnchorError::Unknown));
        assert_eq!(c.current_fence(), None);
        // The server committed the fence even though the reply was lost.
        assert_eq!(f.on_disk().fence, 2);
        let before = f.received();
        assert_eq!(c.advance(&s0, &dg('a')), Err(AnchorError::Fenced));
        assert_eq!(f.received(), before);
        assert!(matches!(
            raw(&f.server(), &adv(1, &s0, &dg('a'), rid(1))),
            CasV2Response::Fenced { .. }
        ));
        let state = c.begin_session().unwrap();
        assert_eq!(c.current_fence(), Some(3));
        assert_eq!(c.advance(&state, &dg('a')).unwrap().revision, 1);
        f.cleanup();
    }

    #[test]
    fn j11_t06_lost_advance_response_is_unknown_and_not_resent() {
        let _guard = test_guard();
        let f = J11Fixture::new();
        let c = f.client();
        let s0 = c.begin_session().unwrap();
        f.transport.lose_next_response("Advance");
        assert_eq!(c.advance(&s0, &dg('a')), Err(AnchorError::Unknown));
        assert_eq!(c.current_fence(), None);
        assert_eq!(f.on_disk().state.revision, 1);
        let id = c.last_advance_request_id().unwrap();
        let before = f.received();
        assert_eq!(c.advance(&s0, &dg('a')), Err(AnchorError::Fenced));
        assert_eq!(f.received(), before);
        assert_eq!(c.last_advance_request_id().unwrap(), id);
        // Only a new session may look; it sees the commit.
        let state = c.begin_session().unwrap();
        assert_eq!((state.revision, state.digest), (1, dg('a')));
        assert_eq!(
            c.inquire(&id).unwrap(),
            InquiryOutcome {
                found: true,
                resulting_revision: Some(1)
            }
        );
        f.cleanup();
    }

    #[test]
    fn j11_t07_old_fence_refused_after_restart() {
        let _guard = test_guard();
        let f = J11Fixture::new();
        let c = f.client();
        let s0 = c.begin_session().unwrap();
        f.transport.hold_next("Advance");
        assert_eq!(c.advance(&s0, &dg('a')), Err(AnchorError::Unknown));
        let c2 = f.client();
        c2.begin_session().unwrap();
        f.restart();
        assert_eq!(f.server().snapshot().unwrap().fence, 2);
        match f.transport.deliver_held(0) {
            Some(CasV2Response::Fenced { current_fence, .. }) => assert_eq!(current_fence, 2),
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(f.on_disk().state, s0);
        // A committed request delivered again after a restart is answered from
        // the persisted ledger and not applied twice.
        let (state, fence) = raw_begin(&f.server(), 9);
        let request = adv(fence, &state, &dg('b'), rid(7));
        assert!(matches!(
            raw(&f.server(), &request),
            CasV2Response::Committed {
                replayed: false,
                ..
            }
        ));
        f.restart();
        match raw(&f.server(), &request) {
            CasV2Response::Committed {
                replayed: true,
                state,
                ..
            } => assert_eq!((state.revision, state.digest), (1, dg('b'))),
            other => panic!("unexpected {other:?}"),
        }
        let durable = f.on_disk();
        assert_eq!((durable.state.revision, durable.ledger.len()), (1, 1));
        f.cleanup();
    }

    #[test]
    fn j11_t08_failed_durable_write_never_reports_success() {
        let _guard = test_guard();
        for point in [
            FaultPoint::BeforeTemp,
            FaultPoint::AfterTempSync,
            FaultPoint::AfterRename,
        ] {
            let renamed = point == FaultPoint::AfterRename;
            // BeginSession
            let f = J11Fixture::new();
            let c = f.client();
            c.begin_session().unwrap();
            f.server().inject_fault("BeginSession", point);
            assert_eq!(c.begin_session(), Err(AnchorError::Unknown), "{point:?}");
            assert_eq!(c.current_fence(), None);
            assert!(f.server().halted());
            // A halted instance answers nothing.
            assert_eq!(c.read(), Err(AnchorError::Unknown));
            f.restart();
            assert_eq!(f.on_disk().fence, if renamed { 2 } else { 1 }, "{point:?}");
            let state = c.begin_session().unwrap();
            assert!(c.current_fence().unwrap() >= 2);
            // Advance
            f.server().inject_fault("Advance", point);
            assert_eq!(c.advance(&state, &dg('a')), Err(AnchorError::Unknown));
            assert!(f.server().halted());
            f.restart();
            let durable = f.on_disk();
            assert_eq!(durable.state.revision, u64::from(renamed), "{point:?}");
            assert_eq!(durable.ledger.len(), usize::from(renamed));
            assert_eq!(c.begin_session().unwrap(), durable.state);
            f.cleanup();
        }
    }

    #[test]
    fn j11_t09_unknown_protocol_version_is_refused() {
        let _guard = test_guard();
        let f = J11Fixture::new();
        let server = f.server();
        let identity = j11_identity();
        let base = serde_json::json!({"op": "Read", "request_id": rid(1), "identity": identity});
        let mut cases = vec![base.clone()];
        for v in [
            serde_json::json!(1),
            serde_json::json!(3),
            serde_json::json!("2"),
            serde_json::json!(2.0),
            serde_json::json!(null),
        ] {
            let mut case = base.clone();
            case["v"] = v;
            cases.push(case);
        }
        // A genuine v1 request, token and all (synthetic token).
        cases.push(
            serde_json::to_value(CasRequest::Read {
                request_id: rid(1),
                identity: identity.clone(),
                token: "synthetic-token".into(),
            })
            .unwrap(),
        );
        for case in cases {
            match raw_value(&server, case.clone()) {
                CasV2Response::Rejected {
                    reason, request_id, ..
                } => assert_eq!(
                    (reason, request_id),
                    (CasV2Reject::Version, rid(1)),
                    "{case}"
                ),
                other => panic!("unexpected {other:?} for {case}"),
            }
        }
        let mut invalid = Vec::new();
        let mut unknown_op = base.clone();
        unknown_op["v"] = serde_json::json!(2);
        unknown_op["op"] = serde_json::json!("Reset");
        invalid.push(unknown_op);
        let mut extra = base.clone();
        extra["v"] = serde_json::json!(2);
        extra["token"] = serde_json::json!("synthetic-token");
        invalid.push(extra);
        let mut bad_id = base.clone();
        bad_id["v"] = serde_json::json!(2);
        bad_id["request_id"] = serde_json::json!("not-hex");
        invalid.push(bad_id);
        for case in invalid {
            assert!(
                matches!(
                    raw_value(&server, case.clone()),
                    CasV2Response::Rejected {
                        reason: CasV2Reject::InvalidRequest,
                        ..
                    }
                ),
                "{case}"
            );
        }
        for bytes in [b"not json".to_vec(), vec![b' '; MAX_CAS_MESSAGE_BYTES + 1]] {
            let reply: CasV2Response =
                serde_json::from_slice(&server.handle(&bytes).unwrap()).unwrap();
            assert!(matches!(
                reply,
                CasV2Response::Rejected {
                    reason: CasV2Reject::InvalidRequest,
                    ..
                }
            ));
        }
        let wrong_identity = serde_json::json!({"v": 2, "op": "Read", "request_id": rid(2),
            "identity": AnchorIdentity::from_hex("e".repeat(64)).unwrap()});
        assert!(matches!(
            raw_value(&server, wrong_identity),
            CasV2Response::Rejected {
                reason: CasV2Reject::UnknownIdentity,
                ..
            }
        ));
        let durable = f.on_disk();
        assert_eq!((durable.state.revision, durable.fence), (0, 0));
        f.cleanup();
    }

    type ScriptedReply =
        Box<dyn Fn(&CasV2Request) -> Result<Vec<u8>, TransportError> + Send + Sync>;

    /// Answers every request with a reply computed from the decoded request.
    struct ScriptedTransport {
        reply: ScriptedReply,
    }

    impl CasTransport for ScriptedTransport {
        fn exchange(&self, request: &[u8]) -> Result<Vec<u8>, TransportError> {
            (self.reply)(&cas_v2_decode_request(request).unwrap())
        }
    }

    fn scripted(
        reply: impl Fn(&CasV2Request) -> Result<Vec<u8>, TransportError> + Send + Sync + 'static,
    ) -> NetworkCasAnchor {
        NetworkCasAnchor::new(
            Arc::new(ScriptedTransport {
                reply: Box::new(reply),
            }),
            j11_identity(),
        )
    }

    fn genesis() -> AnchorState {
        AnchorState {
            identity: j11_identity(),
            revision: 0,
            digest: ANCHOR_GENESIS_DIGEST.into(),
        }
    }

    fn json(response: CasV2Response) -> Result<Vec<u8>, TransportError> {
        Ok(serde_json::to_vec(&response).unwrap())
    }

    #[test]
    fn j11_t09b_client_classifies_failures_without_guessing() {
        // Transport outcomes.
        for (error, expected) in [
            (TransportError::NotSent, AnchorError::Unavailable),
            (TransportError::AuthFailure, AnchorError::AuthFailure),
            (TransportError::Unknown, AnchorError::Unknown),
        ] {
            let c = scripted(move |_| Err(error));
            assert_eq!(c.begin_session(), Err(expected));
            assert_eq!(c.current_fence(), None);
        }
        // Replies that cannot be trusted are Protocol (recovery: like Unknown).
        let wrong_version = scripted(|r| {
            json(CasV2Response::Session {
                v: 1,
                request_id: r.request_id().into(),
                state: genesis(),
                fence: 1,
            })
        });
        assert_eq!(wrong_version.begin_session(), Err(AnchorError::Protocol));
        assert_eq!(wrong_version.current_fence(), None);
        let wrong_id = scripted(|_| {
            json(CasV2Response::Session {
                v: 2,
                request_id: rid(9),
                state: genesis(),
                fence: 1,
            })
        });
        assert_eq!(wrong_id.begin_session(), Err(AnchorError::Protocol));
        let zero_fence = scripted(|r| {
            json(CasV2Response::Session {
                v: 2,
                request_id: r.request_id().into(),
                state: genesis(),
                fence: 0,
            })
        });
        assert_eq!(zero_fence.begin_session(), Err(AnchorError::Protocol));
        assert_eq!(zero_fence.current_fence(), None);
        let garbage = scripted(|_| Ok(b"{\"op\":\"Session\"".to_vec()));
        assert_eq!(garbage.begin_session(), Err(AnchorError::Protocol));
        for (reason, expected) in [
            (CasV2Reject::Forbidden, AnchorError::Forbidden),
            (CasV2Reject::UnknownIdentity, AnchorError::Forbidden),
            (CasV2Reject::Version, AnchorError::Protocol),
            (CasV2Reject::NotReady, AnchorError::Unavailable),
            (CasV2Reject::Corrupt, AnchorError::Corrupt),
            (CasV2Reject::Exhausted, AnchorError::Exhausted),
        ] {
            let c = scripted(move |r| {
                json(CasV2Response::Rejected {
                    v: 2,
                    request_id: r.request_id().into(),
                    reason,
                })
            });
            assert_eq!(c.begin_session(), Err(expected));
        }
        // An advance answered as a replay, or with another digest, fails closed
        // and drops the fence.
        let session_then = |advance_reply: fn(&CasV2Request) -> CasV2Response| {
            scripted(move |r| match r {
                CasV2Request::BeginSession { request_id, .. } => json(CasV2Response::Session {
                    v: 2,
                    request_id: request_id.clone(),
                    state: genesis(),
                    fence: 1,
                }),
                other => json(advance_reply(other)),
            })
        };
        let replay = session_then(|r| CasV2Response::Committed {
            v: 2,
            request_id: r.request_id().into(),
            state: AnchorState {
                identity: j11_identity(),
                revision: 1,
                digest: dg('a'),
            },
            replayed: true,
        });
        replay.begin_session().unwrap();
        assert_eq!(
            replay.advance(&genesis(), &dg('a')),
            Err(AnchorError::Protocol)
        );
        assert_eq!(replay.current_fence(), None);
        let other_digest = session_then(|r| CasV2Response::Committed {
            v: 2,
            request_id: r.request_id().into(),
            state: AnchorState {
                identity: j11_identity(),
                revision: 1,
                digest: dg('b'),
            },
            replayed: false,
        });
        other_digest.begin_session().unwrap();
        assert_eq!(
            other_digest.advance(&genesis(), &dg('a')),
            Err(AnchorError::Protocol)
        );
        assert_eq!(other_digest.current_fence(), None);
    }

    #[test]
    fn j11_t10_request_id_duplicates_and_reuse() {
        let _guard = test_guard();
        let f = J11Fixture::new();
        let server = f.server();
        let (s0, fence) = raw_begin(&server, 100);
        let first = adv(fence, &s0, &dg('a'), rid(1));
        let s1 = match raw(&server, &first) {
            CasV2Response::Committed {
                state,
                replayed: false,
                ..
            } => state,
            other => panic!("unexpected {other:?}"),
        };
        match raw(&server, &first) {
            CasV2Response::Committed {
                state,
                replayed: true,
                ..
            } => assert_eq!(state, s1),
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(
            (f.on_disk().state.clone(), f.on_disk().ledger.len()),
            (s1.clone(), 1)
        );
        // Same id, different body.
        assert!(matches!(
            raw(&server, &adv(fence, &s1, &dg('b'), rid(1))),
            CasV2Response::Rejected {
                reason: CasV2Reject::RequestIdReuse,
                ..
            }
        ));
        assert_eq!(f.on_disk().state, s1);
        // Push the first request out of the ledger.
        let mut current = s1.clone();
        for n in 2..=(CAS_LEDGER_CAPACITY as u8 + 1) {
            let digest = format!("{:064x}", u64::from(n) + 1000);
            current = match raw(&server, &adv(fence, &current, &digest, rid(n))) {
                CasV2Response::Committed { state, .. } => state,
                other => panic!("unexpected {other:?}"),
            };
        }
        assert_eq!(f.on_disk().ledger.len(), CAS_LEDGER_CAPACITY);
        // Evicted: evaluated afresh and refused by the CAS conditions.
        match raw(&server, &first) {
            CasV2Response::Conflict { state, .. } => assert_eq!(state, current),
            other => panic!("unexpected {other:?}"),
        }
        raw_begin(&server, 101);
        assert!(matches!(raw(&server, &first), CasV2Response::Fenced { .. }));
        assert_eq!(f.on_disk().state, current);
        f.cleanup();
    }

    #[test]
    fn j11_t11_journal_open_stages_with_v2_anchor() {
        let _guard = test_guard();
        let f = J11Fixture::new();
        let c = f.client();
        let store = f.store(&c);
        let j = store.initialize(record()).unwrap();
        assert!(!j.send_authorized());
        drop(j);
        reset_stage();
        let j = store.open().unwrap();
        assert_eq!(stage(), 0);
        assert_eq!(c.current_fence(), Some(2));
        drop(j);
        // Stage 7: BeginSession not delivered, or its outcome unknown.
        f.transport.refuse_next("BeginSession");
        reset_stage();
        assert!(store.open().is_err());
        assert_eq!(stage(), 7);
        f.transport.lose_next_response("BeginSession");
        reset_stage();
        assert!(store.open().is_err());
        assert_eq!(stage(), 7);
        // Stage 5: a client bound to another identity.
        let transport: Arc<dyn CasTransport> = f.transport.clone();
        let stranger = Arc::new(NetworkCasAnchor::new(
            transport,
            AnchorIdentity::from_hex("e".repeat(64)).unwrap(),
        ));
        reset_stage();
        assert!(f.store(&stranger).open().is_err());
        assert_eq!(stage(), 5);
        // Stage 8: the CAS moved on without this journal.
        let (state, fence) = raw_begin(&f.server(), 50);
        assert!(matches!(
            raw(&f.server(), &adv(fence, &state, &dg('e'), rid(51))),
            CasV2Response::Committed { .. }
        ));
        let journal = fs::read(f.journal_file()).unwrap();
        reset_stage();
        assert!(store.open().is_err());
        assert_eq!(stage(), 8);
        assert_eq!(fs::read(f.journal_file()).unwrap(), journal);
        f.cleanup();
    }

    #[test]
    fn j11_t12_initialize_uses_a_fenced_session() {
        let _guard = test_guard();
        let f = J11Fixture::new();
        let c = f.client();
        let store = f.store(&c);
        let j = store.initialize(record()).unwrap();
        let durable = f.on_disk();
        assert_eq!((durable.state.revision, durable.fence), (1, 1));
        assert_eq!(j.record().revision, 1);
        drop(j);
        assert!(store.initialize(record()).is_err());
        assert_eq!(f.on_disk().state.revision, 1);
        f.cleanup();

        // A CAS that is not at genesis is refused and left untouched.
        let f = J11Fixture::new();
        let (state, fence) = raw_begin(&f.server(), 1);
        raw(&f.server(), &adv(fence, &state, &dg('a'), rid(2)));
        let c = f.client();
        assert!(f.store(&c).initialize(record()).is_err());
        assert_eq!(f.on_disk().state.revision, 1);
        assert!(!f.journal_file().exists());
        f.cleanup();

        // No session, no journal.
        let f = J11Fixture::new();
        let c = f.client();
        f.transport.refuse_next("BeginSession");
        assert!(f.store(&c).initialize(record()).is_err());
        assert!(!f.journal_file().exists());
        assert_eq!(f.on_disk().fence, 0);
        f.cleanup();
    }

    #[test]
    fn j11_t13_rollback_rejection_with_v2_anchor() {
        let _guard = test_guard();
        // Journal rolled back, CAS intact.
        let f = J11Fixture::new();
        let c = f.client();
        let store = f.store(&c);
        let mut j = store.initialize(record()).unwrap();
        let old_record = fs::read(f.journal_file()).unwrap();
        let old_sidecar = fs::read(f.sidecar()).unwrap();
        j.advance(&record().attempt, State::MayHaveBeenSent, None)
            .unwrap();
        drop(j);
        fs::write(f.journal_file(), &old_record).unwrap();
        fs::write(f.sidecar(), &old_sidecar).unwrap();
        reset_stage();
        assert!(store.open().is_err());
        assert_eq!(stage(), 8);
        assert_eq!(f.on_disk().state.revision, 2);
        f.cleanup();

        // CAS rolled back (state file restored, server restarted), journal intact.
        let f = J11Fixture::new();
        let c = f.client();
        let store = f.store(&c);
        let mut j = store.initialize(record()).unwrap();
        let old_cas = fs::read(&f.state).unwrap();
        j.advance(&record().attempt, State::MayHaveBeenSent, None)
            .unwrap();
        drop(j);
        fs::write(&f.state, &old_cas).unwrap();
        f.restart();
        reset_stage();
        assert!(store.open().is_err());
        assert_eq!(stage(), 8);
        assert_eq!(f.on_disk().state.revision, 1);
        f.cleanup();
    }

    #[test]
    fn j11_t14_unknown_advance_poisons_the_handle() {
        let _guard = test_guard();
        let f = J11Fixture::new();
        let c = f.client();
        let store = f.store(&c);
        let mut j = store.initialize(record()).unwrap();
        f.transport.lose_next_response("Advance");
        assert!(
            j.advance(&record().attempt, State::MayHaveBeenSent, None)
                .is_err()
        );
        let before = f.received();
        assert!(
            j.advance(&record().attempt, State::MayHaveBeenSent, None)
                .is_err()
        );
        assert_eq!(f.received(), before);
        assert!(!j.send_authorized());
        assert_eq!(j.record().revision, 1);
        drop(j);
        // The CAS committed; the journal did not. Recovery (J14) does not
        // exist yet, so this stays closed.
        assert_eq!(f.on_disk().state.revision, 2);
        reset_stage();
        assert!(store.open().is_err());
        assert_eq!(stage(), 8);
        f.cleanup();
    }

    #[test]
    fn j11_t15_send_is_never_authorized() {
        let _guard = test_guard();
        let f = J11Fixture::new();
        let c = f.client();
        let store = f.store(&c);
        let attempt = record().attempt;
        let mut j = store.initialize(record()).unwrap();
        assert!(!j.send_authorized() && !j.record().send_authorized());
        for (next, operation) in [
            (State::MayHaveBeenSent, None),
            (
                State::OperationKnown,
                Some(("operation-synthetic".to_string(), "op-1".to_string())),
            ),
            (State::DoneObserved, None),
            (State::TerminatedObserved, None),
            (State::ProofEstablished, None),
        ] {
            j.advance(&attempt, next, operation).unwrap();
            assert!(!j.send_authorized() && !j.record().send_authorized());
        }
        drop(j);
        let j = store.open().unwrap();
        assert_eq!(j.record().state, State::ProofEstablished);
        assert!(!j.send_authorized() && !j.record().send_authorized());
        f.cleanup();
    }

    /// Two journals sharing one v2 client: the second open is refused by the
    /// journal lock before it can start a session, so the first journal's fence
    /// is untouched and its advance still commits.
    #[test]
    fn j11_t17_second_open_on_shared_anchor_does_not_touch_the_fence() {
        let _guard = test_guard();
        let f = J11Fixture::new();
        let c = f.client();
        let store = f.store(&c);
        let mut j = store.initialize(record()).unwrap();
        let (fence, received) = (c.current_fence(), f.received());
        assert!(store.open().is_err());
        assert!(f.store(&c).initialize(record()).is_err());
        assert_eq!((c.current_fence(), f.received()), (fence, received));
        assert_eq!(f.on_disk().fence, 1);
        j.advance(&record().attempt, State::MayHaveBeenSent, None)
            .unwrap();
        assert_eq!(f.on_disk().state.revision, 2);
        f.cleanup();
    }

    /// F06: an advance that was sent, reported Unknown and delivered only after
    /// a new session began must not commit.
    #[test]
    fn j11_t16_f06_delayed_advance_after_unknown_cannot_commit() {
        let _guard = test_guard();
        let f = J11Fixture::new();
        let attempt = record().attempt;
        // 1. Session S1.
        let c1 = f.client();
        let mut j1 = f.store(&c1).initialize(record()).unwrap();
        assert_eq!(f.on_disk().fence, 1);
        // 2-4. A1 is sent and held in the network; the client sees Unknown.
        f.transport.hold_next("Advance");
        assert!(j1.advance(&attempt, State::MayHaveBeenSent, None).is_err());
        assert_eq!(f.transport.captured.lock().unwrap().len(), 1);
        assert_eq!(f.on_disk().state.revision, 1);
        drop(j1);
        // 5. Session S2: the new fence is durable before the comparison.
        let c2 = f.client();
        let mut j2 = f.store(&c2).open().unwrap();
        assert_eq!(f.on_disk().fence, 2);
        // 6-7. A1 arrives late and is refused without any change.
        match f.transport.deliver_held(0) {
            Some(CasV2Response::Fenced { current_fence, .. }) => assert_eq!(current_fence, 2),
            other => panic!("unexpected {other:?}"),
        }
        let durable = f.on_disk();
        assert_eq!((durable.state.revision, durable.ledger.len()), (1, 1));
        // 8. S2's own advance commits.
        j2.advance(&attempt, State::MayHaveBeenSent, None).unwrap();
        assert_eq!(f.on_disk().state.revision, 2);
        assert!(!j2.send_authorized());
        drop(j2);
        let j = f.store(&f.client()).open().unwrap();
        assert_eq!(j.record().state, State::MayHaveBeenSent);
        f.cleanup();
    }

    /// Control for F06: the same held request, re-stamped with the fence that
    /// is current after S2, commits. So the fence is what refused it above, and
    /// a plain read showing the old revision was never evidence of non-commit.
    #[test]
    fn j11_t16_control_without_fence_the_delayed_advance_would_commit() {
        let _guard = test_guard();
        let f = J11Fixture::new();
        let attempt = record().attempt;
        let c1 = f.client();
        let mut j1 = f.store(&c1).initialize(record()).unwrap();
        f.transport.hold_next("Advance");
        assert!(j1.advance(&attempt, State::MayHaveBeenSent, None).is_err());
        drop(j1);
        let c2 = f.client();
        let mut j2 = f.store(&c2).open().unwrap();
        assert_eq!(c2.read().unwrap().revision, 1);
        let mut held: serde_json::Value =
            serde_json::from_slice(&f.transport.captured.lock().unwrap()[0]).unwrap();
        held["fence"] = serde_json::json!(2);
        assert!(matches!(
            raw_value(&f.server(), held),
            CasV2Response::Committed {
                replayed: false,
                ..
            }
        ));
        assert_eq!(f.on_disk().state.revision, 2);
        // The journal never accepts a revision it did not write.
        assert!(j2.advance(&attempt, State::MayHaveBeenSent, None).is_err());
        assert_eq!(j2.record().revision, 1);
        drop(j2);
        reset_stage();
        assert!(f.store(&f.client()).open().is_err());
        assert_eq!(stage(), 8);
        f.cleanup();
    }

    // Phase 1-J12: TLS 1.3 mutual authentication and ACL. Unless a test says
    // otherwise it uses real TLS over loopback TCP (rustls on both ends), the
    // production loaders, `TlsTransport`, `cas_tls_accept` and
    // `CasTlsSession::serve`; the CAS behind it is the in-process reference.

    use super::cas_tls_reference::{Behavior, Ca, Files, Leaf, Recorded, TlsCasServer};

    const SERVER_DNS: &str = "cas-a.mikagami.invalid";
    const WRITER: &str = "mikagami-cas://test-cluster/node/node-1";
    const MONITOR: &str = "mikagami-cas://test-cluster/monitor/mon-1";
    const OTHER_NODE: &str = "mikagami-cas://test-cluster/node/node-2";

    fn j12_other_identity() -> AnchorIdentity {
        AnchorIdentity::from_hex(format!("{:064x}", 0x2222_0000_u64)).unwrap()
    }

    fn j12_acl() -> CasAcl {
        CasAcl::from_toml(&format!(
            r#"
            [[grant]]
            principal = "{WRITER}"
            identity = "{id}"
            ops = ["read", "session", "advance"]

            [[grant]]
            principal = "{MONITOR}"
            identity = "{id}"
            ops = ["read"]

            [[grant]]
            principal = "{OTHER_NODE}"
            identity = "{other}"
            ops = ["read", "session", "advance"]
            "#,
            id = j11_identity().as_str(),
            other = j12_other_identity().as_str(),
        ))
        .unwrap()
    }

    struct J12Fixture {
        j11: J11Fixture,
        files: Files,
        ca: Ca,
        server_leaf: Leaf,
        writer: Leaf,
        server: Option<TlsCasServer>,
    }

    impl J12Fixture {
        fn new() -> Self {
            Self::with(|f| f.server_config(&[&f.ca], vec![f.ca.crl(&[])]))
        }

        fn with(config: impl Fn(&Self) -> Arc<rustls::ServerConfig>) -> Self {
            let j11 = J11Fixture::new();
            let pki = j11.base.join("pki");
            fs::create_dir(&pki).unwrap();
            set_mode(&pki, 0o700);
            let ca = Ca::new("synthetic-ca-1");
            let mut f = Self {
                files: Files::new(pki),
                server_leaf: ca.server(SERVER_DNS),
                writer: ca.client(WRITER),
                ca,
                j11,
                server: None,
            };
            let config = config(&f);
            f.start(config, j12_acl());
            f
        }

        fn server_config(
            &self,
            client_cas: &[&Ca],
            crls: Vec<String>,
        ) -> Arc<rustls::ServerConfig> {
            cas_server_tls_config(
                self.files.roots(client_cas),
                self.files.crls(&crls),
                self.files.identity(&self.server_leaf),
            )
            .unwrap()
        }

        fn start(&mut self, config: Arc<rustls::ServerConfig>, acl: CasAcl) {
            let addr = self
                .server
                .take()
                .map(|server| {
                    let addr = server.addr;
                    server.stop();
                    addr
                })
                .unwrap_or_else(|| "127.0.0.1:0".parse().unwrap());
            self.server = Some(TlsCasServer::start(
                addr,
                config,
                Arc::new(acl),
                self.j11.server(),
            ));
        }

        fn srv(&self) -> &TlsCasServer {
            self.server.as_ref().unwrap()
        }

        fn client_config(&self, leaf: &Leaf, server_cas: &[&Ca]) -> Arc<rustls::ClientConfig> {
            let crls: Vec<String> = server_cas.iter().map(|ca| ca.crl(&[])).collect();
            self.client_config_with_crls(leaf, server_cas, &crls)
        }

        fn client_config_with_crls(
            &self,
            leaf: &Leaf,
            server_cas: &[&Ca],
            crls: &[String],
        ) -> Arc<rustls::ClientConfig> {
            cas_client_tls_config(
                self.files.roots(server_cas),
                self.files.crls(crls),
                self.files.identity(leaf),
            )
            .unwrap()
        }

        fn transport_with(
            &self,
            config: Arc<rustls::ClientConfig>,
            server_name: &str,
            io_timeout: Duration,
        ) -> Arc<TlsTransport> {
            Arc::new(
                TlsTransport::new(
                    self.srv().addr,
                    server_name,
                    config,
                    Duration::from_secs(2),
                    io_timeout,
                )
                .unwrap(),
            )
        }

        fn transport(&self, leaf: &Leaf) -> Arc<TlsTransport> {
            self.transport_with(
                self.client_config(leaf, &[&self.ca]),
                SERVER_DNS,
                Duration::from_secs(5),
            )
        }

        fn anchor_over(
            &self,
            transport: Arc<TlsTransport>,
            identity: AnchorIdentity,
        ) -> Arc<NetworkCasAnchor> {
            Arc::new(NetworkCasAnchor::new(transport, identity))
        }

        fn anchor(&self, leaf: &Leaf) -> Arc<NetworkCasAnchor> {
            self.anchor_over(self.transport(leaf), j11_identity())
        }

        fn cas_received(&self) -> usize {
            self.j11.received()
        }

        fn cleanup(mut self) {
            if let Some(server) = self.server.take() {
                server.stop();
            }
            self.j11.cleanup();
        }
    }

    fn handshake_failed(recorded: &[Recorded]) -> bool {
        recorded.contains(&Recorded::Outcome(CasServeOutcome::HandshakeFailed))
    }

    #[test]
    fn j12_t01_mutual_tls_round_trip_and_journal() {
        let _guard = test_guard();
        let f = J12Fixture::new();
        let c = f.anchor(&f.writer);
        let s0 = c.begin_session().unwrap();
        let s1 = c.advance(&s0, &dg('a')).unwrap();
        assert_eq!((c.read().unwrap(), s1.revision), (s1.clone(), 1));
        let recorded = f.srv().wait_recorded(3);
        assert!(recorded.iter().all(|r| *r
            == Recorded::Outcome(CasServeOutcome::Forwarded {
                principal: WRITER.into(),
                responded: true
            })));
        // The journal over TLS, end to end.
        let f2 = J12Fixture::new();
        let c = f2.anchor(&f2.writer);
        let store = f2.j11.store(&c);
        let mut j = store.initialize(record()).unwrap();
        j.advance(&record().attempt, State::MayHaveBeenSent, None)
            .unwrap();
        assert!(!j.send_authorized());
        drop(j);
        let j = store.open().unwrap();
        assert_eq!(j.record().state, State::MayHaveBeenSent);
        assert_eq!(f2.j11.on_disk().state.revision, 2);
        f.cleanup();
        f2.cleanup();
    }

    #[test]
    fn j12_t02_untrusted_ca_is_refused_both_ways() {
        let _guard = test_guard();
        let f = J12Fixture::new();
        let rogue = Ca::new("synthetic-rogue-ca");
        // Client certificate from another CA: the server refuses it after the
        // client already wrote (TLS 1.3), so the client must report Unknown.
        let c = f.anchor(&rogue.client(WRITER));
        assert_eq!(c.begin_session(), Err(AnchorError::Unknown));
        assert!(handshake_failed(&f.srv().wait_recorded(1)));
        // Server certificate the client does not trust: refused in the
        // handshake, before any request byte.
        let transport = f.transport_with(
            f.client_config(&f.writer, &[&rogue]),
            SERVER_DNS,
            Duration::from_secs(5),
        );
        let c = f.anchor_over(transport, j11_identity());
        assert_eq!(c.begin_session(), Err(AnchorError::AuthFailure));
        assert_eq!(f.cas_received(), 0);
        assert_eq!(f.j11.on_disk().fence, 0);
        f.cleanup();
    }

    #[test]
    fn j12_t03_missing_client_certificate_is_refused() {
        let _guard = test_guard();
        let f = J12Fixture::new();
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(f.files.roots(&[&f.ca]))
        .with_no_client_auth();
        config.alpn_protocols = vec![CAS_TLS_ALPN.to_vec()];
        let c = f.anchor_over(
            f.transport_with(Arc::new(config), SERVER_DNS, Duration::from_secs(5)),
            j11_identity(),
        );
        assert_eq!(c.begin_session(), Err(AnchorError::Unknown));
        assert!(handshake_failed(&f.srv().wait_recorded(1)));
        assert_eq!(f.cas_received(), 0);
        f.cleanup();
    }

    #[test]
    fn j12_t04_expired_certificates_are_refused() {
        let _guard = test_guard();
        let f = J12Fixture::new();
        let c = f.anchor(&f.ca.client_with_uris(&[WRITER], true));
        assert_eq!(c.begin_session(), Err(AnchorError::Unknown));
        assert!(handshake_failed(&f.srv().wait_recorded(1)));
        // A server whose own certificate (from the trusted CA) has expired.
        let g = J12Fixture::with(|g| {
            cas_server_tls_config(
                g.files.roots(&[&g.ca]),
                g.files.crls(&[g.ca.crl(&[])]),
                g.files.identity(&g.ca.expired_server(SERVER_DNS)),
            )
            .unwrap()
        });
        let c = g.anchor(&g.writer);
        assert_eq!(c.begin_session(), Err(AnchorError::AuthFailure));
        assert_eq!((f.cas_received(), g.cas_received()), (0, 0));
        f.cleanup();
        g.cleanup();
    }

    #[test]
    fn j12_t05_server_name_mismatch_is_refused() {
        let _guard = test_guard();
        let f = J12Fixture::new();
        let c = f.anchor_over(
            f.transport_with(
                f.client_config(&f.writer, &[&f.ca]),
                "cas-b.mikagami.invalid",
                Duration::from_secs(5),
            ),
            j11_identity(),
        );
        assert_eq!(c.begin_session(), Err(AnchorError::AuthFailure));
        assert_eq!(f.cas_received(), 0);
        // An IP address is not accepted as a server name at all.
        assert!(
            TlsTransport::new(
                f.srv().addr,
                "127.0.0.1",
                f.client_config(&f.writer, &[&f.ca]),
                Duration::from_secs(1),
                Duration::from_secs(1),
            )
            .is_err()
        );
        f.cleanup();
    }

    #[test]
    fn j12_t06_principal_must_be_registered_and_unique() {
        let _guard = test_guard();
        let f = J12Fixture::new();
        // Valid certificate, valid principal, no grant.
        let stranger = f.anchor(&f.ca.client("mikagami-cas://test-cluster/node/node-9"));
        assert_eq!(stranger.begin_session(), Err(AnchorError::Forbidden));
        assert_eq!(stranger.read(), Err(AnchorError::Forbidden));
        // No URI SAN, two URI SANs, or a URI outside the scheme: no principal.
        for uris in [
            vec![],
            vec![WRITER, MONITOR],
            vec!["https://example.invalid/node-1"],
            vec!["mikagami-cas://Test-Cluster/node/node-1"],
        ] {
            let c = f.anchor(&f.ca.client_with_uris(&uris, false));
            assert_eq!(c.read(), Err(AnchorError::Unknown), "{uris:?}");
        }
        let recorded = f.srv().wait_recorded(6);
        assert_eq!(
            recorded
                .iter()
                .filter(|r| **r == Recorded::Outcome(CasServeOutcome::NoPrincipal))
                .count(),
            4
        );
        assert_eq!(
            recorded
                .iter()
                .filter(
                    |r| **r == Recorded::Outcome(CasServeOutcome::Refused(CasV2Reject::Forbidden))
                )
                .count(),
            2
        );
        assert_eq!(f.cas_received(), 0);
        f.cleanup();
    }

    #[test]
    fn j12_t07_identity_is_bound_to_the_principal() {
        let _guard = test_guard();
        let f = J12Fixture::new();
        // node-2 holds every op, but on another identity.
        let other = f.anchor(&f.ca.client(OTHER_NODE));
        assert_eq!(other.read(), Err(AnchorError::Forbidden));
        assert_eq!(other.begin_session(), Err(AnchorError::Forbidden));
        // node-1 asking about node-2's identity.
        let crossed = f.anchor_over(f.transport(&f.writer), j12_other_identity());
        assert_eq!(crossed.read(), Err(AnchorError::Forbidden));
        assert_eq!(crossed.begin_session(), Err(AnchorError::Forbidden));
        assert_eq!(f.cas_received(), 0);
        assert_eq!(f.j11.on_disk().fence, 0);
        f.cleanup();
    }

    #[test]
    fn j12_t08_monitor_reads_but_cannot_write() {
        let _guard = test_guard();
        let f = J12Fixture::new();
        let writer = f.anchor(&f.writer);
        let s0 = writer.begin_session().unwrap();
        writer.advance(&s0, &dg('a')).unwrap();
        let id = writer.last_advance_request_id().unwrap();
        let monitor = f.anchor(&f.ca.client(MONITOR));
        assert_eq!(monitor.read().unwrap().revision, 1);
        assert!(monitor.inquire(&id).unwrap().found);
        assert_eq!(monitor.begin_session(), Err(AnchorError::Forbidden));
        // Advance through the raw transport with the writer's live fence.
        let raw_advance =
            serde_json::to_vec(&adv(1, &writer.read().unwrap(), &dg('b'), rid(77))).unwrap();
        let reply: CasV2Response = serde_json::from_slice(
            &f.transport(&f.ca.client(MONITOR))
                .exchange(&raw_advance)
                .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            reply,
            CasV2Response::Rejected {
                reason: CasV2Reject::Forbidden,
                ..
            }
        ));
        let durable = f.j11.on_disk();
        assert_eq!((durable.state.revision, durable.fence), (1, 1));
        f.cleanup();
    }

    #[test]
    fn j12_t09_acl_structure_is_enforced_at_load() {
        let id = j11_identity();
        let grant = |principal: &str, ops: &str| {
            format!(
                "[[grant]]\nprincipal = \"{principal}\"\nidentity = \"{}\"\nops = {ops}\n",
                id.as_str()
            )
        };
        assert!(CasAcl::from_toml(&grant(WRITER, r#"["read", "session", "advance"]"#)).is_ok());
        for bad in [
            grant(WRITER, r#"["session"]"#),
            grant(WRITER, r#"["advance"]"#),
            grant(WRITER, r#"[]"#),
            grant(WRITER, r#"["read", "read"]"#),
            grant(WRITER, r#"["admin"]"#),
            grant("https://example.invalid/x", r#"["read"]"#),
            grant(WRITER, r#"["read"]"#) + &grant(WRITER, r#"["read"]"#),
            grant(WRITER, r#"["read", "session", "advance"]"#)
                + &grant(OTHER_NODE, r#"["read", "session", "advance"]"#),
            "[[grant]]\nprincipal = \"mikagami-cas://x/y\"\nidentity = \"not-hex\"\nops = [\"read\"]\n".into(),
            grant(WRITER, r#"["read"]"#) + "extra = 1\n",
        ] {
            assert!(CasAcl::from_toml(&bad).is_err(), "{bad}");
        }
        // Over TLS: only the advance principal may begin a session.
        let _guard = test_guard();
        let f = J12Fixture::new();
        assert_eq!(
            f.anchor(&f.ca.client(MONITOR)).begin_session(),
            Err(AnchorError::Forbidden)
        );
        assert!(f.anchor(&f.writer).begin_session().is_ok());
        assert_eq!(f.j11.on_disk().fence, 1);
        f.cleanup();
    }

    #[test]
    fn j12_t10_duplicate_request_id_over_tls() {
        let _guard = test_guard();
        let f = J12Fixture::new();
        let transport = f.transport(&f.writer);
        let call = |request: &CasV2Request| -> CasV2Response {
            serde_json::from_slice(
                &transport
                    .exchange(&serde_json::to_vec(request).unwrap())
                    .unwrap(),
            )
            .unwrap()
        };
        let (s0, fence) = match call(&CasV2Request::BeginSession {
            v: 2,
            request_id: rid(1),
            identity: j11_identity(),
        }) {
            CasV2Response::Session { state, fence, .. } => (state, fence),
            other => panic!("unexpected {other:?}"),
        };
        let request = adv(fence, &s0, &dg('a'), rid(2));
        assert!(matches!(
            call(&request),
            CasV2Response::Committed {
                replayed: false,
                ..
            }
        ));
        assert!(matches!(
            call(&request),
            CasV2Response::Committed { replayed: true, .. }
        ));
        assert!(matches!(
            call(&adv(fence, &s0, &dg('b'), rid(2))),
            CasV2Response::Rejected {
                reason: CasV2Reject::RequestIdReuse,
                ..
            }
        ));
        assert_eq!(f.j11.on_disk().state.revision, 1);
        f.cleanup();
    }

    #[test]
    fn j12_t11_protocol_version_and_alpn_mismatch() {
        let _guard = test_guard();
        let f = J12Fixture::new();
        // Application protocol v1 inside a valid TLS session: refused before
        // the CAS.
        let v1 = serde_json::to_vec(&CasRequest::Read {
            request_id: rid(3),
            identity: j11_identity(),
            token: "synthetic-token".into(),
        })
        .unwrap();
        let reply: CasV2Response =
            serde_json::from_slice(&f.transport(&f.writer).exchange(&v1).unwrap()).unwrap();
        assert!(matches!(
            reply,
            CasV2Response::Rejected {
                reason: CasV2Reject::Version,
                ..
            }
        ));
        assert_eq!(f.cas_received(), 0);
        // Our client without ALPN: it refuses the session itself, unsent.
        let mut config = (*f.client_config(&f.writer, &[&f.ca])).clone();
        config.alpn_protocols.clear();
        let config = Arc::new(config);
        let c = f.anchor_over(
            f.transport_with(Arc::clone(&config), SERVER_DNS, Duration::from_secs(5)),
            j11_identity(),
        );
        assert_eq!(c.read(), Err(AnchorError::AuthFailure));
        // A raw rustls client without ALPN that writes a request anyway: the
        // server refuses after the handshake, before reading it.
        let mut tcp = std::net::TcpStream::connect(f.srv().addr).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut conn = rustls::ClientConnection::new(
            config,
            rustls::pki_types::ServerName::try_from(SERVER_DNS).unwrap(),
        )
        .unwrap();
        let read = serde_json::to_vec(&CasV2Request::Read {
            v: 2,
            request_id: rid(4),
            identity: j11_identity(),
        })
        .unwrap();
        while conn.is_handshaking() {
            conn.complete_io(&mut tcp).unwrap();
        }
        assert_eq!(
            conn.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        let mut stream = rustls::Stream::new(&mut conn, &mut tcp);
        let _ = write_frame(&mut stream, &read);
        assert!(read_frame(&mut stream).is_err());
        assert!(
            f.srv()
                .wait_recorded(3)
                .contains(&Recorded::Outcome(CasServeOutcome::ProtocolMismatch))
        );
        // A server that negotiates no ALPN: the client refuses before writing.
        let mut g = J12Fixture::new();
        let mut config = (*g.server_config(&[&g.ca], vec![g.ca.crl(&[])])).clone();
        config.alpn_protocols.clear();
        g.start(Arc::new(config), j12_acl());
        assert_eq!(g.anchor(&g.writer).read(), Err(AnchorError::AuthFailure));
        assert_eq!((f.cas_received(), g.cas_received()), (0, 0));
        // TLS 1.2 is not compiled in (rustls without the `tls12` feature) and
        // both configurations list TLS 1.3 only; the raw session above shows
        // the negotiated version. A TLS 1.2 peer cannot be built to test it.
        f.cleanup();
        g.cleanup();
    }

    #[test]
    fn j12_t12_connection_failure_is_not_sent() {
        let _guard = test_guard();
        let f = J12Fixture::new();
        let free = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap()
        };
        let transport = TlsTransport::new(
            free,
            SERVER_DNS,
            f.client_config(&f.writer, &[&f.ca]),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(transport.exchange(b"{}"), Err(TransportError::NotSent));
        let c = f.anchor_over(Arc::new(transport), j11_identity());
        assert_eq!(c.begin_session(), Err(AnchorError::Unavailable));
        assert_eq!(c.current_fence(), None);
        // Oversized requests are not sent either.
        assert_eq!(
            f.transport(&f.writer)
                .exchange(&vec![b' '; MAX_CAS_MESSAGE_BYTES + 1]),
            Err(TransportError::NotSent)
        );
        f.cleanup();
    }

    #[test]
    fn j12_t13_connection_cut_after_request_is_unknown() {
        let _guard = test_guard();
        let f = J12Fixture::new();
        let c = f.anchor(&f.writer);
        let s0 = c.begin_session().unwrap();
        f.srv().next_behavior("Advance", Behavior::CloseAfterRead);
        assert_eq!(c.advance(&s0, &dg('a')), Err(AnchorError::Unknown));
        assert!(
            f.srv()
                .wait_recorded(2)
                .contains(&Recorded::ClosedAfterRead)
        );
        // Nothing reached the CAS, yet the client concluded nothing: no fence,
        // no resend.
        assert_eq!(c.current_fence(), None);
        assert_eq!(f.j11.on_disk().state.revision, 0);
        let before = f.cas_received();
        assert_eq!(c.advance(&s0, &dg('a')), Err(AnchorError::Fenced));
        assert_eq!(f.cas_received(), before);
        f.cleanup();
    }

    #[test]
    fn j12_t14_lost_response_poisons_the_journal() {
        let _guard = test_guard();
        let f = J12Fixture::new();
        let c = f.anchor(&f.writer);
        let store = f.j11.store(&c);
        let mut j = store.initialize(record()).unwrap();
        f.srv().next_behavior("Advance", Behavior::DropResponse);
        assert!(
            j.advance(&record().attempt, State::MayHaveBeenSent, None)
                .is_err()
        );
        assert_eq!(f.j11.on_disk().state.revision, 2);
        let before = f.cas_received();
        assert!(
            j.advance(&record().attempt, State::MayHaveBeenSent, None)
                .is_err()
        );
        assert_eq!(f.cas_received(), before);
        drop(j);
        reset_stage();
        assert!(store.open().is_err());
        assert_eq!(stage(), 8);
        f.cleanup();
    }

    #[test]
    fn j12_t15_late_response_is_unknown_and_not_resent() {
        let _guard = test_guard();
        let f = J12Fixture::new();
        let c = f.anchor_over(
            f.transport_with(
                f.client_config(&f.writer, &[&f.ca]),
                SERVER_DNS,
                Duration::from_millis(300),
            ),
            j11_identity(),
        );
        let s0 = c.begin_session().unwrap();
        let (release_tx, release) = mpsc::channel();
        f.srv()
            .next_behavior("Advance", Behavior::HoldResponse(release));
        assert_eq!(c.advance(&s0, &dg('a')), Err(AnchorError::Unknown));
        release_tx.send(()).unwrap();
        f.srv().wait_recorded(2);
        // The CAS committed exactly once; the client did not try again.
        let durable = f.j11.on_disk();
        assert_eq!((durable.state.revision, durable.ledger.len()), (1, 1));
        assert_eq!(f.cas_received(), 2);
        assert_eq!(c.current_fence(), None);
        f.cleanup();
    }

    /// F06 over real TLS: the delayed advance reaches the CAS only after a new
    /// session began, and is fenced.
    #[test]
    fn j12_t16_old_fence_advance_over_tls_is_fenced() {
        let _guard = test_guard();
        let f = J12Fixture::new();
        let a = f.anchor_over(
            f.transport_with(
                f.client_config(&f.writer, &[&f.ca]),
                SERVER_DNS,
                Duration::from_millis(300),
            ),
            j11_identity(),
        );
        let s0 = a.begin_session().unwrap();
        let (arrived_tx, arrived) = mpsc::channel();
        let (release_tx, release) = mpsc::channel();
        let (reply_tx, reply) = mpsc::channel();
        f.srv().next_behavior(
            "Advance",
            Behavior::HoldBeforeCas {
                arrived: arrived_tx,
                release,
                reply: reply_tx,
            },
        );
        assert_eq!(a.advance(&s0, &dg('a')), Err(AnchorError::Unknown));
        wait(&arrived);
        let b = f.anchor(&f.writer);
        let s0b = b.begin_session().unwrap();
        assert_eq!(f.j11.on_disk().fence, 2);
        release_tx.send(()).unwrap();
        let answer: CasV2Response = serde_json::from_slice(
            &reply
                .recv_timeout(Duration::from_secs(10))
                .unwrap()
                .expect("the CAS answered the delayed advance"),
        )
        .unwrap();
        assert!(
            matches!(
                answer,
                CasV2Response::Fenced {
                    current_fence: 2,
                    ..
                }
            ),
            "{answer:?}"
        );
        f.srv().wait_recorded(3);
        let durable = f.j11.on_disk();
        assert_eq!((durable.state.revision, durable.ledger.len()), (0, 0));
        assert_eq!(b.advance(&s0b, &dg('b')).unwrap().revision, 1);
        f.cleanup();
    }

    #[test]
    fn j12_t17_reconnect_and_server_restart() {
        let _guard = test_guard();
        let mut f = J12Fixture::new();
        let c = f.anchor(&f.writer);
        let mut state = c.begin_session().unwrap();
        for n in 0..5u8 {
            state = c
                .advance(&state, &format!("{:064x}", u64::from(n) + 1))
                .unwrap();
        }
        // One TLS connection per request.
        assert_eq!(f.srv().wait_recorded(6).len(), 6);
        // Restart the TLS server on the same address and the CAS from disk.
        f.j11.restart();
        let config = f.server_config(&[&f.ca], vec![f.ca.crl(&[])]);
        f.start(config, j12_acl());
        let resumed = c.begin_session().unwrap();
        assert_eq!(resumed, state);
        assert_eq!(c.current_fence(), Some(2));
        f.cleanup();
    }

    #[test]
    fn j12_t18_certificate_rotation_revocation_and_ca_rollover() {
        let _guard = test_guard();
        let mut f = J12Fixture::new();
        // New certificate for the same principal: works without an ACL change.
        let rotated = f.ca.client(WRITER);
        assert!(f.anchor(&rotated).read().is_ok());
        // Revoke the old certificate: refused; the rotated one still works.
        let config = f.server_config(&[&f.ca], vec![f.ca.crl(&[f.writer.serial])]);
        f.start(config, j12_acl());
        assert_eq!(f.anchor(&f.writer).read(), Err(AnchorError::Unknown));
        assert!(handshake_failed(&f.srv().wait_recorded(1)));
        assert!(f.anchor(&rotated).read().is_ok());
        // CA rollover: trust both CAs, then only the new one.
        let ca2 = Ca::new("synthetic-ca-2");
        let from_ca2 = ca2.client(WRITER);
        let config = f.server_config(&[&f.ca, &ca2], vec![f.ca.crl(&[]), ca2.crl(&[])]);
        f.start(config, j12_acl());
        assert!(f.anchor(&from_ca2).read().is_ok());
        assert!(f.anchor(&rotated).read().is_ok());
        let config = f.server_config(&[&ca2], vec![ca2.crl(&[])]);
        f.start(config, j12_acl());
        assert!(f.anchor(&from_ca2).read().is_ok());
        assert_eq!(f.anchor(&rotated).read(), Err(AnchorError::Unknown));
        // A trusted CA without a CRL on the server: refused (unknown status).
        let config = f.server_config(&[&f.ca, &ca2], vec![ca2.crl(&[])]);
        f.start(config, j12_acl());
        assert_eq!(f.anchor(&rotated).read(), Err(AnchorError::Unknown));
        // A CRL past its nextUpdate: refused, not silently trusted.
        let config = f.server_config(&[&f.ca], vec![f.ca.expired_crl()]);
        f.start(config, j12_acl());
        assert_eq!(f.anchor(&rotated).read(), Err(AnchorError::Unknown));
        f.cleanup();
    }

    #[test]
    fn j12_t19_secrets_stay_out_of_debug_errors_and_permissive_files() {
        let _guard = test_guard();
        let f = J12Fixture::new();
        let leaf = f.ca.client(WRITER);
        let key_body: String = leaf
            .key_pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        assert!(key_body.len() > 40);
        let identity = f.files.identity(&leaf);
        let transport = f.transport(&leaf);
        for text in [
            format!("{identity:?}"),
            format!("{transport:?}"),
            format!("{:?}", f.anchor(&leaf).begin_session()),
            format!("{:?}", CasTlsError::Pem),
        ] {
            for chunk in key_body.as_bytes().chunks(16) {
                assert!(
                    !text.contains(std::str::from_utf8(chunk).unwrap()),
                    "{text}"
                );
            }
        }
        // Key files must be private; certificates must not be writable by others.
        let cert = f.files.write(&leaf.cert_pem, 0o644);
        for mode in [0o640, 0o604, 0o644] {
            let key = f.files.write(&leaf.key_pem, mode);
            assert_eq!(
                CasTlsIdentity::load(&cert, &key).unwrap_err(),
                CasTlsError::File
            );
        }
        let key = f.files.write(&leaf.key_pem, 0o600);
        let writable_cert = f.files.write(&leaf.cert_pem, 0o664);
        assert_eq!(
            CasTlsIdentity::load(&writable_cert, &key).unwrap_err(),
            CasTlsError::File
        );
        let link = f.files.dir.join("link.pem");
        symlink(&key, &link).unwrap();
        assert_eq!(
            CasTlsIdentity::load(&cert, &link).unwrap_err(),
            CasTlsError::File
        );
        assert_eq!(
            CasTlsIdentity::load(&key, &cert).unwrap_err(),
            CasTlsError::File
        );
        assert_eq!(
            CasTlsIdentity::load(&cert, &f.files.dir.join("missing")).unwrap_err(),
            CasTlsError::File
        );
        // A FIFO in place of the key is refused without blocking on open.
        let fifo = f.files.dir.join("fifo.pem");
        make_fifo(&fifo);
        assert_eq!(
            CasTlsIdentity::load(&cert, &fifo).unwrap_err(),
            CasTlsError::File
        );
        assert!(CasTlsIdentity::load(&cert, &key).is_ok());
        f.cleanup();
    }

    /// Revocation checking cannot be switched off by passing no CRL, and the
    /// client checks the server's certificate against a CRL too.
    #[test]
    fn j12_t21_revocation_is_mandatory_on_both_ends() {
        let _guard = test_guard();
        let f = J12Fixture::new();
        assert_eq!(
            cas_server_tls_config(
                f.files.roots(&[&f.ca]),
                Vec::new(),
                f.files.identity(&f.server_leaf)
            )
            .unwrap_err(),
            CasTlsError::Config
        );
        assert_eq!(
            cas_client_tls_config(
                f.files.roots(&[&f.ca]),
                Vec::new(),
                f.files.identity(&f.writer)
            )
            .unwrap_err(),
            CasTlsError::Config
        );
        // The server's certificate revoked on the client's CRL: refused in the
        // handshake, before any request byte.
        let revoked =
            f.client_config_with_crls(&f.writer, &[&f.ca], &[f.ca.crl(&[f.server_leaf.serial])]);
        let c = f.anchor_over(
            f.transport_with(revoked, SERVER_DNS, Duration::from_secs(5)),
            j11_identity(),
        );
        assert_eq!(c.begin_session(), Err(AnchorError::AuthFailure));
        // The client's CRL past its nextUpdate: refused as well.
        let stale = f.client_config_with_crls(&f.writer, &[&f.ca], &[f.ca.expired_crl()]);
        let c = f.anchor_over(
            f.transport_with(stale, SERVER_DNS, Duration::from_secs(5)),
            j11_identity(),
        );
        assert_eq!(c.begin_session(), Err(AnchorError::AuthFailure));
        assert_eq!(f.cas_received(), 0);
        assert!(f.anchor(&f.writer).begin_session().is_ok());
        f.cleanup();
    }

    #[test]
    fn j12_t20_send_is_never_authorized_over_tls() {
        let _guard = test_guard();
        let f = J12Fixture::new();
        let c = f.anchor(&f.writer);
        let store = f.j11.store(&c);
        let attempt = record().attempt;
        let mut j = store.initialize(record()).unwrap();
        for (next, operation) in [
            (State::MayHaveBeenSent, None),
            (
                State::OperationKnown,
                Some(("operation-synthetic".to_string(), "op-1".to_string())),
            ),
            (State::DoneObserved, None),
            (State::TerminatedObserved, None),
            (State::ProofEstablished, None),
        ] {
            j.advance(&attempt, next, operation).unwrap();
            assert!(!j.send_authorized() && !j.record().send_authorized());
        }
        drop(j);
        let j = store.open().unwrap();
        assert!(!j.send_authorized());
        f.cleanup();
    }

    // Phase 1-J13: the durable network CAS server. Real TLS over loopback, the
    // production store (`CasStore`), server (`CasNetworkServer`), loaders and
    // client (`TlsTransport`, `NetworkCasAnchor`). Faults are injected at the
    // named steps of a durable write (`CasStorePoint`); crashes are real
    // SIGKILLs of a child server process. Interleavings are forced with
    // pause/notify hooks, never with sleeps.

    use super::cas_store_hooks::Action;

    const J13_CHILD: &str = "gce_operation_journal::tests::j13_child_server";
    const ROGUE: &str = "mikagami-cas://test-cluster/node/rogue";
    /// A request id with hex letters, so that upper-casing changes it.
    const J13_LETTERED_ID: &str = "abcdef00000000000000000000000007";

    fn j13_limits() -> CasServerLimits {
        CasServerLimits {
            max_connections: 8,
            handshake_deadline: Duration::from_secs(3),
            io_timeout: Duration::from_secs(3),
        }
    }

    fn j13_acl_text() -> String {
        format!(
            r#"
            [[grant]]
            principal = "{WRITER}"
            identity = "{id}"
            ops = ["read", "session", "advance"]

            [[grant]]
            principal = "{MONITOR}"
            identity = "{id}"
            ops = ["read"]

            [[grant]]
            principal = "{OTHER_NODE}"
            identity = "{other}"
            ops = ["read", "session", "advance"]
            "#,
            id = j11_identity().as_str(),
            other = j12_other_identity().as_str(),
        )
    }

    struct J13Pki {
        files: Files,
        ca: Ca,
        server_leaf: Leaf,
        writer: Leaf,
        monitor: Leaf,
        other: Leaf,
        rogue: Leaf,
        paths: CasServerFiles,
    }

    impl J13Pki {
        fn new(dir: PathBuf) -> Self {
            fs::create_dir(&dir).unwrap();
            set_mode(&dir, 0o700);
            let files = Files::new(dir);
            let ca = Ca::new("synthetic-j13-ca");
            let server_leaf = ca.server(SERVER_DNS);
            let paths = CasServerFiles {
                certificate: files.write(&server_leaf.cert_pem, 0o644),
                key: files.write(&server_leaf.key_pem, 0o600),
                client_roots: files.write(&ca.cert_pem, 0o644),
                crls: files.write(&ca.crl(&[]), 0o644),
                acl: files.write(&j13_acl_text(), 0o644),
            };
            Self {
                writer: ca.client(WRITER),
                monitor: ca.client(MONITOR),
                other: ca.client(OTHER_NODE),
                rogue: ca.client(ROGUE),
                files,
                ca,
                server_leaf,
                paths,
            }
        }

        fn client_config(&self, leaf: &Leaf) -> Arc<rustls::ClientConfig> {
            cas_client_tls_config(
                self.files.roots(&[&self.ca]),
                self.files.crls(&[self.ca.crl(&[])]),
                self.files.identity(leaf),
            )
            .unwrap()
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    enum J13Start {
        Store(CasStoreError),
        Server(CasStartError),
    }

    struct J13Running {
        server: Arc<CasNetworkServer>,
        serve: thread::JoinHandle<CasServeExit>,
        workers: Arc<Mutex<Vec<thread::JoinHandle<()>>>>,
    }

    struct J13 {
        base: PathBuf,
        store: PathBuf,
        anchor: PathBuf,
        pki: J13Pki,
        events: Arc<Mutex<Vec<CasEvent>>>,
        addr: std::net::SocketAddr,
        running: Option<J13Running>,
        children: usize,
    }

    impl J13 {
        /// A created store with both identities at genesis; no server.
        fn provisioned() -> Self {
            let base = unique_base("j13");
            let store = base.join("store");
            fs::create_dir(&store).unwrap();
            set_mode(&store, 0o700);
            CasStore::create_for_test(&store).unwrap();
            CasStore::provision_for_test(&store, &j11_identity()).unwrap();
            CasStore::provision_for_test(&store, &j12_other_identity()).unwrap();
            let anchor = base.join("anchor");
            fs::create_dir(&anchor).unwrap();
            set_mode(&anchor, 0o700);
            Self {
                pki: J13Pki::new(base.join("pki")),
                base,
                store,
                anchor,
                events: Arc::new(Mutex::new(Vec::new())),
                addr: "127.0.0.1:0".parse().unwrap(),
                running: None,
                children: 0,
            }
        }

        fn new() -> Self {
            let mut f = Self::provisioned();
            f.start();
            f
        }

        fn start(&mut self) {
            self.try_start(j13_limits()).unwrap();
        }

        fn try_start(&mut self, limits: CasServerLimits) -> Result<(), J13Start> {
            assert!(self.running.is_none());
            let store = CasStore::open_for_test(&self.store).map_err(J13Start::Store)?;
            let events = Arc::clone(&self.events);
            let sink: Arc<dyn Fn(&CasEvent) + Send + Sync> =
                Arc::new(move |event: &CasEvent| events.lock().unwrap().push(event.clone()));
            let server = Arc::new(
                CasNetworkServer::start(store, &self.pki.paths, limits, sink)
                    .map_err(J13Start::Server)?,
            );
            let listener = server.bind(self.addr).map_err(J13Start::Server)?;
            self.addr = listener.local_addr().unwrap();
            let workers: Arc<Mutex<Vec<thread::JoinHandle<()>>>> = Arc::default();
            let (s, w) = (Arc::clone(&server), Arc::clone(&workers));
            let serve = thread::spawn(move || {
                let exit = s.serve(&listener, &mut |connection| {
                    w.lock()
                        .unwrap()
                        .push(thread::spawn(move || connection.run()));
                });
                drop(listener);
                exit
            });
            self.running = Some(J13Running {
                server,
                serve,
                workers,
            });
            Ok(())
        }

        fn server(&self) -> &CasNetworkServer {
            &self.running.as_ref().unwrap().server
        }

        fn arm(&self, point: CasStorePoint, op: &'static str, action: Action) {
            self.server().store().arm(point, op, action);
        }

        /// Graceful stop: no new connection, admitted ones finish, the store
        /// lock is released.
        fn stop(&mut self) -> CasServeExit {
            let running = self.running.take().unwrap();
            running.server.shutdown();
            let exit = running.serve.join().unwrap();
            let workers: Vec<_> = running.workers.lock().unwrap().drain(..).collect();
            for worker in workers {
                worker.join().unwrap();
            }
            let server = Arc::try_unwrap(running.server).expect("no connection left");
            drop(server.into_store());
            exit
        }

        fn restart(&mut self) {
            self.stop();
            self.start();
        }

        fn transport_for(&self, leaf: &Leaf, io_timeout: Duration) -> Arc<TlsTransport> {
            Arc::new(
                TlsTransport::new(
                    self.addr,
                    SERVER_DNS,
                    self.pki.client_config(leaf),
                    Duration::from_secs(2),
                    io_timeout,
                )
                .unwrap(),
            )
        }

        fn anchor_for(&self, leaf: &Leaf, identity: AnchorIdentity) -> Arc<NetworkCasAnchor> {
            Arc::new(NetworkCasAnchor::new(
                self.transport_for(leaf, Duration::from_secs(5)),
                identity,
            ))
        }

        fn writer(&self) -> Arc<NetworkCasAnchor> {
            self.anchor_for(&self.pki.writer, j11_identity())
        }

        fn send_bytes(&self, leaf: &Leaf, bytes: &[u8]) -> Result<CasV2Response, TransportError> {
            let reply = self
                .transport_for(leaf, Duration::from_secs(5))
                .exchange(bytes)?;
            Ok(serde_json::from_slice(&reply).unwrap())
        }

        fn send(
            &self,
            leaf: &Leaf,
            request: &CasV2Request,
        ) -> Result<CasV2Response, TransportError> {
            self.send_bytes(leaf, &serde_json::to_vec(request).unwrap())
        }

        fn send_value(
            &self,
            leaf: &Leaf,
            value: serde_json::Value,
        ) -> Result<CasV2Response, TransportError> {
            self.send_bytes(leaf, &serde_json::to_vec(&value).unwrap())
        }

        fn state_path(&self, identity: &AnchorIdentity) -> PathBuf {
            self.store.join(cas_state_name(identity))
        }

        /// What the disk holds, read directly (not through the server).
        fn disk(&self, identity: &AnchorIdentity) -> CasDurableState {
            decode_cas_state(&fs::read(self.state_path(identity)).unwrap()).unwrap()
        }

        fn temporaries(&self) -> usize {
            fs::read_dir(&self.store)
                .unwrap()
                .filter(|entry| {
                    entry
                        .as_ref()
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .contains(CAS_TEMP_MARKER)
                })
                .count()
        }

        fn events(&self) -> Vec<CasEvent> {
            self.events.lock().unwrap().clone()
        }

        fn authorized(&self, op: CasOp) -> usize {
            self.events()
                .iter()
                .filter(|event| matches!(event, CasEvent::Authorized { op: o, .. } if *o == op))
                .count()
        }

        fn wait_event(&self, what: &str, predicate: impl Fn(&CasEvent) -> bool) {
            for _ in 0..1500 {
                if self.events().iter().any(&predicate) {
                    return;
                }
                thread::sleep(Duration::from_millis(10));
            }
            panic!("no event: {what}");
        }

        fn journal_store(&self, client: &Arc<NetworkCasAnchor>) -> JournalStore {
            JournalStore::for_test_with_anchor(&self.anchor, client.clone()).unwrap()
        }

        /// A child server process (this test binary in `j13_child_server`).
        /// `Err(byte)` if it refused to start.
        fn spawn_child(&mut self, crash: Option<&str>, port: u16) -> Result<J13Child, u8> {
            self.children += 1;
            let ready = self.base.join(format!("child-{}.ready", self.children));
            let port_file = self.base.join(format!("child-{}.port", self.children));
            let stderr = self.base.join(format!("child-{}.stderr", self.children));
            make_fifo(&ready);
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args(["--exact", J13_CHILD, "--nocapture"])
                .env("MKG_J13_STORE", &self.store)
                .env("MKG_J13_CERT", &self.pki.paths.certificate)
                .env("MKG_J13_KEY", &self.pki.paths.key)
                .env("MKG_J13_ROOTS", &self.pki.paths.client_roots)
                .env("MKG_J13_CRLS", &self.pki.paths.crls)
                .env("MKG_J13_ACL", &self.pki.paths.acl)
                .env("MKG_J13_PORT", port.to_string())
                .env("MKG_J13_PORTFILE", &port_file)
                .env("MKG_J13_READY", &ready)
                .stdout(Stdio::null())
                .stderr(File::create(&stderr).unwrap());
            if let Some(crash) = crash {
                command.env("MKG_J13_CRASH", crash);
            }
            let mut child = command.spawn().unwrap();
            match read_fifo(&ready) {
                b'R' => {}
                other => {
                    let _ = child.wait();
                    return Err(other);
                }
            }
            let port: u16 = fs::read_to_string(&port_file).unwrap().parse().unwrap();
            self.addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
            Ok(J13Child { child, stderr })
        }

        fn cleanup(mut self) {
            if self.running.is_some() {
                self.stop();
            }
            base_cleanup(&self.base);
        }
    }

    struct J13Child {
        child: Child,
        stderr: PathBuf,
    }

    impl J13Child {
        fn sigkill(mut self) -> PathBuf {
            self.child.kill().unwrap();
            let status = self.child.wait().unwrap();
            assert_eq!(status.signal(), Some(libc::SIGKILL));
            self.stderr
        }

        /// The child killed itself at an armed point.
        fn died_by_sigkill(mut self) -> PathBuf {
            let status = self.child.wait().unwrap();
            assert_eq!(status.signal(), Some(libc::SIGKILL), "{status:?}");
            self.stderr
        }
    }

    fn j13_point(name: &str) -> CasStorePoint {
        match name {
            "BeforeLock" => CasStorePoint::BeforeLock,
            "BeforeCommit" => CasStorePoint::BeforeCommit,
            "TempWritten" => CasStorePoint::TempWritten,
            "BeforeFileSync" => CasStorePoint::BeforeFileSync,
            "BeforeRename" => CasStorePoint::BeforeRename,
            "BeforeDirSync" => CasStorePoint::BeforeDirSync,
            "Committed" => CasStorePoint::Committed,
            other => panic!("unknown point {other}"),
        }
    }

    #[test]
    fn j13_child_server() {
        let Ok(store) = std::env::var("MKG_J13_STORE") else {
            return;
        };
        let path = |key: &str| PathBuf::from(std::env::var(key).unwrap());
        let ready = path("MKG_J13_READY");
        let signal = |byte: u8| {
            OpenOptions::new()
                .write(true)
                .open(&ready)
                .unwrap()
                .write_all(&[byte])
                .unwrap();
        };
        let store = match CasStore::open_for_test(Path::new(&store)) {
            Ok(store) => store,
            Err(error) => {
                eprintln!("cas start refused: store {error:?}");
                signal(b'E');
                std::process::exit(3);
            }
        };
        if let Ok(crash) = std::env::var("MKG_J13_CRASH") {
            let (point, op) = crash.split_once(':').unwrap();
            let op: &'static str = match op {
                "Advance" => "Advance",
                "BeginSession" => "BeginSession",
                other => panic!("unknown op {other}"),
            };
            store.arm(j13_point(point), op, Action::Kill);
        }
        let files = CasServerFiles {
            certificate: path("MKG_J13_CERT"),
            key: path("MKG_J13_KEY"),
            client_roots: path("MKG_J13_ROOTS"),
            crls: path("MKG_J13_CRLS"),
            acl: path("MKG_J13_ACL"),
        };
        let sink: Arc<dyn Fn(&CasEvent) + Send + Sync> =
            Arc::new(|event: &CasEvent| eprintln!("{event}"));
        let server = match CasNetworkServer::start(store, &files, j13_limits(), sink) {
            Ok(server) => Arc::new(server),
            Err(error) => {
                eprintln!("cas start refused: server {error:?}");
                signal(b'E');
                std::process::exit(4);
            }
        };
        let port: u16 = std::env::var("MKG_J13_PORT").unwrap().parse().unwrap();
        let listener = server
            .bind(std::net::SocketAddr::from(([127, 0, 0, 1], port)))
            .unwrap();
        fs::write(
            path("MKG_J13_PORTFILE"),
            listener.local_addr().unwrap().port().to_string(),
        )
        .unwrap();
        signal(b'R');
        let exit = server.serve(&listener, &mut |connection| {
            thread::spawn(move || connection.run());
        });
        std::process::exit(if exit == CasServeExit::Halted { 70 } else { 0 });
    }

    fn j13_begin(n: u8, identity: AnchorIdentity) -> CasV2Request {
        CasV2Request::BeginSession {
            v: 2,
            request_id: rid(n),
            identity,
        }
    }

    fn j13_read(n: u8, identity: AnchorIdentity) -> CasV2Request {
        CasV2Request::Read {
            v: 2,
            request_id: rid(n),
            identity,
        }
    }

    fn at(revision: u64, digest: &str) -> AnchorState {
        AnchorState {
            identity: j11_identity(),
            revision,
            digest: digest.to_string(),
        }
    }

    fn fence_of(response: Result<CasV2Response, TransportError>) -> u64 {
        match response {
            Ok(CasV2Response::Session { fence, .. }) => fence,
            other => panic!("unexpected {other:?}"),
        }
    }

    fn file_mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().mode() & 0o7777
    }

    /// Rewrite a state document without the encoder's consistency checks, so
    /// a test can store a state whose checksum is valid but whose content is
    /// not.
    fn j13_forge(path: &Path, durable: &CasDurableState, schema: u32) {
        let bytes = serde_json::to_vec(&CasStateDocument {
            schema,
            identity: durable.state.identity.clone(),
            revision: durable.state.revision,
            digest: durable.state.digest.clone(),
            fence: durable.fence,
            ledger: durable.ledger.clone(),
            checksum: cas_state_checksum(durable).unwrap(),
        })
        .unwrap();
        fs::write(path, bytes).unwrap();
        set_mode(path, 0o600);
    }

    fn j13_secret_fragments(pem: &str) -> Vec<String> {
        pem.lines()
            .filter(|line| !line.starts_with("-----") && line.len() >= 16)
            .map(|line| line[..16].to_string())
            .collect()
    }

    #[test]
    fn j13_t01_initialization_creates_durable_state() {
        let _guard = test_guard();
        let mut f = J13::provisioned();
        // Registry and state files exist, private, with genesis content.
        let registry = f.store.join(CAS_REGISTRY_FILE);
        assert_eq!(file_mode(&registry), 0o600);
        assert_eq!(
            decode_cas_registry(&fs::read(&registry).unwrap()).unwrap(),
            vec![j11_identity(), j12_other_identity()]
        );
        for identity in [j11_identity(), j12_other_identity()] {
            assert_eq!(file_mode(&f.state_path(&identity)), 0o600);
            let disk = f.disk(&identity);
            assert_eq!(
                (disk.state.revision, disk.fence, disk.ledger.len()),
                (0, 0, 0)
            );
            assert_eq!(disk.state.digest, ANCHOR_GENESIS_DIGEST);
        }
        // Administrative operations never replace anything.
        assert_eq!(
            CasStore::create_for_test(&f.store),
            Err(CasStoreError::Exists)
        );
        assert_eq!(
            CasStore::provision_for_test(&f.store, &j11_identity()),
            Err(CasStoreError::Exists)
        );
        f.start();
        f.wait_event("ready", |event| {
            *event
                == CasEvent::Ready {
                    identities: 2,
                    leftover_temporaries: 0,
                }
        });
        // While a server holds the store, no administrative operation runs.
        let third = AnchorIdentity::from_hex(format!("{:064x}", 0x3333_u64)).unwrap();
        assert_eq!(
            CasStore::provision_for_test(&f.store, &third),
            Err(CasStoreError::Locked)
        );
        assert_eq!(
            CasStore::provision_new_for_test(&f.store),
            Err(CasStoreError::Locked)
        );
        assert_eq!(f.writer().read().unwrap(), genesis());
        f.stop();
        // An empty directory is not a store, and opening never creates one.
        let empty = f.base.join("empty");
        fs::create_dir(&empty).unwrap();
        set_mode(&empty, 0o700);
        assert_eq!(
            CasStore::open_for_test(&empty).unwrap_err(),
            CasStoreError::Missing
        );
        assert_eq!(fs::read_dir(&empty).unwrap().count(), 0);
        // A generated identity: 64 hex from the CSPRNG, at genesis, and
        // registered, so it cannot be provisioned twice.
        let generated = CasStore::provision_new_for_test(&f.store).unwrap();
        assert_ne!(generated, third);
        assert_eq!(f.disk(&generated).state.revision, 0);
        assert_eq!(
            CasStore::provision_for_test(&f.store, &generated),
            Err(CasStoreError::Exists)
        );
        // The state survives a restart unchanged.
        f.start();
        assert_eq!(f.writer().read().unwrap(), genesis());
        f.cleanup();
    }

    #[test]
    fn j13_t02_read() {
        let _guard = test_guard();
        let f = J13::new();
        assert_eq!(f.writer().read().unwrap(), genesis());
        let monitor = f.anchor_for(&f.pki.monitor, j11_identity());
        assert_eq!(monitor.read().unwrap(), genesis());
        assert_eq!(
            monitor.inquire(&rid(9)).unwrap(),
            InquiryOutcome {
                found: false,
                resulting_revision: None
            }
        );
        assert_eq!(f.authorized(CasOp::Read), 3);
        // Reading changes nothing on disk.
        let disk = f.disk(&j11_identity());
        assert_eq!((disk.fence, disk.state.revision), (0, 0));
        f.cleanup();
    }

    #[test]
    fn j13_t03_begin_session() {
        let _guard = test_guard();
        let mut f = J13::new();
        let c = f.writer();
        assert_eq!(c.begin_session().unwrap(), genesis());
        assert_eq!(c.current_fence(), Some(1));
        assert_eq!(f.disk(&j11_identity()).fence, 1);
        c.begin_session().unwrap();
        assert_eq!(
            (c.current_fence(), f.disk(&j11_identity()).fence),
            (Some(2), 2)
        );
        // The other identity is independent.
        assert_eq!(f.disk(&j12_other_identity()).fence, 0);
        f.restart();
        c.begin_session().unwrap();
        assert_eq!(
            (c.current_fence(), f.disk(&j11_identity()).fence),
            (Some(3), 3)
        );
        f.cleanup();
    }

    #[test]
    fn j13_t04_advance_and_journal_end_to_end() {
        let _guard = test_guard();
        let mut f = J13::new();
        let c = f.writer();
        let s0 = c.begin_session().unwrap();
        let s1 = c.advance(&s0, &dg('a')).unwrap();
        assert_eq!(s1, at(1, &dg('a')));
        let disk = f.disk(&j11_identity());
        assert_eq!(disk.state, s1);
        assert_eq!(disk.ledger.len(), 1);
        assert_eq!(
            Some(disk.ledger[0].request_id.clone()),
            c.last_advance_request_id()
        );
        assert_eq!(c.read().unwrap(), s1);
        let s2 = c.advance(&s1, &dg('b')).unwrap();
        assert_eq!(s2.revision, 2);
        // The journal over the network server, with its own identity.
        let other = f.anchor_for(&f.pki.other, j12_other_identity());
        let store = f.journal_store(&other);
        let mut j = store.initialize(record()).unwrap();
        j.advance(&record().attempt, State::MayHaveBeenSent, None)
            .unwrap();
        drop(j);
        f.restart();
        let j = store.open().unwrap();
        assert_eq!(j.record().state, State::MayHaveBeenSent);
        assert_eq!(f.disk(&j12_other_identity()).state.revision, 2);
        drop(j);
        f.cleanup();
    }

    #[test]
    fn j13_t05_old_fence_is_refused() {
        let _guard = test_guard();
        let f = J13::new();
        // Fence 0 (the provisioned value) is not a session, even at genesis.
        assert_eq!(
            f.send(&f.pki.writer, &adv(0, &genesis(), &dg('a'), rid(9))),
            Ok(CasV2Response::Fenced {
                v: 2,
                request_id: rid(9),
                current_fence: 0
            })
        );
        assert_eq!(f.disk(&j11_identity()).state, genesis());
        let a = f.writer();
        let b = f.writer();
        a.begin_session().unwrap();
        let s0 = b.begin_session().unwrap();
        assert_eq!((a.current_fence(), b.current_fence()), (Some(1), Some(2)));
        assert_eq!(a.advance(&s0, &dg('a')), Err(AnchorError::Fenced));
        for fence in [1, 3] {
            assert_eq!(
                f.send(
                    &f.pki.writer,
                    &adv(fence, &genesis(), &dg('a'), rid(fence as u8))
                ),
                Ok(CasV2Response::Fenced {
                    v: 2,
                    request_id: rid(fence as u8),
                    current_fence: 2
                })
            );
        }
        let disk = f.disk(&j11_identity());
        assert_eq!((disk.state.revision, disk.fence), (0, 2));
        b.advance(&s0, &dg('b')).unwrap();
        assert_eq!(f.disk(&j11_identity()).state, at(1, &dg('b')));
        f.cleanup();
    }

    #[test]
    fn j13_t06_revision_mismatch_is_refused() {
        let _guard = test_guard();
        let f = J13::new();
        let fence = fence_of(f.send(&f.pki.writer, &j13_begin(1, j11_identity())));
        let mut wrong_next = adv(fence, &genesis(), &dg('a'), rid(2));
        if let CasV2Request::Advance { next_revision, .. } = &mut wrong_next {
            *next_revision = 2;
        }
        assert_eq!(
            f.send(&f.pki.writer, &wrong_next),
            Ok(CasV2Response::Rejected {
                v: 2,
                request_id: rid(2),
                reason: CasV2Reject::InvalidRequest
            })
        );
        assert_eq!(
            f.send(
                &f.pki.writer,
                &adv(fence, &at(5, &dg('c')), &dg('a'), rid(3))
            ),
            Ok(CasV2Response::Conflict {
                v: 2,
                request_id: rid(3),
                state: genesis()
            })
        );
        assert_eq!(f.disk(&j11_identity()).state, genesis());
        f.send(&f.pki.writer, &adv(fence, &genesis(), &dg('a'), rid(4)))
            .unwrap();
        // The old revision is now stale.
        assert_eq!(
            f.send(&f.pki.writer, &adv(fence, &genesis(), &dg('b'), rid(5))),
            Ok(CasV2Response::Conflict {
                v: 2,
                request_id: rid(5),
                state: at(1, &dg('a'))
            })
        );
        let c = f.writer();
        c.begin_session().unwrap();
        assert_eq!(c.advance(&genesis(), &dg('d')), Err(AnchorError::Conflict));
        assert_eq!(f.disk(&j11_identity()).state, at(1, &dg('a')));
        f.cleanup();
    }

    #[test]
    fn j13_t07_digest_mismatch_is_refused() {
        let _guard = test_guard();
        let f = J13::new();
        let fence = fence_of(f.send(&f.pki.writer, &j13_begin(1, j11_identity())));
        let wrong_expected = AnchorState {
            identity: j11_identity(),
            revision: 0,
            digest: dg('b'),
        };
        assert_eq!(
            f.send(
                &f.pki.writer,
                &adv(fence, &wrong_expected, &dg('a'), rid(2))
            ),
            Ok(CasV2Response::Conflict {
                v: 2,
                request_id: rid(2),
                state: genesis()
            })
        );
        for (n, next) in [
            (3, "zz".to_string()),
            (4, ANCHOR_GENESIS_DIGEST.to_string()),
            (5, "A".repeat(64)),
            (6, "a".repeat(63)),
        ] {
            assert_eq!(
                f.send(&f.pki.writer, &adv(fence, &genesis(), &next, rid(n))),
                Ok(CasV2Response::Rejected {
                    v: 2,
                    request_id: rid(n),
                    reason: CasV2Reject::InvalidRequest
                })
            );
        }
        let disk = f.disk(&j11_identity());
        assert_eq!((disk.state.clone(), disk.ledger.len()), (genesis(), 0));
        f.cleanup();
    }

    #[test]
    fn j13_t08_second_instance_is_refused() {
        let _guard = test_guard();
        let mut f = J13::new();
        // In process: the store is locked by the running server.
        assert_eq!(
            CasStore::open_for_test(&f.store).unwrap_err(),
            CasStoreError::Locked
        );
        assert_eq!(
            CasStore::create_for_test(&f.store),
            Err(CasStoreError::Locked)
        );
        f.stop();
        // Across processes.
        let first = f.spawn_child(None, 0).unwrap();
        let port = f.addr.port();
        assert_eq!(f.spawn_child(None, 0).err(), Some(b'E'));
        let stderr = fs::read_to_string(f.base.join("child-2.stderr")).unwrap();
        assert!(stderr.contains("store Locked"), "{stderr}");
        assert_eq!(
            CasStore::open_for_test(&f.store).unwrap_err(),
            CasStoreError::Locked
        );
        f.writer().begin_session().unwrap();
        first.sigkill();
        // The kernel released the lock with the dead process.
        let third = f.spawn_child(None, port).unwrap();
        assert_eq!(f.writer().read().unwrap(), genesis());
        assert_eq!(f.disk(&j11_identity()).fence, 1);
        third.sigkill();
        f.cleanup();
    }

    /// SIGKILL at every step of a durable Advance, and after the reply.
    #[test]
    fn j13_t09_sigkill_and_restart() {
        let _guard = test_guard();
        let mut f = J13::provisioned();
        let mut port = 0;
        let mut revision = 0;
        let mut digest = ANCHOR_GENESIS_DIGEST.to_string();
        // (crash point, does the disk hold the new state after the kill?)
        for (n, (point, new_on_disk)) in [
            ("TempWritten", false),
            ("BeforeFileSync", false),
            ("BeforeRename", false),
            ("BeforeDirSync", true),
            ("Committed", true),
        ]
        .into_iter()
        .enumerate()
        {
            let child = f
                .spawn_child(Some(&format!("{point}:Advance")), port)
                .unwrap();
            port = f.addr.port();
            let c = f.writer();
            let expected = c.begin_session().unwrap();
            assert_eq!(expected, at(revision, &digest));
            let fence_before_kill = c.current_fence().unwrap();
            let next = dg((b'a' + n as u8) as char);
            // The reply never comes: the outcome is unknown to the client.
            assert_eq!(c.advance(&expected, &next), Err(AnchorError::Unknown));
            child.died_by_sigkill();
            let disk = f.disk(&j11_identity());
            if new_on_disk {
                revision += 1;
                digest = next.clone();
            }
            assert_eq!(disk.state, at(revision, &digest), "{point}");
            // Restart: the server reports the disk, never a reset.
            let child = f.spawn_child(None, port).unwrap();
            let fresh = f.writer();
            assert_eq!(fresh.begin_session().unwrap(), at(revision, &digest));
            assert_eq!(c.current_fence(), None);
            assert_eq!(fresh.current_fence(), Some(fence_before_kill + 1));
            let stderr = child.sigkill();
            let leftover = fs::read_to_string(stderr).unwrap();
            if !new_on_disk {
                assert!(
                    leftover.contains(&format!("leftover_temporaries={}", f.temporaries())),
                    "{leftover}"
                );
            }
        }
        // SIGKILL after the success reply: the acknowledged state survives.
        let child = f.spawn_child(None, port).unwrap();
        let c = f.writer();
        let expected = c.begin_session().unwrap();
        let acknowledged = c.advance(&expected, &dg('f')).unwrap();
        child.sigkill();
        assert_eq!(f.disk(&j11_identity()).state, acknowledged);
        let child = f.spawn_child(None, port).unwrap();
        assert_eq!(f.writer().read().unwrap(), acknowledged);
        // SIGKILL after a durable BeginSession, before its reply: the fence
        // moved and is never handed out again.
        let fence_before = f.disk(&j11_identity()).fence;
        child.sigkill();
        let child = f.spawn_child(Some("Committed:BeginSession"), port).unwrap();
        assert_eq!(f.writer().begin_session(), Err(AnchorError::Unknown));
        child.died_by_sigkill();
        assert_eq!(f.disk(&j11_identity()).fence, fence_before + 1);
        let child = f.spawn_child(None, port).unwrap();
        let c = f.writer();
        c.begin_session().unwrap();
        assert_eq!(c.current_fence(), Some(fence_before + 2));
        child.sigkill();
        f.cleanup();
    }

    fn j13_failed_write(point: CasStorePoint) -> (J13, Arc<NetworkCasAnchor>) {
        let mut f = J13::new();
        let c = f.writer();
        let s0 = c.begin_session().unwrap();
        f.arm(point, "Advance", Action::Fail);
        assert_eq!(c.advance(&s0, &dg('a')), Err(AnchorError::Unknown));
        f.wait_event("halted", |event| *event == CasEvent::Halted);
        // Halted: nothing more is served by this instance.
        assert!(f.server().store().halted());
        assert!(matches!(
            f.writer().read(),
            Err(AnchorError::Unknown | AnchorError::Unavailable)
        ));
        assert_eq!(f.stop(), CasServeExit::Halted);
        (f, c)
    }

    #[test]
    fn j13_t10_file_fsync_failure_halts_without_reply() {
        let _guard = test_guard();
        let (mut f, _) = j13_failed_write(CasStorePoint::BeforeFileSync);
        let disk = f.disk(&j11_identity());
        assert_eq!((disk.state.clone(), disk.fence), (genesis(), 1));
        assert_eq!(f.temporaries(), 1);
        f.start();
        f.wait_event("ready with the leftover", |event| {
            *event
                == CasEvent::Ready {
                    identities: 2,
                    leftover_temporaries: 1,
                }
        });
        let c = f.writer();
        assert_eq!(c.begin_session().unwrap(), genesis());
        assert_eq!(c.current_fence(), Some(2));
        f.cleanup();
    }

    #[test]
    fn j13_t11_rename_failure_halts_and_keeps_the_old_state() {
        let _guard = test_guard();
        let (mut f, _) = j13_failed_write(CasStorePoint::BeforeRename);
        assert_eq!(f.disk(&j11_identity()).state, genesis());
        assert_eq!(f.temporaries(), 1);
        f.start();
        assert_eq!(f.writer().read().unwrap(), genesis());
        // A failed BeginSession write: the fence stays, nobody holds the
        // unwritten one (the client clears its fence before sending).
        let c = f.writer();
        c.begin_session().unwrap();
        let fence = f.disk(&j11_identity()).fence;
        f.arm(CasStorePoint::BeforeRename, "BeginSession", Action::Fail);
        assert_eq!(c.begin_session(), Err(AnchorError::Unknown));
        assert_eq!(c.current_fence(), None);
        assert_eq!(f.stop(), CasServeExit::Halted);
        assert_eq!(f.disk(&j11_identity()).fence, fence);
        f.cleanup();
    }

    #[test]
    fn j13_t12_directory_fsync_failure_halts_and_restart_shows_the_rename() {
        let _guard = test_guard();
        let (mut f, _) = j13_failed_write(CasStorePoint::BeforeDirSync);
        // The rename happened; its durability was not confirmed. The client
        // saw Unknown; the restarted server fsyncs the file and the directory
        // before it reports anything.
        assert_eq!(f.disk(&j11_identity()).state, at(1, &dg('a')));
        assert_eq!(f.temporaries(), 0);
        f.start();
        let c = f.writer();
        assert_eq!(c.begin_session().unwrap(), at(1, &dg('a')));
        f.cleanup();
    }

    #[test]
    fn j13_t13_corrupt_state_is_refused() {
        let _guard = test_guard();
        let f = J13::provisioned();
        let path = f.state_path(&j11_identity());
        let good = fs::read(&path).unwrap();
        let registry = f.store.join(CAS_REGISTRY_FILE);
        let good_registry = fs::read(&registry).unwrap();
        let durable = f.disk(&j11_identity());
        let restore = || {
            fs::write(&path, &good).unwrap();
            set_mode(&path, 0o600);
            fs::write(&registry, &good_registry).unwrap();
            set_mode(&registry, 0o600);
        };
        let open = || CasStore::open_for_test(&f.store).map(|_| ()).unwrap_err();
        let mut flipped = good.clone();
        let at_digest = String::from_utf8_lossy(&good)
            .find(ANCHOR_GENESIS_DIGEST)
            .unwrap();
        flipped[at_digest] = if flipped[at_digest] == b'1' {
            b'2'
        } else {
            b'1'
        };
        let mut forged_rev = durable.clone();
        forged_rev.state.revision = 2;
        forged_rev.state.digest = dg('a');
        let mut other_identity = durable.clone();
        other_identity.state.identity = j12_other_identity();
        let mut bad_ledger = durable.clone();
        bad_ledger.state = at(1, &dg('a'));
        bad_ledger.ledger.push_back(CasLedgerEntry {
            request_id: rid(1),
            body_hash: dg('c'),
            resulting_revision: 5,
            resulting_digest: dg('a'),
        });
        type Corruption<'a> = (&'a str, Box<dyn Fn() + 'a>);
        let cases: Vec<Corruption<'_>> = vec![
            (
                "flipped byte",
                Box::new(|| fs::write(&path, &flipped).unwrap()),
            ),
            (
                "truncated",
                Box::new(|| fs::write(&path, &good[..good.len() / 2]).unwrap()),
            ),
            ("empty", Box::new(|| fs::write(&path, b"").unwrap())),
            (
                "fence changed, checksum kept",
                Box::new(|| {
                    let mut value: serde_json::Value = serde_json::from_slice(&good).unwrap();
                    value["fence"] = serde_json::json!(5);
                    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
                }),
            ),
            ("schema 3", Box::new(|| j13_forge(&path, &durable, 3))),
            (
                "unknown field",
                Box::new(|| {
                    let mut value: serde_json::Value = serde_json::from_slice(&good).unwrap();
                    value["extra"] = serde_json::json!(1);
                    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
                }),
            ),
            (
                "revision without ledger",
                Box::new(|| j13_forge(&path, &forged_rev, 2)),
            ),
            (
                "identity of another file",
                Box::new(|| j13_forge(&path, &other_identity, 2)),
            ),
            (
                "inconsistent ledger",
                Box::new(|| j13_forge(&path, &bad_ledger, 2)),
            ),
            (
                "too large",
                Box::new(|| fs::write(&path, vec![b' '; 70_000]).unwrap()),
            ),
            (
                "registry checksum",
                Box::new(|| {
                    let mut value: serde_json::Value =
                        serde_json::from_slice(&good_registry).unwrap();
                    value["checksum"] = serde_json::json!(dg('0'));
                    fs::write(&registry, serde_json::to_vec(&value).unwrap()).unwrap();
                }),
            ),
            (
                "registry unsorted",
                Box::new(|| {
                    let ids = vec![j12_other_identity(), j11_identity()];
                    fs::write(
                        &registry,
                        serde_json::to_vec(&CasRegistryDocument {
                            schema: 1,
                            checksum: cas_registry_checksum(&ids).unwrap(),
                            identities: ids,
                        })
                        .unwrap(),
                    )
                    .unwrap();
                }),
            ),
        ];
        for (name, corrupt) in cases {
            corrupt();
            assert_eq!(open(), CasStoreError::Corrupt, "{name}");
            restore();
        }
        let store = CasStore::open_for_test(&f.store).unwrap();
        assert_eq!(store.snapshot(&j11_identity()).unwrap().state, genesis());
        drop(store);
        f.cleanup();
    }

    #[test]
    fn j13_t14_missing_state_is_never_a_genesis() {
        let _guard = test_guard();
        let mut f = J13::new();
        let c = f.writer();
        let s0 = c.begin_session().unwrap();
        c.advance(&s0, &dg('a')).unwrap();
        f.stop();
        let path = f.state_path(&j11_identity());
        let saved = fs::read(&path).unwrap();
        fs::remove_file(&path).unwrap();
        assert_eq!(
            CasStore::open_for_test(&f.store).unwrap_err(),
            CasStoreError::Missing
        );
        assert_eq!(
            f.try_start(j13_limits()),
            Err(J13Start::Store(CasStoreError::Missing))
        );
        // The registry still names the identity: it cannot be re-provisioned
        // at genesis.
        assert_eq!(
            CasStore::provision_for_test(&f.store, &j11_identity()),
            Err(CasStoreError::Exists)
        );
        assert!(!path.exists());
        fs::write(&path, &saved).unwrap();
        set_mode(&path, 0o600);
        // A missing registry is a missing store.
        let registry = f.store.join(CAS_REGISTRY_FILE);
        let saved_registry = fs::read(&registry).unwrap();
        fs::remove_file(&registry).unwrap();
        assert_eq!(
            CasStore::open_for_test(&f.store).unwrap_err(),
            CasStoreError::Missing
        );
        assert_eq!(
            CasStore::create_for_test(&f.store),
            Err(CasStoreError::Exists)
        );
        fs::write(&registry, &saved_registry).unwrap();
        set_mode(&registry, 0o600);
        // A state the registry does not name, and stray names, are refused.
        for stray in [
            cas_state_name(&AnchorIdentity::from_hex(dg('9')).unwrap()),
            "notes.txt".to_string(),
            format!("{}{CAS_TEMP_MARKER}short", cas_state_name(&j11_identity())),
        ] {
            let stray = f.store.join(stray);
            fs::write(&stray, &saved).unwrap();
            set_mode(&stray, 0o600);
            assert_eq!(
                CasStore::open_for_test(&f.store).unwrap_err(),
                CasStoreError::Unexpected
            );
            fs::remove_file(&stray).unwrap();
        }
        f.start();
        assert_eq!(f.writer().read().unwrap(), at(1, &dg('a')));
        f.cleanup();
    }

    #[test]
    fn j13_t15_links_and_unsafe_files_are_refused() {
        let _guard = test_guard();
        let f = J13::provisioned();
        let path = f.state_path(&j11_identity());
        let registry = f.store.join(CAS_REGISTRY_FILE);
        let copy = f.base.join("state-copy");
        fs::copy(&path, &copy).unwrap();
        set_mode(&copy, 0o600);
        let open = || CasStore::open_for_test(&f.store).map(|_| ()).unwrap_err();
        // State replaced by a symlink to a valid copy.
        fs::remove_file(&path).unwrap();
        symlink(&copy, &path).unwrap();
        assert_eq!(open(), CasStoreError::Untrusted);
        fs::remove_file(&path).unwrap();
        // A second hard link (outside the store directory).
        fs::copy(&copy, &path).unwrap();
        set_mode(&path, 0o600);
        let link = f.base.join("state-hardlink");
        fs::hard_link(&path, &link).unwrap();
        assert_eq!(open(), CasStoreError::Untrusted);
        fs::remove_file(&link).unwrap();
        // Permissive mode, then a FIFO and a directory under the state name.
        set_mode(&path, 0o644);
        assert_eq!(open(), CasStoreError::Untrusted);
        set_mode(&path, 0o600);
        fs::remove_file(&path).unwrap();
        make_fifo(&path);
        assert_eq!(open(), CasStoreError::Untrusted);
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        set_mode(&path, 0o700);
        assert_eq!(open(), CasStoreError::Untrusted);
        fs::remove_dir(&path).unwrap();
        fs::copy(&copy, &path).unwrap();
        set_mode(&path, 0o600);
        // Registry as a symlink.
        let registry_copy = f.base.join("registry-copy");
        fs::rename(&registry, &registry_copy).unwrap();
        symlink(&registry_copy, &registry).unwrap();
        assert_eq!(open(), CasStoreError::Untrusted);
        fs::remove_file(&registry).unwrap();
        fs::rename(&registry_copy, &registry).unwrap();
        // The store directory itself: permissive, or reached through a symlink.
        set_mode(&f.store, 0o750);
        assert_eq!(open(), CasStoreError::Untrusted);
        set_mode(&f.store, 0o700);
        let alias = f.base.join("store-alias");
        symlink(&f.store, &alias).unwrap();
        assert_eq!(
            CasStore::open_for_test(&alias).unwrap_err(),
            CasStoreError::Untrusted
        );
        drop(CasStore::open_for_test(&f.store).unwrap());
        f.cleanup();
    }

    #[test]
    fn j13_t16_path_replacement_is_detected() {
        let _guard = test_guard();
        // (a) The state file is replaced by another (valid) file.
        let f = J13::new();
        let c = f.writer();
        c.begin_session().unwrap();
        let path = f.state_path(&j11_identity());
        let replacement = f.store.join("replacement");
        fs::copy(&path, &replacement).unwrap();
        set_mode(&replacement, 0o600);
        fs::rename(&replacement, &path).unwrap();
        assert_eq!(c.begin_session(), Err(AnchorError::Unknown));
        f.wait_event("halted", |event| *event == CasEvent::Halted);
        assert_eq!(f.disk(&j11_identity()).fence, 1);
        f.cleanup();
        // (b) The store directory is moved away and another put in its place.
        let f = J13::new();
        let c = f.writer();
        c.begin_session().unwrap();
        let moved = f.base.join("store-moved");
        fs::rename(&f.store, &moved).unwrap();
        fs::create_dir(&f.store).unwrap();
        set_mode(&f.store, 0o700);
        for entry in fs::read_dir(&moved).unwrap() {
            let entry = entry.unwrap();
            let target = f.store.join(entry.file_name());
            fs::copy(entry.path(), &target).unwrap();
            set_mode(&target, 0o600);
        }
        assert_eq!(c.begin_session(), Err(AnchorError::Unknown));
        f.wait_event("halted", |event| *event == CasEvent::Halted);
        let copied = f.disk(&j11_identity());
        assert_eq!(copied.fence, 1);
        f.cleanup();
        // (c) The store directory becomes group-writable.
        let f = J13::new();
        let c = f.writer();
        c.begin_session().unwrap();
        set_mode(&f.store, 0o770);
        assert_eq!(c.begin_session(), Err(AnchorError::Unknown));
        f.wait_event("halted", |event| *event == CasEvent::Halted);
        set_mode(&f.store, 0o700);
        assert_eq!(f.disk(&j11_identity()).fence, 1);
        f.cleanup();
    }

    #[test]
    fn j13_t17_acl_refusals_never_reach_the_store() {
        let _guard = test_guard();
        let mut f = J13::new();
        let monitor = &f.pki.monitor;
        let refused = |n: u8| {
            Ok(CasV2Response::Rejected {
                v: 2,
                request_id: rid(n),
                reason: CasV2Reject::Forbidden,
            })
        };
        assert_eq!(f.send(monitor, &j13_begin(1, j11_identity())), refused(1));
        assert_eq!(
            f.send(monitor, &adv(0, &genesis(), &dg('a'), rid(2))),
            refused(2)
        );
        assert_eq!(
            f.send(&f.pki.other, &j13_read(3, j11_identity())),
            refused(3)
        );
        assert_eq!(
            f.send(&f.pki.writer, &j13_begin(4, j12_other_identity())),
            refused(4)
        );
        assert_eq!(
            f.send(&f.pki.rogue, &j13_read(5, j11_identity())),
            refused(5)
        );
        assert_eq!(
            f.anchor_for(&f.pki.monitor, j11_identity()).begin_session(),
            Err(AnchorError::Forbidden)
        );
        assert_eq!(
            f.events()
                .iter()
                .filter(|e| matches!(e, CasEvent::Authorized { .. }))
                .count(),
            0
        );
        assert_eq!(f.disk(&j11_identity()).fence, 0);
        assert_eq!(f.disk(&j12_other_identity()).fence, 0);
        f.stop();
        // Unsafe or invalid ACL files keep the server from starting at all.
        let original = f.pki.paths.acl.clone();
        let other_store_identity = dg('7');
        let cases: Vec<(&str, PathBuf)> = vec![
            ("world-writable", f.pki.files.write(&j13_acl_text(), 0o666)),
            ("symlink", {
                let path = f.pki.files.dir.join("acl-link");
                symlink(&original, &path).unwrap();
                path
            }),
            (
                "unregistered identity",
                f.pki.files.write(
                    &format!(
                        "[[grant]]\nprincipal = \"{WRITER}\"\nidentity = \"{other_store_identity}\"\nops = [\"read\"]\n"
                    ),
                    0o644,
                ),
            ),
            (
                "two writers",
                f.pki.files.write(
                    &format!(
                        "{}\n[[grant]]\nprincipal = \"{OTHER_NODE}\"\nidentity = \"{}\"\nops = [\"session\", \"advance\"]\n",
                        j13_acl_text(),
                        j11_identity().as_str()
                    ),
                    0o644,
                ),
            ),
            ("second hard link", {
                let path = f.pki.files.write(&j13_acl_text(), 0o644);
                fs::hard_link(&path, f.pki.files.dir.join("acl-hardlink")).unwrap();
                path
            }),
            ("not utf-8", {
                let path = f.pki.files.dir.join("acl-binary");
                fs::write(&path, [0xff, 0xfe, 0x00]).unwrap();
                set_mode(&path, 0o644);
                path
            }),
        ];
        for (name, acl) in cases {
            f.pki.paths.acl = acl;
            assert_eq!(
                f.try_start(j13_limits()),
                Err(J13Start::Server(CasStartError::Acl)),
                "{name}"
            );
        }
        // The key must be private.
        f.pki.paths.acl = original;
        let key = f.pki.paths.key.clone();
        set_mode(&key, 0o644);
        assert_eq!(
            f.try_start(j13_limits()),
            Err(J13Start::Server(CasStartError::Tls(CasTlsError::File)))
        );
        set_mode(&key, 0o600);
        f.start();
        assert_eq!(f.writer().read().unwrap(), genesis());
        f.cleanup();
    }

    #[test]
    fn j13_t18_tls_authentication_failures_never_reach_the_store() {
        let _guard = test_guard();
        let mut f = J13::new();
        let rogue_ca = Ca::new("synthetic-j13-rogue-ca");
        let handshakes = |f: &J13| {
            f.events()
                .iter()
                .filter(|e| **e == CasEvent::Connection(CasServeOutcome::HandshakeFailed))
                .count()
        };
        // A client certificate from another CA: refused after the client
        // wrote (TLS 1.3), hence Unknown, and never decoded.
        let c = Arc::new(NetworkCasAnchor::new(
            Arc::new(
                TlsTransport::new(
                    f.addr,
                    SERVER_DNS,
                    cas_client_tls_config(
                        f.pki.files.roots(&[&f.pki.ca]),
                        f.pki.files.crls(&[f.pki.ca.crl(&[])]),
                        f.pki.files.identity(&rogue_ca.client(WRITER)),
                    )
                    .unwrap(),
                    Duration::from_secs(2),
                    Duration::from_secs(5),
                )
                .unwrap(),
            ),
            j11_identity(),
        ));
        assert_eq!(c.begin_session(), Err(AnchorError::Unknown));
        f.wait_event("handshake failed", |e| {
            *e == CasEvent::Connection(CasServeOutcome::HandshakeFailed)
        });
        // An expired client certificate.
        let expired = f.pki.ca.client_with_uris(&[WRITER], true);
        assert_eq!(
            f.anchor_for(&expired, j11_identity()).begin_session(),
            Err(AnchorError::Unknown)
        );
        // A server the client does not trust: refused before writing.
        let untrusting = Arc::new(NetworkCasAnchor::new(
            Arc::new(
                TlsTransport::new(
                    f.addr,
                    SERVER_DNS,
                    cas_client_tls_config(
                        f.pki.files.roots(&[&rogue_ca]),
                        f.pki.files.crls(&[rogue_ca.crl(&[])]),
                        f.pki.files.identity(&f.pki.writer),
                    )
                    .unwrap(),
                    Duration::from_secs(2),
                    Duration::from_secs(5),
                )
                .unwrap(),
            ),
            j11_identity(),
        ));
        assert_eq!(untrusting.begin_session(), Err(AnchorError::AuthFailure));
        // A revoked client certificate, after the CRL is updated and the
        // server restarted.
        f.stop();
        f.pki.paths.crls = f
            .pki
            .files
            .write(&f.pki.ca.crl(&[f.pki.writer.serial]), 0o644);
        f.start();
        assert_eq!(f.writer().begin_session(), Err(AnchorError::Unknown));
        f.wait_event("revoked refused", |e| {
            *e == CasEvent::Connection(CasServeOutcome::HandshakeFailed)
        });
        assert!(handshakes(&f) >= 3);
        assert_eq!(
            f.events()
                .iter()
                .filter(|e| matches!(e, CasEvent::Authorized { .. }))
                .count(),
            0
        );
        assert_eq!(f.disk(&j11_identity()).fence, 0);
        // The monitor is not revoked and still reads.
        assert_eq!(
            f.anchor_for(&f.pki.monitor, j11_identity()).read().unwrap(),
            genesis()
        );
        f.cleanup();
    }

    fn j13_raw_session(f: &J13, leaf: &Leaf) -> (rustls::ClientConnection, std::net::TcpStream) {
        let mut tcp = std::net::TcpStream::connect(f.addr).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut conn = rustls::ClientConnection::new(
            f.pki.client_config(leaf),
            rustls::pki_types::ServerName::try_from(SERVER_DNS).unwrap(),
        )
        .unwrap();
        while conn.is_handshaking() {
            conn.complete_io(&mut tcp).unwrap();
        }
        (conn, tcp)
    }

    /// Read until the server closes; returns how long that took.
    fn j13_until_closed(tcp: &mut std::net::TcpStream) -> Duration {
        let start = std::time::Instant::now();
        tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut buf = [0u8; 256];
        loop {
            match tcp.read(&mut buf) {
                Ok(0) | Err(_) => return start.elapsed(),
                Ok(_) => {}
            }
        }
    }

    #[test]
    fn j13_t19_handshake_deadline_bounds_slow_peers() {
        let _guard = test_guard();
        let mut f = J13::provisioned();
        f.try_start(CasServerLimits {
            max_connections: 1,
            handshake_deadline: Duration::from_millis(3000),
            io_timeout: Duration::from_millis(1000),
        })
        .unwrap();
        // (a) A silent connection is closed by the single-read timeout,
        // which is shorter than the deadline here.
        let mut silent = std::net::TcpStream::connect(f.addr).unwrap();
        assert!(j13_until_closed(&mut silent) < Duration::from_secs(4));
        f.wait_event("silent peer closed", |e| {
            *e == CasEvent::Connection(CasServeOutcome::HandshakeFailed)
        });
        // (b) A peer that keeps every single read under the io timeout is
        // still cut at the deadline: a TLS record header announcing 512
        // bytes, then one byte every 300 ms from a thread of its own, from
        // the start, so the server never waits a full io timeout.
        let mut slow = std::net::TcpStream::connect(f.addr).unwrap();
        let start = std::time::Instant::now();
        slow.write_all(&[0x16, 0x03, 0x01, 0x02, 0x00]).unwrap();
        let mut dribbler = slow.try_clone().unwrap();
        let dribble = thread::spawn(move || {
            while start.elapsed() < Duration::from_secs(10) {
                thread::sleep(Duration::from_millis(300));
                if dribbler.write_all(&[0]).is_err() {
                    return Some(start.elapsed());
                }
            }
            None
        });
        // (c) While it holds the only slot, another connection is refused
        // before any handshake: the client wrote no request (NotSent).
        f.wait_event("slot taken", |_| f.server().active_connections() == 1);
        assert_eq!(f.writer().read(), Err(AnchorError::Unavailable));
        f.wait_event("refused", |e| *e == CasEvent::ConnectionRefused);
        let cut = dribble.join().unwrap().expect("slow peer was not cut");
        assert!(cut < Duration::from_secs(6), "{cut:?}");
        drop(slow);
        f.wait_event("deadline", |e| {
            *e == CasEvent::Connection(CasServeOutcome::Deadline)
        });
        assert_eq!(
            f.events()
                .iter()
                .filter(|e| **e == CasEvent::Connection(CasServeOutcome::Deadline))
                .count(),
            1
        );
        // (d) The slot is free again.
        f.wait_event("idle", |_| f.server().active_connections() == 0);
        assert_eq!(f.writer().read().unwrap(), genesis());
        assert_eq!(f.authorized(CasOp::Read), 1);
        f.cleanup();
    }

    #[test]
    fn j13_t20_oversized_request_is_refused_unread() {
        let _guard = test_guard();
        let f = J13::new();
        // The client side refuses to send more than the limit at all.
        let transport = f.transport_for(&f.pki.writer, Duration::from_secs(5));
        assert_eq!(
            transport.exchange(&vec![b' '; MAX_CAS_MESSAGE_BYTES + 1]),
            Err(TransportError::NotSent)
        );
        // A raw peer announces one byte too many: the server stops at the
        // header and answers nothing.
        let (mut conn, mut tcp) = j13_raw_session(&f, &f.pki.writer);
        {
            let mut stream = rustls::Stream::new(&mut conn, &mut tcp);
            stream
                .write_all(&((MAX_CAS_MESSAGE_BYTES as u32 + 1).to_be_bytes()))
                .unwrap();
            stream.flush().unwrap();
            assert!(read_frame(&mut stream).is_err());
        }
        f.wait_event("oversized", |e| {
            *e == CasEvent::Connection(CasServeOutcome::Oversized)
        });
        // At the limit exactly, garbage is read and refused.
        assert_eq!(
            f.send_bytes(&f.pki.writer, &vec![b'x'; MAX_CAS_MESSAGE_BYTES]),
            Ok(CasV2Response::Rejected {
                v: 2,
                request_id: String::new(),
                reason: CasV2Reject::InvalidRequest
            })
        );
        assert_eq!(f.authorized(CasOp::Read), 0);
        assert_eq!(f.disk(&j11_identity()).fence, 0);
        f.cleanup();
    }

    #[test]
    fn j13_t21_concurrent_updates_are_serialized() {
        let _guard = test_guard();
        let f = J13::new();
        let fence = fence_of(f.send(&f.pki.writer, &j13_begin(1, j11_identity())));
        // (a) Two Advances from the same expected state: the first holds the
        // identity lock inside its critical section while the second is
        // shown to wait for it.
        let (arrived_tx, arrived) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let (contended_tx, contended) = mpsc::channel();
        f.arm(
            CasStorePoint::BeforeCommit,
            "Advance",
            Action::Pause {
                arrived: arrived_tx,
                release: release_rx,
            },
        );
        f.arm(
            CasStorePoint::Contended,
            "Advance",
            Action::Notify(contended_tx),
        );
        let first_transport = f.transport_for(&f.pki.writer, Duration::from_secs(10));
        let second_transport = f.transport_for(&f.pki.writer, Duration::from_secs(10));
        let first_request = serde_json::to_vec(&adv(fence, &genesis(), &dg('a'), rid(2))).unwrap();
        let second_request = serde_json::to_vec(&adv(fence, &genesis(), &dg('b'), rid(3))).unwrap();
        let first = thread::spawn(move || first_transport.exchange(&first_request));
        arrived.recv_timeout(Duration::from_secs(10)).unwrap();
        let second = thread::spawn(move || second_transport.exchange(&second_request));
        contended.recv_timeout(Duration::from_secs(10)).unwrap();
        release.send(()).unwrap();
        let parse = |reply: Result<Vec<u8>, TransportError>| -> CasV2Response {
            serde_json::from_slice(&reply.unwrap()).unwrap()
        };
        assert!(matches!(
            parse(first.join().unwrap()),
            CasV2Response::Committed {
                replayed: false,
                ..
            }
        ));
        assert_eq!(
            parse(second.join().unwrap()),
            CasV2Response::Conflict {
                v: 2,
                request_id: rid(3),
                state: at(1, &dg('a'))
            }
        );
        let disk = f.disk(&j11_identity());
        assert_eq!(
            (disk.state.clone(), disk.ledger.len()),
            (at(1, &dg('a')), 1)
        );
        // (b) A BeginSession that arrives while an Advance is committing waits
        // for it, sees its result, and fences the advancing client.
        let a = f.writer();
        let s1 = a.begin_session().unwrap();
        let (arrived_tx, arrived) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let (contended_tx, contended) = mpsc::channel();
        f.arm(
            CasStorePoint::BeforeCommit,
            "Advance",
            Action::Pause {
                arrived: arrived_tx,
                release: release_rx,
            },
        );
        f.arm(
            CasStorePoint::Contended,
            "BeginSession",
            Action::Notify(contended_tx),
        );
        let a2 = Arc::clone(&a);
        let advancing = thread::spawn(move || a2.advance(&s1, &dg('c')));
        arrived.recv_timeout(Duration::from_secs(10)).unwrap();
        let b = f.writer();
        let b2 = Arc::clone(&b);
        let beginning = thread::spawn(move || b2.begin_session());
        contended.recv_timeout(Duration::from_secs(10)).unwrap();
        release.send(()).unwrap();
        let s2 = advancing.join().unwrap().unwrap();
        assert_eq!(beginning.join().unwrap().unwrap(), s2);
        assert_eq!(a.advance(&s2, &dg('d')), Err(AnchorError::Fenced));
        // (c) Another node's principal cannot write this identity at all.
        assert_eq!(
            f.send(&f.pki.other, &adv(fence, &s2, &dg('e'), rid(4))),
            Ok(CasV2Response::Rejected {
                v: 2,
                request_id: rid(4),
                reason: CasV2Reject::Forbidden
            })
        );
        assert_eq!(f.disk(&j11_identity()).state, s2);
        f.cleanup();
    }

    #[test]
    fn j13_t22_unknown_then_late_advance_is_fenced() {
        let _guard = test_guard();
        let f = J13::new();
        // A client whose reply wait is short; its Advance is held in front of
        // the identity lock until after a new session started.
        let a = Arc::new(NetworkCasAnchor::new(
            f.transport_for(&f.pki.writer, Duration::from_millis(500)),
            j11_identity(),
        ));
        let s0 = a.begin_session().unwrap();
        let (arrived_tx, arrived) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        f.arm(
            CasStorePoint::BeforeLock,
            "Advance",
            Action::Pause {
                arrived: arrived_tx,
                release: release_rx,
            },
        );
        assert_eq!(a.advance(&s0, &dg('a')), Err(AnchorError::Unknown));
        arrived.recv_timeout(Duration::from_secs(10)).unwrap();
        let held_id = a.last_advance_request_id().unwrap();
        // Recovery is a new session, never a resend.
        let b = f.writer();
        assert_eq!(b.begin_session().unwrap(), genesis());
        let forwarded = |f: &J13| {
            f.events()
                .iter()
                .filter(|e| matches!(e, CasEvent::Connection(CasServeOutcome::Forwarded { .. })))
                .count()
        };
        // a's BeginSession and b's BeginSession are recorded; the held
        // Advance is not, until it is released.
        f.wait_event("two sessions recorded", |_| forwarded(&f) == 2);
        release.send(()).unwrap();
        f.wait_event("late advance handled", |_| forwarded(&f) == 3);
        let disk = f.disk(&j11_identity());
        assert_eq!((disk.state.clone(), disk.fence), (genesis(), 2));
        assert_eq!(f.authorized(CasOp::Advance), 1);
        assert_eq!(
            b.inquire(&held_id).unwrap(),
            InquiryOutcome {
                found: false,
                resulting_revision: None
            }
        );
        // Committed, but the reply is lost: Unknown to the client; the new
        // session sees the commit and the ledger confirms it.
        let s1 = genesis();
        let (arrived_tx, arrived) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        f.arm(
            CasStorePoint::Committed,
            "Advance",
            Action::Pause {
                arrived: arrived_tx,
                release: release_rx,
            },
        );
        let b_short = Arc::new(NetworkCasAnchor::new(
            f.transport_for(&f.pki.writer, Duration::from_millis(500)),
            j11_identity(),
        ));
        b_short.begin_session().unwrap();
        assert_eq!(b_short.advance(&s1, &dg('b')), Err(AnchorError::Unknown));
        arrived.recv_timeout(Duration::from_secs(10)).unwrap();
        let committed_id = b_short.last_advance_request_id().unwrap();
        release.send(()).unwrap();
        let c = f.writer();
        assert_eq!(c.begin_session().unwrap(), at(1, &dg('b')));
        assert_eq!(
            c.inquire(&committed_id).unwrap(),
            InquiryOutcome {
                found: true,
                resulting_revision: Some(1)
            }
        );
        assert_eq!(f.authorized(CasOp::Advance), 2);
        f.cleanup();
    }

    #[test]
    fn j13_t23_duplicate_request_id() {
        let _guard = test_guard();
        let mut f = J13::new();
        let fence = fence_of(f.send(&f.pki.writer, &j13_begin(1, j11_identity())));
        let original = adv(fence, &genesis(), &dg('a'), rid(2));
        assert_eq!(
            f.send(&f.pki.writer, &original),
            Ok(CasV2Response::Committed {
                v: 2,
                request_id: rid(2),
                state: at(1, &dg('a')),
                replayed: false
            })
        );
        let replay = Ok(CasV2Response::Committed {
            v: 2,
            request_id: rid(2),
            state: at(1, &dg('a')),
            replayed: true,
        });
        assert_eq!(f.send(&f.pki.writer, &original), replay);
        assert_eq!(
            f.send(&f.pki.writer, &adv(fence, &genesis(), &dg('b'), rid(2))),
            Ok(CasV2Response::Rejected {
                v: 2,
                request_id: rid(2),
                reason: CasV2Reject::RequestIdReuse
            })
        );
        let disk = f.disk(&j11_identity());
        assert_eq!(
            (disk.state.clone(), disk.ledger.len()),
            (at(1, &dg('a')), 1)
        );
        // The ledger is durable: a restarted server still recognizes it.
        f.restart();
        assert_eq!(f.send(&f.pki.writer, &original), replay);
        // Pushed out of the ledger, the old request is refused by the CAS
        // conditions themselves, never committed twice.
        let mut state = at(1, &dg('a'));
        for n in 0..CAS_LEDGER_CAPACITY as u64 {
            let next = format!("{:064x}", 0xa000 + n);
            match f.send(
                &f.pki.writer,
                &adv(fence, &state, &next, format!("{:032x}", 0xb000 + n)),
            ) {
                Ok(CasV2Response::Committed { state: s, .. }) => state = s,
                other => panic!("unexpected {other:?}"),
            }
        }
        assert!(
            !f.disk(&j11_identity())
                .ledger
                .iter()
                .any(|e| e.request_id == rid(2))
        );
        assert_eq!(
            f.send(&f.pki.writer, &original),
            Ok(CasV2Response::Conflict {
                v: 2,
                request_id: rid(2),
                state: state.clone()
            })
        );
        assert_eq!(f.disk(&j11_identity()).state, state);
        f.cleanup();
    }

    #[test]
    fn j13_t24_fence_survives_restarts() {
        let _guard = test_guard();
        let mut f = J13::new();
        let a = f.writer();
        let s0 = a.begin_session().unwrap();
        // Graceful restart.
        f.restart();
        assert_eq!(f.disk(&j11_identity()).fence, 1);
        let b = f.writer();
        b.begin_session().unwrap();
        assert_eq!(b.current_fence(), Some(2));
        assert_eq!(a.advance(&s0, &dg('a')), Err(AnchorError::Fenced));
        f.stop();
        // SIGKILL restart of a server process.
        let child = f.spawn_child(None, 0).unwrap();
        let port = f.addr.port();
        let c = f.writer();
        let s0 = c.begin_session().unwrap();
        assert_eq!(c.current_fence(), Some(3));
        child.sigkill();
        let child = f.spawn_child(None, port).unwrap();
        let d = f.writer();
        d.begin_session().unwrap();
        assert_eq!(d.current_fence(), Some(4));
        assert_eq!(c.advance(&s0, &dg('b')), Err(AnchorError::Fenced));
        assert_eq!(d.advance(&s0, &dg('c')).unwrap(), at(1, &dg('c')));
        child.sigkill();
        assert_eq!(f.disk(&j11_identity()).fence, 4);
        f.cleanup();
    }

    #[test]
    fn j13_t25_parser_differentials_cannot_split_authorization_from_execution() {
        let _guard = test_guard();
        let f = J13::new();
        let id = j11_identity().as_str().to_string();
        let other = j12_other_identity().as_str().to_string();
        let send_text = |leaf: &Leaf, text: String| f.send_bytes(leaf, text.as_bytes());
        let fences = || {
            (
                f.disk(&j11_identity()).fence,
                f.disk(&j12_other_identity()).fence,
            )
        };
        // Duplicate "identity": the decoder keeps one; the ACL and the store
        // see that same one. Writer may act on `id` only.
        assert_eq!(
            send_text(
                &f.pki.writer,
                format!(
                    r#"{{"v":2,"op":"BeginSession","request_id":"{}","identity":"{id}","identity":"{other}"}}"#,
                    rid(1)
                )
            ),
            Ok(CasV2Response::Rejected {
                v: 2,
                request_id: rid(1),
                reason: CasV2Reject::Forbidden
            })
        );
        assert_eq!(fences(), (0, 0));
        assert!(matches!(
            send_text(
                &f.pki.writer,
                format!(
                    r#"{{"v":2,"op":"BeginSession","request_id":"{}","identity":"{other}","identity":"{id}"}}"#,
                    rid(2)
                )
            ),
            Ok(CasV2Response::Session { fence: 1, .. })
        ));
        assert_eq!(fences(), (1, 0));
        // Duplicate "op": a read-only principal never gets a session.
        let monitor = &f.pki.monitor;
        assert_eq!(
            send_text(
                monitor,
                format!(
                    r#"{{"v":2,"op":"Read","op":"BeginSession","request_id":"{}","identity":"{id}"}}"#,
                    rid(3)
                )
            ),
            Ok(CasV2Response::Rejected {
                v: 2,
                request_id: rid(3),
                reason: CasV2Reject::Forbidden
            })
        );
        assert!(matches!(
            send_text(
                monitor,
                format!(
                    r#"{{"v":2,"op":"BeginSession","op":"Read","request_id":"{}","identity":"{id}"}}"#,
                    rid(4)
                )
            ),
            Ok(CasV2Response::State { .. })
        ));
        assert_eq!(fences(), (1, 0));
        // `expected.identity` other than the request identity.
        let mut crossed = adv(1, &genesis(), &dg('a'), rid(5));
        if let CasV2Request::Advance { expected, .. } = &mut crossed {
            expected.identity = j12_other_identity();
        }
        assert_eq!(
            f.send(&f.pki.writer, &crossed),
            Ok(CasV2Response::Rejected {
                v: 2,
                request_id: rid(5),
                reason: CasV2Reject::InvalidRequest
            })
        );
        // Escapes decode to the same identity, authorized and executed alike.
        let escaped: String = id.chars().map(|c| format!("\\u{:04x}", c as u32)).collect();
        assert!(matches!(
            send_text(&f.pki.writer, format!(r#"{{"v":2,"op":"Read","request_id":"{}","identity":"{escaped}"}}"#, rid(6))),
            Ok(CasV2Response::State { state, .. }) if state.identity == j11_identity()
        ));
        // Encodings that another parser might read differently are refused.
        let advance = |extra: &str, fence: &str| {
            format!(
                r#"{{"v":2,"op":"Advance","request_id":"{}","identity":"{id}","fence":{fence},"expected":{{"identity":"{id}","revision":0,"digest":"{}"{extra}}},"next_revision":1,"next_digest":"{}"}}"#,
                J13_LETTERED_ID,
                ANCHOR_GENESIS_DIGEST,
                dg('a')
            )
        };
        let invalid = [
            advance("", "1e0"),
            advance("", "1.0"),
            advance("", "-1"),
            advance("", "18446744073709551616"),
            advance("", "\"1\""),
            advance(r#","extra":1"#, "1"),
            format!("{} trailing", advance("", "1")),
            format!("\u{feff}{}", advance("", "1")),
            advance("", "1").replace("\"identity\":\"", "\"Identity\":\""),
            advance("", "1").replace(J13_LETTERED_ID, &J13_LETTERED_ID.to_uppercase()),
        ];
        for text in invalid {
            let reply = send_text(&f.pki.writer, text.clone()).unwrap();
            assert!(
                matches!(
                    reply,
                    CasV2Response::Rejected {
                        reason: CasV2Reject::InvalidRequest,
                        ..
                    }
                ),
                "{text}: {reply:?}"
            );
        }
        for version in ["2.0", "\"2\"", "3", "null"] {
            let reply = send_text(
                &f.pki.writer,
                format!(
                    r#"{{"v":{version},"op":"Read","request_id":"{}","identity":"{id}"}}"#,
                    rid(8)
                ),
            )
            .unwrap();
            assert!(
                matches!(
                    reply,
                    CasV2Response::Rejected {
                        reason: CasV2Reject::Version,
                        ..
                    }
                ),
                "{version}: {reply:?}"
            );
        }
        let disk = f.disk(&j11_identity());
        assert_eq!((disk.state.clone(), disk.fence), (genesis(), 1));
        // Every authorization event names what the store then executed: the
        // two accepted requests above were for `id`.
        for event in f.events() {
            if let CasEvent::Authorized { identity, .. } = event {
                assert_eq!(identity, id);
            }
        }
        // Source shape: the request bytes are decoded in exactly one place,
        // and the store is handed the decoded value.
        let source = include_str!("gce_operation_journal.rs");
        let production = &source[..source.find("\nmod tests {").unwrap()];
        assert_eq!(
            production.matches("cas_v2_decode_request(request)").count(),
            1
        );
        assert_eq!(
            production.matches("server.store.handle(&decoded)").count(),
            1
        );
        let block = &production
            [production.find("// J13-BEGIN").unwrap()..production.find("// J13-END").unwrap()];
        for forbidden in [
            "from_slice(&request",
            "from_slice(request",
            "cas_v2_decode_request",
        ] {
            assert!(!block.contains(forbidden), "{forbidden}");
        }
        f.cleanup();
    }

    #[test]
    fn j13_t26_send_is_never_authorized_and_nothing_is_wired() {
        let _guard = test_guard();
        let mut f = J13::new();
        let other = f.anchor_for(&f.pki.other, j12_other_identity());
        let store = f.journal_store(&other);
        let attempt = record().attempt;
        let mut j = store.initialize(record()).unwrap();
        assert!(!j.send_authorized());
        for (next, operation) in [
            (State::MayHaveBeenSent, None),
            (
                State::OperationKnown,
                Some(("operation-synthetic".to_string(), "op-1".to_string())),
            ),
            (State::DoneObserved, None),
        ] {
            j.advance(&attempt, next, operation).unwrap();
            assert!(!j.send_authorized() && !j.record().send_authorized());
        }
        drop(j);
        f.restart();
        let j = store.open().unwrap();
        assert!(!j.send_authorized());
        drop(j);
        // Nothing of J13 is reachable from the binary, starts a thread, reads
        // the environment or carries a fault switch outside the test build.
        let source = include_str!("gce_operation_journal.rs");
        let block =
            &source[source.find("// J13-BEGIN").unwrap()..source.find("// J13-END").unwrap()];
        for forbidden in [
            "std::env",
            "MKG_",
            "thread::spawn",
            "process::exit",
            "abort()",
            "AtomicBool",
        ] {
            assert!(
                !block.contains(forbidden),
                "J13 production block contains {forbidden}"
            );
        }
        let main = include_str!("main.rs");
        assert!(!main.contains("gce_operation_journal") && !main.contains("CasNetworkServer"));
        f.cleanup();
    }

    #[test]
    fn j13_t27_secrets_stay_out_of_events_logs_and_debug() {
        let _guard = test_guard();
        let mut f = J13::new();
        // Exercise success, refusals, a TLS failure and a halt.
        let c = f.writer();
        let s0 = c.begin_session().unwrap();
        c.advance(&s0, &dg('a')).unwrap();
        let _ = f.send(&f.pki.monitor, &j13_begin(1, j11_identity()));
        let rogue_ca = Ca::new("synthetic-j13-rogue-ca");
        let _ = f
            .anchor_for(&rogue_ca.client(WRITER), j11_identity())
            .read();
        let mut text = String::new();
        text.push_str(&format!("{:?}\n", f.server()));
        f.arm(CasStorePoint::BeforeRename, "*", Action::Fail);
        let _ = c.begin_session();
        f.wait_event("halted", |e| *e == CasEvent::Halted);
        f.stop();
        // A child process logging to stderr, including a refused start.
        let child = f.spawn_child(None, 0).unwrap();
        let _ = f.writer().read();
        let _ = f.send(&f.pki.monitor, &j13_begin(2, j11_identity()));
        let stderr = child.sigkill();
        text.push_str(&fs::read_to_string(stderr).unwrap());
        for event in f.events() {
            text.push_str(&format!("{event}\n{event:?}\n"));
        }
        text.push_str(&format!(
            "{:?} {:?} {:?}\n",
            CasStore::open_for_test(&f.store).map(|_| ()),
            f.pki.paths,
            f.pki.files.identity(&f.pki.server_leaf)
        ));
        assert!(text.contains("cas authorized principal="));
        for pem in [
            &f.pki.server_leaf.key_pem,
            &f.pki.writer.key_pem,
            &f.pki.monitor.key_pem,
        ] {
            for fragment in j13_secret_fragments(pem) {
                assert!(!text.contains(&fragment), "key material in logs");
            }
        }
        for marker in ["PRIVATE KEY", "BEGIN ", "-----"] {
            assert!(!text.contains(marker), "{marker} in logs");
        }
        f.cleanup();
    }

    #[test]
    fn j13_t28_graceful_shutdown_finishes_admitted_requests() {
        let _guard = test_guard();
        let mut f = J13::new();
        let c = f.writer();
        let s0 = c.begin_session().unwrap();
        let (arrived_tx, arrived) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        f.arm(
            CasStorePoint::BeforeCommit,
            "Advance",
            Action::Pause {
                arrived: arrived_tx,
                release: release_rx,
            },
        );
        let c2 = Arc::clone(&c);
        let in_flight = thread::spawn(move || c2.advance(&s0, &dg('a')));
        arrived.recv_timeout(Duration::from_secs(10)).unwrap();
        // Shut down while the request is inside its critical section.
        let running = f.running.take().unwrap();
        running.server.shutdown();
        assert_eq!(running.serve.join().unwrap(), CasServeExit::Shutdown);
        // The BeginSession connection may still be finishing; the held
        // Advance stays admitted until it is released.
        f.wait_event("only the held request left", |_| {
            running.server.active_connections() == 1
        });
        // No new connection is accepted.
        assert_eq!(f.writer().read(), Err(AnchorError::Unavailable));
        assert!(!running.server.wait_idle(Duration::from_millis(50)));
        // The admitted request completes, durably and with its reply.
        release.send(()).unwrap();
        assert_eq!(in_flight.join().unwrap().unwrap(), at(1, &dg('a')));
        assert!(running.server.wait_idle(Duration::from_secs(10)));
        let workers: Vec<_> = running.workers.lock().unwrap().drain(..).collect();
        for worker in workers {
            worker.join().unwrap();
        }
        // Still locked until the server is dropped; then released.
        assert_eq!(
            CasStore::open_for_test(&f.store).unwrap_err(),
            CasStoreError::Locked
        );
        let server = Arc::try_unwrap(running.server).expect("sole owner");
        drop(server.into_store());
        let store = CasStore::open_for_test(&f.store).unwrap();
        assert_eq!(
            store.snapshot(&j11_identity()).unwrap().state,
            at(1, &dg('a'))
        );
        drop(store);
        f.events.lock().unwrap().clear();
        f.start();
        assert_eq!(c.read().unwrap(), at(1, &dg('a')));
        assert_eq!(c.advance(&at(1, &dg('a')), &dg('b')).unwrap().revision, 2);
        f.cleanup();
    }

    // Phase 1-J14: recovery assessment (R-A) and dry-run plans (R-B) over the
    // J13 server. The journal is the real journal, the CAS is the real store
    // behind real TLS; client crashes are SIGKILLs of a child process at the
    // existing journal crash points; interleavings use the J13 hooks.

    const J14_CHILD: &str = "gce_operation_journal::tests::j14_child_client";

    /// A journal at revision 2 (initialize + one advance) over a fresh server.
    struct J14 {
        f: J13,
        writer_cert: PathBuf,
        writer_key: PathBuf,
        server_roots: PathBuf,
        server_crls: PathBuf,
    }

    impl J14 {
        fn new() -> Self {
            let f = J13::new();
            let c = f.writer();
            let store = f.journal_store(&c);
            let mut j = store.initialize(record()).unwrap();
            j.advance(&record().attempt, State::MayHaveBeenSent, None)
                .unwrap();
            drop(j);
            Self {
                writer_cert: f.pki.files.write(&f.pki.writer.cert_pem, 0o644),
                writer_key: f.pki.files.write(&f.pki.writer.key_pem, 0o600),
                server_roots: f.pki.files.write(&f.pki.ca.cert_pem, 0o644),
                server_crls: f.pki.files.write(&f.pki.ca.crl(&[]), 0o644),
                f,
            }
        }

        fn store(&self, client: &Arc<NetworkCasAnchor>) -> JournalStore {
            self.f.journal_store(client)
        }

        fn assess_with(
            &self,
            client: &Arc<NetworkCasAnchor>,
            context: &RecoveryContext<'_>,
        ) -> RecoveryReport {
            self.store(client).assess_recovery(context).unwrap()
        }

        fn assess(&self) -> RecoveryReport {
            self.assess_with(&self.f.writer(), &RecoveryContext::default())
        }

        fn journal_dir(&self) -> PathBuf {
            self.f.anchor.join(JOURNAL_DIR)
        }

        /// Names and contents of every journal file, hashed.
        fn journal_fingerprint(&self) -> String {
            let mut entries: Vec<_> = fs::read_dir(self.journal_dir())
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect();
            entries.sort();
            let mut hasher = Sha256::new();
            for path in entries {
                hasher.update(path.file_name().unwrap().as_bytes());
                hasher.update(fs::read(&path).unwrap());
            }
            format!("{:x}", hasher.finalize())
        }

        fn cas(&self) -> CasDurableState {
            self.f.disk(&j11_identity())
        }

        fn short_client(&self) -> Arc<NetworkCasAnchor> {
            Arc::new(NetworkCasAnchor::new(
                self.f
                    .transport_for(&self.f.pki.writer, Duration::from_millis(500)),
                j11_identity(),
            ))
        }

        /// A child process acting as a journal client with the writer's
        /// certificate. Returns its exit status and stdout.
        fn child(
            &self,
            action: &str,
            crash: Option<&str>,
            out: Option<&Path>,
        ) -> (std::process::ExitStatus, String) {
            let stdout = self
                .f
                .base
                .join(format!("j14-child-{}.out", cas_request_id().unwrap()));
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args(["--exact", J14_CHILD, "--nocapture"])
                .env("MKG_J14_ANCHOR", &self.f.anchor)
                .env("MKG_J14_ADDR", self.f.addr.to_string())
                .env("MKG_J14_CERT", &self.writer_cert)
                .env("MKG_J14_KEY", &self.writer_key)
                .env("MKG_J14_ROOTS", &self.server_roots)
                .env("MKG_J14_CRLS", &self.server_crls)
                .env("MKG_J14_ACTION", action)
                .stdout(File::create(&stdout).unwrap())
                .stderr(Stdio::null());
            if let Some(crash) = crash {
                command.env("MKG_J5_CRASH_POINT", crash);
            }
            if let Some(out) = out {
                command.env("MKG_J14_OUT", out);
            }
            let status = command.status().unwrap();
            (status, fs::read_to_string(stdout).unwrap())
        }

        fn cleanup(self) {
            self.f.cleanup();
        }
    }

    #[test]
    fn j14_child_client() {
        let Ok(anchor) = std::env::var("MKG_J14_ANCHOR") else {
            return;
        };
        let path = |key: &str| PathBuf::from(std::env::var(key).unwrap());
        let config = cas_client_tls_config(
            cas_load_roots(&path("MKG_J14_ROOTS")).unwrap(),
            cas_load_crls(&path("MKG_J14_CRLS")).unwrap(),
            CasTlsIdentity::load(&path("MKG_J14_CERT"), &path("MKG_J14_KEY")).unwrap(),
        )
        .unwrap();
        let transport = Arc::new(
            TlsTransport::new(
                std::env::var("MKG_J14_ADDR").unwrap().parse().unwrap(),
                SERVER_DNS,
                config,
                Duration::from_secs(2),
                Duration::from_secs(5),
            )
            .unwrap(),
        );
        let client = Arc::new(NetworkCasAnchor::new(transport, j11_identity()));
        let store = JournalStore::for_test_with_anchor(Path::new(&anchor), client.clone()).unwrap();
        match std::env::var("MKG_J14_ACTION").unwrap().as_str() {
            "advance" => {
                let mut j = store.open().unwrap();
                j.advance(
                    &record().attempt,
                    State::OperationKnown,
                    Some(("operation-synthetic".to_string(), "op-1".to_string())),
                )
                .unwrap();
                println!("advanced");
            }
            "session" => {
                let state = client.begin_session().unwrap();
                println!(
                    "session revision={} fence={:?}",
                    state.revision,
                    client.current_fence()
                );
            }
            "assess" => {
                let report = store.assess_recovery(&RecoveryContext::default()).unwrap();
                println!("{}", String::from_utf8(report.to_json().unwrap()).unwrap());
            }
            "dryrun" => {
                let report = store.assess_recovery(&RecoveryContext::default()).unwrap();
                store
                    .write_recovery_plan(&report, &path("MKG_J14_OUT"))
                    .unwrap();
                println!("written");
            }
            other => panic!("unknown action {other}"),
        }
    }

    fn established(report: &RecoveryReport) -> (u64, Option<u64>) {
        match &report.observation.session {
            SessionObservation::Established {
                revision, fence, ..
            } => (*revision, *fence),
            other => panic!("no session: {other:?}"),
        }
    }

    fn class_reason(report: &RecoveryReport) -> (RecoveryClass, RecoveryReason) {
        (report.decision.class, report.decision.reason)
    }

    // --- The decision table, exhaustively -------------------------------

    /// Digest of the "true" record at revision `r`; `wrong` is another one.
    fn j14_d(r: u64) -> String {
        format!("{:064x}", r + 1)
    }

    /// The J10 rows, written as six independent predicates (the oracle).
    fn j14_oracle(o: &RecoveryObservation) -> Option<RecoveryRow> {
        let (
            LocalRecord::Present {
                revision: j,
                digest: jd,
            },
            LocalCheckpoint::Present {
                revision: a,
                digest: ad,
            },
        ) = (&o.record, &o.checkpoint)
        else {
            return None;
        };
        // J10: a row needs an answered session with a fence (CAS-11); a
        // session without one may be a plain read.
        let SessionObservation::Established {
            revision: s,
            digest: sd,
            fence: Some(fence),
        } = &o.session
        else {
            return None;
        };
        if !o.identity_consistent
            || o.previous_fence.is_some_and(|p| *fence <= p)
            || matches!(o.inquiry, InquiryObservation::Found { resulting_revision } if resulting_revision > *s)
        {
            return None;
        }
        let (p, ap) = (o.pending, o.checkpoint_pending);
        let clean = j == a && ad == jd;
        match &o.intent {
            IntentObservation::Absent => {
                if clean && !p && !ap && s == j && sd == ad {
                    return Some(RecoveryRow::R0);
                }
            }
            IntentObservation::Present {
                revision: i,
                digest: id,
            } => {
                if clean && !p && !ap && *i == j + 1 && s == j && sd == ad {
                    return Some(RecoveryRow::R1);
                }
                if clean && !p && !ap && *i == j + 1 && *s == j + 1 && sd == id {
                    return Some(RecoveryRow::R2);
                }
                if clean && p && !ap && *i == j + 1 && *s == j + 1 && sd == id {
                    return Some(RecoveryRow::R3);
                }
                if clean && !p && !ap && i == j && id == ad && s == j && sd == ad {
                    return Some(RecoveryRow::R6);
                }
            }
            IntentObservation::Unsupported => return None,
        }
        let intent_ok = match &o.intent {
            IntentObservation::Absent => true,
            IntentObservation::Present {
                revision: i,
                digest: id,
            } => i == j && id == jd,
            IntentObservation::Unsupported => false,
        };
        if *j == a + 1 && !p && intent_ok && s == j && sd == jd {
            return Some(if ap { RecoveryRow::R5 } else { RecoveryRow::R4 });
        }
        None
    }

    /// The expected class, written from J10 without the implementation's
    /// order of checks: a row decides; otherwise a readable local state of
    /// this identity with no fenced answer is undecidable; everything else
    /// is unrecoverable.
    fn j14_oracle_class(o: &RecoveryObservation) -> RecoveryClass {
        match j14_oracle(o) {
            Some(RecoveryRow::R0) => return RecoveryClass::Consistent,
            Some(_) => return RecoveryClass::RepairablePendingOwnerApproval,
            None => {}
        }
        let local_ok = match (&o.record, &o.checkpoint) {
            (
                LocalRecord::Present {
                    revision: j,
                    digest: jd,
                },
                LocalCheckpoint::Present {
                    revision: a,
                    digest: ad,
                },
            ) => {
                o.identity_consistent
                    && o.intent != IntentObservation::Unsupported
                    && !(o.pending && o.checkpoint_pending)
                    && (j == a && ad == jd || *j == a + 1)
            }
            _ => false,
        };
        let no_fenced_answer = matches!(
            o.session,
            SessionObservation::Unknown
                | SessionObservation::NotSent
                | SessionObservation::NotAttempted
                | SessionObservation::Established { fence: None, .. }
        );
        if local_ok && no_fenced_answer {
            RecoveryClass::Undecidable
        } else {
            RecoveryClass::Unrecoverable
        }
    }

    fn j14_all_observations() -> Vec<RecoveryObservation> {
        let mut all = j14_observations_at(5);
        all.extend(j14_observations_at(1));
        all
    }

    fn j14_observations_at(n: u64) -> Vec<RecoveryObservation> {
        let wrong = dg('f');
        let records = {
            let mut v = vec![LocalRecord::Missing, LocalRecord::Invalid];
            for r in [n, n + 1, n + 2] {
                v.push(LocalRecord::Present {
                    revision: r,
                    digest: j14_d(r),
                });
            }
            v
        };
        let checkpoints = {
            let mut v = vec![LocalCheckpoint::Missing, LocalCheckpoint::Invalid];
            for r in [n - 1, n, n + 1] {
                v.push(LocalCheckpoint::Present {
                    revision: r,
                    digest: j14_d(r),
                });
                v.push(LocalCheckpoint::Present {
                    revision: r,
                    digest: wrong.clone(),
                });
            }
            v
        };
        let intents = {
            let mut v = vec![IntentObservation::Absent, IntentObservation::Unsupported];
            for r in [n, n + 1, n + 2] {
                v.push(IntentObservation::Present {
                    revision: r,
                    digest: j14_d(r),
                });
                v.push(IntentObservation::Present {
                    revision: r,
                    digest: wrong.clone(),
                });
            }
            v
        };
        let sessions = {
            let mut v = vec![
                SessionObservation::NotAttempted,
                SessionObservation::Unknown,
                SessionObservation::NotSent,
                SessionObservation::Refused,
            ];
            for r in [n - 1, n, n + 1, n + 2, n + 3] {
                for fence in [Some(9), None] {
                    v.push(SessionObservation::Established {
                        revision: r,
                        digest: j14_d(r),
                        fence,
                    });
                    v.push(SessionObservation::Established {
                        revision: r,
                        digest: wrong.clone(),
                        fence,
                    });
                }
            }
            v
        };
        let mut all = Vec::new();
        for record in &records {
            for checkpoint in &checkpoints {
                for intent in &intents {
                    for session in &sessions {
                        for (pending, checkpoint_pending) in
                            [(false, false), (true, false), (false, true), (true, true)]
                        {
                            for identity_consistent in [true, false] {
                                all.push(RecoveryObservation {
                                    identity_consistent,
                                    record: record.clone(),
                                    checkpoint: checkpoint.clone(),
                                    pending,
                                    checkpoint_pending,
                                    intent: intent.clone(),
                                    session: session.clone(),
                                    previous_fence: None,
                                    inquiry: InquiryObservation::NotAsked,
                                });
                            }
                        }
                    }
                }
            }
        }
        all
    }

    #[test]
    fn j14_t26_unknown_inputs_are_closed_and_the_table_matches_j10() {
        let all = j14_all_observations();
        let mut per_row = std::collections::BTreeMap::new();
        for o in &all {
            let decision = decide_recovery(o);
            let oracle = j14_oracle(o);
            assert_eq!(decision.row, oracle, "{o:?} -> {decision:?}");
            assert_eq!(decision.class, j14_oracle_class(o), "{o:?} -> {decision:?}");
            // A session without a fence decides nothing.
            if let SessionObservation::Established { fence: None, .. } = o.session {
                assert!(decision.row.is_none());
            }
            assert!(!decision.send_authorized());
            match oracle {
                Some(RecoveryRow::R0) => {
                    assert_eq!(decision.class, RecoveryClass::Consistent);
                    assert!(decision.plan.is_empty());
                    assert_eq!(decision.approval, ApprovalStatus::NotRequired);
                }
                Some(row) => {
                    assert_eq!(
                        decision.class,
                        RecoveryClass::RepairablePendingOwnerApproval,
                        "{row:?}"
                    );
                    assert_eq!(decision.approval, ApprovalStatus::PendingOwnerApproval);
                    assert_eq!(decision.plan.first(), Some(&PlanStep::ReverifyObservation));
                    assert_eq!(decision.plan.last(), Some(&PlanStep::VerifyByOpen));
                }
                // Everything the table does not list is closed.
                None => assert!(
                    matches!(
                        decision.class,
                        RecoveryClass::Unrecoverable | RecoveryClass::Undecidable
                    ),
                    "{o:?} -> {decision:?}"
                ),
            }
            // No conclusion without an established session.
            if !matches!(o.session, SessionObservation::Established { .. }) {
                assert!(decision.row.is_none());
            }
            if let SessionObservation::Unknown | SessionObservation::NotSent = o.session
                && o.identity_consistent
                && matches!(o.record, LocalRecord::Present { .. })
                && matches!(o.checkpoint, LocalCheckpoint::Present { .. })
                && decision.class == RecoveryClass::Undecidable
            {
                assert!(matches!(
                    decision.reason,
                    RecoveryReason::SessionUnknown | RecoveryReason::CasUnreachable
                ));
            }
            *per_row
                .entry(format!("{:?}", decision.row))
                .or_insert(0usize) += 1;
            // Inquiry can only make it more cautious.
            for inquiry in [
                InquiryObservation::NotFound,
                InquiryObservation::Failed,
                InquiryObservation::Found {
                    resulting_revision: 1,
                },
            ] {
                let mut with = o.clone();
                with.inquiry = inquiry;
                assert_eq!(decide_recovery(&with).row, decision.row);
            }
            if let SessionObservation::Established { revision, .. } = o.session {
                let mut ahead = o.clone();
                ahead.inquiry = InquiryObservation::Found {
                    resulting_revision: revision + 1,
                };
                assert!(decide_recovery(&ahead).row.is_none());
                // Found at exactly the session's revision changes nothing.
                let mut at = o.clone();
                at.inquiry = InquiryObservation::Found {
                    resulting_revision: revision,
                };
                assert_eq!(decide_recovery(&at).row, decision.row);
                // A fence that does not exceed the caller's previous one
                // closes; a fence beyond it changes nothing.
                let mut regressed = o.clone();
                regressed.previous_fence = Some(9);
                assert!(decide_recovery(&regressed).row.is_none());
                let mut moved_on = o.clone();
                moved_on.previous_fence = Some(8);
                assert_eq!(decide_recovery(&moved_on).row, decision.row);
            }
        }
        // Every row is reachable, and the table is not trivially empty.
        for row in ["R0", "R1", "R2", "R3", "R4", "R5", "R6"] {
            assert!(
                per_row.contains_key(&format!("Some({row})")),
                "{row} unreachable: {per_row:?}"
            );
        }
        assert!(all.len() > 90_000, "{}", all.len());
        eprintln!("J14 table: {} combinations, {per_row:?}", all.len());
    }

    // --- End to end ------------------------------------------------------

    #[test]
    fn j14_t01_journal_and_cas_agree() {
        let _guard = test_guard();
        let t = J14::new();
        let before = t.journal_fingerprint();
        let report = t.assess();
        assert_eq!(
            class_reason(&report),
            (RecoveryClass::Consistent, RecoveryReason::Consistent)
        );
        assert_eq!(report.decision.row, Some(RecoveryRow::R0));
        assert_eq!(established(&report).0, 2);
        assert_eq!(t.journal_fingerprint(), before);
        // The assessment's session is dropped; a normal open works.
        let c = t.f.writer();
        let report = t.assess_with(&c, &RecoveryContext::default());
        assert_eq!(c.current_fence(), None);
        assert!(report.decision.plan.is_empty());
        let j = t.store(&c).open().unwrap();
        assert!(!j.send_authorized());
        drop(j);
        // An anchor whose session carries no fence (a plain read would do)
        // proves nothing about older requests: undecidable, not R0.
        struct NoFence(Arc<NetworkCasAnchor>);
        impl MonotonicAnchor for NoFence {
            fn identity(&self) -> AnchorIdentity {
                self.0.identity()
            }
            fn read(&self) -> Result<AnchorState, AnchorError> {
                self.0.read()
            }
            fn begin_session(&self) -> Result<AnchorState, AnchorError> {
                self.0.read()
            }
            fn advance(
                &self,
                expected: &AnchorState,
                next: &str,
            ) -> Result<AnchorState, AnchorError> {
                self.0.advance(expected, next)
            }
        }
        let plain: Arc<dyn MonotonicAnchor> = Arc::new(NoFence(t.f.writer()));
        let store = JournalStore::for_test_with_anchor(&t.f.anchor, plain).unwrap();
        // J17: an anchor without fenced, owned sessions cannot start an
        // assessment at all (in J14 it was assessed as Undecidable / NoFence).
        // The decision table still closes a fenceless session (T17 enumeration).
        let sessions = t.f.authorized(CasOp::Session);
        assert_eq!(
            store.assess_recovery(&RecoveryContext::default()),
            Err(RecoveryError::NoFencedAnchor)
        );
        assert_eq!(t.f.authorized(CasOp::Session), sessions);
        t.cleanup();
    }

    #[test]
    fn j14_t02_t08_journal_one_behind_and_known_request_in_ledger() {
        let _guard = test_guard();
        let t = J14::new();
        let before = t.journal_fingerprint();
        // Another session of the writer commits revision 3 behind the
        // journal's back (as a crash after the CAS commit would leave it).
        let c = t.f.writer();
        let s = c.begin_session().unwrap();
        c.advance(&s, &dg('e')).unwrap();
        let committed = c.last_advance_request_id().unwrap();
        let inquirer = t.f.writer();
        let report = t.assess_with(
            &t.f.writer(),
            &RecoveryContext {
                previous_fence: None,
                known_request: Some((&committed, inquirer.as_ref())),
            },
        );
        assert_eq!(
            class_reason(&report),
            (
                RecoveryClass::Unrecoverable,
                RecoveryReason::CasAheadWithoutEvidence
            )
        );
        // T08: the ledger confirms the commit. It cannot rebuild the record
        // (no intent: R-B is not implemented), so it stays closed.
        assert_eq!(
            report.observation.inquiry,
            InquiryObservation::Found {
                resulting_revision: 3
            }
        );
        assert_eq!(t.journal_fingerprint(), before);
        // The open fails at stage 8, after its session: that session is
        // dropped from the client as well.
        let opener = t.f.writer();
        assert!(t.store(&opener).open().is_err());
        assert_eq!(opener.current_fence(), None);
        t.cleanup();
    }

    #[test]
    fn j14_t03_journal_several_behind() {
        let _guard = test_guard();
        let t = J14::new();
        let c = t.f.writer();
        let mut s = c.begin_session().unwrap();
        for d in ['a', 'b', 'c'] {
            s = c.advance(&s, &dg(d)).unwrap();
        }
        let report = t.assess();
        assert_eq!(established(&report).0, 5);
        assert_eq!(
            class_reason(&report),
            (RecoveryClass::Unrecoverable, RecoveryReason::CasFarAhead)
        );
        t.cleanup();
    }

    #[test]
    fn j14_t04_t21_cas_behind_or_rolled_back() {
        let _guard = test_guard();
        let mut t = J14::new();
        let state = t.f.state_path(&j11_identity());
        let snapshot = fs::read(&state).unwrap();
        // The journal moves to 3; then the CAS is restored to the old file.
        let c = t.f.writer();
        let mut j = t.store(&c).open().unwrap();
        j.advance(
            &record().attempt,
            State::OperationKnown,
            Some(("operation-synthetic".into(), "op-1".into())),
        )
        .unwrap();
        let held = c.current_fence().unwrap();
        drop(j);
        t.f.stop();
        fs::write(&state, &snapshot).unwrap();
        t.f.start();
        // T21: a client that remembers its fence sees the fence go back
        // (checked first: every later session moves the fence on again).
        let report = t.assess_with(
            &t.f.writer(),
            &RecoveryContext {
                previous_fence: Some(held),
                known_request: None,
            },
        );
        assert_eq!(
            class_reason(&report),
            (
                RecoveryClass::Unrecoverable,
                RecoveryReason::FenceRegression
            )
        );
        // T04: any client sees the CAS behind the journal.
        let report = t.assess();
        assert_eq!(
            class_reason(&report),
            (RecoveryClass::Unrecoverable, RecoveryReason::CasBehind)
        );
        t.cleanup();
    }

    #[test]
    fn j14_t05_same_revision_different_digest() {
        let _guard = test_guard();
        let mut t = J14::new();
        t.f.stop();
        let mut forged = t.cas();
        forged.state.digest = dg('9');
        forged.ledger.back_mut().unwrap().resulting_digest = dg('9');
        fs::write(
            t.f.state_path(&j11_identity()),
            encode_cas_state(&forged).unwrap(),
        )
        .unwrap();
        t.f.start();
        let report = t.assess();
        assert_eq!(established(&report).0, 2);
        assert_eq!(
            class_reason(&report),
            (RecoveryClass::Unrecoverable, RecoveryReason::DigestMismatch)
        );
        t.cleanup();
    }

    #[test]
    fn j14_t06_identity_mismatch_spends_no_session() {
        let _guard = test_guard();
        let t = J14::new();
        let other = t.f.anchor_for(&t.f.pki.other, j12_other_identity());
        let report = t.assess_with(&other, &RecoveryContext::default());
        assert_eq!(
            class_reason(&report),
            (
                RecoveryClass::Unrecoverable,
                RecoveryReason::IdentityMismatch
            )
        );
        assert_eq!(report.observation.session, SessionObservation::NotAttempted);
        assert_eq!(t.f.disk(&j12_other_identity()).fence, 0);
        t.cleanup();
    }

    #[test]
    fn j14_t07_unknown_advance_then_session_and_inquiry() {
        let _guard = test_guard();
        let t = J14::new();
        let c = t.short_client();
        let mut j = t.store(&c).open().unwrap();
        let (arrived_tx, arrived) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        t.f.arm(
            CasStorePoint::BeforeLock,
            "Advance",
            Action::Pause {
                arrived: arrived_tx,
                release: release_rx,
            },
        );
        assert!(
            j.advance(
                &record().attempt,
                State::OperationKnown,
                Some(("operation-synthetic".into(), "op-1".into()))
            )
            .is_err()
        );
        arrived.recv_timeout(Duration::from_secs(10)).unwrap();
        // The failed journal dropped its session: the client cannot send.
        // It still remembers which fence it had, for a later assessment.
        assert_eq!(c.current_fence(), None);
        assert!(c.last_session_fence().is_some());
        let unknown = c.last_advance_request_id().unwrap();
        // The poisoned handle still holds the journal lock; the assessment
        // needs it.
        drop(j);
        let inquirer = t.f.writer();
        let report = t.assess_with(
            &t.f.writer(),
            &RecoveryContext {
                previous_fence: None,
                known_request: Some((&unknown, inquirer.as_ref())),
            },
        );
        // The session fenced the held request: the journal is consistent and
        // the request can never commit. The ledger miss is noted, not used.
        assert_eq!(
            class_reason(&report),
            (RecoveryClass::Consistent, RecoveryReason::Consistent)
        );
        assert_eq!(report.observation.inquiry, InquiryObservation::NotFound);
        let advances = t.f.authorized(CasOp::Advance);
        release.send(()).unwrap();
        // The held connection is the only one left until it is answered.
        t.f.wait_event("late advance handled", |_| {
            t.f.server().active_connections() == 0
        });
        assert_eq!(t.cas().state.revision, 2);
        assert_eq!(t.f.authorized(CasOp::Advance), advances);
        let mut j = t.store(&t.f.writer()).open().unwrap();
        j.advance(
            &record().attempt,
            State::OperationKnown,
            Some(("operation-synthetic".into(), "op-1".into())),
        )
        .unwrap();
        drop(j);
        t.cleanup();
    }

    #[test]
    fn j14_t09_request_outside_the_ledger_is_not_proof_of_anything() {
        let _guard = test_guard();
        let t = J14::new();
        let c = t.f.writer();
        let mut s = c.begin_session().unwrap();
        s = c.advance(&s, &dg('e')).unwrap();
        let committed = c.last_advance_request_id().unwrap();
        // Push it out of the 64-entry ledger.
        for n in 0..CAS_LEDGER_CAPACITY as u64 {
            s = c.advance(&s, &format!("{:064x}", 0xc000 + n)).unwrap();
        }
        let inquirer = t.f.writer();
        let report = t.assess_with(
            &t.f.writer(),
            &RecoveryContext {
                previous_fence: None,
                known_request: Some((&committed, inquirer.as_ref())),
            },
        );
        // It did commit, yet the ledger no longer knows it.
        assert_eq!(report.observation.inquiry, InquiryObservation::NotFound);
        assert_eq!(
            class_reason(&report),
            (RecoveryClass::Unrecoverable, RecoveryReason::CasFarAhead)
        );
        t.cleanup();
    }

    #[test]
    fn j14_t10_t11_lost_and_late_begin_session() {
        let _guard = test_guard();
        let t = J14::new();
        let before = t.journal_fingerprint();
        // T10: the session commits, its reply is lost.
        let (arrived_tx, arrived) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        t.f.arm(
            CasStorePoint::Committed,
            "BeginSession",
            Action::Pause {
                arrived: arrived_tx,
                release: release_rx,
            },
        );
        let report = t.assess_with(&t.short_client(), &RecoveryContext::default());
        assert_eq!(
            class_reason(&report),
            (RecoveryClass::Undecidable, RecoveryReason::SessionUnknown)
        );
        arrived.recv_timeout(Duration::from_secs(10)).unwrap();
        release.send(()).unwrap();
        let lost_fence = t.cas().fence;
        let report = t.assess();
        assert_eq!(report.decision.class, RecoveryClass::Consistent);
        assert_eq!(established(&report).1, Some(lost_fence + 1));
        // T11: a session held in the network arrives after a newer one. It
        // fences the newer session: the journal fails closed, never commits.
        let (arrived_tx, arrived) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        t.f.arm(
            CasStorePoint::BeforeLock,
            "BeginSession",
            Action::Pause {
                arrived: arrived_tx,
                release: release_rx,
            },
        );
        let report = t.assess_with(&t.short_client(), &RecoveryContext::default());
        assert_eq!(report.decision.class, RecoveryClass::Undecidable);
        arrived.recv_timeout(Duration::from_secs(10)).unwrap();
        let c = t.f.writer();
        let mut j = t.store(&c).open().unwrap();
        let open_fence = c.current_fence().unwrap();
        release.send(()).unwrap();
        t.f.wait_event("late session committed", |_| {
            t.cas().fence == open_fence + 1
        });
        assert!(
            j.advance(
                &record().attempt,
                State::OperationKnown,
                Some(("operation-synthetic".into(), "op-1".into()))
            )
            .is_err()
        );
        assert_eq!(c.current_fence(), None);
        drop(j);
        assert_eq!(t.cas().state.revision, 2);
        assert_eq!(t.journal_fingerprint(), before);
        assert_eq!(t.assess().decision.class, RecoveryClass::Consistent);
        t.cleanup();
    }

    fn j14_advance(j: &mut Journal) -> Result<(), ()> {
        j.advance(
            &record().attempt,
            State::OperationKnown,
            Some(("operation-synthetic".to_string(), "op-1".to_string())),
        )
    }

    #[test]
    fn j14_t12_t13_late_advance_and_lost_commit_reply() {
        let _guard = test_guard();
        let t = J14::new();
        // T13: the CAS commits revision 3, the reply is lost; the journal is
        // not written (anchor-first) and is poisoned.
        let c = t.short_client();
        let mut j = t.store(&c).open().unwrap();
        let (arrived_tx, arrived) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        t.f.arm(
            CasStorePoint::Committed,
            "Advance",
            Action::Pause {
                arrived: arrived_tx,
                release: release_rx,
            },
        );
        assert!(j14_advance(&mut j).is_err());
        arrived.recv_timeout(Duration::from_secs(10)).unwrap();
        release.send(()).unwrap();
        let lost = c.last_advance_request_id().unwrap();
        drop(j);
        let inquirer = t.f.writer();
        let report = t.assess_with(
            &t.f.writer(),
            &RecoveryContext {
                previous_fence: None,
                known_request: Some((&lost, inquirer.as_ref())),
            },
        );
        assert_eq!(
            class_reason(&report),
            (
                RecoveryClass::Unrecoverable,
                RecoveryReason::CasAheadWithoutEvidence
            )
        );
        assert_eq!(
            report.observation.inquiry,
            InquiryObservation::Found {
                resulting_revision: 3
            }
        );
        t.cleanup();
        // The CAS commits and replies, then the local journal write fails.
        // The client got its fence back from the commit; the poisoned
        // journal must take it away again (J11 IA-01).
        let t = J14::new();
        let c = t.f.writer();
        let mut j = t.store(&c).open().unwrap();
        INJECT.with(|value| value.set(1));
        let result = j14_advance(&mut j);
        INJECT.with(|value| value.set(0));
        assert!(result.is_err());
        assert_eq!(t.cas().state.revision, 3);
        assert_eq!(c.current_fence(), None);
        let advances = t.f.authorized(CasOp::Advance);
        assert_eq!(
            c.advance(&t.cas().state, &dg('d')),
            Err(AnchorError::Fenced)
        );
        assert_eq!(t.f.authorized(CasOp::Advance), advances);
        drop(j);
        assert_eq!(
            class_reason(&t.assess()),
            (
                RecoveryClass::Unrecoverable,
                RecoveryReason::CasAheadWithoutEvidence
            )
        );
        t.cleanup();
        // T12: an Advance held before the identity lock, released after a
        // new session: fenced, nothing changes, and it is never resent.
        let t = J14::new();
        let c = t.short_client();
        let mut j = t.store(&c).open().unwrap();
        let (arrived_tx, arrived) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        t.f.arm(
            CasStorePoint::BeforeLock,
            "Advance",
            Action::Pause {
                arrived: arrived_tx,
                release: release_rx,
            },
        );
        assert!(j14_advance(&mut j).is_err());
        arrived.recv_timeout(Duration::from_secs(10)).unwrap();
        drop(j);
        let advances = t.f.authorized(CasOp::Advance);
        assert_eq!(t.assess().decision.class, RecoveryClass::Consistent);
        release.send(()).unwrap();
        t.f.wait_event("late advance handled", |_| {
            t.f.server().active_connections() == 0
        });
        assert_eq!(t.cas().state.revision, 2);
        assert_eq!(t.f.authorized(CasOp::Advance), advances);
        assert_eq!(t.assess().decision.class, RecoveryClass::Consistent);
        t.cleanup();
    }

    #[test]
    fn j14_t14_t15_t17_client_crashes() {
        let _guard = test_guard();
        // T14: SIGKILL after the CAS commit, before the journal write.
        let t = J14::new();
        let before = t.journal_fingerprint();
        let (status, _) = t.child("advance", Some("after_anchor"), None);
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        assert_eq!(t.journal_fingerprint(), before);
        assert_eq!(t.cas().state.revision, 3);
        let report = t.assess();
        assert_eq!(
            class_reason(&report),
            (
                RecoveryClass::Unrecoverable,
                RecoveryReason::CasAheadWithoutEvidence
            )
        );
        t.cleanup();
        // T15: SIGKILL after the journal write, before the checkpoint: J10 R4.
        let t = J14::new();
        let (status, _) = t.child("advance", Some("after_journal"), None);
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        let report = t.assess();
        assert_eq!(report.decision.row, Some(RecoveryRow::R4));
        assert_eq!(
            report.decision.class,
            RecoveryClass::RepairablePendingOwnerApproval
        );
        assert_eq!(
            report.decision.plan,
            vec![
                PlanStep::ReverifyObservation,
                PlanStep::WriteCheckpoint { revision: 3 },
                PlanStep::SyncDirectory,
                PlanStep::VerifyByOpen
            ]
        );
        assert!(t.store(&t.f.writer()).open().is_err());
        // SIGKILL after the checkpoint: complete, R0.
        t.cleanup();
        let t = J14::new();
        let (status, _) = t.child("advance", Some("after_checkpoint"), None);
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        assert_eq!(t.assess().decision.row, Some(RecoveryRow::R0));
        t.cleanup();
        // T17: SIGKILL of a client in the middle of an assessment (after its
        // session). Nothing local changed; the lock died with it; re-running
        // gives the same answer with a newer fence.
        let t = J14::new();
        let before = t.journal_fingerprint();
        let fence = t.cas().fence;
        let (status, out) = t.child("assess", Some("recovery_after_session"), None);
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        assert!(!out.contains("decision"), "{out}");
        assert_eq!(t.cas().fence, fence + 1);
        assert_eq!(t.journal_fingerprint(), before);
        let report = t.assess();
        assert_eq!(report.decision.class, RecoveryClass::Consistent);
        assert_eq!(established(&report).1, Some(fence + 2));
        t.cleanup();
    }

    #[test]
    fn j14_t16_cas_server_sigkill() {
        let _guard = test_guard();
        for (point, revision, class) in [
            ("BeforeRename:Advance", 2, RecoveryClass::Consistent),
            ("Committed:Advance", 3, RecoveryClass::Unrecoverable),
        ] {
            let mut t = J14::new();
            t.f.stop();
            let child = t.f.spawn_child(Some(point), 0).unwrap();
            let port = t.f.addr.port();
            let c = t.f.writer();
            let mut j = t.store(&c).open().unwrap();
            assert!(j14_advance(&mut j).is_err());
            child.died_by_sigkill();
            drop(j);
            assert_eq!(t.cas().state.revision, revision, "{point}");
            let child = t.f.spawn_child(None, port).unwrap();
            let report = t.assess();
            assert_eq!(report.decision.class, class, "{point}");
            child.sigkill();
            t.cleanup();
        }
    }

    #[test]
    fn j14_t18_partition_is_undecidable() {
        let _guard = test_guard();
        let mut t = J14::new();
        let before = t.journal_fingerprint();
        // Before sending: nothing listens.
        t.f.stop();
        let report = t.assess();
        assert_eq!(
            class_reason(&report),
            (RecoveryClass::Undecidable, RecoveryReason::CasUnreachable)
        );
        assert_eq!(report.observation.session, SessionObservation::NotSent);
        t.f.start();
        // After sending: the session is held, the client gives up.
        let fence = t.cas().fence;
        let (arrived_tx, arrived) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        t.f.arm(
            CasStorePoint::BeforeLock,
            "BeginSession",
            Action::Pause {
                arrived: arrived_tx,
                release: release_rx,
            },
        );
        let report = t.assess_with(&t.short_client(), &RecoveryContext::default());
        assert_eq!(
            class_reason(&report),
            (RecoveryClass::Undecidable, RecoveryReason::SessionUnknown)
        );
        arrived.recv_timeout(Duration::from_secs(10)).unwrap();
        release.send(()).unwrap();
        // It did commit, later: a fence the client never learned.
        t.f.wait_event("held session committed", |_| t.cas().fence == fence + 1);
        assert_eq!(t.journal_fingerprint(), before);
        t.cleanup();
    }

    #[test]
    fn j14_t19_t20_several_clients_one_identity() {
        let _guard = test_guard();
        let t = J14::new();
        // T19: the same certificate in another process. Its assessment starts
        // a session; the first client's journal is fenced and fails closed.
        let a = t.f.writer();
        let j = t.store(&a).open().unwrap();
        drop(j);
        let mut j = {
            // Re-open: the first client now holds the latest session.
            t.store(&a).open().unwrap()
        };
        let advances = t.f.authorized(CasOp::Advance);
        // The journal lock is held by `j`, so a second assessment of this
        // journal cannot even start in this process.
        assert_eq!(
            t.store(&t.f.writer())
                .assess_recovery(&RecoveryContext::default())
                .unwrap_err(),
            RecoveryError::Store
        );
        drop(j);
        j = t.store(&a).open().unwrap();
        let b = t.f.writer();
        // A second client (same principal) on its own copy of the journal,
        // as a cloned VM would have: it opens and wins the session.
        let clone = t.f.base.join("clone");
        fs::create_dir(&clone).unwrap();
        set_mode(&clone, 0o700);
        fs::create_dir(clone.join(JOURNAL_DIR)).unwrap();
        set_mode(&clone.join(JOURNAL_DIR), 0o700);
        for name in [JOURNAL_FILE, ANCHOR_FILE, LOCK_FILE] {
            let target = clone.join(JOURNAL_DIR).join(name);
            fs::copy(t.journal_dir().join(name), &target).unwrap();
            set_mode(&target, 0o600);
        }
        let clone_store = JournalStore::for_test_with_anchor(&clone, b.clone()).unwrap();
        // The clone's store identity differs (other inodes): it cannot open.
        assert!(clone_store.open().is_err());
        // The other process, same certificate: it starts a session (the
        // journal lock keeps it from this journal, not from the CAS).
        let (status, out) = t.child("session", None, None);
        assert!(status.success());
        assert!(out.contains("session revision=2"), "{out}");
        // The first client's session is gone: its advance is refused by the
        // CAS, its journal is poisoned, and its client holds no fence after.
        assert!(j14_advance(&mut j).is_err());
        assert_eq!(a.current_fence(), None);
        // A direct call on the shared client sends nothing now.
        assert_eq!(
            a.advance(&t.cas().state, &dg('d')),
            Err(AnchorError::Fenced)
        );
        assert_eq!(t.f.authorized(CasOp::Advance), advances + 1);
        drop(j);
        assert_eq!(t.assess().decision.class, RecoveryClass::Consistent);
        // T20: another principal cannot start a session of this identity.
        let fence = t.cas().fence;
        let intruder = t.f.anchor_for(&t.f.pki.other, j11_identity());
        let report = t.assess_with(&intruder, &RecoveryContext::default());
        assert_eq!(
            class_reason(&report),
            (RecoveryClass::Unrecoverable, RecoveryReason::SessionRefused)
        );
        assert_eq!(t.cas().fence, fence);
        t.cleanup();
    }

    #[test]
    fn j14_t22_t23_journal_rollback_and_the_simultaneous_limit() {
        let _guard = test_guard();
        let mut t = J14::new();
        let journal = t.journal_dir();
        let saved: Vec<(String, Vec<u8>)> = [JOURNAL_FILE, ANCHOR_FILE]
            .iter()
            .map(|name| (name.to_string(), fs::read(journal.join(name)).unwrap()))
            .collect();
        let state = t.f.state_path(&j11_identity());
        let saved_cas = fs::read(&state).unwrap();
        let c = t.f.writer();
        let mut j = t.store(&c).open().unwrap();
        j14_advance(&mut j).unwrap();
        let held = c.current_fence().unwrap();
        drop(j);
        let restore_journal = || {
            for (name, bytes) in &saved {
                fs::write(journal.join(name), bytes).unwrap();
            }
        };
        // T22: only the journal goes back. Indistinguishable from a client
        // that crashed after the CAS commit: closed, never repaired.
        restore_journal();
        let report = t.assess();
        assert_eq!(
            class_reason(&report),
            (
                RecoveryClass::Unrecoverable,
                RecoveryReason::CasAheadWithoutEvidence
            )
        );
        // T23: both go back to a consistent pair. The known limit (J10 RB-6):
        // the state comparison sees nothing wrong.
        t.f.stop();
        fs::write(&state, &saved_cas).unwrap();
        t.f.start();
        // A client that remembers its fence notices (only before a newer
        // session has moved the fence past it).
        let report = t.assess_with(
            &t.f.writer(),
            &RecoveryContext {
                previous_fence: Some(held),
                known_request: None,
            },
        );
        assert_eq!(
            class_reason(&report),
            (
                RecoveryClass::Unrecoverable,
                RecoveryReason::FenceRegression
            )
        );
        // Any other client: the state comparison sees nothing wrong.
        let report = t.assess();
        assert_eq!(report.decision.class, RecoveryClass::Consistent);
        t.cleanup();
    }

    #[test]
    fn j14_t24_t25_t29_dry_run_plans_and_refused_repairs() {
        let _guard = test_guard();
        let t = J14::new();
        let (status, _) = t.child("advance", Some("after_journal"), None);
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        let journal_before = t.journal_fingerprint();
        let out = t.f.base.join("plans");
        fs::create_dir(&out).unwrap();
        set_mode(&out, 0o700);
        // T29: a crash while the dry-run report is written leaves a temporary
        // file and no report.
        let (status, _) = t.child("dryrun", Some("dry_run_after_temp"), Some(&out));
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        let names = || -> Vec<String> {
            let mut v: Vec<String> = fs::read_dir(&out)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            v.sort();
            v
        };
        assert_eq!(names().len(), 1);
        assert!(names()[0].starts_with("recovery-plan.json.tmp-"));
        // Re-running completes it; the decision is the same.
        let report = t.assess();
        let written = t
            .store(&t.f.writer())
            .write_recovery_plan(&report, &out)
            .unwrap();
        assert_eq!(file_mode(&written), 0o600);
        let plan: serde_json::Value = serde_json::from_slice(&fs::read(&written).unwrap()).unwrap();
        // T24: the plan names the row, its steps and the missing approval.
        assert_eq!(plan["decision"]["row"], "R4");
        assert_eq!(plan["decision"]["approval"], "PendingOwnerApproval");
        assert_eq!(
            plan["decision"]["plan"][1]["WriteCheckpoint"]["revision"],
            3
        );
        assert_eq!(names().len(), 2);
        // Never inside the journal store.
        for inside in [t.f.anchor.clone(), t.journal_dir()] {
            assert_eq!(
                t.store(&t.f.writer()).write_recovery_plan(&report, &inside),
                Err(RecoveryError::Report)
            );
        }
        // T25: applying it is refused and writes nothing anywhere.
        let cas_before = fs::read(t.f.state_path(&j11_identity())).unwrap();
        assert_eq!(
            t.store(&t.f.writer()).apply_recovery(&report),
            Err(RecoveryError::PendingOwnerApproval)
        );
        assert_eq!(t.journal_fingerprint(), journal_before);
        assert_eq!(
            fs::read(t.f.state_path(&j11_identity())).unwrap(),
            cas_before
        );
        assert!(t.store(&t.f.writer()).open().is_err());
        // Structurally: the recovery code calls none of the journal or CAS
        // writers, and holds no switch, thread or environment read.
        let source = include_str!("gce_operation_journal.rs");
        let block =
            &source[source.find("// J14-BEGIN").unwrap()..source.find("// J14-END").unwrap()];
        for forbidden in [
            "write_record(",
            "write_anchor_checkpoint(",
            "cas_write_member(",
            "cas_unlink(",
            "cas_link(",
            "cas_rename(",
            "renameat",
            "unlinkat",
            "linkat",
            "std::env",
            "MKG_",
            "thread::spawn",
            "process::exit",
            "abort()",
            "AtomicBool",
        ] {
            assert!(!block.contains(forbidden), "J14 block contains {forbidden}");
        }
        t.cleanup();
    }

    #[test]
    fn j14_t27_t28_restart_and_send_never_authorized() {
        let _guard = test_guard();
        let mut t = J14::new();
        let (status, _) = t.child("advance", Some("after_journal"), None);
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        let first = t.assess();
        // T28: the assessment keeps no state; after a server restart and with
        // a new client it reads the same disks and decides the same.
        t.f.restart();
        let second = t.assess();
        assert_eq!(first.decision, second.decision);
        assert_eq!(first.observation.record, second.observation.record);
        assert!(established(&second).1 > established(&first).1);
        // T27: no recovery result authorizes a send.
        assert!(!first.decision.send_authorized() && !second.decision.send_authorized());
        t.cleanup();
        let t = J14::new();
        let report = t.assess();
        assert!(!report.decision.send_authorized());
        let mut j = t.store(&t.f.writer()).open().unwrap();
        assert!(!j.send_authorized());
        j14_advance(&mut j).unwrap();
        assert!(!j.send_authorized() && !j.record().send_authorized());
        drop(j);
        t.cleanup();
    }

    #[test]
    fn j14_t30_reports_and_logs_hold_no_secret() {
        let _guard = test_guard();
        let t = J14::new();
        let (status, _) = t.child("advance", Some("after_journal"), None);
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        let (_, child_out) = t.child("assess", None, None);
        let report = t.assess();
        let mut text = String::from_utf8(report.to_json().unwrap()).unwrap();
        text.push_str(&child_out);
        text.push_str(&format!("{report:?}"));
        for event in t.f.events() {
            text.push_str(&format!("{event}\n"));
        }
        for pem in [&t.f.pki.server_leaf.key_pem, &t.f.pki.writer.key_pem] {
            for fragment in j13_secret_fragments(pem) {
                assert!(!text.contains(&fragment), "key material");
            }
        }
        for marker in ["PRIVATE KEY", "BEGIN ", "-----", "/Users/", "/home/"] {
            assert!(!text.contains(marker), "{marker}");
        }
        t.cleanup();
    }

    // Phase 1-J15: cross-host harness. Each role runs as its own process of
    // this test binary (`--exact …::j15_role --nocapture`), configured only by
    // environment variables, so the same binary is the CAS server on one VM
    // and the client on another. Test-only: the store uses the test boundary,
    // the PKI is a synthetic private CA, and nothing here is a deployable
    // server. Results are printed as one `J15RESULT {json}` line.

    const J15_ROLE: &str = "gce_operation_journal::tests::j15_role";

    fn j15_var(key: &str) -> String {
        std::env::var(key).unwrap_or_else(|_| panic!("{key} not set"))
    }

    fn j15_path(key: &str) -> PathBuf {
        PathBuf::from(j15_var(key))
    }

    fn j15_identity(name: &str) -> AnchorIdentity {
        match name {
            "main" => j11_identity(),
            "other" => j12_other_identity(),
            other => panic!("unknown identity {other}"),
        }
    }

    fn j15_op(name: &str) -> &'static str {
        match name {
            "Advance" => "Advance",
            "BeginSession" => "BeginSession",
            other => panic!("unknown op {other}"),
        }
    }

    fn j15_result(value: serde_json::Value) {
        println!("J15RESULT {value}");
    }

    #[test]
    fn j15_role() {
        let Ok(role) = std::env::var("MKG_J15_ROLE") else {
            return;
        };
        match role.as_str() {
            "pki" => j15_pki(&j15_path("MKG_J15_OUT")),
            "store-init" => {
                let dir = j15_path("MKG_J15_STORE");
                fs::create_dir_all(&dir).unwrap();
                set_mode(&dir, 0o700);
                CasStore::create_for_test(&dir).unwrap();
                CasStore::provision_for_test(&dir, &j11_identity()).unwrap();
                CasStore::provision_for_test(&dir, &j12_other_identity()).unwrap();
                j15_result(serde_json::json!({"store": "initialized"}));
            }
            "server" => j15_server(),
            "client" => j15_client(),
            other => panic!("unknown role {other}"),
        }
    }

    /// A synthetic private CA and every certificate the scenarios use. Keys
    /// are written 0600 and never printed.
    fn j15_pki(out: &Path) {
        fs::create_dir_all(out).unwrap();
        set_mode(out, 0o700);
        let write = |name: &str, text: &str, mode: u32| {
            let path = out.join(name);
            fs::write(&path, text).unwrap();
            set_mode(&path, mode);
        };
        let ca = Ca::new("synthetic-j15-ca");
        let rogue = Ca::new("synthetic-j15-rogue-ca");
        let server = ca.server(SERVER_DNS);
        write("server.crt", &server.cert_pem, 0o644);
        write("server.key", &server.key_pem, 0o600);
        let revoked = ca.client(WRITER);
        let revoked_serial = revoked.serial;
        for (name, leaf) in [
            ("writer", ca.client(WRITER)),
            ("monitor", ca.client(MONITOR)),
            ("other", ca.client(OTHER_NODE)),
            ("unregistered", ca.client(ROGUE)),
            ("expired", ca.client_with_uris(&[WRITER], true)),
            ("rogue", rogue.client(WRITER)),
            ("revoked", revoked),
        ] {
            write(&format!("{name}.crt"), &leaf.cert_pem, 0o644);
            write(&format!("{name}.key"), &leaf.key_pem, 0o600);
        }
        write("ca.pem", &ca.cert_pem, 0o644);
        write("crl.pem", &ca.crl(&[]), 0o644);
        write("crl-revoking.pem", &ca.crl(&[revoked_serial]), 0o644);
        write("rogue-ca.pem", &rogue.cert_pem, 0o644);
        write("rogue-crl.pem", &rogue.crl(&[]), 0o644);
        write("acl.toml", &j13_acl_text(), 0o644);
        j15_result(serde_json::json!({"pki": "written"}));
    }

    fn j15_server() {
        let pki = j15_path("MKG_J15_PKI");
        let ctl = j15_path("MKG_J15_CTL");
        fs::create_dir_all(&ctl).unwrap();
        // J16: whatever an earlier run left is removed before anything else,
        // so that a waiter can never take it for this run's.
        j16_clear_ready(&ctl);
        let refuse = |code: i32, what: String| -> ! {
            eprintln!("cas start refused: {what}");
            let _ = j16_publish(&ctl, "refused", &what);
            std::process::exit(code);
        };
        let store = match CasStore::open_for_test(&j15_path("MKG_J15_STORE")) {
            Ok(store) => store,
            Err(error) => refuse(3, format!("store {error:?}")),
        };
        if let Ok(spec) = std::env::var("MKG_J15_CRASH") {
            let (point, op) = spec.split_once(':').unwrap();
            store.arm(j13_point(point), j15_op(op), Action::Kill);
        }
        if let Ok(spec) = std::env::var("MKG_J15_PAUSE") {
            // Hold the first request of `op` at `point` until the operator
            // creates `release`; report `arrived` first.
            let (point, op) = spec.split_once(':').unwrap();
            let (arrived_tx, arrived) = mpsc::channel();
            let (release, release_rx) = mpsc::channel();
            store.arm(
                j13_point(point),
                j15_op(op),
                Action::Pause {
                    arrived: arrived_tx,
                    release: release_rx,
                },
            );
            let ctl = ctl.clone();
            thread::spawn(move || {
                if arrived.recv().is_ok() {
                    j16_publish(&ctl, "arrived", "arrived\n").unwrap();
                    while !ctl.join("release").exists() {
                        thread::sleep(Duration::from_millis(20));
                    }
                    let _ = release.send(());
                }
            });
        }
        let crls = std::env::var("MKG_J15_SERVER_CRL").unwrap_or_else(|_| "crl.pem".into());
        let files = CasServerFiles {
            certificate: pki.join("server.crt"),
            key: pki.join("server.key"),
            client_roots: pki.join("ca.pem"),
            crls: pki.join(crls),
            acl: pki.join("acl.toml"),
        };
        let sink: Arc<dyn Fn(&CasEvent) + Send + Sync> =
            Arc::new(|event: &CasEvent| eprintln!("{event}"));
        let server = match CasNetworkServer::start(store, &files, j13_limits(), sink) {
            Ok(server) => Arc::new(server),
            Err(error) => refuse(4, format!("server {error:?}")),
        };
        let listener = match server.bind(j15_var("MKG_J15_BIND").parse().unwrap()) {
            Ok(listener) => listener,
            Err(error) => refuse(5, format!("bind {error:?}")),
        };
        // J16: published only once the listener exists (bind listens), and
        // atomically: the name `ready` appears with its complete content.
        if let Err(error) = j16_publish_ready(&ctl, listener.local_addr().unwrap()) {
            refuse(6, format!("ready {:?}", error.kind()));
        }
        let exit = server.serve(&listener, &mut |connection| {
            thread::spawn(move || connection.run());
        });
        std::process::exit(if exit == CasServeExit::Halted { 70 } else { 0 });
    }

    fn j15_next(j: &mut Journal) -> Result<(), ()> {
        let attempt = record().attempt;
        match j.record().state {
            State::Prepared => j.advance(&attempt, State::MayHaveBeenSent, None),
            State::MayHaveBeenSent => j.advance(
                &attempt,
                State::OperationKnown,
                Some(("operation-synthetic".to_string(), "op-1".to_string())),
            ),
            State::OperationKnown => j.advance(&attempt, State::DoneObserved, None),
            State::DoneObserved => j.advance(&attempt, State::TerminatedObserved, None),
            _ => j.advance(&attempt, State::ProofEstablished, None),
        }
    }

    fn j15_client() {
        let pki = j15_path("MKG_J15_PKI");
        let cert = std::env::var("MKG_J15_CERT_NAME").unwrap_or_else(|_| "writer".into());
        let (roots, crls) = match std::env::var("MKG_J15_TRUST").as_deref() {
            Ok("rogue") => ("rogue-ca.pem", "rogue-crl.pem"),
            _ => ("ca.pem", "crl.pem"),
        };
        let config = cas_client_tls_config(
            cas_load_roots(&pki.join(roots)).unwrap(),
            cas_load_crls(&pki.join(crls)).unwrap(),
            CasTlsIdentity::load(
                &pki.join(format!("{cert}.crt")),
                &pki.join(format!("{cert}.key")),
            )
            .unwrap(),
        )
        .unwrap();
        let timeout = std::env::var("MKG_J15_TIMEOUT_MS")
            .map(|v| v.parse().unwrap())
            .unwrap_or(5000);
        let transport = Arc::new(
            TlsTransport::new(
                j15_var("MKG_J15_ADDR").parse().unwrap(),
                SERVER_DNS,
                config,
                Duration::from_secs(3),
                Duration::from_millis(timeout),
            )
            .unwrap(),
        );
        let identity =
            j15_identity(&std::env::var("MKG_J15_IDENTITY").unwrap_or_else(|_| "main".into()));
        let anchor = Arc::new(NetworkCasAnchor::new(transport.clone(), identity));
        let journal = || {
            JournalStore::for_test_with_anchor(&j15_path("MKG_J15_ANCHOR"), anchor.clone()).unwrap()
        };
        let action = j15_var("MKG_J15_ACTION");
        let fmt = |r: Result<AnchorState, AnchorError>| match r {
            Ok(state) => serde_json::json!({"ok": state}),
            Err(error) => serde_json::json!({"err": format!("{error:?}")}),
        };
        match action.as_str() {
            "read" => j15_result(serde_json::json!({"read": fmt(anchor.read())})),
            "begin" => {
                let r = anchor.begin_session();
                j15_result(serde_json::json!({"begin": fmt(r), "fence": anchor.current_fence()}));
            }
            "begin-advance" => {
                let begun = anchor.begin_session();
                let fence = anchor.current_fence();
                let advanced = match &begun {
                    Ok(state) => fmt(anchor.advance(state, &j15_var("MKG_J15_DIGEST"))),
                    Err(_) => serde_json::json!({"skipped": true}),
                };
                j15_result(serde_json::json!({
                    "begin": fmt(begun),
                    "fence": fence,
                    "advance": advanced,
                    "request_id": anchor.last_advance_request_id(),
                }));
            }
            "raw" => {
                let reply = transport.exchange(j15_var("MKG_J15_RAW").as_bytes());
                let reply = match reply {
                    Ok(bytes) => serde_json::json!({"reply": String::from_utf8_lossy(&bytes)}),
                    Err(error) => serde_json::json!({"transport": format!("{error:?}")}),
                };
                j15_result(reply);
            }
            "inquire" => {
                let begun = fmt(anchor.begin_session());
                let outcome = anchor.inquire(&j15_var("MKG_J15_TARGET"));
                j15_result(serde_json::json!({
                    "begin": begun,
                    "inquire": match outcome {
                        Ok(o) => serde_json::json!({"found": o.found, "resulting_revision": o.resulting_revision}),
                        Err(error) => serde_json::json!({"err": format!("{error:?}")}),
                    }
                }));
            }
            "journal-init" => {
                let dir = j15_path("MKG_J15_ANCHOR");
                fs::create_dir_all(&dir).unwrap();
                set_mode(&dir, 0o700);
                let mut j = journal().initialize(record()).unwrap();
                j15_next(&mut j).unwrap();
                j15_result(
                    serde_json::json!({"journal": j.record().revision, "send_authorized": j.send_authorized()}),
                );
            }
            "journal-advance" => {
                let opened = journal().open();
                let Ok(mut j) = opened else {
                    j15_result(serde_json::json!({"open": "failed"}));
                    return;
                };
                let fence = anchor.current_fence();
                let result = j15_next(&mut j);
                j15_result(serde_json::json!({
                    "opened_fence": fence,
                    "advance": if result.is_ok() { "ok" } else { "err" },
                    "revision": j.record().revision,
                    "request_id": anchor.last_advance_request_id(),
                    "fence_after": anchor.current_fence(),
                    "send_authorized": j.send_authorized() || j.record().send_authorized(),
                }));
            }
            "assess" | "apply" | "dryrun" => {
                let target = std::env::var("MKG_J15_TARGET").ok();
                let previous = std::env::var("MKG_J15_PREVIOUS_FENCE")
                    .ok()
                    .map(|v| v.parse().unwrap());
                let inquirer = Arc::clone(&anchor);
                let context = RecoveryContext {
                    previous_fence: previous,
                    known_request: target
                        .as_deref()
                        .map(|id| (id, inquirer.as_ref() as &dyn CasInquiry)),
                };
                let store = journal();
                let report = store.assess_recovery(&context).unwrap();
                let extra = match action.as_str() {
                    "apply" => serde_json::json!(format!("{:?}", store.apply_recovery(&report))),
                    "dryrun" => serde_json::json!(
                        store
                            .write_recovery_plan(&report, &j15_path("MKG_J15_OUT"))
                            .is_ok()
                    ),
                    _ => serde_json::Value::Null,
                };
                j15_result(serde_json::json!({
                    "report": report,
                    "extra": extra,
                    "send_authorized": report.decision.send_authorized(),
                }));
            }
            other => panic!("unknown action {other}"),
        }
    }

    /// The harness on one host (loopback), as separate processes: proves the
    /// roles and their wiring, nothing about separate hosts.
    #[test]
    fn j15_t00_harness_roles_on_one_host() {
        let _guard = test_guard();
        let base = unique_base("j15");
        let pki = base.join("pki");
        let ctl = base.join("ctl");
        let run = |envs: &[(&str, String)]| -> String {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args(["--exact", J15_ROLE, "--nocapture"])
                .stderr(Stdio::null());
            for (key, value) in envs {
                command.env(key, value);
            }
            let out = command.output().unwrap();
            assert!(out.status.success(), "{envs:?}");
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .find_map(|l| l.strip_prefix("J15RESULT ").map(String::from))
                .unwrap()
        };
        let s = |p: &Path| p.to_string_lossy().into_owned();
        run(&[("MKG_J15_ROLE", "pki".into()), ("MKG_J15_OUT", s(&pki))]);
        run(&[
            ("MKG_J15_ROLE", "store-init".into()),
            ("MKG_J15_STORE", s(&base.join("store"))),
        ]);
        let mut server = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", J15_ROLE, "--nocapture"])
            .env("MKG_J15_ROLE", "server")
            .env("MKG_J15_PKI", s(&pki))
            .env("MKG_J15_CTL", s(&ctl))
            .env("MKG_J15_STORE", s(&base.join("store")))
            .env("MKG_J15_BIND", "127.0.0.1:0")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut ready = String::new();
        for _ in 0..1500 {
            if let Ok(text) = fs::read_to_string(ctl.join("ready")) {
                ready = text;
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let addr = ready.split_whitespace().nth(1).unwrap().to_string();
        let client = |action: &str, extra: &[(&str, String)]| {
            let mut envs = vec![
                ("MKG_J15_ROLE", "client".to_string()),
                ("MKG_J15_PKI", s(&pki)),
                ("MKG_J15_ADDR", addr.clone()),
                ("MKG_J15_ANCHOR", s(&base.join("anchor"))),
                ("MKG_J15_ACTION", action.to_string()),
            ];
            envs.extend(extra.iter().cloned());
            serde_json::from_str::<serde_json::Value>(&run(&envs)).unwrap()
        };
        assert_eq!(client("journal-init", &[])["journal"], 2);
        let advanced = client("journal-advance", &[]);
        assert_eq!(
            (advanced["advance"].as_str(), advanced["revision"].as_u64()),
            (Some("ok"), Some(3))
        );
        let report = client("assess", &[]);
        assert_eq!(report["report"]["decision"]["class"], "Consistent");
        assert_eq!(report["send_authorized"], false);
        let refused = client("read", &[("MKG_J15_CERT_NAME", "unregistered".into())]);
        assert_eq!(refused["read"]["err"], "Forbidden");
        assert_eq!(client("apply", &[])["extra"], "Err(PendingOwnerApproval)");
        server.kill().unwrap();
        server.wait().unwrap();
        base_cleanup(&base);
    }

    // Phase 1-J16: client session ownership, close, E2E evidence quality,
    // TLS and ACL file directories. Deliverables:
    // prototype/v0.7/phase1-journal/j16/.

    /// J16: write `name` in `dir` atomically: a temporary name is created
    /// exclusively, written, fsynced, then linked to `name` (never replacing
    /// an existing one) and unlinked; the directory is fsynced. A reader sees
    /// either no `name` or its complete content.
    fn j16_publish(dir: &Path, name: &str, content: &str) -> std::io::Result<()> {
        j16_publish_held(dir, name, content, || {})
    }

    fn j16_publish_held(
        dir: &Path,
        name: &str,
        content: &str,
        hold: impl FnOnce(),
    ) -> std::io::Result<()> {
        let temp = dir.join(format!(".{name}.tmp-{}", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        drop(file);
        hold();
        fs::hard_link(&temp, dir.join(name))?;
        fs::remove_file(&temp)?;
        File::open(dir)?.sync_all()
    }

    /// The ready line of this server process: pid, listening address, run id.
    fn j16_ready_line(addr: std::net::SocketAddr) -> String {
        let run = std::env::var("MKG_J15_RUN_ID").unwrap_or_else(|_| "none".into());
        format!("{} {addr} run={run}\n", std::process::id())
    }

    /// Publish `ready`. With `MKG_J16_READY_HOLD`, the complete temporary file
    /// is written first, `ready-held` is published, and the link to `ready`
    /// waits until the test creates `ready-release`.
    fn j16_publish_ready(ctl: &Path, addr: std::net::SocketAddr) -> std::io::Result<()> {
        let line = j16_ready_line(addr);
        if std::env::var("MKG_J16_READY_HOLD").is_ok() {
            let mut held = Ok(());
            j16_publish_held(ctl, "ready", &line, || {
                held = j16_publish(ctl, "ready-held", "held\n");
                while held.is_ok() && !ctl.join("ready-release").exists() {
                    thread::sleep(Duration::from_millis(10));
                }
            })?;
            held
        } else {
            j16_publish(ctl, "ready", &line)
        }
    }

    /// Remove every control file an earlier run may have left, including
    /// the pause handshake and unpublished temporaries (J16-IA-06).
    fn j16_clear_ready(ctl: &Path) {
        const NAMES: [&str; 6] = [
            "ready",
            "refused",
            "ready-held",
            "ready-release",
            "arrived",
            "release",
        ];
        for entry in fs::read_dir(ctl).unwrap() {
            let name = entry.unwrap().file_name();
            let name = name.to_string_lossy();
            let temporary = NAMES
                .iter()
                .any(|known| name.starts_with(&format!(".{known}.tmp-")));
            if NAMES.contains(&name.as_ref()) || temporary {
                match fs::remove_file(ctl.join(name.as_ref())) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => panic!("cannot clear {name}: {error}"),
                }
            }
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    enum J16Ready {
        Absent,
        /// Complete, but of another process or run.
        Stale,
        Ready(std::net::SocketAddr),
    }

    /// Read `ready` for the server with `pid` and `run`. A partial or
    /// malformed file fails the test: with atomic publication it cannot be
    /// observed.
    fn j16_read_ready(ctl: &Path, pid: u32, run: &str) -> J16Ready {
        let text = match fs::read_to_string(ctl.join("ready")) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return J16Ready::Absent,
            Err(error) => panic!("ready unreadable: {error}"),
        };
        let line = text
            .strip_suffix('\n')
            .unwrap_or_else(|| panic!("partial ready: {text:?}"));
        let fields: Vec<&str> = line.split(' ').collect();
        let [ready_pid, addr, ready_run] = fields[..] else {
            panic!("malformed ready: {text:?}");
        };
        let addr: std::net::SocketAddr = addr.parse().expect("ready address");
        let ready_pid: u32 = ready_pid.parse().expect("ready pid");
        if ready_pid != pid || ready_run != format!("run={run}") {
            return J16Ready::Stale;
        }
        J16Ready::Ready(addr)
    }

    /// A transport that delivers the request but loses the next reply: an
    /// unknown outcome after the server committed.
    struct J16LoseReply {
        inner: Arc<TlsTransport>,
        lose_next: Mutex<bool>,
    }

    impl CasTransport for J16LoseReply {
        fn exchange(&self, request: &[u8]) -> Result<Vec<u8>, TransportError> {
            let reply = self.inner.exchange(request);
            let mut lose = self.lose_next.lock().unwrap();
            if *lose {
                *lose = false;
                return Err(TransportError::Unknown);
            }
            reply
        }
    }

    impl J13 {
        fn advances(&self) -> usize {
            self.authorized(CasOp::Advance)
        }

        /// A journal store in its own anchor directory whose external anchor
        /// has no sessions (the test `FileAnchor`).
        fn journal_store_without_sessions(&self) -> JournalStore {
            let dir = self.base.join("anchor-plain");
            fs::create_dir(&dir).unwrap();
            set_mode(&dir, 0o700);
            let file: Arc<dyn MonotonicAnchor> = Arc::new(FileAnchor::new(
                &self.base.join("plain-anchor.json"),
                j11_identity(),
            ));
            JournalStore::for_test_with_anchor(&dir, file).unwrap()
        }

        fn sessions(&self) -> usize {
            self.authorized(CasOp::Session)
        }
    }

    /// The next state for an advance of `state`.
    fn j16_digest(n: u8) -> String {
        format!("{:x}", Sha256::digest([b'j', b'1', b'6', n]))
    }

    #[test]
    fn j16_t01_t02_close_ends_the_session_and_nothing_is_sent_after_it() {
        let _guard = test_guard();
        let f = J13::new();
        let c = f.writer();
        let store = f.journal_store(&c);
        let mut j = store.initialize(record()).unwrap();
        j.advance(&record().attempt, State::MayHaveBeenSent, None)
            .unwrap();
        let fence = c.current_fence().unwrap();
        let state = c.read().unwrap();
        assert_eq!((state.revision, f.disk(&j11_identity()).fence), (2, fence));
        // While the journal is open, its session is its own: a direct advance
        // through the same client sends nothing, and the journal goes on.
        let before = f.advances();
        assert_eq!(c.advance(&state, &j16_digest(1)), Err(AnchorError::Fenced));
        assert_eq!(f.advances(), before);
        assert!(!c.holds_unowned_session());
        // Nor can another caller take the session over: a begin through the
        // same client is refused with nothing sent (J16-IA-01).
        let sessions = f.sessions();
        assert_eq!(c.begin_session(), Err(AnchorError::Busy));
        assert_eq!(c.begin_owned_session().unwrap_err(), AnchorError::Busy);
        assert_eq!(f.sessions(), sessions);
        assert_eq!(c.current_fence(), Some(fence));
        j.advance(
            &record().attempt,
            State::OperationKnown,
            Some(("operation-synthetic".into(), "op-1".into())),
        )
        .unwrap();
        // T01: a normal close ends the session; the record is unchanged.
        assert_eq!(j.close(), SessionClose::Ended);
        assert_eq!(c.current_fence(), None);
        let state = c.read().unwrap();
        assert_eq!(state.revision, 3);
        // T02: nothing can be sent under the closed session.
        let before = f.advances();
        assert_eq!(c.advance(&state, &j16_digest(2)), Err(AnchorError::Fenced));
        assert_eq!(f.advances(), before);
        assert_eq!(f.disk(&j11_identity()).state, state);
        assert_eq!(f.disk(&j11_identity()).fence, fence);
        // Dropping instead of closing ends it the same way.
        let mut j = store.open().unwrap();
        assert_eq!(j.record().revision, 3);
        j.advance(&record().attempt, State::DoneObserved, None)
            .unwrap();
        assert!(c.current_fence().is_some());
        drop(j);
        assert_eq!(c.current_fence(), None);
        let state = c.read().unwrap();
        let before = f.advances();
        assert_eq!(c.advance(&state, &j16_digest(3)), Err(AnchorError::Fenced));
        assert_eq!(f.advances(), before);
        assert_eq!(f.disk(&j11_identity()).state, state);
        // The record is intact: a new journal opens it.
        assert_eq!(store.open().unwrap().close(), SessionClose::Ended);
        f.cleanup();
    }

    #[test]
    fn j16_t03_ending_a_session_twice_and_closing_a_failed_journal() {
        let _guard = test_guard();
        let f = J13::new();
        let c = f.writer();
        // J17: ending consumes the lease, so it cannot be ended twice; a
        // dropped lease ends its session too.
        let FencedSession { lease, .. } = c.begin_owned_session().unwrap();
        assert!(c.end_owned_session(lease));
        assert_eq!(c.current_fence(), None);
        let FencedSession { lease, .. } = c.begin_owned_session().unwrap();
        drop(lease);
        assert_eq!(c.current_fence(), None);
        // A lease of another client never matches this client's session, and
        // ends nothing here (handing it over ends its own session, on its own
        // client, when it is dropped).
        let other = f.writer();
        let FencedSession { lease: foreign, .. } = other.begin_owned_session().unwrap();
        let FencedSession { lease: mine, .. } = c.begin_owned_session().unwrap();
        let state = c.read().unwrap();
        assert_eq!(
            c.advance_owned(&foreign, &state, &j16_digest(1)),
            Err(AnchorError::Fenced)
        );
        assert!(!c.end_owned_session(foreign));
        assert!(c.current_fence().is_some());
        assert_eq!(other.current_fence(), None);
        assert!(c.end_owned_session(mine));
        // close after a failure: the session already ended, nothing is held.
        let store = f.journal_store(&c);
        let mut j = store.initialize(record()).unwrap();
        let rival = f.writer();
        rival.begin_session().unwrap();
        let before = f.advances();
        assert!(
            j.advance(&record().attempt, State::MayHaveBeenSent, None)
                .is_err()
        );
        assert_eq!(f.advances(), before + 1);
        assert_eq!(c.current_fence(), None);
        assert!(
            j.advance(&record().attempt, State::MayHaveBeenSent, None)
                .is_err()
        );
        assert_eq!(f.advances(), before + 1);
        assert_eq!(j.close(), SessionClose::NotHeld);
        // Another caller of the same client cannot end a journal's session
        // (J17): `end_session` leaves it, and the journal still ends it.
        let c2 = f.writer();
        let store2 = f.journal_store(&c2);
        // (the rival advanced nothing; the record still matches the CAS)
        let j = store2.open().unwrap();
        assert_eq!(c2.begin_session(), Err(AnchorError::Busy));
        c2.end_session();
        assert!(c2.current_fence().is_some());
        assert_eq!(c2.begin_session(), Err(AnchorError::Busy));
        assert_eq!(j.close(), SessionClose::Ended);
        assert_eq!(c2.current_fence(), None);
        // An anchor without sessions owns nothing: its leases were never held.
        let plain = f.journal_store_without_sessions();
        let j = plain.initialize(record()).unwrap();
        assert_eq!(j.close(), SessionClose::NotHeld);
        f.cleanup();
    }

    #[test]
    fn j16_t04_close_racing_with_a_new_session_on_the_same_client() {
        let _guard = test_guard();
        let f = J13::new();
        let c = f.writer();
        let store = f.journal_store(&c);
        drop(store.initialize(record()).unwrap());
        // Both orders, forced: a begin before the close is refused and the
        // close still ends the journal's session; a begin after it succeeds.
        let j = store.open().unwrap();
        assert_eq!(c.begin_session(), Err(AnchorError::Busy));
        assert_eq!(j.close(), SessionClose::Ended);
        assert_eq!(c.current_fence(), None);
        c.begin_session().unwrap();
        assert!(c.holds_unowned_session());
        c.end_session();
        // Raced: whichever wins, the close ends the journal's own session,
        // and a session is held exactly when the begin won.
        let (mut refused, mut began) = (0, 0);
        for _ in 0..12 {
            let j = store.open().unwrap();
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let (b, c2) = (Arc::clone(&barrier), Arc::clone(&c));
            let begin = thread::spawn(move || {
                b.wait();
                c2.begin_session()
            });
            barrier.wait();
            assert_eq!(j.close(), SessionClose::Ended);
            match begin.join().unwrap() {
                Err(AnchorError::Busy) => {
                    refused += 1;
                    assert_eq!(c.current_fence(), None);
                }
                Ok(state) => {
                    began += 1;
                    assert!(c.holds_unowned_session());
                    assert_eq!(c.current_fence(), Some(f.disk(&j11_identity()).fence));
                    assert_eq!(state, f.disk(&j11_identity()).state);
                }
                other => panic!("unexpected {other:?}"),
            }
            c.end_session();
        }
        assert_eq!(refused + began, 12);
        eprintln!("j16_t04 raced: begin refused {refused}, begin won {began}");
        // Ending a session while its advance is in flight: the advance may
        // commit, but an unowned session is not reinstated afterwards. An owned
        // session cannot be ended by another caller at all (J17): it is still
        // held after the commit, and only its lease ends it.
        for owned in [false, true] {
            let state = c.read().unwrap();
            let lease = if owned {
                Some(c.begin_owned_session().unwrap().lease)
            } else {
                c.begin_session().unwrap();
                None
            };
            let (arrived_tx, arrived) = mpsc::channel();
            let (release, release_rx) = mpsc::channel();
            f.arm(
                CasStorePoint::BeforeCommit,
                "Advance",
                Action::Pause {
                    arrived: arrived_tx,
                    release: release_rx,
                },
            );
            let digest = j16_digest(if owned { 41 } else { 40 });
            let in_flight = {
                let (c, state, digest) = (Arc::clone(&c), state.clone(), digest.clone());
                thread::spawn(move || match lease {
                    Some(lease) => c
                        .advance_owned(&lease, &state, &digest)
                        .map(|s| (s, Some(lease))),
                    None => c.advance(&state, &digest).map(|s| (s, None)),
                })
            };
            arrived.recv().unwrap();
            c.end_session();
            release.send(()).unwrap();
            let (committed, lease) = in_flight.join().unwrap().unwrap();
            assert_eq!(committed.revision, state.revision + 1);
            assert_eq!(
                c.advance(&committed, &j16_digest(42)),
                Err(AnchorError::Fenced)
            );
            match lease {
                Some(lease) => {
                    assert!(c.current_fence().is_some());
                    assert!(c.end_owned_session(lease));
                }
                None => assert_eq!(c.current_fence(), None),
            }
            assert_eq!(c.current_fence(), None);
        }
        f.cleanup();
    }

    #[test]
    fn j16_t05_a_failed_journal_ends_only_its_own_session() {
        let _guard = test_guard();
        let f = J13::new();
        let c = f.writer();
        let store = f.journal_store(&c);
        let mut j = store.initialize(record()).unwrap();
        // Another caller of the same client can neither drop nor replace the
        // journal's session (J17; in J16 `end_session` could drop it). The
        // journal goes on.
        let fence = c.current_fence().unwrap();
        let sessions = f.sessions();
        c.end_session();
        assert_eq!(c.begin_session(), Err(AnchorError::Busy));
        assert_eq!(c.current_fence(), Some(fence));
        assert_eq!(f.sessions(), sessions);
        j.advance(&record().attempt, State::MayHaveBeenSent, None)
            .unwrap();
        assert_eq!(j.close(), SessionClose::Ended);
        assert_eq!(c.current_fence(), None);
        // A failure at the CAS: the session ends and nothing more is sent.
        let mut j = store.open().unwrap();
        f.writer().begin_session().unwrap();
        let before = f.advances();
        assert!(
            j.advance(
                &record().attempt,
                State::OperationKnown,
                Some(("operation-synthetic".into(), "op-1".into())),
            )
            .is_err()
        );
        assert_eq!(f.advances(), before + 1);
        assert_eq!(c.current_fence(), None);
        let state = c.read().unwrap();
        assert_eq!(c.advance(&state, &j16_digest(1)), Err(AnchorError::Fenced));
        assert_eq!(f.advances(), before + 1);
        drop(j);
        f.cleanup();
    }

    #[test]
    fn j16_t06_begin_session_with_an_unknown_outcome() {
        let _guard = test_guard();
        let f = J13::new();
        let ok = f.writer();
        drop(f.journal_store(&ok).initialize(record()).unwrap());
        let lossy = Arc::new(J16LoseReply {
            inner: f.transport_for(&f.pki.writer, Duration::from_secs(5)),
            lose_next: Mutex::new(true),
        });
        let c = Arc::new(NetworkCasAnchor::new(lossy.clone(), j11_identity()));
        // A client that held a session holds none after an unknown begin.
        *lossy.lose_next.lock().unwrap() = false;
        c.begin_session().unwrap();
        assert!(c.holds_unowned_session());
        *lossy.lose_next.lock().unwrap() = true;
        let fence_before = f.disk(&j11_identity()).fence;
        // The server committed the session; the client does not know that.
        assert_eq!(c.begin_owned_session().unwrap_err(), AnchorError::Unknown);
        assert_eq!(f.disk(&j11_identity()).fence, fence_before + 1);
        assert_eq!(c.current_fence(), None);
        let state = c.read().unwrap();
        let before = f.advances();
        assert_eq!(c.advance(&state, &j16_digest(1)), Err(AnchorError::Fenced));
        assert_eq!(f.advances(), before);
        // Opening a journal over an unknown BeginSession fails at stage 7 and
        // leaves no session behind.
        *lossy.lose_next.lock().unwrap() = true;
        let store = f.journal_store(&c);
        J9B_OPEN_STAGE.store(0, std::sync::atomic::Ordering::SeqCst);
        assert!(store.open().is_err());
        assert_eq!(J9B_OPEN_STAGE.load(std::sync::atomic::Ordering::SeqCst), 7);
        assert_eq!(c.current_fence(), None);
        assert_eq!(f.disk(&j11_identity()).fence, fence_before + 2);
        assert_eq!(f.advances(), before);
        // Recovery is a new session, never a resend of anything.
        let mut j = store.open().unwrap();
        assert_eq!(f.disk(&j11_identity()).fence, fence_before + 3);
        j.advance(&record().attempt, State::MayHaveBeenSent, None)
            .unwrap();
        assert_eq!(f.advances(), before + 1);
        assert_eq!(j.close(), SessionClose::Ended);
        f.cleanup();
    }

    #[test]
    fn j16_t07_one_client_used_by_many_threads() {
        let _guard = test_guard();
        let f = J13::new();
        let c = f.writer();
        let store = f.journal_store(&c);
        let mut j = store.initialize(record()).unwrap();
        let start = Arc::new(std::sync::Barrier::new(5));
        let stop = Arc::new(AtomicBool::new(false));
        let mut threads = Vec::new();
        for _ in 0..4 {
            let (c, start, stop) = (Arc::clone(&c), Arc::clone(&start), Arc::clone(&stop));
            threads.push(thread::spawn(move || {
                start.wait();
                let mut attempts = 0usize;
                while !stop.load(Ordering::SeqCst) {
                    let state = c.read().unwrap();
                    assert_eq!(c.advance(&state, &j16_digest(9)), Err(AnchorError::Fenced));
                    // Taking the session over is refused too (J16-IA-01).
                    assert_eq!(c.begin_session(), Err(AnchorError::Busy));
                    attempts += 1;
                }
                attempts
            }));
        }
        start.wait();
        let before = f.advances();
        let sessions = f.sessions();
        for (next, operation) in [
            (State::MayHaveBeenSent, None),
            (
                State::OperationKnown,
                Some(("operation-synthetic".to_string(), "op-1".to_string())),
            ),
            (State::DoneObserved, None),
        ] {
            j.advance(&record().attempt, next, operation).unwrap();
        }
        stop.store(true, Ordering::SeqCst);
        let attempts: usize = threads.into_iter().map(|t| t.join().unwrap()).sum();
        assert!(attempts > 0);
        // Only the journal's three advances reached the CAS, and no session
        // but the journal's.
        assert_eq!(f.advances(), before + 3);
        assert_eq!(f.sessions(), sessions);
        assert_eq!(f.disk(&j11_identity()).state.revision, 4);
        assert_eq!(j.close(), SessionClose::Ended);
        f.cleanup();
    }

    #[test]
    fn j16_t08_another_client_moves_the_fence() {
        let _guard = test_guard();
        let f = J13::new();
        let c1 = f.writer();
        let store = f.journal_store(&c1);
        let mut j = store.initialize(record()).unwrap();
        let c2 = f.writer();
        c2.begin_session().unwrap();
        let newer = c2.current_fence().unwrap();
        let disk = f.disk(&j11_identity());
        let before = f.advances();
        assert!(
            j.advance(&record().attempt, State::MayHaveBeenSent, None)
                .is_err()
        );
        // The CAS refused it (one Advance reached the server), nothing changed.
        assert_eq!(f.advances(), before + 1);
        assert_eq!(f.disk(&j11_identity()), disk);
        assert_eq!(disk.fence, newer);
        assert_eq!(c1.current_fence(), None);
        // The failed journal sends nothing more, and c2's session is intact.
        assert!(
            j.advance(&record().attempt, State::MayHaveBeenSent, None)
                .is_err()
        );
        assert_eq!(f.advances(), before + 1);
        assert_eq!(j.close(), SessionClose::NotHeld);
        assert_eq!(c2.current_fence(), Some(newer));
        let state = c2.read().unwrap();
        assert!(c2.advance(&state, &j16_digest(1)).is_ok());
        f.cleanup();
    }

    /// An inquirer that does something with the assessed client while the
    /// assessment's session is open.
    struct J16Interfere {
        client: Arc<NetworkCasAnchor>,
        /// Drop the assessment's session and begin one of its own.
        replace: bool,
        /// What a direct advance and a direct begin returned.
        direct: Mutex<Option<[Result<AnchorState, AnchorError>; 2]>>,
    }

    impl CasInquiry for J16Interfere {
        fn inquire_request(&self, request_id: &str) -> Result<InquiryOutcome, AnchorError> {
            if self.replace {
                // J17: `end_session` leaves the assessment's owned session,
                // so the begin that follows is refused.
                self.client.end_session();
                let state = self.client.read().unwrap();
                *self.direct.lock().unwrap() = Some([
                    self.client.advance(&state, &j16_digest(6)),
                    self.client.begin_session(),
                ]);
            } else {
                let state = self.client.read().unwrap();
                *self.direct.lock().unwrap() = Some([
                    self.client.advance(&state, &j16_digest(5)),
                    self.client.begin_session(),
                ]);
            }
            self.client.inquire(request_id)
        }
    }

    #[test]
    fn j16_t09_assessment_and_a_concurrent_caller_of_the_same_client() {
        let _guard = test_guard();
        let t = J14::new();
        let c = t.f.writer();
        let fingerprint = t.journal_fingerprint();
        // A direct advance during the assessment sends nothing; the
        // assessment still holds its session and decides.
        let quiet = J16Interfere {
            client: Arc::clone(&c),
            replace: false,
            direct: Mutex::new(None),
        };
        let before = t.f.advances();
        let sessions = t.f.sessions();
        let report = t.assess_with(
            &c,
            &RecoveryContext {
                previous_fence: None,
                known_request: Some((&rid(77), &quiet)),
            },
        );
        assert_eq!(
            quiet.direct.lock().unwrap().clone(),
            Some([Err(AnchorError::Fenced), Err(AnchorError::Busy)])
        );
        assert_eq!(t.f.advances(), before);
        // Only the assessment's own session reached the CAS.
        assert_eq!(t.f.sessions(), sessions + 1);
        assert_eq!(report.decision.class, RecoveryClass::Consistent);
        // Another caller dropping the session and beginning its own during
        // the assessment makes its observation stale: nothing is concluded.
        let replacing = J16Interfere {
            client: Arc::clone(&c),
            replace: true,
            direct: Mutex::new(None),
        };
        let report = t.assess_with(
            &c,
            &RecoveryContext {
                previous_fence: None,
                known_request: Some((&rid(78), &replacing)),
            },
        );
        // J17: the other caller could neither drop nor replace the session
        // (in J16 it could, and the observation became Unknown).
        assert_eq!(
            replacing.direct.lock().unwrap().clone(),
            Some([Err(AnchorError::Fenced), Err(AnchorError::Busy)])
        );
        assert_eq!(report.decision.class, RecoveryClass::Consistent);
        assert!(!report.decision.send_authorized());
        // Nothing of the assessment is left on the client.
        assert_eq!(c.current_fence(), None);
        assert_eq!(t.f.advances(), before);
        assert_eq!(t.journal_fingerprint(), fingerprint);
        t.f.cleanup();
    }

    #[test]
    fn j16_t10_a_delayed_advance_is_answered_fenced() {
        let _guard = test_guard();
        let f = J13::new();
        let a = f.writer();
        let state = a.begin_session().map(|_| a.read().unwrap()).unwrap();
        let stale_fence = a.current_fence().unwrap();
        a.end_session();
        let (arrived_tx, arrived) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        f.arm(
            CasStorePoint::BeforeLock,
            "Advance",
            Action::Pause {
                arrived: arrived_tx,
                release: release_rx,
            },
        );
        let request = CasV2Request::Advance {
            v: CAS_PROTOCOL_VERSION,
            request_id: rid(161),
            identity: j11_identity(),
            fence: stale_fence,
            expected: state.clone(),
            next_revision: 1,
            next_digest: j16_digest(1),
        };
        let pki_transport = f.transport_for(&f.pki.writer, Duration::from_secs(10));
        let bytes = serde_json::to_vec(&request).unwrap();
        let delayed = thread::spawn(move || pki_transport.exchange(&bytes));
        arrived.recv().unwrap();
        // While the advance waits in the server, a newer session commits.
        let b = f.writer();
        b.begin_session().unwrap();
        let newer = b.current_fence().unwrap();
        assert!(newer > stale_fence);
        release.send(()).unwrap();
        let reply: CasV2Response =
            serde_json::from_slice(&delayed.join().unwrap().unwrap()).unwrap();
        // The response kind, recorded directly.
        assert_eq!(
            reply,
            CasV2Response::Fenced {
                v: CAS_PROTOCOL_VERSION,
                request_id: rid(161),
                current_fence: newer,
            }
        );
        let disk = f.disk(&j11_identity());
        assert_eq!((disk.state, disk.fence), (state, newer));
        // One Advance reached the server and nothing resent it.
        assert_eq!(f.advances(), 1);
        assert_eq!(a.current_fence(), None);
        f.cleanup();
    }

    #[test]
    fn j16_t11_two_clients_wait_for_the_identity_lock_in_order() {
        let _guard = test_guard();
        let f = J13::new();
        let c1 = f.writer();
        let genesis_state = c1.begin_session().unwrap();
        let (arrived_tx, arrived) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let (contended_tx, contended) = mpsc::channel();
        let (committed_tx, committed) = mpsc::channel();
        // Client 1's advance holds the identity lock at BeforeCommit.
        f.arm(
            CasStorePoint::BeforeCommit,
            "Advance",
            Action::Pause {
                arrived: arrived_tx,
                release: release_rx,
            },
        );
        f.arm(
            CasStorePoint::Contended,
            "BeginSession",
            Action::Notify(contended_tx),
        );
        f.arm(
            CasStorePoint::Committed,
            "Advance",
            Action::Notify(committed_tx),
        );
        let mut log = Vec::new();
        let first = {
            let c1 = Arc::clone(&c1);
            let state = genesis_state.clone();
            thread::spawn(move || c1.advance(&state, &j16_digest(1)))
        };
        arrived.recv().unwrap();
        log.push("c1-advance-holds-lock");
        let c2 = f.writer();
        let second = {
            let c2 = Arc::clone(&c2);
            thread::spawn(move || c2.begin_session())
        };
        // Direct observation: client 2 found the lock held and waits.
        contended.recv().unwrap();
        log.push("c2-session-waits-on-lock");
        assert!(!second.is_finished());
        release.send(()).unwrap();
        committed.recv().unwrap();
        log.push("c1-advance-committed");
        let advanced = first.join().unwrap().unwrap();
        let session = second.join().unwrap().unwrap();
        log.push("c2-session-committed");
        // Client 2's session saw client 1's commit: serialized after it.
        assert_eq!(advanced.revision, 1);
        assert_eq!(session, advanced);
        let disk = f.disk(&j11_identity());
        assert_eq!(disk.state, advanced);
        assert_eq!(disk.fence, c2.current_fence().unwrap());
        assert_eq!(
            log,
            [
                "c1-advance-holds-lock",
                "c2-session-waits-on-lock",
                "c1-advance-committed",
                "c2-session-committed"
            ]
        );
        // Client 1's session is now stale at the CAS.
        assert_eq!(
            c1.advance(&advanced, &j16_digest(2)),
            Err(AnchorError::Fenced)
        );
        assert_eq!(f.disk(&j11_identity()), disk);
        f.cleanup();
    }

    /// A child server that is killed when the test ends, also on a failed
    /// assertion, so that no server outlives its test.
    struct J16Child(Child);

    impl J16Child {
        fn id(&self) -> u32 {
            self.0.id()
        }

        /// Wait for the exit, bounded; a child still running is killed and
        /// the test fails.
        fn wait_exit(&mut self, what: &str) -> std::process::ExitStatus {
            for _ in 0..1500 {
                if let Some(status) = self.0.try_wait().unwrap() {
                    return status;
                }
                thread::sleep(Duration::from_millis(10));
            }
            let _ = self.0.kill();
            let _ = self.0.wait();
            panic!("{what}: still running");
        }
    }

    impl Drop for J16Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn j16_spawn_server(base: &Path, ctl: &Path, run: &str, hold: bool) -> J16Child {
        let s = |p: &Path| p.to_string_lossy().into_owned();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", J15_ROLE, "--nocapture"])
            .env("MKG_J15_ROLE", "server")
            .env("MKG_J15_PKI", s(&base.join("pki")))
            .env("MKG_J15_CTL", s(ctl))
            .env("MKG_J15_STORE", s(&base.join("store")))
            .env("MKG_J15_BIND", "127.0.0.1:0")
            .env("MKG_J15_RUN_ID", run)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if hold {
            command.env("MKG_J16_READY_HOLD", "1");
        }
        J16Child(command.spawn().unwrap())
    }

    fn j16_role_run(envs: &[(&str, String)]) {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", J15_ROLE, "--nocapture"])
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (key, value) in envs {
            command.env(key, value);
        }
        assert!(command.status().unwrap().success(), "{envs:?}");
    }

    /// Wait for a condition on the file system, bounded; not a timing race:
    /// the test proceeds on the condition, never on the elapsed time.
    fn j16_wait_for(what: &str, mut condition: impl FnMut() -> bool) {
        for _ in 0..1500 {
            if condition() {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("timed out waiting for {what}");
    }

    fn j16_server_base() -> PathBuf {
        let base = unique_base("j16");
        let s = |p: &Path| p.to_string_lossy().into_owned();
        j16_role_run(&[
            ("MKG_J15_ROLE", "pki".into()),
            ("MKG_J15_OUT", s(&base.join("pki"))),
        ]);
        j16_role_run(&[
            ("MKG_J15_ROLE", "store-init".into()),
            ("MKG_J15_STORE", s(&base.join("store"))),
        ]);
        base
    }

    fn j16_client_read(
        base: &Path,
        addr: std::net::SocketAddr,
    ) -> Result<AnchorState, AnchorError> {
        let pki = base.join("pki");
        let config = cas_client_tls_config(
            cas_load_roots(&pki.join("ca.pem")).unwrap(),
            cas_load_crls(&pki.join("crl.pem")).unwrap(),
            CasTlsIdentity::load(&pki.join("writer.crt"), &pki.join("writer.key")).unwrap(),
        )
        .unwrap();
        let transport = TlsTransport::new(
            addr,
            SERVER_DNS,
            config,
            Duration::from_secs(3),
            Duration::from_secs(5),
        )
        .unwrap();
        NetworkCasAnchor::new(Arc::new(transport), j11_identity()).read()
    }

    #[test]
    fn j16_t12_ready_is_published_atomically_after_the_listener_exists() {
        let _guard = test_guard();
        let base = j16_server_base();
        let ctl = base.join("ctl");
        fs::create_dir(&ctl).unwrap();
        let server = j16_spawn_server(&base, &ctl, "r1", true);
        let pid = server.id();
        j16_wait_for("ready-held", || ctl.join("ready-held").exists());
        // Held between the complete temporary file and its publication: the
        // name `ready` does not exist yet, the content is already complete.
        assert_eq!(j16_read_ready(&ctl, pid, "r1"), J16Ready::Absent);
        let temp = fs::read_to_string(ctl.join(format!(".ready.tmp-{pid}"))).unwrap();
        let addr: std::net::SocketAddr = temp.split(' ').nth(1).unwrap().parse().unwrap();
        // The listener exists before `ready` is published.
        std::net::TcpStream::connect(addr).unwrap();
        fs::write(ctl.join("ready-release"), b"go").unwrap();
        j16_wait_for("ready", || ctl.join("ready").exists());
        assert_eq!(j16_read_ready(&ctl, pid, "r1"), J16Ready::Ready(addr));
        assert!(!ctl.join(format!(".ready.tmp-{pid}")).exists());
        assert_eq!(j16_client_read(&base, addr).unwrap(), genesis());
        drop(server);
        // A start that fails leaves no `ready`, also not an earlier one.
        let failed_ctl = base.join("ctl-failed");
        fs::create_dir(&failed_ctl).unwrap();
        fs::write(failed_ctl.join("ready"), format!("{pid} {addr} run=r1\n")).unwrap();
        set_mode(&base.join("pki"), 0o770);
        let mut failing = j16_spawn_server(&base, &failed_ctl, "r2", false);
        let status = failing.wait_exit("a server whose start must be refused");
        assert_eq!(status.code(), Some(4));
        assert!(!failed_ctl.join("ready").exists());
        assert_eq!(
            fs::read_to_string(failed_ctl.join("refused")).unwrap(),
            "server Tls(Directory)"
        );
        set_mode(&base.join("pki"), 0o700);
        base_cleanup(&base);
    }

    #[test]
    fn j16_t13_a_stale_ready_is_never_taken_for_this_run() {
        let _guard = test_guard();
        let base = j16_server_base();
        let ctl = base.join("ctl");
        fs::create_dir(&ctl).unwrap();
        // Left by an earlier run: another pid and run id, a pause handshake
        // that would release the next pause at once, and an unpublished
        // temporary (J16-IA-06).
        fs::write(ctl.join("ready"), "4194303 127.0.0.1:9 run=r0\n").unwrap();
        for stale in [
            "release",
            "arrived",
            ".ready.tmp-4194303",
            ".refused.tmp-4194303",
        ] {
            fs::write(ctl.join(stale), b"stale").unwrap();
        }
        let server = j16_spawn_server(&base, &ctl, "r3", true);
        let pid = server.id();
        assert_ne!(
            j16_read_ready(&ctl, pid, "r3"),
            J16Ready::Ready("127.0.0.1:9".parse().unwrap())
        );
        assert!(matches!(
            j16_read_ready(&ctl, pid, "r3"),
            J16Ready::Stale | J16Ready::Absent
        ));
        j16_wait_for("ready-held", || ctl.join("ready-held").exists());
        // The server removed the stale files before publishing anything.
        assert_eq!(j16_read_ready(&ctl, pid, "r3"), J16Ready::Absent);
        for stale in [
            "release",
            "arrived",
            ".ready.tmp-4194303",
            ".refused.tmp-4194303",
        ] {
            assert!(!ctl.join(stale).exists(), "{stale}");
        }
        fs::write(ctl.join("ready-release"), b"go").unwrap();
        j16_wait_for("ready", || ctl.join("ready").exists());
        let J16Ready::Ready(addr) = j16_read_ready(&ctl, pid, "r3") else {
            panic!("ready not for this run");
        };
        // The same file is stale for any other run id or pid.
        assert_eq!(j16_read_ready(&ctl, pid, "r4"), J16Ready::Stale);
        assert_eq!(j16_read_ready(&ctl, pid + 1, "r3"), J16Ready::Stale);
        assert_eq!(j16_client_read(&base, addr).unwrap(), genesis());
        drop(server);
        base_cleanup(&base);
    }

    /// Complete a raw TLS handshake with `leaf`, send one Read, and return the
    /// TLS alert the server sent, if any (None: a CAS reply arrived).
    fn j16_alert_for(f: &J13, leaf: &Leaf) -> Option<rustls::AlertDescription> {
        let mut tcp = std::net::TcpStream::connect(f.addr).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut conn = rustls::ClientConnection::new(
            f.pki.client_config(leaf),
            rustls::pki_types::ServerName::try_from(SERVER_DNS).unwrap(),
        )
        .unwrap();
        let alert = |error: std::io::Error| -> Option<rustls::AlertDescription> {
            match error
                .get_ref()
                .and_then(|e| e.downcast_ref::<rustls::Error>())
            {
                Some(rustls::Error::AlertReceived(alert)) => Some(*alert),
                other => panic!("not an alert: {other:?} ({error})"),
            }
        };
        while conn.is_handshaking() {
            if let Err(error) = conn.complete_io(&mut tcp) {
                return alert(error);
            }
        }
        let read = serde_json::to_vec(&CasV2Request::Read {
            v: CAS_PROTOCOL_VERSION,
            request_id: rid(162),
            identity: j11_identity(),
        })
        .unwrap();
        let mut stream = rustls::Stream::new(&mut conn, &mut tcp);
        if let Err(error) = write_frame(&mut stream, &read) {
            return alert(error);
        }
        match read_frame(&mut stream) {
            Ok(reply) => {
                let reply: CasV2Response = serde_json::from_slice(&reply).unwrap();
                assert!(matches!(reply, CasV2Response::State { .. }), "{reply:?}");
                None
            }
            Err(error) => alert(error),
        }
    }

    #[test]
    fn j16_t14_t15_revocation_with_a_control_and_classified_reasons() {
        let _guard = test_guard();
        let mut f = J13::provisioned();
        let revoked = f.pki.ca.client(WRITER);
        let expired = f.pki.ca.client_with_uris(&[WRITER], true);
        let rogue_ca = Ca::new("synthetic-j16-rogue-ca");
        let rogue = rogue_ca.client(WRITER);
        f.pki.paths.crls = f.pki.files.write(&f.pki.ca.crl(&[revoked.serial]), 0o644);
        f.start();
        let (reached_tx, reached) = mpsc::channel();
        f.arm(CasStorePoint::BeforeLock, "*", Action::Notify(reached_tx));
        let disk = f.disk(&j11_identity());
        let handshakes = |f: &J13| {
            f.events()
                .iter()
                .filter(|e| **e == CasEvent::Connection(CasServeOutcome::HandshakeFailed))
                .count()
        };
        // T15: each refused certificate, with the reason the server gave.
        for (leaf, reason) in [
            (&revoked, rustls::AlertDescription::CertificateRevoked),
            (&expired, rustls::AlertDescription::CertificateExpired),
            (&rogue, rustls::AlertDescription::UnknownCA),
        ] {
            let failed = handshakes(&f);
            assert_eq!(j16_alert_for(&f, leaf), Some(reason));
            f.wait_event("handshake failed", |_| handshakes(&f) > failed);
        }
        // Through the client: the outcome is Unknown (TLS 1.3 reports the
        // refusal after the request may have been written), nothing reached
        // the store, nothing was authorized, the disk is unchanged.
        let c = f.anchor_for(&revoked, j11_identity());
        assert_eq!(c.begin_session(), Err(AnchorError::Unknown));
        assert_eq!(reached.try_recv(), Err(mpsc::TryRecvError::Empty));
        assert_eq!(
            f.events()
                .iter()
                .filter(|e| matches!(e, CasEvent::Authorized { .. }))
                .count(),
            0
        );
        assert_eq!(f.disk(&j11_identity()), disk);
        // T14: the control. A certificate of the same CA, same principal, not
        // revoked, is accepted under the same CRL and reaches the store.
        assert_eq!(j16_alert_for(&f, &f.pki.writer), None);
        reached.recv().unwrap();
        assert_eq!(f.authorized(CasOp::Read), 1);
        assert_eq!(f.writer().read().unwrap(), genesis());
        f.cleanup();
    }

    /// TLS and ACL files in their own directories, under `parent`.
    fn j16_files(f: &J13, parent: &Path) -> CasServerFiles {
        let tls = parent.join("tls");
        let acl = parent.join("acl");
        for dir in [&tls, &acl] {
            fs::create_dir_all(dir).unwrap();
            set_mode(dir, 0o700);
        }
        let copy = |from: &Path, dir: &Path, name: &str, mode: u32| {
            let to = dir.join(name);
            fs::copy(from, &to).unwrap();
            set_mode(&to, mode);
            to
        };
        CasServerFiles {
            certificate: copy(&f.pki.paths.certificate, &tls, "server.crt", 0o644),
            key: copy(&f.pki.paths.key, &tls, "server.key", 0o600),
            client_roots: copy(&f.pki.paths.client_roots, &tls, "ca.pem", 0o644),
            crls: copy(&f.pki.paths.crls, &tls, "crl.pem", 0o644),
            acl: copy(&f.pki.paths.acl, &acl, "acl.toml", 0o644),
        }
    }

    impl J13 {
        /// Start with `files`; on success, stop again. Nothing listens if the
        /// start is refused (`start` precedes `bind`).
        fn start_with(&mut self, files: &CasServerFiles) -> Result<(), J13Start> {
            let saved = std::mem::replace(&mut self.pki.paths, files.clone());
            let result = self.try_start(j13_limits());
            self.pki.paths = saved;
            if result.is_ok() {
                assert!(std::net::TcpStream::connect(self.addr).is_ok());
                self.stop();
            }
            result
        }
    }

    #[test]
    fn j16_t16_t17_directories_above_tls_and_acl_files() {
        let _guard = test_guard();
        let mut f = J13::provisioned();
        let parent = f.base.join("conf");
        fs::create_dir(&parent).unwrap();
        set_mode(&parent, 0o700);
        let files = j16_files(&f, &parent);
        // The control: the same files in protected directories start.
        assert_eq!(f.start_with(&files), Ok(()));
        let refused_tls = Err(J13Start::Server(CasStartError::Tls(CasTlsError::Directory)));
        // T16: the directory holding the TLS files, then one further up.
        for (dir, mode) in [
            (parent.join("tls"), 0o770),
            (parent.join("tls"), 0o702),
            (parent.join("tls"), 0o720),
            (parent.clone(), 0o770),
            (parent.clone(), 0o707),
        ] {
            set_mode(&dir, mode);
            assert_eq!(f.start_with(&files), refused_tls, "{dir:?} {mode:o}");
            set_mode(&dir, 0o700);
        }
        // A sticky world-writable directory is refused too (only a root-owned
        // one is accepted, and only by test builds).
        set_mode(&parent.join("tls"), 0o1777);
        assert_eq!(f.start_with(&files), refused_tls);
        set_mode(&parent.join("tls"), 0o700);
        // T17: the directory holding the ACL file.
        for (dir, mode) in [
            (parent.join("acl"), 0o770),
            (parent.join("acl"), 0o703),
            (parent.join("acl"), 0o1777),
        ] {
            set_mode(&dir, mode);
            assert_eq!(
                f.start_with(&files),
                Err(J13Start::Server(CasStartError::Acl)),
                "{dir:?} {mode:o}"
            );
            set_mode(&dir, 0o700);
        }
        // The rule itself, including owners this host cannot create: root
        // and this uid only, never another uid; never group or other
        // writable; a directory only.
        let me = uid();
        for (is_dir, owner, mode, ok) in [
            (true, me, 0o755, true),
            (true, 0, 0o755, true),
            (true, me, 0o700, true),
            (true, me + 1, 0o755, false),
            (true, me + 1, 0o700, false),
            (true, me, 0o775, false),
            (true, me, 0o757, false),
            (true, me, 0o1777, false),
            (true, 0, 0o1777, true), // test builds only (the Linux /tmp)
            (true, 0, 0o0777, false),
            (false, me, 0o700, false),
        ] {
            assert_eq!(
                protected_ancestor_ok(is_dir, owner, mode, me),
                ok,
                "{is_dir} {owner} {mode:o}"
            );
        }
        // Unchanged: the files themselves.
        set_mode(&files.key, 0o640);
        assert_eq!(
            f.start_with(&files),
            Err(J13Start::Server(CasStartError::Tls(CasTlsError::File)))
        );
        set_mode(&files.key, 0o600);
        assert_eq!(f.start_with(&files), Ok(()));
        f.cleanup();
    }

    #[test]
    fn j16_t18_symlinks_and_hardlinks_are_refused() {
        let _guard = test_guard();
        let mut f = J13::provisioned();
        let parent = f.base.join("conf");
        fs::create_dir(&parent).unwrap();
        set_mode(&parent, 0o700);
        let files = j16_files(&f, &parent);
        assert_eq!(f.start_with(&files), Ok(()));
        // A symlinked directory on the way (the configured path names it).
        let linked = f.base.join("conf-link");
        symlink(&parent, &linked).unwrap();
        let mut through_link = files.clone();
        through_link.certificate = linked.join("tls").join("server.crt");
        assert_eq!(
            f.start_with(&through_link),
            Err(J13Start::Server(CasStartError::Tls(CasTlsError::Directory)))
        );
        let mut acl_through_link = files.clone();
        acl_through_link.acl = linked.join("acl").join("acl.toml");
        assert_eq!(
            f.start_with(&acl_through_link),
            Err(J13Start::Server(CasStartError::Acl))
        );
        // A symlink as the file itself.
        let key_link = parent.join("tls").join("key-link");
        symlink(&files.key, &key_link).unwrap();
        let mut key_symlink = files.clone();
        key_symlink.key = key_link;
        assert_eq!(
            f.start_with(&key_symlink),
            Err(J13Start::Server(CasStartError::Tls(CasTlsError::File)))
        );
        let acl_link = parent.join("acl").join("acl-link");
        symlink(&files.acl, &acl_link).unwrap();
        let mut acl_symlink = files.clone();
        acl_symlink.acl = acl_link;
        assert_eq!(
            f.start_with(&acl_symlink),
            Err(J13Start::Server(CasStartError::Acl))
        );
        // A hardlink (nlink 2), for a TLS file and for the ACL.
        let extra = parent.join("tls").join("extra-link");
        fs::hard_link(&files.client_roots, &extra).unwrap();
        assert_eq!(
            f.start_with(&files),
            Err(J13Start::Server(CasStartError::Tls(CasTlsError::File)))
        );
        fs::remove_file(&extra).unwrap();
        let extra = parent.join("acl").join("extra-link");
        fs::hard_link(&files.acl, &extra).unwrap();
        assert_eq!(
            f.start_with(&files),
            Err(J13Start::Server(CasStartError::Acl))
        );
        fs::remove_file(&extra).unwrap();
        assert_eq!(f.start_with(&files), Ok(()));
        f.cleanup();
    }

    #[test]
    fn j16_t19_path_replacement_after_the_walk_is_not_followed() {
        let _guard = test_guard();
        let f = J13::provisioned();
        let parent = f.base.join("conf");
        fs::create_dir(&parent).unwrap();
        set_mode(&parent, 0o700);
        let files = j16_files(&f, &parent);
        // Paths that are not absolute and plain are refused.
        for bad in [
            PathBuf::from("relative/crl.pem"),
            parent.join("tls").join("..").join("tls").join("crl.pem"),
        ] {
            assert_eq!(
                cas_load_crls(&bad).unwrap_err(),
                CasTlsError::Directory,
                "{bad:?}"
            );
        }
        // After the walk verified the directory, it is renamed away and an
        // impostor directory takes its name, holding another CRL. The file is
        // opened through the verified descriptor: the original CRL is read.
        let tls = parent.join("tls");
        let original = cas_load_crls(&files.crls).unwrap();
        let impostor_crl = Ca::new("synthetic-j16-impostor").crl(&[]);
        let (tls_hook, parent_hook) = (tls.clone(), parent.clone());
        J16_AFTER_WALK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                fs::rename(&tls_hook, parent_hook.join("tls-verified")).unwrap();
                fs::create_dir(&tls_hook).unwrap();
                set_mode(&tls_hook, 0o700);
                fs::write(tls_hook.join("crl.pem"), &impostor_crl).unwrap();
                set_mode(&tls_hook.join("crl.pem"), 0o644);
            }));
        });
        let loaded = cas_load_crls(&files.crls);
        J16_AFTER_WALK.with(|hook| *hook.borrow_mut() = None);
        assert_eq!(loaded.unwrap(), original);
        // Without the hook, the path now names the impostor's CRL.
        assert_ne!(cas_load_crls(&files.crls).unwrap(), original);
        // A directory replaced by a symlink before the walk is refused.
        fs::remove_dir_all(&tls).unwrap();
        symlink(parent.join("tls-verified"), &tls).unwrap();
        assert_eq!(
            cas_load_crls(&files.crls).unwrap_err(),
            CasTlsError::Directory
        );
        // Structure: the file is opened through the parent's descriptor, not
        // by path, and the descriptor checked is the one read.
        let source = include_str!("gce_operation_journal.rs");
        let body = &source[source.find("fn read_protected_file(").unwrap()..];
        let body = &body[..body.find("\n}\n").unwrap()];
        assert!(body.contains("open_protected_parent(path, euid)?"));
        assert!(body.contains("open_at(&parent, name"));
        assert!(!body.contains(".open(path)"));
        f.cleanup();
    }

    #[test]
    fn j16_t20_t21_send_never_authorized_and_repairs_refused() {
        let _guard = test_guard();
        let t = J14::new();
        let c = t.f.writer();
        let store = t.store(&c);
        let mut j = store.open().unwrap();
        assert!(!j.send_authorized() && !j.record().send_authorized());
        j.advance(
            &record().attempt,
            State::OperationKnown,
            Some(("operation-synthetic".into(), "op-1".into())),
        )
        .unwrap();
        assert!(!j.send_authorized() && !j.record().send_authorized());
        assert_eq!(j.close(), SessionClose::Ended);
        let report = t.assess();
        assert_eq!(report.decision.class, RecoveryClass::Consistent);
        assert!(!report.decision.send_authorized());
        // T21: repairs stay refused and write nothing.
        let (fingerprint, cas) = (t.journal_fingerprint(), t.cas());
        assert_eq!(
            store.apply_recovery(&report),
            Err(RecoveryError::PendingOwnerApproval)
        );
        assert_eq!((t.journal_fingerprint(), t.cas()), (fingerprint, cas));
        // Structure: the J16 production changes start no thread, read no
        // environment, hold no switch, and ending a session sends nothing.
        let source = include_str!("gce_operation_journal.rs");
        let production = &source[..source.find("\nmod tests {").unwrap()];
        let section = |start: &str, end: &str| {
            let from = production.find(start).unwrap();
            &production[from..from + production[from..].find(end).unwrap()]
        };
        let drop_impl = section("impl Drop for Journal {", "\nimpl Journal {");
        let end_owned = section(
            "    pub fn end_owned_session(&self, lease: SessionLease) -> bool {",
            "\n    }\n",
        );
        // J17: the lease ends its session on drop, locally.
        let lease_drop = section("impl Drop for SessionLease {", "\n}\n");
        let end_lease = section(
            "    fn end_lease(&mut self, id: u64) -> bool {",
            "\n    }\n",
        );
        let end_own = section(
            "    fn end_own_session(&mut self) -> SessionClose {",
            "\n    }\n",
        );
        let walk = section("fn protected_ancestor_ok(", "\n/// Read a file through");
        for (name, block) in [
            ("drop", drop_impl),
            ("end_owned_session", end_owned),
            ("end_own_session", end_own),
            ("walk", walk),
            ("lease drop", lease_drop),
            ("end_lease", end_lease),
        ] {
            for forbidden in [
                "exchange(",
                "transport",
                "thread::spawn",
                "std::env",
                "MKG_",
                "AtomicBool",
                "sleep(",
                "unwrap()",
                "expect(",
            ] {
                assert!(!block.contains(forbidden), "{name} contains {forbidden}");
            }
        }
        assert!(drop_impl.contains("self.end_own_session();"));
        t.f.cleanup();
    }

    #[test]
    fn j16_t24_new_types_and_errors_carry_no_secret() {
        let _guard = test_guard();
        let f = J13::new();
        let key_body: String = f
            .pki
            .writer
            .key_pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        let c = f.writer();
        let session = c.begin_owned_session().unwrap();
        let texts = [
            format!("{session:?}"),
            format!("{:?}", session.lease),
            format!("{:?}", SessionClose::Ended),
            format!("{:?}", CasTlsError::Directory),
            format!("{:?}", CasStartError::Tls(CasTlsError::Directory)),
            format!("{:?}", f.events()),
        ];
        for text in &texts {
            for chunk in key_body.as_bytes().chunks(16) {
                assert!(
                    !text.contains(std::str::from_utf8(chunk).unwrap()),
                    "{text}"
                );
            }
            // No path either: the errors say which rule, not where.
            assert!(!text.contains(&*f.base.to_string_lossy()), "{text}");
        }
        assert!(c.end_owned_session(session.lease));
        f.cleanup();
    }

    // Phase 1-J17: legacy v1 isolation, session ownership, recovery
    // lifecycle. Deliverables: prototype/v0.7/phase1-journal/j17/.

    /// The source before `mod tests`: what a production build compiles.
    fn j17_production_source() -> &'static str {
        let source = include_str!("gce_operation_journal.rs");
        &source[..source.find("\nmod tests {").unwrap()]
    }

    /// Whether `line` of the production source is compiled in test builds
    /// only: `#[cfg(test)]` among the attribute lines directly above it, or
    /// above the top-level item that encloses it.
    fn j17_gated(lines: &[&str], line: usize) -> bool {
        let attributed = |at: usize| {
            lines[..at]
                .iter()
                .rev()
                .take_while(|l| {
                    let l = l.trim_start();
                    l.starts_with("#[") || l.starts_with("///") || l.starts_with("//")
                })
                .any(|l| l.trim_start() == "#[cfg(test)]")
        };
        let item = (0..=line).rev().find(|&i| {
            let l = lines[i];
            !l.is_empty()
                && !l.starts_with(' ')
                && !l.starts_with('}')
                && !l.starts_with('#')
                && !l.starts_with("//")
        });
        attributed(line) || item.is_some_and(attributed)
    }

    #[test]
    fn j17_t01_t02_unfenced_anchors_cannot_start_a_recovery() {
        let _guard = test_guard();
        // The v1 client: its begin is a plain read. It still runs a test-only
        // legacy journal (J5-J9), but never an assessment, and nothing is
        // sent for the refused assessment.
        let f = CasFixture::new();
        let store = f.store();
        let mut j = store.initialize(record()).unwrap();
        j.advance(&record().attempt, State::MayHaveBeenSent, None)
            .unwrap();
        drop(j);
        let state = fs::read(&f.state).unwrap();
        assert_eq!(
            store.assess_recovery(&RecoveryContext::default()),
            Err(RecoveryError::NoFencedAnchor)
        );
        assert_eq!(fs::read(&f.state).unwrap(), state);
        // Nor any other anchor without fenced, owned sessions.
        let dir = f.base.join("anchor-file");
        fs::create_dir(&dir).unwrap();
        set_mode(&dir, 0o700);
        let file: Arc<dyn MonotonicAnchor> = Arc::new(FileAnchor::new(
            &f.base.join("file-anchor.json"),
            j6_identity(),
        ));
        let file_store = JournalStore::for_test_with_anchor(&dir, file).unwrap();
        drop(file_store.initialize(record()).unwrap());
        assert_eq!(
            file_store.assess_recovery(&RecoveryContext::default()),
            Err(RecoveryError::NoFencedAnchor)
        );
        f.cleanup();
    }

    #[test]
    fn j17_t02_t03_production_has_no_unfenced_path() {
        let production = j17_production_source();
        let lines: Vec<&str> = production.lines().collect();
        // T03: the fenced trait has no default bodies: an implementation must
        // write every method, so a plain read cannot stand in for a begin.
        let start = lines
            .iter()
            .position(|l| l.starts_with("pub trait FencedAnchor"))
            .unwrap();
        let end = start + lines[start..].iter().position(|l| *l == "}").unwrap();
        let body = &lines[start + 1..end];
        let methods = body
            .iter()
            .filter(|l| l.trim_start().starts_with("fn "))
            .count();
        assert_eq!(methods, 5);
        assert!(
            body.iter().all(|l| !l.trim_end().ends_with('{')),
            "a default body in FencedAnchor"
        );
        // The production store with an external anchor requires the trait.
        assert!(production.contains(
            "pub fn system_with_anchor(external: Arc<dyn FencedAnchor>) -> Result<Self, ()> {"
        ));
        // T02: the v1 protocol, its client, and the legacy (unfenced) external
        // anchor exist in test builds only.
        for item in [
            "enum CasRequest {",
            "enum CasResponse {",
            "enum CasReject {",
            "fn constant_time_eq(",
            "pub struct CasAnchor {",
            "impl CasAnchor {",
            "impl MonotonicAnchor for CasAnchor {",
            "impl IntoExternal for Arc<CasAnchor> {",
            "trait IntoExternal {",
        ] {
            let at: Vec<usize> = lines
                .iter()
                .enumerate()
                .filter(|(_, l)| l.contains(item))
                .map(|(i, _)| i)
                .collect();
            assert!(!at.is_empty(), "{item}");
            for i in at {
                assert!(j17_gated(&lines, i), "{item} is reachable outside tests");
            }
        }
        for (i, line) in lines.iter().enumerate() {
            if line.contains("Legacy(") && !line.trim_start().starts_with("//") {
                assert!(
                    j17_gated(&lines, i),
                    "legacy external anchor outside tests at line {}",
                    i + 1
                );
            }
        }
        // The recovery assessment takes only a fenced anchor.
        let assess = &production[production.find("pub fn assess_recovery(").unwrap()..];
        let assess = &assess[..assess.find("\n    }\n").unwrap()];
        assert!(assess.contains("Some(ExternalAnchor::Fenced(anchor)) => anchor,"));
        assert!(assess.contains(
            "Some(ExternalAnchor::Legacy(_)) => return Err(RecoveryError::NoFencedAnchor),"
        ));
        // `end_session` on the v2 client ends unowned sessions only.
        let end = &production[production
            .find("    fn end_session(&self) {\n        self.slot().end_unowned();")
            .unwrap()..];
        assert!(
            end.starts_with(
                "    fn end_session(&self) {\n        self.slot().end_unowned();\n    }"
            )
        );
    }

    #[test]
    fn j17_t04_a_journal_session_cannot_be_ended_or_taken_by_another_caller() {
        let _guard = test_guard();
        let f = J13::new();
        let c = f.writer();
        let store = f.journal_store(&c);
        let mut j = store.initialize(record()).unwrap();
        let fence = c.current_fence().unwrap();
        let (sessions, advances) = (f.sessions(), f.advances());
        // Holding the same client is no authority over the journal's session.
        c.end_session();
        assert_eq!(c.current_fence(), Some(fence));
        assert_eq!(c.begin_session(), Err(AnchorError::Busy));
        assert_eq!(c.begin_owned_session().unwrap_err(), AnchorError::Busy);
        let state = c.read().unwrap();
        assert_eq!(c.advance(&state, &j16_digest(70)), Err(AnchorError::Fenced));
        assert_eq!((f.sessions(), f.advances()), (sessions, advances));
        // The journal's session is intact: it advances and closes normally.
        j.advance(&record().attempt, State::MayHaveBeenSent, None)
            .unwrap();
        assert_eq!(f.advances(), advances + 1);
        assert_eq!(c.current_fence(), Some(fence));
        assert_eq!(j.close(), SessionClose::Ended);
        assert_eq!(c.current_fence(), None);
        c.begin_session().unwrap();
        c.end_session();
        f.cleanup();
    }

    #[test]
    fn j17_t09_close_racing_with_a_direct_advance() {
        let _guard = test_guard();
        let f = J13::new();
        let c = f.writer();
        let store = f.journal_store(&c);
        drop(store.initialize(record()).unwrap());
        // J17-IA-06: the orders, forced. (a) Before the close, while the
        // journal holds its session: nothing is sent.
        let mut j = store.open().unwrap();
        let state = c.read().unwrap();
        let advances = f.advances();
        assert_eq!(c.advance(&state, &j16_digest(75)), Err(AnchorError::Fenced));
        assert_eq!(f.advances(), advances);
        // (b) While the journal's own advance is in flight (held in the
        // server): the direct advance waits for it and then finds the
        // journal's session again, so it sends nothing either.
        let (arrived_tx, arrived) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        f.arm(
            CasStorePoint::BeforeCommit,
            "Advance",
            Action::Pause {
                arrived: arrived_tx,
                release: release_rx,
            },
        );
        let journal = thread::spawn(move || {
            j.advance(&record().attempt, State::MayHaveBeenSent, None)
                .map(|()| j)
        });
        arrived.recv().unwrap();
        let direct = {
            let (c, state) = (Arc::clone(&c), state.clone());
            thread::spawn(move || c.advance(&state, &j16_digest(76)))
        };
        release.send(()).unwrap();
        let j = journal.join().unwrap().unwrap();
        assert_eq!(direct.join().unwrap(), Err(AnchorError::Fenced));
        assert_eq!(f.advances(), advances + 1);
        // (c) After the close: nothing to use.
        assert_eq!(j.close(), SessionClose::Ended);
        let state = c.read().unwrap();
        assert_eq!(c.advance(&state, &j16_digest(77)), Err(AnchorError::Fenced));
        assert_eq!(f.advances(), advances + 1);
        // Raced (12 times): either order ends the same way.
        for _ in 0..12 {
            let j = store.open().unwrap();
            let state = c.read().unwrap();
            let advances = f.advances();
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let (b, c2) = (Arc::clone(&barrier), Arc::clone(&c));
            let direct = thread::spawn(move || {
                b.wait();
                c2.advance(&state, &j16_digest(71))
            });
            barrier.wait();
            assert_eq!(j.close(), SessionClose::Ended);
            // Before or after the close, the direct advance has no session
            // it may use: nothing is sent.
            assert_eq!(direct.join().unwrap(), Err(AnchorError::Fenced));
            assert_eq!(f.advances(), advances);
            assert_eq!(c.current_fence(), None);
        }
        f.cleanup();
    }

    /// An inquirer that panics, fails, or loses its answer.
    struct J17Inquirer {
        client: Arc<NetworkCasAnchor>,
        mode: &'static str,
    }

    impl CasInquiry for J17Inquirer {
        fn inquire_request(&self, request_id: &str) -> Result<InquiryOutcome, AnchorError> {
            match self.mode {
                "panic" => panic!("synthetic panic inside the assessment"),
                "unknown" => Err(AnchorError::Unknown),
                _ => self.client.inquire(request_id),
            }
        }
    }

    #[test]
    fn j17_t10_t11_a_panic_or_a_failure_inside_the_assessment_releases_the_session() {
        let _guard = test_guard();
        let t = J14::new();
        let c = t.f.writer();
        let fingerprint = t.journal_fingerprint();
        // T10: the inquirer panics after the session began. The unwind drops
        // the lease, which ends the session locally: no Busy is left.
        let panicking = J17Inquirer {
            client: Arc::clone(&c),
            mode: "panic",
        };
        let store = t.store(&c);
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            store.assess_recovery(&RecoveryContext {
                previous_fence: None,
                known_request: Some((&rid(80), &panicking)),
            })
        }));
        assert!(unwound.is_err());
        assert_eq!(c.current_fence(), None);
        c.begin_session().unwrap();
        c.end_session();
        // A panic while a journal is open releases its session the same way.
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _j = store.open().unwrap();
            assert!(c.current_fence().is_some());
            panic!("synthetic panic with an open journal");
        }));
        assert!(unwound.is_err());
        assert_eq!(c.current_fence(), None);
        // T11 / T14: the inquiry fails with an unknown outcome. The
        // assessment concludes nothing from it and releases its session.
        let failing = J17Inquirer {
            client: Arc::clone(&c),
            mode: "unknown",
        };
        let report = t.assess_with(
            &c,
            &RecoveryContext {
                previous_fence: None,
                known_request: Some((&rid(81), &failing)),
            },
        );
        assert_eq!(report.observation.inquiry, InquiryObservation::Failed);
        assert!(!report.decision.send_authorized());
        assert_eq!(c.current_fence(), None);
        // T11: the journal is held elsewhere: refused before any session.
        let sessions = t.f.sessions();
        let held = store.open().unwrap();
        assert_eq!(
            t.store(&t.f.writer())
                .assess_recovery(&RecoveryContext::default()),
            Err(RecoveryError::Store)
        );
        assert_eq!(t.f.sessions(), sessions + 1);
        drop(held);
        // T11: the client is busy with an owned session: the assessment's
        // begin is refused, nothing is sent, and nothing is concluded.
        let FencedSession { lease, .. } = c.begin_owned_session().unwrap();
        let sessions = t.f.sessions();
        let report = t.assess_with(&c, &RecoveryContext::default());
        assert_eq!(report.observation.session, SessionObservation::NotSent);
        assert_eq!(report.decision.class, RecoveryClass::Undecidable);
        assert_eq!(t.f.sessions(), sessions);
        assert!(c.end_owned_session(lease));
        assert_eq!(t.journal_fingerprint(), fingerprint);
        t.f.cleanup();
    }

    #[test]
    fn j17_t12_t13_repeated_assessments_and_an_unknown_begin_leave_no_session() {
        let _guard = test_guard();
        let t = J14::new();
        let c = t.f.writer();
        let mut fences = Vec::new();
        for _ in 0..5 {
            let report = t.assess_with(&c, &RecoveryContext::default());
            assert_eq!(report.decision.class, RecoveryClass::Consistent);
            let SessionObservation::Established { fence, .. } = report.observation.session else {
                panic!("no session");
            };
            fences.push(fence.unwrap());
            assert_eq!(c.current_fence(), None);
        }
        assert!(fences.windows(2).all(|w| w[0] < w[1]), "{fences:?}");
        // T13: the assessment's BeginSession is committed but its answer lost.
        let lossy = Arc::new(J16LoseReply {
            inner: t.f.transport_for(&t.f.pki.writer, Duration::from_secs(5)),
            lose_next: Mutex::new(true),
        });
        let l = Arc::new(NetworkCasAnchor::new(lossy, j11_identity()));
        let before = t.f.disk(&j11_identity()).fence;
        let report = t.assess_with(&l, &RecoveryContext::default());
        assert_eq!(report.observation.session, SessionObservation::Unknown);
        assert_eq!(report.decision.class, RecoveryClass::Undecidable);
        assert_eq!(t.f.disk(&j11_identity()).fence, before + 1);
        assert_eq!(l.current_fence(), None);
        // The next assessment of the same client starts afresh.
        let report = t.assess_with(&l, &RecoveryContext::default());
        assert_eq!(report.decision.class, RecoveryClass::Consistent);
        assert_eq!(l.current_fence(), None);
        t.f.cleanup();
    }

    #[test]
    fn j17_t17_a_lease_of_an_earlier_session_never_matches_a_later_one() {
        let _guard = test_guard();
        let f = J13::new();
        let c = f.writer();
        let first = c.begin_owned_session().unwrap();
        let (old_id, old_fence) = (first.lease.id, first.fence);
        assert!(c.end_owned_session(first.lease));
        let second = c.begin_owned_session().unwrap();
        assert!(second.fence > old_fence);
        assert!(second.lease.id > old_id);
        // A lease that claims the earlier id on this very client (only this
        // module can build one): it can neither use nor end the later
        // session, and dropping it ends nothing.
        let stale = SessionLease {
            id: old_id,
            slot: Arc::downgrade(&c.session),
        };
        let state = c.read().unwrap();
        let advances = f.advances();
        assert_eq!(
            c.advance_owned(&stale, &state, &j16_digest(72)),
            Err(AnchorError::Fenced)
        );
        assert!(!c.end_owned_session(stale));
        let stale = SessionLease {
            id: old_id,
            slot: Arc::downgrade(&c.session),
        };
        drop(stale);
        assert_eq!(c.current_fence(), Some(second.fence));
        assert_eq!(f.advances(), advances);
        // A lease with the later session's own id, but issued for another
        // client, matches nothing here either.
        let other = f.writer();
        let crossed = SessionLease {
            id: second.lease.id,
            slot: Arc::downgrade(&other.session),
        };
        assert_eq!(
            c.advance_owned(&crossed, &state, &j16_digest(74)),
            Err(AnchorError::Fenced)
        );
        assert!(!c.end_owned_session(crossed));
        assert_eq!(c.current_fence(), Some(second.fence));
        assert_eq!(f.advances(), advances);
        // The later session's own lease still works.
        assert!(
            c.advance_owned(&second.lease, &state, &j16_digest(73))
                .is_ok()
        );
        assert!(c.end_owned_session(second.lease));
        // A client made afresh shares nothing with the earlier one: leases of
        // the old client end nothing on it (recovery from a leaked lease).
        let leaked = c.begin_owned_session().unwrap();
        std::mem::forget(leaked);
        assert_eq!(c.begin_session(), Err(AnchorError::Busy));
        let fresh = f.writer();
        fresh.begin_session().unwrap();
        assert!(fresh.holds_unowned_session());
        fresh.end_session();
        f.cleanup();
    }

    #[test]
    fn j17_t26_new_types_carry_no_secret() {
        let _guard = test_guard();
        let f = J13::new();
        let key_body: String = f
            .pki
            .writer
            .key_pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        let c = f.writer();
        let session = c.begin_owned_session().unwrap();
        for text in [
            format!("{session:?}"),
            format!("{:?}", session.lease),
            format!("{:?}", RecoveryError::NoFencedAnchor),
            format!("{:?}", AnchorError::Busy),
        ] {
            for chunk in key_body.as_bytes().chunks(16) {
                assert!(
                    !text.contains(std::str::from_utf8(chunk).unwrap()),
                    "{text}"
                );
            }
            assert!(!text.contains(&*f.base.to_string_lossy()), "{text}");
        }
        // The lease shows its id only, not the client it points to.
        assert_eq!(
            format!("{:?}", session.lease),
            format!("SessionLease {{ id: {} }}", session.lease.id)
        );
        assert!(c.end_owned_session(session.lease));
        f.cleanup();
    }
}

// Test-only items are placed after `mod tests` on purpose: the architecture
// guards (`tests/architecture.rs`, `production_source`) treat everything before
// the first `mod tests` as production code, and these are not production code.
// The J9A/J9B statics are open/advance diagnostics that the journal records only
// under `#[cfg(test)]`.
#[cfg(test)]
static J9A_EXTERNAL_READ: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
static J9A_EXTERNAL_MISMATCH: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
static J9B_OPEN_STAGE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Phase 1-J11 in-process reference server for protocol v2. Test-only: it is
/// the executable model of the server contract, not a deployable server. A
/// "halt" models the production abort after a failed durable write: the
/// instance stops answering and only a fresh instance opened from disk can
/// serve again.
#[cfg(test)]
mod cas_v2_reference {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc::{Receiver, Sender};
    use std::sync::{MutexGuard, TryLockError};

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(super) struct LedgerEntry {
        pub(super) request_id: String,
        pub(super) body_hash: String,
        pub(super) resulting_revision: u64,
        pub(super) resulting_digest: String,
    }

    #[derive(Serialize)]
    struct StateBody<'a> {
        schema: u32,
        identity: &'a AnchorIdentity,
        revision: u64,
        digest: &'a str,
        fence: u64,
        ledger: &'a VecDeque<LedgerEntry>,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct StateFile {
        schema: u32,
        identity: AnchorIdentity,
        revision: u64,
        digest: String,
        fence: u64,
        ledger: VecDeque<LedgerEntry>,
        checksum: String,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(super) struct Durable {
        pub(super) state: AnchorState,
        pub(super) fence: u64,
        pub(super) ledger: VecDeque<LedgerEntry>,
    }

    fn checksum(durable: &Durable) -> Result<String, ()> {
        let data = serde_json::to_vec(&StateBody {
            schema: 2,
            identity: &durable.state.identity,
            revision: durable.state.revision,
            digest: &durable.state.digest,
            fence: durable.fence,
            ledger: &durable.ledger,
        })
        .map_err(|_| ())?;
        Ok(format!("{:x}", Sha256::digest(&data)))
    }

    /// Where an injected durable-write failure happens.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum FaultPoint {
        /// Before the temporary file exists.
        BeforeTemp,
        /// Temporary file written and fsynced, not renamed.
        AfterTempSync,
        /// Renamed, parent directory fsync reported failure.
        AfterRename,
    }

    fn uid() -> u32 {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() }
    }

    pub(super) fn read_state(path: &Path) -> Result<(Durable, (u64, u64)), ()> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| ())?;
        let metadata = file_metadata(&file)?;
        if !trusted(&metadata, false, uid()) || metadata.len() > MAX_CAS_STATE_BYTES {
            return Err(());
        }
        let mut bytes = Vec::new();
        file.take(MAX_CAS_STATE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ())?;
        let file: StateFile = serde_json::from_slice(&bytes).map_err(|_| ())?;
        let durable = Durable {
            state: AnchorState {
                identity: file.identity,
                revision: file.revision,
                digest: file.digest,
            },
            fence: file.fence,
            ledger: file.ledger,
        };
        if file.schema != 2
            || file.checksum != checksum(&durable)?
            || !valid_anchor_state(&durable.state)
            || durable.ledger.len() > CAS_LEDGER_CAPACITY
        {
            return Err(());
        }
        Ok((durable, (metadata.dev(), metadata.ino())))
    }

    /// temp (create_new, O_NOFOLLOW, 0600) -> write -> fsync -> rename ->
    /// parent fsync. `expected` is the inode recorded by the last successful
    /// write (or the open); a different file at the path is refused.
    fn write_state(
        path: &Path,
        durable: &Durable,
        expected: Option<(u64, u64)>,
        fault: Option<FaultPoint>,
    ) -> Result<(u64, u64), ()> {
        let parent = path.parent().ok_or(())?;
        match (expected, fs::symlink_metadata(path)) {
            (Some((dev, ino)), Ok(meta))
                if trusted(&meta, false, uid()) && meta.dev() == dev && meta.ino() == ino => {}
            (None, Err(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err(()),
        }
        if fault == Some(FaultPoint::BeforeTemp) {
            return Err(());
        }
        let bytes = serde_json::to_vec(&StateFile {
            schema: 2,
            identity: durable.state.identity.clone(),
            revision: durable.state.revision,
            digest: durable.state.digest.clone(),
            fence: durable.fence,
            ledger: durable.ledger.clone(),
            checksum: checksum(durable)?,
        })
        .map_err(|_| ())?;
        let temp = path.with_extension(format!("tmp-{}", cas_request_id().map_err(|_| ())?));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(&temp)
            .map_err(|_| ())?;
        file.write_all(&bytes).map_err(|_| ())?;
        file.sync_all().map_err(|_| ())?;
        if fault == Some(FaultPoint::AfterTempSync) {
            return Err(());
        }
        fs::rename(&temp, path).map_err(|_| ())?;
        if fault == Some(FaultPoint::AfterRename) {
            return Err(());
        }
        File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(|_| ())?;
        let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
        if !trusted(&metadata, false, uid()) {
            return Err(());
        }
        Ok((metadata.dev(), metadata.ino()))
    }

    /// Deterministic interleaving point. The first request of `op` that reaches
    /// the point reports arrival and blocks until released.
    pub(super) struct Gate {
        pub(super) op: &'static str,
        pub(super) arrived: Sender<()>,
        pub(super) release: Receiver<()>,
    }

    fn op_name(request: &CasV2Request) -> &'static str {
        match request {
            CasV2Request::Read { .. } => "Read",
            CasV2Request::BeginSession { .. } => "BeginSession",
            CasV2Request::Advance { .. } => "Advance",
            CasV2Request::Inquire { .. } => "Inquire",
        }
    }

    fn pass_gate(slot: &Mutex<Option<Gate>>, request: &CasV2Request) {
        let gate = {
            let mut slot = slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            match slot.as_ref() {
                Some(gate) if gate.op == op_name(request) => slot.take(),
                _ => None,
            }
        };
        if let Some(gate) = gate {
            let _ = gate.arrived.send(());
            let _ = gate.release.recv();
        }
    }

    struct Live {
        durable: Durable,
        inode: (u64, u64),
    }

    pub(super) struct CasV2Server {
        path: PathBuf,
        identity: AnchorIdentity,
        /// `None` after a failed durable write (halted). Every check and every
        /// state change for this identity happens while this lock is held.
        live: Mutex<Option<Live>>,
        fault: Mutex<Option<(&'static str, FaultPoint)>>,
        pub(super) before_lock: Mutex<Option<Gate>>,
        pub(super) before_commit: Mutex<Option<Gate>>,
        /// One-shot: reports that a request of `op` found the identity lock
        /// held and is about to wait for it.
        pub(super) contended: Mutex<Option<(&'static str, Sender<()>)>>,
        /// Requests that reached the server (decoded or not).
        pub(super) received: AtomicUsize,
    }

    impl CasV2Server {
        /// Administrative genesis. Refuses an existing state file.
        pub(super) fn provision(path: &Path, identity: &AnchorIdentity) -> Result<(), ()> {
            let durable = Durable {
                state: AnchorState {
                    identity: identity.clone(),
                    revision: 0,
                    digest: ANCHOR_GENESIS_DIGEST.to_string(),
                },
                fence: 0,
                ledger: VecDeque::new(),
            };
            write_state(path, &durable, None, None).map(|_| ())
        }

        /// A missing or corrupt state file is an error, never a genesis. The
        /// state file and its directory are fsynced before the instance serves,
        /// so a rename whose directory fsync failed before a restart is durable
        /// before anything read from it is reported.
        pub(super) fn open(path: &Path, identity: &AnchorIdentity) -> Result<Self, ()> {
            let (durable, inode) = read_state(path)?;
            if &durable.state.identity != identity {
                return Err(());
            }
            File::open(path)
                .and_then(|file| file.sync_all())
                .map_err(|_| ())?;
            File::open(path.parent().ok_or(())?)
                .and_then(|dir| dir.sync_all())
                .map_err(|_| ())?;
            Ok(Self {
                path: path.to_path_buf(),
                identity: identity.clone(),
                live: Mutex::new(Some(Live { durable, inode })),
                fault: Mutex::new(None),
                before_lock: Mutex::new(None),
                before_commit: Mutex::new(None),
                contended: Mutex::new(None),
                received: AtomicUsize::new(0),
            })
        }

        pub(super) fn inject_fault(&self, op: &'static str, point: FaultPoint) {
            *self.fault.lock().unwrap() = Some((op, point));
        }

        pub(super) fn halted(&self) -> bool {
            self.live.lock().unwrap().is_none()
        }

        pub(super) fn snapshot(&self) -> Option<Durable> {
            self.live
                .lock()
                .unwrap()
                .as_ref()
                .map(|live| live.durable.clone())
        }

        fn take_fault(&self, op: &'static str) -> Option<FaultPoint> {
            let mut slot = self.fault.lock().unwrap();
            match *slot {
                Some((fault_op, point)) if fault_op == op => {
                    *slot = None;
                    Some(point)
                }
                _ => None,
            }
        }

        fn reply(response: &CasV2Response) -> Option<Vec<u8>> {
            serde_json::to_vec(response).ok()
        }

        fn rejected(request_id: String, reason: CasV2Reject) -> Option<Vec<u8>> {
            Self::reply(&CasV2Response::Rejected {
                v: CAS_PROTOCOL_VERSION,
                request_id,
                reason,
            })
        }

        /// One request. `None` means no response (halted or failed write).
        pub(super) fn handle(&self, bytes: &[u8]) -> Option<Vec<u8>> {
            self.received.fetch_add(1, Ordering::SeqCst);
            let request = match cas_v2_decode_request(bytes) {
                Ok(request) => request,
                Err((request_id, reason)) => return Self::rejected(request_id, reason),
            };
            let request_id = request.request_id().to_string();
            if request.identity() != &self.identity {
                return Self::rejected(request_id, CasV2Reject::UnknownIdentity);
            }
            pass_gate(&self.before_lock, &request);
            let mut guard = self.lock_live(&request);
            let live = guard.as_mut()?;
            let v = CAS_PROTOCOL_VERSION;
            match request {
                CasV2Request::Read { .. } => Self::reply(&CasV2Response::State {
                    v,
                    request_id,
                    state: live.durable.state.clone(),
                }),
                CasV2Request::Inquire {
                    target_request_id, ..
                } => {
                    let entry = live
                        .durable
                        .ledger
                        .iter()
                        .find(|entry| entry.request_id == target_request_id);
                    Self::reply(&CasV2Response::InquiryResult {
                        v,
                        request_id,
                        found: entry.is_some(),
                        resulting_revision: entry.map(|entry| entry.resulting_revision),
                    })
                }
                CasV2Request::BeginSession { .. } => {
                    let request = CasV2Request::BeginSession {
                        v,
                        request_id: request_id.clone(),
                        identity: self.identity.clone(),
                    };
                    let Some(fence) = live.durable.fence.checked_add(1) else {
                        return Self::rejected(request_id, CasV2Reject::Exhausted);
                    };
                    let mut next = live.durable.clone();
                    next.fence = fence;
                    pass_gate(&self.before_commit, &request);
                    self.commit(&mut guard, next, "BeginSession")?;
                    Self::reply(&CasV2Response::Session {
                        v,
                        request_id,
                        state: guard.as_ref()?.durable.state.clone(),
                        fence,
                    })
                }
                CasV2Request::Advance {
                    fence,
                    expected,
                    next_revision,
                    next_digest,
                    ..
                } => {
                    let Ok(body_hash) = cas_v2_body_hash(
                        &self.identity,
                        fence,
                        &expected,
                        next_revision,
                        &next_digest,
                    ) else {
                        return Self::rejected(request_id, CasV2Reject::InvalidRequest);
                    };
                    if let Some(entry) = live
                        .durable
                        .ledger
                        .iter()
                        .find(|entry| entry.request_id == request_id)
                    {
                        if entry.body_hash != body_hash {
                            return Self::rejected(request_id, CasV2Reject::RequestIdReuse);
                        }
                        // The original result; the state does not change.
                        return Self::reply(&CasV2Response::Committed {
                            v,
                            request_id,
                            state: AnchorState {
                                identity: self.identity.clone(),
                                revision: entry.resulting_revision,
                                digest: entry.resulting_digest.clone(),
                            },
                            replayed: true,
                        });
                    }
                    if fence != live.durable.fence {
                        return Self::reply(&CasV2Response::Fenced {
                            v,
                            request_id,
                            current_fence: live.durable.fence,
                        });
                    }
                    if !valid_hex64(&next_digest)
                        || next_digest == ANCHOR_GENESIS_DIGEST
                        || expected.identity != self.identity
                    {
                        return Self::rejected(request_id, CasV2Reject::InvalidRequest);
                    }
                    let Some(expected_next) = expected.revision.checked_add(1) else {
                        return Self::rejected(request_id, CasV2Reject::Exhausted);
                    };
                    if next_revision != expected_next {
                        return Self::rejected(request_id, CasV2Reject::InvalidRequest);
                    }
                    if expected != live.durable.state {
                        return Self::reply(&CasV2Response::Conflict {
                            v,
                            request_id,
                            state: live.durable.state.clone(),
                        });
                    }
                    let mut next = live.durable.clone();
                    next.state = AnchorState {
                        identity: self.identity.clone(),
                        revision: next_revision,
                        digest: next_digest,
                    };
                    next.ledger.push_back(LedgerEntry {
                        request_id: request_id.clone(),
                        body_hash,
                        resulting_revision: next.state.revision,
                        resulting_digest: next.state.digest.clone(),
                    });
                    while next.ledger.len() > CAS_LEDGER_CAPACITY {
                        next.ledger.pop_front();
                    }
                    let advance = CasV2Request::Advance {
                        v,
                        request_id: request_id.clone(),
                        identity: self.identity.clone(),
                        fence,
                        expected,
                        next_revision,
                        next_digest: next.state.digest.clone(),
                    };
                    pass_gate(&self.before_commit, &advance);
                    self.commit(&mut guard, next, "Advance")?;
                    Self::reply(&CasV2Response::Committed {
                        v,
                        request_id,
                        state: guard.as_ref()?.durable.state.clone(),
                        replayed: false,
                    })
                }
            }
        }

        fn lock_live(&self, request: &CasV2Request) -> MutexGuard<'_, Option<Live>> {
            match self.live.try_lock() {
                Ok(guard) => guard,
                Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
                Err(TryLockError::WouldBlock) => {
                    let waiter = {
                        let mut slot = self.contended.lock().unwrap();
                        match slot.as_ref() {
                            Some((op, _)) if *op == op_name(request) => slot.take(),
                            _ => None,
                        }
                    };
                    if let Some((_, sender)) = waiter {
                        let _ = sender.send(());
                    }
                    self.live
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                }
            }
        }

        /// Durable write, then the in-memory update. A failed write halts the
        /// instance without touching memory and without a response.
        fn commit(
            &self,
            guard: &mut std::sync::MutexGuard<'_, Option<Live>>,
            next: Durable,
            op: &'static str,
        ) -> Option<()> {
            let inode = guard.as_ref()?.inode;
            match write_state(&self.path, &next, Some(inode), self.take_fault(op)) {
                Ok(inode) => {
                    **guard = Some(Live {
                        durable: next,
                        inode,
                    });
                    Some(())
                }
                Err(()) => {
                    **guard = None;
                    None
                }
            }
        }
    }

    /// In-process transport with one-shot faults selected by request op.
    pub(super) struct TestTransport {
        server: Mutex<Arc<CasV2Server>>,
        drop_request: Mutex<Option<&'static str>>,
        drop_response: Mutex<Option<&'static str>>,
        not_sent: Mutex<Option<&'static str>>,
        pub(super) captured: Mutex<Vec<Vec<u8>>>,
    }

    fn peek_op(bytes: &[u8]) -> String {
        serde_json::from_slice::<serde_json::Value>(bytes)
            .ok()
            .and_then(|value| value.get("op").and_then(|op| op.as_str()).map(String::from))
            .unwrap_or_default()
    }

    fn take_if(slot: &Mutex<Option<&'static str>>, op: &str) -> bool {
        let mut slot = slot.lock().unwrap();
        if slot.is_some_and(|wanted| wanted == op) {
            *slot = None;
            true
        } else {
            false
        }
    }

    impl TestTransport {
        pub(super) fn new(server: Arc<CasV2Server>) -> Self {
            Self {
                server: Mutex::new(server),
                drop_request: Mutex::new(None),
                drop_response: Mutex::new(None),
                not_sent: Mutex::new(None),
                captured: Mutex::new(Vec::new()),
            }
        }

        pub(super) fn server(&self) -> Arc<CasV2Server> {
            Arc::clone(&self.server.lock().unwrap())
        }

        /// Models a server restart: later requests reach the new instance.
        pub(super) fn replace_server(&self, server: Arc<CasV2Server>) {
            *self.server.lock().unwrap() = server;
        }

        /// The next request of `op` is "sent" but held in the network: the
        /// client sees `Unknown` and the bytes are kept for late delivery.
        pub(super) fn hold_next(&self, op: &'static str) {
            *self.drop_request.lock().unwrap() = Some(op);
        }

        /// The next request of `op` is processed but its response is lost.
        pub(super) fn lose_next_response(&self, op: &'static str) {
            *self.drop_response.lock().unwrap() = Some(op);
        }

        pub(super) fn refuse_next(&self, op: &'static str) {
            *self.not_sent.lock().unwrap() = Some(op);
        }

        /// Late delivery of a held request to the current server instance.
        pub(super) fn deliver_held(&self, index: usize) -> Option<CasV2Response> {
            let bytes = self.captured.lock().unwrap()[index].clone();
            self.server()
                .handle(&bytes)
                .and_then(|reply| serde_json::from_slice(&reply).ok())
        }
    }

    impl CasTransport for TestTransport {
        fn exchange(&self, request: &[u8]) -> Result<Vec<u8>, TransportError> {
            let op = peek_op(request);
            if take_if(&self.not_sent, &op) {
                return Err(TransportError::NotSent);
            }
            if take_if(&self.drop_request, &op) {
                self.captured.lock().unwrap().push(request.to_vec());
                return Err(TransportError::Unknown);
            }
            let reply = self.server().handle(request);
            if take_if(&self.drop_response, &op) {
                return Err(TransportError::Unknown);
            }
            reply.ok_or(TransportError::Unknown)
        }
    }
}

/// Phase 1-J12 test-only TLS harness: a private CA built with rcgen and a TLS
/// server that runs `cas_tls_accept` / `CasTlsSession::serve` in front of the
/// in-process reference CAS. It listens on 127.0.0.1 only.
#[cfg(test)]
mod cas_tls_reference {
    use super::cas_v2_reference::CasV2Server;
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, CertificateRevocationListParams, DnType,
        ExtendedKeyUsagePurpose, IsCa, Issuer, KeyIdMethod, KeyPair, KeyUsagePurpose,
        RevokedCertParams, SanType, SerialNumber, date_time_ymd,
    };
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::mpsc::{Receiver, Sender};

    pub(super) struct Ca {
        issuer: Issuer<'static, KeyPair>,
        pub(super) cert_pem: String,
        next_serial: AtomicU64,
    }

    /// One issued certificate and its key, as PEM.
    pub(super) struct Leaf {
        pub(super) cert_pem: String,
        pub(super) key_pem: String,
        pub(super) serial: u64,
    }

    impl Ca {
        pub(super) fn new(name: &str) -> Self {
            let key = KeyPair::generate().unwrap();
            let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.key_usages = vec![
                KeyUsagePurpose::KeyCertSign,
                KeyUsagePurpose::CrlSign,
                KeyUsagePurpose::DigitalSignature,
            ];
            params.distinguished_name.push(DnType::CommonName, name);
            params.not_before = date_time_ymd(2026, 1, 1);
            params.not_after = date_time_ymd(2036, 1, 1);
            let cert_pem = params.self_signed(&key).unwrap().pem();
            Self {
                issuer: Issuer::new(params, key),
                cert_pem,
                next_serial: AtomicU64::new(1000),
            }
        }

        fn issue(&self, sans: Vec<SanType>, server: bool, expired: bool) -> Leaf {
            let key = KeyPair::generate().unwrap();
            let serial = self.next_serial.fetch_add(1, Ordering::SeqCst);
            let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
            params.subject_alt_names = sans;
            params.serial_number = Some(SerialNumber::from(serial));
            params
                .distinguished_name
                .push(DnType::CommonName, "synthetic");
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![if server {
                ExtendedKeyUsagePurpose::ServerAuth
            } else {
                ExtendedKeyUsagePurpose::ClientAuth
            }];
            params.not_before = date_time_ymd(2026, 1, 1);
            params.not_after = if expired {
                date_time_ymd(2026, 1, 2)
            } else {
                date_time_ymd(2036, 1, 1)
            };
            let cert_pem = params.signed_by(&key, &self.issuer).unwrap().pem();
            Leaf {
                cert_pem,
                key_pem: key.serialize_pem(),
                serial,
            }
        }

        pub(super) fn server(&self, dns: &str) -> Leaf {
            self.issue(
                vec![
                    SanType::DnsName(dns.to_string().try_into().unwrap()),
                    SanType::URI(
                        format!("{CAS_PRINCIPAL_PREFIX}test-cluster/server/{dns}")
                            .try_into()
                            .unwrap(),
                    ),
                ],
                true,
                false,
            )
        }

        pub(super) fn expired_server(&self, dns: &str) -> Leaf {
            self.issue(
                vec![SanType::DnsName(dns.to_string().try_into().unwrap())],
                true,
                true,
            )
        }

        /// A client certificate whose SAN is exactly the given URIs.
        pub(super) fn client_with_uris(&self, uris: &[&str], expired: bool) -> Leaf {
            let sans = uris
                .iter()
                .map(|uri| SanType::URI(uri.to_string().try_into().unwrap()))
                .collect();
            self.issue(sans, false, expired)
        }

        pub(super) fn client(&self, principal: &str) -> Leaf {
            self.client_with_uris(&[principal], false)
        }

        pub(super) fn crl(&self, revoked: &[u64]) -> String {
            self.crl_until(revoked, false)
        }

        /// A CRL whose nextUpdate has already passed.
        pub(super) fn expired_crl(&self) -> String {
            self.crl_until(&[], true)
        }

        fn crl_until(&self, revoked: &[u64], expired: bool) -> String {
            CertificateRevocationListParams {
                this_update: date_time_ymd(2026, 1, 1),
                next_update: if expired {
                    date_time_ymd(2026, 1, 2)
                } else {
                    date_time_ymd(2036, 1, 1)
                },
                crl_number: SerialNumber::from(1u64),
                issuing_distribution_point: None,
                revoked_certs: revoked
                    .iter()
                    .map(|serial| RevokedCertParams {
                        serial_number: SerialNumber::from(*serial),
                        revocation_time: date_time_ymd(2026, 1, 2),
                        reason_code: None,
                        invalidity_date: None,
                    })
                    .collect(),
                key_identifier_method: KeyIdMethod::Sha256,
            }
            .signed_by(&self.issuer)
            .unwrap()
            .pem()
            .unwrap()
        }
    }

    /// Write PEM files with the modes the loaders require (keys 0600, public
    /// material 0644) and load them back through the production loaders.
    pub(super) struct Files {
        pub(super) dir: PathBuf,
        next: AtomicU64,
    }

    impl Files {
        pub(super) fn new(dir: PathBuf) -> Self {
            Self {
                dir,
                next: AtomicU64::new(0),
            }
        }

        pub(super) fn write(&self, contents: &str, mode: u32) -> PathBuf {
            let path = self
                .dir
                .join(format!("f{}.pem", self.next.fetch_add(1, Ordering::SeqCst)));
            fs::write(&path, contents).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            path
        }

        pub(super) fn identity(&self, leaf: &Leaf) -> CasTlsIdentity {
            let cert = self.write(&leaf.cert_pem, 0o644);
            let key = self.write(&leaf.key_pem, 0o600);
            CasTlsIdentity::load(&cert, &key).unwrap()
        }

        pub(super) fn roots(&self, cas: &[&Ca]) -> rustls::RootCertStore {
            let bundle: String = cas.iter().map(|ca| ca.cert_pem.clone()).collect();
            cas_load_roots(&self.write(&bundle, 0o644)).unwrap()
        }

        pub(super) fn crls(
            &self,
            crls: &[String],
        ) -> Vec<rustls::pki_types::CertificateRevocationListDer<'static>> {
            cas_load_crls(&self.write(&crls.concat(), 0o644)).unwrap()
        }
    }

    /// What the server does with the next accepted connection.
    pub(super) enum Behavior {
        Normal,
        /// Read the request, then drop the connection without a response or
        /// close_notify. The CAS never sees the request.
        CloseAfterRead,
        /// The CAS processes the request; the reply is discarded.
        DropResponse,
        /// The CAS processes the request; the reply is held until released.
        HoldResponse(Receiver<()>),
        /// The request is held before the CAS sees it; `arrived` reports that
        /// it was received.
        HoldBeforeCas {
            arrived: Sender<()>,
            release: Receiver<()>,
            reply: Sender<Option<Vec<u8>>>,
        },
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) enum Recorded {
        Outcome(CasServeOutcome),
        ClosedAfterRead,
    }

    pub(super) struct TlsCasServer {
        pub(super) addr: SocketAddr,
        pub(super) recorded: Arc<Mutex<Vec<Recorded>>>,
        behaviors: Arc<Mutex<Vec<(&'static str, Behavior)>>>,
        stop: Arc<AtomicBool>,
        thread: Option<thread::JoinHandle<()>>,
    }

    impl TlsCasServer {
        pub(super) fn start(
            addr: SocketAddr,
            config: Arc<rustls::ServerConfig>,
            acl: Arc<CasAcl>,
            cas: Arc<CasV2Server>,
        ) -> Self {
            let listener = TcpListener::bind(addr).unwrap();
            let addr = listener.local_addr().unwrap();
            let recorded = Arc::new(Mutex::new(Vec::new()));
            let behaviors = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let (r, b, s) = (
                Arc::clone(&recorded),
                Arc::clone(&behaviors),
                Arc::clone(&stop),
            );
            let thread = thread::spawn(move || {
                for stream in listener.incoming() {
                    if s.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(stream) = stream else { continue };
                    let (config, acl, cas, recorded, behaviors) = (
                        Arc::clone(&config),
                        Arc::clone(&acl),
                        Arc::clone(&cas),
                        Arc::clone(&r),
                        Arc::clone(&b),
                    );
                    thread::spawn(move || {
                        let entry = serve_one(stream, config, &acl, &cas, &behaviors);
                        recorded.lock().unwrap().push(entry);
                    });
                }
            });
            Self {
                addr,
                recorded,
                behaviors,
                stop,
                thread: Some(thread),
            }
        }

        /// Apply `behavior` once, to the next request of `op`.
        pub(super) fn next_behavior(&self, op: &'static str, behavior: Behavior) {
            self.behaviors.lock().unwrap().push((op, behavior));
        }

        /// Wait (bounded) until `count` connections have been recorded.
        pub(super) fn wait_recorded(&self, count: usize) -> Vec<Recorded> {
            for _ in 0..1000 {
                let recorded = self.recorded.lock().unwrap().clone();
                if recorded.len() >= count {
                    return recorded;
                }
                thread::sleep(Duration::from_millis(10));
            }
            panic!("server did not record {count} connections");
        }

        pub(super) fn stop(mut self) {
            self.stop.store(true, Ordering::SeqCst);
            let _ = TcpStream::connect(self.addr);
            if let Some(thread) = self.thread.take() {
                thread.join().unwrap();
            }
        }
    }

    fn serve_one(
        stream: TcpStream,
        config: Arc<rustls::ServerConfig>,
        acl: &CasAcl,
        cas: &CasV2Server,
        behaviors: &Mutex<Vec<(&'static str, Behavior)>>,
    ) -> Recorded {
        let mut session = match cas_tls_accept(stream, config, Duration::from_secs(5)) {
            Ok(session) => session,
            Err(outcome) => return Recorded::Outcome(outcome),
        };
        let request = match session.read_request() {
            Ok(request) => request,
            Err(outcome) => return Recorded::Outcome(outcome),
        };
        let op = serde_json::from_slice::<serde_json::Value>(&request)
            .ok()
            .and_then(|value| value.get("op").and_then(|op| op.as_str()).map(String::from))
            .unwrap_or_default();
        let behavior = {
            let mut behaviors = behaviors.lock().unwrap();
            match behaviors.iter().position(|(wanted, _)| *wanted == op) {
                Some(index) => behaviors.remove(index).1,
                None => Behavior::Normal,
            }
        };
        type Handler<'a> = Box<dyn Fn(&[u8]) -> Option<Vec<u8>> + 'a>;
        let handler: Handler<'_> = match behavior {
            Behavior::Normal => Box::new(|bytes| cas.handle(bytes)),
            Behavior::CloseAfterRead => {
                drop(session);
                return Recorded::ClosedAfterRead;
            }
            Behavior::DropResponse => Box::new(|bytes| {
                cas.handle(bytes);
                None
            }),
            Behavior::HoldResponse(release) => Box::new(move |bytes| {
                let reply = cas.handle(bytes);
                let _ = release.recv_timeout(Duration::from_secs(10));
                reply
            }),
            Behavior::HoldBeforeCas {
                arrived,
                release,
                reply,
            } => Box::new(move |bytes| {
                let _ = arrived.send(());
                let _ = release.recv_timeout(Duration::from_secs(10));
                let response = cas.handle(bytes);
                let _ = reply.send(response.clone());
                response
            }),
        };
        Recorded::Outcome(session.serve(&request, acl, handler.as_ref()))
    }
}

/// Phase 1-J13 test-only fault injection for `CasStore`. Each armed action
/// fires once, at the first matching step of a request of the given op (`*`
/// for any op), and is then removed.
#[cfg(test)]
mod cas_store_hooks {
    use super::{CasStore, CasStorePoint};
    use std::sync::Mutex;
    use std::sync::mpsc::{Receiver, Sender};

    pub(super) enum Action {
        /// The step fails as if its system call had failed.
        Fail,
        /// The process is killed at the step by SIGKILL, as by a crash.
        Kill,
        /// Report arrival, then wait for release.
        Pause {
            arrived: Sender<()>,
            release: Receiver<()>,
        },
        /// Report arrival and continue.
        Notify(Sender<()>),
    }

    #[derive(Default)]
    pub(super) struct Hooks {
        armed: Mutex<Vec<(CasStorePoint, &'static str, Action)>>,
    }

    impl Hooks {
        pub(super) fn fire(&self, point: CasStorePoint, op: &'static str) -> Result<(), ()> {
            let action = {
                let mut armed = self
                    .armed
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                armed
                    .iter()
                    .position(|(at, wanted, _)| *at == point && (*wanted == "*" || *wanted == op))
                    .map(|index| armed.remove(index).2)
            };
            match action {
                None => Ok(()),
                Some(Action::Fail) => Err(()),
                Some(Action::Kill) => {
                    // SAFETY: kill and pause have no preconditions.
                    unsafe { libc::kill(libc::getpid(), libc::SIGKILL) };
                    loop {
                        // SAFETY: as above.
                        unsafe { libc::pause() };
                    }
                }
                Some(Action::Pause { arrived, release }) => {
                    let _ = arrived.send(());
                    let _ = release.recv();
                    Ok(())
                }
                Some(Action::Notify(sender)) => {
                    let _ = sender.send(());
                    Ok(())
                }
            }
        }
    }

    impl CasStore {
        pub(super) fn arm(&self, point: CasStorePoint, op: &'static str, action: Action) {
            self.hooks
                .armed
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push((point, op, action));
        }
    }
}
