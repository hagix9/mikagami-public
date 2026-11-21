//! Stage 14 operator attestation intent file (Design Revision 5 §18.3-§18.5;
//! Phase 14.8, §41 step 6).
//!
//! The one counted operator channel (§18.6): the `recover` CLI installs one
//! intent file next to the Node state, and the daemon's ingestion step reads,
//! revalidates, and removes it. This module holds the file contract shared by
//! both sides — the fixed name, the strict TOML document, the tmp+link
//! installer, the posture-checking reader, and the pure revalidation against
//! the current incident. It performs no Node store write, carries no
//! authority, and never mints `CONFIRMED`: the one T8 write belongs to the
//! runtime owner's ingestion step.

use crate::config::{Config, ServiceManager};
use crate::fencing::{
    AttestationId, ContinuityContext, ContinuityViolation, FencingIncident, IncidentId,
    WitnessEpoch,
};
use crate::protocol::{ClusterId, NodeId, Term};
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path};

/// The fixed intent file name, `<dirname(state.path)>/fence-attestation.toml`
/// (§18.4). Defined once; every name derives from it.
pub const ATTESTATION_INTENT_FILE: &str = "fence-attestation.toml";
/// The statement token bound in the file (§18.3).
pub const ATTESTATION_STATEMENT: &str = "confirm-fenced-through-arm-v1";
pub const ATTESTATION_FORMAT_VERSION: u32 = 1;
/// §18.4: the intent document is at most 4 KiB.
pub const MAX_INTENT_BYTES: u64 = 4096;
/// The production owner of the intent file and its parent directory (§18.4).
pub const ROOT_UID: u32 = 0;

const S_IFMT: u32 = 0o170000;
const S_IFLNK: u32 = 0o120000;
const S_IFREG: u32 = 0o100000;

mod sys {
    //! Descriptor-relative (`*at`) primitives for the trusted intent
    //! directory (F14.8-01). Linux uses the target's `libc`; macOS (the
    //! development host) declares the same POSIX calls manually with its
    //! 64-bit-inode layouts. No new crate.
    use std::ffi::CStr;
    use std::io;
    use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

    #[cfg(not(any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        all(
            target_os = "macos",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
    )))]
    compile_error!(
        "attestation: descriptor-relative calls are verified only for Linux and macOS on x86_64/aarch64"
    );

    /// The fields `lstat_at` reports.
    pub struct Stat {
        pub mode: u32,
        pub uid: u32,
        pub nlink: u64,
    }

    #[cfg(target_os = "linux")]
    mod imp {
        use super::Stat;
        use std::ffi::{CStr, c_char};

        pub const O_RDONLY: i32 = libc::O_RDONLY;
        pub const O_WRONLY: i32 = libc::O_WRONLY;
        pub const O_CREAT: i32 = libc::O_CREAT;
        pub const O_EXCL: i32 = libc::O_EXCL;
        pub const O_NOFOLLOW: i32 = libc::O_NOFOLLOW;
        pub const O_NONBLOCK: i32 = libc::O_NONBLOCK;
        pub const O_DIRECTORY: i32 = libc::O_DIRECTORY;
        pub const O_CLOEXEC: i32 = libc::O_CLOEXEC;
        pub const ELOOP: i32 = libc::ELOOP;
        pub const ENOTDIR: i32 = libc::ENOTDIR;

        pub fn openat(fd: i32, name: &CStr, flags: i32, mode: u32) -> i32 {
            // SAFETY: `name` is a valid NUL-terminated string for the call.
            unsafe { libc::openat(fd, name.as_ptr(), flags, mode as libc::c_uint) }
        }

        pub fn linkat(fd: i32, from: &CStr, to: &CStr) -> i32 {
            // SAFETY: both names are valid NUL-terminated strings; flag 0
            // never follows a symlink source.
            unsafe { libc::linkat(fd, from.as_ptr(), fd, to.as_ptr(), 0) }
        }

        pub fn unlinkat(fd: i32, name: &CStr) -> i32 {
            // SAFETY: `name` is a valid NUL-terminated string.
            unsafe { libc::unlinkat(fd, name.as_ptr(), 0) }
        }

        pub fn lstat_at(fd: i32, name: &CStr) -> Option<Stat> {
            // SAFETY: `stat` is plain data; the call writes it fully on
            // success and `name` is a valid NUL-terminated string.
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            let result =
                unsafe { libc::fstatat(fd, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) };
            (result == 0).then(|| Stat {
                mode: stat.st_mode,
                uid: stat.st_uid,
                nlink: stat.st_nlink as u64,
            })
        }

        /// Entry names of the directory `fd` refers to, read through a
        /// duplicate descriptor rewound to the start.
        pub fn names(fd: i32) -> Option<Vec<Vec<u8>>> {
            // SAFETY: the duplicate is owned by the directory stream from
            // `fdopendir` on success and closed here otherwise; entries are
            // read before the next `readdir`.
            unsafe {
                let duplicate = libc::dup(fd);
                if duplicate < 0 {
                    return None;
                }
                let stream = libc::fdopendir(duplicate);
                if stream.is_null() {
                    libc::close(duplicate);
                    return None;
                }
                libc::rewinddir(stream);
                let mut names = Vec::new();
                loop {
                    let entry = libc::readdir(stream);
                    if entry.is_null() {
                        break;
                    }
                    let name: *const c_char = (*entry).d_name.as_ptr();
                    names.push(CStr::from_ptr(name).to_bytes().to_vec());
                }
                libc::closedir(stream);
                Some(names)
            }
        }
    }

    #[cfg(target_os = "macos")]
    mod imp {
        use super::Stat;
        use std::ffi::{CStr, c_char, c_int, c_uint, c_void};

        pub const O_RDONLY: i32 = 0;
        pub const O_WRONLY: i32 = 0x1;
        pub const O_NONBLOCK: i32 = 0x4;
        pub const O_NOFOLLOW: i32 = 0x100;
        pub const O_CREAT: i32 = 0x200;
        pub const O_EXCL: i32 = 0x800;
        pub const O_DIRECTORY: i32 = 0x0010_0000;
        pub const O_CLOEXEC: i32 = 0x0100_0000;
        pub const ELOOP: i32 = 62;
        pub const ENOTDIR: i32 = 20;
        const AT_SYMLINK_NOFOLLOW: c_int = 0x20;
        /// 64-bit-inode `struct stat`: `st_dev` i32, `st_mode` u16 at 4,
        /// `st_nlink` u16 at 6, `st_ino` u64 at 8, `st_uid` u32 at 16.
        const STAT_MODE: usize = 4;
        const STAT_NLINK: usize = 6;
        const STAT_UID: usize = 16;
        /// 64-bit-inode `struct dirent`: `d_name` at 21.
        const DIRENT_NAME: usize = 21;

        unsafe extern "C" {
            #[link_name = "openat"]
            fn c_openat(fd: c_int, path: *const c_char, oflag: c_int, ...) -> c_int;
            #[link_name = "linkat"]
            fn c_linkat(
                fd1: c_int,
                name1: *const c_char,
                fd2: c_int,
                name2: *const c_char,
                flag: c_int,
            ) -> c_int;
            #[link_name = "unlinkat"]
            fn c_unlinkat(fd: c_int, path: *const c_char, flag: c_int) -> c_int;
            #[cfg_attr(target_arch = "x86_64", link_name = "fstatat$INODE64")]
            #[cfg_attr(target_arch = "aarch64", link_name = "fstatat")]
            fn c_fstatat(fd: c_int, path: *const c_char, buf: *mut u8, flag: c_int) -> c_int;
            #[link_name = "dup"]
            fn c_dup(fd: c_int) -> c_int;
            #[link_name = "close"]
            fn c_close(fd: c_int) -> c_int;
            #[cfg_attr(target_arch = "x86_64", link_name = "fdopendir$INODE64")]
            #[cfg_attr(target_arch = "aarch64", link_name = "fdopendir")]
            fn c_fdopendir(fd: c_int) -> *mut c_void;
            #[cfg_attr(target_arch = "x86_64", link_name = "rewinddir$INODE64")]
            #[cfg_attr(target_arch = "aarch64", link_name = "rewinddir")]
            fn c_rewinddir(dir: *mut c_void);
            #[cfg_attr(target_arch = "x86_64", link_name = "readdir$INODE64")]
            #[cfg_attr(target_arch = "aarch64", link_name = "readdir")]
            fn c_readdir(dir: *mut c_void) -> *const u8;
            #[link_name = "closedir"]
            fn c_closedir(dir: *mut c_void) -> c_int;
        }

        pub fn openat(fd: i32, name: &CStr, flags: i32, mode: u32) -> i32 {
            // SAFETY: `name` is a valid NUL-terminated string for the call.
            unsafe { c_openat(fd, name.as_ptr(), flags, mode as c_uint) }
        }

        pub fn linkat(fd: i32, from: &CStr, to: &CStr) -> i32 {
            // SAFETY: both names are valid NUL-terminated strings.
            unsafe { c_linkat(fd, from.as_ptr(), fd, to.as_ptr(), 0) }
        }

        pub fn unlinkat(fd: i32, name: &CStr) -> i32 {
            // SAFETY: `name` is a valid NUL-terminated string.
            unsafe { c_unlinkat(fd, name.as_ptr(), 0) }
        }

        pub fn lstat_at(fd: i32, name: &CStr) -> Option<Stat> {
            // Larger than `struct stat` (144 bytes); read at fixed offsets.
            let mut buffer = [0u8; 256];
            // SAFETY: the buffer outlives the call and exceeds the struct.
            let result =
                unsafe { c_fstatat(fd, name.as_ptr(), buffer.as_mut_ptr(), AT_SYMLINK_NOFOLLOW) };
            (result == 0).then(|| Stat {
                mode: u32::from(u16::from_ne_bytes([
                    buffer[STAT_MODE],
                    buffer[STAT_MODE + 1],
                ])),
                uid: u32::from_ne_bytes([
                    buffer[STAT_UID],
                    buffer[STAT_UID + 1],
                    buffer[STAT_UID + 2],
                    buffer[STAT_UID + 3],
                ]),
                nlink: u64::from(u16::from_ne_bytes([
                    buffer[STAT_NLINK],
                    buffer[STAT_NLINK + 1],
                ])),
            })
        }

        /// Entry names of the directory `fd` refers to, read through a
        /// duplicate descriptor rewound to the start.
        pub fn names(fd: i32) -> Option<Vec<Vec<u8>>> {
            // SAFETY: as for Linux; each name is NUL-terminated at
            // `DIRENT_NAME` within the returned entry.
            unsafe {
                let duplicate = c_dup(fd);
                if duplicate < 0 {
                    return None;
                }
                let stream = c_fdopendir(duplicate);
                if stream.is_null() {
                    c_close(duplicate);
                    return None;
                }
                c_rewinddir(stream);
                let mut names = Vec::new();
                loop {
                    let entry = c_readdir(stream);
                    if entry.is_null() {
                        break;
                    }
                    let name = entry.add(DIRENT_NAME).cast::<c_char>();
                    names.push(CStr::from_ptr(name).to_bytes().to_vec());
                }
                c_closedir(stream);
                Some(names)
            }
        }
    }

    pub use imp::{ELOOP, ENOTDIR, O_CLOEXEC, O_DIRECTORY, O_NOFOLLOW, O_NONBLOCK, O_RDONLY};
    use imp::{O_CREAT, O_EXCL, O_WRONLY};

    pub fn openat(dir: BorrowedFd<'_>, name: &CStr, flags: i32) -> io::Result<OwnedFd> {
        let fd = imp::openat(dir.as_raw_fd(), name, flags, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh descriptor that nothing else owns.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// `O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC`, mode 0600.
    pub fn create_exclusive(dir: BorrowedFd<'_>, name: &CStr) -> io::Result<OwnedFd> {
        let fd = imp::openat(
            dir.as_raw_fd(),
            name,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            0o600,
        );
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh descriptor that nothing else owns.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    pub fn linkat(dir: BorrowedFd<'_>, from: &CStr, to: &CStr) -> io::Result<()> {
        if imp::linkat(dir.as_raw_fd(), from, to) != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn unlinkat(dir: BorrowedFd<'_>, name: &CStr) -> io::Result<()> {
        if imp::unlinkat(dir.as_raw_fd(), name) != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// `fstatat(AT_SYMLINK_NOFOLLOW)`: `None` when the name does not exist.
    pub fn lstat_at(dir: BorrowedFd<'_>, name: &CStr) -> io::Result<Option<Stat>> {
        match imp::lstat_at(dir.as_raw_fd(), name) {
            Some(stat) => Ok(Some(stat)),
            None => {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::NotFound {
                    Ok(None)
                } else {
                    Err(error)
                }
            }
        }
    }

    pub fn names(dir: BorrowedFd<'_>) -> io::Result<Vec<Vec<u8>>> {
        imp::names(dir.as_raw_fd()).ok_or_else(io::Error::last_os_error)
    }
}

/// The §18.4 document. Strict: unknown fields and wrong types fail to parse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationIntent {
    pub attestation_format_version: u32,
    pub attestation_id: AttestationId,
    pub cluster_id: String,
    pub node_id: String,
    pub subject: String,
    pub target_node_id: String,
    pub incident_seq: u64,
    pub incident_id: IncidentId,
    pub statement: String,
}

/// A directory-trust, file-posture, or parse failure (§18.4-§18.5). Always a
/// rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentFault {
    /// The directory path is not absolute and normalized, or one of its
    /// components (intermediate or final) is a symlink or not a directory.
    ParentPath,
    ParentUnreadable,
    ParentNotDirectory,
    ParentOwner,
    ParentWritable,
    Symlink,
    NotRegularFile,
    Open(i32),
    Owner,
    Mode,
    LinkCount,
    Oversize,
    Read,
    Parse,
    Version,
}

/// §18.5 steps 1-2 as seen by the reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentRead {
    Absent,
    /// `nlink != 1` while a `tmp-*` sibling exists: an install is in progress.
    Defer,
    Reject(IntentFault),
    Intent(AttestationIntent),
}

/// Why the CLI installed nothing (§18.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallRefusal {
    /// The fixed name exists: an attestation is pending ingestion.
    Pending,
    /// `link(tmp, fixed)` found the fixed name: a concurrent creator won.
    Concurrent,
    Oversize,
    Io(String),
}

/// An intent field that does not match the current state (§18.5 step 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentMismatch {
    Cluster,
    Node,
    Subject,
    Target,
    Incident,
    Statement,
    AttestationId,
}

/// The pure §18.5 step 3 decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentVerdict {
    /// Valid for the current incident: T8 (or a no-op if already `CONFIRMED`).
    Accept(AttestationId),
    /// A bad intent: rejected, and the fencing state is never mutated.
    Reject(IntentMismatch),
    /// The incident itself failed a §26 continuity rule at ingestion: the
    /// incident is retired (T9) and the intent rejected.
    Retire(ContinuityViolation),
}

/// The local facts an intent must match, fixed at runtime construction.
pub struct IntentBinding<'a> {
    pub cluster_id: &'a ClusterId,
    pub node_id: &'a NodeId,
    pub subject: &'a str,
}

/// §18.1: `service.unit` for systemd, `cluster.id` for the command manager.
pub fn canonical_subject(config: &Config) -> Option<&str> {
    match config.service.manager {
        ServiceManager::Systemd => config.service.unit.as_deref(),
        ServiceManager::Command => Some(&config.cluster.id),
    }
}

/// §18.4: the directory holding the Node state and the intent file.
pub fn intent_dir(state_path: &Path) -> Option<&Path> {
    state_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
}

fn temp_prefix() -> String {
    format!("{ATTESTATION_INTENT_FILE}.tmp-")
}

fn c_name(name: &[u8]) -> io::Result<CString> {
    CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

/// F14.8-01: the trusted intent directory as one open, validated directory
/// object. `open` walks the path from `/` one component at a time with
/// `openat(O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)`, so no component —
/// intermediate or final — can be a symlink, then validates the opened
/// descriptor itself (`fstat`: a directory owned by `owner`, not
/// group/world-writable). Every later intent operation is relative to that
/// descriptor and the directory fsync uses it too, so renaming or replacing
/// any pathname after validation cannot redirect an operation to another
/// directory. It holds no pathname.
pub struct TrustedDir {
    dir: File,
    owner: u32,
}

impl TrustedDir {
    /// §18.4: checked by both the CLI and the daemon. Fails closed.
    pub fn open(path: &Path, owner: u32) -> Result<Self, IntentFault> {
        if !path.is_absolute() {
            return Err(IntentFault::ParentPath);
        }
        let mut dir = OpenOptions::new()
            .read(true)
            .custom_flags(sys::O_DIRECTORY | sys::O_CLOEXEC)
            .open("/")
            .map_err(|_| IntentFault::ParentUnreadable)?;
        for component in path.components() {
            let name = match component {
                Component::RootDir => continue,
                Component::Normal(name) => name,
                _ => return Err(IntentFault::ParentPath),
            };
            let name = c_name(name.as_bytes()).map_err(|_| IntentFault::ParentPath)?;
            dir = sys::openat(
                dir.as_fd(),
                &name,
                sys::O_RDONLY | sys::O_DIRECTORY | sys::O_NOFOLLOW | sys::O_CLOEXEC,
            )
            .map(File::from)
            .map_err(|error| match error.raw_os_error() {
                Some(errno) if errno == sys::ELOOP || errno == sys::ENOTDIR => {
                    IntentFault::ParentPath
                }
                _ => IntentFault::ParentUnreadable,
            })?;
        }
        let metadata = dir.metadata().map_err(|_| IntentFault::ParentUnreadable)?;
        if !metadata.is_dir() {
            return Err(IntentFault::ParentNotDirectory);
        }
        if metadata.uid() != owner {
            return Err(IntentFault::ParentOwner);
        }
        if metadata.mode() & 0o022 != 0 {
            return Err(IntentFault::ParentWritable);
        }
        Ok(Self { dir, owner })
    }

    fn entry(&self, name: &[u8]) -> io::Result<Option<sys::Stat>> {
        sys::lstat_at(self.dir.as_fd(), &c_name(name)?)
    }

    fn create_exclusive(&self, name: &[u8]) -> io::Result<File> {
        sys::create_exclusive(self.dir.as_fd(), &c_name(name)?).map(File::from)
    }

    fn open_read(&self, name: &[u8]) -> io::Result<File> {
        sys::openat(
            self.dir.as_fd(),
            &c_name(name)?,
            sys::O_RDONLY | sys::O_NOFOLLOW | sys::O_NONBLOCK | sys::O_CLOEXEC,
        )
        .map(File::from)
    }

    fn link(&self, from: &[u8], to: &[u8]) -> io::Result<()> {
        sys::linkat(self.dir.as_fd(), &c_name(from)?, &c_name(to)?)
    }

    fn unlink(&self, name: &[u8]) -> io::Result<()> {
        sys::unlinkat(self.dir.as_fd(), &c_name(name)?)
    }

    fn names(&self) -> io::Result<Vec<Vec<u8>>> {
        sys::names(self.dir.as_fd())
    }

    /// fsync of the validated directory object itself.
    fn sync(&self) -> io::Result<()> {
        self.dir.sync_all()
    }

    /// `(st_dev, st_ino)` of the validated directory object.
    #[cfg(test)]
    fn identity(&self) -> (u64, u64) {
        let metadata = self.dir.metadata().unwrap();
        (metadata.dev(), metadata.ino())
    }
}

/// §18.4 step 3: an intent is pending while anything exists at the fixed
/// name in the trusted directory.
pub fn intent_pending(trusted: &TrustedDir) -> Result<bool, IntentFault> {
    trusted
        .entry(ATTESTATION_INTENT_FILE.as_bytes())
        .map(|entry| entry.is_some())
        .map_err(|error| IntentFault::Open(error.raw_os_error().unwrap_or(0)))
}

/// The CLI half of §18.4 (steps 3, 4, 6, 7, 8), entirely inside the trusted
/// directory object: refuse if an intent is pending, remove stale
/// temporaries, create a fresh `tmp-<uuid>` with `O_CREAT|O_EXCL|O_NOFOLLOW`
/// and mode 0600, fsync it, `link` it to the fixed name (EEXIST: a concurrent
/// creator won, nothing is overwritten), unlink the temporary, and fsync the
/// directory. A partial file is never visible at the fixed name. The caller
/// prints the statement (step 5) first.
pub fn install_intent(
    trusted: &TrustedDir,
    intent: &AttestationIntent,
) -> Result<(), InstallRefusal> {
    let io = |error: io::Error| InstallRefusal::Io(error.to_string());
    match intent_pending(trusted) {
        Ok(true) => return Err(InstallRefusal::Pending),
        Ok(false) => {}
        Err(fault) => return Err(InstallRefusal::Io(format!("{fault:?}"))),
    }
    remove_stale_temporaries(trusted);
    let body = toml::to_string(intent).map_err(|error| InstallRefusal::Io(error.to_string()))?;
    if body.len() as u64 > MAX_INTENT_BYTES {
        return Err(InstallRefusal::Oversize);
    }
    let token = crate::node_mutation::generate_uuid()
        .ok_or_else(|| InstallRefusal::Io("temporary name generation failed".into()))?;
    let temporary = format!("{}{token}", temp_prefix());
    let mut file = trusted.create_exclusive(temporary.as_bytes()).map_err(io)?;
    let written = file
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .and_then(|()| file.write_all(body.as_bytes()))
        .and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = written {
        let _ = trusted.unlink(temporary.as_bytes());
        return Err(io(error));
    }
    if let Err(error) = trusted.link(temporary.as_bytes(), ATTESTATION_INTENT_FILE.as_bytes()) {
        let _ = trusted.unlink(temporary.as_bytes());
        // EEXIST: another creator linked first. ENOENT: a concurrent CLI's
        // step-4 cleanup removed this still-unlinked temporary. Either way
        // another intent wins and nothing is overwritten.
        return Err(match error.kind() {
            io::ErrorKind::AlreadyExists | io::ErrorKind::NotFound => InstallRefusal::Concurrent,
            _ => io(error),
        });
    }
    // After the link the intent is installed. A concurrent CLI's cleanup may
    // already have removed this temporary name, which is equally final.
    match trusted.unlink(temporary.as_bytes()) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(io(error)),
    }
    trusted.sync().map_err(io)
}

/// §18.4 step 4: only regular, owner-owned, single-link temporaries.
fn remove_stale_temporaries(trusted: &TrustedDir) {
    let Ok(names) = trusted.names() else {
        return;
    };
    let prefix = temp_prefix();
    for name in names {
        if !name.starts_with(prefix.as_bytes()) {
            continue;
        }
        if trusted.entry(&name).is_ok_and(|entry| {
            entry.is_some_and(|stat| {
                stat.mode & S_IFMT == S_IFREG && stat.uid == trusted.owner && stat.nlink == 1
            })
        }) {
            let _ = trusted.unlink(&name);
        }
    }
}

fn temporary_sibling_exists(trusted: &TrustedDir) -> bool {
    let prefix = temp_prefix();
    trusted
        .names()
        .is_ok_and(|names| names.iter().any(|name| name.starts_with(prefix.as_bytes())))
}

/// The daemon half of §18.5 steps 1-2, inside the trusted directory object.
/// The final component's type is checked with `fstatat(AT_SYMLINK_NOFOLLOW)`
/// before anything opens it, and the open adds `O_NOFOLLOW | O_NONBLOCK`, so
/// a symlink, FIFO, or device is refused without blocking. Then: regular,
/// owner-owned, mode 0600, one link, at most 4 KiB, strict TOML, supported
/// version.
pub fn read_intent(trusted: &TrustedDir) -> IntentRead {
    let name = ATTESTATION_INTENT_FILE.as_bytes();
    let linked = match trusted.entry(name) {
        Ok(Some(stat)) => stat,
        Ok(None) => return IntentRead::Absent,
        Err(error) => {
            return IntentRead::Reject(IntentFault::Open(error.raw_os_error().unwrap_or(0)));
        }
    };
    if linked.mode & S_IFMT == S_IFLNK {
        return IntentRead::Reject(IntentFault::Symlink);
    }
    if linked.mode & S_IFMT != S_IFREG {
        return IntentRead::Reject(IntentFault::NotRegularFile);
    }
    let file = match trusted.open_read(name) {
        Ok(file) => file,
        Err(error) => {
            return IntentRead::Reject(IntentFault::Open(error.raw_os_error().unwrap_or(0)));
        }
    };
    let Ok(metadata) = file.metadata() else {
        return IntentRead::Reject(IntentFault::Read);
    };
    if !metadata.is_file() {
        return IntentRead::Reject(IntentFault::NotRegularFile);
    }
    if metadata.nlink() != 1 {
        return if temporary_sibling_exists(trusted) {
            IntentRead::Defer
        } else {
            IntentRead::Reject(IntentFault::LinkCount)
        };
    }
    if let Err(fault) = check_intent_metadata(
        metadata.uid(),
        metadata.mode(),
        metadata.len(),
        trusted.owner,
    ) {
        return IntentRead::Reject(fault);
    }
    let mut body = Vec::new();
    if file
        .take(MAX_INTENT_BYTES + 1)
        .read_to_end(&mut body)
        .is_err()
    {
        return IntentRead::Reject(IntentFault::Read);
    }
    if body.len() as u64 > MAX_INTENT_BYTES {
        return IntentRead::Reject(IntentFault::Oversize);
    }
    let Ok(text) = String::from_utf8(body) else {
        return IntentRead::Reject(IntentFault::Parse);
    };
    let Ok(intent) = toml::from_str::<AttestationIntent>(&text) else {
        return IntentRead::Reject(IntentFault::Parse);
    };
    if intent.attestation_format_version != ATTESTATION_FORMAT_VERSION {
        return IntentRead::Reject(IntentFault::Version);
    }
    IntentRead::Intent(intent)
}

/// §18.5 step 1: owner-owned, mode exactly 0600, at most 4 KiB.
fn check_intent_metadata(uid: u32, mode: u32, len: u64, owner: u32) -> Result<(), IntentFault> {
    if uid != owner {
        return Err(IntentFault::Owner);
    }
    if mode & 0o7777 != 0o600 {
        return Err(IntentFault::Mode);
    }
    if len > MAX_INTENT_BYTES {
        return Err(IntentFault::Oversize);
    }
    Ok(())
}

/// §18.5 outcome cleanup inside the trusted directory object: unlink the
/// fixed name and fsync the same directory. An already-absent file is not an
/// error.
pub fn remove_intent(trusted: &TrustedDir) -> io::Result<()> {
    match trusted.unlink(ATTESTATION_INTENT_FILE.as_bytes()) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    trusted.sync()
}

/// §18.5 step 3, pure: the intent's fields against the local binding and the
/// current durable incident, then the incident's §26 R1-R4 continuity (R4 as
/// "no newer authenticated TermStatus term than `anchor_term`"). A bad intent
/// is only rejected; a continuity failure retires the incident.
pub fn validate_intent(
    intent: &AttestationIntent,
    incident: &FencingIncident,
    binding: &IntentBinding<'_>,
    context: &ContinuityContext<'_>,
    latest_observed_term: Option<Term>,
) -> IntentVerdict {
    let mismatch = if intent.cluster_id != binding.cluster_id.as_str() {
        Some(IntentMismatch::Cluster)
    } else if intent.node_id != binding.node_id.as_str() {
        Some(IntentMismatch::Node)
    } else if intent.subject != binding.subject {
        Some(IntentMismatch::Subject)
    } else if intent.target_node_id != context.configured_peer.as_str()
        || intent.target_node_id != incident.target_node_id.as_str()
    {
        Some(IntentMismatch::Target)
    } else if intent.incident_seq != incident.incident_seq
        || intent.incident_id != incident.incident_id
    {
        Some(IntentMismatch::Incident)
    } else if intent.statement != ATTESTATION_STATEMENT {
        Some(IntentMismatch::Statement)
    } else if !crate::node_mutation::is_canonical_uuid_v4(intent.attestation_id.as_str()) {
        Some(IntentMismatch::AttestationId)
    } else {
        None
    };
    if let Some(mismatch) = mismatch {
        return IntentVerdict::Reject(mismatch);
    }
    if let Err(violation) =
        incident.check_continuity(context, WitnessEpoch::LatestObserved(latest_observed_term))
    {
        return IntentVerdict::Retire(violation);
    }
    IntentVerdict::Accept(intent.attestation_id.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::failure_assessment::PeerFailureDetector;
    use crate::fencing::{FencingState, UnknownReason};
    use crate::protocol::{Sequence, SessionId};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::time::{Duration, Instant};

    const INCIDENT_UUID: &str = "11111111-2222-4333-8444-555555555555";
    const ATTESTATION_UUID: &str = "66666666-7777-4888-9999-aaaaaaaaaaaa";
    const CONFIG: &str = "[cluster]\nid = \"cluster\"\n\
        [node]\nid = \"node-a\"\n\
        [peer]\nid = \"node-b\"\naddress = \"127.0.0.1:7946\"\n\
        [witness]\nid = \"witness-1\"\naddress = \"127.0.0.1:7947\"\n\
        [vip]\naddress = \"192.0.2.50/24\"\ninterface = \"eth0\"\n\
        [service]\nmanager = \"systemd\"\nunit = \"nginx.service\"\n\
        [health]\ncommand = [\"/usr/bin/true\"]\n\
        [security]\npsk_file = \"/etc/mikagami/cluster.psk\"\n";

    /// A private 0700 directory owned by the test user, and that uid. The
    /// fixture base is canonicalized (macOS `/var` is a symlink) because the
    /// trusted-directory walk refuses every symlinked component; production
    /// paths are never canonicalized.
    fn private_dir(tag: &str) -> (PathBuf, u32) {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "mikagami-att-{}-{tag}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::SeqCst)
            ));
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(&dir).unwrap().uid();
        (dir, uid)
    }

    fn trusted(dir: &Path, uid: u32) -> TrustedDir {
        TrustedDir::open(dir, uid).unwrap()
    }

    fn install(dir: &Path, uid: u32, intent: &AttestationIntent) -> Result<(), InstallRefusal> {
        install_intent(&trusted(dir, uid), intent)
    }

    /// The daemon's view: an untrusted directory rejects before any read.
    fn read(dir: &Path, uid: u32) -> IntentRead {
        match TrustedDir::open(dir, uid) {
            Ok(trusted) => read_intent(&trusted),
            Err(fault) => IntentRead::Reject(fault),
        }
    }

    fn pending(dir: &Path, uid: u32) -> bool {
        intent_pending(&trusted(dir, uid)).unwrap()
    }

    fn intent() -> AttestationIntent {
        AttestationIntent {
            attestation_format_version: ATTESTATION_FORMAT_VERSION,
            attestation_id: AttestationId::new(ATTESTATION_UUID),
            cluster_id: "cluster".into(),
            node_id: "node-a".into(),
            subject: "nginx.service".into(),
            target_node_id: "node-b".into(),
            incident_seq: 7,
            incident_id: IncidentId::new(INCIDENT_UUID),
            statement: ATTESTATION_STATEMENT.into(),
        }
    }

    fn write_raw(dir: &Path, body: &[u8], mode: u32) {
        let fixed = dir.join(ATTESTATION_INTENT_FILE);
        let _ = fs::remove_file(&fixed);
        fs::write(&fixed, body).unwrap();
        fs::set_permissions(&fixed, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn temporaries(dir: &Path) -> Vec<String> {
        fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(&temp_prefix()))
            .collect()
    }

    /// §18.4: tmp + fsync + link + unlink + dir fsync; the reader sees exactly
    /// the installed document, mode 0600, one link, no temporary left.
    #[test]
    fn stage14_8_install_then_read_round_trip() {
        let (dir, uid) = private_dir("round-trip");
        assert!(!pending(&dir, uid));
        install(&dir, uid, &intent()).unwrap();
        let metadata = fs::symlink_metadata(dir.join(ATTESTATION_INTENT_FILE)).unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        assert!(temporaries(&dir).is_empty());
        assert!(pending(&dir, uid));
        assert_eq!(read(&dir, uid), IntentRead::Intent(intent()));
        remove_intent(&trusted(&dir, uid)).unwrap();
        assert_eq!(read(&dir, uid), IntentRead::Absent);
        remove_intent(&trusted(&dir, uid)).unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    /// §18.4 step 3/7 and §34.7 duplicate: a pending intent is never
    /// overwritten.
    #[test]
    fn stage14_8_install_refuses_pending_and_never_overwrites() {
        let (dir, uid) = private_dir("pending");
        install(&dir, uid, &intent()).unwrap();
        let before = fs::read(dir.join(ATTESTATION_INTENT_FILE)).unwrap();
        let mut second = intent();
        second.incident_seq = 8;
        assert_eq!(install(&dir, uid, &second), Err(InstallRefusal::Pending));
        assert_eq!(fs::read(dir.join(ATTESTATION_INTENT_FILE)).unwrap(), before);
        assert!(temporaries(&dir).is_empty());
        fs::remove_dir_all(dir).unwrap();
    }

    /// §34.7 concurrent intents: exactly one wins; the others install nothing
    /// and no temporary leaks.
    #[test]
    fn stage14_8_concurrent_installs_exactly_one_wins() {
        let (dir, uid) = private_dir("concurrent");
        let barrier = Arc::new(Barrier::new(8));
        let handles: Vec<_> = (0..8u64)
            .map(|index| {
                let (dir, barrier) = (dir.clone(), barrier.clone());
                std::thread::spawn(move || {
                    let mut mine = intent();
                    mine.incident_seq = 100 + index;
                    let trusted = TrustedDir::open(&dir, uid).unwrap();
                    barrier.wait();
                    (mine.incident_seq, install_intent(&trusted, &mine))
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let winners: Vec<u64> = results
            .iter()
            .filter(|(_, result)| result.is_ok())
            .map(|(seq, _)| *seq)
            .collect();
        assert_eq!(winners.len(), 1, "{results:?}");
        for (_, result) in &results {
            assert!(
                matches!(
                    result,
                    Ok(()) | Err(InstallRefusal::Pending | InstallRefusal::Concurrent)
                ),
                "{result:?}"
            );
        }
        let IntentRead::Intent(read) = read(&dir, uid) else {
            panic!("the winner's intent must be readable");
        };
        assert_eq!(read.incident_seq, winners[0]);
        assert!(temporaries(&dir).is_empty());
        fs::remove_dir_all(dir).unwrap();
    }

    /// §18.4 step 4 / §34.7 partial file: a crash before link leaves only a
    /// temporary, which is invisible to the reader and removed by the next
    /// CLI only when it is a regular, owned, single-link file.
    #[test]
    fn stage14_8_partial_and_stale_temporaries() {
        let (dir, uid) = private_dir("stale");
        let stale = dir.join(format!("{}crashed", temp_prefix()));
        fs::write(&stale, "attestation_format_version = 1\n").unwrap();
        assert_eq!(read(&dir, uid), IntentRead::Absent);
        let other = dir.join("other");
        fs::write(&other, "x").unwrap();
        let linked = dir.join(format!("{}linked", temp_prefix()));
        fs::hard_link(&other, &linked).unwrap();
        let symlink = dir.join(format!("{}symlink", temp_prefix()));
        std::os::unix::fs::symlink(&other, &symlink).unwrap();
        install(&dir, uid, &intent()).unwrap();
        assert!(!stale.exists(), "a safe stale temporary is removed");
        assert!(linked.exists(), "a multi-link temporary is kept");
        assert!(
            fs::symlink_metadata(&symlink).is_ok(),
            "a symlink temporary is kept"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    /// §34.7 symlink at the fixed path, and special files, are refused
    /// without following or blocking.
    #[test]
    fn stage14_8_reader_refuses_symlink_fifo_and_directory() {
        let (dir, uid) = private_dir("special");
        let target = dir.join("target");
        write_raw(&dir, toml::to_string(&intent()).unwrap().as_bytes(), 0o600);
        fs::rename(dir.join(ATTESTATION_INTENT_FILE), &target).unwrap();
        std::os::unix::fs::symlink(&target, dir.join(ATTESTATION_INTENT_FILE)).unwrap();
        assert_eq!(read(&dir, uid), IntentRead::Reject(IntentFault::Symlink));
        remove_intent(&trusted(&dir, uid)).unwrap();
        assert!(target.exists(), "unlinking the symlink leaves its target");

        let status = std::process::Command::new("mkfifo")
            .arg(dir.join(ATTESTATION_INTENT_FILE))
            .status()
            .unwrap();
        assert!(status.success());
        let started = Instant::now();
        assert_eq!(
            read(&dir, uid),
            IntentRead::Reject(IntentFault::NotRegularFile)
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        remove_intent(&trusted(&dir, uid)).unwrap();

        fs::create_dir(dir.join(ATTESTATION_INTENT_FILE)).unwrap();
        assert_eq!(
            read(&dir, uid),
            IntentRead::Reject(IntentFault::NotRegularFile)
        );
        fs::remove_dir_all(dir).unwrap();
    }

    /// §34.7 hardlink: nlink 2 without a temporary rejects; with a `tmp-*`
    /// sibling (an install in progress) the reader defers.
    #[test]
    fn stage14_8_reader_hardlink_rejects_or_defers() {
        let (dir, uid) = private_dir("hardlink");
        install(&dir, uid, &intent()).unwrap();
        let alias = dir.join("alias");
        fs::hard_link(dir.join(ATTESTATION_INTENT_FILE), &alias).unwrap();
        assert_eq!(read(&dir, uid), IntentRead::Reject(IntentFault::LinkCount));
        fs::remove_file(&alias).unwrap();
        let temporary = dir.join(format!("{}inflight", temp_prefix()));
        fs::hard_link(dir.join(ATTESTATION_INTENT_FILE), &temporary).unwrap();
        assert_eq!(read(&dir, uid), IntentRead::Defer);
        fs::remove_file(&temporary).unwrap();
        assert_eq!(read(&dir, uid), IntentRead::Intent(intent()));
        fs::remove_dir_all(dir).unwrap();
    }

    /// §34.7 wrong mode, oversize, unsafe parent (writable, foreign owner,
    /// symlinked), for both the reader and the installer.
    #[test]
    fn stage14_8_posture_rules() {
        let (dir, uid) = private_dir("posture");
        let body = toml::to_string(&intent()).unwrap();
        write_raw(&dir, body.as_bytes(), 0o644);
        assert_eq!(read(&dir, uid), IntentRead::Reject(IntentFault::Mode));
        write_raw(&dir, body.as_bytes(), 0o400);
        assert_eq!(read(&dir, uid), IntentRead::Reject(IntentFault::Mode));
        let padded = format!("{body}{}", "#".repeat(MAX_INTENT_BYTES as usize));
        write_raw(&dir, padded.as_bytes(), 0o600);
        assert_eq!(read(&dir, uid), IntentRead::Reject(IntentFault::Oversize));
        write_raw(&dir, body.as_bytes(), 0o600);
        assert_eq!(
            TrustedDir::open(&dir, uid + 1).err(),
            Some(IntentFault::ParentOwner)
        );
        for mode in [0o777, 0o770, 0o702] {
            fs::set_permissions(&dir, fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(
                TrustedDir::open(&dir, uid).err(),
                Some(IntentFault::ParentWritable),
                "{mode:o}"
            );
        }
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let link = dir.with_extension("link");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        assert_eq!(
            TrustedDir::open(&link, uid).err(),
            Some(IntentFault::ParentPath)
        );
        fs::remove_file(link).unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    /// The metadata rule the reader applies after `fstat`, including a
    /// foreign owner that a non-root test cannot create on disk. The size
    /// boundary is the literal §18.4 value, independent of the constant.
    #[test]
    fn stage14_8_intent_metadata_rule() {
        assert_eq!(check_intent_metadata(0, 0o100600, 10, ROOT_UID), Ok(()));
        assert_eq!(
            check_intent_metadata(1000, 0o100600, 10, ROOT_UID),
            Err(IntentFault::Owner)
        );
        for mode in [0o100644, 0o100640, 0o100700, 0o104600, 0o100400] {
            assert_eq!(
                check_intent_metadata(0, mode, 10, ROOT_UID),
                Err(IntentFault::Mode),
                "{mode:o}"
            );
        }
        assert_eq!(check_intent_metadata(0, 0o100600, 4096, ROOT_UID), Ok(()));
        assert_eq!(
            check_intent_metadata(0, 0o100600, 4097, ROOT_UID),
            Err(IntentFault::Oversize)
        );
    }

    /// F14.8-02: the §18.4 4 KiB ceiling, pinned with literal sizes. A valid
    /// document padded to exactly 4096 bytes is read; the same padded to 4097
    /// bytes is rejected as oversize.
    #[test]
    fn stage14_8r_literal_4096_byte_boundary() {
        let (dir, uid) = private_dir("boundary");
        let body = toml::to_string(&intent()).unwrap();
        let padded = |total: usize| {
            let mut bytes = body.clone().into_bytes();
            bytes.push(b'#');
            bytes.resize(total - 1, b'x');
            bytes.push(b'\n');
            assert_eq!(bytes.len(), total);
            bytes
        };
        write_raw(&dir, &padded(4096), 0o600);
        assert_eq!(read(&dir, uid), IntentRead::Intent(intent()));
        write_raw(&dir, &padded(4097), 0o600);
        assert_eq!(read(&dir, uid), IntentRead::Reject(IntentFault::Oversize));
        fs::remove_dir_all(dir).unwrap();
    }

    /// §34.7 unknown field, wrong type, unsupported version, malformed TOML.
    #[test]
    fn stage14_8_strict_document() {
        let (dir, uid) = private_dir("strict");
        let body = toml::to_string(&intent()).unwrap();
        for (case, text, fault) in [
            (
                "unknown field",
                format!("{body}extra = 1\n"),
                IntentFault::Parse,
            ),
            (
                "wrong type",
                body.replace("incident_seq = 7", "incident_seq = \"7\""),
                IntentFault::Parse,
            ),
            (
                "missing field",
                body.lines()
                    .filter(|line| !line.starts_with("statement"))
                    .collect::<Vec<_>>()
                    .join("\n"),
                IntentFault::Parse,
            ),
            (
                "version",
                body.replace(
                    "attestation_format_version = 1",
                    "attestation_format_version = 2",
                ),
                IntentFault::Version,
            ),
            (
                "malformed",
                "attestation_format_version = ".into(),
                IntentFault::Parse,
            ),
        ] {
            write_raw(&dir, text.as_bytes(), 0o600);
            assert_eq!(read(&dir, uid), IntentRead::Reject(fault), "{case}");
        }
        write_raw(&dir, &[0xff, 0xfe], 0o600);
        assert_eq!(read(&dir, uid), IntentRead::Reject(IntentFault::Parse));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn stage14_8_canonical_subject_and_directory() {
        let valid = CONFIG;
        let systemd = Config::parse_str(valid).unwrap();
        assert_eq!(canonical_subject(&systemd), Some("nginx.service"));
        let command = Config::parse_str(&valid.replace(
            "manager = \"systemd\"\nunit = \"nginx.service\"",
            "manager = \"command\"\nstart = [\"/opt/app/start\"]\nstop = [\"/opt/app/stop\"]\nstatus = [\"/opt/app/status\"]",
        ))
        .unwrap();
        assert_eq!(canonical_subject(&command), Some("cluster"));
        assert_eq!(
            intent_dir(Path::new("/var/lib/mikagami/state.toml")),
            Some(Path::new("/var/lib/mikagami"))
        );
        assert_eq!(intent_dir(Path::new("state.toml")), None);
    }

    // ---- F14.8-01: the trusted directory is one inode-bound object ----

    /// A symlinked component anywhere on the path — intermediate or final —
    /// refuses the directory; so do relative, `..`, and non-directory paths.
    /// The audited candidate accepted `base/link/inner`.
    #[test]
    fn stage14_8r_symlinked_components_are_rejected() {
        let (base, uid) = private_dir("symlink-walk");
        let inner = base.join("real").join("inner");
        fs::create_dir_all(&inner).unwrap();
        for dir in [base.join("real"), inner.clone()] {
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::os::unix::fs::symlink(base.join("real"), base.join("link")).unwrap();
        std::os::unix::fs::symlink(&inner, base.join("final")).unwrap();
        assert!(TrustedDir::open(&inner, uid).is_ok());
        for (case, path) in [
            ("intermediate symlink", base.join("link").join("inner")),
            ("final symlink", base.join("final")),
            ("parent component", inner.join("..").join("inner")),
            ("relative", PathBuf::from("real/inner")),
        ] {
            assert_eq!(
                TrustedDir::open(&path, uid).err(),
                Some(IntentFault::ParentPath),
                "{case}"
            );
        }
        fs::write(base.join("file"), "x").unwrap();
        assert_eq!(
            TrustedDir::open(&base.join("file"), uid).err(),
            Some(IntentFault::ParentPath)
        );
        assert_eq!(
            TrustedDir::open(&base.join("missing"), uid).err(),
            Some(IntentFault::ParentUnreadable)
        );
        assert!(!inner.join(ATTESTATION_INTENT_FILE).exists());
        fs::remove_dir_all(base).unwrap();
    }

    /// After validation the pathname is swapped for another trusted-looking
    /// directory. The check, pending, install, read, removal, and fsync all
    /// stay on the validated inode; the replacement is never touched.
    #[test]
    fn stage14_8r_replacement_after_validation_stays_on_the_validated_inode() {
        let (base, uid) = private_dir("swap");
        let original = base.join("state");
        fs::create_dir(&original).unwrap();
        fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).unwrap();
        let checked = fs::metadata(&original).unwrap();
        let trusted = TrustedDir::open(&original, uid).unwrap();
        assert_eq!(trusted.identity(), (checked.dev(), checked.ino()));

        let moved = base.join("moved");
        fs::rename(&original, &moved).unwrap();
        fs::create_dir(&original).unwrap();
        fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).unwrap();
        let replacement = fs::metadata(&original).unwrap();
        assert_ne!(trusted.identity(), (replacement.dev(), replacement.ino()));

        install_intent(&trusted, &intent()).unwrap();
        assert!(moved.join(ATTESTATION_INTENT_FILE).exists());
        assert!(!original.join(ATTESTATION_INTENT_FILE).exists());
        assert_eq!(read_intent(&trusted), IntentRead::Intent(intent()));

        let decoy = toml::to_string(&AttestationIntent {
            incident_seq: 99,
            ..intent()
        })
        .unwrap();
        write_raw(&original, decoy.as_bytes(), 0o600);
        assert!(intent_pending(&trusted).unwrap());
        remove_intent(&trusted).unwrap();
        assert!(!moved.join(ATTESTATION_INTENT_FILE).exists());
        assert_eq!(
            fs::read(original.join(ATTESTATION_INTENT_FILE)).unwrap(),
            decoy.as_bytes()
        );
        assert!(!intent_pending(&trusted).unwrap());
        assert!(temporaries(&moved).is_empty() && temporaries(&original).is_empty());
        fs::remove_dir_all(base).unwrap();
    }

    /// An unsafe directory is refused before anything inside it is read,
    /// created, or removed.
    #[test]
    fn stage14_8r_unsafe_directory_is_rejected_without_mutation() {
        let (dir, uid) = private_dir("unsafe");
        let body = toml::to_string(&intent()).unwrap();
        write_raw(&dir, body.as_bytes(), 0o600);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            read(&dir, uid),
            IntentRead::Reject(IntentFault::ParentWritable)
        );
        assert_eq!(
            fs::read(dir.join(ATTESTATION_INTENT_FILE)).unwrap(),
            body.as_bytes()
        );
        assert!(temporaries(&dir).is_empty());
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    // ---- §18.5 step 3 revalidation ----

    fn incident(anchor: u64, session: &str, generation: u64) -> FencingIncident {
        FencingIncident {
            incident_seq: 7,
            incident_id: IncidentId::new(INCIDENT_UUID),
            target_node_id: NodeId::new("node-b"),
            anchor_term: Term(anchor),
            observer_session_id: SessionId::new(session),
            observer_loss_generation: generation,
            attempt_token_high_water: 0,
            state: FencingState::Unknown(UnknownReason::NotAttempted {}),
        }
    }

    fn lost_detector() -> PeerFailureDetector {
        let mut detector = PeerFailureDetector::new(Duration::from_secs(5)).unwrap();
        let peer_session = SessionId::new("peer-session-1");
        let t0 = Instant::now();
        detector
            .observe_session_established(peer_session.clone(), t0)
            .unwrap();
        assert!(
            detector
                .observe_trusted_heartbeat(&peer_session, Sequence(1), t0)
                .unwrap()
        );
        detector.observe_transport_failure(t0).unwrap();
        detector.tick(t0 + Duration::from_secs(5)).unwrap();
        assert_eq!(detector.loss_evidence().unwrap().generation(), 1);
        detector
    }

    fn verdict(
        intent: &AttestationIntent,
        incident: &FencingIncident,
        live: bool,
        latest: Option<Term>,
    ) -> IntentVerdict {
        let evidence = if live {
            lost_detector().loss_evidence()
        } else {
            None
        };
        let (cluster, node, peer, session) = (
            ClusterId::new("cluster"),
            NodeId::new("node-a"),
            NodeId::new("node-b"),
            SessionId::new("0123456789abcdef"),
        );
        validate_intent(
            intent,
            incident,
            &IntentBinding {
                cluster_id: &cluster,
                node_id: &node,
                subject: "nginx.service",
            },
            &ContinuityContext {
                configured_peer: &peer,
                current_session: &session,
                live_episode: evidence.as_ref(),
            },
            latest,
        )
    }

    /// §34.7: the correct current intent is accepted; every mismatched field
    /// is rejected without touching the incident (a pure verdict).
    #[test]
    fn stage14_8_revalidation_fields() {
        let current = incident(41, "0123456789abcdef", 1);
        assert_eq!(
            verdict(&intent(), &current, true, None),
            IntentVerdict::Accept(AttestationId::new(ATTESTATION_UUID))
        );
        let cases: Vec<(&str, fn(&mut AttestationIntent), IntentMismatch)> = vec![
            (
                "cluster",
                |i| i.cluster_id = "other".into(),
                IntentMismatch::Cluster,
            ),
            (
                "node",
                |i| i.node_id = "node-c".into(),
                IntentMismatch::Node,
            ),
            (
                "service",
                |i| i.subject = "other.service".into(),
                IntentMismatch::Subject,
            ),
            (
                "target",
                |i| i.target_node_id = "node-c".into(),
                IntentMismatch::Target,
            ),
            (
                "local target",
                |i| i.target_node_id = "node-a".into(),
                IntentMismatch::Target,
            ),
            ("sequence", |i| i.incident_seq = 8, IntentMismatch::Incident),
            (
                "uuid",
                |i| i.incident_id = IncidentId::new("11111111-2222-4333-8444-555555555556"),
                IntentMismatch::Incident,
            ),
            (
                "statement",
                |i| i.statement = "confirm-fenced-v0".into(),
                IntentMismatch::Statement,
            ),
            (
                "attestation id",
                |i| i.attestation_id = AttestationId::new("not-a-uuid"),
                IntentMismatch::AttestationId,
            ),
        ];
        for (case, mutate, expected) in cases {
            let mut bad = intent();
            mutate(&mut bad);
            assert_eq!(
                verdict(&bad, &current, true, None),
                IntentVerdict::Reject(expected),
                "{case}"
            );
            // A bad intent is rejected even when the incident's continuity
            // has also failed: it never causes the retirement itself.
            assert_eq!(
                verdict(&bad, &current, false, Some(Term(42))),
                IntentVerdict::Reject(expected),
                "{case}"
            );
        }
    }

    /// §34.7 / G7(a): stale anchor (a newer TermStatus term observed), stale
    /// observer session, stale or absent loss generation retire the incident.
    #[test]
    fn stage14_8_revalidation_continuity() {
        let current = incident(41, "0123456789abcdef", 1);
        assert_eq!(
            verdict(&intent(), &current, true, Some(Term(41))),
            IntentVerdict::Accept(AttestationId::new(ATTESTATION_UUID))
        );
        for term in [Term(42), Term(40)] {
            assert_eq!(
                verdict(&intent(), &current, true, Some(term)),
                IntentVerdict::Retire(ContinuityViolation::WitnessEpoch)
            );
        }
        assert_eq!(
            verdict(&intent(), &incident(41, "fedcba9876543210", 1), true, None),
            IntentVerdict::Retire(ContinuityViolation::ObserverSession)
        );
        assert_eq!(
            verdict(&intent(), &incident(41, "0123456789abcdef", 2), true, None),
            IntentVerdict::Retire(ContinuityViolation::Episode)
        );
        assert_eq!(
            verdict(&intent(), &current, false, None),
            IntentVerdict::Retire(ContinuityViolation::Episode)
        );
    }
}
