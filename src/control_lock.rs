//! The shared control-plane lock between the production HA daemon and the
//! manual node agent.
//!
//! This is deliberately a small, standalone primitive: it is not HA control
//! logic and it is not manual-plane control logic. Both sides call it to
//! exclude each other's *processes* on one host. It proves nothing about VIP
//! uniqueness, cloud operations, or the completion of an earlier request;
//! those are separate layers (`manual_barrier` and the existing Witness/lease
//! protocols).
//!
//! Properties enforced here:
//!
//! * a Linux kernel `flock(LOCK_EX | LOCK_NB)` on a root-owned regular file;
//! * fail-closed on every uncertainty (busy, unsafe path, wrong owner,
//!   symlink, hard link, writable mode, non-local filesystem, inode swap);
//! * `O_CLOEXEC` so a fencing command or a managed service cannot inherit the
//!   descriptor and keep the lock alive after the owner dies;
//! * the file lives below a private (0700) directory that is never cleaned by
//!   `RuntimeDirectory=` or tmpfiles; the path is checked again after the
//!   `flock`, so an unlink/recreate race is detected;
//! * the descriptor is held for the whole owner lifetime (HA) or the whole
//!   mutating request (manual agent) and released by the kernel on death.
//!
//! The threat model is an accidental second control process, a stale marker,
//! a cleanup job, or an operator mistake. A hostile root can always replace
//! the path or write the files; root is the trust anchor for both planes.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// The production path. It is deliberately below `/var/lib` (persistent,
/// not cleaned by systemd on restart) rather than `/run`.
pub(crate) const DEFAULT_LOCK_PATH: &str = "/var/lib/mikagami/control/control.lock";

#[derive(Debug)]
pub(crate) enum LockError {
    /// Another process holds the lock.
    Busy,
    /// The path or one of its attributes is not safe to use.
    Unsafe(String),
    /// The kernel refused the operation.
    Io(String),
}

impl fmt::Display for LockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Busy => formatter.write_str("the control lock is held by another process"),
            Self::Unsafe(reason) => write!(formatter, "the control lock is unsafe: {reason}"),
            Self::Io(error) => write!(formatter, "the control lock failed: {error}"),
        }
    }
}

impl std::error::Error for LockError {}

/// A held shared control lock. Dropping it releases the kernel lock.
pub(crate) struct ControlLock {
    file: File,
    /// The lock is taken on the directory *and* on the file. The directory
    /// lock is what still excludes a second controller after an accidental
    /// unlink/recreate of the file: both implementations lock the directory
    /// first, so a replacement file cannot become a second control channel.
    directory: File,
    path: PathBuf,
    /// Identity of the inode the lock was taken on. Checked against the path
    /// after `flock` and on every explicit [`Self::verify`].
    device: u64,
    inode: u64,
    directory_device: u64,
    directory_inode: u64,
    /// Test-only stand-in. It never appears in production code and holds no
    /// kernel lock; the field is private and the constructor is `cfg(test)`.
    #[cfg(test)]
    test_only: bool,
}

impl ControlLock {
    /// Acquire the lock at `path`, requiring the file and its directory to be
    /// owned by `expected_uid` (0 in production).
    pub(crate) fn acquire(path: &Path, expected_uid: u32) -> Result<Self, LockError> {
        let parent = path
            .parent()
            .ok_or_else(|| LockError::Unsafe("the lock path has no parent".to_string()))?;
        ensure_private_dir(parent, expected_uid)?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(parent)
            .map_err(|error| LockError::Io(format!("cannot open the lock directory: {error}")))?;
        let directory_metadata = directory.metadata().map_err(|error| {
            LockError::Io(format!("cannot inspect the lock directory: {error}"))
        })?;
        flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB).map_err(|error| {
            if is_would_block(&error) {
                LockError::Busy
            } else {
                LockError::Io(format!("flock(directory): {error}"))
            }
        })?;
        if !same_inode(parent, directory_metadata.dev(), directory_metadata.ino())? {
            return Err(LockError::Unsafe(
                "the lock directory was replaced while it was being acquired".to_string(),
            ));
        }
        // O_NOFOLLOW closes the symlink-at-the-final-component race; the
        // directory check above closes the symlinked-directory variant.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .mode(0o600)
            .open(path)
            .map_err(|error| map_open_error(path, error))?;
        let metadata = file
            .metadata()
            .map_err(|error| LockError::Io(format!("cannot inspect the lock file: {error}")))?;
        check_file_metadata(&metadata, expected_uid)?;
        check_local_fs(&file)?;
        // A non-blocking lock is the point: a second controller must fail
        // closed now, not queue behind the first one.
        flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB).map_err(|error| {
            if is_would_block(&error) {
                LockError::Busy
            } else {
                LockError::Io(format!("flock: {error}"))
            }
        })?;
        let device = metadata.dev();
        let inode = metadata.ino();
        if !same_inode(path, device, inode)? {
            // Releasing is implicit when `file` drops; the caller gets an
            // error and does not act.
            return Err(LockError::Unsafe(
                "the lock file was replaced while it was being acquired".to_string(),
            ));
        }
        Ok(Self {
            file,
            directory,
            path: path.to_path_buf(),
            device,
            inode,
            directory_device: directory_metadata.dev(),
            directory_inode: directory_metadata.ino(),
            #[cfg(test)]
            test_only: false,
        })
    }

    /// Re-check that the path still names the inode the lock was taken on.
    /// Called after acquisition and, by long-lived owners, before critical
    /// operations. A replacement cannot be prevented by a lock on the old
    /// inode; it is detected here.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn verify(&self) -> Result<(), LockError> {
        #[cfg(test)]
        if self.test_only {
            return Ok(());
        }
        if !same_inode(&self.path, self.device, self.inode)? {
            return Err(LockError::Unsafe(
                "the lock file was replaced after it was acquired".to_string(),
            ));
        }
        if let Some(parent) = self.path.parent()
            && !same_inode(parent, self.directory_device, self.directory_inode)?
        {
            return Err(LockError::Unsafe(
                "the lock directory was replaced after it was acquired".to_string(),
            ));
        }
        Ok(())
    }

    /// Test-only proof stand-in. The architecture guard ensures production
    /// code never names this constructor.
    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        Self {
            file: File::open("/dev/null").expect("/dev/null"),
            directory: File::open("/").expect("/"),
            path: PathBuf::from("/dev/null"),
            device: 0,
            inode: 0,
            directory_device: 0,
            directory_inode: 0,
            test_only: true,
        }
    }
}

impl Drop for ControlLock {
    fn drop(&mut self) {
        // Best effort: file drop releases the flock anyway. `LOCK_UN` makes
        // the release immediate for a lock that is about to be probed by
        // another process in the same test.
        let _ = flock(self.file.as_raw_fd(), libc::LOCK_UN);
        let _ = flock(self.directory.as_raw_fd(), libc::LOCK_UN);
    }
}

fn map_open_error(path: &Path, error: io::Error) -> LockError {
    if error.raw_os_error() == Some(libc::ELOOP) {
        LockError::Unsafe(format!("{} is a symlink", path.display()))
    } else {
        LockError::Io(format!("cannot open {}: {error}", path.display()))
    }
}

fn is_would_block(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::WouldBlock || error.raw_os_error() == Some(libc::EWOULDBLOCK)
}

fn flock(fd: i32, operation: i32) -> io::Result<()> {
    // SAFETY: `fd` is an owned descriptor for the lifetime of `self`; flock
    // only takes an integer and touches no Rust memory.
    let result = unsafe { libc::flock(fd, operation) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn check_file_metadata(metadata: &fs::Metadata, expected_uid: u32) -> Result<(), LockError> {
    if !metadata.is_file() {
        return Err(LockError::Unsafe(
            "the lock file is not a regular file".to_string(),
        ));
    }
    if metadata.uid() != expected_uid {
        return Err(LockError::Unsafe(format!(
            "the lock file is owned by uid {}, not {}",
            metadata.uid(),
            expected_uid
        )));
    }
    if metadata.nlink() != 1 {
        return Err(LockError::Unsafe(format!(
            "the lock file has {} hard links, not 1",
            metadata.nlink()
        )));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(LockError::Unsafe(format!(
            "the lock file mode is {:o}, not 0600",
            metadata.mode() & 0o777
        )));
    }
    Ok(())
}

fn check_private_dir(path: &Path, expected_uid: u32) -> Result<(), LockError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| LockError::Io(format!("cannot inspect {}: {error}", path.display())))?;
    if metadata.file_type().is_symlink() {
        return Err(LockError::Unsafe(format!(
            "the lock directory {} is a symlink",
            path.display()
        )));
    }
    if !metadata.is_dir() {
        return Err(LockError::Unsafe(format!(
            "the lock directory {} is not a directory",
            path.display()
        )));
    }
    if metadata.uid() != expected_uid {
        return Err(LockError::Unsafe(format!(
            "the lock directory {} is owned by uid {}, not {}",
            path.display(),
            metadata.uid(),
            expected_uid
        )));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(LockError::Unsafe(format!(
            "the lock directory {} is not private (mode {:o})",
            path.display(),
            metadata.mode() & 0o777
        )));
    }
    Ok(())
}

/// Create the missing components of `path` (from the nearest existing
/// ancestor down) as 0700 directories, after checking every existing ancestor
/// for a symlink, a wrong owner and group/world writability. The final
/// directory must be private (0700).
pub(crate) fn ensure_private_dir(path: &Path, expected_uid: u32) -> Result<(), LockError> {
    // Walk every existing ancestor up to `/`: a symlink or a writable
    // ancestor anywhere in the chain would make the private final directory
    // meaningless. Missing components are created only after the existing
    // chain has been checked.
    let mut missing = Vec::new();
    let mut current = Some(path);
    while let Some(component) = current {
        match fs::symlink_metadata(component) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(LockError::Unsafe(format!(
                        "the lock path component {} is a symlink",
                        component.display()
                    )));
                }
                if !metadata.is_dir() {
                    return Err(LockError::Unsafe(format!(
                        "the lock path component {} is not a directory",
                        component.display()
                    )));
                }
                // The final directory must be owned by the caller's trust
                // uid. An ancestor may also be root-owned (the normal chain
                // /var/lib/...); a user-owned ancestor is accepted only for
                // the invoking uid. A foreign owner anywhere is refused.
                let trusted_owner =
                    metadata.uid() == expected_uid || (component != path && metadata.uid() == 0);
                if !trusted_owner {
                    return Err(LockError::Unsafe(format!(
                        "the lock path component {} is owned by uid {}, not {} or root",
                        component.display(),
                        metadata.uid(),
                        expected_uid
                    )));
                }
                let writable = metadata.mode() & 0o022 != 0;
                let sticky = metadata.mode() & 0o1000 != 0;
                if writable && !sticky {
                    return Err(LockError::Unsafe(format!(
                        "the lock path component {} is group/world writable without the sticky bit",
                        component.display()
                    )));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                missing.push(component.to_path_buf());
            }
            Err(error) => {
                return Err(LockError::Io(format!(
                    "cannot inspect {}: {error}",
                    component.display()
                )));
            }
        }
        let parent = component.parent();
        if parent == Some(component) {
            break;
        }
        current = parent;
    }
    for directory in missing.iter().rev() {
        let mut builder = fs::DirBuilder::new();
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(directory).map_err(|error| {
            LockError::Io(format!(
                "cannot create the lock directory {}: {error}",
                directory.display()
            ))
        })?;
        check_private_dir(directory, expected_uid)?;
    }
    check_private_dir(path, expected_uid)
}

fn same_inode(path: &Path, device: u64, inode: u64) -> Result<bool, LockError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        LockError::Unsafe(format!(
            "the lock path {} cannot be checked: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() {
        return Err(LockError::Unsafe(format!(
            "the lock path {} became a symlink",
            path.display()
        )));
    }
    Ok(metadata.dev() == device && metadata.ino() == inode)
}

#[cfg(target_os = "linux")]
pub(crate) fn check_local_fs(file: &File) -> Result<(), LockError> {
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: `stat` is a valid, writable `statfs`; the descriptor is owned
    // by `file` for the call.
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut stat) } != 0 {
        return Err(LockError::Io(format!(
            "cannot inspect the lock filesystem: {}",
            io::Error::last_os_error()
        )));
    }
    if !is_local_filesystem(stat.f_type as u64) {
        return Err(LockError::Unsafe(format!(
            "the lock file is on a non-local filesystem (type 0x{:x})",
            stat.f_type
        )));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn check_local_fs(_file: &File) -> Result<(), LockError> {
    // The production daemon and agent are Linux-only. Unit tests on the
    // development host still exercise the path/ownership/inode checks.
    Ok(())
}

/// Filesystem magic values that cannot provide a reliable local flock (or
/// whose semantics are not the local kernel's). Kept as a pure function so it
/// is testable on every host.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn is_local_filesystem(magic: u64) -> bool {
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
            "mkg-control-lock-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn uid() -> u32 {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() }
    }

    #[test]
    fn a_second_acquire_is_busy_and_drop_releases_it() {
        let dir = temp_dir("busy");
        let path = dir.join("control.lock");
        let first = ControlLock::acquire(&path, uid()).unwrap();
        assert!(matches!(
            ControlLock::acquire(&path, uid()),
            Err(LockError::Busy)
        ));
        drop(first);
        let again = ControlLock::acquire(&path, uid()).unwrap();
        drop(again);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_symlink_to_an_unrelated_file_is_refused() {
        let dir = temp_dir("symlink");
        let target = dir.join("target");
        fs::write(&target, b"").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let path = dir.join("control.lock");
        symlink(&target, &path).unwrap();
        assert!(matches!(
            ControlLock::acquire(&path, uid()),
            Err(LockError::Unsafe(_))
        ));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_symlinked_ancestor_is_refused_even_when_the_final_directory_exists() {
        let dir = temp_dir("symlink-existing-final");
        let real = dir.join("real");
        let control = real.join("control");
        fs::create_dir_all(&control).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&control, fs::Permissions::from_mode(0o700)).unwrap();
        let alias = dir.join("alias");
        symlink(&real, &alias).unwrap();
        assert!(matches!(
            ControlLock::acquire(&alias.join("control").join("control.lock"), uid()),
            Err(LockError::Unsafe(_))
        ));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_symlinked_parent_directory_is_refused() {
        let dir = temp_dir("symlink-dir");
        let real = dir.join("real");
        fs::create_dir(&real).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        let alias = dir.join("alias");
        symlink(&real, &alias).unwrap();
        assert!(matches!(
            ControlLock::acquire(&alias.join("control.lock"), uid()),
            Err(LockError::Unsafe(_))
        ));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_hard_link_or_a_wrong_mode_is_refused() {
        let dir = temp_dir("attrs");
        let path = dir.join("control.lock");
        fs::write(&path, b"").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&path, dir.join("second-name")).unwrap();
        assert!(matches!(
            ControlLock::acquire(&path, uid()),
            Err(LockError::Unsafe(_))
        ));
        fs::remove_file(dir.join("second-name")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            ControlLock::acquire(&path, uid()),
            Err(LockError::Unsafe(_))
        ));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_wrong_owner_is_refused() {
        let dir = temp_dir("owner");
        let path = dir.join("control.lock");
        fs::write(&path, b"").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            ControlLock::acquire(&path, uid().wrapping_add(1)),
            Err(LockError::Unsafe(_))
        ));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_replaced_inode_is_detected_after_acquisition() {
        let dir = temp_dir("inode");
        let path = dir.join("control.lock");
        let lock = ControlLock::acquire(&path, uid()).unwrap();
        lock.verify().unwrap();
        fs::rename(&path, dir.join("old")).unwrap();
        fs::write(&path, b"").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(lock.verify(), Err(LockError::Unsafe(_))));
        drop(lock);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_replaced_directory_is_detected_after_acquisition() {
        let dir = temp_dir("dir-inode");
        let control = dir.join("control");
        let path = control.join("control.lock");
        let lock = ControlLock::acquire(&path, uid()).unwrap();
        lock.verify().unwrap();
        fs::rename(&control, dir.join("control.old")).unwrap();
        fs::create_dir(&control).unwrap();
        fs::set_permissions(&control, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&path, b"").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            matches!(lock.verify(), Err(LockError::Unsafe(_))),
            "a replaced directory must be detected"
        );
        drop(lock);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_directory_created_by_the_lock_is_private() {
        let dir = temp_dir("private");
        let path = dir.join("nested").join("control.lock");
        let lock = ControlLock::acquire(&path, uid()).unwrap();
        let mode = fs::metadata(path.parent().unwrap()).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o700);
        drop(lock);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn non_local_filesystem_magics_are_refused() {
        assert!(is_local_filesystem(0xef53)); // ext4
        assert!(is_local_filesystem(0x0102_1994)); // tmpfs
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

    #[cfg(target_os = "linux")]
    #[test]
    fn the_descriptor_is_close_on_exec() {
        let dir = temp_dir("cloexec");
        let path = dir.join("control.lock");
        let lock = ControlLock::acquire(&path, uid()).unwrap();
        let fd = lock.file.as_raw_fd();
        let status = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("test ! -e /proc/self/fd/{fd}"))
            .status()
            .unwrap();
        assert!(status.success(), "fd {fd} survived exec");
        drop(lock);
        fs::remove_dir_all(dir).unwrap();
    }
}
