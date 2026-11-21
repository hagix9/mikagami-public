//! Small filesystem helpers with explicit symlink / ownership discipline.

use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Flush a directory entry change (create/rename/unlink) to stable storage.
pub(crate) fn fsync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Create a new file that must not exist yet, never following a symlink at
/// the final component, with the final mode set before any data is written.
pub(crate) fn create_new(path: &Path, mode: u32) -> io::Result<File> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(mode)
        .open(path)?;
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    Ok(file)
}

/// Create `path` exclusively, write all bytes, flush to disk and fsync the
/// parent directory. If the file was created by this call and a later step
/// fails, the partial file is removed; a file that already existed is never
/// touched (the exclusive create fails first).
pub(crate) fn write_new_durable(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let mut file = create_new(path, mode)?;
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        if let Some(parent) = path.parent() {
            fsync_dir(parent)?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(path);
    }
    result
}

/// Read a regular file without following a symlink at the final component.
/// Anything larger than `max` bytes is an error, not a truncated read.
pub(crate) fn read_regular_nofollow(path: &Path, max: u64) -> io::Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    if metadata.len() > max {
        return Err(io::Error::other("file too large"));
    }
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(io::Error::other("file too large"));
    }
    Ok(bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TrustError {
    NotFound,
    Symlink,
    NotRegular,
    NotDirectory,
    WrongOwner,
    Writable,
    Io,
}

impl std::fmt::Display for TrustError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotFound => "missing",
            Self::Symlink => "is a symlink",
            Self::NotRegular => "is not a regular file",
            Self::NotDirectory => "is not a directory",
            Self::WrongOwner => "has an untrusted owner",
            Self::Writable => "is group/world writable",
            Self::Io => "could not be inspected",
        })
    }
}

fn map_io(error: &io::Error) -> TrustError {
    if error.kind() == io::ErrorKind::NotFound {
        TrustError::NotFound
    } else {
        TrustError::Io
    }
}

/// A trusted file: regular, not a symlink, owned by `owner_uid`, and not
/// group/world writable.
pub(crate) fn check_trusted_file(path: &Path, owner_uid: u32) -> Result<(), TrustError> {
    let metadata = fs::symlink_metadata(path).map_err(|e| map_io(&e))?;
    if metadata.file_type().is_symlink() {
        return Err(TrustError::Symlink);
    }
    if !metadata.is_file() {
        return Err(TrustError::NotRegular);
    }
    if metadata.uid() != owner_uid {
        return Err(TrustError::WrongOwner);
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(TrustError::Writable);
    }
    Ok(())
}

/// A trusted directory: a real directory (not a symlink), owned by
/// `owner_uid`, not group/world writable.
pub(crate) fn check_trusted_dir(path: &Path, owner_uid: u32) -> Result<(), TrustError> {
    let metadata = fs::symlink_metadata(path).map_err(|e| map_io(&e))?;
    if metadata.file_type().is_symlink() {
        return Err(TrustError::Symlink);
    }
    if !metadata.is_dir() {
        return Err(TrustError::NotDirectory);
    }
    if metadata.uid() != owner_uid {
        return Err(TrustError::WrongOwner);
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(TrustError::Writable);
    }
    Ok(())
}

/// Create a private directory (mode 0700) if it does not exist yet, then
/// require it to be trusted.
pub(crate) fn ensure_private_dir(path: &Path, owner_uid: u32) -> Result<(), TrustError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
            builder
                .recursive(true)
                .create(path)
                .map_err(|_| TrustError::Io)?;
        }
        Err(_) => return Err(TrustError::Io),
    }
    check_trusted_dir(path, owner_uid)
}

// ---------------------------------------------------------------------------
// atomic exchange (audit D-02)
// ---------------------------------------------------------------------------

#[cfg(test)]
thread_local! {
    /// A test can force the "this filesystem cannot exchange" fallback.
    pub(crate) static EXCHANGE_UNSUPPORTED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// A test can make the n-th (1-based) call of [`exchange`] since
    /// [`EXCHANGE_CALLS`] was last reset fail with an I/O error (EIO) before
    /// anything happens: the "put back" exchange of a publish.
    pub(crate) static EXCHANGE_FAIL_AT: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    pub(crate) static EXCHANGE_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Atomically swap two directory entries (Linux `renameat2` with
/// `RENAME_EXCHANGE`). `Err` of kind `Unsupported` means the platform or the
/// filesystem cannot do it and nothing happened; the caller decides whether
/// to fall back. NOT VERIFIED on a real Linux host (development host is not
/// Linux); the surrounding logic is covered by an emulation in tests.
pub(crate) fn exchange(a: &Path, b: &Path) -> io::Result<()> {
    #[cfg(test)]
    if EXCHANGE_UNSUPPORTED.with(std::cell::Cell::get) {
        return Err(io::Error::from(io::ErrorKind::Unsupported));
    }
    #[cfg(test)]
    {
        let call = EXCHANGE_CALLS.with(|c| {
            c.set(c.get() + 1);
            c.get()
        });
        if EXCHANGE_FAIL_AT.with(std::cell::Cell::get) == Some(call) {
            return Err(io::Error::from_raw_os_error(5));
        }
    }
    exchange_impl(a, b)
}

#[cfg(target_os = "linux")]
fn exchange_impl(a: &Path, b: &Path) -> io::Result<()> {
    const RENAME_EXCHANGE: libc::c_uint = 2;
    renameat2(a, b, RENAME_EXCHANGE)
}

/// `renameat2(2)` with `flags`; `ENOSYS`, `EINVAL` and `ENOTSUP` (the kernel
/// or the filesystem does not know the flag) are reported as `Unsupported`
/// with nothing done; every other error is returned as it is.
#[cfg(target_os = "linux")]
fn renameat2(a: &Path, b: &Path, flags: libc::c_uint) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let to_c = |p: &Path| {
        CString::new(p.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
    };
    let (ca, cb) = (to_c(a)?, to_c(b)?);
    // SAFETY: both pointers are valid NUL-terminated strings for the call.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            ca.as_ptr(),
            libc::AT_FDCWD,
            cb.as_ptr(),
            flags,
        )
    };
    if rc == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ENOSYS | libc::EINVAL | libc::ENOTSUP) => {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
        _ => Err(error),
    }
}

#[cfg(all(not(target_os = "linux"), test))]
fn exchange_impl(a: &Path, b: &Path) -> io::Result<()> {
    let mut tmp = a.as_os_str().to_os_string();
    tmp.push(".exchange-tmp");
    let tmp = PathBuf::from(tmp);
    fs::rename(a, &tmp)?;
    fs::rename(b, a)?;
    fs::rename(&tmp, b)
}

#[cfg(all(not(target_os = "linux"), not(test)))]
fn exchange_impl(_a: &Path, _b: &Path) -> io::Result<()> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

// ---------------------------------------------------------------------------
// names that never replace anything (final R7, R-3)
// ---------------------------------------------------------------------------

#[cfg(test)]
thread_local! {
    /// A test can make [`link_new`] fail with this errno (a filesystem that
    /// refuses hard links: `EPERM`, `EMLINK`, `EXDEV`).
    pub(crate) static LINK_FAIL: std::cell::Cell<Option<i32>> = const { std::cell::Cell::new(None) };
    /// Like [`LINK_FAIL`], but only the next call fails (a transient error).
    pub(crate) static LINK_FAIL_ONCE: std::cell::Cell<Option<i32>> = const { std::cell::Cell::new(None) };
    /// A test can make [`rename_noreplace`] fail: `Some(None)` is
    /// "unsupported", `Some(Some(errno))` an I/O error.
    pub(crate) static NOREPLACE_FAIL: std::cell::Cell<Option<Option<i32>>> = const { std::cell::Cell::new(None) };
    /// A test can make the plain rename of the last resort fail with an errno.
    pub(crate) static PLAIN_RENAME_FAIL: std::cell::Cell<Option<i32>> = const { std::cell::Cell::new(None) };
}

/// A second name for the file `from`. It fails with `AlreadyExists` when `to`
/// exists (a file, a directory, a link): an existing name is never replaced.
pub(crate) fn link_new(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(test)]
    if let Some(code) = LINK_FAIL.with(std::cell::Cell::get) {
        return Err(io::Error::from_raw_os_error(code));
    }
    #[cfg(test)]
    if let Some(code) = LINK_FAIL_ONCE.with(std::cell::Cell::take) {
        return Err(io::Error::from_raw_os_error(code));
    }
    fs::hard_link(from, to)
}

/// Move `from` to `to` **only if `to` does not exist** (Linux `renameat2` with
/// `RENAME_NOREPLACE`, atomic); `AlreadyExists` otherwise. `Unsupported` means
/// that the platform or the filesystem cannot do it and nothing happened. It
/// needs no support for hard links, which is why it is the second way of
/// keeping a displaced version. NOT VERIFIED on a real Linux host before the
/// R7 hardware tests.
pub(crate) fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(test)]
    match NOREPLACE_FAIL.with(std::cell::Cell::get) {
        Some(None) => return Err(io::Error::from(io::ErrorKind::Unsupported)),
        Some(Some(code)) => return Err(io::Error::from_raw_os_error(code)),
        None => {}
    }
    rename_noreplace_impl(from, to)
}

#[cfg(target_os = "linux")]
fn rename_noreplace_impl(from: &Path, to: &Path) -> io::Result<()> {
    const RENAME_NOREPLACE: libc::c_uint = 1;
    renameat2(from, to, RENAME_NOREPLACE)
}

/// The development hosts that are not Linux have no such call; the tests use
/// a link followed by the removal of the old name (it also never replaces).
#[cfg(all(not(target_os = "linux"), test))]
fn rename_noreplace_impl(from: &Path, to: &Path) -> io::Result<()> {
    fs::hard_link(from, to)?;
    fs::remove_file(from)
}

#[cfg(all(not(target_os = "linux"), not(test)))]
fn rename_noreplace_impl(_from: &Path, _to: &Path) -> io::Result<()> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

/// The last resort when the kernel cannot do [`rename_noreplace`]: a plain
/// rename to a name that does not exist at the moment. Not atomic against a
/// writer that creates exactly this name in between; the caller uses a name
/// that nobody else knows and holds the lock of the operation.
pub(crate) fn rename_to_absent_name(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(test)]
    if let Some(code) = PLAIN_RENAME_FAIL.with(std::cell::Cell::get) {
        return Err(io::Error::from_raw_os_error(code));
    }
    match fs::symlink_metadata(to) {
        Ok(_) => Err(io::Error::from(io::ErrorKind::AlreadyExists)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => fs::rename(from, to),
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------------------
// file attributes (audit D-03)
// ---------------------------------------------------------------------------

/// What was carried from the live file to its replacement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Attributes {
    pub(crate) mode: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    /// Extended attributes carried (ACLs and `security.selinux` included).
    pub(crate) xattrs: usize,
    /// Whether this build can carry extended attributes at all.
    pub(crate) xattrs_supported: bool,
}

impl Attributes {
    pub(crate) fn mode_text(&self) -> String {
        format!("{:04o}", self.mode)
    }
}

fn open_nofollow(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
mod xattr {
    use std::fs::File;
    use std::io;
    use std::os::fd::AsRawFd;

    pub(super) type Pairs = Vec<(Vec<u8>, Vec<u8>)>;

    pub(super) fn list(file: &File) -> io::Result<Pairs> {
        let fd = file.as_raw_fd();
        // SAFETY: size query with a null buffer.
        let size = unsafe { libc::flistxattr(fd, std::ptr::null_mut(), 0) };
        if size < 0 {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(libc::ENOTSUP) {
                Ok(Vec::new())
            } else {
                Err(error)
            };
        }
        let mut names = vec![0u8; size as usize];
        if size > 0 {
            // SAFETY: the buffer is `size` bytes long.
            let got = unsafe { libc::flistxattr(fd, names.as_mut_ptr().cast(), names.len()) };
            if got < 0 {
                return Err(io::Error::last_os_error());
            }
            names.truncate(got as usize);
        }
        let mut out = Vec::new();
        for name in names.split(|b| *b == 0).filter(|n| !n.is_empty()) {
            let mut c_name = name.to_vec();
            c_name.push(0);
            // SAFETY: NUL-terminated name, null buffer for the size query.
            let vsize =
                unsafe { libc::fgetxattr(fd, c_name.as_ptr().cast(), std::ptr::null_mut(), 0) };
            if vsize < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut value = vec![0u8; vsize as usize];
            if vsize > 0 {
                // SAFETY: the buffer is `vsize` bytes long.
                let got = unsafe {
                    libc::fgetxattr(
                        fd,
                        c_name.as_ptr().cast(),
                        value.as_mut_ptr().cast(),
                        value.len(),
                    )
                };
                if got < 0 {
                    return Err(io::Error::last_os_error());
                }
                value.truncate(got as usize);
            }
            out.push((name.to_vec(), value));
        }
        out.sort();
        Ok(out)
    }

    pub(super) fn set(file: &File, name: &[u8], value: &[u8]) -> io::Result<()> {
        let mut c_name = name.to_vec();
        c_name.push(0);
        // SAFETY: NUL-terminated name; the value pointer/length pair is valid.
        let rc = unsafe {
            libc::fsetxattr(
                file.as_raw_fd(),
                c_name.as_ptr().cast(),
                value.as_ptr().cast(),
                value.len(),
                0,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub(super) fn remove(file: &File, name: &[u8]) -> io::Result<()> {
        let mut c_name = name.to_vec();
        c_name.push(0);
        // SAFETY: NUL-terminated name.
        let rc = unsafe { libc::fremovexattr(file.as_raw_fd(), c_name.as_ptr().cast()) };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

/// Make `to` carry the owner, group, mode and (on Linux) the extended
/// attributes of `from`, then verify that it does. Used for the file that is
/// about to replace the live configuration, so that an `0640 root:chrony`
/// file with an SELinux label stays that way (audit D-03). Any difference
/// that remains afterwards is an error.
/// Give `target` the owner and group `wanted` when it does not have them
/// already. `chown` is the system call (a parameter so that a test can see
/// that it is made: with a single-user test account the owners are always
/// equal and a missing call went unnoticed, audit RA-D-03).
fn ensure_owner(
    target: &File,
    have: (u32, u32),
    wanted: (u32, u32),
    chown: &dyn Fn(&File, u32, u32) -> io::Result<()>,
) -> Result<(), String> {
    if have != wanted {
        chown(target, wanted.0, wanted.1)
            .map_err(|e| format!("cannot set the owner {}:{}: {e}", wanted.0, wanted.1))?;
    }
    Ok(())
}

pub(crate) fn copy_attributes(from: &Path, to: &Path) -> Result<Attributes, String> {
    let source = open_nofollow(from).map_err(|e| format!("cannot open {}: {e}", from.display()))?;
    let target = open_nofollow(to).map_err(|e| format!("cannot open {}: {e}", to.display()))?;
    let wanted = source.metadata().map_err(|e| e.to_string())?;
    let have = target.metadata().map_err(|e| e.to_string())?;
    ensure_owner(
        &target,
        (have.uid(), have.gid()),
        (wanted.uid(), wanted.gid()),
        &|file, uid, gid| std::os::unix::fs::fchown(file, Some(uid), Some(gid)),
    )?;
    let mode = wanted.mode() & 0o7777;
    // After the ownership change: a chown may clear the set-id bits.
    target
        .set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|e| format!("cannot set the mode {mode:04o}: {e}"))?;
    #[allow(unused_mut)]
    let mut carried = 0usize;
    #[allow(unused_mut)]
    let mut supported = false;
    #[cfg(target_os = "linux")]
    {
        supported = true;
        let want = xattr::list(&source).map_err(|e| format!("cannot read xattrs: {e}"))?;
        let present = xattr::list(&target).map_err(|e| format!("cannot read xattrs: {e}"))?;
        for (name, _) in &present {
            if !want.iter().any(|(n, _)| n == name) {
                xattr::remove(&target, name).map_err(|e| {
                    format!("cannot remove xattr {}: {e}", String::from_utf8_lossy(name))
                })?;
            }
        }
        for (name, value) in &want {
            xattr::set(&target, name, value).map_err(|e| {
                format!("cannot carry xattr {}: {e}", String::from_utf8_lossy(name))
            })?;
        }
        let after = xattr::list(&target).map_err(|e| format!("cannot re-read xattrs: {e}"))?;
        if after != want {
            return Err("the extended attributes differ after copying".to_string());
        }
        carried = want.len();
    }
    target.sync_all().map_err(|e| e.to_string())?;
    let now = target.metadata().map_err(|e| e.to_string())?;
    if now.uid() != wanted.uid() || now.gid() != wanted.gid() || now.mode() & 0o7777 != mode {
        return Err(format!(
            "owner/mode differ after copying (wanted {}:{} {mode:04o}, found {}:{} {:04o})",
            wanted.uid(),
            wanted.gid(),
            now.uid(),
            now.gid(),
            now.mode() & 0o7777
        ));
    }
    Ok(Attributes {
        mode,
        uid: wanted.uid(),
        gid: wanted.gid(),
        xattrs: carried,
        xattrs_supported: supported,
    })
}

// ---------------------------------------------------------------------------
// control-host trust checks (audit E-02)
// ---------------------------------------------------------------------------

fn owner_ok(uid: u32, euid: u32) -> bool {
    uid == 0 || uid == euid
}

/// A directory the control host may rely on: owned by root or the invoking
/// user, and not writable by group/others (a root-owned sticky directory is
/// tolerated as an ancestor only).
fn ancestor_ok(metadata: &fs::Metadata, euid: u32) -> bool {
    owner_ok(metadata.uid(), euid)
        && (metadata.mode() & 0o022 == 0 || (metadata.uid() == 0 && metadata.mode() & 0o1000 != 0))
}

/// The directory that holds `path`: owned by root or the invoking user and
/// not group/world writable. Only this one directory is checked, not the
/// whole chain up to `/` (a volume mount point such as `/Volumes/<name>` is
/// group-writable on a typical workstation); see LIMITATIONS.
fn check_parent(path: &Path, euid: u32) -> Result<(), String> {
    let Some(dir) = path.parent() else {
        return Ok(());
    };
    let metadata = fs::metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if !metadata.is_dir() || !ancestor_ok(&metadata, euid) {
        return Err(format!(
            "directory {} is not owned by root or the invoking user, or is group/world writable",
            dir.display()
        ));
    }
    Ok(())
}

/// The control configuration decides which programs run with the operator's
/// rights, so it is held to the agent's standard: a regular file (no
/// symlink), owned by root or the invoking user, not group/world writable,
/// in a directory that nobody else can write, and small. Returns its
/// bytes.
pub(crate) fn read_trusted_control_file(
    path: &Path,
    max: u64,
    euid: u32,
) -> Result<Vec<u8>, String> {
    let linked = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if linked.file_type().is_symlink() {
        return Err("is a symlink".to_string());
    }
    if !linked.is_file() {
        return Err("is not a regular file".to_string());
    }
    let file = open_nofollow(path).map_err(|e| e.to_string())?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !owner_ok(metadata.uid(), euid) {
        return Err("is owned by somebody other than root or the invoking user".to_string());
    }
    if metadata.mode() & 0o022 != 0 {
        return Err("is group/world writable".to_string());
    }
    check_parent(path, euid)?;
    if metadata.len() > max {
        return Err(format!("is larger than {max} bytes"));
    }
    let mut bytes = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > max {
        return Err(format!("is larger than {max} bytes"));
    }
    Ok(bytes)
}

/// A program the control host will run (`ssh`, `gcloud`): regular, executable,
/// owned by root or the invoking user, not group/world writable, and so is
/// the directory that holds it. A symlink is followed once (package managers
/// install tools that way) and both the link's directory and the
/// resolved target (with its directory) are checked.
pub(crate) fn check_tool_trust(path: &Path, euid: u32) -> Result<(), String> {
    check_parent(path, euid)?;
    let linked = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if linked.file_type().is_symlink() && !owner_ok(linked.uid(), euid) {
        return Err("is a symlink owned by somebody else".to_string());
    }
    let resolved = fs::canonicalize(path).map_err(|e| e.to_string())?;
    let metadata = fs::metadata(&resolved).map_err(|e| e.to_string())?;
    if !metadata.is_file() {
        return Err("is not a regular file".to_string());
    }
    if metadata.mode() & 0o111 == 0 {
        return Err("is not executable".to_string());
    }
    if !owner_ok(metadata.uid(), euid) {
        return Err("is owned by somebody other than root or the invoking user".to_string());
    }
    if metadata.mode() & 0o022 != 0 {
        return Err("is group/world writable".to_string());
    }
    check_parent(&resolved, euid)
}

/// Exclusive lock of one state store, held until dropped.
///
/// Two `flock`s are taken: one on the (trusted, private) state *directory*
/// and one on `<state>.lock` inside it. The directory lock is the one that
/// matters: unlinking or replacing the lock file while a critical section is
/// running cannot admit a second holder (round-1 audit, B-03), because the
/// directory inode stays the same. The lock file lock is kept for tools that
/// only know the old protocol; its identity is verified after the lock is
/// obtained (`fstat` against `stat`).
pub(crate) struct StoreLock {
    _dir: File,
    _file: File,
}

fn same_inode(file: &File, path: &Path) -> io::Result<bool> {
    let a = file.metadata()?;
    let b = fs::symlink_metadata(path)?;
    Ok(a.dev() == b.dev() && a.ino() == b.ino() && !b.file_type().is_symlink())
}

fn lock_with_wait(file: &File, wait: Duration, what: &str) -> Result<(), String> {
    let started = Instant::now();
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(()),
            Err(fs::TryLockError::WouldBlock) => {
                if started.elapsed() >= wait {
                    return Err(format!("{what} busy"));
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(fs::TryLockError::Error(e)) => return Err(format!("{what}: {e}")),
        }
    }
}

impl StoreLock {
    pub(crate) fn acquire(state: &Path, owner_uid: u32, wait: Duration) -> Result<Self, String> {
        let dir: PathBuf = state
            .parent()
            .ok_or_else(|| "state path has no parent".to_string())?
            .to_path_buf();
        ensure_private_dir(&dir, owner_uid)
            .map_err(|e| format!("state directory {}: {e}", dir.display()))?;
        let dir_file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&dir)
            .map_err(|e| format!("state directory: {e}"))?;
        lock_with_wait(&dir_file, wait, "state directory lock")?;
        if !same_inode(&dir_file, &dir).map_err(|e| format!("state directory: {e}"))? {
            return Err("state directory was replaced while locking".to_string());
        }
        let mut name = state
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_default();
        name.push(".lock");
        let lock_path = state.with_file_name(name);
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(&lock_path)
            .map_err(|e| format!("lock file: {e}"))?;
        lock_with_wait(&file, wait, "lock file")?;
        if !same_inode(&file, &lock_path).map_err(|e| format!("lock file: {e}"))? {
            return Err("lock file was replaced while locking".to_string());
        }
        Ok(Self {
            _dir: dir_file,
            _file: file,
        })
    }
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        let _ = self._file.unlock();
        let _ = self._dir.unlock();
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    pub(crate) fn temp_dir(label: &str) -> std::path::PathBuf {
        let base = std::env::var_os("TMPDIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .canonicalize()
            .unwrap_or_else(|_| std::env::temp_dir());
        let dir = base.join(format!(
            "mkg-test-{label}-{}",
            crate::manual::proto::random_hex(6)
        ));
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    pub(crate) fn my_uid() -> u32 {
        fs::metadata(std::env::temp_dir())
            .map(|_| unsafe { libc::geteuid() })
            .unwrap()
    }

    #[test]
    fn ra_b06_a_state_directory_replaced_while_the_lock_was_awaited_is_refused() {
        // Mutant M11 of the audit: the identity of the directory is checked
        // after its lock is obtained. Holder A keeps the lock; B opens the
        // directory and waits; the directory is renamed away and a new one
        // created at the same path; A lets go. B then holds a lock on a
        // directory that is no longer the state directory and must say so.
        let base = temp_dir("lock-replaced");
        let state = base.join("state").join("record.json");
        fs::create_dir_all(state.parent().unwrap()).unwrap();
        fs::set_permissions(state.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = my_uid();
        let holder = StoreLock::acquire(&state, uid, Duration::from_secs(2)).unwrap();
        let waiting_state = state.clone();
        let waiter = std::thread::spawn(move || {
            StoreLock::acquire(&waiting_state, uid, Duration::from_secs(10)).map(|_| ())
        });
        std::thread::sleep(Duration::from_millis(400));
        let dir = state.parent().unwrap().to_path_buf();
        fs::rename(&dir, base.join("state.old")).unwrap();
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        drop(holder);
        let result = waiter.join().unwrap();
        assert!(
            matches!(&result, Err(m) if m.contains("replaced while locking")),
            "{result:?}"
        );
        // Without a replacement the same wait succeeds (the check is not a
        // blanket refusal).
        let again = StoreLock::acquire(&state, uid, Duration::from_secs(2));
        assert!(again.is_ok());
        drop(again);
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn ra_d03_the_owner_of_the_source_is_given_to_the_target_with_a_system_call() {
        // Mutant M07 of the audit removed the `fchown`: with one test account
        // the owners are always equal and nothing noticed. The call is a
        // parameter of `ensure_owner`, so the decision is observable.
        let dir = temp_dir("ensure-owner");
        let file = File::create(dir.join("t")).unwrap();
        let calls = std::cell::RefCell::new(Vec::new());
        let record = |_: &File, uid: u32, gid: u32| {
            calls.borrow_mut().push((uid, gid));
            Ok(())
        };
        // Different owner or group: the call is made, with the wanted ids.
        ensure_owner(&file, (0, 0), (33, 44), &record).unwrap();
        ensure_owner(&file, (33, 0), (33, 44), &record).unwrap();
        ensure_owner(&file, (0, 44), (33, 44), &record).unwrap();
        assert_eq!(*calls.borrow(), [(33, 44), (33, 44), (33, 44)]);
        // Already right: no call.
        ensure_owner(&file, (33, 44), (33, 44), &record).unwrap();
        assert_eq!(calls.borrow().len(), 3);
        // A refusal of the system call is an error that names the owner.
        let deny = |_: &File, _: u32, _: u32| Err(io::Error::from_raw_os_error(1));
        let r = ensure_owner(&file, (0, 0), (33, 44), &deny);
        assert!(matches!(&r, Err(m) if m.contains("33:44")), "{r:?}");
        // The real call, on a file of the test account: a no-op change that
        // succeeds.
        let me = fs::metadata(dir.join("t")).unwrap();
        ensure_owner(
            &file,
            (u32::MAX, u32::MAX),
            (me.uid(), me.gid()),
            &|f, u, g| std::os::unix::fs::fchown(f, Some(u), Some(g)),
        )
        .unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn sha256_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(is_sha256_hex(&sha256_hex(b"")));
        assert!(!is_sha256_hex("ABC"));
    }

    #[test]
    fn create_new_refuses_existing_file_and_symlink() {
        let dir = temp_dir("fsutil-create");
        let path = dir.join("f");
        write_new_durable(&path, b"one", 0o600).unwrap();
        assert!(write_new_durable(&path, b"two", 0o600).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"one");
        let link = dir.join("l");
        symlink(&path, &link).unwrap();
        assert!(write_new_durable(&link, b"x", 0o600).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"one");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_regular_nofollow_rejects_symlink_oversize_and_non_regular() {
        let dir = temp_dir("fsutil-read");
        let path = dir.join("f");
        fs::write(&path, b"abcdef").unwrap();
        assert_eq!(read_regular_nofollow(&path, 6).unwrap(), b"abcdef");
        assert!(read_regular_nofollow(&path, 5).is_err());
        let link = dir.join("l");
        symlink(&path, &link).unwrap();
        assert!(read_regular_nofollow(&link, 100).is_err());
        assert!(read_regular_nofollow(&dir, 100).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn trust_checks_classify_symlink_owner_and_mode() {
        let dir = temp_dir("fsutil-trust");
        let file = dir.join("f");
        fs::write(&file, b"x").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        let me = my_uid();
        assert_eq!(check_trusted_file(&file, me), Ok(()));
        assert_eq!(
            check_trusted_file(&file, me + 1),
            Err(TrustError::WrongOwner)
        );
        fs::set_permissions(&file, fs::Permissions::from_mode(0o664)).unwrap();
        assert_eq!(check_trusted_file(&file, me), Err(TrustError::Writable));
        let link = dir.join("l");
        symlink(&file, &link).unwrap();
        assert_eq!(check_trusted_file(&link, me), Err(TrustError::Symlink));
        assert_eq!(
            check_trusted_file(&dir.join("nope"), me),
            Err(TrustError::NotFound)
        );
        assert_eq!(check_trusted_dir(&dir, me), Ok(()));
        assert_eq!(check_trusted_dir(&file, me), Err(TrustError::NotDirectory));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn exchange_swaps_two_files_or_reports_unsupported() {
        let dir = temp_dir("fsutil-exchange");
        let (a, b) = (dir.join("a"), dir.join("b"));
        fs::write(&a, "one").unwrap();
        fs::write(&b, "two").unwrap();
        match exchange(&a, &b) {
            Ok(()) => {
                assert_eq!(fs::read_to_string(&a).unwrap(), "two");
                assert_eq!(fs::read_to_string(&b).unwrap(), "one");
            }
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::Unsupported, "{e}"),
        }
        EXCHANGE_UNSUPPORTED.with(|f| f.set(true));
        let forced = exchange(&a, &b);
        EXCHANGE_UNSUPPORTED.with(|f| f.set(false));
        assert_eq!(forced.unwrap_err().kind(), io::ErrorKind::Unsupported);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// Runs only on Linux, where the real `renameat2` is used. NOT EXECUTED
    /// in the development environment (macOS); compiled for Linux with
    /// `cargo check --target x86_64-unknown-linux-gnu --tests`.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_renameat2_exchange_is_atomic_and_keeps_both_inodes() {
        let dir = temp_dir("fsutil-exchange-linux");
        let (a, b) = (dir.join("a"), dir.join("b"));
        fs::write(&a, "one").unwrap();
        fs::write(&b, "two").unwrap();
        let (ia, ib) = (
            fs::metadata(&a).unwrap().ino(),
            fs::metadata(&b).unwrap().ino(),
        );
        exchange(&a, &b).expect("tmpfs/ext4/xfs support RENAME_EXCHANGE");
        assert_eq!(fs::metadata(&a).unwrap().ino(), ib);
        assert_eq!(fs::metadata(&b).unwrap().ino(), ia);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn copy_attributes_carries_the_mode_and_refuses_what_is_not_a_regular_file() {
        let dir = temp_dir("fsutil-attrs");
        let (from, to) = (dir.join("from"), dir.join("to"));
        fs::write(&from, "a").unwrap();
        fs::write(&to, "b").unwrap();
        fs::set_permissions(&from, fs::Permissions::from_mode(0o640)).unwrap();
        fs::set_permissions(&to, fs::Permissions::from_mode(0o644)).unwrap();
        let carried = copy_attributes(&from, &to).unwrap();
        assert_eq!(carried.mode, 0o640);
        assert_eq!(carried.mode_text(), "0640");
        assert_eq!(fs::metadata(&to).unwrap().mode() & 0o7777, 0o640);
        let link = dir.join("link");
        symlink(&from, &link).unwrap();
        assert!(copy_attributes(&from, &link).is_err());
        assert!(copy_attributes(&dir, &to).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn control_files_and_tools_are_held_to_a_trust_standard() {
        let dir = temp_dir("fsutil-control");
        let me = my_uid();
        let file = dir.join("c.toml");
        fs::write(&file, "x = 1\n").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_trusted_control_file(&file, 64, me).unwrap(),
            b"x = 1\n"
        );
        // too large
        assert!(
            read_trusted_control_file(&file, 3, me)
                .unwrap_err()
                .contains("larger")
        );
        // group/world writable
        fs::set_permissions(&file, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(
            read_trusted_control_file(&file, 64, me)
                .unwrap_err()
                .contains("writable")
        );
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        // somebody else's file (only meaningful when the tests do not run as root)
        if me != 0 {
            assert!(
                read_trusted_control_file(&file, 64, me + 7)
                    .unwrap_err()
                    .contains("owned by somebody")
            );
        }
        // a directory above it that others can write
        let open_dir = dir.join("open");
        fs::create_dir(&open_dir).unwrap();
        fs::set_permissions(&open_dir, fs::Permissions::from_mode(0o777)).unwrap();
        let inner = open_dir.join("c.toml");
        fs::write(&inner, "x").unwrap();
        fs::set_permissions(&inner, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            read_trusted_control_file(&inner, 64, me)
                .unwrap_err()
                .contains("writable")
        );
        // symlink
        let link = dir.join("l.toml");
        symlink(&file, &link).unwrap();
        assert!(
            read_trusted_control_file(&link, 64, me)
                .unwrap_err()
                .contains("symlink")
        );
        // a FIFO or device is not a regular file and is never read
        assert!(read_trusted_control_file(Path::new("/dev/zero"), 64, me).is_err());
        // tools
        let tool = dir.join("tool");
        fs::write(&tool, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(check_tool_trust(&tool, me).is_ok());
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o775)).unwrap();
        assert!(
            check_tool_trust(&tool, me)
                .unwrap_err()
                .contains("writable")
        );
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            check_tool_trust(&tool, me)
                .unwrap_err()
                .contains("executable")
        );
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();
        let tool_link = dir.join("tool-link");
        symlink(&tool, &tool_link).unwrap();
        assert!(
            check_tool_trust(&tool_link, me).is_ok(),
            "a link to a good tool"
        );
        let open_tool = open_dir.join("tool");
        fs::write(&open_tool, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&open_tool, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            check_tool_trust(&open_tool, me)
                .unwrap_err()
                .contains("writable")
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
